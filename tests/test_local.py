"""Local stdio and public-client auth: all Microsoft, browser and keychain IO is mocked."""

import asyncio
import itertools
import json
import logging
import os
import sys
import time
from copy import deepcopy
from unittest.mock import Mock

import httpx2
import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from pydantic import ValidationError

from intune_mcp import local, server
from intune_mcp.config import (
    APPS_SCOPE,
    CONFIGURATION_SCOPE,
    GRAPH_SCOPE,
    KNOWN_READ_SCOPES,
    Settings,
)
from intune_mcp.graph import GraphClient, GraphError, ScopeNotAllowedError
from intune_mcp.groups import INVENTORY_TOOLS, TOOL_GROUPS, authorize_scopes

from .conftest import CLIENT_ID, OID_A, OID_B, OTHER_TENANT, TENANT

TOKEN = "opaque-not-a-jwt-token-DO-NOT-LOG"
NAME = "private-person-name-DO-NOT-LOG"
UPN = "private-person@example.test"
ACCOUNT = {
    "realm": TENANT,
    "local_account_id": OID_A,
    "home_account_id": f"{OID_A}.{TENANT}",
    "environment": "login.microsoftonline.com",
    "username": UPN,
    "name": NAME,
}


@pytest.fixture(autouse=True)
def mock_desktop(monkeypatch):
    from msal.oauth2cli import authcode

    monkeypatch.setattr(authcode, "_is_inside_docker", lambda: False)


def settings(**kwargs):
    return Settings(tenant_id=TENANT, client_id=CLIENT_ID, **kwargs)


class FakeMsal:
    def __init__(self):
        self.accounts = [deepcopy(ACCOUNT)]
        self.result = {"access_token": TOKEN, "expires_in": 3600}
        self.get_accounts = Mock(side_effect=lambda: deepcopy(self.accounts))
        self.acquire_token_silent = Mock(side_effect=lambda *a, **k: deepcopy(self.result))
        signed_in = {
            **self.result,
            "id_token_claims": {
                "tid": TENANT,
                "oid": OID_A,
                "name": NAME,
                "aud": CLIENT_ID,
                "iss": f"https://login.microsoftonline.com/{TENANT}/v2.0",
                "sub": "test-subject",
                "iat": time.time(),
                "exp": time.time() + 3600,
            },
        }
        self.acquire_token_interactive = Mock(return_value=signed_in)
        self.initiate_device_flow = Mock(
            return_value={
                "user_code": "ABCD-EFGH",
                "device_code": TOKEN,
                "message": NAME + UPN,
            }
        )
        self.acquire_token_by_device_flow = Mock(return_value=signed_in)
        self.remove_account = Mock(side_effect=lambda account: self.accounts.remove(account))


def graph_client(requests):
    def handler(request):
        requests.append(request)
        assert request.headers["authorization"] == f"Bearer {TOKEN}"
        if request.url.path == f"/v1.0/deviceManagement/managedDevices/{OID_A}":
            return httpx2.Response(200, json={"id": OID_A})
        return httpx2.Response(200, json={"value": []})

    return GraphClient(client=httpx2.AsyncClient(transport=httpx2.MockTransport(handler)))


def local_server(session, requests):
    return server.build_server(
        session.settings,
        token_source=session,
        identity_provider=session.caller,
        graph=graph_client(requests),
    )


async def test_protocol_smoke_single_scope_identity_and_audit(caplog):
    app, requests = FakeMsal(), []
    session = local.Session(settings(), app)
    caplog.set_level(logging.INFO)
    mcp = local_server(session, requests)
    assert mcp.auth is None
    assert not mcp._additional_http_routes
    async with Client(mcp) as client:
        tools = await client.list_tools()
        assert {t.name for t in tools} == {"whoami", *TOOL_GROUPS["devices"].tools}
        assert all(t.annotations.read_only_hint for t in tools)
        result = await client.call_tool("whoami", {})
        assert result.data == {"tenant_id": TENANT, "object_id": OID_A, "tool_groups": ["devices"]}
        assert not app.acquire_token_silent.called
        result = await client.call_tool("list_devices", {})
        assert result.data["devices"] == []
    app.acquire_token_silent.assert_called_once_with([GRAPH_SCOPE], account=ACCOUNT)
    assert len(requests) == 1
    assert f"caller_oid={OID_A}" in caplog.text
    assert "outcome=ok" in caplog.text
    for secret in (TOKEN, NAME, UPN):
        assert secret not in caplog.text


GROUP_SETS = [
    subset
    for n in range(1, len(TOOL_GROUPS) + 1)
    for subset in itertools.combinations(TOOL_GROUPS, n)
]


@pytest.mark.parametrize("groups", GROUP_SETS)
@pytest.mark.parametrize("device_code", [False, True])
async def test_enabled_groups_same_catalog_and_only_enabled_login_scopes(
    groups, device_code, capsys
):
    app = FakeMsal()
    session = local.Session(settings(enabled_tool_groups=",".join(groups)), app)
    session.login(device_code=device_code)
    scopes = authorize_scopes(groups)
    if device_code:
        app.initiate_device_flow.assert_called_once_with(scopes=scopes)
        app.acquire_token_by_device_flow.assert_called_once()
        app.acquire_token_interactive.assert_not_called()
    else:
        app.acquire_token_interactive.assert_called_once_with(
            scopes=scopes, prompt="select_account", timeout=300
        )
        app.initiate_device_flow.assert_not_called()
    assert set(scopes) == {TOOL_GROUPS[g].scope for g in groups}
    assert not (KNOWN_READ_SCOPES - set(scopes)) & set(scopes)
    async with Client(local_server(session, [])) as client:
        tools = {t.name for t in await client.list_tools()}
        assert tools == {"whoami", *(t for g in groups for t in TOOL_GROUPS[g].tools)}
    capture = capsys.readouterr()
    assert not capture.out
    assert all(value not in capture.err for value in (TOKEN, NAME, UPN))


@pytest.mark.parametrize("inventory", [False, True])
async def test_inventory_opt_in_uses_same_registrars_and_scopes(inventory):
    app = FakeMsal()
    session = local.Session(settings(enable_tenant_inventory=inventory), app)
    async with Client(local_server(session, [])) as client:
        tools = {t.name for t in await client.list_tools()}
        assert set(INVENTORY_TOOLS) <= tools if inventory else not set(INVENTORY_TOOLS) & tools
    session.login()
    assert app.acquire_token_interactive.call_args.kwargs["scopes"] == [GRAPH_SCOPE]


async def test_cross_scope_parent_visibility_reuses_existing_layer():
    app, requests = FakeMsal(), []
    session = local.Session(settings(enabled_tool_groups="devices,configuration"), app)
    async with Client(local_server(session, requests)) as client:
        await client.call_tool("get_device_compliance_states", {"device_id": OID_A})
    assert [c.args[0] for c in app.acquire_token_silent.call_args_list] == [
        [GRAPH_SCOPE],
        [CONFIGURATION_SCOPE],
    ]
    assert len(requests) == 2
    assert requests[0].url.path.endswith(OID_A)
    assert requests[1].url.path.endswith("deviceCompliancePolicyStates")


async def test_parent_group_disabled_fails_before_msal_and_graph():
    app, requests = FakeMsal(), []
    session = local.Session(settings(enabled_tool_groups="configuration"), app)
    async with Client(local_server(session, requests)) as client:
        result = await client.call_tool(
            "get_device_compliance_states", {"device_id": OID_A}, raise_on_error=False
        )
        assert "parent_check_unavailable" in result.content[0].text
    app.acquire_token_silent.assert_not_called()
    assert not requests


@pytest.mark.parametrize(
    "scope",
    [
        ".default",
        "https://graph.microsoft.com/.default",
        "DeviceManagementManagedDevices.Read.All",
        "https://graph.microsoft.com/DeviceManagementManagedDevices.ReadWrite.All",
        "https://other.example.test/DeviceManagementManagedDevices.Read.All",
        [GRAPH_SCOPE],
        [GRAPH_SCOPE, CONFIGURATION_SCOPE],
        "",
        None,
        1,
    ],
)
async def test_scope_guard_before_any_silent_acquisition(scope):
    app = FakeMsal()
    session = local.Session(settings(), app)
    caller, identity = session.caller()
    with pytest.raises(ScopeNotAllowedError):
        await session.token_for(caller, identity, scope)
    app.acquire_token_silent.assert_not_called()


@pytest.mark.parametrize(
    "scope",
    [
        "https://graph.microsoft.com/.default",
        "https://graph.microsoft.com/DeviceManagementManagedDevices.ReadWrite.All",
    ],
)
async def test_closed_guard_independent_of_enabled_scope_list(scope):
    app = FakeMsal()
    session = local.Session(settings(), app)
    # A future registry/config bug must not replace the token source's closed allowlist.
    session.scopes.append(scope)
    with pytest.raises(ScopeNotAllowedError):
        await session.token_for(*session.caller(), scope)
    app.acquire_token_silent.assert_not_called()


async def test_disabled_but_allowlisted_scope_is_rejected():
    app = FakeMsal()
    session = local.Session(settings(), app)
    caller, identity = session.caller()
    with pytest.raises(ScopeNotAllowedError):
        await session.token_for(caller, identity, APPS_SCOPE)
    app.acquire_token_silent.assert_not_called()


@pytest.mark.parametrize("scope", sorted(KNOWN_READ_SCOPES))
async def test_each_scope_uses_one_silent_call_and_keeps_token_opaque(scope):
    app = FakeMsal()
    session = local.Session(settings(enabled_tool_groups=",".join(TOOL_GROUPS)), app)
    caller, identity = session.caller()
    assert await session.token_for(caller, identity, scope) == TOKEN
    app.acquire_token_silent.assert_called_once_with([scope], account=ACCOUNT)
    app.acquire_token_interactive.assert_not_called()
    app.initiate_device_flow.assert_not_called()


async def test_missing_silent_token_never_opens_browser(caplog):
    app, requests = FakeMsal(), []
    app.result = None
    session = local.Session(settings(), app)
    async with Client(local_server(session, requests)) as client:
        result = await client.call_tool("list_devices", {}, raise_on_error=False)
        assert "sign_in_required" in result.content[0].text
        assert "intune-mcp login" in result.content[0].text
    app.acquire_token_silent.assert_called_once()
    app.acquire_token_interactive.assert_not_called()
    app.initiate_device_flow.assert_not_called()
    assert not requests


@pytest.mark.parametrize(
    "field,value",
    [
        ("realm", OTHER_TENANT),
        ("realm", None),
        ("realm", "malformed"),
        ("local_account_id", None),
        ("local_account_id", "malformed"),
        ("home_account_id", ""),
    ],
)
async def test_account_identity_fail_closed(field, value):
    app, requests = FakeMsal(), []
    app.accounts[0][field] = value
    session = local.Session(settings(), app)
    with pytest.raises(ToolError, match="sign_in_required"):
        session.caller()
    async with Client(local_server(session, requests)) as client:
        for tool in ("whoami", "list_devices"):
            result = await client.call_tool(tool, {}, raise_on_error=False)
            assert result.is_error
    app.acquire_token_silent.assert_not_called()
    assert not requests


@pytest.mark.parametrize("accounts", [[], [ACCOUNT, {**ACCOUNT, "local_account_id": OID_B}]])
def test_no_first_account_fallback(accounts):
    app = FakeMsal()
    app.accounts = accounts
    with pytest.raises(ToolError, match="sign_in_required"):
        local.Session(settings(), app).caller()


async def test_account_switch_during_call_fails_before_silent():
    app = FakeMsal()
    session = local.Session(settings(), app)
    caller, identity = session.caller()
    app.accounts[0]["local_account_id"] = OID_B
    with pytest.raises(GraphError, match="intune-mcp login"):
        await session.token_for(caller, identity)
    app.acquire_token_silent.assert_not_called()


@pytest.mark.parametrize("field,value", [("tid", OTHER_TENANT), ("oid", OID_B)])
def test_login_rejects_wrong_id_claims(field, value):
    app = FakeMsal()
    app.acquire_token_interactive.return_value["id_token_claims"][field] = value
    with pytest.raises(GraphError, match="intune-mcp login"):
        local.Session(settings(), app).login()


@pytest.mark.parametrize(
    "field,value",
    [
        ("aud", CLIENT_ID + "extra"),
        ("iss", "https://other.example.test/v2.0"),
        ("sub", ""),
        ("sub", None),
        ("exp", 0),
        ("exp", True),
        ("exp", float("nan")),
        ("iat", float("inf")),
        ("iat", 9_999_999_999),
        ("nbf", 9_999_999_999),
        ("nbf", False),
    ],
)
def test_login_id_claim_validation_not_delegated_to_msal(field, value):
    app = FakeMsal()
    app.acquire_token_interactive.return_value["id_token_claims"][field] = value
    with pytest.raises(GraphError, match="Sign-in identity rejected"):
        local.Session(settings(), app).login()


def test_browser_login_refuses_msal_container_wildcard_listener(monkeypatch):
    from msal.oauth2cli import authcode

    app = FakeMsal()
    monkeypatch.setattr(authcode, "_is_inside_docker", lambda: True)
    with pytest.raises(local.LocalError, match="login --device-code"):
        local.Session(settings(), app).login()
    app.acquire_token_interactive.assert_not_called()
    # Headless flow never constructs a receiver/listener.
    local.Session(settings(), app).login(device_code=True)


@pytest.mark.parametrize(
    "result,expected",
    [
        (None, "sign_in_required"),
        ({"error": "interaction_required"}, "graph_interaction_required"),
        ({"error": "consent_required"}, "graph_consent_required"),
        ({"error": "invalid_grant"}, "graph_access_revoked"),
        ({"error_codes": [65001]}, "graph_consent_required"),
        ({"error_codes": [50105]}, "graph_access_revoked"),
        ({"error_codes": [50076]}, "graph_interaction_required"),
        ({"error_codes": [123456]}, "graph_exchange_failed"),
    ],
)
async def test_safe_failure_classes_without_upstream_text(result, expected, caplog):
    app = FakeMsal()
    if result is not None:
        result = {
            **result,
            "error": result.get("error", "invalid_request"),
            "error_description": TOKEN + NAME + UPN,
            "claims": TOKEN,
            "correlation_id": TOKEN,
        }
    app.result = result
    session = local.Session(settings(), app)
    caplog.set_level(logging.INFO)
    async with Client(local_server(session, [])) as client:
        response = await client.call_tool("list_devices", {}, raise_on_error=False)
        assert expected in response.content[0].text
    for value in (TOKEN, NAME, UPN):
        assert value not in str(response)
        assert value not in caplog.text


async def test_unexpected_msal_exception_is_not_logged_or_echoed(caplog):
    app = FakeMsal()
    app.acquire_token_silent.side_effect = RuntimeError(TOKEN + NAME + UPN)
    session = local.Session(settings(), app)
    async with Client(local_server(session, [])) as client:
        result = await client.call_tool("list_devices", {}, raise_on_error=False)
        assert "graph_exchange_failed" in result.content[0].text
    assert all(secret not in caplog.text + str(result) for secret in (TOKEN, NAME, UPN))


@pytest.mark.parametrize(
    "result",
    [
        {"access_token": "", "expires_in": 3600},
        {"access_token": TOKEN, "expires_in": 0},
        {"access_token": TOKEN, "expires_in": True},
        {"access_token": TOKEN, "expires_in": float("nan")},
        {"access_token": TOKEN, "expires_in": float("inf")},
        {"access_token": TOKEN},
    ],
)
async def test_unusable_tokens_rejected(result):
    app = FakeMsal()
    app.result = result
    session = local.Session(settings(), app)
    with pytest.raises(GraphError, match="unusable Graph token"):
        await session.token_for(*session.caller())


async def test_input_validation_precedes_silent_acquisition():
    app, requests = FakeMsal(), []
    session = local.Session(settings(), app)
    async with Client(local_server(session, requests)) as client:
        result = await client.call_tool("get_device", {"device_id": UPN}, raise_on_error=False)
        assert result.is_error
    app.acquire_token_silent.assert_not_called()
    assert not requests


@pytest.mark.parametrize("groups", ["", "devices,devices", "unknown", "devices,"])
def test_group_list_validation(groups):
    with pytest.raises(ValidationError):
        settings(enabled_tool_groups=groups)


def test_inventory_requires_devices():
    with pytest.raises(ValidationError):
        settings(enabled_tool_groups="apps", enable_tenant_inventory=True)


@pytest.mark.parametrize("failure", ["builder", "plaintext", "save", "load", "silent_save"])
def test_cache_encryption_unavailable_fails_closed_no_plaintext(failure, tmp_path, monkeypatch):
    import msal_extensions
    import platformdirs
    from msal_extensions.persistence import FilePersistence, PersistenceNotFound

    monkeypatch.setattr(platformdirs, "user_data_path", lambda *a, **k: tmp_path)
    backend = Mock(is_encrypted=True)
    backend.get_location.return_value = str(tmp_path / "encrypted.cache")
    backend.load.side_effect = PersistenceNotFound()
    if failure == "builder":
        builder = Mock(side_effect=RuntimeError(TOKEN + UPN))
    elif failure == "plaintext":
        backend = FilePersistence(str(tmp_path / "plaintext.cache"))
        builder = Mock(return_value=backend)
    else:
        builder = Mock(return_value=backend)
        if failure == "save":
            backend.save.side_effect = RuntimeError(TOKEN + UPN)
        elif failure == "load":
            backend.load.side_effect = RuntimeError(TOKEN + UPN)
        elif failure == "silent_save":
            backend.load.side_effect = [PersistenceNotFound(), "old content"]
    monkeypatch.setattr(msal_extensions, "build_encrypted_persistence", builder)
    with pytest.raises(local.LocalError, match="Plaintext fallback is forbidden") as exc:
        local.encrypted_cache(settings())
    assert TOKEN not in str(exc.value) and UPN not in str(exc.value)
    assert not list(tmp_path.iterdir())  # No plaintext, temporary cache, or leftover lock file.


def test_encrypted_cache_roundtrip_and_persisted_locking(tmp_path, monkeypatch):
    import msal_extensions
    import platformdirs
    from msal_extensions.persistence import PersistenceNotFound

    class MemoryEncrypted:
        is_encrypted = True
        content = None
        saves = 0

        def load(self):
            if self.content is None:
                raise PersistenceNotFound()
            return self.content

        def save(self, content):
            # PersistedTokenCache holds its cross-process lock for writes.
            assert (tmp_path / f"{TENANT}-{CLIENT_ID}.cache.lockfile").exists()
            self.content = content
            self.saves += 1

        def get_location(self):
            return str(tmp_path / f"{TENANT}-{CLIENT_ID}.cache")

        def time_last_modified(self):
            return 1

    backend = MemoryEncrypted()
    monkeypatch.setattr(platformdirs, "user_data_path", lambda *a, **k: tmp_path)
    monkeypatch.setattr(msal_extensions, "build_encrypted_persistence", lambda p: backend)
    cache = local.encrypted_cache(settings())
    assert cache.is_encrypted
    cache.modify(cache.CredentialType.ACCOUNT, {}, {"home_account_id": OID_A})
    assert backend.saves == 2
    assert not list(tmp_path.iterdir())


def test_create_session_is_a_public_client_with_no_secret(monkeypatch):
    import msal

    cache, app = object(), FakeMsal()
    monkeypatch.setattr(local, "encrypted_cache", lambda s: cache)
    constructor = Mock(return_value=app)
    monkeypatch.setattr(msal, "PublicClientApplication", constructor)
    session = local.create_session(settings())
    assert session.app is app
    constructor.assert_called_once_with(
        CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{TENANT}",
        token_cache=cache,
        enable_pii_log=False,
        enable_broker_on_windows=False,
        enable_broker_on_mac=False,
        timeout=local.HTTP_TIMEOUT,
    )


def test_unencrypted_cache_failure_precedes_msal(monkeypatch):
    import msal

    constructor = Mock()
    monkeypatch.setattr(msal, "PublicClientApplication", constructor)
    monkeypatch.setattr(
        local, "encrypted_cache", Mock(side_effect=local.LocalError(local.CACHE_ERROR))
    )
    with pytest.raises(local.LocalError):
        local.create_session(settings())
    constructor.assert_not_called()


@pytest.mark.parametrize("args", [["login"], ["login", "--device-code"], ["logout"], ["status"]])
def test_cli_lifecycle_stdout_pure(args, monkeypatch, capsys):
    monkeypatch.setenv("INTUNE_TENANT_ID", TENANT)
    monkeypatch.setenv("INTUNE_CLIENT_ID", CLIENT_ID)
    session = local.Session(settings(), FakeMsal())
    monkeypatch.setattr(local, "create_session", lambda s: session)
    monkeypatch.setattr(local, "configure_logging", lambda: None)
    assert local.main(args) == 0
    capture = capsys.readouterr()
    assert capture.out == ""
    assert all(s not in capture.err for s in (NAME, UPN, TOKEN))
    if args == ["logout"]:
        assert not session.app.accounts
        session.app.remove_account.assert_called_once()
    if args == ["status"]:
        session.app.acquire_token_silent.assert_not_called()


def test_cli_invalid_settings_never_echo_values(monkeypatch, capsys):
    monkeypatch.setenv("INTUNE_TENANT_ID", TOKEN + UPN)
    monkeypatch.setattr(local, "configure_logging", lambda: None)
    assert local.main(["status"]) == 1
    capture = capsys.readouterr()
    assert not capture.out
    assert "Invalid local configuration" in capture.err
    assert TOKEN not in capture.err and UPN not in capture.err


async def test_real_stdio_subprocess_only_protocol_frames():
    # Actual CLI -> FastMCP stdio, with fake MSAL and MockTransport Graph. No network/keychain.
    script = """
from tests.test_local import FakeMsal, settings, graph_client, TOKEN, NAME, UPN
from intune_mcp import local, server
import logging
session = local.Session(settings(), FakeMsal())
local.create_session = lambda settings: session
def build(settings, **kw):
    return server.build_server(settings, graph=graph_client([]), **kw)
local.build_server = build
original = local.configure_logging
def logging_setup():
    original()
    for name in ('msal', 'msal_extensions', 'azure', 'httpx2', 'httpx', 'urllib3'):
        logging.getLogger(name).critical(TOKEN + NAME + UPN)
local.configure_logging = logging_setup
raise SystemExit(local.main([]))
"""
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        script,
        env={
            **os.environ,
            "INTUNE_TENANT_ID": TENANT,
            "INTUNE_CLIENT_ID": CLIENT_ID,
            "INTUNE_UPDATE_CHECK": "0",
        },
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    frames = []

    async def rpc(identifier, method, params):
        process.stdin.write(
            (
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": identifier,
                        "method": method,
                        "params": params,
                    }
                )
                + "\n"
            ).encode()
        )
        await process.stdin.drain()
        while True:
            line = await asyncio.wait_for(process.stdout.readline(), 20)
            assert line, "stdio ended without a response"
            frame = json.loads(line)  # A banner or log on stdout fails immediately.
            frames.append(frame)
            if frame.get("id") == identifier:
                return frame

    try:
        await rpc(
            1,
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "mock", "version": "1"},
            },
        )
        process.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        await process.stdin.drain()
        listed = await rpc(2, "tools/list", {})
        assert {t["name"] for t in listed["result"]["tools"]} == {
            "whoami",
            *TOOL_GROUPS["devices"].tools,
        }
        called = await rpc(3, "tools/call", {"name": "list_devices", "arguments": {}})
        assert not called["result"].get("isError")
        process.stdin.close()
        await asyncio.wait_for(process.wait(), 20)
        trailing = await process.stdout.read()
        assert not trailing
        stderr = (await process.stderr.read()).decode()
        assert process.returncode == 0, stderr
        assert "tool=list_devices" in stderr and "outcome=ok" in stderr
        assert all(s not in stderr for s in (TOKEN, NAME, UPN))
        assert all(frame["jsonrpc"] == "2.0" for frame in frames)
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()


def test_rejected_login_leaves_no_usable_account():
    """Review finding: MSAL caches before our claim checks run; a rejected sign-in must not stay."""
    app = FakeMsal()  # the cache already holds the account MSAL wrote for this sign-in
    app.acquire_token_interactive.return_value["id_token_claims"]["aud"] = "wrong-audience"
    with pytest.raises(GraphError, match="Sign-in identity rejected"):
        local.Session(settings(), app).login()
    assert app.accounts == []


def test_failed_login_removes_only_the_account_it_added():
    app = FakeMsal()  # signed in as ACCOUNT before
    other = deepcopy(ACCOUNT)
    other["home_account_id"] = "other-home"
    other["local_account_id"] = OID_B
    app.acquire_token_interactive.side_effect = lambda *a, **k: (
        app.accounts.append(other) or {"error": "access_denied"}
    )
    with pytest.raises(GraphError):
        local.Session(settings(), app).login()
    assert [a["home_account_id"] for a in app.accounts] == [ACCOUNT["home_account_id"]]


def test_msal_http_timeout_is_configured(monkeypatch):
    import msal

    seen = {}

    class Capturing:
        def __init__(self, *args, **kwargs):
            seen.update(kwargs)

    monkeypatch.setattr(msal, "PublicClientApplication", Capturing)
    monkeypatch.setattr(local, "encrypted_cache", lambda _settings: object())
    local.create_session(settings())
    assert seen["timeout"] == local.HTTP_TIMEOUT


async def test_slow_refresh_never_blocks_identity_lookup_or_other_threads():
    """Review finding: the event loop must never wait on the refresh lock."""
    import threading

    app = FakeMsal()
    entered, release = threading.Event(), threading.Event()

    def slow(*args, **kwargs):
        entered.set()
        release.wait(5)
        return {"access_token": TOKEN, "expires_in": 3600}

    app.acquire_token_silent = Mock(side_effect=slow)
    session = local.Session(settings(), app)
    caller, identity = session.caller()
    task = asyncio.create_task(session.token_for(caller, identity))
    assert await asyncio.to_thread(entered.wait, 2)
    # Identity lookups (what every tool call and whoami do on the loop) stay responsive.
    got = await asyncio.wait_for(asyncio.to_thread(session.caller), 1)
    assert got[1] == identity
    release.set()
    assert await task == TOKEN


async def test_hung_silent_acquisition_times_out_with_a_safe_error(monkeypatch):
    import threading

    app = FakeMsal()
    release = threading.Event()
    app.acquire_token_silent = Mock(side_effect=lambda *a, **k: release.wait(5) or {})
    monkeypatch.setattr(local, "SILENT_TIMEOUT", 0.05)
    session = local.Session(settings(), app)
    caller, identity = session.caller()
    try:
        with pytest.raises(GraphError, match="timed out") as info:
            await session.token_for(caller, identity)
        assert info.value.code == "graph_exchange_failed"
        assert TOKEN not in str(info.value)
    finally:
        release.set()


@pytest.mark.parametrize(
    "result",
    [
        {"access_token": "", "expires_in": 3600},
        {"access_token": None, "expires_in": 3600},
        {"access_token": 1, "expires_in": 3600},
        {"access_token": TOKEN, "expires_in": 0},
        {"access_token": TOKEN, "expires_in": -5},
        {"access_token": TOKEN, "expires_in": True},
        {"access_token": TOKEN, "expires_in": float("nan")},
        {"access_token": TOKEN, "expires_in": "3600"},
        {"access_token": TOKEN},
        {},
        None,
    ],
)
async def test_unusable_graph_token_results_fail_closed(result):
    """The Graph token is opaque, but an empty, expired or malformed MSAL result is never used."""
    app = FakeMsal()
    app.acquire_token_silent = Mock(return_value=result)
    session = local.Session(settings(), app)
    caller, identity = session.caller()
    with pytest.raises(GraphError) as info:
        await session.token_for(caller, identity)
    assert info.value.code in {"graph_token_invalid", "sign_in_required"}
    assert TOKEN not in str(info.value)


@pytest.mark.parametrize(
    "result,expected,absent",
    [
        (
            {"error": "invalid_client", "error_codes": [7000218]},
            "[error=invalid_client AADSTS7000218]",
            "",
        ),
        ({"error": "invalid_grant", "error_codes": [50076, 50158]}, "AADSTS50076,50158", ""),
        ({"error": "Bad Name<script>", "error_codes": [True, "65001", 12, 10**9]}, None, "AADSTS"),
        (
            {"error": "x", "error_description": "AADSTS999999 secret@example.test Trace"},
            "[error=x]",
            "secret",
        ),
        ({"error_codes": "not-a-list"}, None, "AADSTS"),
        ("not a dict", None, "AADSTS"),
    ],
)
def test_failure_detail_is_only_a_closed_name_and_numeric_codes(result, expected, absent):
    detail = local.error_detail(result)
    if expected:
        assert expected in detail
    if absent:
        assert absent not in detail
    assert "secret" not in detail and "example.test" not in detail and "Trace" not in detail


def test_login_failure_reports_the_code_but_never_the_description():
    app = FakeMsal()
    app.acquire_token_by_device_flow = Mock(
        return_value={
            "error": "invalid_grant",
            "error_codes": [53003],
            "error_description": "AADSTS53003: blocked for " + UPN,
        }
    )
    with pytest.raises(GraphError) as info:
        local.Session(settings(), app).login(device_code=True)
    assert "AADSTS53003" in info.value.message and UPN not in info.value.message


def test_unexpected_login_exceptions_name_only_their_type():
    app = FakeMsal()

    class KeychainBoom(OSError):
        pass

    app.acquire_token_by_device_flow = Mock(side_effect=KeychainBoom("secret path /Users/x " + UPN))
    with pytest.raises(GraphError) as info:
        local.Session(settings(), app).login(device_code=True)
    assert "[KeychainBoom]" in info.value.message and UPN not in info.value.message
    assert "/Users/x" not in info.value.message


def test_status_says_which_groups_are_enabled_and_how_to_add_more(monkeypatch, capsys):
    monkeypatch.setenv("INTUNE_TENANT_ID", TENANT)
    monkeypatch.setenv("INTUNE_CLIENT_ID", CLIENT_ID)
    monkeypatch.setattr(local, "configure_logging", lambda: None)
    for groups, enabled, missing in (
        ("devices", "devices.", "apps, configuration, enrollment, rbac"),
        ("devices,rbac", "devices, rbac.", "apps, configuration, enrollment"),
    ):
        monkeypatch.setenv("INTUNE_ENABLED_TOOL_GROUPS", groups)
        session = local.Session(settings(enabled_tool_groups=groups), FakeMsal())
        monkeypatch.setattr(local, "create_session", lambda s, session=session: session)
        assert local.main(["status"]) == 0
        err = capsys.readouterr().err
        assert f"Enabled tool groups: {enabled}" in err
        assert f"Not enabled: {missing}." in err and "INTUNE_ENABLED_TOOL_GROUPS" in err
    every = "devices,configuration,apps,rbac,enrollment"
    monkeypatch.setenv("INTUNE_ENABLED_TOOL_GROUPS", every)
    session = local.Session(settings(enabled_tool_groups=every), FakeMsal())
    monkeypatch.setattr(local, "create_session", lambda s: session)
    assert local.main(["status"]) == 0
    assert "Not enabled" not in capsys.readouterr().err
