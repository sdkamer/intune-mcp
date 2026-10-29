"""Group gating with a test-only second group (registry monkeypatched). Everything is mocked."""

import logging

import httpx2
import jwt
import pytest

from intune_mcp import graph as graph_module
from intune_mcp import server
from intune_mcp.config import CONFIGURATION_SCOPE, GRAPH_SCOPE
from intune_mcp.graph import CollectionSpec
from intune_mcp.groups import TOOL_GROUPS, ToolGroup
from intune_mcp.groups import authorize_scopes as groups_authorize_scopes

from .conftest import OID_A, make_settings
from .harness import Harness, rpc_body
from .test_device_tools import all_calls, error_text, payload, prime

DEFAULT_TOOLS = [
    "count_devices",
    "device_summary",
    "get_device",
    "list_devices",
    "search_devices",
    "whoami",
]
DUMMY_SPEC = CollectionSpec(
    "dummy.things",
    "/deviceManagement/dummyThings",
    CONFIGURATION_SCOPE,
    ("id", "name"),
)


def register_dummy(ctx):
    @ctx.tool
    async def dummy_read() -> dict:
        """Test-only tool of the test-only group."""
        identity, cid, page = await ctx.run(
            "dummy_read",
            "dummyThings",
            DUMMY_SPEC,
            lambda token, correlation_id, plan: ctx.graph.fetch_page(token, plan, correlation_id),
            prepare=lambda: ctx.graph.plan(DUMMY_SPEC, page_size=5, page_token=None),
        )
        ctx.audit("dummy_read", identity, cid, "ok", returned=len(page.rows))
        return {"things": page.rows}


@pytest.fixture
def dummy_group(monkeypatch):
    monkeypatch.setitem(
        TOOL_GROUPS, "dummy", ToolGroup("dummy", CONFIGURATION_SCOPE, ("dummy_read",))
    )
    monkeypatch.setitem(server.GROUP_REGISTRARS, "dummy", register_dummy)


def scp_of(request):
    bearer = request.headers["authorization"].split()[1]
    return jwt.decode(bearer, options={"verify_signature": False})["scp"]


class Both:
    """A harness whose Graph also serves the dummy endpoint, and only for its own scope."""

    def __init__(self, settings):
        self.h = Harness(settings)
        self.dummy_requests = []

        def handler(request):
            if request.url.path == "/v1.0/deviceManagement/dummyThings":
                self.h.graph_requests.append(request)
                self.dummy_requests.append(request)
                if scp_of(request) != CONFIGURATION_SCOPE.rsplit("/", 1)[1]:
                    return httpx2.Response(403, json={})
                return httpx2.Response(
                    200, json={"value": [{"id": "1", "name": "thing", "secret": "leak"}]}
                )
            return self.h._graph_handler(request)  # noqa: SLF001

        self.h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))  # noqa: SLF001


@pytest.fixture
async def both(dummy_group):
    harness = Both(make_settings(enabled_tool_groups="devices,dummy"))
    async with harness.h.running():
        yield harness


async def bearer(h, oid):
    _, token = await h.sign_in(oid)
    assert token.status_code == 200, token.text
    return token.json()["access_token"]


async def tools(h, token):
    init = {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "t", "version": "1"},
    }
    await h.mcp(token, "initialize", init)
    listed = rpc_body(await h.mcp(token, "tools/list"))["result"]["tools"]
    for t in listed:
        assert t["annotations"] == {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        }, t["name"]
    return sorted(t["name"] for t in listed)


async def authorize_scopes(h):
    """The Graph scopes a sign-in asks Entra for (what `intune-mcp login` requests)."""
    return set(groups_authorize_scopes(h.settings.enabled_groups))


# -- default config: exactly today's surface ---------------------------------------------------
async def test_default_config_registers_only_the_devices_group_and_its_scope(dummy_group, settings):
    async with Harness(settings).running() as h:  # registry has "dummy", but it is not enabled
        token = await bearer(h, OID_A)
        assert await tools(h, token) == DEFAULT_TOOLS
        assert "dummy_read" not in DEFAULT_TOOLS
        text = error_text(await h.call_tool(token, "dummy_read"))
        assert text == "Unknown tool: 'dummy_read'"
        assert h.graph_requests == [] and h.token_requests == []
        assert await authorize_scopes(h) == {
            GRAPH_SCOPE,
        }


async def test_the_dummy_group_cannot_be_enabled_when_it_is_not_in_the_registry():
    with pytest.raises(ValueError):
        make_settings(enabled_tool_groups="devices,dummy")


# -- enabling a group --------------------------------------------------------------------------
async def test_enabling_a_group_adds_its_tools_and_its_scope_to_the_sign_in(both):
    h = both.h
    token = await bearer(h, OID_A)
    assert await tools(h, token) == sorted([*DEFAULT_TOOLS, "dummy_read"])
    assert await authorize_scopes(h) == {
        GRAPH_SCOPE,
        CONFIGURATION_SCOPE,
    }


async def test_enabling_only_the_second_group_asks_only_for_its_scope(dummy_group):
    async with Harness(make_settings(enabled_tool_groups="dummy")).running() as h:
        token = await bearer(h, OID_A)
        assert await tools(h, token) == ["dummy_read", "whoami"]
        assert await authorize_scopes(h) == {
            CONFIGURATION_SCOPE,
        }


async def test_each_tool_requests_only_its_own_groups_scope(both):
    h = both.h
    prime(h)
    token = await bearer(h, OID_A)
    for tool, args in all_calls(h.devices[OID_A][0]):
        before = len(h.token_requests)
        payload(await h.call_tool(token, tool, args))
        assert [s for _, s in h.token_requests[before:]] == [(GRAPH_SCOPE,)], tool
        assert scp_of(h.graph_requests[-1]) == GRAPH_SCOPE.rsplit("/", 1)[1]
    before = len(h.token_requests)
    out = payload(await h.call_tool(token, "dummy_read"))
    assert out == {"things": [{"id": "1", "name": "thing"}]}  # field minimisation still applies
    assert [s for _, s in h.token_requests[before:]] == [(CONFIGURATION_SCOPE,)]
    assert scp_of(both.dummy_requests[-1]) == CONFIGURATION_SCOPE.rsplit("/", 1)[1]


async def test_one_tool_cannot_obtain_another_groups_scope(both):
    """Every devices-tool token is refused by the second group's endpoint, and vice versa."""
    h = both.h
    prime(h)
    token = await bearer(h, OID_A)
    payload(await h.call_tool(token, "list_devices"))
    devices_token = h.graph_requests[-1].headers["authorization"]
    # Replaying the devices tool's token at the second group's endpoint: Graph refuses it.
    async with httpx2.AsyncClient(transport=h.graph._client._transport) as raw:  # noqa: SLF001
        refused = await raw.get(
            "https://graph.microsoft.com/v1.0/deviceManagement/dummyThings",
            headers={"authorization": devices_token},
        )
    assert refused.status_code == 403
    payload(await h.call_tool(token, "dummy_read"))
    dummy_token = both.dummy_requests[-1].headers["authorization"]
    assert dummy_token != devices_token
    async with httpx2.AsyncClient(transport=h.graph._client._transport) as raw:  # noqa: SLF001
        refused = await raw.get(
            "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices",
            headers={"authorization": dummy_token},
        )
    assert refused.status_code == 403
    # No exchange ever asked for both scopes, and no tool asked for a scope outside its group.
    assert all(len(scopes) == 1 for _, scopes in h.token_requests)


async def test_a_tool_using_an_endpoint_of_another_group_fails_closed_and_is_audited(
    monkeypatch, caplog
):
    from intune_mcp.graph import DEVICE_OVERVIEW_SPEC, plan_object

    def register_wrong(ctx):
        @ctx.tool
        async def dummy_read() -> dict:
            """Wrongly built: group `dummy` (config scope) tool using a devices-scope endpoint."""
            _, _, summary = await ctx.run(
                "dummy_read",
                "wrong",
                DEVICE_OVERVIEW_SPEC,
                lambda token, cid, plan: ctx.graph.fetch_object(token, plan, cid),
                prepare=lambda: plan_object(DEVICE_OVERVIEW_SPEC, path_args={}),
            )
            return summary

    monkeypatch.setitem(
        TOOL_GROUPS, "dummy", ToolGroup("dummy", CONFIGURATION_SCOPE, ("dummy_read",))
    )
    monkeypatch.setitem(server.GROUP_REGISTRARS, "dummy", register_wrong)
    async with Harness(make_settings(enabled_tool_groups="dummy")).running() as h:
        token = await bearer(h, OID_A)
        with caplog.at_level(logging.INFO, logger="intune_mcp.audit"):
            text = error_text(await h.call_tool(token, "dummy_read"))
        assert text.startswith("internal_error: The request could not be completed. (ref ")
        for scope_text in ("Read.All", "DeviceManagement", "scope"):
            assert scope_text not in text
        assert h.token_requests == [] and h.graph_requests == []  # never exchanged, never called
        [line] = [r.getMessage() for r in caplog.records if r.name == "intune_mcp.audit"]
        assert "outcome=scope_not_allowed" in line and f"caller_oid={OID_A}" in line


async def test_scope_outside_the_allowlist_at_exchange_time_is_generic_audited_and_unexchanged(
    h_default, monkeypatch, caplog
):
    h = h_default
    prime(h)
    token = await bearer(h, OID_A)
    monkeypatch.setattr(graph_module, "KNOWN_READ_SCOPES", frozenset())  # nothing is allowed
    with caplog.at_level(logging.INFO, logger="intune_mcp.audit"):
        text = error_text(await h.call_tool(token, "list_devices"))
    assert text.startswith("internal_error: The request could not be completed. (ref ")
    assert "DeviceManagement" not in text and "allowlist" not in text
    assert h.token_requests == [] and h.graph_requests == []  # no credential, no exchange, no call
    [line] = [r.getMessage() for r in caplog.records if r.name == "intune_mcp.audit"]
    assert "outcome=scope_not_allowed" in line and "tool=list_devices" in line


@pytest.fixture
async def h_default(settings):
    async with Harness(settings).running() as harness:
        yield harness


# -- registry/registrar consistency fails at startup -------------------------------------------
def test_a_group_without_an_implementation_fails_startup(monkeypatch, settings):
    monkeypatch.setitem(
        TOOL_GROUPS, "dummy", ToolGroup("dummy", CONFIGURATION_SCOPE, ("dummy_read",))
    )
    with pytest.raises(RuntimeError, match="no implementation"):
        Harness(make_settings(enabled_tool_groups="devices,dummy"))


def test_a_registrar_that_registers_different_tools_than_declared_fails_startup(monkeypatch):
    monkeypatch.setitem(
        TOOL_GROUPS, "dummy", ToolGroup("dummy", CONFIGURATION_SCOPE, ("other_name",))
    )
    monkeypatch.setitem(server.GROUP_REGISTRARS, "dummy", register_dummy)
    with pytest.raises(RuntimeError, match="differ from its declaration"):
        Harness(make_settings(enabled_tool_groups="dummy"))


def test_a_registrar_that_registers_an_extra_tool_fails_startup(monkeypatch):
    def greedy(ctx):
        register_dummy(ctx)

        @ctx.tool
        async def sneaky() -> dict:
            """Undeclared."""
            return {}

    monkeypatch.setitem(
        TOOL_GROUPS, "dummy", ToolGroup("dummy", CONFIGURATION_SCOPE, ("dummy_read",))
    )
    monkeypatch.setitem(server.GROUP_REGISTRARS, "dummy", greedy)
    with pytest.raises(RuntimeError, match="differ from its declaration"):
        Harness(make_settings(enabled_tool_groups="dummy"))
