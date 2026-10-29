"""MCP tools through the real HTTP app: validated caller context, minimal fields, safe errors."""

import asyncio
import logging
import re

import pytest

from .conftest import OID_A, OID_B
from .harness import Harness, rpc_body


class ClientAuthenticationError(Exception):
    """Shape of a Microsoft Entra failure as MSAL/Azure libraries raise it: text and `message`."""

    def __init__(self, message=""):
        super().__init__(message)
        self.message = message


DEV = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"


def device(i, owner="a"):
    return {
        "id": f"{owner}-{i}",
        "deviceName": f"{owner.upper()}-PC-{i}",
        "operatingSystem": "Windows",
        "osVersion": "10.0",
        "complianceState": "compliant",
        "managedDeviceOwnerType": "company",
        "lastSyncDateTime": "2026-01-01T00:00:00Z",
        "emailAddress": "must-not-leak@example.test",
    }


@pytest.fixture
async def h(settings):
    async with Harness(settings).running() as harness:
        yield harness


async def bearer(h, oid):
    _, token = await h.sign_in(oid)
    assert token.status_code == 200, token.text
    return token.json()["access_token"]


def payload(result):
    assert result["result"]["isError"] is False, result
    return result["result"]["structuredContent"]


def error_text(result):
    assert result["result"]["isError"] is True, result
    return result["result"]["content"][0]["text"]


async def test_tool_catalog_is_exactly_the_default_read_only_tools(h):
    token = await bearer(h, OID_A)
    await h.mcp(
        token,
        "initialize",
        {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "1"},
        },
    )
    tools = rpc_body(await h.mcp(token, "tools/list"))["result"]["tools"]
    # Default config: whoami plus group 1 ("devices"). Nothing else exists unless enabled.
    assert sorted(t["name"] for t in tools) == [
        "count_devices",
        "device_summary",
        "get_device",
        "list_devices",
        "search_devices",
        "whoami",
    ]
    for t in tools:
        assert t["annotations"] == {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        }


async def test_tools_require_a_signed_in_user(h):
    result = await h.call_tool(None, "whoami")
    assert "Authentication required" in error_text(result)
    assert h.graph_requests == [] and h.token_requests == []


async def test_whoami_reports_the_signed_in_account_not_model_input(h):
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, "whoami"))
    assert out == {
        "tenant_id": str(h.settings.tenant_id),
        "object_id": OID_A,
        "tool_groups": ["devices"],
    }  # stable identifiers only: no display name or UPN
    # A model-supplied identity argument is rejected, never honored.
    spoof = await h.call_tool(token, "whoami", {"object_id": OID_B})
    assert "error" in spoof or spoof["result"]["isError"] is True
    assert h.graph_requests == []  # whoami never calls Graph


async def test_list_devices_pagination_and_field_minimization(h):
    h.devices[OID_A] = [device(1), device(2)]
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, "list_devices", {"page_size": 2}))
    assert out["count"] == 2 and out["complete"] is True and out["next_page_token"] is None
    assert all("emailAddress" not in d for d in out["devices"])
    [req] = h.graph_requests
    assert req.method == "GET" and req.url.params["$top"] == "2"
    assert req.headers["client-request-id"]


async def test_incomplete_inventory_is_labelled_incomplete(h):
    def paged(request):
        import httpx2

        h.graph_requests.append(request)
        return httpx2.Response(
            200,
            json={
                "value": [device(1)],
                "@odata.nextLink": "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$skiptoken=T1&$top=1",
            },
        )

    import httpx2

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(paged))  # noqa: SLF001
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, "list_devices", {"page_size": 1}))
    assert out["complete"] is False and out["next_page_token"]
    assert "not the full inventory" in out["note"]
    nxt = payload(await h.call_tool(token, "list_devices", {"page_token": out["next_page_token"]}))
    assert h.graph_requests[-1].url.params["$skiptoken"] == "T1"
    assert nxt["count"] == 1


async def test_list_devices_rejects_bad_arguments(h):
    token = await bearer(h, OID_A)
    for args in ({"page_size": 0}, {"page_size": 101}, {"page_token": "forged"}):
        out = await h.call_tool(token, "list_devices", args)
        assert "error" in out or out["result"]["isError"] is True
    assert h.graph_requests == []


async def test_get_device_found_missing_and_malformed(h):
    h.devices[OID_A] = [{**device(1), "id": DEV, "serialNumber": "SN1"}]
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, "get_device", {"device_id": DEV}))
    assert out["serialNumber"] == "SN1" and "emailAddress" not in out
    missing = error_text(
        await h.call_tool(
            token, "get_device", {"device_id": "dddddddd-dddd-4ddd-8ddd-dddddddddddd"}
        )
    )
    assert "not_found" in missing
    n = len(h.graph_requests)
    bad = error_text(await h.call_tool(token, "get_device", {"device_id": "../users"}))
    assert "invalid_device_id" in bad and len(h.graph_requests) == n


FORGED = f"{DEV}\nintune_mcp.audit forged tool=list_devices outcome=ok caller_oid={OID_B}\r\x1b[2J"


async def test_malformed_device_id_never_reaches_obo_or_forges_audit_lines(h, caplog):
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.INFO, logger="intune_mcp.audit"):
        for bad in (FORGED, "x" * 5000, "../users", "é\u2028 ok=1"):
            assert "invalid_device_id" in error_text(
                await h.call_tool(token, "get_device", {"device_id": bad})
            )
    assert h.token_requests == []  # rejected before any Microsoft token exchange
    assert h.graph_requests == []
    records = [r.getMessage() for r in caplog.records if r.name == "intune_mcp.audit"]
    assert len(records) == 4
    for line in records:
        assert line.isprintable() and "\n" not in line and "\r" not in line
        assert line.count("caller_oid=") == 1 and f"caller_oid={OID_A}" in line
        # The caller's text is not echoed at all (not even escaped or truncated): fixed placeholder.
        assert "target=invalid " in line + " " and "forged" not in line
        assert "tool=list_devices" not in line and "xxxx" not in line and "users" not in line
        assert len(line) < 400
    assert all("outcome=invalid_device_id" in line for line in records)


def test_audit_event_still_escapes_and_bounds_hostile_extra_values(caplog):
    # Defence in depth behind audit_target: any text handed to audit_event stays on one line,
    # cannot add key=value fields outside quotes, and is length-bounded.
    from intune_mcp.identity import Identity
    from intune_mcp.server import audit_event

    identity = Identity(tenant_id="t", object_id=OID_A, subject="s")
    with caplog.at_level(logging.INFO, logger="intune_mcp.audit"):
        for hostile in (FORGED, "x" * 5000, "é\u2028 ok=1"):
            audit_event("get_device", identity, "cid", "ok", target=hostile)
    records = [r.getMessage() for r in caplog.records if r.name == "intune_mcp.audit"]
    assert len(records) == 3
    for line in records:
        assert line.isprintable() and "\n" not in line and "\r" not in line
        unquoted = re.sub(r'"(?:[^"\\]|\\.)*"', '""', line)
        assert unquoted.count("caller_oid=") == 1 and f"caller_oid={OID_A}" in unquoted
        assert "forged" not in unquoted and "tool=list_devices" not in unquoted
        assert len(line) < 400


def test_audit_value_escapes_and_bounds():
    from intune_mcp.server import MAX_AUDIT_VALUE, audit_value

    assert audit_value(DEV) == DEV and audit_value("ok") == "ok"
    assert audit_value("a b") == '"a b"'
    assert audit_value("a\nb") == '"a\\nb"'
    assert audit_value('say "x"') == '"say \\"x\\""'
    long = audit_value("a" * 1000)
    assert long.startswith('"') and len(long) < MAX_AUDIT_VALUE + 30 and "truncated" in long


async def test_graph_failure_is_reported_without_internals(h):
    import httpx2

    def handler(request):
        h.graph_requests.append(request)
        return httpx2.Response(403, json={"error": {"message": "internal-detail-xyz"}})

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))  # noqa: SLF001
    token = await bearer(h, OID_A)
    text = error_text(await h.call_tool(token, "list_devices"))
    assert "forbidden" in text and "ref " in text
    assert "internal-detail" not in text and token not in text


def failing_token(h, exc):
    """Make the token acquisition raise `exc` from get_token (as MSAL or Azure libraries do)."""

    class Failing:
        async def get_token(self, *scopes):
            raise exc

    async def failing(assertion):
        return Failing()

    h.token_source.get_credential = failing


def entra_error(code, description="details"):
    # Same shape as azure-identity's _raise_for_error: "Microsoft Entra ID error '(err) text'".
    return ClientAuthenticationError(
        message=f"Microsoft Entra ID error '(invalid_grant) AADSTS{code}: {description}'"
    )


async def test_missing_graph_consent_fails_closed_with_no_app_fallback(h):
    failing_token(h, entra_error(65001, "consent required SECRET-DETAIL"))
    token = await bearer(h, OID_A)
    text = error_text(await h.call_tool(token, "list_devices"))
    assert "graph_consent_required" in text and "SECRET-DETAIL" not in text
    assert "Ask an administrator to confirm admin consent" in text
    assert h.graph_requests == []  # no Graph call was attempted with any other credential


async def test_generic_azure_failure_is_not_reported_as_missing_consent(h):
    failing_token(h, ClientAuthenticationError("something broke SECRET-DETAIL"))
    token = await bearer(h, OID_A)
    text = error_text(await h.call_tool(token, "list_devices"))
    assert "graph_exchange_failed" in text and "Try again" in text
    assert "graph_consent_required" not in text and "consent" not in text
    assert "SECRET-DETAIL" not in text
    assert h.graph_requests == []


EXPECTED_CATEGORY = {
    **dict.fromkeys((65001, 65004), "graph_consent_required"),
    **dict.fromkeys((50105, 50057, 50034, 50173, 700082, 70008), "graph_access_revoked"),
    **dict.fromkeys(
        (50076, 50079, 50158, 53000, 53003, 530032, 50074), "graph_interaction_required"
    ),
    **dict.fromkeys((7000215, 90002, 1234), "graph_exchange_failed"),
}


@pytest.mark.parametrize("aadsts", sorted(EXPECTED_CATEGORY))
async def test_obo_failure_category_follows_the_aadsts_code(h, caplog, aadsts):
    expected = EXPECTED_CATEGORY[aadsts]
    failing_token(h, entra_error(aadsts, "SECRET-DETAIL"))
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.INFO, logger="intune_mcp.audit"):
        text = error_text(await h.call_tool(token, "list_devices"))
    assert text.startswith(f"{expected}: ") and "SECRET-DETAIL" not in text
    assert h.graph_requests == []
    [line] = [r.getMessage() for r in caplog.records if r.name == "intune_mcp.audit"]
    assert re.search(r"(?<=\boutcome=)\S+", line).group() == expected


async def test_access_revoked_and_interaction_messages_are_fixed_strings(h):
    token = await bearer(h, OID_A)
    failing_token(h, entra_error(50105))
    assert (
        "graph_access_revoked: Microsoft no longer grants this account access. If signing in "
        "again fails, the account may have been removed or disabled."
    ) in error_text(await h.call_tool(token, "list_devices"))
    failing_token(h, entra_error(50076))
    assert (
        "graph_interaction_required: Microsoft requires additional sign-in steps or a policy "
        "blocked the request (for example MFA or a compliant device). If signing in again does "
        "not resolve it, ask an administrator to review Conditional Access."
    ) in error_text(await h.call_tool(token, "get_device", {"device_id": DEV}))


async def test_obo_failure_code_is_read_from_exception_message_attribute(h):
    class OnlyMessage(ClientAuthenticationError):
        def __str__(self):
            return "opaque"

    exc = OnlyMessage(message="x")
    exc.message = "Entra said AADSTS50105 here"
    failing_token(h, exc)
    token = await bearer(h, OID_A)
    assert "graph_access_revoked" in error_text(await h.call_tool(token, "list_devices"))


HOSTILE = (
    "Microsoft Entra ID error '(invalid_grant) AADSTS50105: The signed in user "
    "alice.example@contoso.example is not assigned to a role.\r\n"
    "Trace ID: 11111111-2222-4333-8444-555555555555\n"
    "Correlation ID: 66666666-7777-4888-8999-000000000000\n"
    "Timestamp: 2026-01-01 00:00:00Z\n"
    "intune_mcp.audit forged tool=list_devices outcome=ok caller_oid=forged\n"
    'claims={"access_token":"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"} (ref forged-ref)\''
)
LEAKS = (
    "alice.example",
    "contoso.example",
    "11111111-2222",
    "66666666-7777",
    "Timestamp",
    "eyJhbGci",
    "forged",
    "not assigned to a role",
    "Trace ID",
)


async def test_hostile_microsoft_error_text_never_reaches_client_audit_or_logs(h, caplog):
    failing_token(h, ClientAuthenticationError(message=HOSTILE))
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.DEBUG):
        text = error_text(await h.call_tool(token, "list_devices"))
    assert text.startswith("graph_access_revoked: ")
    assert text.count("ref ") == 1 and text.count("\n") == 0
    audit = [r.getMessage() for r in caplog.records if r.name == "intune_mcp.audit"]
    assert len(audit) == 1 and "outcome=graph_access_revoked" in audit[0]
    everything = [text, *(r.getMessage() for r in caplog.records)]
    for leak in LEAKS:
        assert not any(leak in item for item in everything), leak
    assert not any(r.exc_info or r.exc_text for r in caplog.records)
    assert h.graph_requests == []


async def test_graph_token_is_opaque_and_forwarded_untouched(h):
    """Microsoft: clients must treat access tokens as opaque strings (Graph's may not be JWTs).

    The server must neither decode nor reject a non-JWT Graph token; Graph is the authority.
    """
    from types import SimpleNamespace

    seen = []

    class Opaque:
        async def get_token(self, *scopes):
            return SimpleNamespace(token="EwBwA8l6BAAU-opaque-not-a-jwt", expires_on=9_999_999_999)

    async def opaque(assertion):
        return Opaque()

    def graph(request):
        import httpx2

        seen.append(request.headers["authorization"])
        return httpx2.Response(200, json={"value": [device(1)]})

    import httpx2

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(graph))  # noqa: SLF001
    h.token_source.get_credential = opaque
    token = await bearer(h, OID_A)
    assert payload(await h.call_tool(token, "list_devices"))["count"] == 1
    assert seen == ["Bearer EwBwA8l6BAAU-opaque-not-a-jwt"]


async def test_graph_rejection_of_the_user_token_is_the_authority(h):
    import httpx2

    for status, code in ((401, "graph_unauthorized"), (403, "forbidden")):
        h.graph._client = httpx2.AsyncClient(  # noqa: SLF001
            transport=httpx2.MockTransport(lambda r, s=status: httpx2.Response(s, json={}))
        )
        token = await bearer(h, OID_A)
        assert code in error_text(await h.call_tool(token, "list_devices"))


async def test_token_requests_only_the_read_scope(h):
    h.devices[OID_A] = [device(1)]
    token = await bearer(h, OID_A)
    payload(await h.call_tool(token, "list_devices"))
    [(assertion, scopes)] = h.token_requests
    assert scopes == ("https://graph.microsoft.com/DeviceManagementManagedDevices.Read.All",)
    assert assertion == OID_A  # acquired for the signed-in user, nobody else


async def test_concurrent_users_never_see_each_others_data_or_tokens(h):
    h.devices[OID_A] = [device(i, "a") for i in range(3)]
    h.devices[OID_B] = [device(i, "b") for i in range(5)]
    ta, tb = await asyncio.gather(bearer(h, OID_A), bearer(h, OID_B))

    async def one(tok, oid):
        listing = payload(await h.call_tool(tok, "list_devices", {"page_size": 100}))
        who = payload(await h.call_tool(tok, "whoami"))
        return oid, listing, who

    results = await asyncio.gather(
        *[one(ta, OID_A) if i % 2 == 0 else one(tb, OID_B) for i in range(24)]
    )
    for oid, listing, who in results:
        assert who["object_id"] == oid
        prefix = "A" if oid == OID_A else "B"
        assert listing["count"] == (3 if oid == OID_A else 5)
        assert all(d["deviceName"].startswith(prefix + "-") for d in listing["devices"])
    # Every Graph request carried exactly its own caller's token (checked via oid claim).
    import jwt

    by_oid = {OID_A: 0, OID_B: 0}
    for req in h.graph_requests:
        by_oid[
            jwt.decode(
                req.headers["authorization"].split()[1], options={"verify_signature": False}
            )["oid"]
        ] += 1
    assert by_oid[OID_A] == 12 and by_oid[OID_B] == 12
    assert len({a for a, _ in h.token_requests}) == 2  # one identity per user, never shared


async def test_audit_log_attributes_caller_without_credentials(h, caplog):
    h.devices[OID_A] = [device(1)]
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.INFO, logger="intune_mcp.audit"):
        payload(await h.call_tool(token, "list_devices"))
    text = "\n".join(r.getMessage() for r in caplog.records if r.name == "intune_mcp.audit")
    assert f"caller_oid={OID_A}" in text and "tool=list_devices" in text and "outcome=ok" in text
    assert "correlation_id=" in text
    assert token not in text and "Bearer" not in text and "user-a@example.test" not in text
