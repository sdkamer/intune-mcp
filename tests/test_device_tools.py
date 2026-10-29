"""Tool group 1 (`devices`) through the real HTTP app. Entra and Graph are mocked."""

import asyncio
import logging
import re
import uuid
from datetime import UTC, datetime

import httpx2
import jwt
import pytest

from intune_mcp.config import GRAPH_SCOPE

from .conftest import OID_A, OID_B
from .harness import Harness, rpc_body

NOW = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)
LEAK = "must-not-leak@example.test"


def guid(owner: str, i: int) -> str:
    return str(uuid.UUID(int=(ord(owner) << 24) + i))


def device(i, owner="a", **overrides):
    row = {
        "id": guid(owner, i),
        "deviceName": f"{owner.upper()}-PC-{i}",
        "operatingSystem": "Windows",
        "osVersion": "10.0",
        "complianceState": "compliant",
        "managedDeviceOwnerType": "company",
        "lastSyncDateTime": "2026-02-27T00:00:00Z",
        "userPrincipalName": f"user{i}@example.test",
        "emailAddress": LEAK,
        "imei": "123456789012345",
        "phoneNumber": "555-0100",
        "managementState": "managed",
        "serialNumber": f"SN{i}",
    }
    row.update(overrides)
    return row


@pytest.fixture
async def h(settings):
    async with Harness(settings).running() as harness:
        harness.graph._clock = lambda: NOW  # noqa: SLF001
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


def names(out):
    return sorted(d["deviceName"] for d in out["devices"])


def last_filter(h):
    return h.graph_requests[-1].url.params.get("$filter")


FLEET = [
    device(1, operatingSystem="Windows", complianceState="compliant"),
    device(2, operatingSystem="Windows", complianceState="noncompliant"),
    device(3, operatingSystem="macOS", managedDeviceOwnerType="personal"),
    device(4, operatingSystem="iOS", complianceState="inGracePeriod"),
    device(5, deviceName="LAB-5", lastSyncDateTime="2026-01-01T00:00:00Z"),
    device(6, userPrincipalName="Tech.Person@example.test", complianceState="noncompliant"),
]


# -- search_devices ----------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("args", "expected", "odata"),
    [
        ({"name_prefix": "A-PC"}, ["A-PC-1", "A-PC-2", "A-PC-3", "A-PC-4", "A-PC-6"], None),
        ({"name_prefix": "LAB"}, ["LAB-5"], "startswith(deviceName,'LAB')"),
        ({"operating_system": "macOS"}, ["A-PC-3"], "operatingSystem eq 'macOS'"),
        (
            {"compliance_state": "noncompliant"},
            ["A-PC-2", "A-PC-6"],
            "complianceState eq 'noncompliant'",
        ),
        ({"ownership": "personal"}, ["A-PC-3"], "managedDeviceOwnerType eq 'personal'"),
        (
            {"not_synced_days": 30},
            ["LAB-5"],
            "lastSyncDateTime lt 2026-01-30T12:00:00Z",
        ),
        (
            {"assigned_user": "tech.person@example.test"},
            ["A-PC-6"],
            "userPrincipalName eq 'tech.person@example.test'",
        ),
        (
            {"operating_system": "Windows", "compliance_state": "noncompliant"},
            ["A-PC-2", "A-PC-6"],
            "operatingSystem eq 'Windows' and complianceState eq 'noncompliant'",
        ),
        (
            {"name_prefix": "A-PC", "ownership": "company", "compliance_state": "compliant"},
            ["A-PC-1"],
            "startswith(deviceName,'A-PC') and complianceState eq 'compliant'"
            " and managedDeviceOwnerType eq 'company'",
        ),
        ({"name_prefix": "NOPE"}, [], "startswith(deviceName,'NOPE')"),
    ],
)
async def test_search_applies_each_filter_and_combines_with_and(h, args, expected, odata):
    h.devices[OID_A] = FLEET
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, "search_devices", args))
    assert names(out) == expected and out["count"] == len(expected)
    assert out["complete"] is True and out["next_page_token"] is None and out["note"] is None
    if odata:
        assert last_filter(h) == odata
    # Same shape and minimisation as list_devices; nothing from the extra Graph fields leaks.
    assert set(out) == {"devices", "count", "next_page_token", "complete", "note"}
    for d in out["devices"]:
        assert set(d) == {
            "id",
            "deviceName",
            "operatingSystem",
            "osVersion",
            "complianceState",
            "managedDeviceOwnerType",
            "lastSyncDateTime",
        }
    assert LEAK not in str(out)


async def test_search_with_no_filter_equals_list_devices(h):
    h.devices[OID_A] = FLEET
    token = await bearer(h, OID_A)
    listed = payload(await h.call_tool(token, "list_devices", {"page_size": 100}))
    searched = payload(await h.call_tool(token, "search_devices", {"page_size": 100}))
    assert searched == listed and searched["count"] == 6
    assert h.graph_requests[-1].url.params.get("$filter") is None
    empty = payload(await h.call_tool(token, "search_devices", {}))
    assert empty["count"] == 6  # default page size


async def test_search_pagination_keeps_filters_and_ignores_new_arguments(h):
    h.devices[OID_A] = [device(i, complianceState="noncompliant") for i in range(1, 6)] + [
        device(i, complianceState="compliant") for i in range(6, 9)
    ]
    token = await bearer(h, OID_A)
    out = payload(
        await h.call_tool(
            token,
            "search_devices",
            {"compliance_state": "noncompliant", "name_prefix": "A-PC", "page_size": 2},
        )
    )
    seen = list(names(out))
    assert out["complete"] is False and "not the full inventory" in out["note"]
    first_filter = last_filter(h)
    assert first_filter == ("startswith(deviceName,'A-PC') and complianceState eq 'noncompliant'")
    pages = 1
    while out["next_page_token"]:
        out = payload(
            await h.call_tool(
                token,
                "search_devices",
                {
                    "page_token": out["next_page_token"],
                    # all ignored: the token's own filters and page size apply
                    "compliance_state": "compliant",
                    "name_prefix": "WRONG",
                    "assigned_user": "someone@example.test",
                    "page_size": 100,
                },
            )
        )
        assert last_filter(h) == first_filter
        assert h.graph_requests[-1].url.params["$top"] == "2"
        seen += names(out)
        pages += 1
    assert pages == 3 and seen == [f"A-PC-{i}" for i in range(1, 6)]


async def test_not_synced_cutoff_comes_from_the_server_clock_not_the_model(h):
    h.devices[OID_A] = FLEET
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, "search_devices", {"not_synced_days": 3650}))
    assert out["count"] == 0
    assert last_filter(h) == "lastSyncDateTime lt 2016-03-03T12:00:00Z"
    h.graph._clock = lambda: datetime(2026, 3, 11, 12, 0, 0, tzinfo=UTC)  # noqa: SLF001
    out = payload(await h.call_tool(token, "search_devices", {"not_synced_days": 7}))
    assert last_filter(h) == "lastSyncDateTime lt 2026-03-04T12:00:00Z"
    assert names(out) == ["A-PC-1", "A-PC-2", "A-PC-3", "A-PC-4", "A-PC-6", "LAB-5"]


ATTACKS = [
    "x' or '1'='1",
    "x'",
    "x') or (deviceName ne 'y",
    "x%27 or 1",
    "x’ or ‘y",
    "＇",
    "x\ny",
    "x\x00y",
    "x" * 5000,
    "",
    "a b c d e f g h i j k l m n o p q r s t u v w x y z a b c d e f g h",
]
STRING_ARGS = ["name_prefix", "operating_system", "compliance_state", "ownership", "assigned_user"]


@pytest.mark.parametrize(
    ("tool", "arg"),
    [
        (tool, arg)
        for tool in ("search_devices", "count_devices")
        for arg in STRING_ARGS
        if (tool, arg) != ("count_devices", "compliance_state")  # not a count_devices argument
    ],
)
async def test_invalid_filters_are_rejected_before_any_exchange_or_graph_call(h, tool, arg):
    token = await bearer(h, OID_A)
    for bad in ATTACKS:
        if arg == "operating_system" and re.fullmatch(r"[A-Za-z0-9 ().-]{1,40}", bad):
            continue  # legitimately allowed text (spaces/letters), inert inside its literal
        text = error_text(await h.call_tool(token, tool, {arg: bad}))
        assert text.startswith(f"invalid_filter: {arg} is not valid") and "(ref " in text
        assert bad not in text or bad == ""
    assert h.token_requests == [] and h.graph_requests == []


@pytest.mark.parametrize("tool", ["search_devices", "count_devices"])
@pytest.mark.parametrize("bad", [0, -1, 3651, 10**12])
async def test_out_of_range_not_synced_days_is_rejected_in_tool_before_microsoft(h, tool, bad):
    # Integers pass the schema; the range is enforced by our own validation (invalid_filter).
    token = await bearer(h, OID_A)
    text = error_text(await h.call_tool(token, tool, {"not_synced_days": bad}))
    assert text.startswith(
        "invalid_filter: not_synced_days is not valid: an integer from 1 to 3650"
    )
    assert "(ref " in text
    assert h.token_requests == [] and h.graph_requests == []


@pytest.mark.parametrize("tool", ["search_devices", "count_devices"])
@pytest.mark.parametrize("bad", [True, False, "7", "abc", 1.5, [1]])
async def test_type_confused_not_synced_days_is_rejected_by_the_schema_before_microsoft(
    h, tool, bad
):
    # Strict integer schema: the tool body (and so our validation and audit) never runs.
    token = await bearer(h, OID_A)
    text = error_text(await h.call_tool(token, tool, {"not_synced_days": bad}))
    assert text.startswith("1 validation error for call[")
    assert "Input should be a valid integer [type=int_type" in text
    assert "invalid_filter" not in text and "(ref " not in text
    assert h.token_requests == [] and h.graph_requests == []


async def test_invalid_page_token_on_search_is_rejected_before_exchange(h):
    token = await bearer(h, OID_A)
    text = error_text(await h.call_tool(token, "search_devices", {"page_token": "forged"}))
    assert text.startswith("invalid_page_token: ")
    assert h.token_requests == [] and h.graph_requests == []


async def test_page_tokens_do_not_cross_tools(h):
    h.devices[OID_A] = [device(i) for i in range(1, 6)]
    token = await bearer(h, OID_A)
    listed = payload(await h.call_tool(token, "list_devices", {"page_size": 2}))
    searched = payload(await h.call_tool(token, "search_devices", {"page_size": 2}))
    n_graph, n_tokens = len(h.graph_requests), len(h.token_requests)
    for tool, foreign in (("search_devices", listed), ("list_devices", searched)):
        text = error_text(
            await h.call_tool(token, tool, {"page_token": foreign["next_page_token"]})
        )
        assert text.startswith("invalid_page_token: ")
    assert (len(h.graph_requests), len(h.token_requests)) == (n_graph, n_tokens)


async def test_search_is_acceptable_with_pydantic_level_type_errors_and_no_calls(h):
    token = await bearer(h, OID_A)
    for args in (
        {"name_prefix": 5},
        {"ownership": ["company"]},
        {"page_size": 0},
        {"page_size": 101},
    ):
        out = await h.call_tool(token, "search_devices", args)
        assert "error" in out or out["result"]["isError"] is True
    assert h.token_requests == [] and h.graph_requests == []


async def tool_schemas(h, token):
    init = {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "t", "version": "1"},
    }
    await h.mcp(token, "initialize", init)
    listed = rpc_body(await h.mcp(token, "tools/list"))["result"]["tools"]
    return {t["name"]: t for t in listed}


# -- count_devices -----------------------------------------------------------------------------
async def test_count_devices_counts_scoped_rows_and_returns_no_ids(h):
    h.devices[OID_A] = FLEET
    token = await bearer(h, OID_A)
    assert payload(await h.call_tool(token, "count_devices")) == {
        "count": 6,
        "complete": True,
        "note": None,
    }
    assert payload(await h.call_tool(token, "count_devices", {"ownership": "personal"})) == {
        "count": 1,
        "complete": True,
        "note": None,
    }
    req = h.graph_requests[-1]
    assert (req.url.params["$select"], req.url.params["$top"]) == ("id", "100")
    assert req.url.params["$filter"] == "managedDeviceOwnerType eq 'personal'"
    assert "$count" not in req.url.params
    zero = payload(await h.call_tool(token, "count_devices", {"name_prefix": "NOPE"}))
    assert zero == {"count": 0, "complete": True, "note": None}
    assert LEAK not in str(zero)


@pytest.mark.parametrize("value", ["noncompliant", "compliant", "configManager", "x' or 1 eq 1"])
async def test_count_devices_has_no_compliance_state_argument(h, caplog, value):
    """Live, count_devices(compliance_state=...) returned 0 for every value: the parameter is gone.

    The schema refuses it before the tool runs: no token acquisition, no Graph call, no audit line.
    """
    h.devices[OID_A] = FLEET
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.DEBUG, logger="intune_mcp.audit"):
        text = error_text(await h.call_tool(token, "count_devices", {"compliance_state": value}))
    assert text.startswith("1 validation error for call[count_devices]")
    assert "unexpected_keyword_argument" in text and "(ref " not in text
    assert h.token_requests == [] and h.graph_requests == []
    assert audit_lines(caplog) == []
    schema = await tool_schemas(h, token)
    assert "compliance_state" not in schema["count_devices"]["inputSchema"]["properties"]
    assert "compliance_state" in schema["search_devices"]["inputSchema"]["properties"]


async def test_search_devices_documents_that_the_compliance_filter_is_unreliable(h):
    token = await bearer(h, OID_A)
    schema = await tool_schemas(h, token)
    text = schema["search_devices"]["inputSchema"]["properties"]["compliance_state"]["description"]
    assert "configManager" in text and "trust each row's complianceState" in text
    description = schema["count_devices"]["description"]
    assert "No compliance filter" in description
    assert "get_compliance_summary" in description
    assert "visible to you" in description and "5000" in description and "at least" in description


# -- device_summary ----------------------------------------------------------------------------
async def test_device_summary_is_aggregate_counts_only(h):
    h.overview[OID_A] = {
        "id": "x",
        "enrolledDeviceCount": 12,
        "mdmEnrolledCount": 10,
        "dualEnrolledDeviceCount": 2,
        "deviceOperatingSystemSummary": {
            "windowsCount": 7,
            "iosCount": 3,
            "macOSCount": 1,
            "androidCount": 1,
            "windowsMobileCount": 0,
            "unknownCount": 0,
            "ownerNames": LEAK,
        },
        "ownerEmail": LEAK,
    }
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, "device_summary"))
    assert out == {
        "enrolledDeviceCount": 12,
        "mdmEnrolledCount": 10,
        "dualEnrolledDeviceCount": 2,
        "deviceOperatingSystemSummary": {
            "androidCount": 1,
            "iosCount": 3,
            "macOSCount": 1,
            "windowsMobileCount": 0,
            "windowsCount": 7,
            "unknownCount": 0,
        },
    }
    assert LEAK not in str(out)
    assert h.graph_requests[-1].url.path == "/v1.0/deviceManagement/managedDeviceOverview"
    assert h.graph_requests[-1].method == "GET"


async def test_device_summary_rejects_arguments(h):
    token = await bearer(h, OID_A)
    out = await h.call_tool(token, "device_summary", {"device_id": guid("a", 1)})
    assert "error" in out or out["result"]["isError"] is True
    assert h.graph_requests == []


# -- per-device state fixtures (the tools themselves are group 2: test_configuration_tools.py) --
def state_row(i):
    return {
        "displayName": f"Policy {i}",
        "platformType": "windows10AndLater",
        "state": "compliant",
        "settingCount": i,
        "version": i,
        "userPrincipalName": LEAK,
        "userId": "u-1",
        "id": f"row-{i}",
        "settingStates": [{"setting": "x"}],
    }


# -- scope, isolation, audit, errors ---------------------------------------------------------
def prime(h, oid="a"):
    owner = oid
    d = device(1, owner)
    h.devices[OID_A if owner == "a" else OID_B] = [d]
    h.overview[OID_A if owner == "a" else OID_B] = {"enrolledDeviceCount": 1}
    h.children[OID_A if owner == "a" else OID_B] = {
        (d["id"], "deviceCompliancePolicyStates"): [state_row(1)],
        (d["id"], "deviceConfigurationStates"): [state_row(1)],
    }
    return d


def all_calls(d):
    return [
        ("list_devices", {}),
        ("get_device", {"device_id": d["id"]}),
        ("search_devices", {"name_prefix": "A"}),
        ("count_devices", {"ownership": "company"}),
        ("device_summary", {}),
    ]


async def test_every_devices_tool_requests_exactly_its_one_declared_scope(h):
    d = prime(h)
    token = await bearer(h, OID_A)
    for tool, args in all_calls(d):
        before = len(h.token_requests)
        payload(await h.call_tool(token, tool, args))
        new = h.token_requests[before:]
        assert len(new) == 1, tool  # one exchange per call
        assert new[0][1] == (GRAPH_SCOPE,), tool
        assert ".default" not in new[0][1][0]
        # The mocked Graph token carries only the requested scope (and Graph accepted it).
        bearer_token = h.graph_requests[-1].headers["authorization"].split()[1]
        assert (
            jwt.decode(bearer_token, options={"verify_signature": False})["scp"]
            == (GRAPH_SCOPE.rsplit("/", 1)[1])
        )
    assert all(len(scopes) == 1 for _, scopes in h.token_requests)


async def test_tools_are_read_only_get_only(h):
    d = prime(h)
    token = await bearer(h, OID_A)
    for tool, args in all_calls(d):
        payload(await h.call_tool(token, tool, args))
    assert {r.method for r in h.graph_requests} == {"GET"}


async def test_two_users_interleaved_across_the_new_tools_never_mix(h):
    da, db = prime(h, "a"), prime(h, "b")
    h.devices[OID_A] = [device(i, "a") for i in range(1, 4)]
    h.devices[OID_A][0] = da
    h.devices[OID_B] = [device(i, "b") for i in range(1, 6)]
    h.devices[OID_B][0] = db
    ta, tb = await asyncio.gather(bearer(h, OID_A), bearer(h, OID_B))

    async def one(tok, oid, owner, dev, i):
        search = payload(
            await h.call_tool(
                tok, "search_devices", {"name_prefix": owner.upper(), "page_size": 100}
            )
        )
        count = payload(await h.call_tool(tok, "count_devices", {"name_prefix": owner.upper()}))
        one_device = payload(await h.call_tool(tok, "get_device", {"device_id": dev["id"]}))
        return oid, owner, search, count, one_device

    jobs = [
        one(ta, OID_A, "a", da, i) if i % 2 == 0 else one(tb, OID_B, "b", db, i) for i in range(24)
    ]
    results = await asyncio.gather(*jobs)
    for oid, owner, search, count, one_device in results:
        expected = 3 if oid == OID_A else 5
        assert search["count"] == expected == count["count"]
        assert all(d["deviceName"].startswith(owner.upper() + "-") for d in search["devices"])
        assert one_device["id"] == (da if oid == OID_A else db)["id"]
    # Each Graph request carried exactly its own caller's token; 12 jobs x 3 calls per user.
    by_oid = {OID_A: 0, OID_B: 0}
    for req in h.graph_requests:
        claims = jwt.decode(
            req.headers["authorization"].split()[1], options={"verify_signature": False}
        )
        by_oid[claims["oid"]] += 1
        # A device GUID of one user never appears in the other's requests.
        other = db["id"] if claims["oid"] == OID_A else da["id"]
        assert other not in str(req.url)
    assert by_oid == {OID_A: 36, OID_B: 36}
    assert len({a for a, _ in h.token_requests}) == 2
    assert all(scopes == (GRAPH_SCOPE,) for _, scopes in h.token_requests)


async def test_user_cannot_read_a_device_they_cannot_see(h):
    da, db = prime(h, "a"), prime(h, "b")
    tb = await bearer(h, OID_B)
    out = error_text(await h.call_tool(tb, "get_device", {"device_id": da["id"]}))
    assert out.startswith("not_found: No matching managed device is visible to this user")
    assert db["id"] != da["id"]


@pytest.fixture
def startup_log_policy():
    """Apply the startup logger policy (it silences the httpx request-URL log, which carries
    OData filter values) without starting a server; loggers are restored afterwards."""
    from intune_mcp import local

    names = ("httpx", "httpcore", "httpx2", "httpcore2", "msal", "requests")
    saved = {n: logging.getLogger(n).level for n in names}
    root_level = logging.getLogger().level
    local.configure_logging()
    yield
    for n, level in saved.items():
        logging.getLogger(n).setLevel(level)
    logging.getLogger().setLevel(root_level)


async def test_audit_logs_filter_field_names_and_counts_never_values(h, caplog, startup_log_policy):
    secret_user, secret_prefix = "tech.secret@example.test", "SECRETPREFIX"
    h.devices[OID_A] = [device(1, userPrincipalName=secret_user, deviceName=secret_prefix + "-1")]
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.INFO):  # main() runs at INFO; DEBUG would log SSE bodies
        ok = payload(
            await h.call_tool(
                token,
                "search_devices",
                {"assigned_user": secret_user, "name_prefix": secret_prefix},
            )
        )
        payload(await h.call_tool(token, "count_devices", {"assigned_user": secret_user}))
        bad = error_text(
            await h.call_tool(
                token,
                "search_devices",
                {"assigned_user": secret_user + "'", "ownership": "company"},
            )
        )
        error_text(await h.call_tool(token, "count_devices", {"name_prefix": secret_prefix + "'"}))
    assert ok["count"] == 1
    records = [r.getMessage() for r in caplog.records]
    audit = [m for m in records if m.startswith("tool=")]
    assert len(audit) == 4
    for line in records:  # not in the audit lines, nor anywhere else that was logged
        assert secret_user not in line and secret_prefix not in line, line
    assert secret_user not in bad
    search_ok, count_ok, search_bad, count_bad = audit
    assert "tool=search_devices" in search_ok and "outcome=ok" in search_ok
    assert 'filters="name_prefix,assigned_user"' in search_ok and "returned=1" in search_ok
    assert "tool=count_devices" in count_ok and "filters=assigned_user" in count_ok
    assert "count=1" in count_ok
    assert (
        "outcome=invalid_filter" in search_bad and 'filters="ownership,assigned_user"' in search_bad
    )
    assert "outcome=invalid_filter" in count_bad and "filters=name_prefix" in count_bad
    for line in audit:
        assert f"caller_oid={OID_A}" in line and "correlation_id=" in line
        assert line.isprintable()


PER_DEVICE_TOOLS = ["get_device"]
# Text a caller or model might put in device_id: none of it may reach any log line.
HOSTILE_DEVICE_IDS = {
    "upn": "private.person@example.test",
    "display_name": "Jane Q. Private's Laptop",
    "long": "SECRETLONG" + "x" * 400,
    "token": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnLXNFQ1JFVFRPS0VO",
    "forging": f"{guid('a', 1)}\nintune_mcp.audit forged outcome=ok SECRETFORGE",
    "traversal": "../users/SECRETPATH",
}
HOSTILE_MARKERS = (
    "private.person",
    "Jane",
    "Laptop",
    "SECRETLONG",
    "xxxxxxxxxx",
    "eyJhbGci",
    "SECRETTOKEN",
    "SECRETFORGE",
    "forged",
    "SECRETPATH",
    "users",
)


def audit_lines(caplog):
    return [r.getMessage() for r in caplog.records if r.name == "intune_mcp.audit"]


@pytest.mark.parametrize("tool", PER_DEVICE_TOOLS)
@pytest.mark.parametrize("kind", list(HOSTILE_DEVICE_IDS))
async def test_invalid_device_id_text_never_reaches_any_log(h, caplog, tool, kind):
    token = await bearer(h, OID_A)
    # Root-propagating loggers at DEBUG (not only the audit one). FastMCP's own non-propagating
    # logger and exception tracebacks are NOT captured here; see docs/VERIFICATION.md.
    with caplog.at_level(logging.DEBUG):
        error_text(await h.call_tool(token, tool, {"device_id": HOSTILE_DEVICE_IDS[kind]}))
    [line] = audit_lines(caplog)
    assert f"tool={tool}" in line and "outcome=invalid_device_id" in line
    assert "target=invalid " in line + " "  # fixed placeholder, not the supplied text
    everything = "\n".join(r.getMessage() for r in caplog.records)
    for marker in HOSTILE_MARKERS:
        assert marker not in everything, marker
    assert token not in everything
    assert h.token_requests == [] and h.graph_requests == []


@pytest.mark.parametrize("tool", PER_DEVICE_TOOLS)
async def test_a_valid_device_id_is_audited_in_canonical_form_only(h, caplog, tool):
    d = prime(h)
    token = await bearer(h, OID_A)
    spelled = "{" + d["id"] + "}"  # accepted by the GUID parser, not canonical text
    with caplog.at_level(logging.INFO):
        payload(await h.call_tool(token, tool, {"device_id": spelled}))
        error_text(await h.call_tool(token, tool, {"device_id": guid("z", 9)}))  # not_found
    ok, missing = audit_lines(caplog)
    assert f"target={d['id']}" in ok and "outcome=ok" in ok
    assert f"target={guid('z', 9)}" in missing and "outcome=not_found" in missing
    assert "{" not in ok and "}" not in ok


async def test_page_token_text_never_reaches_a_log_on_any_paged_tool(h, caplog):
    token = await bearer(h, OID_A)
    bad = "SECRETTOKEN-forged"
    with caplog.at_level(logging.DEBUG):
        for tool, args in (
            ("list_devices", {}),
            ("search_devices", {"name_prefix": "SECRETPREFIX"}),
        ):
            error_text(await h.call_tool(token, tool, {**args, "page_token": bad}))
    everything = "\n".join(r.getMessage() for r in caplog.records)
    assert "SECRETTOKEN" not in everything and "SECRETPREFIX" not in everything
    assert len(audit_lines(caplog)) == 2
    assert h.token_requests == [] and h.graph_requests == []


async def test_audit_filter_names_are_those_actually_sent_for_paged_requests(h, caplog):
    h.devices[OID_A] = [device(i, complianceState="noncompliant") for i in range(1, 5)]
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.INFO, logger="intune_mcp.audit"):
        first = payload(
            await h.call_tool(
                token,
                "search_devices",
                {"compliance_state": "noncompliant", "name_prefix": "A-PC", "page_size": 2},
            )
        )
        # Subsequent page: only the token. The token's filters are what Graph receives.
        second = payload(
            await h.call_tool(token, "search_devices", {"page_token": first["next_page_token"]})
        )
        # Spurious filters next to a page_token are ignored and must not be logged.
        payload(
            await h.call_tool(
                token,
                "search_devices",
                {
                    "page_token": first["next_page_token"],
                    "ownership": "personal",
                    "assigned_user": "ignored@example.test",
                },
            )
        )
        # A bad page token with spurious filters: nothing was planned, so none are named.
        error_text(
            await h.call_tool(
                token, "search_devices", {"page_token": "bad", "ownership": "personal"}
            )
        )
        # A bad first page names the arguments that were submitted for planning.
        error_text(await h.call_tool(token, "search_devices", {"ownership": "nope"}))
    assert second["complete"] is True
    lines = audit_lines(caplog)
    assert len(lines) == 5
    first_ok, second_ok, spurious_ok, bad_token, bad_first = lines
    assert 'filters="name_prefix,compliance_state"' in first_ok
    assert 'filters="name_prefix,compliance_state"' in second_ok
    assert 'filters="name_prefix,compliance_state"' in spurious_ok
    assert "ownership" not in spurious_ok and "assigned_user" not in spurious_ok
    assert "outcome=invalid_page_token" in bad_token and "filters=unresolved" in bad_token
    assert "ownership" not in bad_token
    assert "outcome=invalid_filter" in bad_first and "filters=ownership" in bad_first
    # What Graph received for the spurious call really is the token's filter, not the arguments.
    assert last_filter(h) == "startswith(deviceName,'A-PC') and complianceState eq 'noncompliant'"


async def test_a_graph_error_on_a_later_page_audits_the_token_filters_not_the_arguments(h, caplog):
    h.devices[OID_A] = [device(i) for i in range(1, 5)]
    token = await bearer(h, OID_A)
    first = payload(
        await h.call_tool(token, "search_devices", {"operating_system": "Windows", "page_size": 2})
    )
    h.graph._client = httpx2.AsyncClient(  # noqa: SLF001
        transport=httpx2.MockTransport(lambda r: httpx2.Response(500))
    )
    with caplog.at_level(logging.INFO, logger="intune_mcp.audit"):
        error_text(
            await h.call_tool(
                token,
                "search_devices",
                {"page_token": first["next_page_token"], "name_prefix": "SPURIOUS"},
            )
        )
    [line] = audit_lines(caplog)
    assert "outcome=upstream_error" in line and "filters=operating_system" in line
    assert "name_prefix" not in line and "SPURIOUS" not in line


async def test_an_internal_planning_invariant_error_is_audited_and_generic(h, caplog, monkeypatch):
    # A filter argument the endpoint spec does not declare is a programming error, not input.
    from intune_mcp import graph as graph_module

    real = graph_module.plan_read

    def broken(spec, **kwargs):
        return real(spec, **{**kwargs, "filters": {"undeclared_filter": "SECRETVALUE"}})

    monkeypatch.setattr(graph_module, "plan_read", broken)
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.DEBUG):
        text = error_text(await h.call_tool(token, "search_devices", {"ownership": "company"}))
    assert text.startswith("internal_error: The request could not be completed. (ref ")
    assert "undeclared" not in text and "SECRETVALUE" not in text
    ref = re.search(r"\(ref ([0-9a-f-]{36})\)", text).group(1)
    [line] = audit_lines(caplog)
    assert "outcome=internal_error" in line and "error_type=ValueError" in line
    assert f"correlation_id={ref}" in line and f"caller_oid={OID_A}" in line
    assert "tool=search_devices" in line and "target=managedDevices" in line
    everything = "\n".join(r.getMessage() for r in caplog.records)
    assert "SECRETVALUE" not in everything and "undeclared" not in everything
    assert h.token_requests == [] and h.graph_requests == []  # failed before any exchange


async def test_correlation_id_goes_to_graph_and_into_the_error_ref(h):
    def handler(request):
        h.graph_requests.append(request)
        return httpx2.Response(
            400, json={"error": {"message": "Bad $filter SECRET-GRAPH-BODY userPrincipalName"}}
        )

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))  # noqa: SLF001
    token = await bearer(h, OID_A)
    text = error_text(
        await h.call_tool(token, "search_devices", {"assigned_user": "tech.one@example.test"})
    )
    assert text.startswith("bad_request: Microsoft Graph rejected the query")
    ref = re.search(r"\(ref ([0-9a-f-]{36})\)", text).group(1)
    assert h.graph_requests[-1].headers["client-request-id"] == ref
    for leak in ("SECRET-GRAPH-BODY", "userPrincipalName", "tech.one", token):
        assert leak not in text


@pytest.mark.parametrize("status", [401, 403, 404, 429, 500])
async def test_graph_failures_for_new_tools_are_safe_codes(h, status):
    h.graph._client = httpx2.AsyncClient(  # noqa: SLF001
        transport=httpx2.MockTransport(
            lambda r: httpx2.Response(status, json={"error": {"message": "internal-detail-xyz"}})
        )
    )
    token = await bearer(h, OID_A)
    for tool, args in all_calls(device(1))[2:]:
        text = error_text(await h.call_tool(token, tool, args))
        assert "internal-detail" not in text and "(ref " in text


async def test_existing_tools_keep_their_exact_output(h):
    h.devices[OID_A] = [device(1), device(2)]
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, "list_devices", {"page_size": 2}))
    assert out == {
        "devices": [
            {
                "id": guid("a", i),
                "deviceName": f"A-PC-{i}",
                "operatingSystem": "Windows",
                "osVersion": "10.0",
                "complianceState": "compliant",
                "managedDeviceOwnerType": "company",
                "lastSyncDateTime": "2026-02-27T00:00:00Z",
            }
            for i in (1, 2)
        ],
        "count": 2,
        "next_page_token": None,
        "complete": True,
        "note": None,
    }
    one = payload(await h.call_tool(token, "get_device", {"device_id": guid("a", 1)}))
    assert set(one) == {
        "id",
        "deviceName",
        "operatingSystem",
        "osVersion",
        "complianceState",
        "managedDeviceOwnerType",
        "lastSyncDateTime",
        "managementState",
        "enrolledDateTime",
        "manufacturer",
        "model",
        "serialNumber",
        "userPrincipalName",
        "isEncrypted",
    }
    assert one["serialNumber"] == "SN1" and LEAK not in str(one)


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("list_devices", {}),
        ("search_devices", {"ownership": "company"}),
    ],
)
@pytest.mark.parametrize("fault", ["oversized", "too_many_rows", "bad_next_link"])
async def test_oversized_or_inconsistent_graph_pages_are_a_safe_bad_response(
    h, caplog, tool, args, fault
):
    from intune_mcp.graph import MAX_RESPONSE_BYTES

    d = device(1)
    bodies = {
        "oversized": b'{"value": []}' + b" " * MAX_RESPONSE_BYTES,
        "too_many_rows": (
            '{"value": ' + str([{"id": "x"}] * 1001).replace("'", '"') + "}"
        ).encode(),
        "bad_next_link": b'{"value": [], "@odata.nextLink": {"a": 1}}',
    }
    h.graph._client = httpx2.AsyncClient(  # noqa: SLF001
        transport=httpx2.MockTransport(lambda r: httpx2.Response(200, content=bodies[fault]))
    )
    token = await bearer(h, OID_A)
    args = args if args is not None else {"device_id": d["id"]}
    with caplog.at_level(logging.INFO, logger="intune_mcp.audit"):
        text = error_text(await h.call_tool(token, tool, args))
    assert text.startswith("bad_response: ") and "(ref " in text
    [line] = audit_lines(caplog)
    assert "outcome=bad_response" in line
