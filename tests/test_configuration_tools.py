"""Tool group 2 (`configuration`) through the real HTTP app. Entra and Graph are mocked.

Nothing here is live evidence: it proves request building, validation, field minimisation, scope
handling and audit policy against a simulation of Graph, not Microsoft's actual behaviour.
"""

import asyncio
import json
import logging
from typing import NamedTuple

import httpx2
import jwt
import pytest

from intune_mcp.config import CONFIGURATION_SCOPE, GRAPH_SCOPE
from intune_mcp.graph import (
    COMPLIANCE_POLICY_ASSIGNMENTS_SPEC,
    COMPLIANCE_POLICY_SETTINGS_SPEC,
    COMPLIANCE_POLICY_SPEC,
    COMPLIANCE_POLICY_STATUS_SPEC,
    COMPLIANCE_STATES_SPEC,
    CONFIGURATION_PROFILE_ASSIGNMENTS_SPEC,
    CONFIGURATION_PROFILE_SETTINGS_SPEC,
    CONFIGURATION_PROFILE_SPEC,
    CONFIGURATION_PROFILE_STATUS_SPEC,
    CONFIGURATION_STATES_SPEC,
    DEVICE_SPEC,
    LIST_COMPLIANCE_POLICIES_SPEC,
    LIST_CONFIGURATION_PROFILES_SPEC,
    MAX_RESPONSE_BYTES,
    POLICY_FIELDS,
    assignment_summary,
    audit_target,
    odata_type_name,
)
from intune_mcp.groups import TOOL_GROUPS
from intune_mcp.server import instructions_for

from .conftest import OID_A, OID_B, make_settings
from .harness import Harness
from .test_device_tools import (
    HOSTILE_DEVICE_IDS,
    HOSTILE_MARKERS,
    LEAK,
    NOW,
    audit_lines,
    bearer,
    device,
    error_text,
    guid,
    payload,
    prime,
    state_row,
)
from .test_tool_groups import DEFAULT_TOOLS, authorize_scopes, scp_of, tools

CONFIG_SCOPE_NAME = CONFIGURATION_SCOPE.rsplit("/", 1)[1]
STATE_TOOLS = [
    ("get_device_compliance_states", "compliance_states", "deviceCompliancePolicyStates"),
    ("get_device_configuration_states", "configuration_states", "deviceConfigurationStates"),
]
TOOLS = [
    (*t, state_row, {"displayName", "platformType", "state", "settingCount", "version"})
    for t in STATE_TOOLS
]
CONFIG_TOOLS = [
    "get_compliance_policy",
    "get_compliance_policy_assignments",
    "get_compliance_policy_settings",
    "get_compliance_policy_status_overview",
    "get_compliance_summary",
    "get_configuration_profile",
    "get_configuration_profile_assignments",
    "get_configuration_profile_settings",
    "get_configuration_profile_status_overview",
    "get_configuration_state_summary",
    "get_device_compliance_states",
    "get_device_configuration_states",
    "list_compliance_policies",
    "list_configuration_profiles",
]
CONFIG_CATALOG = sorted([*DEFAULT_TOOLS, *CONFIG_TOOLS])


@pytest.fixture
async def h():
    """Both groups enabled. (Overrides the devices-only fixture of the other test modules.)"""
    async with Harness(make_settings(enabled_tool_groups="devices,configuration")).running() as x:
        x.graph._clock = lambda: NOW  # noqa: SLF001
        yield x


@pytest.fixture
async def h_default(settings):
    async with Harness(settings).running() as harness:
        yield harness


# -- moved from group 1: the two per-device state tools (behaviour, names and outputs unchanged) --
@pytest.mark.parametrize(("tool", "key", "collection", "row", "fields"), TOOLS)
async def test_per_device_tools_minimise_page_and_hit_the_right_endpoint(
    h, tool, key, collection, row, fields
):
    dev = device(1)
    h.devices[OID_A] = [dev]
    h.children[OID_A] = {(dev["id"], collection): [row(i) for i in range(1, 6)]}
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, tool, {"device_id": dev["id"].upper(), "page_size": 2}))
    assert set(out) == {key, "count", "next_page_token", "complete", "note"}
    assert (
        out["count"] == 2 and out["complete"] is False and "not the complete result" in out["note"]
    )
    req = h.graph_requests[-1]
    assert req.url.path == f"/v1.0/deviceManagement/managedDevices/{dev['id']}/{collection}"
    assert set(req.url.params["$select"].split(",")) == fields
    collected = list(out[key])
    while out["next_page_token"]:
        out = payload(
            await h.call_tool(
                token,
                tool,
                {"device_id": dev["id"], "page_token": out["next_page_token"], "page_size": 100},
            )
        )
        assert h.graph_requests[-1].url.params["$top"] == "2"
        collected += out[key]
    assert len(collected) == 5 and out["complete"] is True and out["note"] is None
    assert all(set(r) == fields for r in collected)
    assert LEAK not in str(collected) and "settingStates" not in str(collected)


@pytest.mark.parametrize(("tool", "key", "collection", "row", "fields"), TOOLS)
async def test_per_device_tools_validate_the_guid_before_any_exchange(
    h, tool, key, collection, row, fields
):
    token = await bearer(h, OID_A)
    for bad in ("../users", f"{guid('a', 1)}/wipe", "x" * 5000, "", f"{guid('a', 1)}\nforged", "1"):
        text = error_text(await h.call_tool(token, tool, {"device_id": bad}))
        assert text.startswith("invalid_device_id: device_id must be a GUID")
    assert h.token_requests == [] and h.graph_requests == []


@pytest.mark.parametrize(("tool", "key", "collection", "row", "fields"), TOOLS)
async def test_per_device_tools_cannot_replay_a_token_for_another_device_or_tool(
    h, tool, key, collection, row, fields
):
    d1, d2 = device(1), device(2)
    h.devices[OID_A] = [d1, d2]
    h.children[OID_A] = {
        (d["id"], c): [row(i) for i in range(1, 4)] for d in (d1, d2) for _, _, c, _, _ in TOOLS
    }
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, tool, {"device_id": d1["id"], "page_size": 1}))
    page_token = out["next_page_token"]
    assert page_token
    n_graph, n_tokens = len(h.graph_requests), len(h.token_requests)
    other_device = error_text(
        await h.call_tool(token, tool, {"device_id": d2["id"], "page_token": page_token})
    )
    assert other_device.startswith("invalid_page_token: ")
    for other_tool, *_ in TOOLS:
        if other_tool != tool:
            text = error_text(
                await h.call_tool(
                    token, other_tool, {"device_id": d1["id"], "page_token": page_token}
                )
            )
            assert text.startswith("invalid_page_token: ")
    for other_tool in ("list_devices", "search_devices"):
        assert error_text(
            await h.call_tool(token, other_tool, {"page_token": page_token})
        ).startswith("invalid_page_token: ")
    assert (len(h.graph_requests), len(h.token_requests)) == (n_graph, n_tokens)


@pytest.mark.parametrize(("tool", "key", "collection", "row", "fields"), TOOLS)
async def test_per_device_tools_report_invisible_devices_as_not_found(
    h, tool, key, collection, row, fields
):
    h.devices[OID_A] = [device(1)]
    token = await bearer(h, OID_A)
    text = error_text(await h.call_tool(token, tool, {"device_id": guid("z", 9)}))
    assert text.startswith("not_found: ")


STATE_TOOL_NAMES = [t for t, *_ in STATE_TOOLS]


@pytest.mark.parametrize("tool", STATE_TOOL_NAMES)
@pytest.mark.parametrize("kind", list(HOSTILE_DEVICE_IDS))
async def test_invalid_device_id_text_never_reaches_any_log_on_the_state_tools(
    h, caplog, tool, kind
):
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.DEBUG):
        error_text(await h.call_tool(token, tool, {"device_id": HOSTILE_DEVICE_IDS[kind]}))
    [line] = audit_lines(caplog)
    assert f"tool={tool}" in line and "outcome=invalid_device_id" in line
    assert "target=invalid " in line + " "
    everything = "\n".join(r.getMessage() for r in caplog.records)
    for marker in HOSTILE_MARKERS:
        assert marker not in everything, marker
    assert token not in everything
    assert h.token_requests == [] and h.graph_requests == []


@pytest.mark.parametrize("tool", STATE_TOOL_NAMES)
async def test_a_valid_device_id_is_audited_in_canonical_form_only_on_the_state_tools(
    h, caplog, tool
):
    d = prime(h)
    token = await bearer(h, OID_A)
    spelled = "{" + d["id"] + "}"
    with caplog.at_level(logging.INFO):
        payload(await h.call_tool(token, tool, {"device_id": spelled}))
        error_text(await h.call_tool(token, tool, {"device_id": guid("z", 9)}))  # not_found
    ok, missing = audit_lines(caplog)
    assert f"target={d['id']}" in ok and "outcome=ok" in ok and "returned=1" in ok
    assert "more=False" in ok and LEAK not in ok
    assert f"target={guid('z', 9)}" in missing and "outcome=not_found" in missing
    assert "{" not in ok and "}" not in ok


async def test_bad_page_tokens_never_reach_a_log_on_any_paged_configuration_tool(h, caplog):
    d = prime(h)
    token = await bearer(h, OID_A)
    bad = "SECRETTOKEN-forged"
    calls = [
        ("get_device_compliance_states", {"device_id": d["id"]}),
        ("get_device_configuration_states", {"device_id": d["id"]}),
        ("list_compliance_policies", {}),
        ("list_configuration_profiles", {}),
        ("get_compliance_policy_assignments", {"policy_id": guid("p", 1)}),
        ("get_configuration_profile_assignments", {"profile_id": guid("r", 1)}),
    ]
    with caplog.at_level(logging.DEBUG):
        for tool, args in calls:
            text = error_text(await h.call_tool(token, tool, {**args, "page_token": bad}))
            assert text.startswith("invalid_page_token: ") and bad not in text
    everything = "\n".join(r.getMessage() for r in caplog.records)
    assert "SECRETTOKEN" not in everything
    assert len(audit_lines(caplog)) == len(calls)
    assert h.token_requests == [] and h.graph_requests == []


@pytest.mark.parametrize("fault", ["oversized", "too_many_rows", "bad_next_link"])
@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("get_device_compliance_states", {"device_id": guid("a", 1)}),
        ("list_compliance_policies", {}),
        ("get_compliance_policy_assignments", {"policy_id": guid("p", 1)}),
        ("list_configuration_profiles", {}),
        ("get_configuration_profile_assignments", {"profile_id": guid("r", 1)}),
    ],
)
async def test_oversized_or_inconsistent_graph_pages_are_a_safe_bad_response(
    h, caplog, tool, args, fault
):
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
    with caplog.at_level(logging.INFO, logger="intune_mcp.audit"):
        text = error_text(await h.call_tool(token, tool, args))
    assert text.startswith("bad_response: ") and "(ref " in text
    [line] = audit_lines(caplog)
    assert "outcome=bad_response" in line


# -- fixtures for policies and profiles --------------------------------------------------------
class Kind(NamedTuple):
    coll: str
    list_tool: str
    get_tool: str
    status_tool: str
    assign_tool: str
    id_arg: str
    list_key: str
    type_key: str
    noun: str
    owners: tuple[str, str]  # GUID owner letter for user A and user B
    base_type: str
    extras: dict  # derived-type properties (some secret-looking) that must never be returned
    specs: tuple  # list, get, status, assignments


COMPLIANCE = Kind(
    "deviceCompliancePolicies",
    "list_compliance_policies",
    "get_compliance_policy",
    "get_compliance_policy_status_overview",
    "get_compliance_policy_assignments",
    "policy_id",
    "policies",
    "policy_type",
    "compliance policy",
    ("p", "q"),
    "windows10CompliancePolicy",
    {
        "passwordRequired": True,
        "passwordMinimumLength": 12,
        "scheduledActionsForRule": [{"ruleName": "SECRET-RULE"}],
        "roleScopeTagIds": ["SECRET-TAG"],
        "secretExtra": LEAK,
    },
    (
        LIST_COMPLIANCE_POLICIES_SPEC,
        COMPLIANCE_POLICY_SPEC,
        COMPLIANCE_POLICY_STATUS_SPEC,
        COMPLIANCE_POLICY_ASSIGNMENTS_SPEC,
    ),
)
PROFILE = Kind(
    "deviceConfigurations",
    "list_configuration_profiles",
    "get_configuration_profile",
    "get_configuration_profile_status_overview",
    "get_configuration_profile_assignments",
    "profile_id",
    "profiles",
    "profile_type",
    "configuration profile",
    ("r", "s"),
    "windows10GeneralConfiguration",
    {
        "wifiSsid": "SECRET-SSID",
        "ssid": "SECRET-SSID",
        "preSharedKey": "SECRET-PSK",
        "password": "SECRET-PASSWORD",
        "vpnPassword": "SECRET-VPN",
        "certificate": "SECRET-CERT",
        "rootCertificate": {"certFileName": "SECRET-CERT", "trustedRootCertificate": "SECRET-B64"},
        "omaSettings": [{"displayName": "x", "value": "SECRET-OMA"}],
        "secretExtra": LEAK,
    },
    (
        LIST_CONFIGURATION_PROFILES_SPEC,
        CONFIGURATION_PROFILE_SPEC,
        CONFIGURATION_PROFILE_STATUS_SPEC,
        CONFIGURATION_PROFILE_ASSIGNMENTS_SPEC,
    ),
)
KINDS = [COMPLIANCE, PROFILE]
kinds = pytest.mark.parametrize("kind", KINDS, ids=["policy", "profile"])
SECRET_MARKERS = ("SECRET-", LEAK)
EXPECTED_ROW_KEYS = {k.coll: {*POLICY_FIELDS, k.type_key} for k in KINDS}
GROUP_A, GROUP_B, FILTER_ID = guid("g", 1), guid("g", 2), guid("f", 1)
STATUS = {
    "id": "x",
    "pendingCount": 1,
    "notApplicableCount": 2,
    "successCount": 30,
    "errorCount": 4,
    "failedCount": 5,
    "conflictCount": 6,
    "lastUpdateDateTime": "2026-03-01T10:00:00Z",
    "configurationVersion": 3,
    "displayName": LEAK,
    "userNames": LEAK,
}
SUMMARY = {
    "id": "SECRET-summary-id",
    "compliantDeviceCount": 100,
    "nonCompliantDeviceCount": 7,
    "inGracePeriodCount": 3,
    "configManagerCount": 11,
    "conflictDeviceCount": 1,
    "errorDeviceCount": 2,
    "notApplicableDeviceCount": 5,
    "unknownDeviceCount": 4,
    "remediatedDeviceCount": 6,
}
ASSIGNMENTS = [
    {
        "id": f"{guid('p', 1)}_{GROUP_A}",
        "source": "direct",
        "sourceId": "x",
        "target": {
            "@odata.type": "#microsoft.graph.groupAssignmentTarget",
            "groupId": GROUP_A,
            "deviceAndAppManagementAssignmentFilterId": FILTER_ID,
            "deviceAndAppManagementAssignmentFilterType": "include",
            "displayName": LEAK,
            "groupName": LEAK,
        },
    },
    {
        "id": "abc_0_0",
        "target": {
            "@odata.type": "#microsoft.graph.allDevicesAssignmentTarget",
            "deviceAndAppManagementAssignmentFilterId": None,
            "deviceAndAppManagementAssignmentFilterType": "none",
        },
    },
    {
        "id": "x2",
        "target": {
            "@odata.type": "#microsoft.graph.exclusionGroupAssignmentTarget",
            "groupId": GROUP_B.upper(),
        },
    },
]
SANITISED_ASSIGNMENTS = [
    {
        "id": f"{guid('p', 1)}_{GROUP_A}",
        "target_type": "groupAssignmentTarget",
        "group_id": GROUP_A,
        "filter_type": "include",
        "filter_id": FILTER_ID,
    },
    {
        "id": "abc_0_0",
        "target_type": "allDevicesAssignmentTarget",
        "group_id": None,
        "filter_type": "none",
        "filter_id": None,
    },
    {
        "id": "x2",
        "target_type": "exclusionGroupAssignmentTarget",
        "group_id": GROUP_B,
        "filter_type": None,
        "filter_id": None,
    },
]


def row(kind, i, user=0, type_name=None, **over):
    out = {
        "@odata.type": f"#microsoft.graph.{type_name or kind.base_type}",
        "id": guid(kind.owners[user], i),
        "displayName": f"{kind.noun} {i}",
        "description": f"Description {i}",
        "createdDateTime": "2026-01-01T00:00:00Z",
        "lastModifiedDateTime": "2026-02-01T00:00:00Z",
        "version": i,
        **kind.extras,
    }
    out.update(over)
    return out


def put(h, oid, kind, rows, *, status=None, assignments=None):
    h.config_rows.setdefault(oid, {})[kind.coll] = rows
    kids = h.config_children.setdefault(oid, {})
    for r in rows:
        if status is not None:
            kids[(kind.coll, r["id"], "deviceStatusOverview")] = status
        if assignments is not None:
            kids[(kind.coll, r["id"], "assignments")] = assignments


def prime_config(h, oid=OID_A, user=0, n=3):
    h.compliance_summary[oid] = dict(SUMMARY)
    for kind in KINDS:
        put(
            h,
            oid,
            kind,
            [row(kind, i, user) for i in range(1, n + 1)],
            status=STATUS,
            assignments=ASSIGNMENTS,
        )


def id_calls(kind, ident):
    return [
        (kind.get_tool, {kind.id_arg: ident}),
        (kind.status_tool, {kind.id_arg: ident}),
        (kind.assign_tool, {kind.id_arg: ident}),
    ]


def no_secrets(value):
    text = json.dumps(value)
    for marker in SECRET_MARKERS:
        assert marker not in text, marker


# -- list / get / status / assignments: success and field minimisation -------------------------
@kinds
async def test_list_minimises_fields_derives_the_type_and_pages(h, kind):
    put(h, OID_A, kind, [row(kind, i) for i in range(1, 6)])
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, kind.list_tool, {"page_size": 2}))
    assert set(out) == {kind.list_key, "count", "next_page_token", "complete", "note"}
    assert out["count"] == 2 and out["complete"] is False
    assert "not the complete result" in out["note"]
    req = h.graph_requests[-1]
    assert req.method == "GET" and req.url.path == f"/v1.0/deviceManagement/{kind.coll}"
    # Only base-type properties are selected; never @odata.type or a derived property.
    assert req.url.params["$select"] == ",".join(POLICY_FIELDS)
    assert req.url.params["$top"] == "2"
    collected, pages = list(out[kind.list_key]), 1
    while out["next_page_token"]:
        out = payload(
            await h.call_tool(
                token, kind.list_tool, {"page_token": out["next_page_token"], "page_size": 100}
            )
        )
        assert h.graph_requests[-1].url.params["$top"] == "2"
        collected += out[kind.list_key]
        pages += 1
    assert pages == 3 and out["complete"] is True and out["note"] is None
    assert [r["id"] for r in collected] == [guid(kind.owners[0], i) for i in range(1, 6)]
    for r in collected:
        assert set(r) == EXPECTED_ROW_KEYS[kind.coll]
        assert r[kind.type_key] == kind.base_type
    assert collected[0] == {
        "id": guid(kind.owners[0], 1),
        "displayName": f"{kind.noun} 1",
        "description": "Description 1",
        "createdDateTime": "2026-01-01T00:00:00Z",
        "lastModifiedDateTime": "2026-02-01T00:00:00Z",
        "version": 1,
        kind.type_key: kind.base_type,
    }
    no_secrets(collected)


@kinds
async def test_list_picks_client_side_even_if_graph_ignores_select(h, kind):
    # The mock ignores $select like a Graph that returns derived properties anyway.
    put(h, OID_A, kind, [row(kind, 1), row(kind, 2, type_name="otherDerivedType")])
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, kind.list_tool, {}))
    assert [r[kind.type_key] for r in out[kind.list_key]] == [kind.base_type, "otherDerivedType"]
    assert all(set(r) == EXPECTED_ROW_KEYS[kind.coll] for r in out[kind.list_key])
    no_secrets(out)


@kinds
async def test_get_returns_common_fields_and_type_only(h, kind):
    put(h, OID_A, kind, [row(kind, 1), row(kind, 2)])
    token = await bearer(h, OID_A)
    ident = guid(kind.owners[0], 2)
    out = payload(await h.call_tool(token, kind.get_tool, {kind.id_arg: ident.upper()}))
    assert out == {
        "id": ident,
        "displayName": f"{kind.noun} 2",
        "description": "Description 2",
        "createdDateTime": "2026-01-01T00:00:00Z",
        "lastModifiedDateTime": "2026-02-01T00:00:00Z",
        "version": 2,
        kind.type_key: kind.base_type,
    }
    req = h.graph_requests[-1]
    assert req.method == "GET" and req.url.path == f"/v1.0/deviceManagement/{kind.coll}/{ident}"
    assert req.url.params["$select"] == ",".join(POLICY_FIELDS)
    no_secrets(out)


@kinds
async def test_secret_looking_properties_are_never_returned_by_any_tool(h, kind, caplog):
    """The mocked Graph returns Wi-Fi/VPN/password/certificate-style properties everywhere."""
    leaky_status = {**STATUS, "preSharedKey": "SECRET-PSK", "password": "SECRET-PASSWORD"}
    leaky_assignments = [
        {
            **a,
            "preSharedKey": "SECRET-PSK",
            "target": {**a["target"], "password": "SECRET-PASSWORD", "ssid": "SECRET-SSID"},
        }
        for a in ASSIGNMENTS
    ]
    put(h, OID_A, kind, [row(kind, 1)], status=leaky_status, assignments=leaky_assignments)
    token = await bearer(h, OID_A)
    ident = guid(kind.owners[0], 1)
    with caplog.at_level(logging.DEBUG):
        outs = [
            payload(await h.call_tool(token, kind.list_tool, {})),
            *[payload(await h.call_tool(token, t, a)) for t, a in id_calls(kind, ident)],
        ]
    for out in outs:
        no_secrets(out)
        text = json.dumps(out).lower()
        for name in ("preshared", "password", "certificate", "ssid", "oma", "vpn", "rootcert"):
            assert name not in text, name
    for req in h.graph_requests:  # no derived or secret-looking property was ever requested
        select = req.url.params.get("$select", "")
        assert not set(select.split(",")) & set(kind.extras) and "odata" not in select
    assert "SECRET-" not in "\n".join(r.getMessage() for r in caplog.records)


@kinds
async def test_status_overview_returns_counts_and_one_timestamp_only(h, kind):
    put(h, OID_A, kind, [row(kind, 1)], status=STATUS)
    token = await bearer(h, OID_A)
    ident = guid(kind.owners[0], 1)
    out = payload(await h.call_tool(token, kind.status_tool, {kind.id_arg: ident}))
    assert out == {
        "pendingCount": 1,
        "notApplicableCount": 2,
        "successCount": 30,
        "errorCount": 4,
        "failedCount": 5,
        "conflictCount": 6,
        "lastUpdateDateTime": "2026-03-01T10:00:00Z",
    }
    req = h.graph_requests[-1]
    assert req.url.path == f"/v1.0/deviceManagement/{kind.coll}/{ident}/deviceStatusOverview"
    assert "$select" not in req.url.params  # $select is not assumed on this endpoint
    assert LEAK not in str(out)


@kinds
async def test_status_overview_drops_values_that_are_not_plain_counts_or_timestamps(h, kind):
    hostile = {
        "pendingCount": "1",
        "notApplicableCount": -2,
        "successCount": True,
        "errorCount": 1.5,
        "failedCount": [1],
        "lastUpdateDateTime": "2026-03-01T10:00:00Z\nintune_mcp.audit forged",
    }
    put(h, OID_A, kind, [row(kind, 1)], status=hostile)
    token = await bearer(h, OID_A)
    ident = guid(kind.owners[0], 1)
    out = payload(await h.call_tool(token, kind.status_tool, {kind.id_arg: ident}))
    assert set(out.values()) == {None}  # conflictCount is simply absent -> null as well
    assert len(out) == 7
    put(
        h,
        OID_A,
        kind,
        [row(kind, 1)],
        status={"lastUpdateDateTime": "2026-03-01T10:00:00.1234567Z"},
    )
    out = payload(await h.call_tool(token, kind.status_tool, {kind.id_arg: ident}))
    assert out["lastUpdateDateTime"] == "2026-03-01T10:00:00.1234567Z"
    assert out["conflictCount"] is None and out["pendingCount"] is None


@kinds
async def test_assignments_are_a_sanitised_target_summary_and_page(h, kind):
    many = [{**ASSIGNMENTS[i % 3], "id": f"a{i}"} for i in range(5)]
    put(h, OID_A, kind, [row(kind, 1)], assignments=many)
    token = await bearer(h, OID_A)
    ident = guid(kind.owners[0], 1)
    out = payload(await h.call_tool(token, kind.assign_tool, {kind.id_arg: ident, "page_size": 2}))
    assert set(out) == {"assignments", "count", "next_page_token", "complete", "note"}
    req = h.graph_requests[-1]
    assert req.url.path == f"/v1.0/deviceManagement/{kind.coll}/{ident}/assignments"
    assert "$select" not in req.url.params and req.url.params["$top"] == "2"
    collected = list(out["assignments"])
    while out["next_page_token"]:
        out = payload(
            await h.call_tool(
                token,
                kind.assign_tool,
                {kind.id_arg: ident, "page_token": out["next_page_token"], "page_size": 100},
            )
        )
        collected += out["assignments"]
    assert out["complete"] is True and len(collected) == 5
    assert [a["id"] for a in collected] == [f"a{i}" for i in range(5)]
    assert all(
        set(a) == {"id", "target_type", "group_id", "filter_type", "filter_id"} for a in collected
    )
    assert collected[0]["group_id"] == GROUP_A and collected[2]["group_id"] == GROUP_B
    assert LEAK not in json.dumps(collected) and "target" not in collected[0]
    # Each distinct target shape is summarised exactly.
    single = payload(await h.call_tool(token, kind.assign_tool, {kind.id_arg: ident}))
    put(h, OID_A, kind, [row(kind, 1)], assignments=ASSIGNMENTS)
    single = payload(await h.call_tool(token, kind.assign_tool, {kind.id_arg: ident}))
    assert single["assignments"] == SANITISED_ASSIGNMENTS


HOSTILE_ASSIGNMENTS = [
    {"id": "has space", "target": "not an object"},
    {"id": "x\nforged", "target": {"@odata.type": 5, "groupId": 7}},
    {"id": "i" * 129, "target": None},
    {
        "id": ["a"],
        "target": {"groupId": "not-a-guid", "deviceAndAppManagementAssignmentFilterId": "x"},
    },
    {
        "id": "ok-1",
        "target": {
            "@odata.type": "#microsoft.graph.<b>SECRETTYPE</b>",
            "groupId": f"{GROUP_A}\nSECRETGROUP",
            "deviceAndAppManagementAssignmentFilterType": "SECRETFILTER",
            "deviceAndAppManagementAssignmentFilterId": {"a": "SECRETFID"},
        },
    },
    {"id": None, "target": {"groupId": "z" * 5000}},
]


@kinds
async def test_hostile_assignment_content_is_reduced_to_nulls_and_unknown(h, kind):
    put(h, OID_A, kind, [row(kind, 1)], assignments=HOSTILE_ASSIGNMENTS)
    token = await bearer(h, OID_A)
    out = payload(
        await h.call_tool(token, kind.assign_tool, {kind.id_arg: guid(kind.owners[0], 1)})
    )
    assert [a["id"] for a in out["assignments"]] == [None, None, None, None, "ok-1", None]
    for a in out["assignments"]:
        assert a["target_type"] == "unknown"
        assert a["group_id"] is None and a["filter_type"] is None and a["filter_id"] is None
    assert "SECRET" not in json.dumps(out) and "forged" not in json.dumps(out)


def test_assignment_summary_keeps_only_validated_values():
    assert assignment_summary({}) == {
        "id": None,
        "target_type": "unknown",
        "group_id": None,
        "filter_type": None,
        "filter_id": None,
    }
    spelled = assignment_summary(
        {
            "id": "a_b.c-1",
            "target": {
                "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                "groupId": "{" + GROUP_A.upper() + "}",  # canonicalised, never echoed as given
                "deviceAndAppManagementAssignmentFilterType": "exclude",
                "deviceAndAppManagementAssignmentFilterId": FILTER_ID,
            },
        }
    )
    assert spelled["group_id"] == GROUP_A and spelled["filter_type"] == "exclude"
    assert spelled["id"] == "a_b.c-1" and spelled["filter_id"] == FILTER_ID
    assert (
        assignment_summary({"target": {"deviceAndAppManagementAssignmentFilterType": "NONE"}})[
            "filter_type"
        ]
        is None
    )  # case-sensitive closed set


@kinds
async def test_nested_values_under_allowlisted_names_are_dropped(h, kind):
    nested = {
        "displayName": {"a": "SECRET-NESTED"},
        "description": ["SECRET-NESTED"],
        "version": {},
    }
    put(h, OID_A, kind, [row(kind, 1, **nested)])
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, kind.list_tool, {}))
    one = payload(await h.call_tool(token, kind.get_tool, {kind.id_arg: guid(kind.owners[0], 1)}))
    for r in (*out[kind.list_key], one):
        assert (r["displayName"], r["description"], r["version"]) == (None, None, None)
    no_secrets([out, one])


# -- @odata.type is never echoed unless it is a plain type name --------------------------------
HOSTILE_TYPES = [
    (None, "unknown"),
    (123, "unknown"),
    ({"a": 1}, "unknown"),
    ("", "unknown"),
    ("#microsoft.graph.windows10CompliancePolicy", "windows10CompliancePolicy"),
    ("#microsoft.graph.windows10CompliancePolicy\n", "unknown"),  # fullmatch, not `$`
    ("#microsoft.graph.a\nintune_mcp.audit forged outcome=ok", "unknown"),
    ("#microsoft.graph.<script>alert(1)</script>", "unknown"),
    ("#microsoft.graph.SECRET text with spaces", "unknown"),
    ("#microsoft.graph." + "A" * 100, "A" * 100),
    ("#microsoft.graph." + "A" * 101, "unknown"),
    ("#microsoft.graph.", "unknown"),
    ("#microsoft.graph.\u00e9", "unknown"),
    ("#microsoft.graph.\uff21", "unknown"),  # full-width letter
    ("windows10CompliancePolicy", "unknown"),  # prefix is required
    ("#other.windows10CompliancePolicy", "unknown"),
    ("#Microsoft.Graph.x", "unknown"),
    ("#microsoft.graph.a.b", "a.b"),
    ("#microsoft.graph.a-b", "unknown"),
    ("#microsoft.graph.a b", "unknown"),
    ("x" * 100_000, "unknown"),
    ("#microsoft.graph." + "x" * 100_000, "unknown"),
]


@pytest.mark.parametrize(("raw", "expected"), HOSTILE_TYPES)
def test_odata_type_name_is_allowlisted(raw, expected):
    assert odata_type_name(raw) == expected


@kinds
async def test_hostile_odata_types_never_reach_a_result_or_a_log(h, kind, caplog):
    rows = [row(kind, i + 1, **{"@odata.type": raw}) for i, (raw, _) in enumerate(HOSTILE_TYPES)]
    rows[0].pop("@odata.type")
    put(h, OID_A, kind, rows)
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.DEBUG):
        out = payload(await h.call_tool(token, kind.list_tool, {"page_size": 100}))
        one = payload(
            await h.call_tool(token, kind.get_tool, {kind.id_arg: guid(kind.owners[0], 10)})
        )
    assert [r[kind.type_key] for r in out[kind.list_key]] == [e for _, e in HOSTILE_TYPES]
    assert one[kind.type_key] == HOSTILE_TYPES[9][1]
    everything = (
        json.dumps(out) + json.dumps(one) + "\n".join(r.getMessage() for r in caplog.records)
    )
    for marker in ("<script>", "forged", "SECRET", "intune_mcp.audit"):
        assert marker not in everything


# -- validation: GUID ids are checked before any token exchange --------------------------------
VALID = guid("p", 1)
BAD_IDS = [
    "private.person@example.test",  # a UPN
    "Jane Q. Private's Laptop",  # a display name
    "SECRETLONG" + "x" * 400,
    "x" * 5000,
    "'; delete from deviceCompliancePolicies; --",
    "' or '1'='1",
    f"{VALID}' or '1'='1",
    f"{VALID}/assignments",
    f"{VALID}?$select=password",
    f"{VALID}\nforged",
    f"{VALID} ",
    "../users/SECRETPATH",
    "%2e%2e/users",
    "",
    "1",
]


@kinds
@pytest.mark.parametrize("which", [1, 2, 3], ids=["get", "status", "assignments"])
async def test_non_guid_ids_are_rejected_before_any_exchange_or_graph_call(h, kind, which):
    token = await bearer(h, OID_A)
    tool = (None, kind.get_tool, kind.status_tool, kind.assign_tool)[which]
    for bad in BAD_IDS:
        text = error_text(await h.call_tool(token, tool, {kind.id_arg: bad}))
        assert text.startswith(f"invalid_{kind.id_arg}: {kind.id_arg} must be a GUID")
        message = text.split(" (ref ")[0]
        assert "(ref " in text and (bad == "" or bad not in message)
    assert h.token_requests == [] and h.graph_requests == []


@kinds
async def test_invalid_paging_arguments_never_reach_microsoft(h, kind):
    token = await bearer(h, OID_A)
    ident = guid(kind.owners[0], 1)
    for tool, args in (
        (kind.list_tool, {}),
        (kind.assign_tool, {kind.id_arg: ident}),
    ):
        for bad in (0, 101, -1, 1.5, "abc", [1]):
            out = await h.call_tool(token, tool, {**args, "page_size": bad})
            assert "error" in out or out["result"]["isError"] is True
        for bad_token in ("forged", "", "x" * 20000, "e30", "SECRET"):
            if bad_token:  # "" is the same as no token
                text = error_text(await h.call_tool(token, tool, {**args, "page_token": bad_token}))
                assert text.startswith("invalid_page_token: ")
    # An id argument on a tool that takes none, and a missing id, are schema errors.
    for tool, args in (
        (kind.list_tool, {kind.id_arg: ident}),
        (kind.get_tool, {}),
        (kind.status_tool, {"device_id": ident}),
    ):
        out = await h.call_tool(token, tool, args)
        assert "error" in out or out["result"]["isError"] is True
    assert h.token_requests == [] and h.graph_requests == []


@kinds
async def test_missing_objects_are_not_found_with_the_right_noun(h, kind):
    put(h, OID_A, kind, [row(kind, 1)], status=STATUS, assignments=ASSIGNMENTS)
    token = await bearer(h, OID_A)
    missing = guid("z", 9)
    for tool, args in id_calls(kind, missing):
        text = error_text(await h.call_tool(token, tool, args))
        assert text.startswith(f"not_found: No matching {kind.noun} is visible to this user.")
    # A sub-resource Graph does not have for a visible object is also a safe not_found.
    h.config_children[OID_A].clear()
    text = error_text(
        await h.call_tool(token, kind.status_tool, {kind.id_arg: guid(kind.owners[0], 1)})
    )
    assert text.startswith("not_found: ")


# -- page tokens stay bound to the endpoint and to the policy/profile id -----------------------
async def test_page_tokens_cannot_be_replayed_across_endpoints_or_ids(h):
    d1 = prime(h)
    h.devices[OID_A] = [d1, device(2), device(3)]  # two pages for the device tools as well
    for state in ("deviceCompliancePolicyStates", "deviceConfigurationStates"):
        h.children[OID_A][(d1["id"], state)] = [state_row(1), state_row(2)]
    p1, p2, r1, r2 = guid("p", 1), guid("p", 2), guid("r", 1), guid("r", 2)
    # A profile that has the SAME GUID as policy p1 (distinct Graph collections can collide).
    shared = row(PROFILE, 1, id=p1)
    put(h, OID_A, COMPLIANCE, [row(COMPLIANCE, 1), row(COMPLIANCE, 2)], assignments=ASSIGNMENTS)
    put(h, OID_A, PROFILE, [row(PROFILE, 1), row(PROFILE, 2), shared], assignments=ASSIGNMENTS)
    token = await bearer(h, OID_A)
    calls = {
        "list_policies": ("list_compliance_policies", {}),
        "list_profiles": ("list_configuration_profiles", {}),
        "policy_p1": ("get_compliance_policy_assignments", {"policy_id": p1}),
        "policy_p2": ("get_compliance_policy_assignments", {"policy_id": p2}),
        "profile_r1": ("get_configuration_profile_assignments", {"profile_id": r1}),
        "profile_r2": ("get_configuration_profile_assignments", {"profile_id": r2}),
        "profile_shared": ("get_configuration_profile_assignments", {"profile_id": p1}),
        "state_compliance": ("get_device_compliance_states", {"device_id": d1["id"]}),
        "state_configuration": ("get_device_configuration_states", {"device_id": d1["id"]}),
        "devices": ("list_devices", {}),
        "search": ("search_devices", {}),
    }
    tokens = {}
    for name, (tool, args) in calls.items():
        out = payload(await h.call_tool(token, tool, {**args, "page_size": 1}))
        tokens[name] = out["next_page_token"]
        assert tokens[name], name
    n_graph, n_tokens = len(h.graph_requests), len(h.token_requests)
    for token_name, page_token in tokens.items():
        for call_name, (tool, args) in calls.items():
            if call_name != token_name:
                text = error_text(
                    await h.call_tool(token, tool, {**args, "page_token": page_token})
                )
                assert text.startswith("invalid_page_token: "), (token_name, call_name)
    assert (len(h.graph_requests), len(h.token_requests)) == (n_graph, n_tokens)
    for name, (tool, args) in calls.items():  # control: each token works where it was issued
        payload(await h.call_tool(token, tool, {**args, "page_token": tokens[name]}))
    # one request per call plus the parent check of the seven per-object tools (never the lists)
    per_object = [n for n in calls if n.startswith(("policy_", "profile_", "state_"))]
    assert len(per_object) == 7
    assert len(h.graph_requests) == n_graph + len(calls) + len(per_object)


# -- gating, scopes ---------------------------------------------------------------------------
def test_groups_split_the_tools_as_designed():
    assert TOOL_GROUPS["devices"].tools == (
        "list_devices",
        "get_device",
        "search_devices",
        "count_devices",
        "device_summary",
    )
    assert sorted(TOOL_GROUPS["configuration"].tools) == [t for t in CONFIG_TOOLS]
    assert TOOL_GROUPS["configuration"].scope == CONFIGURATION_SCOPE
    assert TOOL_GROUPS["devices"].scope == GRAPH_SCOPE


async def test_default_config_has_no_configuration_tools_and_asks_only_for_the_devices_scope(
    h_default,
):
    h = h_default
    token = await bearer(h, OID_A)
    assert await tools(h, token) == DEFAULT_TOOLS
    for tool in CONFIG_TOOLS:
        assert error_text(await h.call_tool(token, tool)) == f"Unknown tool: '{tool}'"
    assert h.graph_requests == [] and h.token_requests == []
    assert await authorize_scopes(h) == {
        GRAPH_SCOPE,
    }


async def test_enabling_devices_and_configuration_requests_exactly_the_two_scopes(h):
    token = await bearer(h, OID_A)
    catalog = await tools(h, token)  # also asserts every annotation is read-only
    assert catalog == CONFIG_CATALOG and len(catalog) == 20
    assert await authorize_scopes(h) == {
        GRAPH_SCOPE,
        CONFIGURATION_SCOPE,
    }


async def test_enabling_only_configuration_asks_only_for_the_configuration_scope():
    async with Harness(make_settings(enabled_tool_groups="configuration")).running() as h:
        token = await bearer(h, OID_A)
        assert await tools(h, token) == sorted(["whoami", *CONFIG_TOOLS])
        assert await authorize_scopes(h) == {
            CONFIGURATION_SCOPE,
        }


def all_calls(h):
    d = prime(h)
    prime_config(h)
    p, r = guid("p", 1), guid("r", 1)
    return [
        ("list_devices", {}, GRAPH_SCOPE),
        ("get_device", {"device_id": d["id"]}, GRAPH_SCOPE),
        ("search_devices", {"name_prefix": "A"}, GRAPH_SCOPE),
        ("count_devices", {"ownership": "company"}, GRAPH_SCOPE),
        ("device_summary", {}, GRAPH_SCOPE),
        ("get_device_compliance_states", {"device_id": d["id"]}, CONFIGURATION_SCOPE),
        ("get_device_configuration_states", {"device_id": d["id"]}, CONFIGURATION_SCOPE),
        ("list_compliance_policies", {}, CONFIGURATION_SCOPE),
        ("get_compliance_policy", {"policy_id": p}, CONFIGURATION_SCOPE),
        ("get_compliance_policy_settings", {"policy_id": p}, CONFIGURATION_SCOPE),
        ("get_compliance_policy_status_overview", {"policy_id": p}, CONFIGURATION_SCOPE),
        ("get_compliance_policy_assignments", {"policy_id": p}, CONFIGURATION_SCOPE),
        ("list_configuration_profiles", {}, CONFIGURATION_SCOPE),
        ("get_configuration_profile", {"profile_id": r}, CONFIGURATION_SCOPE),
        ("get_configuration_profile_settings", {"profile_id": r}, CONFIGURATION_SCOPE),
        ("get_configuration_profile_status_overview", {"profile_id": r}, CONFIGURATION_SCOPE),
        ("get_configuration_profile_assignments", {"profile_id": r}, CONFIGURATION_SCOPE),
        ("get_compliance_summary", {}, CONFIGURATION_SCOPE),
        ("get_configuration_state_summary", {}, CONFIGURATION_SCOPE),
    ]


DEVICE_PARENT_CHECKED = {"get_device_compliance_states", "get_device_configuration_states"}


async def test_each_tool_exchanges_only_its_own_groups_scope(h):
    calls = all_calls(h)
    assert {t for t, *_ in calls} | {"whoami"} == set(CONFIG_CATALOG)
    token = await bearer(h, OID_A)
    for tool, args, scope in calls:
        before = len(h.token_requests)
        payload(await h.call_tool(token, tool, args))
        new = h.token_requests[before:]
        # One exchange per scope used, exactly one scope each: the per-device state tools also
        # exchange the managed-devices scope once, for their parent-visibility check.
        expected = [(GRAPH_SCOPE,)] if tool in DEVICE_PARENT_CHECKED else []
        assert [s for _, s in new] == [*expected, (scope,)], tool
        assert all(".default" not in s[0] for _, s in new)
        assert scp_of(h.graph_requests[-1]) == scope.rsplit("/", 1)[1], tool
    assert all(len(scopes) == 1 for _, scopes in h.token_requests)
    assert {r.method for r in h.graph_requests} == {"GET"}
    assert {s for _, s in h.token_requests} == {(GRAPH_SCOPE,), (CONFIGURATION_SCOPE,)}


async def test_a_token_of_one_scope_cannot_read_the_other_groups_endpoints(h):
    calls = all_calls(h)
    token = await bearer(h, OID_A)
    payload(await h.call_tool(token, "list_devices"))
    devices_auth = h.graph_requests[-1].headers["authorization"]
    payload(await h.call_tool(token, "list_compliance_policies"))
    config_auth = h.graph_requests[-1].headers["authorization"]
    transport = h.graph._client._transport  # noqa: SLF001
    base = "https://graph.microsoft.com/v1.0/deviceManagement/"
    d = prime(h)
    async with httpx2.AsyncClient(transport=transport) as raw:
        for path in (
            "deviceCompliancePolicies",
            "deviceConfigurations",
            f"managedDevices/{d['id']}/deviceCompliancePolicyStates",
        ):
            assert (
                await raw.get(base + path, headers={"authorization": devices_auth})
            ).status_code == 403
        for path in ("managedDevices", "managedDeviceOverview"):
            assert (
                await raw.get(base + path, headers={"authorization": config_auth})
            ).status_code == 403
    assert len(calls) == 19


async def test_missing_configuration_consent_fails_the_exchange_for_configuration_tools_only(h):
    """E7 path (mocked): Entra refuses the Configuration scope; the devices scope still works."""
    original = h.token_source.get_credential  # noqa: SLF001

    async def get_credential(assertion):
        real = await original(assertion)

        class Cred:
            async def get_token(self, *scopes):
                if scopes == (CONFIGURATION_SCOPE,):
                    raise RuntimeError("AADSTS65001: consent SECRET-TENANT-TEXT")
                return await real.get_token(*scopes)

        return Cred()

    h.token_source.get_credential = get_credential
    d = prime(h)
    prime_config(h)
    token = await bearer(h, OID_A)
    payload(await h.call_tool(token, "list_devices"))
    n_graph = len(h.graph_requests)
    for tool, args in (
        ("list_compliance_policies", {}),
        ("get_configuration_profile", {"profile_id": guid("r", 1)}),
        ("get_device_compliance_states", {"device_id": d["id"]}),
    ):
        text = error_text(await h.call_tool(token, tool, args))
        assert text.startswith("graph_consent_required: ") and "SECRET-TENANT-TEXT" not in text
    assert len(h.graph_requests) == n_graph  # no Graph call without a token
    payload(await h.call_tool(token, "get_device", {"device_id": d["id"]}))


async def test_graph_forbidden_is_the_existing_safe_message_for_every_configuration_tool(h):
    h.graph._client = httpx2.AsyncClient(  # noqa: SLF001
        transport=httpx2.MockTransport(
            lambda r: httpx2.Response(403, json={"error": {"message": "internal-detail-xyz"}})
        )
    )
    token = await bearer(h, OID_A)
    for tool, args, scope in all_calls(h):
        if scope != CONFIGURATION_SCOPE:
            continue
        text = error_text(await h.call_tool(token, tool, args))
        assert text.startswith(
            "forbidden: Microsoft denied access: this user, or this app's consented "
            "permissions, may not read this Intune data."
        )
        assert "internal-detail" not in text and "(ref " in text


@pytest.mark.parametrize("status", [400, 401, 404, 429, 500])
async def test_graph_failures_for_configuration_tools_are_safe_codes(h, status):
    h.graph._client = httpx2.AsyncClient(  # noqa: SLF001
        transport=httpx2.MockTransport(
            lambda r: httpx2.Response(status, json={"error": {"message": "internal-detail-xyz"}})
        )
    )
    token = await bearer(h, OID_A)
    for tool, args, scope in all_calls(h):
        if scope == CONFIGURATION_SCOPE:
            text = error_text(await h.call_tool(token, tool, args))
            assert "internal-detail" not in text and "(ref " in text and ":" in text


def test_instructions_describe_the_configuration_tools_only_when_enabled():
    both = instructions_for(("devices", "configuration"))
    devices_only = instructions_for(("devices",))
    config_only = instructions_for(("configuration",))
    assert "DeviceManagementConfiguration.Read.All" in both
    assert "DeviceManagementConfiguration" not in devices_only
    for name in CONFIG_TOOLS[:2]:
        assert name not in devices_only
    assert "get_device_compliance_states" in config_only and "search_devices" not in config_only
    assert "never returned" in both  # per-type setting values
    assert "forbidden" not in both  # the old "may need an additional permission" hedge is gone


# -- audit ---------------------------------------------------------------------------------
async def test_audit_lines_carry_tool_target_and_counts_but_no_names_or_values(h, caplog):
    # Construct calls first: all_calls primes fixtures, so doing it after planting sentinels
    # would overwrite the hostile metadata and make the non-disclosure check partly vacuous.
    calls = [(t, a) for t, a, s in all_calls(h) if s == CONFIGURATION_SCOPE]
    for kind in KINDS:
        put(
            h,
            OID_A,
            kind,
            [row(kind, i, displayName=f"SECRETNAME-{i}", description="SECRETDESC") for i in (1, 2)],
            status=STATUS,
            assignments=[
                {**a, "target": {**a["target"], "displayName": "SECRETGROUPNAME"}}
                for a in ASSIGNMENTS
            ],
        )
    d = prime(h)
    token = await bearer(h, OID_A)
    # INFO like the deployed process (main()): third-party DEBUG logs carry response bodies, which
    # legitimately contain the names this test plants.
    with caplog.at_level(logging.INFO):
        for tool, args in calls:
            result = payload(await h.call_tool(token, tool, args))
            if tool in {
                "list_compliance_policies",
                "get_compliance_policy",
                "list_configuration_profiles",
                "get_configuration_profile",
            }:
                assert "SECRETNAME" in str(result)  # the sentinels really reached this path
    everything = "\n".join(r.getMessage() for r in caplog.records)
    for marker in ("SECRETNAME", "SECRETDESC", "SECRETGROUPNAME", "Description", LEAK, token):
        assert marker not in everything, marker
    lines = audit_lines(caplog)
    assert len(lines) == len(calls) == 14
    for line, (tool, args) in zip(lines, calls, strict=True):
        assert f"tool={tool} " in line and "outcome=ok" in line and line.isprintable()
        assert f"caller_oid={OID_A}" in line and "correlation_id=" in line
        ident = next(iter(args.values()), None)
        if ident:
            assert f"target={ident} " in line + " "
        if tool.startswith(("list_", "get_device_")) or tool.endswith("assignments"):
            assert "returned=" in line and "more=False" in line
    assert d["id"] in lines[0]


@pytest.mark.parametrize("kind", list(HOSTILE_DEVICE_IDS))
@pytest.mark.parametrize("which", range(6))
async def test_invalid_policy_and_profile_id_text_never_reaches_any_log(h, caplog, kind, which):
    kind_of, pos = divmod(which, 3)
    k = KINDS[kind_of]
    tool = (k.get_tool, k.status_tool, k.assign_tool)[pos]
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.DEBUG):
        error_text(await h.call_tool(token, tool, {k.id_arg: HOSTILE_DEVICE_IDS[kind]}))
    [line] = audit_lines(caplog)
    assert f"tool={tool} " in line and f"outcome=invalid_{k.id_arg}" in line
    assert "target=invalid " in line + " "
    everything = "\n".join(r.getMessage() for r in caplog.records)
    for marker in HOSTILE_MARKERS:
        assert marker not in everything, marker
    assert token not in everything
    assert h.token_requests == [] and h.graph_requests == []


@kinds
async def test_valid_ids_are_audited_in_canonical_form_only(h, caplog, kind):
    put(h, OID_A, kind, [row(kind, 1)], status=STATUS, assignments=ASSIGNMENTS)
    token = await bearer(h, OID_A)
    ident = guid(kind.owners[0], 1)
    spelled = "{" + ident.upper() + "}"
    with caplog.at_level(logging.INFO, logger="intune_mcp.audit"):
        for tool, args in id_calls(kind, spelled):
            payload(await h.call_tool(token, tool, args))
        error_text(await h.call_tool(token, kind.get_tool, {kind.id_arg: guid("z", 9)}))
    *oks, missing = audit_lines(caplog)
    assert len(oks) == 3
    for line in oks:
        assert f"target={ident} " in line + " " and "{" not in line and "outcome=ok" in line
    assert f"target={guid('z', 9)}" in missing and "outcome=not_found" in missing


def test_audit_target_is_the_canonical_guid_or_invalid_for_every_id_scoped_spec():
    canonical = guid("p", 7)
    scoped = [
        COMPLIANCE_STATES_SPEC,
        CONFIGURATION_STATES_SPEC,
        DEVICE_SPEC,
        COMPLIANCE_POLICY_SETTINGS_SPEC,
        CONFIGURATION_PROFILE_SETTINGS_SPEC,
        COMPLIANCE_POLICY_SPEC,
        COMPLIANCE_POLICY_STATUS_SPEC,
        COMPLIANCE_POLICY_ASSIGNMENTS_SPEC,
        CONFIGURATION_PROFILE_SPEC,
        CONFIGURATION_PROFILE_STATUS_SPEC,
        CONFIGURATION_PROFILE_ASSIGNMENTS_SPEC,
    ]
    for spec in scoped:
        assert audit_target(spec, "{" + canonical.upper() + "}") == canonical
        assert audit_target(spec, canonical) == canonical
        for bad in ("private.person@example.test", f"{canonical}\nx", "", "x" * 999, None):
            assert audit_target(spec, bad) == "invalid", (spec.key, bad)
    for spec in (LIST_COMPLIANCE_POLICIES_SPEC, LIST_CONFIGURATION_PROFILES_SPEC):
        assert audit_target(spec, "deviceCompliancePolicies") == "deviceCompliancePolicies"


def test_configuration_specs_are_in_the_configuration_scope_and_never_select_derived_fields():
    specs = [
        COMPLIANCE_STATES_SPEC,
        CONFIGURATION_STATES_SPEC,
        *COMPLIANCE.specs,
        *PROFILE.specs,
    ]
    assert all(s.scope == CONFIGURATION_SCOPE for s in specs)
    assert len({s.key for s in specs}) == len(specs)  # keys bind page tokens: never reused
    for s in (*COMPLIANCE.specs[:2], *PROFILE.specs[:2]):
        assert s.fields == POLICY_FIELDS  # base-type properties only
    for s in (COMPLIANCE.specs[2], COMPLIANCE.specs[3], PROFILE.specs[2], PROFILE.specs[3]):
        assert s.select is False  # $select not assumed on status/assignment endpoints
    assert "@odata.type" not in POLICY_FIELDS


# -- isolation -------------------------------------------------------------------------------
async def test_two_users_interleaved_across_both_groups_never_mix(h):
    users = {OID_A: (0, 3, "a"), OID_B: (1, 5, "b")}
    for oid, (user, n, letter) in users.items():
        h.devices[oid] = [device(i, letter) for i in range(1, n + 1)]
        prime_config(h, oid, user, n)
    ta, tb = await asyncio.gather(bearer(h, OID_A), bearer(h, OID_B))

    async def job(tok, oid):
        user, n, letter = users[oid]
        for kind in KINDS:
            listed = payload(await h.call_tool(tok, kind.list_tool, {"page_size": 100}))
            assert listed["count"] == n
            assert [r["id"] for r in listed[kind.list_key]] == [
                guid(kind.owners[user], i) for i in range(1, n + 1)
            ]
            ident = guid(kind.owners[user], 1)
            got = payload(await h.call_tool(tok, kind.get_tool, {kind.id_arg: ident}))
            assert got["id"] == ident
            status = payload(await h.call_tool(tok, kind.status_tool, {kind.id_arg: ident}))
            assert status["successCount"] == 30
            assigned = payload(await h.call_tool(tok, kind.assign_tool, {kind.id_arg: ident}))
            assert assigned["count"] == 3
        found = payload(
            await h.call_tool(
                tok, "search_devices", {"name_prefix": letter.upper(), "page_size": 100}
            )
        )
        assert found["count"] == n

    await asyncio.gather(*[job(ta, OID_A) if i % 2 == 0 else job(tb, OID_B) for i in range(24)])
    by_oid = {OID_A: 0, OID_B: 0}
    for req in h.graph_requests:
        claims = jwt.decode(
            req.headers["authorization"].split()[1], options={"verify_signature": False}
        )
        by_oid[claims["oid"]] += 1
        foreign = (OID_B, "q", "s") if claims["oid"] == OID_A else (OID_A, "p", "r")
        assert not any(
            guid(letter, i) in str(req.url) for letter in foreign[1:] for i in range(1, 9)
        )
    # 12 jobs x (2 kinds x (list, get, status + its parent check, assignments + its parent check)
    # + 1 search) per user; the parent check reuses the call's single exchange
    assert by_oid == {OID_A: 12 * 13, OID_B: 12 * 13}
    assert len({a for a, _ in h.token_requests}) == 2  # one assertion per user
    assert {s for _, s in h.token_requests} == {(GRAPH_SCOPE,), (CONFIGURATION_SCOPE,)}
    assert sum(1 for _, s in h.token_requests if s == (CONFIGURATION_SCOPE,)) == 24 * 8


async def test_a_user_cannot_read_another_users_policies_or_profiles(h):
    prime_config(h, OID_A, 0)
    prime_config(h, OID_B, 1)
    tb = await bearer(h, OID_B)
    for kind in KINDS:
        for tool, args in id_calls(kind, guid(kind.owners[0], 1)):  # user A's ids
            text = error_text(await h.call_tool(tb, tool, args))
            assert text.startswith(f"not_found: No matching {kind.noun} is visible")
        out = payload(await h.call_tool(tb, kind.list_tool, {"page_size": 100}))
        assert [r["id"] for r in out[kind.list_key]] == [
            guid(kind.owners[1], i) for i in range(1, 4)
        ]


# -- review round: compliance summary, row cap, nextLink forms, text and timestamps ------------
SUMMARY_KEYS = {
    "compliantDeviceCount",
    "nonCompliantDeviceCount",
    "inGracePeriodCount",
    "configManagerCount",
    "conflictDeviceCount",
    "errorDeviceCount",
    "notApplicableDeviceCount",
    "unknownDeviceCount",
    "remediatedDeviceCount",
}


async def test_compliance_summary_returns_only_the_nine_counts(h):
    prime_config(h)
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, "get_compliance_summary"))
    assert set(out) == SUMMARY_KEYS and "id" not in out
    assert out["compliantDeviceCount"] == 100 and out["configManagerCount"] == 11
    assert "SECRET-" not in json.dumps(out)
    req = h.graph_requests[-1]
    assert req.method == "GET"
    assert req.url.path == "/v1.0/deviceManagement/deviceCompliancePolicyDeviceStateSummary"
    assert dict(req.url.params) == {}  # no $select: support is not assumed
    assert scp_of(req) == CONFIG_SCOPE_NAME
    assert [s for _, s in h.token_requests] == [(CONFIGURATION_SCOPE,)]


async def test_compliance_summary_drops_non_integers_extras_and_missing_fields(h):
    h.compliance_summary[OID_A] = {
        "id": "SECRET-id",
        "compliantDeviceCount": "12",
        "nonCompliantDeviceCount": 7.5,
        "inGracePeriodCount": True,
        "configManagerCount": -3,
        "conflictDeviceCount": None,
        "errorDeviceCount": [1],
        "notApplicableDeviceCount": {"n": 1},
        "unknownDeviceCount": 0,
        "devices": [{"deviceName": "SECRET-NAME"}],
        "@odata.type": "#microsoft.graph.deviceCompliancePolicyDeviceStateSummary",
        "extraCount": 99,
    }  # remediatedDeviceCount absent
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, "get_compliance_summary"))
    assert set(out) == SUMMARY_KEYS
    assert out["unknownDeviceCount"] == 0
    assert [v for k, v in out.items() if k != "unknownDeviceCount"] == [None] * 8


async def test_compliance_summary_takes_no_arguments_and_is_configuration_only(h, h_default):
    token = await bearer(h, OID_A)
    text = error_text(await h.call_tool(token, "get_compliance_summary", {"device_id": "x"}))
    assert text.startswith("1 validation error for call[get_compliance_summary]")
    assert h.token_requests == [] and h.graph_requests == []
    default_token = await bearer(h_default, OID_A)
    assert error_text(await h_default.call_tool(default_token, "get_compliance_summary")) == (
        "Unknown tool: 'get_compliance_summary'"
    )
    assert "get_compliance_summary" in TOOL_GROUPS["configuration"].tools
    assert "get_compliance_summary" not in TOOL_GROUPS["devices"].tools
    assert len(TOOL_GROUPS["configuration"].tools) == 14


async def test_compliance_summary_failures_are_safe_and_audited(h, caplog):
    import logging

    prime_config(h)
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.INFO, logger="intune_mcp.audit"):
        payload(await h.call_tool(token, "get_compliance_summary"))
        h.graph._client = httpx2.AsyncClient(  # noqa: SLF001
            transport=httpx2.MockTransport(lambda r: httpx2.Response(404, json={"error": "S"}))
        )
        text = error_text(await h.call_tool(token, "get_compliance_summary"))
    assert text.startswith("not_found: No matching compliance summary is visible")
    ok, failed = audit_lines(caplog)
    assert "tool=get_compliance_summary" in ok and "outcome=ok" in ok and "target=" not in ok
    assert "outcome=not_found" in failed


def assignments_for(n):
    return [
        {
            "id": f"a{i}",
            "target": {
                "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                "groupId": GROUP_A,
            },
        }
        for i in range(n)
    ]


async def test_a_sub_collection_that_ignores_top_is_returned_in_full(h):
    """30 assignments for page_size 25: all 30 come back, none silently dropped."""
    h.ignore_top = True
    put(h, OID_A, COMPLIANCE, [row(COMPLIANCE, 1)], assignments=assignments_for(30))
    token = await bearer(h, OID_A)
    out = payload(
        await h.call_tool(
            token,
            "get_compliance_policy_assignments",
            {"policy_id": guid("p", 1), "page_size": 25},
        )
    )
    assert h.graph_requests[-1].url.params["$top"] == "25"
    assert out["count"] == 30 == len(out["assignments"])
    assert [a["id"] for a in out["assignments"]] == [f"a{i}" for i in range(30)]
    assert out["complete"] is True and out["next_page_token"] is None and out["note"] is None


async def test_more_than_1000_rows_in_one_page_fails_closed_for_a_tool(h):
    h.ignore_top = True
    put(h, OID_A, COMPLIANCE, [row(COMPLIANCE, 1)], assignments=assignments_for(1001))
    token = await bearer(h, OID_A)
    text = error_text(
        await h.call_tool(token, "get_compliance_policy_assignments", {"policy_id": guid("p", 1)})
    )
    assert (
        text.startswith("bad_response: Microsoft Graph returned too many rows") and "(ref " in text
    )
    put(h, OID_A, COMPLIANCE, [row(COMPLIANCE, 1)], assignments=assignments_for(1000))
    ok = payload(
        await h.call_tool(token, "get_compliance_policy_assignments", {"policy_id": guid("p", 1)})
    )
    assert ok["count"] == 1000


@pytest.mark.parametrize("paren_links", [False, True], ids=["segment-links", "key-links"])
async def test_assignments_and_state_pages_follow_either_nextlink_form(h, paren_links):
    """Both link shapes Graph may use walk to the end; the key form needs the bound GUID."""
    h.paren_links = paren_links
    d = prime(h)
    h.children[OID_A] = {
        (d["id"], "deviceCompliancePolicyStates"): [state_row(i) for i in range(5)]
    }
    put(h, OID_A, COMPLIANCE, [row(COMPLIANCE, 1)], assignments=assignments_for(5))
    token = await bearer(h, OID_A)
    for tool, args, key in (
        ("get_compliance_policy_assignments", {"policy_id": guid("p", 1)}, "assignments"),
        ("get_device_compliance_states", {"device_id": d["id"]}, "compliance_states"),
    ):
        out = payload(await h.call_tool(token, tool, {**args, "page_size": 2}))
        collected = list(out[key])
        while out["next_page_token"]:
            out = payload(
                await h.call_tool(token, tool, {**args, "page_token": out["next_page_token"]})
            )
            collected += out[key]
        assert len(collected) == 5 and out["complete"] is True, tool
    if paren_links:
        assert any("(" in r.url.path for r in h.graph_requests) is False  # we rebuild the URL


async def test_free_text_is_bounded_in_every_policy_and_profile_result(h):
    huge = "T" * 100_000
    for kind in KINDS:
        put(
            h,
            OID_A,
            kind,
            [row(kind, 1, displayName=huge, description=huge)],
            status=STATUS,
            assignments=ASSIGNMENTS,
        )
    token = await bearer(h, OID_A)
    for kind in KINDS:
        listed = payload(await h.call_tool(token, kind.list_tool, {}))[kind.list_key][0]
        got = payload(
            await h.call_tool(token, kind.get_tool, {kind.id_arg: guid(kind.owners[0], 1)})
        )
        for item in (listed, got):
            assert item["displayName"] == "T" * 255 + "…"
            assert item["description"] == "T" * 499 + "…"


async def test_a_huge_device_name_is_bounded_in_device_tools(h):
    d = device(1, deviceName="D" * 100_000)
    h.devices[OID_A] = [d]
    token = await bearer(h, OID_A)
    listed = payload(await h.call_tool(token, "list_devices"))["devices"][0]
    one = payload(await h.call_tool(token, "get_device", {"device_id": d["id"]}))
    assert listed["deviceName"] == one["deviceName"] == "D" * 255 + "…"


async def test_timestamps_are_normalised_or_null_in_tool_results(h):
    put(
        h,
        OID_A,
        COMPLIANCE,
        [
            row(
                COMPLIANCE,
                1,
                createdDateTime="2016-12-31T23:58:21.6459442-08:00",
                lastModifiedDateTime="2026-99-99T99:99:99Z",
            )
        ],
        status={**STATUS, "lastUpdateDateTime": "2026-03-01T10:00:00+02:00"},
    )
    d = device(1, lastSyncDateTime="2026-03-01T10:00:00.5+01:00", enrolledDateTime="not a date")
    h.devices[OID_A] = [d]
    token = await bearer(h, OID_A)
    ident = guid("p", 1)
    got = payload(await h.call_tool(token, "get_compliance_policy", {"policy_id": ident}))
    assert got["createdDateTime"] == "2017-01-01T07:58:21.6459442Z"
    assert got["lastModifiedDateTime"] is None
    listed = payload(await h.call_tool(token, "list_compliance_policies"))["policies"][0]
    assert listed["createdDateTime"] == got["createdDateTime"]
    status = payload(
        await h.call_tool(token, "get_compliance_policy_status_overview", {"policy_id": ident})
    )
    assert status["lastUpdateDateTime"] == "2026-03-01T08:00:00Z"
    one = payload(await h.call_tool(token, "get_device", {"device_id": d["id"]}))
    assert one["lastSyncDateTime"] == "2026-03-01T09:00:00.5Z" and one["enrolledDateTime"] is None
    assert payload(await h.call_tool(token, "list_devices"))["devices"][0]["lastSyncDateTime"] == (
        "2026-03-01T09:00:00.5Z"
    )


async def schemas(h, token):
    from .test_device_tools import tool_schemas

    return await tool_schemas(h, token)


async def test_tool_descriptions_state_the_documented_caveats(h):
    token = await bearer(h, OID_A)
    described = {n: t["description"] for n, t in (await schemas(h, token)).items()}
    for tool in ("get_compliance_policy_assignments", "get_configuration_profile_assignments"):
        assert '"not reported", not "unfiltered"' in described[tool]
    assert "Settings Catalog" in described["list_configuration_profiles"]
    assert "NOT included" in described["list_configuration_profiles"]
    assert "conflictCount" in described["get_compliance_policy_status_overview"]
    assert "null" in described["get_compliance_policy_status_overview"]
    assert "compliance totals" in described["get_compliance_summary"]


def test_instructions_call_all_returned_text_untrusted_and_document_the_filter_caveat():
    both = instructions_for(("devices", "configuration"))
    assert "untrusted data" in both and "never instructions" in both
    assert "trailing ellipsis" in both and "more rows than page_size" in both
    assert "also returned configManager rows" in both and "authoritative" in both
    assert "count_devices has no compliance filter" in both
    assert "not Settings Catalog" in both
    assert "not reported, not unfiltered" in both
    assert "conflictCount is null for compliance policies" in both
    assert "get_compliance_summary" in both
