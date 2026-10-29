"""Configuration group tenant state summaries through the real HTTP app. Entra/Graph mocked.

Nothing here is live evidence (docs/tools/CONFIG-SUMMARIES.md): it proves request building, scope,
allowlist minimisation, bounds and audit policy against a simulation of Graph.
"""

import json
import logging

import httpx2
import pytest

from intune_mcp.config import CONFIGURATION_SCOPE
from intune_mcp.graph import (
    COMPLIANCE_SETTING_SUMMARIES_SPEC,
    CONFIGURATION_STATE_SUMMARY_SPEC,
    MAX_RESPONSE_BYTES,
    POLICY_PLATFORM_TYPES,
)
from intune_mcp.groups import TOOL_GROUPS

from .conftest import OID_A, make_settings
from .harness import Harness
from .test_device_tools import audit_lines, bearer, error_text, guid, payload
from .test_tool_groups import authorize_scopes, scp_of, tools

NEW_TOOLS = ["get_configuration_state_summary", "list_compliance_setting_state_summaries"]
ROOT = "/v1.0/deviceManagement/"
SECRET = "SECRET-HOSTILE-VALUE"
LEAKS = {
    "password": SECRET,
    "adminEmail": "admin@example.invalid",
    "url": "https://evil.example/" + SECRET,
    "settingValue": SECRET,
    "certificate": SECRET,
    "serialNumber": SECRET,
    "settingStates": [{"userPrincipalName": "u@example.invalid"}],
}
COUNTS = {
    "compliantDeviceCount": 4,
    "nonCompliantDeviceCount": 7,
    "errorDeviceCount": 0,
    "conflictDeviceCount": 3,
    "notApplicableDeviceCount": 8,
    "unknownDeviceCount": 2,
    "remediatedDeviceCount": 5,
}


def row(i, **over):
    base = {
        "@odata.type": "#microsoft.graph.deviceCompliancePolicySettingStateSummary",
        "id": guid("a", i),
        "setting": "DeviceCompliancePolicy.PasswordRequired",
        "settingName": "PasswordRequired",
        "platformType": "iOS",
        **COUNTS,
        **LEAKS,
    }
    return {**base, **over}


@pytest.fixture
async def h():
    async with Harness(
        make_settings(enabled_tool_groups="devices,configuration", enable_tenant_inventory=True)
    ).running() as x:
        x.config_state_summary[OID_A] = {**COUNTS, "id": guid("b", 1), **LEAKS}
        x.setting_summaries[OID_A] = [row(i) for i in range(1, 6)]
        yield x


def _no_leaks(out):
    text = json.dumps(out)
    for needle in (SECRET, "example.invalid", "evil.example", "settingStates"):
        assert needle not in text


async def test_tools_in_group_and_scope(h):
    token = await bearer(h, OID_A)
    assert NEW_TOOLS[0] in TOOL_GROUPS["configuration"].tools
    assert NEW_TOOLS[1] not in TOOL_GROUPS["configuration"].tools  # opt-in, outside the group
    assert set(NEW_TOOLS) <= set(await tools(h, token))  # fixture enables the opt-in flag
    for tool in NEW_TOOLS:
        assert tool not in TOOL_GROUPS["devices"].tools
    await h.call_tool(token, NEW_TOOLS[0])
    await h.call_tool(token, NEW_TOOLS[1])
    assert {scp_of(r) for r in h.graph_requests} == {CONFIGURATION_SCOPE.rsplit("/", 1)[1]}
    assert [scopes for _, scopes in h.token_requests] == [(CONFIGURATION_SCOPE,)] * 2


async def test_disabled_without_configuration_group():
    async with Harness(make_settings(enabled_tool_groups="devices")).running() as d:
        token = await bearer(d, OID_A)
        for tool in NEW_TOOLS:
            assert "Unknown tool" in error_text(await d.call_tool(token, tool))
        assert not d.graph_requests
        assert CONFIGURATION_SCOPE not in await authorize_scopes(d)


async def test_state_summary_counts_only_and_endpoint(h):
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, "get_configuration_state_summary"))
    assert out == COUNTS
    _no_leaks(out)
    (req,) = h.graph_requests
    assert req.url.path == ROOT + "deviceConfigurationDeviceStateSummaries"
    assert "$select" not in req.url.params


async def test_state_summary_accepts_value_wrapper_and_drops_bad_counts(h):
    h.config_state_summary[OID_A] = {
        "value": {**COUNTS, "errorDeviceCount": "9", "unknownDeviceCount": True, **LEAKS}
    }
    out = payload(await h.call_tool(await bearer(h, OID_A), "get_configuration_state_summary"))
    assert out == {**COUNTS, "errorDeviceCount": None, "unknownDeviceCount": None}
    h.config_state_summary[OID_A] = {"compliantDeviceCount": -1, "x": SECRET}
    out = payload(await h.call_tool(await bearer(h, OID_A), "get_configuration_state_summary"))
    assert set(out) == set(COUNTS) and set(out.values()) == {None}


async def test_state_summary_takes_no_arguments(h):
    token = await bearer(h, OID_A)
    text = error_text(await h.call_tool(token, NEW_TOOLS[0], {"x": "y"}))
    assert text.startswith("1 validation error")
    assert not h.graph_requests and not h.token_requests


async def test_setting_summaries_allowlist_and_hostile_values(h):
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, NEW_TOOLS[1], {"page_size": 2}))
    assert set(out) == {"setting_summaries", "count", "next_page_token", "complete", "note"}
    assert out["count"] == 2 and out["complete"] is False and out["next_page_token"]
    for r in out["setting_summaries"]:
        assert set(r) == {"id", "setting", "settingName", "platformType", *COUNTS}
        assert r["setting"] == "DeviceCompliancePolicy.PasswordRequired"
    _no_leaks(out)
    (req,) = h.graph_requests
    assert req.url.path == ROOT + "deviceCompliancePolicySettingStateSummaries"
    assert "$select" not in req.url.params


@pytest.mark.parametrize(
    "bad",
    [
        SECRET + " with spaces",
        "https://evil.example/x",
        "a@example.invalid",
        "line\nforged",
        "x" * 200,
        "1starts.with.digit",
        "",
        None,
        5,
        ["a"],
        {"a": 1},
    ],
)
async def test_setting_names_must_be_strict_identifiers(h, bad):
    h.setting_summaries[OID_A] = [
        row(1, setting=bad, settingName=bad, platformType=bad, id=bad, nonCompliantDeviceCount=bad)
    ]
    out = payload(await h.call_tool(await bearer(h, OID_A), NEW_TOOLS[1]))
    (r,) = out["setting_summaries"]
    assert r["setting"] is None and r["settingName"] is None
    assert r["platformType"] is None and r["id"] is None
    assert r["nonCompliantDeviceCount"] is (5 if bad == 5 else None)
    assert SECRET not in json.dumps(out) and "evil.example" not in json.dumps(out)


DOCUMENTED_PLATFORMS = (
    "android",
    "iOS",
    "macOS",
    "windowsPhone81",
    "windows81AndLater",
    "windows10AndLater",
    "androidWorkProfile",
    "linux",
    "all",
)


def test_platform_enum_is_exactly_the_documented_nine():
    """Independent of production: an accidental expansion must fail here."""
    assert set(DOCUMENTED_PLATFORMS) == set(POLICY_PLATFORM_TYPES)
    assert len(DOCUMENTED_PLATFORMS) == 9


@pytest.mark.parametrize("platform", DOCUMENTED_PLATFORMS)
async def test_documented_platform_types_pass(h, platform):
    h.setting_summaries[OID_A] = [row(1, platformType=platform)]
    out = payload(await h.call_tool(await bearer(h, OID_A), NEW_TOOLS[1]))
    assert out["setting_summaries"][0]["platformType"] == platform


async def test_undocumented_platform_type_is_null(h):
    h.setting_summaries[OID_A] = [row(1, platformType="IOS")]
    out = payload(await h.call_tool(await bearer(h, OID_A), NEW_TOOLS[1]))
    assert out["setting_summaries"][0]["platformType"] is None


async def test_paging_walk_and_token_bound_to_endpoint(h):
    token = await bearer(h, OID_A)
    seen, page_token = [], None
    while True:
        args = {"page_size": 2, **({"page_token": page_token} if page_token else {})}
        out = payload(await h.call_tool(token, NEW_TOOLS[1], args))
        seen += [r["id"] for r in out["setting_summaries"]]
        page_token = out["next_page_token"]
        if page_token is None:
            break
    assert seen == [guid("a", i) for i in range(1, 6)]
    # A token minted for another endpoint is refused before any Graph call.
    h.config_rows[OID_A] = {"deviceCompliancePolicies": [{"id": guid("c", i)} for i in (1, 2)]}
    foreign = payload(await h.call_tool(token, "list_compliance_policies", {"page_size": 1}))
    mark = len(h.graph_requests)
    text = error_text(
        await h.call_tool(token, NEW_TOOLS[1], {"page_token": foreign["next_page_token"]})
    )
    assert text.startswith("invalid_page_token:")
    assert len(h.graph_requests) == mark


@pytest.mark.parametrize(
    "status,code", [(400, "bad_request"), (403, "forbidden"), (404, "not_found")]
)
@pytest.mark.parametrize("tool", NEW_TOOLS)
async def test_error_mapping(h, status, code, tool):
    def handler(request):
        h.graph_requests.append(request)
        return httpx2.Response(status, json={"error": SECRET})

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))  # noqa: SLF001
    text = error_text(await h.call_tool(await bearer(h, OID_A), tool))
    assert text.startswith(code + ":") and SECRET not in text
    assert len(h.graph_requests) == 1


@pytest.mark.parametrize("kind", ["rows", "bytes", "nextlink"])
async def test_collection_bounds(h, kind):
    def handler(request):
        if kind == "bytes":
            return httpx2.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))
        body = {"value": [{}] * (1001 if kind == "rows" else 1)}
        if kind == "nextlink":
            body["@odata.nextLink"] = "https://evil.example/x?$skiptoken=1"
        return httpx2.Response(200, json=body)

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))  # noqa: SLF001
    text = error_text(await h.call_tool(await bearer(h, OID_A), NEW_TOOLS[1]))
    assert text.startswith("bad_response:")


async def test_object_size_bounded(h):
    h.graph._client = httpx2.AsyncClient(  # noqa: SLF001
        transport=httpx2.MockTransport(
            lambda r: httpx2.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))
        )
    )
    text = error_text(await h.call_tool(await bearer(h, OID_A), NEW_TOOLS[0]))
    assert text.startswith("bad_response:")


async def test_audit_has_no_values_or_targets(h, caplog):
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.INFO, logger="intune_mcp.audit"):
        await h.call_tool(token, NEW_TOOLS[0])
        await h.call_tool(token, NEW_TOOLS[1])
    lines = [line for line in audit_lines(caplog) if any(t in line for t in NEW_TOOLS)]
    assert len(lines) == 2 and all("outcome=ok" in line for line in lines)
    for line in lines:
        assert "target=" not in line
        for needle in (SECRET, "example.invalid", "PasswordRequired", guid("a", 1)):
            assert needle not in line


def test_specs_are_configuration_scoped_and_not_selected():
    for spec in (CONFIGURATION_STATE_SUMMARY_SPEC, COMPLIANCE_SETTING_SUMMARIES_SPEC):
        assert spec.scope == CONFIGURATION_SCOPE and spec.parent is None and spec.select is False
        assert spec.path.startswith("/deviceManagement/")


async def test_descriptions_state_tenant_level_residual(h):
    from .harness import rpc_body

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
    listed = rpc_body(await h.mcp(token, "tools/list"))["result"]["tools"]
    described = {t["name"]: t["description"] for t in listed}
    for tool in NEW_TOOLS:
        assert "NOT limited to this user's Intune scope" in " ".join(described[tool].split())
        assert "Unverified live" in " ".join(described[tool].split())


@pytest.mark.parametrize("wrapped", [False, True])
@pytest.mark.parametrize("oversized", [2_147_483_648, 10**100, 2**63])
async def test_counts_above_int32_are_null_in_both_tools(h, oversized, wrapped):
    """Review finding: Learn documents Int32 counts; larger values must not be echoed."""
    counts = {
        "compliantDeviceCount": oversized,
        "nonCompliantDeviceCount": 2_147_483_647,  # the documented maximum still passes
        "errorDeviceCount": 3,
    }
    token = await bearer(h, OID_A)
    h.setting_summaries[OID_A] = [row(1, **counts)]
    h.config_state_summary[OID_A] = {"value": counts} if wrapped else counts
    for tool, key in ((NEW_TOOLS[0], None), (NEW_TOOLS[1], "setting_summaries")):
        out = payload(await h.call_tool(token, tool))
        r = out[key][0] if key else out
        assert r["compliantDeviceCount"] is None
        assert r["nonCompliantDeviceCount"] == 2_147_483_647 and r["errorDeviceCount"] == 3
        assert str(oversized) not in json.dumps(out)


async def test_setting_summaries_are_opt_in_and_absent_by_default():
    """Live finding: these aggregates ignore a scoped user's scope, so default-off."""
    async with Harness(make_settings(enabled_tool_groups="devices,configuration")).running() as off:
        token = await bearer(off, OID_A)
        names = set(await tools(off, token))
        assert "get_configuration_state_summary" in names
        assert "list_compliance_setting_state_summaries" not in names
        text = error_text(await off.call_tool(token, NEW_TOOLS[1]))
        assert text and not off.token_requests and not off.graph_requests
    on_settings = make_settings(
        enabled_tool_groups="devices,configuration", enable_tenant_inventory=True
    )
    async with Harness(on_settings).running() as on:
        names = set(await tools(on, await bearer(on, OID_A)))
        assert "list_compliance_setting_state_summaries" in names
    # Without the configuration group the opt-in flag adds nothing for this tool.
    no_cfg_settings = make_settings(enabled_tool_groups="devices", enable_tenant_inventory=True)
    async with Harness(no_cfg_settings).running() as no_cfg:
        names = set(await tools(no_cfg, await bearer(no_cfg, OID_A)))
        assert "list_compliance_setting_state_summaries" not in names
        assert "list_detected_apps" in names
