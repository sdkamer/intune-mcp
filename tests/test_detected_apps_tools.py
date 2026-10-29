"""Opt-in tenant inventory (detected apps): real HTTP/OAuth/MCP, mocked Microsoft only."""

import json
import logging

import httpx2
import pytest

from intune_mcp.config import GRAPH_SCOPE
from intune_mcp.graph import (
    DETECTED_APP_FIELDS,
    DETECTED_APP_SPEC,
    LIST_DETECTED_APPS_SPEC,
    MAX_RESPONSE_BYTES,
)
from intune_mcp.groups import INVENTORY_TOOLS, TOOL_GROUPS

from .conftest import OID_A, make_settings
from .harness import Harness
from .test_device_tools import audit_lines, bearer, error_text, guid, payload
from .test_tool_groups import DEFAULT_TOOLS, scp_of, tools

APP_ID = guid("a", 1)
ROOT = "/v1.0/deviceManagement/detectedApps"
CALLS = [("list_detected_apps", {}), ("get_detected_app", {"detected_app_id": APP_ID})]
SECRET = "SECRET-DETECTED"
HOSTILE = {
    k: SECRET + " user@example.com https://evil.example/x"
    for k in (
        "managedDevices",
        "serialNumber",
        "installCommandLine",
        "certificate",
        "downloadUrl",
        "userPrincipalName",
        "settings",
        "script",
    )
}


def prime(h):
    rows = [
        dict(
            id=guid("a", i),
            displayName="x" * 800,
            version="1.2.3",
            sizeInByte=1024,
            deviceCount=7,
            publisher="p" * 800,
            platform="windows",
            **HOSTILE,
        )
        for i in range(1, 4)
    ]
    rows[0]["@odata.type"] = "#microsoft.graph.detectedApp"
    h.detected_rows[OID_A] = {"detectedApps": rows}


@pytest.fixture
async def h():
    settings = make_settings(enabled_tool_groups="devices", enable_tenant_inventory=True)
    async with Harness(settings).running() as x:
        prime(x)
        yield x


async def test_default_off_tools_absent():
    async with Harness(make_settings()).running() as h:
        token = await bearer(h, OID_A)
        assert await tools(h, token) == DEFAULT_TOOLS
        for tool, args in CALLS:
            assert "Unknown tool" in error_text(await h.call_tool(token, tool, args))
        assert not h.token_requests and not h.graph_requests


async def test_on_registers_exactly_two_extra_tools_devices_scope_only(h):
    token = await bearer(h, OID_A)
    assert await tools(h, token) == sorted({*DEFAULT_TOOLS, *INVENTORY_TOOLS})
    assert not set(INVENTORY_TOOLS) & set(TOOL_GROUPS["devices"].tools)
    for tool, args in CALLS:
        h.token_requests.clear()
        h.graph_requests.clear()
        payload(await h.call_tool(token, tool, args))
        assert [s for _, s in h.token_requests] == [(GRAPH_SCOPE,)]
        assert {scp_of(r) for r in h.graph_requests} == {GRAPH_SCOPE.rsplit("/", 1)[1]}


def test_inventory_requires_devices_group():
    with pytest.raises(ValueError):
        make_settings(enabled_tool_groups="apps", enable_tenant_inventory=True)
    assert make_settings(enable_tenant_inventory=False).enable_tenant_inventory is False


@pytest.mark.parametrize(("tool", "args"), CALLS)
async def test_allowlist_bounds_and_audit(h, caplog, tool, args):
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.INFO):
        out = payload(await h.call_tool(token, tool, args))
    dumped = json.dumps(out)
    assert SECRET not in dumped and "example.com" not in dumped and "evil" not in dumped
    assert all(k not in dumped for k in HOSTILE)
    row = out if tool == "get_detected_app" else out["detected_apps"][0]
    assert set(row) == set(DETECTED_APP_FIELDS)
    assert len(row["displayName"]) == 256 and len(row["publisher"]) == 256
    assert row["version"] == "1.2.3" and row["deviceCount"] == 7 and row["platform"] == "windows"
    assert row["sizeInByte"] == 1024
    assert set(h.graph_requests[-1].url.params["$select"].split(",")) == set(DETECTED_APP_FIELDS)
    assert h.graph_requests[-1].url.path.startswith(ROOT)
    [line] = audit_lines(caplog)
    assert "outcome=ok" in line and "x" * 50 not in line and SECRET not in line


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("version", "1.0\nforged"),
        ("version", "https://evil.example"),
        ("version", "v" * 65),
        ("sizeInByte", -1),
        ("sizeInByte", "5"),
        ("deviceCount", True),
        ("deviceCount", {"x": SECRET}),
        ("platform", "evil"),
        ("platform", ["windows"]),
        ("id", "../x"),
        ("displayName", {"x": SECRET}),
    ],
)
def test_shape_rejects_malformed_values(field, value):
    for spec in (LIST_DETECTED_APPS_SPEC, DETECTED_APP_SPEC):
        out = spec.shape({field: value})
        assert out[field] is None
        assert SECRET not in json.dumps(out)


@pytest.mark.parametrize("bad", ["../users", "", "1", "x" * 5000, APP_ID + "\nforged"])
async def test_guid_before_exchange(h, bad):
    token = await bearer(h, OID_A)
    text = error_text(await h.call_tool(token, "get_detected_app", {"detected_app_id": bad}))
    assert text.startswith("invalid_detected_app_id:")
    assert not h.token_requests and not h.graph_requests


@pytest.mark.parametrize("paren", [False, True])
async def test_paging_and_binding(h, paren):
    h.paren_links = paren
    token = await bearer(h, OID_A)
    first = payload(await h.call_tool(token, "list_detected_apps", {"page_size": 1}))
    cursor = first["next_page_token"]
    second = payload(
        await h.call_tool(token, "list_detected_apps", {"page_token": cursor, "page_size": 100})
    )
    assert (
        first["complete"] is False
        and second["detected_apps"][0]["id"] != first["detected_apps"][0]["id"]
    )
    assert h.graph_requests[-1].url.params["$top"] == "1"
    before = len(h.token_requests)
    # A token from another endpoint is rejected before any exchange, in both directions.
    assert error_text(await h.call_tool(token, "list_devices", {"page_token": cursor})).startswith(
        "invalid_page_token:"
    )
    assert len(h.token_requests) == before


async def test_unknown_filter_argument_rejected(h):
    token = await bearer(h, OID_A)
    assert error_text(await h.call_tool(token, "list_detected_apps", {"name_prefix": "a"}))
    assert not h.token_requests and not h.graph_requests


@pytest.mark.parametrize(
    "status,code", [(400, "bad_request"), (403, "forbidden"), (404, "not_found")]
)
@pytest.mark.parametrize(("tool", "args"), CALLS)
async def test_error_mapping(h, status, code, tool, args):
    def handler(request):
        h.graph_requests.append(request)
        return httpx2.Response(status, json={"error": SECRET})

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))  # noqa: SLF001
    token = await bearer(h, OID_A)
    text = error_text(await h.call_tool(token, tool, args))
    assert text.startswith(code + ":") and SECRET not in text
    assert len(h.graph_requests) == 1


@pytest.mark.parametrize("kind", ["rows", "bytes", "nextlink"])
async def test_list_response_bounds(h, kind):
    def handler(request):
        if kind == "bytes":
            return httpx2.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))
        body = {"value": [{}] * (1001 if kind == "rows" else 1)}
        if kind == "nextlink":
            body["@odata.nextLink"] = "https://evil.example/detectedApps?$skiptoken=1"
        return httpx2.Response(200, json=body)

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))  # noqa: SLF001
    token = await bearer(h, OID_A)
    assert error_text(await h.call_tool(token, "list_detected_apps")).startswith("bad_response:")


async def test_get_response_size_is_bounded(h):
    h.graph._client = httpx2.AsyncClient(  # noqa: SLF001
        transport=httpx2.MockTransport(
            lambda r: httpx2.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))
        )
    )
    token = await bearer(h, OID_A)
    text = error_text(await h.call_tool(token, "get_detected_app", {"detected_app_id": APP_ID}))
    assert text.startswith("bad_response:")


async def test_ignored_top_returns_all_bounded_rows(h):
    h.ignore_top = True
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, "list_detected_apps", {"page_size": 1}))
    assert out["count"] == 3 and out["complete"] is True


async def test_wrong_scope_stub_rejects(h):
    from .conftest import graph_token

    response = h._graph_handler(  # noqa: SLF001
        httpx2.Request(
            "GET",
            "https://graph.microsoft.com" + ROOT,
            headers={
                "authorization": "Bearer " + graph_token(OID_A, scp="DeviceManagementApps.Read.All")
            },
        )
    )
    assert response.status_code == 403


async def test_no_managed_devices_child_tool(h):
    token = await bearer(h, OID_A)
    assert not [t for t in await tools(h, token) if "detected" in t and t not in INVENTORY_TOOLS]
