"""Apps group: app categories and app configuration policies. Mocked Microsoft; no live evidence."""

import json
import logging

import httpx2
import pytest

from intune_mcp.config import APPS_SCOPE
from intune_mcp.graph import (
    APP_CONFIGURATION_ASSIGNMENTS_SPEC,
    APP_CONFIGURATION_FIELDS,
    MAX_RESPONSE_BYTES,
    app_configuration_summary,
)
from intune_mcp.groups import TOOL_GROUPS

from .conftest import OID_A, OID_B, graph_token, make_settings
from .harness import Harness
from .test_device_tools import audit_lines, bearer, error_text, guid, payload
from .test_tool_groups import scp_of, tools

CFG_ID = guid("c", 1)
ROOT = "/v1.0/deviceAppManagement/mobileAppConfigurations"
CALLS = [
    ("list_app_categories", {}),
    ("list_app_configuration_policies", {}),
    ("get_app_configuration_policy", {"app_configuration_id": CFG_ID}),
    ("get_app_configuration_policy_assignments", {"app_configuration_id": CFG_ID}),
]
SECRET = "SECRET-APP-CONFIG"
HOSTILE = {
    k: [{"appConfigKey": SECRET, "appConfigKeyValue": "https://evil.example/" + SECRET}]
    if k == "settings"
    else SECRET + " admin@example.com https://evil.example/x"
    for k in (
        "settings",
        "payloadJson",
        "encodedSettingXml",
        "appConfigKey",
        "appConfigKeyValue",
        "contentUrl",
        "ownerEmail",
        "userPrincipalName",
        "certificate",
        "password",
    )
}


def prime(h):
    row = dict(
        id=CFG_ID,
        displayName="x" * 800,
        description="d" * 800,
        createdDateTime="2026-01-01T00:00:00Z",
        lastModifiedDateTime="2026-01-02T00:00:00Z",
        version=3,
        targetedMobileApps=[guid("e", 1), guid("e", 2), SECRET],
        **HOSTILE,
    )
    row["@odata.type"] = "#microsoft.graph.iosMobileAppConfiguration"
    categories = [
        dict(
            id=guid("d", i),
            displayName=f"cat-{i}",
            lastModifiedDateTime="2026-01-02T00:00:00Z",
            **HOSTILE,
        )
        for i in range(1, 4)
    ]
    h.app_rows[OID_A] = {
        "mobileAppConfigurations": [dict(row, id=guid("c", i)) for i in range(1, 4)],
        "mobileAppCategories": categories,
    }
    assignments = [
        dict(
            id=guid("f", i),
            target={
                "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                "groupId": guid("b", i),
                "groupName": SECRET,
                **HOSTILE,
            },
            **HOSTILE,
        )
        for i in range(1, 4)
    ]
    h.app_children[OID_A] = {("mobileAppConfigurations", CFG_ID, "assignments"): assignments}
    h.app_children[OID_B] = dict(h.app_children[OID_A])


@pytest.fixture
async def h():
    async with Harness(make_settings(enabled_tool_groups="apps")).running() as x:
        prime(x)
        yield x


def test_group_registers_new_tools():
    names = {t for t, _ in CALLS}
    assert names <= set(TOOL_GROUPS["apps"].tools)
    assert TOOL_GROUPS["apps"].scope == APPS_SCOPE and TOOL_GROUPS["apps"].parent_scope is None


async def test_tools_listed_and_gated():
    async with Harness(make_settings(enabled_tool_groups="apps")).running() as x:
        token = await bearer(x, OID_A)
        assert {t for t, _ in CALLS} <= set(await tools(x, token))
    async with Harness(make_settings(enabled_tool_groups="devices")).running() as x:
        token = await bearer(x, OID_A)
        for tool, args in CALLS:
            assert "Unknown tool" in error_text(await x.call_tool(token, tool, args))
        assert not x.token_requests and not x.graph_requests


@pytest.mark.parametrize(("tool", "args"), CALLS)
@pytest.mark.parametrize("cfg_type", ["iosMobileAppConfiguration", "androidManagedStoreAppConfig"])
async def test_fields_scope_audit_and_secret_exclusion(h, caplog, tool, args, cfg_type):
    for row in h.app_rows[OID_A]["mobileAppConfigurations"]:
        row["@odata.type"] = "#microsoft.graph." + cfg_type
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.INFO):
        out = payload(await h.call_tool(token, tool, args))
    blob = json.dumps(out)
    assert [s for _, s in h.token_requests] == [(APPS_SCOPE,)]
    assert {scp_of(r) for r in h.graph_requests} == {APPS_SCOPE.rsplit("/", 1)[1]}
    assert SECRET not in blob and "evil.example" not in blob and "@example.com" not in blob
    assert all(k not in blob for k in HOSTILE)
    assert all(r.method == "GET" for r in h.graph_requests)
    if tool == "list_app_categories":
        assert set(out["categories"][0]) == {"id", "displayName", "lastModifiedDateTime"}
        assert set(h.graph_requests[-1].url.params["$select"].split(",")) == {
            "id",
            "displayName",
            "lastModifiedDateTime",
        }
    elif tool == "get_app_configuration_policy_assignments":
        assert [r.url.path for r in h.graph_requests] == [
            ROOT + "/" + CFG_ID,
            ROOT + "/" + CFG_ID + "/assignments",
        ]
        assert dict(h.graph_requests[0].url.params) == {"$select": "id"}
        assert out["assignments"][0]["group_id"] == guid("b", 1)
        assert set(out["assignments"][0]) == {
            "id",
            "target_type",
            "group_id",
            "filter_type",
            "filter_id",
        }
    else:
        row = out if tool == "get_app_configuration_policy" else out["policies"][0]
        assert set(row) == {
            "id",
            "displayName",
            "description",
            "createdDateTime",
            "lastModifiedDateTime",
            "version",
            "configuration_type",
            "targeted_app_count",
        }
        assert row["configuration_type"] == cfg_type and row["targeted_app_count"] == 3
        assert len(row["displayName"]) == 256 and len(row["description"]) == 500
        assert row["version"] == 3
        assert set(h.graph_requests[-1].url.params["$select"].split(",")) == set(
            APP_CONFIGURATION_FIELDS
        )
    [line] = audit_lines(caplog)
    assert "outcome=ok" in line and "x" * 50 not in line and SECRET not in line


@pytest.mark.parametrize(
    "tool", ["get_app_configuration_policy", "get_app_configuration_policy_assignments"]
)
@pytest.mark.parametrize(
    "bad", ["../users", "", "1", "x" * 5000, CFG_ID + "\nforged", CFG_ID + "_x"]
)
async def test_guid_before_exchange(h, tool, bad):
    token = await bearer(h, OID_A)
    text = error_text(await h.call_tool(token, tool, {"app_configuration_id": bad}))
    assert text.startswith("invalid_app_configuration_id:")
    assert not h.token_requests and not h.graph_requests


@pytest.mark.parametrize(
    "tool,key,args",
    [
        ("list_app_categories", "categories", {}),
        ("list_app_configuration_policies", "policies", {}),
        (
            "get_app_configuration_policy_assignments",
            "assignments",
            {"app_configuration_id": CFG_ID},
        ),
    ],
)
@pytest.mark.parametrize("paren", [False, True])
async def test_paging_and_binding(h, tool, key, args, paren):
    h.paren_links = paren
    token = await bearer(h, OID_A)
    first = payload(await h.call_tool(token, tool, dict(args, page_size=1)))
    cursor = first["next_page_token"]
    second = payload(await h.call_tool(token, tool, dict(args, page_token=cursor, page_size=100)))
    assert first["complete"] is False and second[key][0]["id"] != first[key][0]["id"]
    assert h.graph_requests[-1].url.params["$top"] == "1"
    before = len(h.token_requests)
    for other, other_args in CALLS:
        if other != tool and other != "get_app_configuration_policy":
            assert error_text(
                await h.call_tool(token, other, dict(other_args, page_token=cursor))
            ).startswith("invalid_page_token:")
    if args:
        assert error_text(
            await h.call_tool(
                token, tool, {"app_configuration_id": guid("c", 2), "page_token": cursor}
            )
        ).startswith("invalid_page_token:")
    assert len(h.token_requests) == before


async def test_restricted_user_hidden_parent_never_reads_leaky_child(h):
    # Control: the stub leaks the child without the parent check.
    req = httpx2.Request(
        "GET",
        "https://graph.microsoft.com" + ROOT + "/" + CFG_ID + "/assignments",
        headers={"authorization": "Bearer " + graph_token(OID_B, scp=APPS_SCOPE.rsplit("/", 1)[1])},
    )
    assert h._graph_handler(req).json()["value"]  # noqa: SLF001
    h.graph_requests.clear()
    token = await bearer(h, OID_B)
    assert payload(await h.call_tool(token, "list_app_configuration_policies"))["policies"] == []
    h.graph_requests.clear()
    text = error_text(
        await h.call_tool(
            token, "get_app_configuration_policy_assignments", {"app_configuration_id": CFG_ID}
        )
    )
    assert text.startswith("not_found: No matching app configuration policy is visible")
    assert [r.url.path for r in h.graph_requests] == [ROOT + "/" + CFG_ID]


async def test_visibility_rechecked_on_later_page(h):
    token = await bearer(h, OID_A)
    args = {"app_configuration_id": CFG_ID}
    first = payload(
        await h.call_tool(
            token, "get_app_configuration_policy_assignments", dict(args, page_size=1)
        )
    )
    h.app_rows[OID_A] = {}
    h.graph_requests.clear()
    text = error_text(
        await h.call_tool(
            token,
            "get_app_configuration_policy_assignments",
            dict(args, page_token=first["next_page_token"]),
        )
    )
    assert text.startswith("not_found:")
    assert [r.url.path for r in h.graph_requests] == [ROOT + "/" + CFG_ID]


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
@pytest.mark.parametrize(
    "tool", ["list_app_categories", "list_app_configuration_policies", "assignments"]
)
async def test_response_bounds(h, kind, tool):
    def handler(request):
        if request.url.params.get("$select") == "id":
            return httpx2.Response(200, json={"id": CFG_ID})
        if kind == "bytes":
            return httpx2.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))
        body = {"value": [{}] * (1001 if kind == "rows" else 1)}
        if kind == "nextlink":
            body["@odata.nextLink"] = "https://evil.example/mobileAppConfigurations?$skiptoken=1"
        return httpx2.Response(200, json=body)

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))  # noqa: SLF001
    token = await bearer(h, OID_A)
    if tool == "assignments":
        tool, args = "get_app_configuration_policy_assignments", {"app_configuration_id": CFG_ID}
    else:
        args = {}
    assert error_text(await h.call_tool(token, tool, args)).startswith("bad_response:")


async def test_read_layer_refuses_unchecked_parent(h):
    plan = h.graph.plan(
        APP_CONFIGURATION_ASSIGNMENTS_SPEC,
        path_args={"app_configuration_id": CFG_ID},
        page_size=5,
        page_token=None,
    )
    with pytest.raises(ValueError):
        await h.graph.fetch_page("opaque", plan, "cid")
    assert not h.graph_requests


@pytest.mark.parametrize("body", [{}, {"id": guid("b", 9)}, {"id": [CFG_ID]}])
async def test_malformed_parent_fails_closed(h, body):
    def handler(request):
        h.graph_requests.append(request)
        return httpx2.Response(200, json=body)

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))  # noqa: SLF001
    token = await bearer(h, OID_A)
    text = error_text(
        await h.call_tool(
            token, "get_app_configuration_policy_assignments", {"app_configuration_id": CFG_ID}
        )
    )
    assert text.startswith("bad_response:")
    assert [r.url.path for r in h.graph_requests] == [ROOT + "/" + CFG_ID]


async def test_refused_apps_obo_leaves_graph_untouched(h):
    class Refused:
        async def get_token(self, *scopes):
            assert scopes == (APPS_SCOPE,)
            raise RuntimeError("AADSTS65001: " + SECRET)

    async def credential(assertion):
        return Refused()

    h.token_source.get_credential = credential
    token = await bearer(h, OID_A)
    text = error_text(await h.call_tool(token, "list_app_categories"))
    assert text.startswith("graph_consent_required:") and SECRET not in text
    assert not h.graph_requests


@pytest.mark.parametrize(
    "row",
    [
        {},
        {"@odata.type": "https://evil.example/" + SECRET, "targetedMobileApps": SECRET},
        {"id": SECRET, "displayName": [SECRET], "description": {"a": SECRET}, "version": True},
        {"version": "3", "createdDateTime": SECRET, "targetedMobileApps": None},
    ],
)
def test_summary_hostile_shapes_are_null_or_unknown(row):
    out = app_configuration_summary(row)
    assert SECRET not in json.dumps(out) and "evil.example" not in json.dumps(out)
    assert out["configuration_type"] == "unknown" and out["targeted_app_count"] is None
    assert out["id"] is None and out["version"] is None and out["createdDateTime"] is None


async def test_ignored_top_returns_all_bounded_rows(h):
    h.ignore_top = True
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, "list_app_configuration_policies", {"page_size": 1}))
    assert len(out["policies"]) == 3 and out["complete"] is True
