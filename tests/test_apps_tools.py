"""G3: real HTTP/OAuth/MCP, mocked Microsoft only. No live evidence."""

import json
import logging

import httpx2
import pytest

from intune_mcp.config import APPS_SCOPE, GRAPH_SCOPE
from intune_mcp.graph import (
    APP_ASSIGNMENTS_SPEC,
    APP_DETAIL_FIELDS,
    APP_FIELDS,
    MAX_RESPONSE_BYTES,
)
from intune_mcp.groups import TOOL_GROUPS

from .conftest import OID_A, OID_B, graph_token, make_settings
from .harness import Harness
from .test_device_tools import audit_lines, bearer, error_text, guid, payload
from .test_tool_groups import DEFAULT_TOOLS, authorize_scopes, scp_of, tools

APP_ID = guid("a", 1)
ROOT = "/v1.0/deviceAppManagement/mobileApps"
CALLS = [
    ("list_apps", {}),
    ("get_app", {"app_id": APP_ID}),
    ("get_app_assignments", {"app_id": APP_ID}),
]
SECRET = "SECRET-PER-TYPE"
SENSITIVE = {
    k: SECRET
    for k in (
        "installCommandLine",
        "uninstallCommandLine",
        "detectionRules",
        "requirementRules",
        "rules",
        "scriptContent",
        "msiInformation",
        "productCode",
        "certificate",
        "appConfiguration",
        "largeIcon",
        "contentUrl",
        "downloadUrl",
        "informationUrl",
        "privacyInformationUrl",
        "settings",
    )
}


def prime(h):
    row = dict(
        id=APP_ID,
        displayName="x" * 800,
        publisher="p" * 800,
        description="d" * 800,
        createdDateTime="2026-01-01T00:00:00Z",
        lastModifiedDateTime="2026-01-02T00:00:00Z",
        publishingState="published",
        isAssigned=True,
        **SENSITIVE,
    )
    row["@odata.type"] = "#microsoft.graph.win32LobApp"
    h.app_rows[OID_A] = {"mobileApps": [dict(row, id=guid("a", i)) for i in range(1, 4)]}
    assignments = [
        dict(
            id=f"assignment-{i}",
            intent="required",
            target={
                "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                "groupId": guid("b", i),
                **SENSITIVE,
            },
            **SENSITIVE,
        )
        for i in range(1, 4)
    ]
    h.app_children[OID_A] = {("mobileApps", APP_ID, "assignments"): assignments}
    h.app_children[OID_B] = dict(h.app_children[OID_A])


@pytest.fixture
async def h():
    async with Harness(make_settings(enabled_tool_groups="apps")).running() as x:
        prime(x)
        yield x


@pytest.mark.parametrize("enabled", ["devices", "apps", "devices,configuration,apps"])
async def test_gating_and_authorize_scope_derivation(enabled):
    async with Harness(make_settings(enabled_tool_groups=enabled)).running() as h:
        token = await bearer(h, OID_A)
        expected = {"whoami"}
        for group in enabled.split(","):
            expected.update(TOOL_GROUPS[group].tools)
        assert await tools(h, token) == sorted(expected)
        assert await authorize_scopes(h) == {
            *(TOOL_GROUPS[g].scope for g in enabled.split(",")),
        }
        if enabled == "devices":
            assert sorted(expected) == DEFAULT_TOOLS
            for tool, args in CALLS:
                assert "Unknown tool" in error_text(await h.call_tool(token, tool, args))
            assert not h.token_requests and not h.graph_requests


@pytest.mark.parametrize(("tool", "args"), CALLS)
@pytest.mark.parametrize("app_type", ["win32LobApp", "iosLobApp", "androidManagedStoreApp"])
async def test_fields_scope_audit_and_secret_exclusion(h, caplog, tool, args, app_type):
    for row in h.app_rows[OID_A]["mobileApps"]:
        row["@odata.type"] = "#microsoft.graph." + app_type
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.INFO):
        out = payload(await h.call_tool(token, tool, args))
    assert [s for _, s in h.token_requests] == [(APPS_SCOPE,)]
    assert {scp_of(r) for r in h.graph_requests} == {APPS_SCOPE.rsplit("/", 1)[1]}
    assert SECRET not in json.dumps(out)
    assert all(k not in json.dumps(out) for k in SENSITIVE)
    if tool == "get_app_assignments":
        assert [r.url.path for r in h.graph_requests] == [
            ROOT + "/" + APP_ID,
            ROOT + "/" + APP_ID + "/assignments",
        ]
        assert dict(h.graph_requests[0].url.params) == {"$select": "id"}
        assert out["assignments"][0]["intent"] == "required"
        assert out["assignments"][0]["group_id"] == guid("b", 1)
    else:
        row = out if tool == "get_app" else out["apps"][0]
        fields = APP_DETAIL_FIELDS if tool == "get_app" else APP_FIELDS
        assert set(row) == {*fields, "app_type"}
        assert row["app_type"] == app_type and len(row["displayName"]) == 256
        assert len(row["publisher"]) == 256
        if tool == "get_app":
            assert len(row["description"]) == 500
        assert set(h.graph_requests[-1].url.params["$select"].split(",")) == set(fields)
    [line] = audit_lines(caplog)
    assert "outcome=ok" in line and "x" * 50 not in line and SECRET not in line


@pytest.mark.parametrize("tool", ["get_app", "get_app_assignments"])
@pytest.mark.parametrize("bad", ["../users", "", "1", "x" * 5000, APP_ID + "\nforged"])
async def test_guid_before_exchange(h, tool, bad):
    token = await bearer(h, OID_A)
    assert error_text(await h.call_tool(token, tool, {"app_id": bad})).startswith("invalid_app_id:")
    assert not h.token_requests and not h.graph_requests


@pytest.mark.parametrize(
    "tool,key,args",
    [
        ("list_apps", "apps", {}),
        ("get_app_assignments", "assignments", {"app_id": APP_ID}),
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
    other_tool = "list_apps" if args else "get_app_assignments"
    other_args = {} if args else {"app_id": APP_ID}
    assert error_text(
        await h.call_tool(token, other_tool, dict(other_args, page_token=cursor))
    ).startswith("invalid_page_token:")
    if args:
        assert error_text(
            await h.call_tool(token, tool, {"app_id": guid("a", 2), "page_token": cursor})
        ).startswith("invalid_page_token:")
    assert len(h.token_requests) == before


async def test_restricted_user_hidden_parent_never_reads_leaky_child(h):
    # Control: stub would leak the child without the parent check.
    req = httpx2.Request(
        "GET",
        "https://graph.microsoft.com" + ROOT + "/" + APP_ID + "/assignments",
        headers={"authorization": "Bearer " + graph_token(OID_B, scp=APPS_SCOPE.rsplit("/", 1)[1])},
    )
    assert h._graph_handler(req).json()["value"]  # noqa: SLF001
    h.graph_requests.clear()
    token = await bearer(h, OID_B)
    assert payload(await h.call_tool(token, "list_apps"))["apps"] == []
    h.graph_requests.clear()
    text = error_text(await h.call_tool(token, "get_app_assignments", {"app_id": APP_ID}))
    assert text.startswith("not_found: No matching app is visible")
    assert [r.url.path for r in h.graph_requests] == [ROOT + "/" + APP_ID]


async def test_visibility_rechecked_on_later_page(h):
    token = await bearer(h, OID_A)
    first = payload(
        await h.call_tool(token, "get_app_assignments", {"app_id": APP_ID, "page_size": 1})
    )
    h.app_rows[OID_A] = {}
    h.graph_requests.clear()
    text = error_text(
        await h.call_tool(
            token, "get_app_assignments", {"app_id": APP_ID, "page_token": first["next_page_token"]}
        )
    )
    assert text.startswith("not_found:")
    assert [r.url.path for r in h.graph_requests] == [ROOT + "/" + APP_ID]


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
@pytest.mark.parametrize("tool", ["list_apps", "get_app_assignments"])
async def test_response_bounds(h, kind, tool):
    def handler(request):
        if request.url.params.get("$select") == "id":
            return httpx2.Response(200, json={"id": APP_ID})
        if kind == "bytes":
            return httpx2.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))
        body = {"value": [{}] * (1001 if kind == "rows" else 1)}
        if kind == "nextlink":
            body["@odata.nextLink"] = "https://evil.example/mobileApps?$skiptoken=1"
        return httpx2.Response(200, json=body)

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))  # noqa: SLF001
    token = await bearer(h, OID_A)
    args = {} if tool == "list_apps" else {"app_id": APP_ID}
    assert error_text(await h.call_tool(token, tool, args)).startswith("bad_response:")


async def test_read_layer_refuses_unchecked_parent(h):
    plan = h.graph.plan(
        APP_ASSIGNMENTS_SPEC, path_args={"app_id": APP_ID}, page_size=5, page_token=None
    )
    with pytest.raises(ValueError):
        await h.graph.fetch_page("opaque", plan, "cid")
    assert not h.graph_requests


@pytest.mark.parametrize("intent", ["evil", {"script": SECRET}, None])
def test_assignment_intent_sanitized(intent):
    assert APP_ASSIGNMENTS_SPEC.shape({"intent": intent})["intent"] is None


async def test_wrong_scope_stub_rejects(h):
    response = h._graph_handler(
        httpx2.Request(
            "GET",
            "https://graph.microsoft.com" + ROOT,  # noqa: SLF001
            headers={
                "authorization": "Bearer " + graph_token(OID_A, scp=GRAPH_SCOPE.rsplit("/", 1)[1])
            },
        )
    )
    assert response.status_code == 403


@pytest.mark.parametrize("body", [{}, {"id": guid("b", 9)}, {"id": [APP_ID]}])
async def test_malformed_parent_fails_closed(h, body):
    def handler(request):
        h.graph_requests.append(request)
        return httpx2.Response(200, json=body)

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))  # noqa: SLF001
    token = await bearer(h, OID_A)
    text = error_text(await h.call_tool(token, "get_app_assignments", {"app_id": APP_ID}))
    assert text.startswith("bad_response:")
    assert [r.url.path for r in h.graph_requests] == [ROOT + "/" + APP_ID]


async def test_refused_apps_obo_leaves_graph_untouched(h):
    class Refused:
        async def get_token(self, *scopes):
            assert scopes == (APPS_SCOPE,)
            raise RuntimeError("AADSTS65001: " + SECRET)

    async def credential(assertion):
        return Refused()

    h.token_source.get_credential = credential
    token = await bearer(h, OID_A)
    text = error_text(await h.call_tool(token, "list_apps"))
    assert text.startswith("graph_consent_required:") and SECRET not in text
    assert not h.graph_requests


async def test_get_app_response_size_is_bounded(h):
    h.graph._client = httpx2.AsyncClient(  # noqa: SLF001
        transport=httpx2.MockTransport(
            lambda r: httpx2.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))
        )
    )
    token = await bearer(h, OID_A)
    assert error_text(await h.call_tool(token, "get_app", {"app_id": APP_ID})).startswith(
        "bad_response:"
    )


@pytest.mark.parametrize(
    "tool,key,args",
    [
        ("list_apps", "apps", {}),
        ("get_app_assignments", "assignments", {"app_id": APP_ID}),
    ],
)
async def test_ignored_top_returns_all_bounded_rows(h, tool, key, args):
    h.ignore_top = True
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, tool, dict(args, page_size=1)))
    assert len(out[key]) == 3 and out["count"] == 3 and out["complete"] is True
