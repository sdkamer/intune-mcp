"""G5: real HTTP/OAuth/MCP, mocked Microsoft only. No live evidence."""

import json
import logging

import httpx2
import pytest

from intune_mcp.config import GRAPH_SCOPE, RBAC_SCOPE
from intune_mcp.graph import (
    MAX_RESPONSE_BYTES,
    RBAC_FIELDS,
    ROLE_ASSIGNMENT_SPEC,
    ROLE_ASSIGNMENTS_SPEC,
    plan_object,
)
from intune_mcp.groups import TOOL_GROUPS

from .conftest import OID_A, OID_B, graph_token, make_settings
from .harness import Harness
from .test_device_tools import audit_lines, bearer, error_text, guid, payload
from .test_tool_groups import DEFAULT_TOOLS, authorize_scopes, scp_of, tools

ROLE_ID = guid("a", 1)
ASSIGNMENT_ID = guid("c", 1)
DETAIL_ARGS = {"role_definition_id": ROLE_ID, "role_assignment_id": ASSIGNMENT_ID}
ROOT = "/v1.0/deviceManagement/roleDefinitions"
CALLS = [
    ("list_role_definitions", {}),
    ("get_role_definition", {"role_definition_id": ROLE_ID}),
    ("list_role_assignments", {"role_definition_id": ROLE_ID}),
    ("get_role_assignment", DETAIL_ARGS),
]
SECRET = "SECRET-RBAC-EXTRA"
SENSITIVE = {
    k: SECRET
    for k in (
        "credentials",
        "accessToken",
        "secret",
        "users",
        "userPrincipalName",
        "groupDisplayNames",
        "settings",
        "notActions",
        "isBuiltInRoleDefinition",
    )
}


def prime(h):
    row = dict(
        id=ROLE_ID,
        displayName="x" * 800,
        description="d" * 800,
        isBuiltIn=True,
        rolePermissions=[
            {
                "resourceActions": [
                    {
                        "allowedResourceActions": ["DeviceManagement_Read"],
                        "notAllowedResourceActions": [SECRET],
                        **SENSITIVE,
                    }
                ],
                **SENSITIVE,
            }
        ],
        **SENSITIVE,
    )
    h.rbac_rows[OID_A] = {"roleDefinitions": [dict(row, id=guid("a", i)) for i in range(1, 4)]}
    assignments = [
        dict(
            id=guid("c", i),
            displayName="x" * 800,
            description="d" * 800,
            members=[guid("b", i), "not-a-guid", {"secret": SECRET}],
            resourceScopes=[guid("d", i)],
            scopeType=SECRET,
            **SENSITIVE,
        )
        for i in range(1, 4)
    ]
    h.rbac_children[OID_A] = {("roleDefinitions", ROLE_ID, "roleAssignments"): assignments}
    h.rbac_children[OID_B] = dict(h.rbac_children[OID_A])


@pytest.fixture
async def h():
    async with Harness(make_settings(enabled_tool_groups="rbac")).running() as x:
        prime(x)
        yield x


@pytest.mark.parametrize("enabled", ["devices", "rbac", "devices,configuration,apps,rbac"])
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
async def test_fields_scope_audit_and_secret_exclusion(h, caplog, tool, args):
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.INFO):
        out = payload(await h.call_tool(token, tool, args))
    assert [s for _, s in h.token_requests] == [(RBAC_SCOPE,)]
    assert {scp_of(r) for r in h.graph_requests} == {RBAC_SCOPE.rsplit("/", 1)[1]}
    assert SECRET not in json.dumps(out)
    assert all(k not in json.dumps(out) for k in SENSITIVE)
    if tool in ("list_role_assignments", "get_role_assignment"):
        child_path = ROOT + "/" + ROLE_ID + "/roleAssignments"
        if tool == "get_role_assignment":
            child_path += "/" + ASSIGNMENT_ID
            assert dict(h.graph_requests[-1].url.params) == {}
        assert [r.url.path for r in h.graph_requests] == [ROOT + "/" + ROLE_ID, child_path]
        assert dict(h.graph_requests[0].url.params) == {"$select": "id"}
        row = out if tool == "get_role_assignment" else out["assignments"][0]
        assert set(row) == {"id", "displayName", "description", "members", "resourceScopes"}
        assert row["members"] == [guid("b", 1)] and row["resourceScopes"] == [guid("d", 1)]
    else:
        row = out if tool == "get_role_definition" else out["role_definitions"][0]
        expected = {"id", "displayName", "description", "isBuiltIn", "role_permission_count"}
        if tool == "get_role_definition":
            expected |= {"allowed_resource_actions", "allowed_resource_actions_complete"}
            assert row["allowed_resource_actions"] == ["DeviceManagement_Read"]
            assert row["allowed_resource_actions_complete"] is True
        assert set(row) == expected
        assert row["role_permission_count"] == 1 and row["isBuiltIn"] is True
        assert set(h.graph_requests[-1].url.params["$select"].split(",")) == set(RBAC_FIELDS)
    assert len(row["displayName"]) == 256 and len(row["description"]) == 500
    [line] = audit_lines(caplog)
    assert "outcome=ok" in line and "x" * 50 not in line and SECRET not in line
    if tool == "get_role_assignment":
        assert "members_dropped=2" in line and "resourceScopes_dropped=0" in line


@pytest.mark.parametrize("tool", ["get_role_definition", "list_role_assignments"])
@pytest.mark.parametrize("bad", ["../users", "", "1", "x" * 5000, ROLE_ID + "\nforged"])
async def test_guid_before_exchange(h, tool, bad):
    token = await bearer(h, OID_A)
    assert error_text(await h.call_tool(token, tool, {"role_definition_id": bad})).startswith(
        "invalid_role_definition_id:"
    )
    assert not h.token_requests and not h.graph_requests


@pytest.mark.parametrize(
    "tool,key,args",
    [
        ("list_role_definitions", "role_definitions", {}),
        ("list_role_assignments", "assignments", {"role_definition_id": ROLE_ID}),
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
    other_tool = "list_role_definitions" if args else "list_role_assignments"
    other_args = {} if args else {"role_definition_id": ROLE_ID}
    assert error_text(
        await h.call_tool(token, other_tool, dict(other_args, page_token=cursor))
    ).startswith("invalid_page_token:")
    if args:
        assert error_text(
            await h.call_tool(
                token, tool, {"role_definition_id": guid("a", 2), "page_token": cursor}
            )
        ).startswith("invalid_page_token:")
    assert len(h.token_requests) == before


@pytest.mark.parametrize("tool,args", CALLS[2:])
async def test_restricted_user_hidden_parent_never_reads_leaky_child(h, tool, args):
    # Control: stub would leak the child without the parent check.
    req = httpx2.Request(
        "GET",
        "https://graph.microsoft.com"
        + ROOT
        + "/"
        + ROLE_ID
        + "/roleAssignments"
        + ("/" + ASSIGNMENT_ID if tool == "get_role_assignment" else ""),
        headers={"authorization": "Bearer " + graph_token(OID_B, scp=RBAC_SCOPE.rsplit("/", 1)[1])},
    )
    assert h._graph_handler(req).status_code == 200  # noqa: SLF001
    h.graph_requests.clear()
    token = await bearer(h, OID_B)
    assert payload(await h.call_tool(token, "list_role_definitions"))["role_definitions"] == []
    h.graph_requests.clear()
    text = error_text(await h.call_tool(token, tool, args))
    assert text.startswith("not_found: No matching role definition is visible")
    assert [r.url.path for r in h.graph_requests] == [ROOT + "/" + ROLE_ID]


async def test_visibility_rechecked_on_later_page(h):
    token = await bearer(h, OID_A)
    first = payload(
        await h.call_tool(
            token, "list_role_assignments", {"role_definition_id": ROLE_ID, "page_size": 1}
        )
    )
    h.rbac_rows[OID_A] = {}
    h.graph_requests.clear()
    text = error_text(
        await h.call_tool(
            token,
            "list_role_assignments",
            {"role_definition_id": ROLE_ID, "page_token": first["next_page_token"]},
        )
    )
    assert text.startswith("not_found:")
    assert [r.url.path for r in h.graph_requests] == [ROOT + "/" + ROLE_ID]


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
@pytest.mark.parametrize("tool", ["list_role_definitions", "list_role_assignments"])
async def test_response_bounds(h, kind, tool):
    def handler(request):
        if request.url.params.get("$select") == "id":
            return httpx2.Response(200, json={"id": ROLE_ID})
        if kind == "bytes":
            return httpx2.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))
        body = {"value": [{}] * (1001 if kind == "rows" else 1)}
        if kind == "nextlink":
            body["@odata.nextLink"] = "https://evil.example/roleDefinitions?$skiptoken=1"
        return httpx2.Response(200, json=body)

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))  # noqa: SLF001
    token = await bearer(h, OID_A)
    args = {} if tool == "list_role_definitions" else {"role_definition_id": ROLE_ID}
    assert error_text(await h.call_tool(token, tool, args)).startswith("bad_response:")


async def test_read_layer_refuses_unchecked_parent(h):
    plan = h.graph.plan(
        ROLE_ASSIGNMENTS_SPEC,
        path_args={"role_definition_id": ROLE_ID},
        page_size=5,
        page_token=None,
    )
    with pytest.raises(ValueError):
        await h.graph.fetch_page("opaque", plan, "cid")
    assert not h.graph_requests


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


@pytest.mark.parametrize("body", [{}, {"id": guid("b", 9)}, {"id": [ROLE_ID]}])
@pytest.mark.parametrize("tool,args", CALLS[2:])
async def test_malformed_parent_fails_closed(h, body, tool, args):
    def handler(request):
        h.graph_requests.append(request)
        return httpx2.Response(200, json=body)

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))  # noqa: SLF001
    token = await bearer(h, OID_A)
    text = error_text(await h.call_tool(token, tool, args))
    assert text.startswith("bad_response:")
    assert [r.url.path for r in h.graph_requests] == [ROOT + "/" + ROLE_ID]


async def test_refused_rbac_obo_leaves_graph_untouched(h):
    class Refused:
        async def get_token(self, *scopes):
            assert scopes == (RBAC_SCOPE,)
            raise RuntimeError("AADSTS65001: " + SECRET)

    async def credential(assertion):
        return Refused()

    h.token_source.get_credential = credential
    token = await bearer(h, OID_A)
    text = error_text(await h.call_tool(token, "list_role_definitions"))
    assert text.startswith("graph_consent_required:") and SECRET not in text
    assert not h.graph_requests


async def test_get_role_definition_response_size_is_bounded(h):
    h.graph._client = httpx2.AsyncClient(  # noqa: SLF001
        transport=httpx2.MockTransport(
            lambda r: httpx2.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))
        )
    )
    token = await bearer(h, OID_A)
    assert error_text(
        await h.call_tool(token, "get_role_definition", {"role_definition_id": ROLE_ID})
    ).startswith("bad_response:")


@pytest.mark.parametrize(
    "tool,key,args",
    [
        ("list_role_definitions", "role_definitions", {}),
        ("list_role_assignments", "assignments", {"role_definition_id": ROLE_ID}),
    ],
)
async def test_ignored_top_returns_all_bounded_rows(h, tool, key, args):
    h.ignore_top = True
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, tool, dict(args, page_size=1)))
    assert len(out[key]) == 3 and out["count"] == 3 and out["complete"] is True


@pytest.mark.parametrize("kind", ["many", "long", "malformed"])
async def test_allowed_actions_are_bounded_strings_only(h, kind):
    values = {
        "many": ["read"] * 1001,
        "long": ["x" * 800],
        "malformed": [{"secret": SECRET}, 1, None],
    }[kind]
    h.rbac_rows[OID_A]["roleDefinitions"][0]["rolePermissions"] = [
        {
            "resourceActions": [
                {"allowedResourceActions": values, "notAllowedResourceActions": [SECRET]}
            ]
        }
    ]
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, "get_role_definition", {"role_definition_id": ROLE_ID}))
    actions = out["allowed_resource_actions"]
    assert len(actions) <= 1000
    assert all(isinstance(a, str) and len(a) <= 256 for a in actions)
    assert out["allowed_resource_actions_complete"] is False
    assert SECRET not in json.dumps(out)


async def test_group_id_list_bounds_and_missing_fields(h):
    child = h.rbac_children[OID_A][("roleDefinitions", ROLE_ID, "roleAssignments")][0]
    child["members"] = [guid("b", 1)] * 1001
    token = await bearer(h, OID_A)
    args = {"role_definition_id": ROLE_ID}
    assert error_text(await h.call_tool(token, "list_role_assignments", args)).startswith(
        "bad_response:"
    )
    child.pop("members")
    child["resourceScopes"] = {"secret": SECRET}
    out = payload(await h.call_tool(token, "list_role_assignments", args))["assignments"][0]
    assert out["members"] is None and out["resourceScopes"] is None


@pytest.mark.parametrize(
    "status,code", [(400, "bad_request"), (403, "forbidden"), (404, "not_found")]
)
@pytest.mark.parametrize("tool,args", CALLS[2:])
async def test_child_error_after_valid_parent(h, status, code, tool, args):
    real = h._graph_handler  # noqa: SLF001

    def handler(request):
        if "/roleAssignments" in request.url.path:
            h.graph_requests.append(request)
            return httpx2.Response(status, json={"error": SECRET})
        return real(request)

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))  # noqa: SLF001
    token = await bearer(h, OID_A)
    text = error_text(await h.call_tool(token, tool, args))
    assert text.startswith(code + ":") and SECRET not in text
    assert len(h.graph_requests) == 2


@pytest.mark.parametrize("name", ["role_definition_id", "role_assignment_id"])
@pytest.mark.parametrize("bad", ["../users", "", "1", "x" * 5000, ROLE_ID + "\nforged"])
async def test_assignment_guid_validation_before_exchange(h, caplog, name, bad):
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.INFO):
        text = error_text(
            await h.call_tool(token, "get_role_assignment", dict(DETAIL_ARGS, **{name: bad}))
        )
    assert text.startswith(f"invalid_{name}:")
    assert not h.token_requests and not h.graph_requests
    [line] = audit_lines(caplog)
    assert "forged" not in line and "x" * 50 not in line
    assert (
        "target=invalid" in line
        if name == "role_assignment_id"
        else f"target={ASSIGNMENT_ID}" in line
    )


@pytest.mark.parametrize("field", ["members", "resourceScopes"])
@pytest.mark.parametrize("kind", ["max", "too_many", "hostile", "missing", "malformed", "bytes"])
async def test_assignment_detail_bounds_and_guid_only(h, caplog, field, kind):
    child = h.rbac_children[OID_A][("roleDefinitions", ROLE_ID, "roleAssignments")][0]
    if kind in ("max", "too_many"):
        child[field] = [guid("b", 1)] * (1000 if kind == "max" else 1001)
    elif kind == "hostile":
        child[field] = [
            guid("b", 1).upper(),
            "AllDevices",
            "AllLicensedUsers",
            SECRET,
            {"id": guid("b", 2)},
            None,
            7,
            True,
        ]
    elif kind == "missing":
        child.pop(field)
    elif kind == "malformed":
        child[field] = {"secret": SECRET}
    else:
        child["extra"] = "x" * MAX_RESPONSE_BYTES
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.INFO):
        raw = await h.call_tool(token, "get_role_assignment", DETAIL_ARGS)
    if kind in ("too_many", "bytes"):
        assert error_text(raw).startswith("bad_response:")
    else:
        out = payload(raw)
        assert set(out) == {"id", "displayName", "description", "members", "resourceScopes"}
        assert SECRET not in json.dumps(out)
        if kind == "max":
            assert len(out[field]) == 1000
        elif kind == "hostile":
            assert out[field] == [guid("b", 1)]
            assert f"{field}_dropped=7" in audit_lines(caplog)[-1]
        else:
            assert out[field] is None
    assert len(h.graph_requests) == 2


async def test_assignment_read_layer_refuses_unchecked_parent(h):
    plan = plan_object(ROLE_ASSIGNMENT_SPEC, path_args=DETAIL_ARGS)
    with pytest.raises(ValueError):
        await h.graph.fetch_object("opaque", plan, "cid")
    assert not h.graph_requests


async def test_assignment_catalog_count_and_list_guidance(h):
    from .test_device_tools import tool_schemas

    token = await bearer(h, OID_A)
    schemas = await tool_schemas(h, token)
    assert len(schemas) == 5  # whoami + four RBAC tools
    description = schemas["list_role_assignments"]["description"]
    assert "may be empty" in description and "get_role_assignment" in description
    async with Harness(
        make_settings(enabled_tool_groups="devices,configuration,apps,rbac")
    ).running() as all_h:
        all_token = await bearer(all_h, OID_A)
        assert (
            len(await tools(all_h, all_token)) == 34
        )  # 26 + protection 3 + app config 4 + summaries 2


async def test_hidden_role_get_is_not_found(h):
    token = await bearer(h, OID_B)
    assert error_text(
        await h.call_tool(token, "get_role_definition", {"role_definition_id": ROLE_ID})
    ).startswith("not_found:")
