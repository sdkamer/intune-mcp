"""Enrollment group, terms and conditions: real HTTP/OAuth/MCP, mocked Microsoft only."""

import json
import logging

import httpx2
import pytest

from intune_mcp.config import SERVICE_CONFIG_SCOPE
from intune_mcp.graph import MAX_RESPONSE_BYTES, TERMS_ASSIGNMENTS_SPEC

from .conftest import OID_A, OID_B, graph_token, make_settings
from .harness import Harness
from .test_device_tools import audit_lines, bearer, error_text, guid, payload
from .test_tool_groups import scp_of

TERMS_ID = guid("a", 1)
ROOT = "/v1.0/deviceManagement/termsAndConditions"
CALLS = [
    ("list_terms_and_conditions", {}),
    ("get_terms_and_conditions", {"terms_id": TERMS_ID}),
    ("get_terms_and_conditions_assignments", {"terms_id": TERMS_ID}),
]
SECRET = "SECRET-TERMS-TEXT"
HOSTILE = {
    k: SECRET + " private@example.test https://evil.example/x"
    for k in (
        "bodyText",
        "acceptanceStatement",
        "password",
        "accessToken",
        "certificate",
        "scriptContent",
        "url",
    )
}


def prime(h):
    row = dict(
        id=TERMS_ID,
        displayName="x" * 800,
        description="d" * 800,
        title="t" * 800,
        createdDateTime="2026-01-01T00:00:00Z",
        lastModifiedDateTime="2026-01-02T00:00:00Z",
        version=7,
        **HOSTILE,
    )
    row["@odata.type"] = "#microsoft.graph.termsAndConditions"
    h.terms_rows[OID_A] = {"termsAndConditions": [dict(row, id=guid("a", i)) for i in range(1, 4)]}
    assignments = [
        dict(
            id=guid("c", i),
            target={
                "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                "groupId": guid("b", i),
                "entraObjectId": guid("e", i),
                **HOSTILE,
            },
            **HOSTILE,
        )
        for i in range(1, 4)
    ]
    h.terms_children[OID_A] = {("termsAndConditions", TERMS_ID, "assignments"): assignments}
    h.terms_children[OID_B] = dict(h.terms_children[OID_A])


@pytest.fixture
async def h():
    async with Harness(make_settings(enabled_tool_groups="enrollment")).running() as x:
        prime(x)
        yield x


async def test_tools_in_enrollment_group_only():
    from intune_mcp.groups import TOOL_GROUPS

    assert {t for t, _ in CALLS} <= set(TOOL_GROUPS["enrollment"].tools)
    async with Harness(make_settings(enabled_tool_groups="devices")).running() as d:
        token = await bearer(d, OID_A)
        for tool, args in CALLS:
            assert "Unknown tool" in error_text(await d.call_tool(token, tool, args))
        assert not d.token_requests and not d.graph_requests


@pytest.mark.parametrize(
    "tool", ["get_terms_and_conditions", "get_terms_and_conditions_assignments"]
)
@pytest.mark.parametrize(
    "bad",
    [
        "../users",
        "",
        "1",
        "x" * 5000,
        TERMS_ID + "\nforged",
        TERMS_ID + "_Default",
        TERMS_ID + "/assignments",
        "_" + TERMS_ID,
    ],
)
async def test_guid_before_exchange(h, tool, bad):
    token = await bearer(h, OID_A)
    assert error_text(await h.call_tool(token, tool, {"terms_id": bad})).startswith(
        "invalid_terms_id:"
    )
    assert not h.token_requests and not h.graph_requests


@pytest.mark.parametrize(
    "tool,key,args",
    [
        ("list_terms_and_conditions", "terms", {}),
        ("get_terms_and_conditions_assignments", "assignments", {"terms_id": TERMS_ID}),
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
    other_tool = "list_terms_and_conditions" if args else "get_terms_and_conditions_assignments"
    other_args = {} if args else {"terms_id": TERMS_ID}
    assert error_text(
        await h.call_tool(token, other_tool, dict(other_args, page_token=cursor))
    ).startswith("invalid_page_token:")
    if args:
        assert error_text(
            await h.call_tool(token, tool, {"terms_id": guid("a", 2), "page_token": cursor})
        ).startswith("invalid_page_token:")
    assert len(h.token_requests) == before


async def test_restricted_user_hidden_parent_never_reads_leaky_child(h):
    # Control: the stub would leak the child without the parent check.
    req = httpx2.Request(
        "GET",
        "https://graph.microsoft.com" + ROOT + "/" + TERMS_ID + "/assignments",
        headers={
            "authorization": "Bearer "
            + graph_token(OID_B, scp=SERVICE_CONFIG_SCOPE.rsplit("/", 1)[1])
        },
    )
    assert h._graph_handler(req).json()["value"]  # noqa: SLF001
    h.graph_requests.clear()
    token = await bearer(h, OID_B)
    assert payload(await h.call_tool(token, "list_terms_and_conditions"))["terms"] == []
    h.graph_requests.clear()
    text = error_text(
        await h.call_tool(token, "get_terms_and_conditions_assignments", {"terms_id": TERMS_ID})
    )
    assert text.startswith("not_found: No matching terms and conditions is visible")
    assert [r.url.path for r in h.graph_requests] == [ROOT + "/" + TERMS_ID]


async def test_visibility_rechecked_on_later_page(h):
    token = await bearer(h, OID_A)
    first = payload(
        await h.call_tool(
            token,
            "get_terms_and_conditions_assignments",
            {"terms_id": TERMS_ID, "page_size": 1},
        )
    )
    h.terms_rows[OID_A] = {}
    h.graph_requests.clear()
    text = error_text(
        await h.call_tool(
            token,
            "get_terms_and_conditions_assignments",
            {"terms_id": TERMS_ID, "page_token": first["next_page_token"]},
        )
    )
    assert text.startswith("not_found:")
    assert [r.url.path for r in h.graph_requests] == [ROOT + "/" + TERMS_ID]


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
    "tool", ["list_terms_and_conditions", "get_terms_and_conditions_assignments"]
)
async def test_response_bounds(h, kind, tool):
    def handler(request):
        if request.url.params.get("$select") == "id":
            return httpx2.Response(200, json={"id": TERMS_ID})
        if kind == "bytes":
            return httpx2.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))
        body = {"value": [{}] * (1001 if kind == "rows" else 1)}
        if kind == "nextlink":
            body["@odata.nextLink"] = "https://evil.example/termsAndConditions?$skiptoken=1"
        return httpx2.Response(200, json=body)

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))  # noqa: SLF001
    token = await bearer(h, OID_A)
    args = {} if tool == "list_terms_and_conditions" else {"terms_id": TERMS_ID}
    assert error_text(await h.call_tool(token, tool, args)).startswith("bad_response:")


async def test_object_response_size_is_bounded(h):
    h.graph._client = httpx2.AsyncClient(  # noqa: SLF001
        transport=httpx2.MockTransport(
            lambda r: httpx2.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))
        )
    )
    token = await bearer(h, OID_A)
    assert error_text(
        await h.call_tool(token, "get_terms_and_conditions", {"terms_id": TERMS_ID})
    ).startswith("bad_response:")


async def test_read_layer_refuses_unchecked_parent(h):
    plan = h.graph.plan(
        TERMS_ASSIGNMENTS_SPEC, path_args={"terms_id": TERMS_ID}, page_size=5, page_token=None
    )
    with pytest.raises(ValueError):
        await h.graph.fetch_page("opaque", plan, "cid")
    assert not h.graph_requests


@pytest.mark.parametrize("body", [{}, {"id": guid("b", 9)}, {"id": [TERMS_ID]}])
async def test_malformed_parent_fails_closed(h, body):
    def handler(request):
        h.graph_requests.append(request)
        return httpx2.Response(200, json=body)

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))  # noqa: SLF001
    token = await bearer(h, OID_A)
    text = error_text(
        await h.call_tool(token, "get_terms_and_conditions_assignments", {"terms_id": TERMS_ID})
    )
    assert text.startswith("bad_response:")
    assert [r.url.path for r in h.graph_requests] == [ROOT + "/" + TERMS_ID]


async def test_ignored_top_returns_all_bounded_rows(h):
    h.ignore_top = True
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, "list_terms_and_conditions", {"page_size": 1}))
    assert len(out["terms"]) == 3 and out["complete"] is True


async def test_unknown_target_types_and_bad_values_are_sanitised(h):
    h.terms_rows[OID_A]["termsAndConditions"][0].update(
        displayName=["x"], description=5, title=True, version=True
    )
    h.terms_children[OID_A][("termsAndConditions", TERMS_ID, "assignments")] = [
        {"id": "not a guid", "target": {"@odata.type": "#microsoft.graph.evil\nx", "groupId": "g"}},
        {"id": guid("c", 1), "target": "string"},
        {
            "id": guid("c", 2),
            "target": {"@odata.type": "microsoft.graph.scopeTagGroupAssignmentTarget"},
        },
    ]
    token = await bearer(h, OID_A)
    got = payload(await h.call_tool(token, "get_terms_and_conditions", {"terms_id": TERMS_ID}))
    assert (got["displayName"], got["description"], got["title"], got["version"]) == (
        None,
        None,
        None,
        None,
    )
    out = payload(
        await h.call_tool(token, "get_terms_and_conditions_assignments", {"terms_id": TERMS_ID})
    )
    assert out["assignments"] == [
        {"id": None, "target_type": "unknown", "group_id": None},
        {"id": guid("c", 1), "target_type": "unknown", "group_id": None},
        {"id": guid("c", 2), "target_type": "unknown", "group_id": None},
    ]


@pytest.mark.parametrize(("tool", "args"), CALLS)
async def test_fields_scope_audit_and_minimisation(h, caplog, tool, args):
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.INFO):
        result = await h.call_tool(token, tool, args)
    out = payload(result)
    serialized = json.dumps(result)
    for value in (SECRET, "private@example.test", "evil.example", "bodyText", guid("e", 1)):
        assert value not in serialized
    assert [s for _, s in h.token_requests] == [(SERVICE_CONFIG_SCOPE,)]
    assert {scp_of(r) for r in h.graph_requests} == {SERVICE_CONFIG_SCOPE.rsplit("/", 1)[1]}
    for line in audit_lines(caplog):
        assert SECRET not in line and "xxxx" not in line
    if tool == "get_terms_and_conditions_assignments":
        assert [r.url.path for r in h.graph_requests] == [
            ROOT + "/" + TERMS_ID,
            ROOT + "/" + TERMS_ID + "/assignments",
        ]
        assert dict(h.graph_requests[0].url.params) == {"$select": "id"}
        assert out["assignments"][0] == {
            "id": guid("c", 1),
            "target_type": "groupAssignmentTarget",
            "group_id": guid("b", 1),
        }
    else:
        row = out if args else out["terms"][0]
        assert set(row) == {
            "id",
            "displayName",
            "description",
            "title",
            "version",
            "createdDateTime",
            "lastModifiedDateTime",
        }
        assert len(row["displayName"]) == 256 and len(row["description"]) == 500
        assert len(row["title"]) == 256 and row["version"] == 7
        select = set(h.graph_requests[0].url.params["$select"].split(","))
        assert select == set(row)
        assert not {"bodyText", "acceptanceStatement"} & select


@pytest.mark.parametrize(
    "odata_type",
    [
        "#microsoft.graph.evilTarget",
        "#microsoft.graph.scopeTagGroupAssignmentTarget",
        "#microsoft.graph.allDevicesAssignmentTarget",
        "#microsoft.graph.allLicensedUsersAssignmentTarget",
        None,
    ],
)
def test_group_id_is_only_returned_for_group_bearing_targets(odata_type):
    """Review finding: an unknown/non-group target carrying a valid GUID must not echo it."""
    from intune_mcp.graph import enrollment_assignment_summary, terms_assignment_summary

    row = {"id": guid("c", 1), "target": {"@odata.type": odata_type, "groupId": guid("b", 1)}}
    for shape in (terms_assignment_summary, enrollment_assignment_summary):
        assert shape(row)["group_id"] is None
    for kind in ("groupAssignmentTarget", "exclusionGroupAssignmentTarget"):
        ok = {
            "id": guid("c", 1),
            "target": {"@odata.type": f"#microsoft.graph.{kind}", "groupId": guid("b", 1)},
        }
        assert terms_assignment_summary(ok)["group_id"] == guid("b", 1)
        assert enrollment_assignment_summary(ok)["group_id"] == guid("b", 1)
