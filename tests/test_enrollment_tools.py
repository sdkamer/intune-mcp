"""G4: real HTTP/OAuth/MCP, mocked Microsoft only. No live evidence."""

import json
import logging

import httpx2
import pytest

from intune_mcp.config import GRAPH_SCOPE, SERVICE_CONFIG_SCOPE
from intune_mcp.graph import (
    ENROLLMENT_ASSIGNMENTS_SPEC,
    MAX_RESPONSE_BYTES,
)
from intune_mcp.groups import TOOL_GROUPS

from .conftest import OID_A, OID_B, graph_token, make_settings
from .harness import Harness
from .test_device_tools import audit_lines, bearer, error_text, guid, payload
from .test_tool_groups import DEFAULT_TOOLS, authorize_scopes, scp_of, tools

CONFIGURATION_ID = guid("a", 1)
ROOT = "/v1.0/deviceManagement/deviceEnrollmentConfigurations"
CALLS = [
    ("list_enrollment_configurations", {}),
    ("get_enrollment_configuration", {"configuration_id": CONFIGURATION_ID}),
    ("get_enrollment_configuration_assignments", {"configuration_id": CONFIGURATION_ID}),
    ("get_apple_push_certificate_status", {}),
]
SECRET = "SECRET-PER-TYPE"
SENSITIVE = {
    k: SECRET
    for k in (
        "password",
        "accessToken",
        "hardwareHash",
        "serialNumber",
        "scriptContent",
        "certificate",
        "certificateUploadFailureReason",
        "enrollmentUrl",
        "tokenName",
        "settings",
    )
}


def prime(h):
    row = dict(
        id=CONFIGURATION_ID,
        displayName="x" * 800,
        description="d" * 800,
        createdDateTime="2026-01-01T00:00:00Z",
        lastModifiedDateTime="2026-01-02T00:00:00Z",
        priority=1,
        version=2,
        limit=5,
        **SENSITIVE,
    )
    row["@odata.type"] = "#microsoft.graph.deviceEnrollmentLimitConfiguration"
    h.enrollment_rows[OID_A] = {
        "deviceEnrollmentConfigurations": [dict(row, id=guid("a", i)) for i in range(1, 4)]
    }
    assignments = [
        dict(
            id=guid("c", i),
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
    h.enrollment_children[OID_A] = {
        ("deviceEnrollmentConfigurations", CONFIGURATION_ID, "assignments"): assignments
    }
    h.enrollment_children[OID_B] = dict(h.enrollment_children[OID_A])


@pytest.fixture
async def h():
    async with Harness(make_settings(enabled_tool_groups="enrollment")).running() as x:
        prime(x)
        yield x


@pytest.mark.parametrize(
    "enabled", ["devices", "enrollment", "devices,configuration,apps,rbac,enrollment"]
)
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


@pytest.mark.parametrize(
    "tool", ["get_enrollment_configuration", "get_enrollment_configuration_assignments"]
)
@pytest.mark.parametrize(
    "bad",
    [
        "../users",
        "",
        "1",
        "x" * 5000,
        CONFIGURATION_ID + "\nforged",
        CONFIGURATION_ID + "_",
        CONFIGURATION_ID + "__x",
        CONFIGURATION_ID + "_a_b",
        CONFIGURATION_ID + "_a/b",
        CONFIGURATION_ID + "_a.b",
        CONFIGURATION_ID + "_%2e",
        CONFIGURATION_ID + "_" + "a" * 65,
        "_" + CONFIGURATION_ID,
        CONFIGURATION_ID[:-1] + "g_Default",
    ],
)
async def test_guid_before_exchange(h, tool, bad):
    token = await bearer(h, OID_A)
    assert error_text(await h.call_tool(token, tool, {"configuration_id": bad})).startswith(
        "invalid_configuration_id:"
    )
    assert not h.token_requests and not h.graph_requests


@pytest.mark.parametrize(
    "tool,key,args",
    [
        ("list_enrollment_configurations", "configurations", {}),
        (
            "get_enrollment_configuration_assignments",
            "assignments",
            {"configuration_id": CONFIGURATION_ID},
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
    other_tool = (
        "list_enrollment_configurations" if args else "get_enrollment_configuration_assignments"
    )
    other_args = {} if args else {"configuration_id": CONFIGURATION_ID}
    assert error_text(
        await h.call_tool(token, other_tool, dict(other_args, page_token=cursor))
    ).startswith("invalid_page_token:")
    if args:
        assert error_text(
            await h.call_tool(token, tool, {"configuration_id": guid("a", 2), "page_token": cursor})
        ).startswith("invalid_page_token:")
    assert len(h.token_requests) == before


async def test_restricted_user_hidden_parent_never_reads_leaky_child(h):
    # Control: stub would leak the child without the parent check.
    req = httpx2.Request(
        "GET",
        "https://graph.microsoft.com" + ROOT + "/" + CONFIGURATION_ID + "/assignments",
        headers={
            "authorization": "Bearer "
            + graph_token(OID_B, scp=SERVICE_CONFIG_SCOPE.rsplit("/", 1)[1])
        },
    )
    assert h._graph_handler(req).json()["value"]  # noqa: SLF001
    h.graph_requests.clear()
    token = await bearer(h, OID_B)
    assert (
        payload(await h.call_tool(token, "list_enrollment_configurations"))["configurations"] == []
    )
    h.graph_requests.clear()
    text = error_text(
        await h.call_tool(
            token,
            "get_enrollment_configuration_assignments",
            {"configuration_id": CONFIGURATION_ID},
        )
    )
    assert text.startswith("not_found: No matching enrollment configuration is visible")
    assert [r.url.path for r in h.graph_requests] == [ROOT + "/" + CONFIGURATION_ID]


async def test_visibility_rechecked_on_later_page(h):
    token = await bearer(h, OID_A)
    first = payload(
        await h.call_tool(
            token,
            "get_enrollment_configuration_assignments",
            {"configuration_id": CONFIGURATION_ID, "page_size": 1},
        )
    )
    h.enrollment_rows[OID_A] = {}
    h.graph_requests.clear()
    text = error_text(
        await h.call_tool(
            token,
            "get_enrollment_configuration_assignments",
            {"configuration_id": CONFIGURATION_ID, "page_token": first["next_page_token"]},
        )
    )
    assert text.startswith("not_found:")
    assert [r.url.path for r in h.graph_requests] == [ROOT + "/" + CONFIGURATION_ID]


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
    "tool", ["list_enrollment_configurations", "get_enrollment_configuration_assignments"]
)
async def test_response_bounds(h, kind, tool):
    def handler(request):
        if request.url.params.get("$select") == "id":
            return httpx2.Response(200, json={"id": CONFIGURATION_ID})
        if kind == "bytes":
            return httpx2.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))
        body = {"value": [{}] * (1001 if kind == "rows" else 1)}
        if kind == "nextlink":
            body["@odata.nextLink"] = (
                "https://evil.example/deviceEnrollmentConfigurations?$skiptoken=1"
            )
        return httpx2.Response(200, json=body)

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))  # noqa: SLF001
    token = await bearer(h, OID_A)
    args = (
        {} if tool == "list_enrollment_configurations" else {"configuration_id": CONFIGURATION_ID}
    )
    assert error_text(await h.call_tool(token, tool, args)).startswith("bad_response:")


async def test_read_layer_refuses_unchecked_parent(h):
    plan = h.graph.plan(
        ENROLLMENT_ASSIGNMENTS_SPEC,
        path_args={"configuration_id": CONFIGURATION_ID},
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


@pytest.mark.parametrize("body", [{}, {"id": guid("b", 9)}, {"id": [CONFIGURATION_ID]}])
async def test_malformed_parent_fails_closed(h, body):
    def handler(request):
        h.graph_requests.append(request)
        return httpx2.Response(200, json=body)

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))  # noqa: SLF001
    token = await bearer(h, OID_A)
    text = error_text(
        await h.call_tool(
            token,
            "get_enrollment_configuration_assignments",
            {"configuration_id": CONFIGURATION_ID},
        )
    )
    assert text.startswith("bad_response:")
    assert [r.url.path for r in h.graph_requests] == [ROOT + "/" + CONFIGURATION_ID]


async def test_refused_apps_obo_leaves_graph_untouched(h):
    class Refused:
        async def get_token(self, *scopes):
            assert scopes == (SERVICE_CONFIG_SCOPE,)
            raise RuntimeError("AADSTS65001: " + SECRET)

    async def credential(assertion):
        return Refused()

    h.token_source.get_credential = credential
    token = await bearer(h, OID_A)
    text = error_text(await h.call_tool(token, "list_enrollment_configurations"))
    assert text.startswith("graph_consent_required:") and SECRET not in text
    assert not h.graph_requests


@pytest.mark.parametrize("tool,args", [CALLS[1], CALLS[3]])
async def test_object_response_size_is_bounded(h, tool, args):
    h.graph._client = httpx2.AsyncClient(  # noqa: SLF001
        transport=httpx2.MockTransport(
            lambda r: httpx2.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))
        )
    )
    token = await bearer(h, OID_A)
    assert error_text(await h.call_tool(token, tool, args)).startswith("bad_response:")


@pytest.mark.parametrize(
    "tool,key,args",
    [
        ("list_enrollment_configurations", "configurations", {}),
        (
            "get_enrollment_configuration_assignments",
            "assignments",
            {"configuration_id": CONFIGURATION_ID},
        ),
    ],
)
async def test_ignored_top_returns_all_bounded_rows(h, tool, key, args):
    h.ignore_top = True
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, tool, dict(args, page_size=1)))
    assert len(out[key]) == 3 and out["count"] == 3 and out["complete"] is True


@pytest.mark.parametrize(("tool", "args"), CALLS)
async def test_fields_scope_audit_and_minimisation(h, caplog, tool, args):
    h.apple_certificate[OID_A] = dict(
        expirationDateTime="2099-01-01T00:00:00Z",
        lastModifiedDateTime="2026-01-01T00:00:00Z",
        certificateUploadStatus=SECRET,
        appleIdentifier="private@example.test",
        certificateSerialNumber="SERIAL-PRIVATE",
        topicIdentifier=SECRET,
        **SENSITIVE,
    )
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.INFO):
        result = await h.call_tool(token, tool, args)
    out = payload(result)
    serialized = json.dumps(result)
    for value in (SECRET, "private@example.test", "SERIAL-PRIVATE"):
        assert value not in serialized
    assert [s for _, s in h.token_requests] == [(SERVICE_CONFIG_SCOPE,)]
    assert {scp_of(r) for r in h.graph_requests} == {SERVICE_CONFIG_SCOPE.rsplit("/", 1)[1]}
    if tool == "get_apple_push_certificate_status":
        assert set(out) == {
            "expirationDateTime",
            "lastModifiedDateTime",
            "certificateUploadStatus",
            "days_until_expiry",
        }
        assert out["certificateUploadStatus"] is None
        assert out["days_until_expiry"] > 0
        assert set(h.graph_requests[0].url.params["$select"].split(",")) == {
            "expirationDateTime",
            "lastModifiedDateTime",
        }
    elif tool == "get_enrollment_configuration_assignments":
        assert [r.url.path for r in h.graph_requests] == [
            ROOT + "/" + CONFIGURATION_ID,
            ROOT + "/" + CONFIGURATION_ID + "/assignments",
        ]
        assert dict(h.graph_requests[0].url.params) == {"$select": "id"}
        assert out["assignments"][0] == {
            "id": guid("c", 1),
            "target_type": "groupAssignmentTarget",
            "group_id": guid("b", 1),
        }
    else:
        row = out if args else out["configurations"][0]
        assert set(row) == {
            "id",
            "displayName",
            "description",
            "priority",
            "version",
            "createdDateTime",
            "lastModifiedDateTime",
            "configuration_type",
            *({"settings_available", "settings"} if args else set()),
        }
        assert len(row["displayName"]) == 256 and len(row["description"]) == 500
        assert row["priority"] == 1 and row["version"] == 2
        assert row["configuration_type"] == "deviceEnrollmentLimitConfiguration"
        if args:
            assert row["settings_available"] and row["settings"] == {"limit": 5}
            assert not h.graph_requests[0].url.params
    [line] = audit_lines(caplog)
    assert "outcome=ok" in line
    assert SECRET not in line and "x" * 50 not in line


@pytest.mark.parametrize(
    "derived,values,expected",
    [
        ("deviceEnrollmentLimitConfiguration", {"limit": 5}, {"limit": 5}),
        (
            "windows10EnrollmentCompletionPageConfiguration",
            {"allowNonBlockingAppInstallation": True},
            {"allowNonBlockingAppInstallation": True},
        ),
        (
            "deviceEnrollmentPlatformRestrictionsConfiguration",
            {
                "iosRestriction": {
                    "platformBlocked": True,
                    "personalDeviceEnrollmentBlocked": False,
                    "osMinimumVersion": SECRET,
                    "certificate": SECRET,
                }
            },
            {"iosRestriction": {"platformBlocked": True, "personalDeviceEnrollmentBlocked": False}},
        ),
        ("deviceEnrollmentWindowsHelloForBusinessConfiguration", {"limit": 5}, {}),
        ("deviceEnrollmentConfiguration", {"limit": 5}, {}),
    ],
)
async def test_exact_derived_allowlists(h, derived, values, expected):
    row = h.enrollment_rows[OID_A]["deviceEnrollmentConfigurations"][0]
    row.update(values)
    row["@odata.type"] = "#microsoft.graph." + derived
    token = await bearer(h, OID_A)
    result = await h.call_tool(
        token, "get_enrollment_configuration", {"configuration_id": CONFIGURATION_ID}
    )
    out = payload(result)
    assert out["settings"] == expected
    assert out["settings_available"] == (
        derived
        in {
            "deviceEnrollmentLimitConfiguration",
            "windows10EnrollmentCompletionPageConfiguration",
            "deviceEnrollmentPlatformRestrictionsConfiguration",
        }
    )
    assert SECRET not in json.dumps(result)


@pytest.mark.parametrize(
    "bad",
    [
        SECRET,
        "private@example.test",
        "SERIAL-PRIVATE",
        "https://secret.example/",
        {},
        [],
        None,
        True,
        -1,
        2**32,
    ],
)
async def test_hostile_listed_and_unlisted_values(h, bad):
    row = h.enrollment_rows[OID_A]["deviceEnrollmentConfigurations"][0]
    row.update(limit=bad, version=bad, priority=bad, createdDateTime=bad, secret=bad)
    token = await bearer(h, OID_A)
    for tool, args in CALLS[:2]:
        result = await h.call_tool(token, tool, args)
        out = payload(result)
        item = out if args else out["configurations"][0]
        assert item["version"] is None and item["priority"] is None
        assert item["createdDateTime"] is None
        if args:
            assert item["settings"] == {}
        if isinstance(bad, str):
            assert bad not in json.dumps(result)


@pytest.mark.parametrize(
    "bad",
    [SECRET, "private@example.test", "SERIAL-PRIVATE", "https://secret.example/", {}, [], None, 1],
)
def test_boolean_platform_and_assignment_values_never_echo(bad):
    from intune_mcp.graph import enrollment_summary

    out = enrollment_summary(
        {
            "@odata.type": "#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration",
            "iosRestriction": {"platformBlocked": bad, "personalDeviceEnrollmentBlocked": bad},
        },
        detail=True,
    )
    assert out["settings"] == {"iosRestriction": {}}
    assignment = ENROLLMENT_ASSIGNMENTS_SPEC.shape(
        {
            "id": bad,
            "target": {
                "groupId": bad,
                "deviceAndAppManagementAssignmentFilterId": bad,
                "deviceAndAppManagementAssignmentFilterType": bad,
                "@odata.type": bad,
            },
        }
    )
    assert assignment == {
        "id": None,
        "target_type": "unknown",
        "group_id": None,
    }


@pytest.mark.parametrize(
    "expiry,expected",
    [
        ("2000-01-01T00:00:00Z", "negative"),
        (SECRET, None),
        (None, None),
    ],
)
def test_certificate_expiry_and_only_safe_fields(expiry, expected):
    from intune_mcp.graph import apple_certificate_summary

    out = apple_certificate_summary(
        {
            "expirationDateTime": expiry,
            "lastModifiedDateTime": SECRET,
            "certificateUploadStatus": SECRET,
            **SENSITIVE,
        }
    )
    assert out["lastModifiedDateTime"] is None and out["certificateUploadStatus"] is None
    assert SECRET not in json.dumps(out)
    if expected == "negative":
        assert out["days_until_expiry"] < 0
    else:
        assert out["days_until_expiry"] is None


@pytest.mark.parametrize(
    "status,code", [(400, "bad_request"), (403, "forbidden"), (404, "not_found")]
)
async def test_child_error_after_visible_parent(h, status, code):
    def handler(request):
        h.graph_requests.append(request)
        if request.url.params.get("$select") == "id":
            return httpx2.Response(200, json={"id": CONFIGURATION_ID})
        return httpx2.Response(status, json={"error": SECRET})

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))  # noqa: SLF001
    token = await bearer(h, OID_A)
    text = error_text(await h.call_tool(token, CALLS[2][0], CALLS[2][1]))
    assert text.startswith(code + ":") and SECRET not in text
    assert len(h.graph_requests) == 2


async def test_hidden_configuration_get_is_not_found(h):
    token = await bearer(h, OID_B)
    assert error_text(await h.call_tool(token, CALLS[1][0], CALLS[1][1])).startswith("not_found:")
    assert len(h.graph_requests) == 1


COMPOSITE_ID = CONFIGURATION_ID + "_DefaultLimit"


async def test_composite_ids_round_trip_from_list_to_get_and_assignments(h):
    """Live finding: Intune's default configurations have GUID_<suffix> ids (was: id null)."""
    h.enrollment_rows[OID_A]["deviceEnrollmentConfigurations"].append(
        {
            "id": COMPOSITE_ID,
            "displayName": "Default",
            "@odata.type": "#microsoft.graph.deviceEnrollmentLimitConfiguration",
            "limit": 5,
            "priority": 0,
            "version": 1,
        }
    )
    h.enrollment_children[OID_A][
        ("deviceEnrollmentConfigurations", COMPOSITE_ID, "assignments")
    ] = [
        {
            "id": f"{COMPOSITE_ID}_{guid('b', i)}",
            "target": {"@odata.type": "#microsoft.graph.allLicensedUsersAssignmentTarget"},
        }
        for i in (1, 2)
    ]
    token = await bearer(h, OID_A)
    listed = payload(await h.call_tool(token, "list_enrollment_configurations", {"page_size": 100}))
    ids = [row["id"] for row in listed["configurations"]]
    assert COMPOSITE_ID in ids and None not in ids
    got = payload(
        await h.call_tool(token, "get_enrollment_configuration", {"configuration_id": COMPOSITE_ID})
    )
    assert got["id"] == COMPOSITE_ID and got["settings_available"] is True
    args = {"configuration_id": COMPOSITE_ID}
    first = payload(
        await h.call_tool(
            token, "get_enrollment_configuration_assignments", dict(args, page_size=1)
        )
    )
    assert first["assignments"][0]["id"] and first["complete"] is False
    second = payload(
        await h.call_tool(
            token,
            "get_enrollment_configuration_assignments",
            dict(args, page_token=first["next_page_token"]),
        )
    )
    assert second["assignments"][0]["id"] != first["assignments"][0]["id"]
    assert h.graph_requests[-1].url.path.endswith(f"/{COMPOSITE_ID}/assignments")
