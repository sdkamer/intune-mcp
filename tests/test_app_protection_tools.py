"""App protection: mocked Microsoft only, no live verification."""

import json
import logging

import httpx2
import pytest

from intune_mcp.config import APPS_SCOPE
from intune_mcp.graph import (
    APP_PROTECTION_ASSIGNMENTS_SPECS,
    APP_PROTECTION_POLICY_SPEC,
    APP_PROTECTION_SETTINGS,
    MAX_RESPONSE_BYTES,
    app_protection_summary,
)

from .conftest import OID_A, OID_B, graph_token, make_settings
from .harness import Harness
from .test_apps_tools import APP_ID, SECRET
from .test_device_tools import audit_lines, bearer, error_text, guid, payload
from .test_tool_groups import tools

TYPES = ("iosManagedAppProtection", "androidManagedAppProtection")
COMMON = {
    "organizationalCredentialsRequired",
    "dataBackupBlocked",
    "deviceComplianceRequired",
    "saveAsBlocked",
    "pinRequired",
    "maximumPinRetries",
    "simplePinBlocked",
    "minimumPinLength",
    "contactSyncBlocked",
    "printBlocked",
    "fingerprintBlocked",
    "disableAppPinIfDevicePinIsSet",
    "pinCharacterSet",
    "allowedInboundDataTransferSources",
    "allowedOutboundDataTransferDestinations",
    "allowedOutboundClipboardSharingLevel",
    "minimumRequiredOsVersion",
    "minimumWarningOsVersion",
    "minimumRequiredAppVersion",
    "minimumWarningAppVersion",
}
EXACT = {
    TYPES[0]: COMMON | {"faceIdBlocked"},
    TYPES[1]: COMMON
    | {"screenCaptureBlocked", "encryptAppData", "disableAppEncryptionIfDeviceEncryptionIsEnabled"},
}
HOSTILE = ["https://evil.example/path", "user@example.invalid", "com.example.browser", SECRET]
CALLS = [
    ("list_app_protection_policies", {}),
    ("get_app_protection_policy", {"policy_id": APP_ID}),
    ("get_app_protection_policy_assignments", {"policy_id": APP_ID, "policy_type": TYPES[0]}),
]
ROOT = "/v1.0/deviceAppManagement/"


def row(kind):
    rules = APP_PROTECTION_SETTINGS[kind]
    values = {k: True if r is bool else 6 if r is int else r[0] for k, r in rules.items()}
    values.update(
        {k: "17.2.1" for k in COMMON if k.startswith("minimum") and k.endswith("Version")}
    )
    return dict(
        values,
        id=APP_ID,
        displayName="n" * 800,
        description="d" * 800,
        version="12",
        createdDateTime="2026-01-01T01:00:00+01:00",
        lastModifiedDateTime="invalid",
        **{"@odata.type": "#microsoft.graph." + kind},
    )


@pytest.fixture
async def h():
    async with Harness(make_settings(enabled_tool_groups="apps")).running() as h:
        policies = [row(k) for k in TYPES]
        for p in policies:
            p["id"] = guid("a", TYPES.index(p["@odata.type"].split(".")[-1]) + 1)
        h.app_rows[OID_A] = {"managedAppPolicies": policies}
        for kind, spec in APP_PROTECTION_ASSIGNMENTS_SPECS.items():
            collection = spec.path.split("/")[2]
            h.app_rows[OID_A][collection] = [row(kind)]
            h.app_children.setdefault(OID_A, {})[(collection, APP_ID, "assignments")] = [
                {
                    "id": guid("b", i),
                    "target": {
                        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                        "groupId": guid("c", i),
                    },
                }
                for i in range(1, 4)
            ]
        h.app_children[OID_B] = dict(h.app_children[OID_A])
        yield h


@pytest.mark.parametrize("kind", TYPES)
def test_exact_allowlist(kind):
    out = app_protection_summary(row(kind))
    assert out["settings_available"] is True
    assert set(out) == {
        "id",
        "displayName",
        "description",
        "createdDateTime",
        "lastModifiedDateTime",
        "version",
        "policy_type",
        "settings_available",
        "settings",
    }
    assert set(out["settings"]) == EXACT[kind]
    assert len(out["displayName"]) == 256 and len(out["description"]) == 500
    assert out["createdDateTime"] == "2026-01-01T00:00:00Z"
    assert out["lastModifiedDateTime"] is None


@pytest.mark.parametrize("kind", TYPES)
@pytest.mark.parametrize("value", HOSTILE + [None, {}, [], 1.2, -1, 2**40])
def test_hostile_listed_and_unlisted_properties(kind, value):
    body = {k: value for k in EXACT[kind]}
    body.update(
        {
            k: value
            for k in (
                "customBrowserProtocol",
                "customBrowserPackageId",
                "customBrowserDisplayName",
                "allowedOutboundDataTransferAppExemptions",
                "allowedDataStorageLocations",
                "apps",
                "contactSyncIdentifier",
                "notificationRestriction",
                "email",
                "tenantId",
                "unknownSecret",
            )
        }
    )
    body.update({"@odata.type": "#microsoft.graph." + kind, "id": value, "version": value})
    out = app_protection_summary(body)
    assert out["settings"] == {}
    assert out["id"] is None and out["version"] is None
    for secret in HOSTILE:
        assert secret not in json.dumps(out)


@pytest.mark.parametrize(
    "kind",
    [
        "unknown",
        "windowsManagedAppProtection",
        "iosManagedAppProtectionX",
        "IOSManagedAppProtection",
        "com.example.browser",
        "https://evil.example",
        None,
    ],
)
def test_unknown_type(kind):
    body = row(TYPES[0])
    body["@odata.type"] = "#microsoft.graph." + kind if kind else None
    out = app_protection_summary(body)
    assert out["settings_available"] is False and out["settings"] == {}
    assert out["policy_type"] == "unknown"


@pytest.mark.parametrize("value", [True, 1, "", "1.2.3.4.5", "123456", "1.2\n", "01-beta", "1..2"])
def test_version_rejects_non_numeric_patterns(value):
    body = row(TYPES[0])
    body.update(minimumRequiredOsVersion=value, version=value)
    out = app_protection_summary(body)
    assert "minimumRequiredOsVersion" not in out["settings"] and out["version"] is None


@pytest.mark.parametrize("tool,args", CALLS)
async def test_scope_audit_and_full_serialized_exclusion(h, caplog, tool, args):
    # Graph ignores select; all listed settings and unknown fields carry hostile values.
    for rows in h.app_rows[OID_A].values():
        for p in rows:
            p.update({k: HOSTILE[0] for k in EXACT[TYPES[0]] | EXACT[TYPES[1]]})
            p.update(
                customBrowserProtocol=HOSTILE[1], customBrowserPackageId=HOSTILE[2], unknown=SECRET
            )
    for rows in h.app_children[OID_A].values():
        for assignment in rows:
            assignment.update(unknown=SECRET, targetGroupId=HOSTILE[1])
            assignment["target"].update(
                customBrowserPackageId=HOSTILE[2], entraObjectId=HOSTILE[1], url=HOSTILE[0]
            )
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.INFO):
        result = await h.call_tool(token, tool, args)
    out = payload(result)
    assert [s for _, s in h.token_requests] == [(APPS_SCOPE,)]
    for secret in HOSTILE:
        assert secret not in json.dumps(result)
        assert secret not in caplog.text
    [line] = audit_lines(caplog)
    assert "outcome=ok" in line and "n" * 40 not in line
    if tool.endswith("assignments"):
        assert len(h.graph_requests) == 2
        assert h.graph_requests[0].url.params["$select"] == "id"
    elif tool.startswith("get_"):
        assert out["settings_available"] and out["settings"] == {}
        assert not h.graph_requests[0].url.params


@pytest.mark.parametrize("tool,args", CALLS[1:])
@pytest.mark.parametrize("value", ["../users", "", "x" * 5000, APP_ID + "\n"])
async def test_guid_validation_before_token(h, tool, args, value):
    token = await bearer(h, OID_A)
    assert error_text(await h.call_tool(token, tool, dict(args, policy_id=value))).startswith(
        "invalid_policy_id:"
    )
    assert not h.token_requests and not h.graph_requests


@pytest.mark.parametrize(
    "value",
    ["../users", "windowsManagedAppProtection", "iosManagedAppProtections", "https://evil.example"],
)
async def test_closed_type_before_token(h, value):
    token = await bearer(h, OID_A)
    result = await h.call_tool(token, CALLS[2][0], dict(CALLS[2][1], policy_type=value))
    assert result["result"]["isError"]
    assert not h.token_requests and not h.graph_requests


@pytest.mark.parametrize("kind", TYPES)
@pytest.mark.parametrize("paren", [False, True])
async def test_parent_visibility_every_page_and_bound_token(h, kind, paren):
    h.paren_links = paren
    tool = CALLS[2][0]
    args = dict(policy_id=APP_ID, policy_type=kind)
    spec = APP_PROTECTION_ASSIGNMENTS_SPECS[kind]
    collection = spec.path.split("/")[2]
    token = await bearer(h, OID_A)
    first = payload(await h.call_tool(token, tool, dict(args, page_size=1)))
    cursor = first["next_page_token"]
    second = payload(await h.call_tool(token, tool, dict(args, page_token=cursor)))
    assert first["assignments"][0]["id"] != second["assignments"][0]["id"]
    before = len(h.token_requests)
    for wrong in [
        dict(args, policy_id=guid("a", 9)),
        dict(args, policy_type=TYPES[1 - TYPES.index(kind)]),
    ]:
        assert error_text(
            await h.call_tool(token, tool, dict(wrong, page_token=cursor))
        ).startswith("invalid_page_token:")
    assert len(h.token_requests) == before
    h.app_rows[OID_A][collection] = []
    h.graph_requests.clear()
    assert error_text(await h.call_tool(token, tool, dict(args, page_token=cursor))).startswith(
        "not_found:"
    )
    assert [r.url.path for r in h.graph_requests] == [ROOT + collection + "/" + APP_ID]


@pytest.mark.parametrize("kind", TYPES)
async def test_hidden_parent_blocks_leaky_children(h, kind):
    spec = APP_PROTECTION_ASSIGNMENTS_SPECS[kind]
    path = spec.path.format(policy_id=APP_ID)
    request = httpx2.Request(
        "GET",
        "https://graph.microsoft.com/v1.0" + path,
        headers={"authorization": "Bearer " + graph_token(OID_B, scp=APPS_SCOPE.rsplit("/", 1)[1])},
    )
    assert h._graph_handler(request).json()["value"]  # noqa: SLF001
    h.graph_requests.clear()
    token = await bearer(h, OID_B)
    assert error_text(
        await h.call_tool(token, CALLS[2][0], dict(policy_id=APP_ID, policy_type=kind))
    ).startswith("not_found:")
    assert len(h.graph_requests) == 1


@pytest.mark.parametrize("kind", TYPES)
@pytest.mark.parametrize(
    "target_type",
    [
        "managedAppPolicyDeploymentSummary",
        "scopeTagGroupAssignmentTarget",
        "unknown",
        "groupAssignmentTarget",
    ],
)
def test_deprecated_unknown_and_hostile_assignments(kind, target_type):
    body = {
        "id": SECRET,
        "targetGroupId": SECRET,
        "isExcluded": True,
        "target": {
            "@odata.type": "#microsoft.graph." + target_type,
            "groupId": HOSTILE[1],
            "entraObjectId": guid("c", 9),
            "deviceAndAppManagementAssignmentFilterId": HOSTILE[0],
            "deviceAndAppManagementAssignmentFilterType": SECRET,
        },
    }
    out = APP_PROTECTION_ASSIGNMENTS_SPECS[kind].shape(body)
    assert out["id"] is None and out["group_id"] is None
    assert out["filter_id"] is None and out["filter_type"] is None
    assert guid("c", 9) not in json.dumps(out)
    for secret in HOSTILE:
        assert secret not in json.dumps(out)


@pytest.mark.parametrize("tool,args", CALLS)
@pytest.mark.parametrize(
    "status,code", [(400, "bad_request"), (403, "forbidden"), (404, "not_found")]
)
async def test_error_mapping(h, tool, args, status, code):
    def handler(request):
        h.graph_requests.append(request)
        return httpx2.Response(status, json={"error": SECRET})

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))  # noqa: SLF001
    token = await bearer(h, OID_A)
    result = await h.call_tool(token, tool, args)
    assert error_text(result).startswith(code + ":") and SECRET not in json.dumps(result)
    assert len(h.graph_requests) == 1


@pytest.mark.parametrize("tool,args", CALLS)
@pytest.mark.parametrize("kind", ["bytes", "rows", "nextlink"])
async def test_bounds(h, tool, args, kind):
    if tool == CALLS[1][0] and kind != "bytes":
        return

    def handler(request):
        if request.url.params.get("$select") == "id":
            return httpx2.Response(200, json={"id": APP_ID})
        if kind == "bytes":
            return httpx2.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))
        body = {"value": [{}] * (1001 if kind == "rows" else 1)}
        if kind == "nextlink":
            body["@odata.nextLink"] = "https://evil.example/?$skiptoken=1"
        return httpx2.Response(200, json=body)

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))  # noqa: SLF001
    token = await bearer(h, OID_A)
    assert error_text(await h.call_tool(token, tool, args)).startswith("bad_response:")


async def test_list_to_get_and_list_paging(h):
    token = await bearer(h, OID_A)
    first = payload(await h.call_tool(token, CALLS[0][0], {"page_size": 1}))
    item = first["policies"][0]
    assert (
        payload(await h.call_tool(token, CALLS[1][0], {"policy_id": item["id"]}))["policy_type"]
        == item["policy_type"]
    )
    second = payload(
        await h.call_tool(token, CALLS[0][0], {"page_token": first["next_page_token"]})
    )
    assert second["policies"][0]["id"] != item["id"]
    assert error_text(
        await h.call_tool(
            token, CALLS[2][0], dict(CALLS[2][1], page_token=first["next_page_token"])
        )
    ).startswith("invalid_page_token:")


@pytest.mark.parametrize("kind", TYPES)
async def test_each_type_list_get_assignments_round_trip(h, kind):
    h.app_rows[OID_A]["managedAppPolicies"] = [row(kind)]
    token = await bearer(h, OID_A)
    [policy] = payload(await h.call_tool(token, CALLS[0][0]))["policies"]
    out = payload(await h.call_tool(token, CALLS[1][0], {"policy_id": policy["id"]}))
    assert out["policy_type"] == kind and set(out["settings"]) == EXACT[kind]
    assignments = payload(
        await h.call_tool(
            token, CALLS[2][0], {"policy_id": policy["id"], "policy_type": policy["policy_type"]}
        )
    )["assignments"]
    assert assignments[0] == {
        "id": guid("b", 1),
        "target_type": "groupAssignmentTarget",
        "group_id": guid("c", 1),
        "filter_type": None,
        "filter_id": None,
    }


async def test_disabled_group():
    async with Harness(make_settings(enabled_tool_groups="devices")).running() as h:
        token = await bearer(h, OID_A)
        assert not {x[0] for x in CALLS}.intersection(await tools(h, token))
        assert not h.token_requests and not h.graph_requests


async def test_unchecked_parent_guard(h):
    spec = APP_PROTECTION_ASSIGNMENTS_SPECS[TYPES[0]]
    plan = h.graph.plan(spec, path_args={"policy_id": APP_ID}, page_size=1, page_token=None)
    with pytest.raises(ValueError):
        await h.graph.fetch_page("opaque", plan, "cid")
    assert APP_PROTECTION_POLICY_SPEC.scope == APPS_SCOPE


def test_closed_types_and_no_value_coercion():
    assert set(APP_PROTECTION_SETTINGS) == set(TYPES)
    for kind in TYPES:
        for name in EXACT[kind]:
            if name in {"maximumPinRetries", "minimumPinLength"}:
                wrong = [True, False, "6", 1.5, -1, 2**31]
            elif name.endswith("Version"):
                wrong = [True, 17, "17.beta", "17.2\n"]
            elif name in {
                "pinCharacterSet",
                "allowedInboundDataTransferSources",
                "allowedOutboundDataTransferDestinations",
                "allowedOutboundClipboardSharingLevel",
            }:
                wrong = [True, 1, "unreviewed", "numeric\n"]
            else:
                wrong = [0, 1, "true", "false"]
            for value in wrong:
                out = app_protection_summary(
                    {"@odata.type": "#microsoft.graph." + kind, name: value}
                )
                assert out["settings"] == {}, (kind, name, value)
        assert app_protection_summary(
            {"@odata.type": "#microsoft.graph." + kind, "pinRequired": False, "minimumPinLength": 0}
        )["settings"] == {"pinRequired": False, "minimumPinLength": 0}


@pytest.mark.parametrize("kind", TYPES)
@pytest.mark.parametrize(
    "status,code", [(400, "bad_request"), (403, "forbidden"), (404, "not_found")]
)
async def test_child_error_mapping_after_visible_parent(h, kind, status, code):
    def handler(request):
        h.graph_requests.append(request)
        if request.url.params.get("$select") == "id":
            return httpx2.Response(200, json={"id": APP_ID})
        return httpx2.Response(status, json={"error": SECRET})

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))  # noqa: SLF001
    token = await bearer(h, OID_A)
    response = await h.call_tool(token, CALLS[2][0], dict(policy_id=APP_ID, policy_type=kind))
    assert error_text(response).startswith(code + ":") and SECRET not in json.dumps(response)
    assert len(h.graph_requests) == 2


@pytest.mark.parametrize("kind", TYPES)
@pytest.mark.parametrize("body", [{}, {"id": guid("a", 9)}, {"id": [APP_ID]}])
async def test_malformed_parent_no_child(h, kind, body):
    def handler(request):
        h.graph_requests.append(request)
        return httpx2.Response(200, json=body)

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))  # noqa: SLF001
    token = await bearer(h, OID_A)
    assert error_text(
        await h.call_tool(token, CALLS[2][0], dict(policy_id=APP_ID, policy_type=kind))
    ).startswith("bad_response:")
    assert len(h.graph_requests) == 1


@pytest.mark.parametrize(
    "tool,key,args", [(CALLS[0][0], "policies", {}), (CALLS[2][0], "assignments", CALLS[2][1])]
)
async def test_ignored_top_and_upper_row_bound(h, tool, key, args):
    h.ignore_top = True
    token = await bearer(h, OID_A)
    if key == "policies":
        rows = h.app_rows[OID_A]["managedAppPolicies"]
    else:
        rows = h.app_children[OID_A][("iosManagedAppProtections", APP_ID, "assignments")]
    original = {"id": APP_ID}
    rows[:] = [original] * 1000
    out = payload(await h.call_tool(token, tool, dict(args, page_size=1)))
    assert len(out[key]) == 1000 and out["complete"] is True
    rows.append(original)
    assert error_text(await h.call_tool(token, tool, dict(args, page_size=1))).startswith(
        "bad_response:"
    )


@pytest.mark.parametrize("tool,args", CALLS)
async def test_opaque_token_and_refused_exchange(h, tool, args):
    from types import SimpleNamespace

    class Credential:
        refused = False

        async def get_token(self, *scopes):
            assert scopes == (APPS_SCOPE,)
            if self.refused:
                raise RuntimeError("AADSTS65001: " + SECRET)
            return SimpleNamespace(token="opaque-not-a-jwt", expires_on=9_999_999_999)

    credential = Credential()

    async def get_credential(assertion):
        return credential

    def handler(request):
        h.graph_requests.append(request)
        assert request.headers["authorization"] == "Bearer opaque-not-a-jwt"
        return httpx2.Response(
            200, json={"id": APP_ID} if request.url.params.get("$select") == "id" else {"value": []}
        )

    h.token_source.get_credential = get_credential
    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))  # noqa: SLF001
    token = await bearer(h, OID_A)
    payload(await h.call_tool(token, tool, args))
    h.graph_requests.clear()
    credential.refused = True
    result = await h.call_tool(token, tool, args)
    assert error_text(result).startswith("graph_consent_required:")
    assert SECRET not in json.dumps(result) and not h.graph_requests
