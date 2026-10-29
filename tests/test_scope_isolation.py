"""Scope-tag isolation of the child endpoints and of count_devices (all mocked).

Live (2026-10-26, operator-reported; see VERIFICATION) a scope-tag-restricted user got tenant-wide
data from: count_devices (`@odata.count`), the assignments of a policy they cannot see, and the
status overviews of a policy and a profile they cannot see. Graph applies scope tags to a managed
device, compliance policy or configuration profile and to collections of them, but NOT to
`$count` or to the child endpoints of an object.

The harness reproduces that: with `leaky_children` (default) a child endpoint answers with data
for any caller, even one for whom the parent object is 404, and `odata_count_total` is a
tenant-wide total that differs from the caller's rows. These tests prove OUR behaviour against that
simulation (parent check first, scoped counting); they are not evidence of Microsoft's behaviour.
"""

import dataclasses
import logging
from typing import NamedTuple

import httpx2
import pytest

from intune_mcp import graph as graph_module
from intune_mcp.config import CONFIGURATION_SCOPE, GRAPH_SCOPE
from intune_mcp.graph import (
    COMPLIANCE_POLICY_ASSIGNMENTS_SPEC,
    COMPLIANCE_POLICY_STATUS_SPEC,
    COMPLIANCE_STATES_SPEC,
    CONFIGURATION_PROFILE_ASSIGNMENTS_SPEC,
    CONFIGURATION_PROFILE_STATUS_SPEC,
    CONFIGURATION_STATES_SPEC,
    DEVICE_SPEC,
    GraphClient,
    GraphError,
    ObjectSpec,
    plan_object,
)
from intune_mcp.groups import TOOL_GROUPS, ToolGroup

from .conftest import OID_A, OID_B, graph_token, make_settings
from .harness import Harness
from .test_configuration_tools import (
    COMPLIANCE,
    PROFILE,
    SANITISED_ASSIGNMENTS,
    STATUS,
    prime_config,
)
from .test_device_tools import (
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

V1 = "/v1.0/deviceManagement/"
TENANT_WIDE_COUNT = 2451


@pytest.fixture
async def h():
    async with Harness(make_settings(enabled_tool_groups="devices,configuration")).running() as x:
        x.graph._clock = lambda: NOW  # noqa: SLF001
        yield x


class Case(NamedTuple):
    tool: str
    arg: str
    parent_coll: str  # path of the parent collection under /deviceManagement
    child: str  # the child endpoint's last path segment
    noun: str
    parent_scope: str  # scope of the parent GET
    ident: str  # the object's ID (it exists for user A only)
    key: str  # output key of the paged tools, or None for an object result


DEVICE_ID = device(1)["id"]
POLICY_ID = guid(COMPLIANCE.owners[0], 1)
PROFILE_ID = guid(PROFILE.owners[0], 1)
CASES = [
    Case(
        "get_device_compliance_states",
        "device_id",
        "managedDevices",
        "deviceCompliancePolicyStates",
        "managed device",
        GRAPH_SCOPE,
        DEVICE_ID,
        "compliance_states",
    ),
    Case(
        "get_device_configuration_states",
        "device_id",
        "managedDevices",
        "deviceConfigurationStates",
        "managed device",
        GRAPH_SCOPE,
        DEVICE_ID,
        "configuration_states",
    ),
    Case(
        COMPLIANCE.status_tool,
        "policy_id",
        "deviceCompliancePolicies",
        "deviceStatusOverview",
        "compliance policy",
        CONFIGURATION_SCOPE,
        POLICY_ID,
        None,
    ),
    Case(
        COMPLIANCE.assign_tool,
        "policy_id",
        "deviceCompliancePolicies",
        "assignments",
        "compliance policy",
        CONFIGURATION_SCOPE,
        POLICY_ID,
        "assignments",
    ),
    Case(
        PROFILE.status_tool,
        "profile_id",
        "deviceConfigurations",
        "deviceStatusOverview",
        "configuration profile",
        CONFIGURATION_SCOPE,
        PROFILE_ID,
        None,
    ),
    Case(
        PROFILE.assign_tool,
        "profile_id",
        "deviceConfigurations",
        "assignments",
        "configuration profile",
        CONFIGURATION_SCOPE,
        PROFILE_ID,
        "assignments",
    ),
]
PAGED_CASES = [c for c in CASES if c.key is not None]
every_case = pytest.mark.parametrize("case", CASES, ids=lambda c: c.tool)
paged_case = pytest.mark.parametrize("case", PAGED_CASES, ids=lambda c: c.tool)


def args_of(case, **extra):
    return {case.arg: case.ident, **extra}


def parent_path(case):
    return f"{V1}{case.parent_coll}/{case.ident}"


def child_path(case):
    return f"{parent_path(case)}/{case.child}"


def requests_to(h, path):
    return [r for r in h.graph_requests if r.url.path == path]


def scope_name(scope):
    return scope.rsplit("/", 1)[1]


def scp_of(request):
    import jwt

    token = request.headers["authorization"].split()[1]
    return jwt.decode(token, options={"verify_signature": False})["scp"]


def world(h):
    """User A sees everything below. User B is scope-tag restricted: one own device, no policies,
    no profiles, but (like live Graph) the child endpoints still answer for A's objects."""
    d = prime(h)  # A's device with one compliance state and one configuration state
    for state in ("deviceCompliancePolicyStates", "deviceConfigurationStates"):
        h.children[OID_A][(d["id"], state)] = [state_row(i) for i in range(1, 4)]
    assert d["id"] == DEVICE_ID
    prime_config(h)  # A: three policies and three profiles with status and assignments
    h.devices[OID_B] = [device(1, "b")]
    h.overview[OID_B] = {"enrolledDeviceCount": 1}
    h.children[OID_B] = dict(h.children[OID_A])  # data exists for A's device
    h.config_children[OID_B] = dict(h.config_children[OID_A])  # ... and A's policies/profiles
    assert not h.config_rows.get(OID_B)
    h.odata_count_total = TENANT_WIDE_COUNT


def hide_parent(h, case, oid):
    """Make the case's parent object invisible to `oid`, leaving the child data in place."""
    if case.parent_coll == "managedDevices":
        h.devices[oid] = [device(1, "b")]
    else:
        h.config_rows.setdefault(oid, {})[case.parent_coll] = []


@pytest.mark.parametrize("kind", [COMPLIANCE, PROFILE], ids=["policy", "profile"])
async def test_settings_reads_use_the_object_get_itself_as_the_visibility_gate(h, kind):
    """No child endpoint or second parent request/exchange: same scoped GET as metadata."""
    world(h)
    ident = POLICY_ID if kind == COMPLIANCE else PROFILE_ID
    tool = kind.get_tool + "_settings"
    allowed, restricted = await bearer(h, OID_A), await bearer(h, OID_B)
    out = payload(await h.call_tool(allowed, tool, {kind.id_arg: ident}))
    assert out["id"] == ident and out["settings_available"] is True
    assert error_text(await h.call_tool(restricted, tool, {kind.id_arg: ident})).startswith(
        f"not_found: No matching {kind.noun} is visible"
    )
    # Two calls, each only one Configuration exchange and one scoped object GET.
    assert [s for _, s in h.token_requests] == [(CONFIGURATION_SCOPE,)] * 2
    assert len(h.graph_requests) == 2
    assert all(r.url.path == f"{V1}{kind.coll}/{ident}" for r in h.graph_requests)
    assert [scp_of(r) for r in h.graph_requests] == [scope_name(CONFIGURATION_SCOPE)] * 2
    # Loss of visibility on a later call fails closed (no cached settings/body).
    h.config_rows[OID_A][kind.coll] = []
    assert error_text(await h.call_tool(allowed, tool, {kind.id_arg: ident})).startswith(
        "not_found:"
    )


# -- the simulation is faithful to the live finding (control) ------------------------------------
@every_case
async def test_control_the_harness_child_endpoint_answers_for_a_user_who_cannot_see_the_parent(
    h, case
):
    """Without our check the restricted user WOULD get the data: this is the live defect."""
    world(h)
    scope = scope_name(case.parent_scope)
    bearer_b = {"authorization": f"Bearer {graph_token(OID_B, scp=scope)}"}
    child_scope = {
        "authorization": f"Bearer {graph_token(OID_B, scp=scope_name(CONFIGURATION_SCOPE))}"
    }
    transport = h.graph._client._transport  # noqa: SLF001
    async with httpx2.AsyncClient(transport=transport) as raw:
        assert (
            await raw.get("https://graph.microsoft.com" + parent_path(case), headers=bearer_b)
        ).status_code == 404
        leaked = await raw.get(
            "https://graph.microsoft.com" + child_path(case), headers=child_scope
        )
    body = leaked.json()
    # The child answers anyway, with real content (not merely a truthy empty wrapper).
    assert leaked.status_code == 200
    assert (
        body.get("value")
        if "value" in body
        else {k: v for k, v in body.items() if not k.startswith("@")}
    )


async def test_control_the_harness_odata_count_is_tenant_wide_while_rows_are_scoped(h):
    world(h)
    params = {"$count": "true", "$top": "1", "$select": "id"}
    bearer_b = {"authorization": f"Bearer {graph_token(OID_B)}"}
    transport = h.graph._client._transport  # noqa: SLF001
    async with httpx2.AsyncClient(transport=transport) as raw:
        body = (
            await raw.get(
                "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices",
                params=params,
                headers=bearer_b,
            )
        ).json()
    assert body["@odata.count"] == TENANT_WIDE_COUNT and len(h.devices[OID_B]) == 1


# -- the restricted user: not_found, and the child is never requested ------------------------------
@every_case
async def test_restricted_user_gets_not_found_and_the_child_endpoint_is_never_requested(h, case):
    world(h)
    token = await bearer(h, OID_B)
    text = error_text(await h.call_tool(token, case.tool, args_of(case)))
    assert text.startswith(f"not_found: No matching {case.noun} is visible to this user.")
    # Exactly one Graph request: the parent GET, id only. The child path is never touched.
    [only] = h.graph_requests
    assert only.method == "GET" and only.url.path == parent_path(case)
    assert dict(only.url.params) == {"$select": "id"}
    assert requests_to(h, child_path(case)) == []
    assert not any(r.url.path.endswith("/" + case.child) for r in h.graph_requests)
    for leaked in ("SECRET", "successCount", "target_type", "group_id", GROUP_A_TEXT):
        assert leaked not in text


GROUP_A_TEXT = guid("g", 1)


@every_case
async def test_not_found_text_equals_the_parent_get_tools_text(h, case):
    world(h)
    token = await bearer(h, OID_B)
    get_tool = {
        "managedDevices": "get_device",
        "deviceCompliancePolicies": "get_compliance_policy",
        "deviceConfigurations": "get_configuration_profile",
    }[case.parent_coll]
    child = error_text(await h.call_tool(token, case.tool, args_of(case)))
    parent = error_text(await h.call_tool(token, get_tool, args_of(case)))
    strip = lambda t: t.rsplit(" (ref ", 1)[0]  # noqa: E731
    assert strip(child) == strip(parent)


@every_case
async def test_restricted_user_has_one_audit_line_with_the_safe_code_and_no_data(h, caplog, case):
    world(h)
    token = await bearer(h, OID_B)
    with caplog.at_level(logging.INFO):
        error_text(await h.call_tool(token, case.tool, args_of(case)))
    [line] = audit_lines(caplog)
    assert f"tool={case.tool}" in line and "outcome=not_found" in line
    assert f"target={case.ident}" in line and f"caller_oid={OID_B}" in line
    assert "parent" not in line and "child" not in line and "precheck" not in line
    assert GROUP_A_TEXT not in line and LEAK not in line


# -- the allowed user still gets data; the order and tokens of the two requests -------------------
@every_case
async def test_allowed_user_gets_data_after_exactly_one_parent_check_then_the_child(h, case):
    world(h)
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, case.tool, args_of(case)))
    if case.key is None:
        assert out["successCount"] == STATUS["successCount"]
    elif case.key == "assignments":
        assert out[case.key] == SANITISED_ASSIGNMENTS
    else:
        assert len(out[case.key]) == 3
    parent, child = h.graph_requests
    assert (parent.url.path, child.url.path) == (parent_path(case), child_path(case))
    assert dict(parent.url.params) == {"$select": "id"}
    assert scp_of(parent) == scope_name(case.parent_scope)
    assert scp_of(child) == scope_name(CONFIGURATION_SCOPE)
    # Both requests carry the caller's own delegated token for the scope they need.
    assert {r.method for r in h.graph_requests} == {"GET"}
    if case.parent_scope == CONFIGURATION_SCOPE:
        assert parent.headers["authorization"] == child.headers["authorization"]
        assert [s for _, s in h.token_requests] == [(CONFIGURATION_SCOPE,)]  # still one exchange
    else:
        assert parent.headers["authorization"] != child.headers["authorization"]
        # One exchange per scope, parent's first; each asks for exactly one allowlisted scope.
        assert [s for _, s in h.token_requests] == [(GRAPH_SCOPE,), (CONFIGURATION_SCOPE,)]
    assert all(len(s) == 1 and ".default" not in s[0] for _, s in h.token_requests)


@every_case
async def test_allowed_user_has_exactly_one_ok_audit_line(h, caplog, case):
    world(h)
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.INFO):
        payload(await h.call_tool(token, case.tool, args_of(case)))
    [line] = audit_lines(caplog)
    assert "outcome=ok" in line and f"target={case.ident}" in line


@every_case
async def test_the_parent_id_is_compared_in_canonical_form(h, case):
    """Graph may spell the GUID in upper case; the same GUID is still the same object."""
    world(h)
    real = h._graph_handler  # noqa: SLF001

    def shouting(request):
        response = real(request)
        if request.url.path == parent_path(case) and response.status_code == 200:
            return httpx2.Response(200, json={"id": case.ident.upper()})
        return response

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(shouting))  # noqa: SLF001
    token = await bearer(h, OID_A)
    payload(
        await h.call_tool(token, case.tool, args_of(case, **({"page_size": 1} if case.key else {})))
    )
    assert len(requests_to(h, child_path(case))) == 1


# -- paging: every page re-checks the parent ------------------------------------------------------
@paged_case
async def test_every_page_repeats_the_parent_check_with_the_page_token(h, case):
    world(h)
    token = await bearer(h, OID_A)
    first = payload(await h.call_tool(token, case.tool, args_of(case, page_size=1)))
    assert first["next_page_token"]
    assert [r.url.path for r in h.graph_requests] == [parent_path(case), child_path(case)]
    second = payload(
        await h.call_tool(token, case.tool, args_of(case, page_token=first["next_page_token"]))
    )
    assert second["count"] == 1
    assert [r.url.path for r in h.graph_requests][2:] == [parent_path(case), child_path(case)]
    assert h.graph_requests[-1].url.params["$skiptoken"]  # it really was the second page


@paged_case
async def test_a_second_page_is_refused_once_the_parent_is_no_longer_visible(h, caplog, case):
    world(h)
    token = await bearer(h, OID_A)
    first = payload(await h.call_tool(token, case.tool, args_of(case, page_size=1)))
    page_token = first["next_page_token"]
    assert page_token
    hide_parent(h, case, OID_A)  # e.g. the user's scope tags changed between pages
    before = len(h.graph_requests)
    with caplog.at_level(logging.INFO):
        text = error_text(await h.call_tool(token, case.tool, args_of(case, page_token=page_token)))
    assert text.startswith(f"not_found: No matching {case.noun} is visible to this user.")
    after = h.graph_requests[before:]
    assert [r.url.path for r in after] == [parent_path(case)]  # the child page was not requested
    assert audit_lines(caplog)[-1].count("outcome=not_found") == 1


# -- parent-check failures fail closed -------------------------------------------------------------
def fault_on_parent(h, respond):
    """Route parent GETs (only) through `respond`; everything else is the normal simulation."""
    real = h._graph_handler  # noqa: SLF001

    def handler(request):
        segments = request.url.path.removeprefix(V1).split("/")
        if len(segments) == 2 and segments[0] in (
            "managedDevices",
            "deviceCompliancePolicies",
            "deviceConfigurations",
        ):
            h.graph_requests.append(request)
            return respond(request)
        return real(request)

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))  # noqa: SLF001


def raise_(exc):
    def respond(request):
        raise exc

    return respond


def status(code, **headers):
    return lambda request: httpx2.Response(code, headers=headers, json={"error": {"code": "X"}})


def ok_body(body):
    return lambda request: httpx2.Response(200, json=body)


OTHER_GUID = guid("z", 77)
CORE_FAULTS = {
    "403": (status(403), "forbidden"),
    "429": (status(429, **{"Retry-After": "9"}), "throttled"),
    "500": (status(500), "upstream_error"),
    "timeout": (raise_(httpx2.ReadTimeout("slow")), "upstream_timeout"),
    "other_id": (ok_body({"id": OTHER_GUID}), "bad_response"),
}
MORE_FAULTS = {
    "401": (status(401), "graph_unauthorized"),
    "503": (status(503), "throttled"),
    "400": (status(400), "bad_request"),
    "connect_error": (raise_(httpx2.ConnectError("down")), "upstream_error"),
    "no_id": (ok_body({}), "bad_response"),
    "null_id": (ok_body({"id": None}), "bad_response"),
    "int_id": (ok_body({"id": 5}), "bad_response"),
    "list_id": (ok_body({"id": [DEVICE_ID]}), "bad_response"),
    "not_a_guid": (ok_body({"id": "not-a-guid"}), "bad_response"),
    "collection_body": (ok_body({"value": [{"id": DEVICE_ID}]}), "bad_response"),
    "prefix_of_id": (ok_body({"id": DEVICE_ID[:-1]}), "bad_response"),
    "list_body": (lambda r: httpx2.Response(200, json=[{"id": DEVICE_ID}]), "bad_response"),
    "invalid_json": (lambda r: httpx2.Response(200, content=b"{not json"), "bad_response"),
}


@pytest.mark.parametrize("fault", sorted(CORE_FAULTS))
@every_case
async def test_a_failed_parent_check_fails_closed_and_the_child_is_never_requested(
    h, caplog, case, fault
):
    world(h)
    respond, code = CORE_FAULTS[fault]
    fault_on_parent(h, respond)
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.INFO):
        text = error_text(await h.call_tool(token, case.tool, args_of(case)))
    assert text.startswith(f"{code}: ") and "(ref " in text
    assert not any(r.url.path.endswith("/" + case.child) for r in h.graph_requests)
    [line] = audit_lines(caplog)
    assert f"outcome={code}" in line
    assert "SECRET" not in text and "SECRET" not in line
    if fault == "429":
        assert "Retry after 9s" in text


@pytest.mark.parametrize("fault", sorted(MORE_FAULTS))
@pytest.mark.parametrize("case", [CASES[0], CASES[2], CASES[3], CASES[5]], ids=lambda c: c.tool)
async def test_more_parent_check_failures_fail_closed(h, case, fault):
    world(h)
    respond, code = MORE_FAULTS[fault]
    fault_on_parent(h, respond)
    token = await bearer(h, OID_A)
    text = error_text(await h.call_tool(token, case.tool, args_of(case)))
    assert text.startswith(f"{code}: ")
    assert not any(r.url.path.endswith("/" + case.child) for r in h.graph_requests)


@paged_case
async def test_a_parent_check_failure_on_a_later_page_fails_closed(h, case):
    world(h)
    token = await bearer(h, OID_A)
    first = payload(await h.call_tool(token, case.tool, args_of(case, page_size=1)))
    fault_on_parent(h, status(500))
    before = len(h.graph_requests)
    text = error_text(
        await h.call_tool(token, case.tool, args_of(case, page_token=first["next_page_token"]))
    )
    assert text.startswith("upstream_error: ")
    assert [r.url.path for r in h.graph_requests[before:]] == [parent_path(case)]


# -- scopes: the second exchange, only for the declared parent scope of an enabled group ----------
@pytest.mark.parametrize("case", CASES[:2], ids=lambda c: c.tool)
async def test_device_state_tools_fail_closed_when_the_devices_group_is_not_enabled(case):
    async with Harness(make_settings(enabled_tool_groups="configuration")).running() as h:
        world(h)
        token = await bearer(h, OID_A)
        text = error_text(await h.call_tool(token, case.tool, args_of(case)))
        assert text.startswith("parent_check_unavailable: ") and "(ref " in text
        assert h.token_requests == [] and h.graph_requests == []  # nothing exchanged or requested
        # The same group's other child tools are unaffected: their parent uses their own scope.
        payload(await h.call_tool(token, CASES[2].tool, args_of(CASES[2])))
        assert [s for _, s in h.token_requests] == [(CONFIGURATION_SCOPE,)]
        assert [r.url.path for r in h.graph_requests] == [
            parent_path(CASES[2]),
            child_path(CASES[2]),
        ]


@pytest.mark.parametrize("refused", [GRAPH_SCOPE, CONFIGURATION_SCOPE])
async def test_a_refused_exchange_for_either_scope_leaves_graph_untouched(h, refused):
    original = h.token_source.get_credential  # noqa: SLF001

    async def get_credential(assertion):
        real = await original(assertion)

        class Cred:
            async def get_token(self, *scopes):
                if scopes == (refused,):
                    raise RuntimeError("AADSTS65001: SECRET-TENANT-TEXT")
                return await real.get_token(*scopes)

        return Cred()

    h.token_source.get_credential = get_credential
    world(h)
    token = await bearer(h, OID_A)
    text = error_text(await h.call_tool(token, CASES[0].tool, args_of(CASES[0])))
    assert text.startswith("graph_consent_required: ") and "SECRET" not in text
    assert h.graph_requests == []


async def test_a_group_may_use_a_parent_scope_only_if_it_declares_it(monkeypatch):
    """Registry-declared: with no declared parent scope the device state tools are an internal
    error before any exchange; nothing falls back to using the group's own scope."""
    bare = dataclasses.replace(TOOL_GROUPS["configuration"], parent_scope=None)
    monkeypatch.setitem(TOOL_GROUPS, "configuration", bare)
    async with Harness(make_settings(enabled_tool_groups="devices,configuration")).running() as h:
        world(h)
        token = await bearer(h, OID_A)
        text = error_text(await h.call_tool(token, CASES[0].tool, args_of(CASES[0])))
        assert text.startswith("internal_error: ")
        assert h.token_requests == [] and h.graph_requests == []
        payload(await h.call_tool(token, CASES[2].tool, args_of(CASES[2])))  # same-scope parent


def test_registry_declares_exactly_the_parent_scope_the_specs_need():
    assert TOOL_GROUPS["devices"].parent_scope is None
    assert TOOL_GROUPS["configuration"].parent_scope == GRAPH_SCOPE
    with pytest.raises(ValueError):
        ToolGroup("g", GRAPH_SCOPE, (), parent_scope=GRAPH_SCOPE)  # not "another" scope
    with pytest.raises(ValueError):
        ToolGroup("g", GRAPH_SCOPE, (), parent_scope="https://graph.microsoft.com/.default")
    with pytest.raises(ValueError):
        ToolGroup(
            "g", GRAPH_SCOPE, (), parent_scope="https://graph.microsoft.com/Foo.ReadWrite.All"
        )
    specs = [
        v
        for v in vars(graph_module).values()
        if isinstance(v, (graph_module.CollectionSpec, graph_module.ObjectSpec))
        and v.parent is not None
    ]
    assert {s.key for s in specs} == {
        graph_module.APP_ASSIGNMENTS_SPEC.key,
        graph_module.APP_CONFIGURATION_ASSIGNMENTS_SPEC.key,
        graph_module.ENROLLMENT_ASSIGNMENTS_SPEC.key,
        graph_module.TERMS_ASSIGNMENTS_SPEC.key,
        graph_module.ROLE_ASSIGNMENTS_SPEC.key,
        graph_module.ROLE_ASSIGNMENT_SPEC.key,
        COMPLIANCE_STATES_SPEC.key,
        CONFIGURATION_STATES_SPEC.key,
        COMPLIANCE_POLICY_STATUS_SPEC.key,
        COMPLIANCE_POLICY_ASSIGNMENTS_SPEC.key,
        CONFIGURATION_PROFILE_STATUS_SPEC.key,
        CONFIGURATION_PROFILE_ASSIGNMENTS_SPEC.key,
    }
    for spec in specs:
        group = next(g for g in TOOL_GROUPS.values() if g.scope == spec.scope)
        assert spec.parent.scope in (spec.scope, group.parent_scope), spec.key
        assert spec.parent.fields == ("id",) and spec.parent.parent is None
        assert set(spec.parent.path_params).issubset(spec.path_params)
        assert spec.path.startswith(spec.parent.path + "/")


def test_a_spec_cannot_declare_a_parent_that_does_not_fit():
    def thing(name, path, *params, fields=("id",), parent=None):
        return ObjectSpec(name, path, CONFIGURATION_SCOPE, fields, params, parent=parent)

    good = thing("t.ok", "/deviceManagement/things/{profile_id}", "profile_id")
    child_path_ = "/deviceManagement/things/{profile_id}/kids"
    thing("t.child", child_path_, "profile_id", fields=("x",), parent=good)  # the valid shape
    nested = thing("t.n", "/deviceManagement/things/{profile_id}/mid", "profile_id", parent=good)
    bad_parents = [
        graph_module.CONFIGURATION_PROFILE_SPEC,  # selects more than the id
        thing("t.p", "/deviceManagement/others/{profile_id}", "profile_id"),  # path not extended
        thing("t.q", "/deviceManagement/things/{policy_id}", "policy_id"),  # another parameter
        thing("t.r", "/deviceManagement/things"),  # no parameter at all
    ]
    for bad in bad_parents:
        with pytest.raises(ValueError):
            thing("t.bad", child_path_, "profile_id", fields=("x",), parent=bad)
    thing("t.deep", child_path_.replace("kids", "mid/kids"), "profile_id", parent=good)  # path fits
    with pytest.raises(ValueError):  # ... but a parent of a parent is not supported
        thing("t.deeper", child_path_.replace("kids", "mid/kids"), "profile_id", parent=nested)


# -- the read layer itself refuses an unchecked plan ----------------------------------------------
UNCHECKED = [
    (COMPLIANCE_STATES_SPEC, {"device_id": DEVICE_ID}),
    (CONFIGURATION_STATES_SPEC, {"device_id": DEVICE_ID}),
    (COMPLIANCE_POLICY_ASSIGNMENTS_SPEC, {"policy_id": POLICY_ID}),
    (CONFIGURATION_PROFILE_ASSIGNMENTS_SPEC, {"profile_id": PROFILE_ID}),
    (COMPLIANCE_POLICY_STATUS_SPEC, {"policy_id": POLICY_ID}),
    (CONFIGURATION_PROFILE_STATUS_SPEC, {"profile_id": PROFILE_ID}),
]


@pytest.mark.parametrize(("spec", "args"), UNCHECKED, ids=[s.key for s, _ in UNCHECKED])
async def test_a_child_endpoint_is_never_requested_without_a_verified_parent(spec, args):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx2.Response(200, json={"value": [], "id": next(iter(args.values()))})

    client = GraphClient(client=httpx2.AsyncClient(transport=httpx2.MockTransport(handler)))
    if isinstance(spec, ObjectSpec):
        plan = plan_object(spec, path_args=args)
        with pytest.raises(ValueError):
            await client.fetch_object("t", plan, "c")
    else:
        plan = client.plan(spec, path_args=args, page_size=5, page_token=None)
        with pytest.raises(ValueError):
            await client.fetch_page("t", plan, "c")
    assert seen == []
    # Verifying marks the plan, and only then may the child be read.
    checked = await client.verify_parent("t", plan, "c")
    assert checked.parent_checked is True and plan.parent_checked is False
    assert len(seen) == 1 and dict(seen[0].url.params) == {"$select": "id"}


async def test_verify_parent_needs_the_matching_id_and_ignores_specs_without_a_parent():
    body = {"id": DEVICE_ID}
    seen = []

    def handler(request):
        seen.append(request)
        return httpx2.Response(200, json=body)

    client = GraphClient(client=httpx2.AsyncClient(transport=httpx2.MockTransport(handler)))
    plan = client.plan(
        COMPLIANCE_STATES_SPEC, path_args={"device_id": DEVICE_ID}, page_size=5, page_token=None
    )
    assert (await client.verify_parent("t", plan, "c")).parent_checked
    body["id"] = OTHER_GUID
    with pytest.raises(GraphError) as exc:
        await client.verify_parent("t", plan, "c")
    assert exc.value.code == "bad_response"
    # A spec with no parent: nothing is requested and the plan is returned unchanged.
    seen.clear()
    no_parent = plan_object(DEVICE_SPEC, path_args={"device_id": DEVICE_ID})
    assert await client.verify_parent("t", no_parent, "c") is no_parent and seen == []
    await client.fetch_object("t", no_parent, "c")  # the parent gate does not touch them


# -- count_devices: scoped rows only, never $count -------------------------------------------------
def fleet(n, owner="a", **kw):
    return [device(i, owner, **kw) for i in range(1, n + 1)]


def count_requests(h):
    return [r for r in h.graph_requests if r.url.path == V1 + "managedDevices"]


async def test_restricted_user_counts_only_their_own_devices_not_the_tenant_total(h):
    world(h)
    token = await bearer(h, OID_B)
    out = payload(await h.call_tool(token, "count_devices"))
    assert out == {"count": 1, "complete": True, "note": None}
    assert str(TENANT_WIDE_COUNT) not in str(out)
    for req in h.graph_requests:
        assert "$count" not in req.url.params and "consistencylevel" not in {
            k.lower() for k in req.headers
        }
        assert req.url.params["$select"] == "id"


async def test_allowed_user_counts_all_their_devices_across_pages(h):
    h.devices[OID_A] = fleet(250)
    h.odata_count_total = 99999  # must never be used
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, "count_devices"))
    assert out == {"count": 250, "complete": True, "note": None}
    reqs = count_requests(h)
    assert [r.url.params.get("$skiptoken") for r in reqs] == [None, "100", "200"]
    assert {r.url.params["$top"] for r in reqs} == {"100"}
    assert all("$count" not in r.url.params for r in reqs)
    assert all(r.headers["authorization"] == reqs[0].headers["authorization"] for r in reqs)
    assert [s for _, s in h.token_requests] == [(GRAPH_SCOPE,)]  # one scope, one exchange


async def test_the_filters_are_applied_to_every_page_of_the_count(h):
    h.devices[OID_A] = fleet(130) + [
        device(1000 + i, managedDeviceOwnerType="personal") for i in range(105)
    ]
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, "count_devices", {"ownership": "personal"}))
    assert out["count"] == 105 and out["complete"] is True
    reqs = count_requests(h)
    assert len(reqs) == 2
    for req in reqs:
        assert req.url.params["$filter"] == "managedDeviceOwnerType eq 'personal'"
        assert req.url.params["$select"] == "id"


async def test_the_count_stops_at_5000_rows_and_says_at_least(h):
    h.devices[OID_A] = fleet(5250)
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, "count_devices"))
    assert out["count"] == 5000 and out["complete"] is False
    assert "at least 5000" in out["note"] and "Narrow the filters" in out["note"]
    assert len(count_requests(h)) == 50  # 5000 rows / 100 per page


async def test_exactly_5000_devices_is_a_complete_count(h):
    h.devices[OID_A] = fleet(5000)
    token = await bearer(h, OID_A)
    out = payload(await h.call_tool(token, "count_devices"))
    assert out == {"count": 5000, "complete": True, "note": None}


async def test_the_count_never_returns_ids_names_or_filter_values(h):
    secret = "tech.secret@example.test"
    h.devices[OID_A] = fleet(3, userPrincipalName=secret)
    token = await bearer(h, OID_A)
    raw = await h.call_tool(token, "count_devices", {"assigned_user": secret})
    out = payload(raw)
    assert set(out) == {"count", "complete", "note"} and out["count"] == 3
    text = str(raw)
    for d in h.devices[OID_A]:
        assert d["id"] not in text and d["deviceName"] not in text
    assert LEAK not in text and secret not in text
    # the id-only $select means Graph is not even asked for names or UPNs
    assert all(r.url.params["$select"] == "id" for r in count_requests(h))


async def test_count_audit_has_filter_names_count_and_completeness_never_values(h, caplog):
    secret = "tech.secret@example.test"
    h.devices[OID_A] = fleet(7, userPrincipalName=secret)
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.INFO):
        payload(await h.call_tool(token, "count_devices", {"assigned_user": secret}))
    [line] = audit_lines(caplog)
    assert "tool=count_devices" in line and "outcome=ok" in line
    assert "count=7" in line and "complete=True" in line and "filters=assigned_user" in line
    assert secret not in "\n".join(r.getMessage() for r in caplog.records)
    h.devices[OID_A] = fleet(5100)
    caplog.clear()
    with caplog.at_level(logging.INFO):
        payload(await h.call_tool(token, "count_devices"))
    [line] = audit_lines(caplog)
    assert "count=5000" in line and "complete=False" in line and "filters=none" in line


async def test_a_failure_while_counting_is_one_safe_error_and_one_audit_line(h, caplog):
    h.devices[OID_A] = fleet(250)
    real = h._graph_handler  # noqa: SLF001
    calls = []

    def flaky(request):
        calls.append(request)
        if len(calls) == 2:
            return httpx2.Response(429, headers={"Retry-After": "5"})
        return real(request)

    h.graph._client = httpx2.AsyncClient(transport=httpx2.MockTransport(flaky))  # noqa: SLF001
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.INFO):
        text = error_text(await h.call_tool(token, "count_devices"))
    assert text.startswith("throttled: ") and "Retry after 5s" in text
    [line] = audit_lines(caplog)
    assert "outcome=throttled" in line and "count=" not in line  # no partial count is reported


async def test_count_description_and_instructions_say_what_the_count_is(h):
    from intune_mcp.server import instructions_for

    token = await bearer(h, OID_A)
    from .test_device_tools import tool_schemas

    description = (await tool_schemas(h, token))["count_devices"]["description"]
    for phrase in ("visible to you", "paging", "5000", "complete=false", "not the tenant"):
        assert phrase in description.replace("Not the tenant", "not the tenant"), phrase
    text = instructions_for(("devices",))
    assert "count_unavailable" not in text and "needs Microsoft to return a count" not in text
    assert "only the devices Microsoft returns to this user" in text
    assert "complete=false" in text and "NOT Microsoft's tenant-wide total" in text


def test_nothing_in_the_source_asks_graph_for_a_count():
    import pathlib

    src = pathlib.Path(graph_module.__file__).parent
    for path in src.glob("*.py"):
        text = path.read_text()
        assert "ConsistencyLevel" not in text and "count_unavailable" not in text, path.name
        # no request parameter or response key lookup for the tenant-wide count
        assert '"$count"' not in text and 'get("@odata.count")' not in text, path.name
