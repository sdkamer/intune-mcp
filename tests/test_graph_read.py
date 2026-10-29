"""Generic safe read layer: typed filters, bound page tokens, nextLink checks (all mocked)."""

import base64
import json
import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from urllib.parse import parse_qsl, urlsplit

import httpx2 as httpx
import pytest

from intune_mcp.graph import (
    COMPLIANCE_STATES_SPEC,
    CONFIGURATION_STATES_SPEC,
    DEVICE_FILTERS,
    DEVICE_OVERVIEW_SPEC,
    DEVICE_SPEC,
    LIST_DEVICES_SPEC,
    MAX_COUNT_PAGES,
    MAX_COUNT_ROWS,
    MAX_NEXT_LINK_CHARS,
    MAX_PAGE_SIZE,
    MAX_PAGE_TOKEN_CHARS,
    MAX_RESPONSE_BYTES,
    MAX_ROWS_PER_PAGE,
    SEARCH_DEVICES_SPEC,
    GraphClient,
    GraphError,
    StringFilter,
    decode_page_token,
    encode_page_token,
    odata_string,
    plan_count,
    plan_object,
    plan_read,
    render_filter,
)

DEV = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
OTHER_DEV = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
NOW = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)
CUTOFF_30 = "2026-01-30T12:00:00Z"
COLLECTIONS = [
    LIST_DEVICES_SPEC,
    SEARCH_DEVICES_SPEC,
    COMPLIANCE_STATES_SPEC,
    CONFIGURATION_STATES_SPEC,
]
FILTERS_BY_NAME = {f.name: f for f in DEVICE_FILTERS}


def args_for(spec, device=DEV):
    return {"device_id": device} if spec.path_params else {}


def link_for(spec, device=DEV, query="$skiptoken=abc"):
    path = spec.path.format(device_id=device)
    return f"https://graph.microsoft.com/v1.0{path}?{query}"


def checked(plan):
    """Mark a plan's parent as already verified: these tests exercise paging, not the parent gate.

    (The gate itself, including that fetch_* refuses an unchecked plan, is in test_parent_checks.)
    """
    return replace(plan, parent_checked=True)


def client_with(handler, clock=lambda: NOW) -> GraphClient:
    return GraphClient(
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)), clock=clock
    )


def forge(payload) -> str:
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")


def valid_payload(spec=SEARCH_DEVICES_SPEC, **overrides):
    payload = {
        "n": 1,
        "e": spec.key,
        "k": "skiptoken",
        "c": "abc",
        "t": 5,
        "p": args_for(spec),
        "f": {},
    }
    payload.update(overrides)
    return {k: v for k, v in payload.items() if v is not ...}


def plan(spec=SEARCH_DEVICES_SPEC, *, filters=None, page_size=25, page_token=None, now=NOW):
    return plan_read(
        spec,
        path_args=args_for(spec),
        filters=filters or {},
        page_size=page_size,
        page_token=page_token,
        now=now,
    )


# -- rendering ---------------------------------------------------------------------------------
def test_odata_string_doubles_single_quotes_and_nothing_else():
    assert odata_string("abc") == "'abc'"
    assert odata_string("a'b") == "'a''b'"
    assert odata_string("'") == "''''"
    assert odata_string("x' or '1'='1") == "'x'' or ''1''=''1'"


def test_renderers_escape_even_if_validation_were_bypassed():
    # Defence in depth: a hostile value handed straight to render() stays inside its literal.
    hostile = "x') or deviceName ne ('y"
    rendered = FILTERS_BY_NAME["name_prefix"].render(hostile)
    assert rendered == "startswith(deviceName,'x'') or deviceName ne (''y')"
    assert FILTERS_BY_NAME["assigned_user"].render("a'b") == "userPrincipalName eq 'a''b'"
    assert FILTERS_BY_NAME["compliance_state"].render("x'y") == "complianceState eq 'x''y'"


def test_filter_is_rendered_in_spec_order_joined_by_and():
    p = plan(
        filters={
            "assigned_user": "tech.one+tag@example.test",
            "not_synced_days": 30,
            "ownership": "company",
            "compliance_state": "noncompliant",
            "operating_system": "Windows 10 (x64)",
            "name_prefix": "PC-01",
        }
    )
    assert render_filter(SEARCH_DEVICES_SPEC, p.filters) == (
        "startswith(deviceName,'PC-01')"
        " and operatingSystem eq 'Windows 10 (x64)'"
        " and complianceState eq 'noncompliant'"
        " and managedDeviceOwnerType eq 'company'"
        f" and lastSyncDateTime lt {CUTOFF_30}"
        " and userPrincipalName eq 'tech.one+tag@example.test'"
    )


def test_no_filter_renders_no_filter_at_all():
    assert plan(filters={}).filters == {}
    assert plan(filters={"name_prefix": None, "ownership": None}).filters == {}


def test_cutoff_is_computed_server_side_in_utc_whole_seconds():
    odd = datetime(2026, 3, 1, 12, 0, 0, 999999, tzinfo=UTC)
    assert plan(filters={"not_synced_days": 30}, now=odd).filters == {"not_synced_days": CUTOFF_30}
    plus = NOW.astimezone(timezone(timedelta(hours=2)))  # same instant, +02:00
    assert plan(filters={"not_synced_days": 30}, now=plus).filters == {"not_synced_days": CUTOFF_30}
    assert plan(filters={"not_synced_days": 1}).filters == {
        "not_synced_days": "2026-02-28T12:00:00Z"
    }


# -- validation matrix -------------------------------------------------------------------------
VALID = {
    "name_prefix": ["a", "PC-01", "a.b_c-d", "x" * 64],
    "operating_system": ["Windows", "Windows 10 (x64)", "macOS", "a.b-c", "x" * 40],
    "compliance_state": [
        "unknown",
        "compliant",
        "noncompliant",
        "conflict",
        "error",
        "inGracePeriod",
        "configManager",
    ],
    "ownership": ["unknown", "company", "personal"],
    "not_synced_days": [1, 30, 3650],
    "assigned_user": ["abc", "tech.one@example.test", "a%b+c@d-e_f", "u" * 256],
}
# Independent copies of the documented patterns.
RULES = {
    "name_prefix": re.compile(r"[A-Za-z0-9._-]{1,64}"),
    "operating_system": re.compile(r"[A-Za-z0-9 ().-]{1,40}"),
    "assigned_user": re.compile(r"[A-Za-z0-9._%+@-]{3,256}"),
}
ENUMS = {
    "compliance_state": set(VALID["compliance_state"]),
    "ownership": set(VALID["ownership"]),
}
QUOTES = ["'", "\u2019", "\u2018", "\u02bc", "\uff07", "\u201c", '"', "`"]
ATTACKS = [
    "x' or '1'='1",
    "x'",
    "'",
    "''",
    "x' or 1 eq 1 or 'a'='a",
    "x or y",
    "x' and 1 eq 1 --",
    "x') or (deviceName ne 'y",
    "x)",
    "(x",
    "((",
    "x%27 or %271%27=%271",
    "%27",
    "x%27or%27y",
    "%2527",
    "x\u2019 or \u2018y",
    "\uff07 or \uff07",
    "x\u02bcy",
    "x\ny",
    "x\r\ny",
    "\n",
    "x\u2028y",
    "x\x00y",
    "\x00",
    "x\ty",
    "x" * 300,
    "x" * 100_000,
    "",
    " ",
    "  ",
    "x;y",
    "x\\y",
    "x/y",
    "é",
    "\uff41bc",  # fullwidth a
    "\u0661\u0662\u0663",  # Arabic-Indic digits
    "x,y",
    "x=y",
    "x&$top=1",
    "x#y",
    "${x}",
    "$filter=a",
    "tolower(x)",
    "x ne y",
    "null",
]
TYPE_CONFUSION = [5, 1.5, True, False, ["a"], {"a": 1}, b"abc", ("a",)]


@pytest.mark.parametrize(("name", "value"), [(n, v) for n, vs in VALID.items() for v in vs])
def test_valid_values_are_accepted(name, value):
    assert name in plan(filters={name: value}).filters


@pytest.mark.parametrize("name", list(VALID))
@pytest.mark.parametrize("value", ATTACKS)
def test_injection_attempts_never_reach_the_rendered_filter(name, value):
    client = client_with(lambda r: httpx.Response(200, json={"value": []}))
    if name in RULES:
        should_pass = bool(RULES[name].fullmatch(value))
    elif name in ENUMS:
        should_pass = value in ENUMS[name]
    else:
        should_pass = False  # not_synced_days takes an integer only
    if should_pass:
        # Only characters that are inert inside a quoted literal can get through; no quote ever.
        filters = client.plan(
            SEARCH_DEVICES_SPEC, filters={name: value}, page_size=5, page_token=None
        ).filters
        text = render_filter(SEARCH_DEVICES_SPEC, filters)
        assert not any(q in value for q in QUOTES) and "\n" not in value and "\x00" not in value
        literal = re.search(r"'(.*)'", text).group(1)
        assert "'" not in literal and text.count("'") == 2
        return
    with pytest.raises(GraphError) as exc:
        client.plan(SEARCH_DEVICES_SPEC, filters={name: value}, page_size=5, page_token=None)
    assert exc.value.code == "invalid_filter"
    assert name in exc.value.message
    assert value[:20] not in exc.value.message or value[:20].strip() == ""


@pytest.mark.parametrize(
    ("name", "value"),
    [
        (name, value)
        for name in VALID
        for value in TYPE_CONFUSION
        if not (name == "not_synced_days" and value == 5)  # 5 is a valid day count
    ],
)
def test_non_string_or_non_integer_values_are_rejected(name, value):
    with pytest.raises(GraphError) as exc:
        plan(filters={name: value})
    assert exc.value.code == "invalid_filter"


@pytest.mark.parametrize("value", [0, -1, 3651, 10**9, 10**100, "7", "7 or 1", 7.0])
def test_not_synced_days_range_and_type(value):
    with pytest.raises(GraphError) as exc:
        plan(filters={"not_synced_days": value})
    assert exc.value.code == "invalid_filter" and "1 to 3650" in exc.value.message


@pytest.mark.parametrize(
    "value", ["Compliant", "COMPLIANT", "compliant ", " compliant", "in_grace"]
)
def test_enums_are_case_and_whitespace_exact(value):
    with pytest.raises(GraphError):
        plan(filters={"compliance_state": value})


def test_undeclared_filter_arguments_are_a_programming_error_not_odata():
    with pytest.raises(ValueError):
        plan(filters={"$filter": "x eq 1"})
    with pytest.raises(ValueError):
        plan(LIST_DEVICES_SPEC, filters={"name_prefix": "a"})  # list_devices has no filters


def test_hostile_values_do_not_appear_in_the_error_message():
    secret = "someone@example.test' or 1 eq 1"
    with pytest.raises(GraphError) as exc:
        plan(filters={"assigned_user": secret})
    assert "someone" not in exc.value.message and "example.test" not in exc.value.message


async def test_percent_forms_are_inert_on_the_wire_and_plus_is_encoded():
    """`%` and `+` are allowed in assigned_user; they must reach Graph as literal text."""
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"value": []})

    client = client_with(handler)
    p = client.plan(
        SEARCH_DEVICES_SPEC,
        filters={"assigned_user": "a%27or%271@x.test", "name_prefix": "a+b"[:1]},
        page_size=5,
        page_token=None,
    )
    await client.fetch_page("tok", p, "c")
    [req] = seen
    # Decoded once (what Graph's OData parser sees), the literal still holds `%27` as text.
    assert req.url.params["$filter"] == (
        "startswith(deviceName,'a') and userPrincipalName eq 'a%27or%271@x.test'"
    )
    assert "%2527or%2527" in str(req.url)  # percent sign itself is encoded: no second decode


async def test_plus_in_an_upn_is_percent_encoded():
    seen = []
    client = client_with(lambda r: seen.append(r) or httpx.Response(200, json={"value": []}))
    p = client.plan(
        SEARCH_DEVICES_SPEC, filters={"assigned_user": "a+b@x.test"}, page_size=5, page_token=None
    )
    await client.fetch_page("tok", p, "c")
    assert "a%2Bb%40x.test" in str(seen[0].url)
    assert seen[0].url.params["$filter"] == "userPrincipalName eq 'a+b@x.test'"


def test_page_size_is_bounded_by_the_spec():
    for bad in (0, 101, -1, True, "5", 5.0, None):
        with pytest.raises(GraphError) as exc:
            plan(page_size=bad)
        assert exc.value.code == "invalid_page_size"


@pytest.mark.parametrize("spec", [s for s in COLLECTIONS if s.path_params])
@pytest.mark.parametrize(
    "bad", ["", "1", "../users", f"{DEV}/wipe", f"{DEV}?x=1", f"{DEV}\n", None, 5, "x" * 5000]
)
def test_path_ids_must_be_guids_before_anything_else(spec, bad):
    with pytest.raises(GraphError) as exc:
        plan_read(
            spec, path_args={"device_id": bad}, filters={}, page_size=5, page_token=None, now=NOW
        )
    assert exc.value.code == "invalid_device_id"
    with pytest.raises(GraphError):
        plan_object(DEVICE_SPEC, path_args={"device_id": bad})


def test_plan_count_is_only_for_countable_endpoints():
    counted = plan_count(SEARCH_DEVICES_SPEC, filters={"ownership": "company"}, now=NOW)
    assert counted.top == MAX_PAGE_SIZE
    with pytest.raises(ValueError):
        plan_count(LIST_DEVICES_SPEC, filters={}, now=NOW)


# -- page tokens -------------------------------------------------------------------------------
def test_token_carries_validated_structured_filter_not_odata():
    p = plan(filters={"name_prefix": "PC", "not_synced_days": 30})
    token = encode_page_token(link_for(SEARCH_DEVICES_SPEC), 5, SEARCH_DEVICES_SPEC, {}, p.filters)
    raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode()
    payload = json.loads(raw)
    assert payload["f"] == {"name_prefix": "PC", "not_synced_days": CUTOFF_30}
    assert "startswith" not in raw and " eq " not in raw and "$filter" not in raw
    assert "graph.microsoft.com" not in token


def test_token_roundtrip_and_page_token_overrides_filters_and_page_size():
    first = plan(filters={"name_prefix": "PC", "ownership": "company"}, page_size=7)
    token = encode_page_token(
        link_for(SEARCH_DEVICES_SPEC, query="$skiptoken=T9&$top=7"),
        first.top,
        SEARCH_DEVICES_SPEC,
        first.path_args,
        first.filters,
    )
    second = plan(
        filters={"name_prefix": "OTHER", "assigned_user": "who@example.test"},
        page_size=100,
        page_token=token,
    )
    assert second.filters == first.filters == {"name_prefix": "PC", "ownership": "company"}
    assert (second.top, second.cursor) == (7, {"$skiptoken": "T9"})
    # Even filter values that would be invalid are ignored when a token is supplied.
    assert plan(filters={"name_prefix": "bad'"}, page_token=token).filters == first.filters


async def test_not_synced_cutoff_is_stable_across_pages_even_if_the_clock_moves():
    times = iter([NOW, NOW + timedelta(days=3)])
    seen = []

    def handler(request):
        seen.append(request)
        if "$skiptoken" not in request.url.params:
            return httpx.Response(
                200,
                json={
                    "value": [],
                    "@odata.nextLink": link_for(SEARCH_DEVICES_SPEC, query="$skiptoken=T1&$top=5"),
                },
            )
        return httpx.Response(200, json={"value": []})

    client = client_with(handler, clock=lambda: next(times))
    p1 = client.plan(
        SEARCH_DEVICES_SPEC, filters={"not_synced_days": 30}, page_size=5, page_token=None
    )
    page = await client.fetch_page("tok", p1, "c")
    p2 = client.plan(SEARCH_DEVICES_SPEC, page_size=5, page_token=page.next_page_token)
    await client.fetch_page("tok", p2, "c")
    assert [r.url.params["$filter"] for r in seen] == [f"lastSyncDateTime lt {CUTOFF_30}"] * 2


async def test_graph_supplied_link_parameters_other_than_the_cursor_are_never_used():
    seen = []

    def handler(request):
        seen.append(request)
        if "$skiptoken" not in request.url.params:
            return httpx.Response(
                200,
                json={
                    "value": [],
                    "@odata.nextLink": link_for(
                        SEARCH_DEVICES_SPEC,
                        query="$skiptoken=T1&$filter=evil%20eq%201&$top=999&$select=imei",
                    ),
                },
            )
        return httpx.Response(200, json={"value": []})

    client = client_with(handler)
    p1 = client.plan(
        SEARCH_DEVICES_SPEC, filters={"ownership": "personal"}, page_size=5, page_token=None
    )
    page = await client.fetch_page("tok", p1, "c")
    await client.fetch_page(
        "tok",
        client.plan(SEARCH_DEVICES_SPEC, page_size=5, page_token=page.next_page_token),
        "c",
    )
    second = seen[1].url.params
    assert second["$filter"] == "managedDeviceOwnerType eq 'personal'"
    assert second["$top"] == "5" and "imei" not in second["$select"]
    assert second["$skiptoken"] == "T1"


@pytest.mark.parametrize("spec", COLLECTIONS)
def test_every_spec_roundtrips_its_own_token(spec):
    filters = {"name_prefix": "PC"} if spec is SEARCH_DEVICES_SPEC else {}
    token = encode_page_token(link_for(spec), 9, spec, args_for(spec), filters)
    cursor = decode_page_token(token, spec)
    assert (cursor.params, cursor.top, cursor.path_args, cursor.filters) == (
        {"$skiptoken": "abc"},
        9,
        args_for(spec),
        filters,
    )


@pytest.mark.parametrize("minted", COLLECTIONS)
@pytest.mark.parametrize("replayed", COLLECTIONS)
def test_a_token_cannot_be_replayed_against_another_endpoint(minted, replayed):
    token = encode_page_token(link_for(minted), 9, minted, args_for(minted), {})
    if minted is replayed:
        assert decode_page_token(token, replayed).top == 9
        return
    with pytest.raises(GraphError) as exc:
        decode_page_token(token, replayed)
    assert exc.value.code == "invalid_page_token"
    with pytest.raises(GraphError):
        plan_read(
            replayed,
            path_args=args_for(replayed),
            filters={},
            page_size=5,
            page_token=token,
            now=NOW,
        )


def test_a_token_for_one_device_cannot_be_used_for_another_device():
    spec = COMPLIANCE_STATES_SPEC
    token = encode_page_token(link_for(spec), 9, spec, {"device_id": DEV}, {})
    assert plan_read(
        spec, path_args={"device_id": DEV}, filters={}, page_size=5, page_token=token, now=NOW
    ).path.endswith(f"/{DEV}/deviceCompliancePolicyStates")
    with pytest.raises(GraphError) as exc:
        plan_read(
            spec,
            path_args={"device_id": OTHER_DEV},
            filters={},
            page_size=5,
            page_token=token,
            now=NOW,
        )
    assert exc.value.code == "invalid_page_token"
    # An invalid id is still rejected as an invalid id, token or not.
    with pytest.raises(GraphError) as exc:
        plan_read(
            spec, path_args={"device_id": "x"}, filters={}, page_size=5, page_token=token, now=NOW
        )
    assert exc.value.code == "invalid_device_id"


@pytest.mark.parametrize(
    "token",
    [
        "!!!",
        "",
        "\u0000",
        forge(valid_payload(n=2)),
        forge(valid_payload(n=True)),
        forge(valid_payload(n=1.0)),  # equal to 1 but not an integer: strict type check
        forge(valid_payload(n="1")),
        forge(valid_payload(n=None)),
        forge(valid_payload(e="devices.list")),
        forge(valid_payload(e="")),
        forge(valid_payload(e=None)),
        forge(valid_payload(k="filter")),
        forge(valid_payload(k="skiptoken ")),
        forge(valid_payload(c="")),
        forge(valid_payload(c=5)),
        forge(valid_payload(c=None)),
        forge(valid_payload(c="x" * 4097)),
        forge(valid_payload(k="skip", c="1;drop")),
        forge(valid_payload(k="skip", c="1" * 10)),
        forge(valid_payload(k="skip", c="-1")),
        forge(valid_payload(t=0)),
        forge(valid_payload(t=101)),
        forge(valid_payload(t=True)),
        forge(valid_payload(t="5")),
        forge(valid_payload(t=5.5)),
        forge(valid_payload(t=None)),
        forge(valid_payload(p={"device_id": DEV})),  # search has no path params
        forge(valid_payload(p=None)),
        forge(valid_payload(p=[])),
        forge(valid_payload(f=None)),
        forge(valid_payload(f=[])),
        forge(valid_payload(f="name_prefix")),
        forge(valid_payload(extra=1)),
        forge(valid_payload(n=...)),
        forge(valid_payload(e=...)),
        forge(valid_payload(c=...)),
        forge(valid_payload(f=...)),
        forge(valid_payload(p=...)),
        forge(["list"]),
        forge("string"),
        forge(None),
        forge(5),
        base64.urlsafe_b64encode(b"\xff\xfe\x00not json").decode(),
        "[" * 6000,  # not base64 json
        forge(json.loads("[" * 400 + "]" * 400)),  # deeply nested
        base64.urlsafe_b64encode(b"[" * 5000).decode(),  # recursion bomb inside valid base64
    ],
)
def test_tampered_page_tokens_are_rejected(token):
    with pytest.raises(GraphError) as exc:
        decode_page_token(token, SEARCH_DEVICES_SPEC)
    assert exc.value.code == "invalid_page_token"


@pytest.mark.parametrize(
    "stored",
    [
        {"name_prefix": "x' or '1'='1"},
        {"name_prefix": "x')--"},
        {"name_prefix": ""},
        {"name_prefix": 5},
        {"name_prefix": None},
        {"name_prefix": ["a"]},
        {"name_prefix": "x" * 65},
        {"name_prefix": "x\n"},
        {"operating_system": "Win' or 'a'='a"},
        {"operating_system": "x\x00"},
        {"assigned_user": "a@b.test' or userPrincipalName ne '"},
        {"assigned_user": "ab"},
        {"assigned_user": "a%27 or 1"},
        {"compliance_state": "compliant' or 1 eq 1 or complianceState eq 'x"},
        {"compliance_state": "Compliant"},
        {"ownership": "company' or '1'='1"},
        {"ownership": "other"},
        {"not_synced_days": 30},  # the stored form is the cutoff, never a day count
        {"not_synced_days": "30"},
        {"not_synced_days": "2026-01-30T12:00:00Z or 1 eq 1"},
        {"not_synced_days": "2026-01-30T12:00:00Z\n"},
        {"not_synced_days": "2026-01-30T12:00:00"},
        {"not_synced_days": "2026-01-30T12:00:00+00:00"},
        {"not_synced_days": "2026-01-30T12:00:00.5Z"},
        {"not_synced_days": "2026-13-45T25:61:61Z"},
        {"not_synced_days": "2026-02-30T12:00:00Z"},
        {"not_synced_days": "1999-01-01T00:00:00Z"},
        {"not_synced_days": "2201-01-01T00:00:00Z"},
        {"not_synced_days": "\u0662026-01-30T12:00:00Z"},
        {"$filter": "deviceName ne 'x'"},
        {"deviceName": "x"},
        {"unknown": "x"},
        {"name_prefix": "ok", "extra": "x"},
    ],
)
def test_tampered_filter_inside_a_token_is_rejected_by_the_same_validators(stored):
    token = forge(valid_payload(f=stored))
    with pytest.raises(GraphError) as exc:
        decode_page_token(token, SEARCH_DEVICES_SPEC)
    assert exc.value.code == "invalid_page_token"
    with pytest.raises(GraphError):
        plan(page_token=token)


def test_a_filter_in_a_token_for_an_endpoint_without_that_filter_is_rejected():
    token = forge(valid_payload(LIST_DEVICES_SPEC, f={"name_prefix": "PC"}))
    with pytest.raises(GraphError) as exc:
        decode_page_token(token, LIST_DEVICES_SPEC)
    assert exc.value.code == "invalid_page_token"


@pytest.mark.parametrize("bad_device", [OTHER_DEV.upper(), "{" + OTHER_DEV + "}", "x", "", 5, None])
def test_tampered_path_args_inside_a_token_are_rejected(bad_device):
    token = forge(valid_payload(COMPLIANCE_STATES_SPEC, p={"device_id": bad_device}))
    with pytest.raises(GraphError) as exc:
        decode_page_token(token, COMPLIANCE_STATES_SPEC)
    assert exc.value.code == "invalid_page_token"
    for p in ({}, {"device_id": DEV, "x": DEV}, {"user_id": DEV}):
        with pytest.raises(GraphError):
            decode_page_token(
                forge(valid_payload(COMPLIANCE_STATES_SPEC, p=p)), COMPLIANCE_STATES_SPEC
            )


def test_valid_filter_in_a_hand_built_token_is_accepted():
    token = forge(valid_payload(f={"name_prefix": "PC-1", "not_synced_days": CUTOFF_30}))
    cursor = decode_page_token(token, SEARCH_DEVICES_SPEC)
    assert cursor.filters == {"name_prefix": "PC-1", "not_synced_days": CUTOFF_30}


def test_oversized_tokens_are_rejected_before_decoding():
    near_cap = forge(valid_payload(c="x" * 4096, f={"name_prefix": "y" * 64}))
    assert len(near_cap) <= MAX_PAGE_TOKEN_CHARS
    assert decode_page_token(near_cap, SEARCH_DEVICES_SPEC).top == 5
    # Valid JSON padded with whitespace decodes fine unless the length cap rejects it first.
    body = json.dumps(valid_payload()).encode()
    padded = base64.urlsafe_b64encode(body + b" " * (MAX_PAGE_TOKEN_CHARS * 2)).decode()
    assert len(padded) > MAX_PAGE_TOKEN_CHARS
    with pytest.raises(GraphError) as exc:
        decode_page_token(padded, SEARCH_DEVICES_SPEC)
    assert exc.value.code == "invalid_page_token"
    just_ok = base64.urlsafe_b64encode(body + b" " * 100).decode().rstrip("=")
    assert decode_page_token(just_ok, SEARCH_DEVICES_SPEC).top == 5
    with pytest.raises(GraphError):
        decode_page_token(5, SEARCH_DEVICES_SPEC)  # type: ignore[arg-type]


# -- nextLink validation -----------------------------------------------------------------------
BAD_LINKS = [
    "https://evil.example/v1.0{path}?$skiptoken=a",
    "http://graph.microsoft.com/v1.0{path}?$skiptoken=a",
    "https://graph.microsoft.com.evil.example/v1.0{path}?$skiptoken=a",
    "https://evil.example@graph.microsoft.com/v1.0{path}?$skiptoken=a",
    "https://graph.microsoft.com:8443/v1.0{path}?$skiptoken=a",
    "ftp://graph.microsoft.com/v1.0{path}?$skiptoken=a",
    "//graph.microsoft.com/v1.0{path}?$skiptoken=a",
    "/v1.0{path}?$skiptoken=a",
    "https://graph.microsoft.com/v1.0/users?$skiptoken=a",
    "https://graph.microsoft.com/beta{path}?$skiptoken=a",
    "https://graph.microsoft.com/v1.0{path}/extra?$skiptoken=a",
    "https://graph.microsoft.com/v1.0{path}/../../users?$skiptoken=a",
    "https://graph.microsoft.com/v1.0{path}%2f..?$skiptoken=a",
    "https://graph.microsoft.com/v1.0{path}?foo=bar",
    "https://graph.microsoft.com/v1.0{path}?$filter=x",
    "https://graph.microsoft.com/v1.0{path}?$skiptoken=",
    "https://graph.microsoft.com/v1.0{path}?$skiptoken=a&$skiptoken=b",
    "https://graph.microsoft.com/v1.0{path}",
    "https://graph.microsoft.com/v1.0{path}?$skiptoken=" + "x" * 4097,
    "",
    "not a url",
]


def encode(spec, link, device=DEV):
    return encode_page_token(link, 5, spec, args_for(spec, device), {})


@pytest.mark.parametrize("spec", COLLECTIONS)
@pytest.mark.parametrize("template", BAD_LINKS)
def test_hostile_or_unsupported_next_links_fail_closed_for_every_endpoint(spec, template):
    path = spec.path.format(device_id=DEV)
    with pytest.raises(GraphError) as exc:
        encode(spec, template.replace("{path}", path))
    assert exc.value.code == "bad_response"


@pytest.mark.parametrize("minted", COLLECTIONS)
@pytest.mark.parametrize("linked", COLLECTIONS)
def test_a_next_link_for_another_endpoint_is_refused(minted, linked):
    if minted is linked or minted.path == linked.path:
        assert encode(minted, link_for(linked))
        return
    with pytest.raises(GraphError) as exc:
        encode(minted, link_for(linked))
    assert exc.value.code == "bad_response"


def test_a_next_link_for_another_device_is_refused_and_case_is_not_significant():
    spec = COMPLIANCE_STATES_SPEC
    with pytest.raises(GraphError):
        encode(spec, link_for(spec, OTHER_DEV), DEV)
    assert encode(spec, link_for(spec, DEV.upper()), DEV)  # same resource, other casing
    assert encode(
        spec,
        link_for(spec).replace("deviceCompliancePolicyStates", "devicecompliancepolicystates"),
        DEV,
    )


def test_only_skiptoken_or_skip_are_taken_from_a_link():
    cursor = decode_page_token(
        encode(LIST_DEVICES_SPEC, link_for(LIST_DEVICES_SPEC, query="$skip=40&$top=2&x=y")),
        LIST_DEVICES_SPEC,
    )
    assert cursor.params == {"$skip": "40"}
    # A non-numeric $skip is accepted by the link check but never survives decoding.
    token = encode(LIST_DEVICES_SPEC, link_for(LIST_DEVICES_SPEC, query="$skip=40x"))
    with pytest.raises(GraphError) as exc:
        decode_page_token(token, LIST_DEVICES_SPEC)
    assert exc.value.code == "invalid_page_token"


# -- field minimisation, count, overview, errors -----------------------------------------------
async def test_collection_rows_are_minimised_and_select_matches_the_allowlist():
    leaky = {
        "displayName": "Policy",
        "platformType": "windows10AndLater",
        "state": "compliant",
        "settingCount": 3,
        "version": 2,
        "userPrincipalName": "must-not-leak@example.test",
        "userId": "u",
        "id": "row-id",
        "settingStates": [{"x": 1}],
    }
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"value": [leaky]})

    client = client_with(handler)
    for spec in (COMPLIANCE_STATES_SPEC, CONFIGURATION_STATES_SPEC):
        page = await client.fetch_page(
            "tok",
            checked(client.plan(spec, path_args={"device_id": DEV}, page_size=5, page_token=None)),
            "c",
        )
        assert page.rows == [
            {
                "displayName": "Policy",
                "platformType": "windows10AndLater",
                "state": "compliant",
                "settingCount": 3,
                "version": 2,
            }
        ]
    assert [r.url.params["$select"] for r in seen] == [
        "displayName,platformType,state,settingCount,version"
    ] * 2
    assert seen[0].url.path.endswith(f"/{DEV}/deviceCompliancePolicyStates")
    assert seen[1].url.path.endswith(f"/{DEV}/deviceConfigurationStates")


async def test_count_pages_the_filtered_query_with_id_only_and_never_asks_graph_for_a_total():
    seen = []

    def handler(request):
        seen.append(request)
        # A tenant-wide total that must never be believed (or even requested).
        return httpx.Response(200, json={"@odata.count": 2451, "value": [{"id": "secret-row"}] * 3})

    client = client_with(handler)
    p = client.plan_count(SEARCH_DEVICES_SPEC, filters={"ownership": "company"})
    result = await client.fetch_count("tok", p, "c")
    assert (result.count, result.complete) == (3, True)  # rows returned, not @odata.count
    [req] = seen
    params = req.url.params
    assert (params["$select"], params["$top"]) == ("id", str(MAX_PAGE_SIZE))
    assert params["$filter"] == "managedDeviceOwnerType eq 'company'"
    assert "$count" not in params and "$skiptoken" not in params
    assert "consistencylevel" not in {k.lower() for k in req.headers}


def pages_handler(page_rows, *, total_pages=None, seen=None):
    """A Graph that serves `page_rows` rows per page, with a nextLink while pages remain."""

    def handler(request):
        if seen is not None:
            seen.append(request)
        index = int(request.url.params.get("$skiptoken", 0))
        body = {"value": [{"id": f"r{index}-{i}"} for i in range(page_rows)]}
        if total_pages is None or index + 1 < total_pages:
            body["@odata.nextLink"] = (
                f"https://graph.microsoft.com/v1.0{SEARCH_DEVICES_SPEC.path}?$skiptoken={index + 1}"
            )
        return httpx.Response(200, json=body)

    return handler


async def test_count_sums_every_page_with_the_filter_on_each_and_ends_without_a_next_link():
    seen = []
    client = client_with(pages_handler(100, total_pages=3, seen=seen))
    p = client.plan_count(SEARCH_DEVICES_SPEC, filters={"name_prefix": "PC", "not_synced_days": 30})
    result = await client.fetch_count("tok", p, "c")
    assert (result.count, result.complete) == (300, True)
    assert [r.url.params.get("$skiptoken") for r in seen] == [None, "1", "2"]
    for req in seen:
        assert req.url.params["$filter"] == (
            "startswith(deviceName,'PC') and lastSyncDateTime lt 2026-01-30T12:00:00Z"
        )
        assert (req.url.params["$select"], req.url.params["$top"]) == ("id", "100")
        assert "$count" not in req.url.params
        assert req.method == "GET" and req.headers["authorization"] == "Bearer tok"


async def test_count_stops_at_the_row_cap_and_says_at_least():
    seen = []
    client = client_with(pages_handler(100, seen=seen))  # endless
    result = await client.fetch_count("t", client.plan_count(SEARCH_DEVICES_SPEC, filters={}), "c")
    assert MAX_COUNT_ROWS == 5000 and MAX_COUNT_PAGES == 60
    assert (result.count, result.complete) == (5000, False)
    assert len(seen) == 50


async def test_count_stops_at_the_page_cap_when_pages_are_small():
    seen = []
    client = client_with(pages_handler(3, seen=seen))
    result = await client.fetch_count("t", client.plan_count(SEARCH_DEVICES_SPEC, filters={}), "c")
    assert (result.count, result.complete) == (3 * MAX_COUNT_PAGES, False)
    assert len(seen) == MAX_COUNT_PAGES


async def test_count_is_complete_when_the_cap_is_met_exactly_on_the_last_page():
    client = client_with(pages_handler(100, total_pages=50))
    result = await client.fetch_count("t", client.plan_count(SEARCH_DEVICES_SPEC, filters={}), "c")
    assert (result.count, result.complete) == (5000, True)  # no nextLink: nothing more to count


async def test_count_never_exceeds_the_cap_when_graph_ignores_top():
    # 900-row pages despite $top=100: 4500 then 5400, so the crossing page must not inflate it.
    client = client_with(pages_handler(900, total_pages=10))
    result = await client.fetch_count("t", client.plan_count(SEARCH_DEVICES_SPEC, filters={}), "c")
    assert (result.count, result.complete) == (MAX_COUNT_ROWS, False)


async def test_count_stops_at_the_deadline_and_says_at_least(monkeypatch):
    import intune_mcp.graph as graph_module

    ticks = iter([0.0] + [graph_module.MAX_COUNT_SECONDS + 1] * 100)
    monkeypatch.setattr(graph_module.time, "monotonic", lambda: next(ticks))
    seen = []
    client = client_with(pages_handler(100, seen=seen))  # endless
    result = await client.fetch_count("t", client.plan_count(SEARCH_DEVICES_SPEC, filters={}), "c")
    assert (result.count, result.complete) == (100, False) and len(seen) == 1


async def test_count_walks_are_limited_per_process():
    import asyncio

    import intune_mcp.graph as graph_module

    active = peak = 0
    release = asyncio.Event()

    async def handler(request):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await release.wait()
        active -= 1
        return httpx.Response(200, json={"value": [{"id": "x"}]})

    client = client_with(handler)
    plan = client.plan_count(SEARCH_DEVICES_SPEC, filters={})
    walks = [asyncio.create_task(client.fetch_count("t", plan, "c")) for _ in range(10)]
    await asyncio.sleep(0.05)
    assert peak == graph_module.MAX_CONCURRENT_COUNTS
    release.set()
    assert [r.count for r in await asyncio.gather(*walks)] == [1] * 10


async def test_count_never_returns_rows_or_ids():
    client = client_with(pages_handler(2, total_pages=1))
    result = await client.fetch_count("t", client.plan_count(SEARCH_DEVICES_SPEC, filters={}), "c")
    assert set(vars(result)) == {"count", "complete"} and "r0-0" not in repr(result)


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"value": None},
        {"value": {"id": "x"}},
        {"value": ["not-an-object"]},
        {"@odata.count": 5},  # a count alone is never accepted as the answer
    ],
)
async def test_count_refuses_a_page_without_a_row_list(body):
    client = client_with(lambda r: httpx.Response(200, json=body))
    with pytest.raises(GraphError) as exc:
        await client.fetch_count("t", client.plan_count(SEARCH_DEVICES_SPEC, filters={}), "c")
    assert exc.value.code == "bad_response"


async def test_count_refuses_more_rows_than_the_hard_page_cap():
    rows = [{"id": "x"}] * (MAX_ROWS_PER_PAGE + 1)
    client = client_with(lambda r: httpx.Response(200, json={"value": rows}))
    with pytest.raises(GraphError) as exc:
        await client.fetch_count("t", client.plan_count(SEARCH_DEVICES_SPEC, filters={}), "c")
    assert exc.value.code == "bad_response" and "too many rows" in exc.value.message


@pytest.mark.parametrize(
    "link",
    [
        "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies?$skiptoken=1",
        "https://evil.test/v1.0/deviceManagement/managedDevices?$skiptoken=1",
        "http://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$skiptoken=1",
        "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices",  # no cursor
        "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$skiptoken=",
        {"href": "x"},
        "",
        False,
    ],
)
async def test_count_follows_only_validated_next_links(link):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"value": [{"id": "x"}], "@odata.nextLink": link})

    client = client_with(handler)
    with pytest.raises(GraphError) as exc:
        await client.fetch_count("t", client.plan_count(SEARCH_DEVICES_SPEC, filters={}), "c")
    assert exc.value.code == "bad_response"
    assert len(seen) == 1  # the hostile link was never followed


async def test_a_failure_on_a_later_page_fails_the_whole_count():
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return pages_handler(100, total_pages=5)(request)
        return httpx.Response(429, headers={"Retry-After": "7"})

    client = client_with(handler)
    with pytest.raises(GraphError) as exc:
        await client.fetch_count("t", client.plan_count(SEARCH_DEVICES_SPEC, filters={}), "c")
    assert exc.value.code == "throttled" and exc.value.retry_after == 7


async def test_overview_is_counts_only_with_an_allowlist_and_integer_sanitising():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "id": "x",
                "enrolledDeviceCount": 10,
                "mdmEnrolledCount": 8,
                "dualEnrolledDeviceCount": 2,
                "deviceOperatingSystemSummary": {
                    "windowsCount": 5,
                    "androidCount": "evil",
                    "iosCount": True,
                    "macOSCount": -1,
                    "windowsMobileCount": 0,
                    "unknownCount": 2,
                    "extraCount": 9,
                },
                "deviceExchangeAccessStateSummary": {"allowedDeviceCount": 1},
                "ownerName": "must-not-leak",
            },
        )

    client = client_with(handler)
    out = await client.fetch_object("t", plan_object(DEVICE_OVERVIEW_SPEC, path_args={}), "c")
    assert out == {
        "enrolledDeviceCount": 10,
        "mdmEnrolledCount": 8,
        "dualEnrolledDeviceCount": 2,
        "deviceOperatingSystemSummary": {
            "androidCount": None,
            "iosCount": None,
            "macOSCount": None,
            "windowsMobileCount": 0,
            "windowsCount": 5,
            "unknownCount": 2,
        },
    }
    assert urlsplit(str(seen[0].url)).path == "/v1.0/deviceManagement/managedDeviceOverview"
    assert not parse_qsl(urlsplit(str(seen[0].url)).query)  # no $select assumed on a singleton
    bare = client_with(lambda r: httpx.Response(200, json={"enrolledDeviceCount": "7"}))
    out = await bare.fetch_object("t", plan_object(DEVICE_OVERVIEW_SPEC, path_args={}), "c")
    assert out["enrolledDeviceCount"] is None and out["deviceOperatingSystemSummary"] is None


async def test_graph_400_maps_to_bad_request_without_echoing_the_body():
    def handler(request):
        return httpx.Response(
            400,
            json={
                "error": {"message": "Unsupported filter on userPrincipalName SECRET-GRAPH-BODY"}
            },
        )

    client = client_with(handler)
    p = client.plan(
        SEARCH_DEVICES_SPEC,
        filters={"assigned_user": "who@example.test"},
        page_size=5,
        page_token=None,
    )
    with pytest.raises(GraphError) as exc:
        await client.fetch_page("SECRETTOKEN", p, "c")
    assert exc.value.code == "bad_request"
    for leak in ("SECRET", "userPrincipalName", "who@example.test"):
        assert leak not in exc.value.message
    assert "filter or option may not be supported" in exc.value.message


async def test_only_get_requests_with_the_callers_token_are_issued():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"value": [], "@odata.count": 0})

    client = client_with(handler)
    await client.fetch_page(
        "tok", client.plan(SEARCH_DEVICES_SPEC, page_size=1, page_token=None), "cid"
    )
    await client.fetch_count("tok", client.plan_count(SEARCH_DEVICES_SPEC, filters={}), "cid")
    assert [r.method for r in seen] == ["GET", "GET"]
    assert {r.headers["authorization"] for r in seen} == {"Bearer tok"}
    assert {r.headers["client-request-id"] for r in seen} == {"cid"}


def test_string_filter_pattern_is_fullmatch_not_search():
    f = StringFilter("n", "f", re.compile(r"[a-z]{1,3}"), "h")
    for bad in ("abcd", "ab\n", "\nab", "ab ", "AB"):
        with pytest.raises(GraphError):
            f.resolve(bad, NOW)
    assert f.resolve("ab", NOW) == "ab"


# -- nextLink: type, size and parse failures all become bad_response ---------------------------
def next_link_body(link, rows=0):
    return {"value": [{"id": str(i)} for i in range(rows)], "@odata.nextLink": link}


async def fetch_with_body(spec, body, *, page_size=5):
    client = client_with(lambda r: httpx.Response(200, json=body))
    p = client.plan(spec, path_args=args_for(spec), page_size=page_size, page_token=None)
    return await client.fetch_page("tok", checked(p), "cid")


@pytest.mark.parametrize("spec", COLLECTIONS)
@pytest.mark.parametrize(
    "link",
    [
        {"href": "https://graph.microsoft.com"},  # object
        ["https://graph.microsoft.com"],  # list
        12345,  # number
        0,
        False,
        True,
        1.5,
        "",
        "\x00",  # null byte alone
        "https://graph.microsoft.com/v1.0/x?$skiptoken=a\x00b",
        "https://[::1/v1.0/x?$skiptoken=a",  # malformed IPv6: urlsplit raises ValueError
        "https://[graph.microsoft.com]/v1.0/x?$skiptoken=a",
        "https://graph.microsoft.com/v1.0/x?$skiptoken=a\nb",  # urlsplit would silently drop it
        "https://graph.microsoft.com\t/v1.0/x?$skiptoken=a",
        "https://graph.microsoft.com/v1.0/x?$skiptoken=\u00e9",  # non-ASCII
        "https://graph.microsoft.com/v1.0/x?$skiptoken=" + "a" * MAX_NEXT_LINK_CHARS,  # oversized
        "https://graph.microsoft.com:443/v1.0/x?$skiptoken=a",  # explicit port
        "https://graph.microsoft.com:@graph.microsoft.com/v1.0/x?$skiptoken=a",
        "https://user:pw@graph.microsoft.com/v1.0/x?$skiptoken=a",  # userinfo
        "https://graph.microsoft.com.evil.test/v1.0/x?$skiptoken=a",
        "https://[::1]/v1.0/x?$skiptoken=a",
    ],
)
async def test_malformed_next_link_values_are_a_safe_bad_response(spec, link):
    if isinstance(link, str):
        link = link.replace("/v1.0/x", "/v1.0" + spec.path.format(device_id=DEV))
    with pytest.raises(GraphError) as exc:
        await fetch_with_body(spec, next_link_body(link))
    assert exc.value.code == "bad_response"
    assert "pagination link" in exc.value.message


@pytest.mark.parametrize("spec", COLLECTIONS)
async def test_absent_or_null_next_link_means_last_page(spec):
    absent = await fetch_with_body(spec, {"value": []})
    null = await fetch_with_body(spec, next_link_body(None))
    assert absent.next_page_token is None and null.next_page_token is None


@pytest.mark.parametrize("value", [{}, [], 5, None, 1.0, object()])
def test_encode_page_token_rejects_non_string_links_directly(value):
    with pytest.raises(GraphError) as exc:
        encode_page_token(value, 5, LIST_DEVICES_SPEC, {}, {})  # type: ignore[arg-type]
    assert exc.value.code == "bad_response"


def test_next_link_at_exactly_the_size_limit_is_still_checked_not_just_accepted():
    prefix = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$skiptoken="
    ok = prefix + "a" * 100
    assert decode_page_token(
        encode_page_token(ok, 5, LIST_DEVICES_SPEC, {}, {}), LIST_DEVICES_SPEC
    ).params == {"$skiptoken": "a" * 100}
    too_long = prefix + "a" * (MAX_NEXT_LINK_CHARS - len(prefix) + 1)
    with pytest.raises(GraphError) as exc:
        encode_page_token(too_long, 5, LIST_DEVICES_SPEC, {}, {})
    assert exc.value.code == "bad_response"


# -- response bounds ---------------------------------------------------------------------------
class Unreadable(httpx.AsyncByteStream):
    """A body that must never be read (a declared-oversize response is refused up front)."""

    async def __aiter__(self):
        raise AssertionError("the body of an oversized response was read")
        yield b""  # pragma: no cover


def spaces_json(total_bytes: int) -> bytes:
    body = b'{"value": []}'
    return body + b" " * (total_bytes - len(body))


async def read_one(handler, spec=LIST_DEVICES_SPEC):
    client = client_with(handler)
    p = client.plan(spec, path_args=args_for(spec), page_size=5, page_token=None)
    return await client.fetch_page("tok", checked(p), "cid")


async def test_a_body_at_the_size_limit_is_accepted_and_one_byte_more_is_not():
    page = await read_one(lambda r: httpx.Response(200, content=spaces_json(MAX_RESPONSE_BYTES)))
    assert page.rows == []
    with pytest.raises(GraphError) as exc:
        await read_one(lambda r: httpx.Response(200, content=spaces_json(MAX_RESPONSE_BYTES + 1)))
    assert exc.value.code == "bad_response" and "oversized" in exc.value.message


async def test_declared_content_length_over_the_limit_is_refused_without_reading_the_body():
    def handler(request):
        return httpx.Response(
            200, headers={"Content-Length": str(MAX_RESPONSE_BYTES + 1)}, stream=Unreadable()
        )

    with pytest.raises(GraphError) as exc:
        await read_one(handler)
    assert exc.value.code == "bad_response" and "oversized" in exc.value.message


async def test_a_streamed_body_without_content_length_stops_being_read_at_the_limit():
    chunk, sent = b" " * 65536, []

    async def body():
        yield b'{"value": ['
        for i in range(200):  # ~12.5 MiB if it were all read
            sent.append(i)
            yield chunk

    with pytest.raises(GraphError) as exc:
        await read_one(lambda r: httpx.Response(200, content=body()))
    assert exc.value.code == "bad_response" and "oversized" in exc.value.message
    assert len(sent) < 40  # abandoned shortly after 2 MiB, not read to the end


async def test_an_oversized_error_response_is_not_read_at_all():
    def handler(request):
        return httpx.Response(500, stream=Unreadable())

    with pytest.raises(GraphError) as exc:
        await read_one(handler)
    assert exc.value.code == "upstream_error"


@pytest.mark.parametrize("spec", COLLECTIONS)
async def test_a_page_with_more_rows_than_top_is_returned_in_full(spec):
    """Sub-collections may ignore $top: 30 rows for $top=25 are all returned, none cut."""
    rows = [{"id": str(i), "displayName": f"row {i}"} for i in range(30)]
    client = client_with(lambda r: httpx.Response(200, json={"value": rows}))
    p = client.plan(spec, path_args=args_for(spec), page_size=25, page_token=None)
    assert p.top == 25
    page = await client.fetch_page("t", checked(p), "c")
    assert len(page.rows) == 30
    assert page.next_page_token is None  # `complete` stays driven by nextLink alone


async def test_surplus_rows_do_not_hide_a_next_link():
    spec = LIST_DEVICES_SPEC
    rows = [{"id": str(i)} for i in range(30)]
    body = {"value": rows, "@odata.nextLink": link_for(spec)}
    client = client_with(lambda r: httpx.Response(200, json=body))
    p = client.plan(spec, page_size=25, page_token=None)
    page = await client.fetch_page("t", p, "c")
    assert len(page.rows) == 30 and page.next_page_token is not None
    assert decode_page_token(page.next_page_token, spec).top == 25  # the requested size, not 30


@pytest.mark.parametrize("spec", COLLECTIONS)
async def test_the_hard_row_cap_is_1000_and_one_more_fails_closed(spec):
    assert MAX_ROWS_PER_PAGE == 1000

    def serve(count):
        return client_with(lambda r: httpx.Response(200, json={"value": [{"id": "x"}] * count}))

    p = serve(0).plan(spec, path_args=args_for(spec), page_size=1, page_token=None)
    p = checked(p)
    page = await serve(MAX_ROWS_PER_PAGE).fetch_page("t", p, "c")
    assert len(page.rows) == MAX_ROWS_PER_PAGE
    with pytest.raises(GraphError) as exc:
        await serve(MAX_ROWS_PER_PAGE + 1).fetch_page("t", p, "c")
    assert exc.value.code == "bad_response" and "too many rows" in exc.value.message


async def test_the_page_token_still_fixes_the_requested_top_for_later_pages():
    spec = LIST_DEVICES_SPEC
    token = encode_page_token(link_for(spec), 2, spec, {}, {})
    seen = []

    def handler(request):
        seen.append(request.url.params["$top"])
        return httpx.Response(200, json={"value": [{"id": str(i)} for i in range(3)]})

    client = client_with(handler)
    p = client.plan(spec, page_size=100, page_token=token)
    page = await client.fetch_page("t", p, "c")
    assert seen == ["2"] and len(page.rows) == 3  # the caller's 100 is ignored; surplus returned


async def test_graph_403_message_is_truthful_about_user_or_consented_permissions():
    with pytest.raises(GraphError) as exc:
        await read_one(lambda r: httpx.Response(403, json={"error": {"message": "SECRET-BODY"}}))
    assert exc.value.code == "forbidden"
    assert "this user, or this app's consented permissions" in exc.value.message
    assert "SECRET" not in exc.value.message
