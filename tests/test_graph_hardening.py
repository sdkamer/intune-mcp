"""Review-round hardening of the generic read layer (all mocked): nextLink forms, cursor casing,
free-text bounds and timestamp sanitising."""

import json

import httpx2 as httpx
import pytest

from intune_mcp.graph import (
    COMPLIANCE_POLICY_ASSIGNMENTS_SPEC,
    COMPLIANCE_POLICY_SPEC,
    COMPLIANCE_POLICY_STATUS_SPEC,
    COMPLIANCE_STATES_SPEC,
    CONFIGURATION_PROFILE_ASSIGNMENTS_SPEC,
    CONFIGURATION_STATES_SPEC,
    DEVICE_SPEC,
    LIST_COMPLIANCE_POLICIES_SPEC,
    LIST_DEVICES_SPEC,
    MAX_DESCRIPTION_CHARS,
    MAX_TEXT_CHARS,
    GraphError,
    _timestamp_or_none,
    decode_page_token,
    encode_page_token,
)

from .test_graph_read import checked, client_with

ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
OTHER = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
PATH_BOUND = [
    (COMPLIANCE_STATES_SPEC, "device_id"),
    (CONFIGURATION_STATES_SPEC, "device_id"),
    (COMPLIANCE_POLICY_ASSIGNMENTS_SPEC, "policy_id"),
    (CONFIGURATION_PROFILE_ASSIGNMENTS_SPEC, "profile_id"),
]
IDS = [f"{spec.key}" for spec, _ in PATH_BOUND]


def split(spec, name):
    """(head, tail) of a one-parameter path: `/a/b/{id}/child` -> (`/a/b`, `/child`)."""
    head, tail = spec.path.split("/{" + name + "}")
    return head, tail


def link(path, query="$skiptoken=abc"):
    return f"https://graph.microsoft.com/v1.0{path}?{query}"


def encode(spec, name, path, query="$skiptoken=abc", guid=ID):
    return encode_page_token(link(path, query), 5, spec, {name: guid}, {})


# -- R2: both path forms, but only for the GUID bound to the call --------------------------------
@pytest.mark.parametrize(("spec", "name"), PATH_BOUND, ids=IDS)
def test_segment_and_key_parenthesis_forms_are_both_accepted(spec, name):
    head, tail = split(spec, name)
    for path in (f"{head}/{ID}{tail}", f"{head}('{ID}'){tail}"):
        cursor = decode_page_token(encode(spec, name, path), spec)
        assert cursor.params == {"$skiptoken": "abc"} and cursor.path_args == {name: ID}


@pytest.mark.parametrize(("spec", "name"), PATH_BOUND, ids=IDS)
def test_case_differences_do_not_matter_in_either_form(spec, name):
    head, tail = split(spec, name)
    for path in (
        f"{head}/{ID.upper()}{tail}",
        f"{head}('{ID.upper()}'){tail}",
        f"{head}('{ID}'){tail}".lower(),
        f"{head}('{ID}'){tail}".upper(),
        f"{head}('{ID}'){tail}".replace("deviceManagement", "DEVICEMANAGEMENT"),
    ):
        assert encode(spec, name, path)


def bad_keyed_paths(head, tail):
    return {
        "other guid": f"{head}('{OTHER}'){tail}",
        "other guid, segment form": f"{head}/{OTHER}{tail}",
        "unquoted": f"{head}({ID}){tail}",
        "double quotes": f'{head}("{ID}"){tail}',
        "encoded quotes": f"{head}(%27{ID}%27){tail}",
        "encoded parentheses": f"{head}%28'{ID}'%29{tail}",
        "encoded open parenthesis only": f"{head}%28'{ID}'){tail}",
        "double encoded": f"{head}(%2527{ID}%2527){tail}",
        "double encoded parentheses": f"{head}%2528'{ID}'%2529{tail}",
        "nested parentheses": f"{head}(('{ID}')){tail}",
        "nested key": f"{head}('{ID}'('{ID}')){tail}",
        "second key": f"{head}('{ID}','{OTHER}'){tail}",
        "spaces": f"{head}( '{ID}' ){tail}",
        "mixed: slash and parentheses": f"{head}/('{ID}'){tail}",
        "mixed: key then slash": f"{head}('{ID}')/{ID}{tail}",
        "extra segment after": f"{head}('{ID}'){tail}/extra",
        "extra segment between": f"{head}('{ID}')/extra{tail}",
        "extra suffix on key": f"{head}('{ID}')x{tail}",
        "no hyphens": f"{head}('{ID.replace('-', '')}'){tail}",
        "braces": f"{head}('{{{ID}}}'){tail}",
        "empty key": f"{head}(''){tail}",
        "no key": f"{head}(){tail}",
        "traversal": f"{head}('{ID}')/../{OTHER}{tail}",
        "doubled quote": f"{head}(''{ID}''){tail}",
        "trailing quote": f"{head}('{ID}''){tail}",
        "dropped child": f"{head}('{ID}')",
    }


@pytest.mark.parametrize(("spec", "name"), PATH_BOUND, ids=IDS)
def test_other_keys_and_malformed_key_forms_are_refused(spec, name):
    head, tail = split(spec, name)
    for label, path in bad_keyed_paths(head, tail).items():
        with pytest.raises(GraphError) as exc:
            encode(spec, name, path)
        assert exc.value.code == "bad_response", label


@pytest.mark.parametrize(("spec", "name"), PATH_BOUND, ids=IDS)
def test_a_key_form_link_for_another_call_is_refused_even_with_a_valid_guid(spec, name):
    head, tail = split(spec, name)
    # Bound to ID, but the link names OTHER in the key form: the token would address another object.
    with pytest.raises(GraphError):
        encode(spec, name, f"{head}('{OTHER}'){tail}", guid=ID)
    # Same link, bound to OTHER: fine.
    assert encode(spec, name, f"{head}('{OTHER}'){tail}", guid=OTHER)


def test_key_parentheses_are_not_accepted_for_endpoints_without_a_path_parameter():
    for spec in (LIST_DEVICES_SPEC, LIST_COMPLIANCE_POLICIES_SPEC):
        head, _, last = spec.path.rpartition("/")
        for path in (f"{head}/{last}('{ID}')", f"{head}('{ID}')/{last}", f"{head}/{last}(%27x%27)"):
            with pytest.raises(GraphError):
                encode_page_token(link(path), 5, spec, {}, {})
        assert encode_page_token(link(spec.path), 5, spec, {}, {})


async def test_a_key_form_next_link_is_followed_end_to_end_with_the_bound_guid():
    spec = COMPLIANCE_POLICY_ASSIGNMENTS_SPEC
    seen = []

    def handler(request):
        seen.append(request)
        nxt = (
            "https://graph.microsoft.com/v1.0/deviceManagement/"
            f"deviceCompliancePolicies('{ID}')/assignments?$skiptoken=p2"
        )
        body = {"value": [{"id": "a"}], "@odata.nextLink": nxt} if len(seen) == 1 else {"value": []}
        return httpx.Response(200, json=body)

    client = client_with(handler)
    plan = client.plan(spec, path_args={"policy_id": ID}, page_size=5, page_token=None)
    page = await client.fetch_page("t", checked(plan), "c")
    assert page.next_page_token
    again = client.plan(
        spec, path_args={"policy_id": ID}, page_size=5, page_token=page.next_page_token
    )
    await client.fetch_page("t", checked(again), "c")
    # The second request is rebuilt by us from the validated parts, in the canonical segment form.
    assert seen[1].url.path == f"/v1.0/deviceManagement/deviceCompliancePolicies/{ID}/assignments"
    assert seen[1].url.params["$skiptoken"] == "p2" and "(" not in str(seen[1].url)


# -- R3: cursor parameter names are case-insensitive ---------------------------------------------
@pytest.mark.parametrize("key", ["$skiptoken", "$skipToken", "$SKIPTOKEN", "$SkipToken"])
def test_skiptoken_is_accepted_in_any_case_and_rendered_canonically(key):
    spec = LIST_DEVICES_SPEC
    cursor = decode_page_token(
        encode_page_token(link(spec.path, f"{key}=Ab%2BC"), 5, spec, {}, {}), spec
    )
    assert cursor.params == {"$skiptoken": "Ab+C"}  # canonical name; the value keeps its case


@pytest.mark.parametrize("key", ["$skip", "$SKIP", "$Skip"])
def test_skip_is_accepted_in_any_case(key):
    spec = LIST_DEVICES_SPEC
    cursor = decode_page_token(
        encode_page_token(link(spec.path, f"{key}=40&$top=2"), 5, spec, {}, {}), spec
    )
    assert cursor.params == {"$skip": "40"}


@pytest.mark.parametrize(
    "query",
    [
        "$skiptoken=a&$skipToken=b",
        "$skipToken=a&$SKIPTOKEN=b",
        "$skiptoken=a&$skiptoken=b",
        "$skip=1&$SKIP=1",
        "$skiptoken=a&$skip=1",  # two different cursor parameters
        "$SkipToken=a&$Skip=1",
        "$skiptoken=",
        "$SKIPTOKEN=",
        "$skiptokens=a",
        "skiptoken=a",  # no dollar sign
        "$top=5",
    ],
)
def test_ambiguous_or_missing_cursors_are_refused(query):
    spec = LIST_DEVICES_SPEC
    with pytest.raises(GraphError) as exc:
        encode_page_token(link(spec.path, query), 5, spec, {}, {})
    assert exc.value.code == "bad_response"


async def test_the_next_request_always_uses_the_canonical_lowercase_parameter():
    spec = LIST_DEVICES_SPEC
    seen = []

    def handler(request):
        seen.append(request)
        if len(seen) == 1:
            nxt = f"https://graph.microsoft.com/v1.0{spec.path}?$SkipToken=Next%2F1"
            return httpx.Response(200, json={"value": [], "@odata.nextLink": nxt})
        return httpx.Response(200, json={"value": []})

    client = client_with(handler)
    page = await client.fetch_page("t", client.plan(spec, page_size=5, page_token=None), "c")
    await client.fetch_page(
        "t", client.plan(spec, page_size=5, page_token=page.next_page_token), "c"
    )
    assert dict(seen[1].url.params)["$skiptoken"] == "Next/1"
    assert not any(k.lower() == "$skiptoken" and k != "$skiptoken" for k in seen[1].url.params)


# -- R5: timestamps --------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-02-27T00:00:00Z", "2026-02-27T00:00:00Z"),  # already valid: byte-identical
        ("2026-02-27T10:11:12.5Z", "2026-02-27T10:11:12.5Z"),
        ("2026-02-27T10:11:12.123456Z", "2026-02-27T10:11:12.123456Z"),
        ("2016-12-31T23:58:21.6459442Z", "2016-12-31T23:58:21.6459442Z"),  # 7 digits kept
        ("2016-12-31T23:58:21.6459442-08:00", "2017-01-01T07:58:21.6459442Z"),  # live Graph form
        ("2026-03-01T10:00:00+05:30", "2026-03-01T04:30:00Z"),
        ("2026-03-01T10:00:00.250+00:00", "2026-03-01T10:00:00.250Z"),
        ("2026-03-01T10:00:00", "2026-03-01T10:00:00Z"),  # no zone: read as UTC (documented)
        ("2026-03-01T10:00:00.1234567", "2026-03-01T10:00:00.1234567Z"),
        ("2024-02-29T12:00:00Z", "2024-02-29T12:00:00Z"),  # leap day
        ("2026-03-01T23:30:00-01:00", "2026-03-02T00:30:00Z"),  # offset crosses midnight
    ],
)
def test_valid_timestamps_are_normalised_to_utc_with_a_trailing_z(value, expected):
    assert _timestamp_or_none(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "2026-99-99T99:99:99Z",  # the impossible date the old pattern accepted
        "2026-13-01T00:00:00Z",
        "2026-00-10T00:00:00Z",
        "2026-02-30T00:00:00Z",
        "2025-02-29T00:00:00Z",  # not a leap year
        "2026-03-01T24:00:00Z",
        "2026-03-01T00:60:00Z",
        "2026-03-01T00:00:60Z",
        "0000-01-01T00:00:00Z",
        "0001-01-01T00:00:00+01:00",  # shifts to year 0: overflow
        "9999-12-31T23:59:59-01:00",  # shifts past year 9999: overflow
        "2026-03-01T10:00:00+24:00",
        "2026-03-01T10:00:00+05:60",
        "2026-03-01T10:00:00+0530",  # basic offset form
        "2026-03-01T10:00:00 +05:30",
        "2026-03-01T10:00:00.Z",
        "2026-03-01T10:00:00.1234567890Z",  # ten fractional digits
        "2026-03-01t10:00:00z",
        "2026-03-01 10:00:00Z",
        "2026-03-01",
        "20260301T100000Z",
        "2026-03-01T10:00:00Z\n",
        "\n2026-03-01T10:00:00Z",
        "2026-03-01T10:00:00Zjunk",
        "２０２６-03-01T10:00:00Z",  # full-width digits
        "2026-03-01T10:00:00Z" + " " * 100,
        "",
        "yesterday",
        None,
        0,
        1_772_000_000,
        True,
        1.5,
        ["2026-03-01T10:00:00Z"],
        {"a": "2026-03-01T10:00:00Z"},
    ],
)
def test_impossible_or_oddly_shaped_timestamps_are_null(value):
    assert _timestamp_or_none(value) is None


async def test_timestamp_fields_are_sanitised_in_every_kind_of_result():
    bad = "2026-99-99T99:99:99Z"
    device = {
        "id": ID,
        "lastSyncDateTime": "2016-12-31T23:58:21.6459442-08:00",
        "enrolledDateTime": bad,
        "deviceName": "PC",
    }
    policy = {
        "id": ID,
        "createdDateTime": "2026-03-01T10:00:00+01:00",
        "lastModifiedDateTime": bad,
        "@odata.type": "#microsoft.graph.windows10CompliancePolicy",
    }
    status = {"pendingCount": 1, "lastUpdateDateTime": "2026-03-01T10:00:00.5-02:00"}

    def handler(request):
        path = request.url.path
        if path.endswith("/deviceStatusOverview"):
            return httpx.Response(200, json=status)
        if path.endswith("/managedDevices"):
            return httpx.Response(200, json={"value": [device]})
        if path.endswith("/deviceCompliancePolicies"):
            return httpx.Response(200, json={"value": [policy]})
        if "/managedDevices/" in path:
            return httpx.Response(200, json=device)
        return httpx.Response(200, json=policy)

    client = client_with(handler)
    page = await client.fetch_page(
        "t", client.plan(LIST_DEVICES_SPEC, page_size=5, page_token=None), "c"
    )
    assert page.rows[0]["lastSyncDateTime"] == "2017-01-01T07:58:21.6459442Z"
    one = await client.fetch_object("t", client_plan_object(DEVICE_SPEC, {"device_id": ID}), "c")
    assert one["enrolledDateTime"] is None and one["lastSyncDateTime"].endswith("Z")
    plist = await client.fetch_page(
        "t", client.plan(LIST_COMPLIANCE_POLICIES_SPEC, page_size=5, page_token=None), "c"
    )
    assert plist.rows[0]["createdDateTime"] == "2026-03-01T09:00:00Z"
    assert plist.rows[0]["lastModifiedDateTime"] is None
    got = await client.fetch_object(
        "t", client_plan_object(COMPLIANCE_POLICY_SPEC, {"policy_id": ID}), "c"
    )
    assert got["createdDateTime"] == "2026-03-01T09:00:00Z" and got["lastModifiedDateTime"] is None
    overview = await client.fetch_object(
        "t", checked(client_plan_object(COMPLIANCE_POLICY_STATUS_SPEC, {"policy_id": ID})), "c"
    )
    assert overview["lastUpdateDateTime"] == "2026-03-01T12:00:00.5Z"


def client_plan_object(spec, args):
    from intune_mcp.graph import plan_object

    return plan_object(spec, path_args=args)


# -- R4: free text is bounded ------------------------------------------------------------------
async def rows_for(spec, row, **plan_args):
    # ASCII-escaped JSON on the wire (as Graph may send it), so even a lone surrogate arrives.
    content = json.dumps({"value": [row]}, ensure_ascii=True).encode()
    client = client_with(lambda r: httpx.Response(200, content=content))
    plan = client.plan(spec, page_size=5, page_token=None, **plan_args)
    return (await client.fetch_page("t", plan, "c")).rows[0]


async def policy_row(**fields):
    return await rows_for(LIST_COMPLIANCE_POLICIES_SPEC, {"id": ID, **fields})


async def test_hundred_thousand_character_text_is_cut_with_one_trailing_marker():
    row = await policy_row(displayName="n" * 100_000, description="d" * 100_000)
    assert row["displayName"] == "n" * (MAX_TEXT_CHARS - 1) + "…" and len(row["displayName"]) == 256
    assert row["description"] == "d" * (MAX_DESCRIPTION_CHARS - 1) + "…"
    assert len(row["description"]) == 500
    assert len(json.dumps(row)) < 1000


@pytest.mark.parametrize(
    ("field", "limit"), [("displayName", 256), ("description", 500), ("version", 256)]
)
async def test_the_limit_is_exact_at_the_boundary(field, limit):
    at = await policy_row(**{field: "x" * limit})
    over = await policy_row(**{field: "x" * (limit + 1)})
    under = await policy_row(**{field: "x" * (limit - 1)})
    assert at[field] == "x" * limit and under[field] == "x" * (limit - 1)  # untouched
    assert over[field] == "x" * (limit - 1) + "…" and len(over[field]) == limit


async def test_short_text_and_text_that_already_ends_with_the_marker_are_not_changed():
    row = await policy_row(displayName="Policy…", description="")
    assert row["displayName"] == "Policy…" and row["description"] == ""
    long_with_marker = await policy_row(displayName="a" * 300 + "…")
    assert long_with_marker["displayName"].count("…") == 1


async def test_unicode_is_cut_on_characters_and_stays_encodable():
    for char in ("é", "日", "😀", "👨‍👩‍👧"):  # 2- and 3-byte, astral, ZWJ sequence
        row = await policy_row(displayName=char * 400, description=char * 700)
        assert len(row["displayName"]) == 256 and len(row["description"]) == 500
        row["displayName"].encode("utf-8")
        row["description"].encode("utf-8")
        assert row["displayName"].endswith("…")
    exact = "😀" * 256
    assert (await policy_row(displayName=exact))["displayName"] == exact


async def test_a_cut_never_leaves_half_a_surrogate_pair():
    # A JSON escape can decode to a lone surrogate (not encodable); it is replaced, wherever it is.
    at_cut = "a" * 254 + "\ud83d" + "x" * 100
    assert (await policy_row(displayName=at_cut))["displayName"] == "a" * 254 + "\ufffd…"
    for lone in ("\ud83d", "\ude00"):
        short = (await policy_row(displayName=f"a{lone}b"))["displayName"]
        assert short == "a\ufffdb"
        short.encode("utf-8")
    # A well-formed pair is one code point: kept whole or cut off whole, never split.
    at_edge = (await policy_row(displayName="a" * 254 + "😀" + "x" * 100))["displayName"]
    assert at_edge == "a" * 254 + "😀…" and len(at_edge) == 256
    over_edge = (await policy_row(displayName="a" * 255 + "😀" + "x" * 100))["displayName"]
    assert over_edge == "a" * 255 + "…"
    for row in (at_edge, over_edge):
        row.encode("utf-8")


async def test_only_strings_are_bounded_other_scalars_and_types_are_unchanged():
    row = await policy_row(version=10**30, displayName=12345, description=True)
    assert row["version"] == 10**30 and row["displayName"] == 12345 and row["description"] is True
    nested = await policy_row(displayName={"a": "x" * 1000}, description=["x" * 1000])
    assert nested["displayName"] is None and nested["description"] is None


async def test_device_text_is_bounded_in_lists_and_in_get_device():
    from intune_mcp.graph import plan_object

    long = "H" * 100_000
    body = {"id": ID, "deviceName": long, "userPrincipalName": "u" * 5000, "model": long}
    client = client_with(lambda r: httpx.Response(200, json={"value": [body]}))
    page = await client.fetch_page(
        "t", client.plan(LIST_DEVICES_SPEC, page_size=5, page_token=None), "c"
    )
    assert page.rows[0]["deviceName"] == "H" * 255 + "…"
    client = client_with(lambda r: httpx.Response(200, json=body))
    one = await client.fetch_object("t", plan_object(DEVICE_SPEC, path_args={"device_id": ID}), "c")
    assert len(one["deviceName"]) == len(one["model"]) == 256
    assert len(one["userPrincipalName"]) == 256 and one["userPrincipalName"].endswith("…")
