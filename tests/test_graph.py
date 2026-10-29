import base64
import json

import httpx2 as httpx
import pytest

from intune_mcp.graph import (
    DETAIL_FIELDS,
    LIST_FIELDS,
    GraphClient,
    GraphError,
    classify_token_failure,
    decode_page_token,
    encode_page_token,
)

DEVICE_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
NEXT = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$skiptoken=abc123&$top=2"


def client_with(handler) -> GraphClient:
    return GraphClient(client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))


def row(i: int) -> dict:
    return {
        "id": f"id-{i}",
        "deviceName": f"PC-{i}",
        "operatingSystem": "Windows",
        "osVersion": "10",
        "complianceState": "compliant",
        "managedDeviceOwnerType": "company",
        "lastSyncDateTime": "2026-01-01T00:00:00Z",
        # Must never be forwarded:
        "emailAddress": "someone@example.test",
        "imei": "123456789012345",
        "phoneNumber": "555-0100",
        "@odata.id": "x",
    }


async def test_list_minimizes_fields_and_paginates_explicitly():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"value": [row(1), row(2)], "@odata.nextLink": NEXT})

    page = await client_with(handler).list_devices(
        "tok", page_size=2, page_token=None, correlation_id="c1"
    )
    req = seen[0]
    assert req.method == "GET"
    assert req.headers["authorization"] == "Bearer tok"
    assert req.url.params["$top"] == "2"
    assert set(req.url.params["$select"].split(",")) == set(LIST_FIELDS)
    assert [set(d) for d in page.devices] == [set(LIST_FIELDS)] * 2
    assert page.next_page_token and "graph.microsoft.com" not in page.next_page_token
    cursor = decode_page_token(page.next_page_token)
    assert (cursor.params, cursor.top) == ({"$skiptoken": "abc123"}, 2)


async def test_next_page_uses_cursor_and_original_top():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"value": [row(3)]})

    token = encode_page_token(NEXT, 2)
    page = await client_with(handler).list_devices(
        "tok", page_size=100, page_token=token, correlation_id="c"
    )
    assert seen[0].url.params["$skiptoken"] == "abc123"
    assert seen[0].url.params["$top"] == "2"  # token wins over a new page_size
    assert page.next_page_token is None


@pytest.mark.parametrize(
    "link",
    [
        "https://evil.example/v1.0/deviceManagement/managedDevices?$skiptoken=a",
        "http://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$skiptoken=a",
        "https://graph.microsoft.com/v1.0/users?$skiptoken=a",
        "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?foo=bar",
    ],
)
async def test_hostile_or_unsupported_next_link_fails_closed(link):
    def handler(request):
        return httpx.Response(200, json={"value": [row(1)], "@odata.nextLink": link})

    with pytest.raises(GraphError) as exc:
        await client_with(handler).list_devices(
            "tok", page_size=1, page_token=None, correlation_id="c"
        )
    assert exc.value.code == "bad_response"  # never silently reported as a complete inventory


def forge(payload) -> str:
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")


@pytest.mark.parametrize(
    "token",
    [
        "!!!",
        "",
        forge({"k": "skiptoken", "v": "a", "t": 0}),
        forge({"k": "skiptoken", "v": "a", "t": 101}),
        forge({"k": "skiptoken", "v": "a", "t": True}),
        forge({"k": "filter", "v": "a", "t": 5}),
        forge({"k": "skip", "v": "1;drop", "t": 5}),
        forge({"k": "skiptoken", "v": "a", "t": 5, "extra": 1}),
        forge({"k": "skiptoken", "v": "x" * 5000, "t": 5}),
        forge(["list"]),
    ],
)
def test_tampered_page_tokens_rejected(token):
    with pytest.raises(GraphError) as exc:
        decode_page_token(token)
    assert exc.value.code == "invalid_page_token"


async def test_get_device_minimal_fields_and_guid_only():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(
            200, json={**row(1), "serialNumber": "S1", "userPrincipalName": "u@x"}
        )

    device = await client_with(handler).get_device("tok", DEVICE_ID.upper(), "c")
    assert seen[0].url.path == f"/v1.0/deviceManagement/managedDevices/{DEVICE_ID}"
    assert set(device) == set(DETAIL_FIELDS)
    assert "emailAddress" not in device and "imei" not in device

    for bad in ["../users", f"{DEVICE_ID}/wipe", "", "1", f"{DEVICE_ID}?x=1"]:
        with pytest.raises(GraphError) as exc:
            await client_with(handler).get_device("tok", bad, "c")
        assert exc.value.code == "invalid_device_id"
    assert len(seen) == 1  # invalid ids never reach Graph


@pytest.mark.parametrize(
    ("status", "code"),
    [(401, "graph_unauthorized"), (403, "forbidden"), (404, "not_found"), (500, "upstream_error")],
)
async def test_http_errors_map_to_safe_codes(status, code):
    def handler(request):
        return httpx.Response(status, json={"error": {"message": "internal-detail-xyz"}})

    with pytest.raises(GraphError) as exc:
        await client_with(handler).get_device("SECRETTOKEN", DEVICE_ID, "c")
    assert exc.value.code == code
    assert "internal-detail" not in exc.value.message and "SECRETTOKEN" not in exc.value.message


async def test_throttling_surfaces_retry_after_without_hidden_retry():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(429, headers={"Retry-After": "17"})

    with pytest.raises(GraphError) as exc:
        await client_with(handler).list_devices(
            "t", page_size=1, page_token=None, correlation_id="c"
        )
    assert (exc.value.code, exc.value.retry_after, len(calls)) == ("throttled", 17, 1)


async def test_timeout_bad_json_and_transport_errors():
    def timeout(request):
        raise httpx.ReadTimeout("slow", request=request)

    def broken(request):
        raise httpx.ConnectError("down", request=request)

    def not_json(request):
        return httpx.Response(200, content=b"<html>")

    for handler, code in [
        (timeout, "upstream_timeout"),
        (broken, "upstream_error"),
        (not_json, "bad_response"),
    ]:
        with pytest.raises(GraphError) as exc:
            await client_with(handler).get_device("t", DEVICE_ID, "c")
        assert exc.value.code == code


async def test_response_cookies_are_never_retained():
    seen = []

    def handler(request):
        seen.append(request.headers.get("cookie"))
        return httpx.Response(
            200, json=row(1), headers={"Set-Cookie": "sess=1; Domain=graph.microsoft.com"}
        )

    gc = GraphClient(
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        base_url="https://graph.microsoft.com/v1.0",
    )
    await gc.get_device("a", DEVICE_ID, "c")
    await gc.get_device("b", DEVICE_ID, "c")
    assert seen == [None, None]


class _ErrorCodes(Exception):
    """Stand-in for an MSAL-style error carrying structured `error_codes`."""

    def __init__(self, text, error_codes):
        super().__init__(text)
        self.error_codes = error_codes


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("AADSTS65001: x", "graph_consent_required"),
        ("(invalid_grant) AADSTS50105: x", "graph_access_revoked"),
        ("'AADSTS50076'", "graph_interaction_required"),
        # first AADSTS code in the text wins, even when a later one maps elsewhere
        ("AADSTS50105 then AADSTS65001", "graph_access_revoked"),
        ("AADSTS65001 then AADSTS50105", "graph_consent_required"),
        # never match inside a longer digit run, with a 3-digit code, a prefix or no digits
        ("AADSTS0650011", "graph_exchange_failed"),
        ("AADSTS65001123", "graph_exchange_failed"),
        ("AADSTS065001", "graph_exchange_failed"),
        ("AADSTS501", "graph_exchange_failed"),
        ("XAADSTS65001", "graph_exchange_failed"),
        ("AADSTS", "graph_exchange_failed"),
        ("65001 consent", "graph_exchange_failed"),
        ("aadsts65001", "graph_exchange_failed"),
        ("", "graph_exchange_failed"),
    ],
)
def test_classify_matches_only_a_whole_aadsts_code(text, expected):
    assert classify_token_failure(Exception(text)).code == expected


def test_classify_reads_error_codes_and_the_exception_chain():
    assert classify_token_failure(_ErrorCodes("x", [50105])).code == "graph_access_revoked"
    assert classify_token_failure(_ErrorCodes("x", ["70008"])).code == "graph_access_revoked"
    assert classify_token_failure(_ErrorCodes("x", [True, "ab", 65001])).code == (
        "graph_consent_required"
    )
    assert classify_token_failure(_ErrorCodes("x", "50105")).code == "graph_exchange_failed"
    try:
        try:
            raise Exception("inner AADSTS53003")
        except Exception as inner:
            raise Exception("outer, nothing here") from inner
    except Exception as outer:
        assert classify_token_failure(outer).code == "graph_interaction_required"


def test_classify_survives_a_self_referencing_exception_chain():
    exc = Exception("nothing")
    exc.__cause__ = exc
    assert classify_token_failure(exc).code == "graph_exchange_failed"


def test_scan_cutoff_cannot_manufacture_a_listed_code():
    """A longer digit run cut off exactly at the scan limit must not read as the shorter code."""
    from intune_mcp.graph import _MAX_SCAN_CHARS, classify_token_failure

    padding = " " * (_MAX_SCAN_CHARS - len("AADSTS65001"))
    cut = RuntimeError(padding + "AADSTS65001123")
    assert classify_token_failure(cut).code == "graph_exchange_failed"
    exact = RuntimeError(padding + "AADSTS65001")  # genuinely ends the text: still recognised
    assert classify_token_failure(exact).code == "graph_consent_required"


@pytest.mark.parametrize("kind", ["huge", "huge_negative", "too_small", "too_large"])
def test_huge_or_out_of_range_error_codes_are_ignored_without_raising(kind):
    from intune_mcp.graph import classify_token_failure

    # Built inside the test: str() of an int over 4300 digits raises ValueError.
    value = {
        "huge": 10**5000,
        "huge_negative": -(10**5000),
        "too_small": 999,
        "too_large": 10**7,
    }[kind]
    exc = RuntimeError("no code in text")
    exc.error_codes = [value, 50105]
    assert classify_token_failure(exc).code == "graph_access_revoked"
