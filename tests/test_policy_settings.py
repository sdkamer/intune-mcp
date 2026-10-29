"""G9 typed settings allowlists. All Microsoft responses are mocked, not live evidence."""

import json
import logging

import httpx2
import pytest

from intune_mcp.config import CONFIGURATION_SCOPE
from intune_mcp.graph import (
    COMPLIANCE_POLICY_SETTINGS_SPEC,
    COMPLIANCE_SETTINGS,
    CONFIGURATION_PROFILE_SETTINGS_SPEC,
    MAX_RESPONSE_BYTES,
    POLICY_FIELDS,
    PROFILE_SETTINGS,
    _pick_object,
)

from .conftest import OID_A, make_settings
from .harness import Harness
from .test_configuration_tools import BAD_IDS, COMPLIANCE, KINDS, PROFILE, put, row
from .test_device_tools import audit_lines, bearer, error_text, payload

# Independent expected outputs: adding ANY field/type to production requires a deliberate review
# here too. Do not generate expectations from the production allowlists (denylist regression).
CASES = [
    (
        COMPLIANCE,
        "windows10CompliancePolicy",
        dict(
            passwordRequired=True,
            passwordMinimumLength=12,
            passwordRequiredType="numeric",
            bitLockerEnabled=False,
            secureBootEnabled=True,
            codeIntegrityEnabled=True,
            storageRequireEncryption=True,
        ),
    ),
    (
        COMPLIANCE,
        "iosCompliancePolicy",
        dict(
            passcodeRequired=True,
            passcodeMinimumLength=6,
            passcodeRequiredType="numeric",
            securityBlockJailbrokenDevices=True,
            deviceThreatProtectionEnabled=False,
        ),
    ),
    (
        COMPLIANCE,
        "androidCompliancePolicy",
        dict(
            passwordRequired=True,
            passwordMinimumLength=8,
            passwordRequiredType="numericComplex",
            securityBlockJailbrokenDevices=True,
            storageRequireEncryption=True,
            securityPreventInstallAppsFromUnknownSources=False,
        ),
    ),
    (
        COMPLIANCE,
        "androidWorkProfileCompliancePolicy",
        dict(
            passwordRequired=True,
            passwordMinimumLength=8,
            passwordRequiredType="numericComplex",
            securityBlockJailbrokenDevices=True,
            storageRequireEncryption=True,
            securityPreventInstallAppsFromUnknownSources=False,
        ),
    ),
    (
        COMPLIANCE,
        "macOSCompliancePolicy",
        dict(
            passwordRequired=True,
            passwordMinimumLength=12,
            passwordRequiredType="alphanumeric",
            firewallEnabled=False,
            storageRequireEncryption=True,
        ),
    ),
    (
        PROFILE,
        "windows10GeneralConfiguration",
        dict(
            cameraBlocked=True,
            screenCaptureBlocked=False,
            defenderRequireRealTimeMonitoring=True,
            passwordRequired=True,
            passwordMinimumLength=12,
            passwordRequiredType="alphanumeric",
        ),
    ),
    (
        PROFILE,
        "macOSGeneralDeviceConfiguration",
        dict(
            passwordRequired=True,
            passwordBlockSimple=False,
            passwordMinimumLength=12,
            passwordRequiredType="alphanumeric",
        ),
    ),
    (
        PROFILE,
        "iosGeneralDeviceConfiguration",
        dict(
            cameraBlocked=True,
            screenCaptureBlocked=False,
            passcodeRequired=True,
            passcodeMinimumLength=6,
            passcodeRequiredType="numeric",
        ),
    ),
    (
        PROFILE,
        "androidGeneralDeviceConfiguration",
        dict(
            cameraBlocked=True,
            screenCaptureBlocked=False,
            passwordRequired=True,
            passwordMinimumLength=8,
            passwordRequiredType="numericComplex",
            storageRequireDeviceEncryption=True,
        ),
    ),
    (
        PROFILE,
        "windowsUpdateForBusinessConfiguration",
        dict(
            microsoftUpdateServiceAllowed=True,
            driversExcluded=False,
            qualityUpdatesDeferralPeriodInDays=0,
            featureUpdatesDeferralPeriodInDays=30,
            qualityUpdatesPaused=False,
            featureUpdatesPaused=True,
        ),
    ),
]
SECRET = "SECRET-G9-canary"
SECRETS = dict.fromkeys(
    (
        "preSharedKey",
        "password",
        "passcode",
        "certificate",
        "trustedRootCertificate",
        "scepCertificate",
        "pkcsCertificate",
        "vpnPassword",
        "wifiSsid",
        "proxyServer",
        "vpnServer",
        "serverUrl",
        "script",
        "customXml",
        "emailAddress",
        "exchangeServer",
        "wallpaper",
        "userId",
        "tenantId",
        "notes",
        "unknownFutureSecret",
    ),
    SECRET,
)
SECRETS.update(
    omaSettings=[{"omaUri": SECRET, "value": SECRET}],
    kioskModeApps=[{"appId": SECRET}],
    unknownBoolean=True,
    unknownNumber=10,
    unknownEnum="numeric",
    # Even a valid enum in a secret-bearing property must not pass.
    sharedSecret="numeric",
)


def spec_for(kind):
    return (
        COMPLIANCE_POLICY_SETTINGS_SPEC
        if kind == COMPLIANCE
        else CONFIGURATION_PROFILE_SETTINGS_SPEC
    )


def tool_for(kind):
    return kind.get_tool + "_settings"


@pytest.fixture
async def h():
    # No devices group: settings need only the existing Configuration scope, one exchange.
    async with Harness(make_settings(enabled_tool_groups="configuration")).running() as harness:
        yield harness


@pytest.mark.parametrize(("kind", "type_name", "expected"), CASES, ids=[c[1] for c in CASES])
async def test_settings_allowlist_exact_output_endpoint_scope_and_audit(
    h, caplog, kind, type_name, expected
):
    obj = row(kind, 1, type_name=type_name, **SECRETS, **expected)
    put(h, OID_A, kind, [obj])
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.INFO):
        response = await h.call_tool(token, tool_for(kind), {kind.id_arg: obj["id"].upper()})
    out = payload(response)
    assert set(out) == {*POLICY_FIELDS, kind.type_key, "settings_available", "settings"}
    assert out[kind.type_key] == type_name and out["settings_available"] is True
    assert out["settings"] == expected
    assert SECRET not in json.dumps(response)  # entire MCP response, not just settings
    assert len(json.dumps(out)) < 3000
    [req] = h.graph_requests
    assert req.method == "GET"
    assert req.url.path == f"/v1.0/deviceManagement/{kind.coll}/{obj['id']}"
    assert dict(req.url.params) == {}  # full object, no $select/$expand or beta
    assert [s for _, s in h.token_requests] == [(CONFIGURATION_SCOPE,)]
    [line] = audit_lines(caplog)
    assert f"tool={tool_for(kind)}" in line and f"target={obj['id']}" in line
    assert "outcome=ok" in line
    logs = "\n".join(r.getMessage() for r in caplog.records)
    assert SECRET not in logs and obj["displayName"] not in logs and token not in logs


@pytest.mark.parametrize("kind", KINDS, ids=["policy", "profile"])
async def test_settings_hostile_listed_values_never_reach_the_mcp_response(h, kind):
    _, type_name, expected = next(c for c in CASES if c[0] == kind)
    token = await bearer(h, OID_A)
    for bad in BAD_VALUES:
        obj = row(kind, 1, type_name=type_name, **SECRETS, **dict.fromkeys(expected, bad))
        put(h, OID_A, kind, [obj])
        response = await h.call_tool(token, tool_for(kind), {kind.id_arg: obj["id"]})
        assert payload(response)["settings"] == {}
        assert SECRET not in json.dumps(response)


def test_settings_supported_types_are_exactly_the_reviewed_set():
    assert set(COMPLIANCE_SETTINGS) == {t for k, t, _ in CASES if k == COMPLIANCE}
    assert set(PROFILE_SETTINGS) == {t for k, t, _ in CASES if k == PROFILE}


BAD_VALUES = [
    None,
    SECRET,
    "x" * 10000,
    "https://example.test/" + SECRET,
    "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJTRUNSRVQifQ.signature",
    "numeric\n",
    "NUMERIC",
    "unreviewedEnum",
    {"value": SECRET},
    [SECRET],
    [True, {"value": SECRET}],
    [[1]],
    -1,
    2**63,
    1.5,
]


@pytest.mark.parametrize(("kind", "type_name", "expected"), CASES, ids=[c[1] for c in CASES])
def test_settings_drop_hostile_values_in_every_listed_property(kind, type_name, expected):
    spec = spec_for(kind)
    for bad in BAD_VALUES:
        obj = {
            "@odata.type": "#microsoft.graph." + type_name,
            **dict.fromkeys(expected, bad),
            **SECRETS,
        }
        out = _pick_object(spec, obj)
        assert out["settings_available"] is True and out["settings"] == {}
        assert SECRET not in json.dumps(out)
    # Booleans are not numbers; numbers and enum strings are not booleans. No coercion.
    for name, valid in expected.items():
        wrong = (
            [True, False, "12"]
            if type(valid) is int
            else (
                [0, 1, "true", "numeric"] if type(valid) is bool else [True, 12, "numericComplex"]
            )
        )
        for value in wrong:
            if value == valid and type(value) is type(valid):
                continue
            # numericComplex is valid ONLY for Android password enums.
            if (
                isinstance(valid, str)
                and "android" in type_name.lower()
                and value == "numericComplex"
            ):
                continue
            out = _pick_object(spec, {"@odata.type": "#microsoft.graph." + type_name, name: value})
            assert out["settings"] == {}, (type_name, name, value)


EXCLUDED = [
    "futureConfiguration",
    "windows10WifiConfiguration",
    "iosWiFiConfiguration",
    "androidWifiConfiguration",
    "windows10VpnConfiguration",
    "iosVpnConfiguration",
    "macOSVpnConfiguration",
    "windows81SCEPCertificateProfile",
    "iosPkcsCertificateProfile",
    "windows81TrustedRootCertificate",
    "windows10CustomConfiguration",
    "macOSCustomConfiguration",
    "iosCustomConfiguration",
    "androidCustomConfiguration",
    "iosEasEmailProfileConfiguration",
    "androidEasEmailProfileConfiguration",
    "windowsKioskConfiguration",
    "windows10KioskConfiguration",
    "androidKioskConfiguration",
    # Exact matching: no missing prefix, case folding, type spoofing or inherited fallback.
    "Windows10GeneralConfiguration",
    "windows10GeneralConfiguration.child",
]


@pytest.mark.parametrize("type_name", EXCLUDED)
async def test_settings_excluded_and_unknown_profile_types_have_no_settings(h, type_name):
    obj = row(PROFILE, 1, type_name=type_name, **SECRETS, cameraBlocked=True, passwordRequired=True)
    put(h, OID_A, PROFILE, [obj])
    token = await bearer(h, OID_A)
    response = await h.call_tool(token, tool_for(PROFILE), {PROFILE.id_arg: obj["id"]})
    out = payload(response)
    assert out["profile_type"] == type_name
    assert out["settings_available"] is False and out["settings"] == {}
    assert SECRET not in json.dumps(response)


@pytest.mark.parametrize("kind", KINDS, ids=["policy", "profile"])
async def test_settings_unknown_or_malformed_type_missing_values_and_bounds(h, kind):
    token = await bearer(h, OID_A)
    for raw in [
        None,
        {},
        "#microsoft.graph.futurePolicy",
        kind.base_type,
        "#microsoft.graph." + SECRET + "\n",
        "#microsoft.graph." + "x" * 101,
    ]:
        obj = row(kind, 1, **{"@odata.type": raw}, **SECRETS)
        put(h, OID_A, kind, [obj])
        response = await h.call_tool(token, tool_for(kind), {kind.id_arg: obj["id"]})
        out = payload(response)
        assert out["settings_available"] is False and out["settings"] == {}
        assert SECRET not in json.dumps(response)
    # Missing settings stay omitted; bounded free text keeps the existing untrusted-data rule.
    obj = row(kind, 1, displayName="N" * 10000, description="D" * 10000)
    obj = {k: v for k, v in obj.items() if k in {*POLICY_FIELDS, "@odata.type"}}
    put(h, OID_A, kind, [obj])
    out = payload(await h.call_tool(token, tool_for(kind), {kind.id_arg: obj["id"]}))
    assert out["settings_available"] is True and out["settings"] == {}
    assert len(out["displayName"]) == 256 and len(out["description"]) == 500


@pytest.mark.parametrize("kind", KINDS, ids=["policy", "profile"])
async def test_settings_guid_validation_before_exchange_and_safe_audit(h, kind, caplog):
    token = await bearer(h, OID_A)
    with caplog.at_level(logging.INFO):
        for bad in BAD_IDS:
            text = error_text(await h.call_tool(token, tool_for(kind), {kind.id_arg: bad}))
            assert text.startswith(f"invalid_{kind.id_arg}: {kind.id_arg} must be a GUID")
    assert h.token_requests == [] and h.graph_requests == []
    assert all("target=invalid " in line + " " for line in audit_lines(caplog))
    assert "private.person" not in caplog.text and "SECRETLONG" not in caplog.text


@pytest.mark.parametrize("kind", KINDS, ids=["policy", "profile"])
async def test_settings_oversized_graph_body_fails_closed(h, kind):
    h.graph._client = httpx2.AsyncClient(  # noqa: SLF001
        transport=httpx2.MockTransport(
            lambda r: httpx2.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))
        )
    )
    token = await bearer(h, OID_A)
    obj = row(kind, 1)
    assert error_text(
        await h.call_tool(token, tool_for(kind), {kind.id_arg: obj["id"]})
    ).startswith("bad_response: ")
