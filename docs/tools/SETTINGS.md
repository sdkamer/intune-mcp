# Settings detail tools

`get_compliance_policy_settings(policy_id)` and `get_configuration_profile_settings(profile_id)`
extend the `configuration` group. Delegated `DeviceManagementConfiguration.Read.All` only.
Classic profiles only: no beta, Settings Catalog, `configurationPolicies` or `intents`.

## Documentation evidence (fetched 2026-10-27)

Microsoft Learn v1.0 confirms both GETs and delegated Configuration read:
[compliance policy](https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-devicecompliancepolicy-get?view=graph-rest-1.0),
[configuration profile](https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-deviceconfiguration-get?view=graph-rest-1.0).
Requests are `/v1.0/deviceManagement/deviceCompliancePolicies/{id}` and
`/v1.0/deviceManagement/deviceConfigurations/{id}`, without `$select`/`$expand`. The full object
is fetched (2 MiB decoded-response cap), then filtered in-process; never logged or returned raw.
The GET itself checks visibility, just like the existing metadata tools: hidden object 404 →
`not_found`, 403 → `forbidden`; no child endpoint, separate parent GET or second exchange.

## Exact supported settings allowlists

Each type links to its fetched v1.0 resource property table. Matching requires the exact
`@odata.type` value `#microsoft.graph.<type>`; no inheritance, prefix or case-insensitive fallback.
Only the properties below can appear inside `settings` (56 total). Unlisted properties, including
secret-bearing extras on a listed type, are dropped. This is **not a complete/effective policy**.

| Type | Exact settings properties |
| - | - |
| [windows10CompliancePolicy](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-windows10compliancepolicy?view=graph-rest-1.0) | `passwordRequired`, `passwordMinimumLength`, `passwordRequiredType`, `bitLockerEnabled`, `secureBootEnabled`, `codeIntegrityEnabled`, `storageRequireEncryption` |
| [iosCompliancePolicy](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-ioscompliancepolicy?view=graph-rest-1.0) | `passcodeRequired`, `passcodeMinimumLength`, `passcodeRequiredType`, `securityBlockJailbrokenDevices`, `deviceThreatProtectionEnabled` |
| [androidCompliancePolicy](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-androidcompliancepolicy?view=graph-rest-1.0) | `passwordRequired`, `passwordMinimumLength`, `passwordRequiredType`, `securityBlockJailbrokenDevices`, `storageRequireEncryption`, `securityPreventInstallAppsFromUnknownSources` |
| [androidWorkProfileCompliancePolicy](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-androidworkprofilecompliancepolicy?view=graph-rest-1.0) | `passwordRequired`, `passwordMinimumLength`, `passwordRequiredType`, `securityBlockJailbrokenDevices`, `storageRequireEncryption`, `securityPreventInstallAppsFromUnknownSources` |
| [macOSCompliancePolicy](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-macoscompliancepolicy?view=graph-rest-1.0) | `passwordRequired`, `passwordMinimumLength`, `passwordRequiredType`, `firewallEnabled`, `storageRequireEncryption` |
| [windows10GeneralConfiguration](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-windows10generalconfiguration?view=graph-rest-1.0) | `cameraBlocked`, `screenCaptureBlocked`, `defenderRequireRealTimeMonitoring`, `passwordRequired`, `passwordMinimumLength`, `passwordRequiredType` |
| [macOSGeneralDeviceConfiguration](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-macosgeneraldeviceconfiguration?view=graph-rest-1.0) | `passwordRequired`, `passwordBlockSimple`, `passwordMinimumLength`, `passwordRequiredType` |
| [iosGeneralDeviceConfiguration](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-iosgeneraldeviceconfiguration?view=graph-rest-1.0) | `cameraBlocked`, `screenCaptureBlocked`, `passcodeRequired`, `passcodeMinimumLength`, `passcodeRequiredType` |
| [androidGeneralDeviceConfiguration](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-androidgeneraldeviceconfiguration?view=graph-rest-1.0) | `cameraBlocked`, `screenCaptureBlocked`, `passwordRequired`, `passwordMinimumLength`, `passwordRequiredType`, `storageRequireDeviceEncryption` |
| [windowsUpdateForBusinessConfiguration](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-windowsupdateforbusinessconfiguration?view=graph-rest-1.0) | `microsoftUpdateServiceAllowed`, `driversExcluded`, `qualityUpdatesDeferralPeriodInDays`, `featureUpdatesDeferralPeriodInDays`, `qualityUpdatesPaused`, `featureUpdatesPaused` |

`*MinimumLength` and `*DeferralPeriodInDays` accept only exact integers 0–2147483647 (not booleans;
this is a safety bound, not validation of each platform's effective range). `*RequiredType` is a
closed enum: `deviceDefault`, `alphanumeric`, `numeric`; Android instead allows `deviceDefault`,
`alphabetic`, `alphanumeric`, `alphanumericWithSymbols`, `lowSecurityBiometric`, `numeric`,
`numericComplex`, `any`. Strings must also match `[A-Za-z][A-Za-z0-9]{0,39}`. All other listed
properties accept only booleans. Missing, null, wrong-type, unknown-enum, URL, token-like and long
text values are **omitted**, not coerced or truncated into settings. No list/object-valued settings
are supported in this initial set.

Output adds `settings_available` and `settings` to existing base metadata: `id`, `displayName`,
`description`, `createdDateTime`, `lastModifiedDateTime`, `version`, `policy_type`/`profile_type`.
Metadata follows existing bounds (name 256, description 500 characters; normalized dates or null).
All text is untrusted data, never instructions; admin-written metadata can itself contain sensitive
text. `settings_available=true` means a supported type, even if all its values were omitted.
Unknown/unlisted types return sanitized type name, base metadata, `settings_available=false`,
`settings={}`; malformed types become `unknown`. No claim that an empty result is an empty policy.

## Exclusions and operational gate

Wi-Fi, VPN, certificate (SCEP/PKCS/trusted root), email/Exchange, custom (including Windows OMA-URI
and macOS custom), and kiosk profile **types are not supported at all**. For every type, no
pre-shared keys, password/passcode values, certificate blobs, VPN/Wi-Fi/proxy credentials or
server details, URLs, scripts, custom OMA values, kiosk app lists, email/account settings,
wallpaper/images, tenant/user identifiers or notes settings are returned. Password/passcode
**requirements** above are flags/lengths/enums, never actual credentials. No denylist is used.

GUIDs are validated before any token request; one Configuration scope exchange per call, configuration-only
works; tools absent unless the group is enabled. Audit uses existing `audit_value` with canonical
GUIDs, no names, bodies or setting values. Keep third-party DEBUG logging disabled.

Check property names and values against the Intune portal and review a real policy's output before
relying on it. Live results: [Verification status](../VERIFICATION.md).
