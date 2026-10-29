# Apps tools

Read-only, off by default (`INTUNE_ENABLED_TOOL_GROUPS=apps`). Six tools.
All calls request exactly `https://graph.microsoft.com/DeviceManagementApps.Read.All` in one
per-call token acquisition. The scope is part of the closed allowlist. No app-only fallback or
Graph-token decoding. Add the permission first: [SETUP](../SETUP.md#2-api-permissions).

The sections below describe the three mobile-app tools; app protection policies are covered
separately further down.

## Microsoft Learn evidence (fetched 2026-10-27)

Documentation-confirmed is not live verification: see [Verification status](../VERIFICATION.md)
for what has been exercised against a real tenant. All implemented requests use Graph v1.0 only.

| Tool | GET path (under `/v1.0`) | Documentation status / delegated permission |
| - | - | - |
| `list_apps` | `/deviceAppManagement/mobileApps` | [v1.0 confirmed](https://learn.microsoft.com/en-us/graph/api/intune-apps-mobileapp-list?view=graph-rest-1.0); `DeviceManagementApps.Read.All` |
| `get_app` | `/deviceAppManagement/mobileApps/{app_id}` | [v1.0 confirmed](https://learn.microsoft.com/en-us/graph/api/intune-apps-mobileapp-get?view=graph-rest-1.0); `DeviceManagementApps.Read.All` |
| `get_app_assignments` | `/deviceAppManagement/mobileApps/{app_id}/assignments` | [v1.0 confirmed](https://learn.microsoft.com/en-us/graph/api/intune-apps-mobileappassignment-list?view=graph-rest-1.0); `DeviceManagementApps.Read.All` |
| Parent visibility gate (not a tool) | `/deviceAppManagement/mobileApps/{app_id}?$select=id` | Same documented GET and scope; no second exchange |

[mobileApp base properties](https://learn.microsoft.com/en-us/graph/api/resources/intune-apps-mobileapp?view=graph-rest-1.0)
and [assignment properties](https://learn.microsoft.com/en-us/graph/api/resources/intune-apps-mobileappassignment?view=graph-rest-1.0)
were also fetched. List/get/assignment docs additionally allow the Configuration read permission,
but this group deliberately uses only Apps read.

## Returned / excluded

List: `id`, `displayName`, `publisher`, `createdDateTime`, `lastModifiedDateTime`, `publishingState`,
and `app_type` derived from sanitized `@odata.type`. Get adds `description` (500 characters).
Other text is bounded to 256 characters; dates are normalized to UTC or null. Missing fields
are null. All text is untrusted data, never instructions; admin-written text can itself contain
sensitive material. Only base fields are selected and picked locally for **every** derived type;
no derived-type properties are allowlisted. No icons, URLs, executable content, install/uninstall
commands, detection/requirement scripts or rules, MSI product codes, certificates or app
configuration values. Assignment output: sanitized `id`, `target_type`, `group_id`, `intent`,
`filter_type`, `filter_id`; no raw target or settings. Intent is an enum or null. Filter null
means not reported, not unfiltered (same caveat as configuration). Assignments are locally
allowlisted even if Graph ignores selection; no `$select` sent on that sub-collection.

Paged output follows the existing bounded read layer (2 MiB, 1000 rows per page, endpoint/parent
bound validated page tokens). GUIDs and tokens are validated before any token request. The existing `parent`
mechanism requires a matching parent GET before assignments on **every page**, failing closed
on any failure. Apps-only enablement works without `devices` or `configuration`. This is a
precaution based on the earlier configuration scope-isolation finding, not evidence that apps
are scope-tag isolated live. Audit uses bounded/escaped identifiers, never app names or UPNs.

## Deliberate omissions

- `isAssigned`: absent from the fetched **v1.0 base mobileApp** property table and examples;
  omitted rather than risk an unsupported base `$select` across derived types.
- `get_app_install_summary`: requesting the proposed Learn page with `view=graph-rest-1.0`
  resolved to [beta-only documentation](https://learn.microsoft.com/en-us/graph/api/intune-apps-mobileappinstallsummary-get?view=graph-rest-beta)
  (`graph-rest-beta` moniker and beta request example). No confirmed v1.0 endpoint, so no tool.
  If a future v1.0 aggregate is added, counts for a visible app may include out-of-scope devices;
  a parent check does not make aggregates device-scoped.
- Detected apps need the managed-devices scope, not Apps read, so they live in the opt-in
  [detected apps tools](DETECTED-APPS.md). No installed-on-device app tool.


## App protection policies

Three additional tools in the **existing `apps` group**, same Apps read scope and per-call token acquisition;
no new group or permission. Not yet exercised against a tenant that has such policies (see
[Verification status](../VERIFICATION.md)). Learn pages fetched with `view=graph-rest-1.0`.

| Tool | GET under `/v1.0/deviceAppManagement` | Learn v1.0 evidence |
| - | - | - |
| `list_app_protection_policies` | `/managedAppPolicies` | [list](https://learn.microsoft.com/en-us/graph/api/intune-mam-managedapppolicy-list?view=graph-rest-1.0) |
| `get_app_protection_policy(policy_id)` | `/managedAppPolicies/{id}` (no `$select`/`$expand`) | [get](https://learn.microsoft.com/en-us/graph/api/intune-mam-managedapppolicy-get?view=graph-rest-1.0) |
| `get_app_protection_policy_assignments(policy_id, policy_type)` | `/iosManagedAppProtections/{id}/assignments` or `/androidManagedAppProtections/{id}/assignments` | [assignments](https://learn.microsoft.com/en-us/graph/api/intune-mam-targetedmanagedapppolicyassignment-list?view=graph-rest-1.0) |
| Parent gate, every assignment page | `/iosManagedAppProtections/{id}?$select=id` or `/androidManagedAppProtections/{id}?$select=id` | [iOS get](https://learn.microsoft.com/en-us/graph/api/intune-mam-iosmanagedappprotection-get?view=graph-rest-1.0), [Android get](https://learn.microsoft.com/en-us/graph/api/intune-mam-androidmanagedappprotection-get?view=graph-rest-1.0) |

All endpoint permission tables confirm delegated `DeviceManagementApps.Read.All`. The base
collection intentionally includes **all managed-app policy types**, not just protection: a listed
GUID works with base get, while settings and assignments support only iOS/Android protection.
Assignment `policy_type` is a closed enum of `iosManagedAppProtection` and
`androidManagedAppProtection`, obtained from the list. It selects a fixed spec, never interpolates
free text into a path. A wrong type cannot bypass the corresponding typed parent GET.
No undocumented `/managedAppPolicies/{id}/assignments` request is used.

List/get metadata: canonical GUID `id` or null, `displayName` (256), `description` (500), normalized
`createdDateTime`/`lastModifiedDateTime` or null, strict numeric `version` or null, and `policy_type`.
Only the two supported exact `#microsoft.graph.<type>` values produce a named `policy_type`;
all others become `unknown` (deliberately tighter than the settings tools, to prevent arbitrary type text).
Name/description are untrusted admin-written data and can themselves contain sensitive text;
no content-scrubbing guarantee is made for those two explicit exceptions.
Get adds `settings_available` and `settings`, like [SETTINGS](SETTINGS.md); a supported type means
available even if no valid settings were supplied, not a complete/effective policy.

### Exact reviewed settings

Property-by-property comparison against the fetched v1.0 resource tables:
[iOS](https://learn.microsoft.com/en-us/graph/api/resources/intune-mam-iosmanagedappprotection?view=graph-rest-1.0),
[Android](https://learn.microsoft.com/en-us/graph/api/resources/intune-mam-androidmanagedappprotection?view=graph-rest-1.0).
Each property below is present with the stated type in **both** tables unless explicitly platform-only.
These are allowlists, never a denylist; no inheritance or near-type fallback.

| Exact property | Accepted value / platforms |
| - | - |
| `organizationalCredentialsRequired` | Boolean; both |
| `dataBackupBlocked` | Boolean; both |
| `deviceComplianceRequired` | Boolean; both |
| `saveAsBlocked` | Boolean; both |
| `pinRequired` | Boolean; both |
| `maximumPinRetries` | Int32, 0–2147483647 safety bound; both |
| `simplePinBlocked` | Boolean; both |
| `minimumPinLength` | Int32, 0–2147483647 safety bound; both |
| `contactSyncBlocked` | Boolean flag only, no identifiers; both |
| `printBlocked` | Boolean; both |
| `fingerprintBlocked` | Boolean; both |
| `disableAppPinIfDevicePinIsSet` | Boolean; both |
| `pinCharacterSet` | `numeric`, `alphanumericAndSymbol`; both |
| `allowedInboundDataTransferSources` | `allApps`, `managedApps`, `none`; both |
| `allowedOutboundDataTransferDestinations` | `allApps`, `managedApps`, `none`; both |
| `allowedOutboundClipboardSharingLevel` | `allApps`, `managedAppsWithPasteIn`, `managedApps`, `blocked`; both |
| `minimumRequiredOsVersion` | Strict version string; both |
| `minimumWarningOsVersion` | Strict version string; both |
| `minimumRequiredAppVersion` | Strict version string; both |
| `minimumWarningAppVersion` | Strict version string; both |
| `faceIdBlocked` | Boolean; iOS only |
| `screenCaptureBlocked` | Boolean; Android only |
| `encryptAppData` | Boolean; Android only |
| `disableAppEncryptionIfDeviceEncryptionIsEnabled` | Boolean; Android only |

Thus iOS permits exactly the 20 common properties plus `faceIdBlocked` (21); Android permits
those 20 plus its three platform properties (23). Exact booleans/integers only (no coercion or
boolean-as-integer); enum membership is closed. Version settings and metadata `version` accept
only `[0-9]{1,5}(?:\.[0-9]{1,5}){0,3}` (at most 23 characters). Missing/null/wrong-type/unknown-enum
values are omitted from settings, not truncated. The bounds are safety bounds, not a declaration
that every numeric value is valid for a platform; legitimate nonnumeric entity versions become null.

### Exclusions, assignment shapes and residuals

Both reviewed tables' remaining settings are deliberately omitted: all durations
(`periodOfflineBeforeAccessCheck`, `periodOnlineBeforeAccessCheck`, `periodOfflineBeforeWipeIsEnforced`,
`periodBeforePinReset`), `managedBrowserToOpenLinksRequired`, `managedBrowser`,
`allowedDataStorageLocations`, `isAssigned`, `deployedAppCount`. iOS additionally omits
`appDataEncryptionType`, `minimumRequiredSdkVersion`, `customBrowserProtocol`; Android omits
`minimumRequiredPatchVersion`, `minimumWarningPatchVersion`, `customBrowserPackageId`,
`customBrowserDisplayName`. These safe-looking omissions keep the initial subset small; patch
versions are dates, not the numeric dotted grammar. No apps/deployment-summary navigation,
custom browser package IDs/URLs/protocols, data-transfer app lists or deep links, email addresses,
tenant/user IDs, contact-sync identifiers, notification strings, arbitrary URLs or other free text.
Unknown properties are dropped even if their values are valid booleans/numbers/enums.

Assignments use the reviewed [targetedManagedAppPolicyAssignment table](https://learn.microsoft.com/en-us/graph/api/resources/intune-mam-targetedmanagedapppolicyassignment?view=graph-rest-1.0):
only `id`, `target_type`, `group_id`, `filter_type`, `filter_id`; assignment/group/filter IDs must
be GUIDs or null. Only group/exclusion-group/all-licensed-users/all-devices target types are
recognized. Unsupported shapes (including `scopeTagGroupAssignmentTarget` in Learn's current
example) return `target_type=unknown` and null target fields; never expose `entraObjectId`.
Deprecated `targetGroupId`/`isExcluded` are not interpreted or returned. Unknown/null targets
are **not proof of no assignment**, and null filters mean not reported, not unfiltered.

Windows-specific support was **dropped**: requesting `windowsManagedAppProtection` with the
v1.0 selector redirected to beta documentation. No beta endpoint or fields are implemented;
other base-list types remain metadata-only. No per-type list tools or extra settings tool needed.

GUID/type/page-token validation precedes any token request; one Apps read exchange per call, opaque Graph token.
Existing 2 MiB response/1000-row limits and endpoint/type/parent-bound tokens apply. A matching
id-only typed parent GET is mandatory **before children on every page**; invisible parent →
`not_found` with no child request, 403 → `forbidden`. Audits use existing `audit_value`, no names
or settings. **App protection policies may not be scope-tag scoped at all.** The gate proves only
that Graph let this caller read this parent at that moment, not tenant/user/device isolation of
visible policies or their assignments; visibility may also change between parent and child reads.
Check results against the Intune portal before relying on them.
