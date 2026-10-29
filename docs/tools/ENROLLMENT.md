# Enrollment tools

Opt-in `enrollment` group: read-only tools for enrollment configurations, their assignments,
the Apple push certificate status and terms and conditions ([TERMS-CATEGORIES](TERMS-CATEGORIES.md)).
One delegated scope, `DeviceManagementServiceConfig.Read.All`. Default is `devices`;
enrollment-only enablement works.

**Add and admin-consent the delegated `DeviceManagementServiceConfig.Read.All` permission before
enabling `enrollment`**, or sign-in fails. Enabling adds the scope to the sign-in request; then add
`enrollment` to `INTUNE_ENABLED_TOOL_GROUPS` and sign in again. To roll back, remove the group;
consent can stay. See [SETUP](../SETUP.md#2-api-permissions).

## Microsoft Learn evidence (fetched 2026-10-27)

Documentation-confirmed is not live verification: see [Verification status](../VERIFICATION.md).
Only v1.0 is used. Each endpoint page below documents delegated ServiceConfig read as sufficient;
no ReadWrite, directory permission, app-only fallback or new authorization architecture.

| Tool | GET path under `/v1.0` | Learn v1.0 |
| - | - | - |
| `list_enrollment_configurations` | `/deviceManagement/deviceEnrollmentConfigurations` | [list](https://learn.microsoft.com/en-us/graph/api/intune-onboarding-deviceenrollmentconfiguration-list?view=graph-rest-1.0) |
| `get_enrollment_configuration` | `/deviceManagement/deviceEnrollmentConfigurations/{configuration_id}` | [get](https://learn.microsoft.com/en-us/graph/api/intune-onboarding-deviceenrollmentconfiguration-get?view=graph-rest-1.0) |
| `get_enrollment_configuration_assignments` | `/deviceManagement/deviceEnrollmentConfigurations/{configuration_id}/assignments` | [assignments](https://learn.microsoft.com/en-us/graph/api/intune-onboarding-enrollmentconfigurationassignment-list?view=graph-rest-1.0) |
| `get_apple_push_certificate_status` | `/deviceManagement/applePushNotificationCertificate` | [get](https://learn.microsoft.com/en-us/graph/api/intune-devices-applepushnotificationcertificate-get?view=graph-rest-1.0) |
| Parent gate (not a tool) | `/deviceManagement/deviceEnrollmentConfigurations/{configuration_id}?$select=id` | Same get endpoint/scope |

Metadata properties: [deviceEnrollmentConfiguration](https://learn.microsoft.com/en-us/graph/api/resources/intune-onboarding-deviceenrollmentconfiguration?view=graph-rest-1.0).
Certificate properties: [applePushNotificationCertificate](https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-applepushnotificationcertificate?view=graph-rest-1.0).
Assignment properties: [enrollmentConfigurationAssignment](https://learn.microsoft.com/en-us/graph/api/resources/intune-onboarding-enrollmentconfigurationassignment?view=graph-rest-1.0),
[groupAssignmentTarget](https://learn.microsoft.com/en-us/graph/api/resources/intune-shared-groupassignmenttarget?view=graph-rest-1.0),
[exclusionGroupAssignmentTarget](https://learn.microsoft.com/en-us/graph/api/resources/intune-shared-exclusiongroupassignmenttarget?view=graph-rest-1.0),
[allDevicesAssignmentTarget](https://learn.microsoft.com/en-us/graph/api/resources/intune-shared-alldevicesassignmenttarget?view=graph-rest-1.0),
[allLicensedUsersAssignmentTarget](https://learn.microsoft.com/en-us/graph/api/resources/intune-shared-alllicensedusersassignmenttarget?view=graph-rest-1.0).

## Returned fields and exact settings allowlists

Configuration list/get: GUID-or-null `id`, bounded untrusted `displayName` (256 characters),
`description` (500), integer-or-null `priority` and `version` (0–2147483647), validated UTC
`createdDateTime` / `lastModifiedDateTime`, and `configuration_type` derived from `@odata.type`
using the existing tight type-name pattern (malformed → `unknown`). Administrator-written
metadata can itself contain sensitive text; this is not content redaction or effective policy.
Lists request only base fields via `$select`; get fetches the full bounded object without
`$select`/`$expand` and filters locally. Extra properties never pass through.

Get adds `settings_available` and `settings`. Exact `#microsoft.graph.<type>` matching only:

| Type (v1.0 property table) | Exact settings |
| - | - |
| [deviceEnrollmentLimitConfiguration](https://learn.microsoft.com/en-us/graph/api/resources/intune-onboarding-deviceenrollmentlimitconfiguration?view=graph-rest-1.0) | `limit`: exact integer 0–2147483647, not boolean |
| [deviceEnrollmentPlatformRestrictionsConfiguration](https://learn.microsoft.com/en-us/graph/api/resources/intune-onboarding-deviceenrollmentplatformrestrictionsconfiguration?view=graph-rest-1.0) | `iosRestriction`, `windowsRestriction`, `windowsMobileRestriction`, `androidRestriction`, `macOSRestriction`: each accepts only boolean `platformBlocked` and `personalDeviceEnrollmentBlocked` |
| [windows10EnrollmentCompletionPageConfiguration](https://learn.microsoft.com/en-us/graph/api/resources/intune-onboarding-windows10enrollmentcompletionpageconfiguration?view=graph-rest-1.0) | boolean `allowNonBlockingAppInstallation` only |

Nested flag names confirmed on [deviceEnrollmentPlatformRestriction](https://learn.microsoft.com/en-us/graph/api/resources/intune-onboarding-deviceenrollmentplatformrestriction?view=graph-rest-1.0).
No string-valued settings, coercion or truncation into settings. Wrong-type/missing values are
omitted; unknown/unlisted types return `settings_available=false`, `settings={}`. Supported type
with missing values remains available, not a claim of complete settings. OS version strings and
all other ESP/Hello settings are deliberately omitted; only one ESP flag was confirmed here.

Assignments: `id` (GUID-or-null), `target_type` (four documented types above or `unknown`),
`group_id` (GUID-or-null). No target names, arbitrary target objects, scope-tag target extras,
filters or filter IDs (not documented on the fetched v1.0 base target). No `$select` assumption
on assignments. Same-scope id-only parent GET before **every page**, including after visibility
loss; invisible → `not_found`, 403 → `forbidden`, malformed/mismatched parent fails closed.
One token acquisition per tool call, including parent/child reads. A visible parent does not prove
child results match portal scope tags; check results against the portal for scope-tag-restricted users.

Apple status: only `expirationDateTime`, `lastModifiedDateTime`, `certificateUploadStatus`
and computed `days_until_expiry` (whole remaining 24-hour periods, rounded down; negative when
expired; null for missing/invalid expiry). **Upload status is always null**: Learn defines an
unconstrained String with no enum. Raw status/failure text is withheld rather than passing
potential secrets through a bounded string. The GET selects only the two date properties.
No certificate ID, Apple ID/email, body, serial, topic ID or failure reason is returned.

Existing read-layer limits apply: GUID validation before any exchange, 2 MiB decoded response,
1000 rows/page, endpoint/parent-bound validated page tokens and nextLinks. Pages ignoring `$top`
are returned whole within bounds. Audit uses `audit_value`, GUIDs/fixed labels and counts only,
never names, bodies, settings or tokens. Graph tokens remain opaque.

## Deliberate omissions / exclusions

- **Dropped `list_autopilot_profiles` and `get_autopilot_profile`:** requesting the proposed
  [profile resource](https://learn.microsoft.com/en-us/graph/api/resources/intune-enrollment-windowsautopilotdeploymentprofile?view=graph-rest-1.0)
  and [get](https://learn.microsoft.com/en-us/graph/api/intune-enrollment-windowsautopilotdeploymentprofile-get?view=graph-rest-1.0)
  with v1.0 redirected to `graph-rest-beta&viewFallbackFrom=graph-rest-1.0`; list returned 404.
  No confirmed v1.0 contract, so no profile/OOBE settings or `deviceNameTemplate` are returned.
  This is a documentation finding, not a claim that a live v1.0 endpoint cannot exist.
- Autopilot device identities, serial numbers, hardware hashes, DEP/ABM tokens and token names,
  Apple IDs, enrollment profiles with URLs/credentials, certificates, secrets, tokens, URLs,
  email/UPN settings and arbitrary derived-type properties are excluded. No writes or aggregates.

## Composite IDs

Intune's default enrollment configurations have composite IDs, so a GUID-only check returned `id: null`. Intune's default enrollment configurations have composite IDs, a GUID plus an underscore and a short alphanumeric suffix, which the original GUID-only check discarded. `configuration_id` now accepts exactly `GUID` or `GUID_<1-64 alphanumerics>` (canonical lower-case GUID part, suffix kept verbatim); anything with a slash, dot, percent, whitespace, a second underscore or a non-GUID prefix is rejected before any token exchange. The parent visibility check and page-token binding use the same form. Enrollment assignment IDs are returned only when they start with a GUID followed by at most two short opaque segments; other text is never echoed. A suffix can carry up to 64 alphanumerics from Graph, which is the accepted residual of this identifier shape.

