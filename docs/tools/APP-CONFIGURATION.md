# App categories and app configuration policies (apps group)

Read-only, part of the existing `apps` group (off by default). Four tools added to the group
([APPS](APPS.md)): `list_app_categories`, `list_app_configuration_policies`,
`get_app_configuration_policy`, `get_app_configuration_policy_assignments`. Every call requests
exactly `DeviceManagementApps.Read.All` in one per-call token acquisition; no new scope, no app-only
fallback, Graph token opaque.

## Microsoft Learn evidence (fetched 2026-10-27, `view=graph-rest-1.0`, no beta redirect)

Documentation-confirmed is not live verification; this tenant had none of these objects when tested
(see [Verification status](../VERIFICATION.md)).

| Tool | GET path (under `/v1.0`) | Learn page / delegated permission |
| - | - | - |
| `list_app_categories` | `/deviceAppManagement/mobileAppCategories` | `intune-apps-mobileappcategory-list`; Apps.Read.All (Configuration.Read.All also allowed, not used) |
| `list_app_configuration_policies` | `/deviceAppManagement/mobileAppConfigurations` | `intune-apps-manageddevicemobileappconfiguration-list`; Apps.Read.All |
| `get_app_configuration_policy` | `/deviceAppManagement/mobileAppConfigurations/{id}` | `intune-apps-manageddevicemobileappconfiguration-get`; Apps.Read.All |
| `get_app_configuration_policy_assignments` | `/deviceAppManagement/mobileAppConfigurations/{id}/assignments` | `intune-apps-manageddevicemobileappconfigurationassignment-list`; Apps.Read.All |
| Parent gate (not a tool) | `/deviceAppManagement/mobileAppConfigurations/{id}?$select=id` | same GET, same scope |

Base properties (`managedDeviceMobileAppConfiguration`): `id`, `targetedMobileApps`,
`createdDateTime`, `description`, `lastModifiedDateTime`, `displayName`, `version`. Category:
`id`, `displayName`, `lastModifiedDateTime`. Derived (e.g. iOS) types add `settings` and
`encodedSettingXml`; the Android/`payloadJson` types are not documented on v1.0 and are
handled only by exclusion.

## Returned / excluded (allowlist only)

- Category: `id` (GUID or null), `displayName` (256 chars), `lastModifiedDateTime` (UTC or null).
- Policy: `id` (GUID or null), `displayName` (256), `description` (500), `createdDateTime`,
  `lastModifiedDateTime`, `version` (int), `configuration_type` (sanitized `@odata.type`, else
  `unknown`), `targeted_app_count` (count of `targetedMobileApps`, null if not a list).
- Assignment: `id`, `target_type`, `group_id`, `filter_type`, `filter_id` (existing sanitizer;
  `id` is a bounded identifier string, `target_type` a bounded type name, `group_id`/`filter_id`
  GUIDs, `filter_type` a closed enum; no group names). Null filter means not reported, not
  unfiltered.
- The properties `settings`, `encodedSettingXml`, `payloadJson`, app config keys/values and
  targeted app IDs are **never** returned, nor any unlisted property (URLs, emails/UPNs,
  certificates and credentials live in such properties). `displayName`/`description` are free
  text and are not redacted.
  Only base fields are `$select`ed (policies); everything is also picked locally, so a derived
  type's extra properties cannot reach output even if Graph returns them. No type-specific
  settings exist, so there is no `settings_available`.
- Text is admin-written, untrusted data, bounded; it may itself hold sensitive material.

## Authorization and bounds

GUID validated before any exchange. Assignments: the parent GET (same scope, same exchange
family) must return the same id before the first read and on **every** page; invisible parent ->
`not_found` with no child call; 403 -> `forbidden`. Page tokens are bound to endpoint and parent.
Existing limits: 1000 rows per page, 2 MiB per response. Audit uses `audit_value`/GUID target
only; no names, no app ids.

## Residual risks

- Whether Intune scope tags apply to these endpoints, whether `$select` of
  `targetedMobileApps` is accepted, nextLink forms, and permission acceptance are not yet verified live.
- `targeted_app_count` counts out-of-scope apps too if Graph does not filter the list.
- Categories are tenant-wide labels; no scope isolation claimed.
- Unfiltered assignment `filter_*` fields may be null because Graph v1.0 documents no filter on
  the base target.
- Permission evidence: the Learn page for the iOS derived type lists delegated
  DeviceManagementApps.Read.All; the base-type get/list pages list that scope alongside
  Configuration.Read.All (not used here). Whether Apps.Read.All alone is accepted by the base
  endpoints is not yet verified live.
