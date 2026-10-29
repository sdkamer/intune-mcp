# Detected apps (opt-in tenant inventory)

Read-only and **off by default**. Two tools, registered only when `INTUNE_ENABLE_TENANT_INVENTORY=true`
(requires the `devices` tool group). They are not part of any group's tool list and add no scope:
every call requests exactly `https://graph.microsoft.com/DeviceManagementManagedDevices.Read.All`
(the `devices` scope) in one per-call token acquisition. Enabling the flag adds 2 tools.
Set `INTUNE_ENABLE_TENANT_INVENTORY=true` in the environment your harness gives the server.

## Why opt-in

`/deviceManagement/detectedApps` is a **tenant-wide root collection**. It has no managed-device
parent object, so the server's parent visibility check cannot apply, and it is not known to
honour Intune scope tags. A scoped admin may therefore see app names and `deviceCount` values that
include devices outside their scope. Enable only where that is acceptable.

## Microsoft Learn evidence (fetched 2026-10-27, v1.0 only)

| Tool | GET path (under `/v1.0`) | Documentation |
| - | - | - |
| `list_detected_apps` | `/deviceManagement/detectedApps` | [v1.0](https://learn.microsoft.com/en-us/graph/api/intune-devices-detectedapp-list?view=graph-rest-1.0); delegated `DeviceManagementManagedDevices.Read.All` |
| `get_detected_app` | `/deviceManagement/detectedApps/{detected_app_id}` | [v1.0](https://learn.microsoft.com/en-us/graph/api/intune-devices-detectedapp-get?view=graph-rest-1.0); same permission; OData query parameters supported |

Properties from the [v1.0 resource](https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-detectedapp?view=graph-rest-1.0):
`id`, `displayName`, `version`, `sizeInByte` (Int64), `deviceCount` (Int32), `publisher`,
`platform` (`detectedAppPlatformType`). The list page documents no `$filter`/`$top` support, so
there are **no typed filters** (paging only; `$top` and `$select` are sent like other collections
and the server also bounds rows locally). Not yet exercised live: permission acceptance, `$select`/`$top`, nextLink form, scope-tag
behaviour and the real `id` format.

## Returned / excluded

Allowlisted fields only, for every row: `id` (strict `[A-Za-z0-9-]{1,128}`, else null),
`displayName` and `publisher` (untrusted text, 256 characters), `version` (strict
`[A-Za-z0-9._+() -]{1,64}`, else null), `sizeInByte` and `deviceCount` (non-negative integers,
else null), `platform` (closed enum from the Learn list, else null). Anything else in a row is
dropped, including `@odata.type` and the `managedDevices` relationship. **No per-app
`managedDevices` child tool**: it could expose out-of-scope devices. The properties that would carry URLs, emails/UPNs,
credentials, certificates, serials or scripts are not returned; `displayName` and `publisher` are
bounded free text and are not redacted, so they may themselves contain such content. Audit lines carry the tool name,
outcome and (for get) the validated GUID only; never names. Page tokens are bound to the
`devices.detected_apps` endpoint; paging bounds are the standard read layer (2 MiB, 1000 rows).

## Residual risks

- Tenant-wide data and `deviceCount` may ignore scope tags (see above).
- `get_detected_app` accepts a GUID only (the documented example shape). If live ids prove not to
  be GUIDs, the get tool will refuse them while the list still returns them; adjust after the live
  check rather than loosening path validation now.
- The Learn get example wraps the object in `value`; the server expects a plain object per the
  standard OData response. Confirm live.
- Names and publishers are third-party/endpoint-reported text: untrusted data, not instructions.
