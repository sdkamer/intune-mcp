# Configuration state summaries

Two read-only tools for the `configuration` group: `get_configuration_state_summary`, and the
opt-in `list_compliance_setting_state_summaries` (see below). Same scope,
`DeviceManagementConfiguration.Read.All`. No parent object, so no parent check.

## Microsoft Learn evidence (fetched 2026-10-27, v1.0 only)

Documentation-confirmed is not live verification: see [Verification status](../VERIFICATION.md). No
beta redirect occurred on any fetched page. Each page lists delegated
`DeviceManagementConfiguration.Read.All` as sufficient.

| Tool | GET path under `/v1.0` | Learn v1.0 |
| - | - | - |
| `get_configuration_state_summary` | `/deviceManagement/deviceConfigurationDeviceStateSummaries` | [get](https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-deviceconfigurationdevicestatesummary-get?view=graph-rest-1.0), [resource](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-deviceconfigurationdevicestatesummary?view=graph-rest-1.0) |
| `list_compliance_setting_state_summaries` | `/deviceManagement/deviceCompliancePolicySettingStateSummaries` | [list](https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-devicecompliancepolicysettingstatesummary-list?view=graph-rest-1.0), [resource](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-devicecompliancepolicysettingstatesummary?view=graph-rest-1.0) |

The first endpoint is a singleton object, not a collection (the list page for it returns 404 on
Learn). Learn's sample response wraps it in `value`; the shaper accepts either that or a bare
object and reads counts only.

## Returned fields (allowlist) and exclusions

`get_configuration_state_summary`: the seven documented Int32 counts only —
`compliantDeviceCount`, `nonCompliantDeviceCount`, `errorDeviceCount`, `conflictDeviceCount`,
`notApplicableDeviceCount`, `unknownDeviceCount`, `remediatedDeviceCount`. Non-integer, boolean or
negative values become null. `id` is not returned.

`list_compliance_setting_state_summaries` (paged, same keys as other paged tools): per row
`id` (GUID or null), `setting` and `settingName` (only if the text matches
`[A-Za-z][A-Za-z0-9_.]{0,127}`, else null; a human-readable name with spaces is therefore null by
design), `platformType` (only the nine documented `policyPlatformType` values: `android`, `iOS`,
`macOS`, `windowsPhone81`, `windows81AndLater`, `windows10AndLater`, `androidWorkProfile`,
`linux`, `all`; anything else null) and the same seven counts. No setting values, no
`deviceComplianceSettingStates` relationship, no unlisted property of any type. No `$select`
is sent (support not assumed). Read-layer limits apply: 2 MiB response, 1000 rows/page,
endpoint-bound validated page tokens and nextLinks.

Audit lines carry the tool name, outcome and (for the list) row counts; never targets,
setting names, values or tokens. Graph tokens remain opaque; one token acquisition per call.

## Residual risk: tenant-level aggregates are not scope-isolated

Both endpoints are tenant-level aggregates. Intune scope tags apply to individual objects, not to
these counters, so the numbers **may include devices outside a scoped user's scope** (the same
residual as `get_compliance_summary`). This server does not claim isolation here; the tool
descriptions say so. A scoped user can learn aggregate counts and which compliance setting
identifiers exist, not which devices or values.

Other residuals: `setting` is a class/property identifier string chosen by Microsoft, but an
unconstrained String per Learn, hence the strict pattern; an identifier that fits the pattern is
echoed verbatim.

## Live finding and opt-in gating

A scope-tag-restricted user (one visible device) received tenant-wide numbers from `list_compliance_setting_state_summaries` (for example 944 and 89 devices for two settings) together with the setting names, so that tool is **not** limited to the caller's Intune scope. It is therefore registered only when `INTUNE_ENABLE_TENANT_INVENTORY=true` **and** the `configuration` group is enabled (off by default, same flag as the detected-apps tools). `get_configuration_state_summary` returned all zeros to the same user (not a demonstrated leak; unclear whether the endpoint is scoped or the tenant has no such data, still unverified). `get_compliance_summary` and `device_summary` were scoped correctly for that user.
