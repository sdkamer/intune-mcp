# Terms and conditions (enrollment group)

Three read-only tools in the opt-in `enrollment` group. Same single delegated scope,
`DeviceManagementServiceConfig.Read.All`. Learn is documentation, not live evidence: this tenant had
no such objects when tested (see [Verification status](../VERIFICATION.md)).

## Microsoft Learn evidence (fetched 2026-10-27, v1.0 only)

| Tool | GET path under `/v1.0` | Learn v1.0 |
| - | - | - |
| `list_terms_and_conditions` | `/deviceManagement/termsAndConditions` | [list](https://learn.microsoft.com/en-us/graph/api/intune-companyterms-termsandconditions-list?view=graph-rest-1.0) |
| `get_terms_and_conditions` | `/deviceManagement/termsAndConditions/{terms_id}` | [get](https://learn.microsoft.com/en-us/graph/api/intune-companyterms-termsandconditions-get?view=graph-rest-1.0) |
| `get_terms_and_conditions_assignments` | `/deviceManagement/termsAndConditions/{terms_id}/assignments` | [assignments](https://learn.microsoft.com/en-us/graph/api/intune-companyterms-termsandconditionsassignment-list?view=graph-rest-1.0) |
| Parent gate (not a tool) | `/deviceManagement/termsAndConditions/{terms_id}?$select=id` | same get endpoint/scope |

All three pages list delegated `DeviceManagementServiceConfig.Read.All` as the least privileged
permission. Properties: [termsAndConditions](https://learn.microsoft.com/en-us/graph/api/resources/intune-companyterms-termsandconditions?view=graph-rest-1.0),
[termsAndConditionsAssignment](https://learn.microsoft.com/en-us/graph/api/resources/intune-companyterms-termsandconditionsassignment?view=graph-rest-1.0).

## Dropped: `list_device_categories`

[deviceCategory list](https://learn.microsoft.com/en-us/graph/api/intune-onboarding-devicecategory-list?view=graph-rest-1.0)
and [get](https://learn.microsoft.com/en-us/graph/api/intune-onboarding-devicecategory-get?view=graph-rest-1.0)
(v1.0, `GET /deviceManagement/deviceCategories`) document delegated
`DeviceManagementManagedDevices.Read.All`, not ServiceConfig. Serving them from this group would
need a second scope exchange or the managed-devices scope, so the tool is not implemented here.
It would belong to the `devices` group if wanted (fields: `id`, `displayName`, `description`).

## Returned and excluded fields

List/get: GUID-or-null `id`, bounded untrusted `displayName` (256) / `title` (256) /
`description` (500) (each null if not a string), integer-or-null `version` (0-2147483647,
not boolean), validated UTC `createdDateTime` / `lastModifiedDateTime`. Both read `$select` only
those fields; the shape also picks locally, so extra properties never pass through.
**Excluded entirely:** `bodyText`, `acceptanceStatement` (never selected, never returned), the
acceptance statuses, and every unlisted property. No URLs, emails, credentials or scripts.

Assignments: `id` (GUID-or-null), `target_type` (closed set: group, exclusion group, all
devices, all licensed users targets, else `unknown`), `group_id` (GUID-or-null). Learn's only
documented target example is `scopeTagGroupAssignmentTarget` with `entraObjectId`; that is not
mapped (unverified shape), so such rows return `unknown` / null. No names, filters or other
target properties. Parent id-only GET before the first read **and every page**; invisible parent
is `not_found` with no child call, 403 is `forbidden`, a malformed/mismatched parent fails closed.
`terms_id` is a GUID validated before any token exchange; page tokens are bound to endpoint and
parent. Existing read-layer bounds apply (2 MiB, 1000 rows, nextLink checks). Audit uses
`audit_value` with the canonical GUID, counts and fixed labels only.

## Residual risks

- Admin-written `displayName`, `description` and `title` can contain sensitive text; bounded, not redacted.
- A visible parent does not prove child assignments match portal scope tags; restricted-user live check needed.
- The assignment target shape on live v1.0 is unconfirmed; unexpected shapes degrade to `unknown`.

