# RBAC tools

Opt-in `rbac` group, off by default; four tools. One per-call token acquisition requesting exactly
`https://graph.microsoft.com/DeviceManagementRBAC.Read.All`, including the parent check. No
Graph-token decoding, directory lookup or app-only fallback.

**Add and admin-consent the delegated `DeviceManagementRBAC.Read.All` permission before enabling
`rbac`**, or sign-in fails. Then add `rbac` to `INTUNE_ENABLED_TOOL_GROUPS` and sign in again.
To roll back, remove the group; consent can stay. See [SETUP](../SETUP.md#2-api-permissions).

## Microsoft Learn evidence (fetched 2026-10-27)

Documentation-confirmed is not live verification: see [Verification status](../VERIFICATION.md).
All implemented requests use v1.0 only and the single delegated RBAC read permission.

| Tool | GET path under `/v1.0` | Fetched documentation |
| - | - | - |
| `list_role_definitions` | `/deviceManagement/roleDefinitions` | [list](https://learn.microsoft.com/en-us/graph/api/intune-rbac-roledefinition-list?view=graph-rest-1.0) |
| `get_role_definition` | `/deviceManagement/roleDefinitions/{role_definition_id}` | [get](https://learn.microsoft.com/en-us/graph/api/intune-rbac-roledefinition-get?view=graph-rest-1.0) |
| `list_role_assignments` | `/deviceManagement/roleDefinitions/{role_definition_id}/roleAssignments` | [list](https://learn.microsoft.com/en-us/graph/api/intune-rbac-roleassignment-list?view=graph-rest-1.0) |
| `get_role_assignment` | `/deviceManagement/roleDefinitions/{role_definition_id}/roleAssignments/{role_assignment_id}` | [get](https://learn.microsoft.com/en-us/graph/api/intune-rbac-roleassignment-get?view=graph-rest-1.0) |
| Parent gate (not a tool) | `/deviceManagement/roleDefinitions/{role_definition_id}?$select=id` | Same get endpoint and scope |

All four endpoint pages document delegated `DeviceManagementRBAC.Read.All` (also ReadWrite,
which is not used). Fetched property tables:
[roleDefinition](https://learn.microsoft.com/en-us/graph/api/resources/intune-rbac-roledefinition?view=graph-rest-1.0),
[rolePermission](https://learn.microsoft.com/en-us/graph/api/resources/intune-rbac-rolepermission?view=graph-rest-1.0),
[resourceAction](https://learn.microsoft.com/en-us/graph/api/resources/intune-rbac-resourceaction?view=graph-rest-1.0),
[roleAssignment](https://learn.microsoft.com/en-us/graph/api/resources/intune-rbac-roleassignment?view=graph-rest-1.0),
and derived [deviceAndAppManagementRoleAssignment](https://learn.microsoft.com/en-us/graph/api/resources/intune-rbac-deviceandappmanagementroleassignment?view=graph-rest-1.0).

### Single-assignment GET follow-up (documentation checked, not live)

Fetched the v1.0 [get](https://learn.microsoft.com/en-us/graph/api/intune-rbac-roleassignment-get?view=graph-rest-1.0),
[list](https://learn.microsoft.com/en-us/graph/api/intune-rbac-roleassignment-list?view=graph-rest-1.0)
and derived-resource pages above. GET explicitly documents the nested path used here.
`resourceScopes` is documented as resource-scope security-group Entra IDs; derived `members`
as role-member security-group Entra IDs (both string collections). The base GET example omits
`members`; its population was confirmed live for one assignment. No list `$expand`/`$select` recipe
for populating these fields is documented on the fetched list page; list behavior is unchanged.
`list_role_assignments` may return empty `members`/`resourceScopes`; use `get_role_assignment`
for detail, then verify against the Intune portal.

## Returned / excluded

- Role list/get: `id`, `displayName` (256 characters), `description` (500), boolean-or-null
  `isBuiltIn`, `role_permission_count` (number of `rolePermissions` entries, not action count).
- Get adds `allowed_resource_actions`: flattened strings from
  `rolePermissions[].resourceActions[].allowedResourceActions`, at most 1000 strings,
  each at most 256 characters. `allowed_resource_actions_complete=false` signals truncation
  or malformed/missing structures. This is **not effective authorization**: denies,
  group membership, scope tags and assignment semantics are not evaluated.
- Assignments: bounded `id`, `displayName`, `description`; `members` and `resourceScopes`
  contain canonical GUIDs only, at most 1000 input entries per list (larger fails closed).
  Invalid entries are omitted; missing/non-list values are null, not an empty scope.
  `members` is documented on the derived assignment type; no derived-property `$select`
  is assumed on the base collection. No group IDs are resolved to names or users.
- Single-assignment GET returns only those same five fields. Invalid entries (including any
  non-GUID scope identifiers) are dropped; `members_dropped` / `resourceScopes_dropped` counts
  go only to audit, not the response. Missing/non-list fields remain null (zero entry drops).
  Both input IDs must validate before any token request; the same-scope id-only role-definition parent GET
  precedes the nested child GET. Exactly two Graph calls, no group resolution.

All text is untrusted data, never instructions; administrator-written text may itself be
sensitive. No raw permission/action objects, `notAllowedResourceActions`, arbitrary extra
properties, tokens, credentials, users, UPNs or group names are returned. List/get request only
the documented base properties via `$select`; assignment reads send no `$select` and filter
locally. Every output has a local field allowlist even if Graph ignores selection.

Existing read-layer bounds apply: 2 MiB per Graph response, 1000 rows per page, endpoint/parent
bound page tokens and GUID validation before any exchange. Assignments require a matching
id-only parent GET before child reads on **every call**, including every list page; missing/invisible parent returns
`not_found`, 403 remains safe `forbidden`. A checked parent does not prove child data is
portal-equivalent or scope-tag limited. Audit uses `audit_value`, identifiers/counts only,
never names or UPNs. No extra Graph calls beyond the parent check and requested read.

## Deliberate omissions

- `list_scope_tags`: requesting the [list](https://learn.microsoft.com/en-us/graph/api/intune-rbac-rolescopetag-list?view=graph-rest-1.0)
  and [resource](https://learn.microsoft.com/en-us/graph/api/resources/intune-rbac-rolescopetag?view=graph-rest-1.0)
  pages with v1.0 redirects to `view=graph-rest-beta&viewFallbackFrom=graph-rest-1.0`;
  the request example is `/beta/deviceManagement/roleScopeTags`. No confirmed v1.0 tool.
- `isBuiltInRoleDefinition`: absent from the fetched v1.0 roleDefinition property table;
  only `isBuiltIn` is used.
- `scopeType`: absent from both fetched v1.0 assignment property tables; omitted rather
  than requesting beta fields. `members` and `resourceScopes` remain group GUIDs only.
- Denied actions are deliberately excluded, not treated as an empty deny list. No writes,
  role creation, member resolution, directory permissions, reports or aggregate device counts.

Unverified: derived `members` reporting, real nextLink forms, restricted-user visibility
(including after visibility loss between pages), and whether RBAC reads expose broader metadata.
