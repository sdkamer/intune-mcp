# Verification status

Be careful what this table means. The automated suite is **all mocked** (a stubbed Graph and a fake
local identity): it proves the server's policy and plumbing, not Microsoft's behaviour. Live results
below come from an earlier **hosted deployment of the same Graph layer and tools** (an OAuth-brokered
server, since replaced by this local design), operated against one real tenant in October 2026.
The local sign-in path has since had a first live check (below), on one machine.

## Exercised live (via the earlier hosted deployment)

| Area | Result |
| - | - |
| `devices` group | List, get, search, count and summary worked, including filters and paging; counts for a scope-tag-restricted user match what that user sees. |
| `configuration` group | Per-device compliance/configuration states, policies, profiles, status overviews, assignments and the compliance summary returned data; for a restricted user, objects outside their scope returned `not_found`. Settings tools returned only typed values; no secrets observed. |
| `apps` group | Apps, assignments and app categories worked; a restricted user got `not_found` for an app outside their scope. |
| `rbac` group | Role definitions, actions and assignments worked (single-assignment GET fills `members`/`resourceScopes` that the list leaves empty). Reads were allowed to a user whose own Intune role includes Roles: Read, as expected. A user without that permission was not tested. |
| `enrollment` group | Configurations, assignments and the Apple certificate status worked; default configurations have composite ids (fixed). |
| Found live and fixed | `$count` ignores scope tags (counts walk visible rows); child endpoints answer for parents a user cannot see (parent check added); composite enrollment ids. |

## Local sign-in path: first live check (macOS, device-code flow, Pi, 2026-10-29)

Signed in with the **device-code** flow against the same app registration the earlier deployment used (a
Mobile and desktop platform with `http://localhost` added, public client flows enabled), with all five
groups enabled, then ran the tools through Pi against the real tenant:

- **The first attempt failed after sign-in** because *Allow public client flows* was still off in Entra;
  the failure only said the exchange failed, which led to printing Microsoft's numeric `AADSTS` code and a
  closed error name (never its text) on failed sign-ins. After enabling the setting, sign-in succeeded and
  `status` found exactly one tenant-matching cached account.
- **Silent refresh across scopes:** one cached refresh token was redeemed for five different single Graph
  scopes (devices, configuration, apps, RBAC, service configuration) across about 30 tool calls, which
  confirms the one-scope-per-call design works against Entra.
- **Parity with the earlier deployment:** device counts, role definitions (11, ten built-in), policy and
  profile settings, enrollment configurations (composite ids intact) and the Apple certificate status
  matched what the hosted server returned for the same user.
- **Two-scope path:** per-device compliance and configuration states (devices parent check, then the
  configuration scope) succeeded; paging returned a different second page; a malformed device id and an
  oversized page size were rejected before any token request.
- Pi connected to the stdio server and listed all 41 tools. `whoami` returned only tenant, object id and
  version.

## Not yet verified live

- **The rest of the local sign-in path**: the browser (loopback) login, `logout` and account switching,
  recovery from a corrupt cache, refresh after the access token has expired for hours, the daily release
  check against a published release, other harnesses (Claude Code, Codex CLI), Windows and Linux
  keychains, and restricted (scope-tag) users running it themselves.
- **Objects that did not exist in the test tenant**: app protection policies, app configuration policies
  and terms and conditions (list calls returned empty), the opt-in detected-apps tools, and policy
  settings for types other than macOS compliance and Windows Update for Business.
- Restricted-user behaviour for the newer tools, and visible-object aggregate scope.
- Behaviour with other tenants, sovereign clouds (public cloud only) and large tenants.

If you verify any of this in your own tenant, please say what you saw (never include tenant data).
