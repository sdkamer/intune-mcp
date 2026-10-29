# Security model

## What it enforces

- **Identity comes from the signed-in account, never from the model.** `whoami` and the audit log use
  the tenant and object id of the single cached MSAL account, re-checked against your configured tenant
  before every token request. More than one cached account is refused, never selected by name, input
  or order. There is no app-only, shared or fallback credential: this project has no client secret.
- **Read-only, closed scopes.** The only Graph scopes that can ever be requested are five
  `DeviceManagement*.Read.All` permissions, matched exactly (no `.default`, no `ReadWrite`, no other
  host, never several at once). Each tool call acquires a token for exactly **one** scope; a tool may
  only use its own group's scope. Sign-in requests only the scopes of the groups you enabled.
- **Microsoft stays the authority.** The Graph access token is treated as opaque: it is never decoded
  or inspected, only sent to Graph, which enforces the user's Intune RBAC and scope tags. Child objects
  (a policy's assignments, a device's states, a role's assignments) are only read after the parent
  object has been read with the same user's token and found visible, on every page, because Graph can
  answer child requests for parents the user cannot see.
- **The model supplies typed arguments, not queries.** Filters are validated against strict patterns
  and enums and rendered into OData by the server. IDs are validated (GUID, or the documented composite
  form) before any token request. Page tokens are bound to one endpoint and one parent.
- **Allowlist-only output.** Every endpoint returns only listed fields; settings tools return only
  typed booleans, numbers and closed enums for a reviewed set of types. Secrets, certificates, URLs,
  scripts, custom OMA values, Wi-Fi/VPN/email profile contents and similar are never selected or
  returned. Responses are bounded in size and rows. Names and descriptions are admin-written text and
  are labelled untrusted: bounded, not redacted.
- **Failures are safe and quiet.** Microsoft and MSAL error text is never echoed or logged; failures
  map to a few fixed categories. Audit lines carry identifiers only (never names, UPNs, filter values
  or tokens), and every value is escaped and length-bounded.
- **Encrypted token cache, fail closed.** See [SETUP.md](SETUP.md#7-encrypted-cache-and-recovery).

## Identity and the MSAL version

MSAL for Python 1.38+ no longer validates ID-token claims itself. The sign-in code therefore checks
the ID token it receives: tenant, exact v2 issuer, audience equal to your client id, a subject, finite
and sane `exp`/`iat`/`nbf` times, and that the object id matches the cached account. It does **not**
verify the ID token's signature. The token is received directly from Microsoft's token endpoint over
TLS, which OpenID Connect Core §3.1.3.7 permits instead of signature validation; trust therefore rests
on the TLS channel (including your machine's CA store and any proxy configuration). The authorization
code flow keeps MSAL's state, PKCE and nonce checks. A failed sign-in clears the cached account(s) it
could have written, and a cancelled or failed one removes only the account it added.

## Scopes and cached tokens

MSAL's cache matches by subset: a cached access token can carry **more** scopes than the one requested
for a call (for example after you enabled several groups at login). The single-scope guarantee is
about what each call *requests*; the token is only ever sent to Graph, and any broader scopes are
limited to those the app has consented and you enabled. Keep the app's permissions minimal.

## Limits you should know about

- **A refresh token lives on each machine**, protected by that user's keychain/DPAPI. Malware or an
  agent running as the same user, or an unlocked session, can use it. Do not run this on shared or
  unmanaged hosts, and do not expose the stdio process through a network wrapper.
- **No central audit log.** Audit events go to the harness's stderr. Entra sign-in and audit logs, and
  **central revocation in Entra** (disable the app, revoke sessions, remove the assignment), remain
  available. Graph output can contain authorised personal data and is visible to the harness, the model
  and any transcript.
- **A user can modify their own copy** and bypass the local read-only, group and tenant checks. They are
  not a boundary against that user. The enforcement is Entra app assignment, consent and Conditional
  Access, plus Intune and Graph RBAC. A client id is not a secret and does not prove client integrity.
- **Entra owns session lifetime.** Cached access can survive assignment removal or session revocation
  until the access token expires; browser SSO can re-authenticate without fresh credentials. No
  continuous access evaluation is added.
- **Guest and external accounts** in your tenant are accepted if Entra lets them sign in; the control
  is *Assignment required* and Conditional Access, not this code.
- **Tenant-wide data.** Some Graph endpoints ignore Intune scope tags and return tenant-wide data to a
  scoped admin. Those tools are opt-in (`INTUNE_ENABLE_TENANT_INVENTORY`) and documented as such.
  Aggregate counts for a visible object may include devices outside the user's scope.
- **Supply chain.** You run code from this repository on your workstation. Pin a reviewed release tag
  and update deliberately. `uvx` and `uv tool install` resolve dependencies from the package metadata,
  not from this repository's `uv.lock`, so transitive versions can resolve anew; audit the installed
  environment too. The update check only displays a validated version number.
- **Network and local services.** A browser sign-in listens briefly on a loopback port; a hung Microsoft
  endpoint is bounded by a 20 s HTTP timeout and a 60 s per-call cap.

## Source evidence

Behaviours above were checked against the pinned sources (MSAL 1.39.0, msal-extensions 1.3.1), not from
memory: refresh tokens are scope-independent and redeemed with the requested scope; the cache's subset
match; `acquire_token_silent` collapsing cache misses and refresh errors to `None` (these become
`sign_in_required`, with no retry into an interactive flow); the account fields used for tenant and
object id; loopback behaviour and the refusal to bind all interfaces inside Docker; and the encrypted
persistence backends. Re-check these before upgrading MSAL, msal-extensions or FastMCP, and run the
full suite.
