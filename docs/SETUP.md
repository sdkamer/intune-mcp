# Setup

Everything here happens once per tenant (steps 1–2) and once per person (steps 3–5).

## 1. Create the Entra app registration

You need a **separate, single-tenant public-client** app registration. Do not reuse an app that has a
client secret or an exposed API.

1. Entra admin center → **App registrations → New registration**. Supported account types:
   *this organizational directory only*.
2. **Authentication → Add a platform → Mobile and desktop applications** with redirect URI
   **`http://localhost`** (no port). Set **Allow public client flows = Yes** (device-code sign-in fails
   after you sign in if this is off). Do not add a Web redirect,
   expose an API, or create a client secret. Leave implicit/hybrid grants off.
3. Copy the **Application (client) ID** and **Directory (tenant) ID**. They are configuration, not
   secrets.
4. Enterprise application → **Properties → Assignment required = Yes**, and assign only the people
   who should use it.
5. Include the app in your Conditional Access / MFA policy. Confirm the effect for browser sign-in
   (and device code, which a policy may deliberately block).
6. Give each person the Intune role and scope tags they should have. Delegated access means Microsoft
   applies *their* Intune permissions; test with a restricted account.

## 2. API permissions

Under **API permissions → Add a permission → Microsoft Graph → Delegated**, add the permissions for
the groups you intend to enable, then **grant admin consent**:

| Permission | Needed for group |
| - | - |
| `DeviceManagementManagedDevices.Read.All` | `devices` (default) |
| `DeviceManagementConfiguration.Read.All` | `configuration` |
| `DeviceManagementApps.Read.All` | `apps` |
| `DeviceManagementRBAC.Read.All` | `rbac` |
| `DeviceManagementServiceConfig.Read.All` | `enrollment` |
| `User.Read` | registration baseline only |

Add only what you need; never an application, `ReadWrite` or privileged-operation permission. Sign-in
requests only the enabled groups' scopes. **Consent a permission before you enable its group**,
otherwise sign-in fails. The `configuration` group's per-device state tools also need the `devices`
group enabled (their parent visibility check uses it).

## 3. Install

Requires Python 3.13 and [`uv`](https://docs.astral.sh/uv/). Pin a release tag:

```sh
export INTUNE_TENANT_ID='<directory-guid>'
export INTUNE_CLIENT_ID='<app-registration-guid>'
export INTUNE_ENABLED_TOOL_GROUPS='devices'   # e.g. devices,configuration,apps,rbac,enrollment

SRC='git+https://github.com/sdkamer/intune-mcp@v0.1.1'
uvx --from "$SRC" intune-mcp login      # opens your browser; then run status
uvx --from "$SRC" intune-mcp status
```

Or install a command: `uv tool install "$SRC"` and run `intune-mcp login`. Use the same OS user,
environment and source for every command and harness (the token cache is per user and per
tenant/app).

## 4. Sign in and the other commands

- `intune-mcp login` — opens the default browser and listens briefly on a loopback port
  (five-minute timeout). It is refused inside Docker.
- `intune-mcp login --device-code` — headless fallback; prints a short code and Microsoft's
  verification address on stderr. It still needs the encrypted keychain.
  Use it when you cannot reach the machine's browser (for example when working remotely): enter the
  code at the printed address on any device. If sign-in fails, the message ends with Microsoft's numeric
  `AADSTS` code, which an administrator can look up (common ones: 7000218 public client flows off,
  65001 consent missing, 50076/50158 MFA, 53000/53003 Conditional Access).
- `intune-mcp status` — checks that exactly one tenant-matching account is cached, and lists which tool
  groups are enabled and which are not. It does **not**
  prove consent, assignment, Graph access or that the refresh token is still valid.
- `intune-mcp serve` (the default) — the stdio MCP server the harness runs. Tool calls never open a
  browser: if you are not signed in they return `sign_in_required`; run `login` in a terminal, then
  restart or reconnect the harness.
- `intune-mcp logout` — removes this app's cached account and tokens **locally**. It does not revoke
  your Entra session. Stop every harness first; to switch accounts, log out, log in, restart.
- After you change `INTUNE_ENABLED_TOOL_GROUPS`, run `login` again and reconnect the harness.

## 5. Connect your harness

Export the `INTUNE_*` variables in the environment that launches the harness (GUI apps may not
inherit terminal exports). Only configuration is passed, never a token or secret. These snippets show
the shape; they have not been tested live against every harness.

**Pi** — `~/.pi/agent/mcp.json`, then `/reload` or reconnect in `/mcp` (Pi's `mcp login` is for
remote OAuth servers; use `intune-mcp login` instead):

```json
{
  "mcpServers": {
    "intune": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/sdkamer/intune-mcp@v0.1.1", "intune-mcp", "serve"],
      "env": {
        "INTUNE_TENANT_ID": "${INTUNE_TENANT_ID}",
        "INTUNE_CLIENT_ID": "${INTUNE_CLIENT_ID}",
        "INTUNE_ENABLED_TOOL_GROUPS": "${INTUNE_ENABLED_TOOL_GROUPS}"
      }
    }
  }
}
```

**Claude Code** — the same JSON in a trusted project's `.mcp.json`, or after `uv tool install`:

```sh
claude mcp add --transport stdio --scope user intune -- intune-mcp serve
```

**Codex CLI** — `~/.codex/config.toml`:

```toml
[mcp_servers.intune]
command = "uvx"
args = ["--from", "git+https://github.com/sdkamer/intune-mcp@v0.1.1", "intune-mcp", "serve"]
env_vars = ["INTUNE_TENANT_ID", "INTUNE_CLIENT_ID", "INTUNE_ENABLED_TOOL_GROUPS"]
```

## 6. Updating

Harnesses do not tell you about new versions. The server checks GitHub's public releases API once a
day in the background and, when a newer release exists, shows the version in `whoami`,
`intune-mcp status` and the server instructions (the assistant may mention it). To update, change the
tag in your configuration (`@v0.1.1` → the new tag) and restart the harness. Disable the check with
`INTUNE_UPDATE_CHECK=0`. The only thing sent is a plain GET with a `User-Agent` naming this version.

## 7. Encrypted cache and recovery

Tokens are stored via `msal-extensions` in **macOS Keychain**, **Windows user DPAPI** or **Linux
libsecret**. On Linux you need an unlocked desktop Secret Service and PyGObject (`gi`) with the Secret
bindings visible to the Python environment `uvx` creates (see the
[extension's Linux guidance](https://github.com/AzureAD/microsoft-authentication-extensions-for-python/wiki/Encryption-on-Linux)).
Do not install an unreviewed plaintext keyring fallback to make headless login work: startup checks
encryption with a locked write/read round trip and **fails closed** with a fixed message if it cannot.
An SSH-only Linux host with no secret service is not supported.

The cache location is namespaced by tenant and app under your per-user data directory
(`intune-mcp`), created `0700`. On macOS and Linux the file is only a change signal; the payload is in
the OS secret store.

**If startup or `logout` says the local operation is unavailable and `login` does not fix it**, the
stored payload cannot be read. Close every harness using the server, remove the stored secret yourself
(macOS: delete the `intune-mcp` item for this tenant/app in Keychain Access; Linux: delete the matching
Secret Service entry; Windows: delete the cache file for this tenant and client id under
`%LOCALAPPDATA%\intune-mcp` and any `.lockfile` beside it), then run `intune-mcp login` again.
