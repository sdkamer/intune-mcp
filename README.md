# intune-mcp

A **read-only** [Model Context Protocol](https://modelcontextprotocol.io) server for Microsoft Intune
that runs **on your own machine** and signs in as **you**. Harnesses such as Claude Code, Codex CLI
and Pi start it as a local process; it answers questions about devices, policies, apps, enrollment
and RBAC using your own delegated Microsoft Graph access, so results reflect what *you* may see in
Intune.

- **Nothing to host.** No public endpoint, no client secret, no server to patch. It speaks MCP over
  stdio to the harness that launched it.
- **Delegated and per-user.** You sign in with Microsoft (MSAL public client, browser or device code).
  There is no app-only or shared credential path. Intune RBAC and scope tags are enforced by Microsoft.
- **Read-only by construction.** Only `*.Read.All` Graph scopes are in a closed allowlist; there is no
  write tool and no ReadWrite scope. Each tool call acquires a token for exactly one scope.
- **Small, typed surface.** The model never writes OData. Inputs are validated before any token
  request; results come back through per-endpoint field allowlists (no secrets, scripts, URLs,
  certificates or credentials), bounded in size, with untrusted text labelled as data.
- **Tokens stay encrypted.** The token cache uses the OS keychain (macOS Keychain, Windows DPAPI,
  Linux libsecret). If encryption is unavailable it refuses to run; there is no plaintext fallback.

> **Status: v0.1, early.** The Graph layer and tools have been exercised against a real tenant
> through an earlier hosted deployment of the same code, and the local sign-in path has had one live
> check (macOS, device-code login, Pi). Browser login, other harnesses and platforms, and restricted
> users are **not yet verified**. See
> [docs/VERIFICATION.md](docs/VERIFICATION.md) for exactly what has and has not been checked.
> Not affiliated with or endorsed by Microsoft.

## Quick start

1. Create an Entra app registration and consent the Graph permissions: [docs/SETUP.md](docs/SETUP.md).
2. Install and sign in (pinned to a release tag):

   ```sh
   export INTUNE_TENANT_ID='<directory-guid>'
   export INTUNE_CLIENT_ID='<app-registration-guid>'
   uvx --from git+https://github.com/sdkamer/intune-mcp@v0.1.0 intune-mcp login
   ```

3. Point your harness at `uvx --from git+https://github.com/sdkamer/intune-mcp@v0.1.0 intune-mcp serve`
   (examples for Pi, Claude Code and Codex CLI are in the setup guide).

Requires Python 3.13 and [`uv`](https://docs.astral.sh/uv/).

## Tools

> **A fresh install enables only the `devices` group (6 tools with `whoami`).** Everything else is
> opt-in: consent the group's Graph permission, set `INTUNE_ENABLED_TOOL_GROUPS` (for example
> `devices,configuration,apps,rbac,enrollment`), run `intune-mcp login` again, and restart your
> harness. `intune-mcp status` and the `whoami` tool both list the groups that are on.

Whoami plus five groups; only `devices` is on by default. Enable more with
`INTUNE_ENABLED_TOOL_GROUPS` (for example `devices,configuration,apps`). Each group needs its Graph
permission consented first.

| Group (permission) | Tools |
| - | - |
| `devices` (`DeviceManagementManagedDevices.Read.All`) | `list_devices`, `get_device`, `search_devices`, `count_devices`, `device_summary` |
| `configuration` (`…Configuration.Read.All`) | per-device compliance and configuration states; compliance policies and configuration profiles (list, get, allowlisted settings, status overview, assignments); compliance and configuration summaries |
| `apps` (`…Apps.Read.All`) | apps and assignments; app protection policies; app categories; app configuration policies |
| `rbac` (`…RBAC.Read.All`) | role definitions, role assignments |
| `enrollment` (`…ServiceConfig.Read.All`) | enrollment configurations and assignments, Apple push certificate status, terms and conditions |

41 tools with every group enabled. Three more are **opt-in** because Graph returns tenant-wide data
that ignores a scoped admin's Intune scope: `list_detected_apps`, `get_detected_app` and
`list_compliance_setting_state_summaries` (`INTUNE_ENABLE_TENANT_INVENTORY=true`).
Per-tool details, returned and excluded fields: [docs/tools/](docs/tools/).

## Security

How it works and what it does not protect against: [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md).
To report a vulnerability see [SECURITY.md](SECURITY.md).

## Updates

The server checks the public GitHub releases API about once a day (in the background, never
blocking) and, if a newer release exists, shows the version number in `whoami`, `intune-mcp status`
and the server instructions. Only a strictly validated version number is ever shown. Turn it off with
`INTUNE_UPDATE_CHECK=0`. Harnesses do not notify you themselves: update by changing the pinned tag in
your configuration.

## License

Apache License 2.0: see [LICENSE](LICENSE). Not affiliated with or endorsed by Microsoft.

## Development

```sh
uv sync
uv run pytest -q            # all mocked; no network
uv run ruff check . && uv run ruff format --check .
```

Tests use an in-process harness with a stubbed Microsoft Graph and a fake local identity. Everything
in the suite is mocked; it proves the policy and plumbing, not Microsoft's behaviour.
