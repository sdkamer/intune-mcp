# Changelog

## Unreleased

- A cache lockfile left behind by a killed process is detected and removed at startup (macOS and Linux),
  and a lock problem now has its own message instead of the misleading keychain one.

## 0.1.1

- `intune-mcp status` and the `whoami` tool now list which tool groups are enabled, and `status` says how
  to enable the others. A fresh install enables only the `devices` group (6 tools with `whoami`); the
  README and setup guide now say so.
- Failed sign-ins print Microsoft's numeric `AADSTS` code and a closed error name (never Microsoft's text),
  so an administrator can look the cause up; the setup guide lists the common codes.
- Documentation: first live checks of the local sign-in path (device-code login on macOS with Pi) and of a
  scope-tag-restricted user running the published install (see docs/VERIFICATION.md).

## 0.1.0

First release: a local, read-only Intune MCP server with delegated per-user sign-in (MSAL public
client), encrypted token cache, closed Graph read-scope allowlist, per-endpoint field allowlists,
five opt-in tool groups (41 tools) and three opt-in tenant-wide tools, and an optional daily
release check. The sign-in path has not yet been verified live (see docs/VERIFICATION.md).
