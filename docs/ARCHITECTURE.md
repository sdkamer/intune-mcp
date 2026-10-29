# Architecture

```
harness (Claude Code / Codex / Pi) ──stdio──> intune-mcp serve ──HTTPS──> Microsoft Graph (v1.0)
                                                  │
                                       MSAL public client ──> Microsoft Entra (sign-in, refresh)
                                                  │
                                       OS keychain (encrypted token cache)
```

- `local.py` – sign-in, the encrypted cache, silent token acquisition (one allowlisted scope per
  call), identity from the cached account, the CLI (`login`, `logout`, `status`, `serve`).
- `server.py` – FastMCP server; every tool call goes through one `run` path that validates input first,
  acquires the token for the tool's single scope, performs the parent visibility check when the
  endpoint has a parent, calls Graph, and audits. Tool groups are registered only when enabled.
- `groups.py` – the groups, their tools and their single scopes (checked against the closed allowlist).
- `graph.py` – the generic, safe read layer: endpoint specs (path, scope, field allowlist, typed
  filters), request building, size and row bounds, page tokens, and the safe error mapping.
- `tools_*.py` – thin per-group tool definitions over the read layer.
- `updates.py` – the optional daily release check.

Design rules: the model never supplies OData; every endpoint is a declared spec; output is allowlist
only; Microsoft is the access-control authority; failures never echo upstream text. Details and limits:
[SECURITY-MODEL.md](SECURITY-MODEL.md).
