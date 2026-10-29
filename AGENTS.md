# Agent instructions

Read-only Microsoft Intune MCP server that runs locally (stdio) with delegated per-user access.
Keep the repository generic: no tenant IDs, hostnames, credentials, personal data or internal
infrastructure details in code, docs, tests or examples.

## Commands

```sh
uv sync --frozen
uv run pytest -q
uv run ruff check . && uv run ruff format --check .
uv build
```

## Conventions

- Everything in the test suite is mocked (Graph stub, fake identity, fake MSAL). Never describe mocked
  results as live verification; record live results in `docs/VERIFICATION.md` separately.
- Every security fix gets a regression test that fails without the fix.
- Security rules: no app-only or shared credential path; identity comes from the signed-in account,
  never model input; fail closed. The Graph access token is opaque (never decode it). Never log tokens,
  names or UPNs; audit values go through `audit_value`. Validate tool inputs before any token request.
  Only `*.Read.All` scopes from the closed allowlist, one scope per token request. Output is
  allowlist-only per endpoint; add a hostile-input test when adding fields.
- New endpoints: Microsoft Graph v1.0 only, verified on Microsoft Learn; a child endpoint needs the
  parent visibility check on every page.
- FastMCP, MSAL and msal-extensions are pinned and a few internals are relied on deliberately; re-run
  the whole suite and re-check the cited behaviours (docs/SECURITY-MODEL.md) when upgrading.
- Do not push, publish or create releases without the user's explicit instruction.
