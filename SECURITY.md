# Security policy

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** for this repository (Security tab →
"Report a vulnerability"). Do not open a public issue for a suspected vulnerability, and never include
tokens, tenant data or other credentials in a report.

## Scope

In scope: the server in this repository, in particular anything that could let it return data a user
should not see, widen its Graph permissions, log or expose tokens, write to a tenant, or accept a
different identity than the signed-in account.

Out of scope: weaknesses in Microsoft Entra, Microsoft Graph, MSAL, the operating system keychain, or
a compromised user session on the same machine. The security model, including its limits, is in
[docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md).

## Supported versions

Only the latest release is supported while the project is pre-1.0.
