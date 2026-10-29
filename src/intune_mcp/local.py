"""Sign-in and the stdio entry point: one OS user, MSAL public client, encrypted token cache."""

import argparse
import asyncio
import logging
import math
import os
import re
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastmcp.exceptions import ToolError
from pydantic import ValidationError

from . import updates
from .config import GRAPH_SCOPE, Settings
from .graph import GraphError, ScopeNotAllowedError, classify_token_failure, require_known_scope
from .groups import TOOL_GROUPS, authorize_scopes
from .identity import Identity
from .server import build_server

SIGN_IN = "Run intune-mcp login (logout first to switch accounts)"
# Network bounds: MSAL passes no timeout to requests by default, so a hung authority would block.
HTTP_TIMEOUT = 20  # seconds, per MSAL HTTP request
SILENT_TIMEOUT = 60  # seconds, whole silent acquisition incl. a possible discovery + refresh
CACHE_ERROR = (
    "Encrypted token cache unavailable. Unlock/configure macOS Keychain, Windows DPAPI, or "
    "Linux libsecret and its desktop secret service. Plaintext fallback is forbidden"
)


LOCK_ERROR = (
    "The token cache is locked by another run, or a previous run was killed while holding the "
    "lock. "
    "Stop every intune-mcp process (including harness servers); if it persists, delete the "
    "'.lockfile' next to the cache in the intune-mcp data directory, then try again"
)


class LocalError(Exception):
    """Fixed, safe startup/CLI message; never wrap external exception text."""


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, force=True)
    # No HTTP URLs, account data, token bodies, or upstream error descriptions in logs.
    for name in (
        "msal",
        "msal_extensions",
        "azure",
        "httpx",
        "httpcore",
        "httpx2",
        "httpcore2",
        "requests",
        "urllib3",
    ):
        logging.getLogger(name).setLevel(logging.CRITICAL + 1)


class CheckedPersistence:
    """Require encryption, and detect even libsecret's non-raising failed save path."""

    is_encrypted = True

    def __init__(self, persistence):
        if persistence.is_encrypted is not True:
            raise LocalError(CACHE_ERROR)
        self.backend = persistence

    def save(self, content):
        self.backend.save(content)
        if self.backend.load() != content:
            raise LocalError(CACHE_ERROR)

    def load(self):
        return self.backend.load()

    def time_last_modified(self):
        return self.backend.time_last_modified()

    def get_location(self):
        return self.backend.get_location()


def _clear_stale_lock(lock_path: str) -> None:
    """Remove a cache lockfile left by a process that no longer exists.

    msal-extensions records the holder's pid in the lockfile and never cleans up after a process
    killed mid-startup (harnesses routinely kill short-lived servers). Only a lockfile whose pid is
    provably dead is removed; anything unreadable, live or foreign is left alone and fails safe.
    Skipped on Windows, where os.kill(pid, 0) would terminate the process instead of probing it.
    """
    if sys.platform == "win32":
        return
    try:
        path = Path(lock_path)
        content = path.read_text()
        first = content.split(None, 1)[0] if content.split() else ""
        pid = int(first) if first.isascii() and first.isdigit() and len(first) <= 10 else 0
        if pid <= 0 or pid == os.getpid():
            return
        try:
            os.kill(pid, 0)
            return  # alive
        except ProcessLookupError:
            pass
        except OSError:
            return  # exists but not ours (PermissionError) or unknowable: leave it
        if path.read_text() == content:  # unchanged since we looked: not a fresh holder
            path.unlink(missing_ok=True)
    except (OSError, ValueError, OverflowError):
        return


def encrypted_cache(settings: Settings):
    """OS-managed encryption only. Test read/write under the same cross-process cache lock."""
    try:
        from msal_extensions import PersistedTokenCache, build_encrypted_persistence
        from msal_extensions.persistence import PersistenceNotFound
        from msal_extensions.token_cache import CrossPlatLock
        from platformdirs import user_data_path

        directory = user_data_path("intune-mcp", appauthor=False)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            directory.chmod(0o700)  # also tighten a directory that already existed
        except OSError:
            pass
        location = str(directory / f"{settings.tenant_id}-{settings.client_id}.cache")
        persistence = CheckedPersistence(build_encrypted_persistence(location))
        _clear_stale_lock(location + ".lockfile")
        with CrossPlatLock(location + ".lockfile"):
            try:
                content = persistence.load()
            except PersistenceNotFound:
                content = "{}"
            persistence.save(content)
        return PersistedTokenCache(persistence)
    except Exception as exc:
        # By name: msal-extensions' lock error is LockError (file lock) or portalocker's
        # LockException, depending on what is installed.
        locked = type(exc).__name__ in ("LockError", "LockException")
        raise LocalError(LOCK_ERROR if locked else CACHE_ERROR) from None


@dataclass(frozen=True)
class LocalCaller:
    account: dict[str, Any] = field(repr=False)


def account_identity(account: dict, settings: Settings) -> Identity:
    try:
        tenant = str(uuid.UUID(account["realm"]))
        oid = str(uuid.UUID(account["local_account_id"]))
        if tenant != str(settings.tenant_id):
            raise ValueError
        home = account.get("home_account_id")
        if not isinstance(home, str) or not home:
            raise ValueError
        return Identity(tenant, oid, home)
    except (ValueError, TypeError, KeyError, AttributeError):
        raise GraphError("sign_in_required", SIGN_IN) from None


def validate_id_claims(claims: object, settings: Settings) -> dict:
    """Claims delivered by MSAL over HTTPS, not a Graph-token decode or signature verifier.

    MSAL 1.39 no longer performs ID claim validation itself. Enforce our local boundary;
    MSAL owns token-endpoint TLS, authorization-code PKCE/state/nonce and device polling.
    """
    try:
        if not isinstance(claims, dict):
            raise ValueError
        if (
            claims.get("tid") != str(settings.tenant_id)
            or claims.get("aud") != str(settings.client_id)
            or claims.get("iss") != f"https://login.microsoftonline.com/{settings.tenant_id}/v2.0"
            or not isinstance(claims.get("sub"), str)
            or not claims["sub"]
        ):
            raise ValueError
        now = time.time()
        for key in ("exp", "iat"):
            value = claims.get(key)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
            ):
                raise ValueError
        if claims["exp"] <= now or claims["iat"] > now + 60:
            raise ValueError
        if "nbf" in claims:
            value = claims["nbf"]
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value > now + 60
            ):
                raise ValueError
        return claims
    except (ValueError, TypeError, KeyError):
        raise GraphError("sign_in_required", "Sign-in identity rejected. " + SIGN_IN) from None


def groups_hint(settings: Settings) -> str:
    """Which tool groups are on and how to get more. Group names only; nothing from the tenant."""
    enabled = settings.enabled_groups
    others = sorted(set(TOOL_GROUPS) - set(enabled))
    text = f"Enabled tool groups: {', '.join(enabled)}."
    if others:
        text += (
            f" Not enabled: {', '.join(others)}. To add one, consent its Graph permission, set"
            " INTUNE_ENABLED_TOOL_GROUPS (comma-separated), run login again and restart"
            " the harness."
        )
    return text


def require_loopback_browser() -> None:
    # Pinned MSAL otherwise binds 0.0.0.0 inside Docker. Never allow that listener here.
    from msal.oauth2cli.authcode import _is_inside_docker

    if _is_inside_docker():
        raise LocalError("Browser login requires a local desktop; use login --device-code")


_ERROR_NAME = re.compile(r"[a-z_]{1,40}", re.ASCII)
_TYPE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,60}", re.ASCII)


def error_detail(result: object) -> str:
    """A short, safe diagnostic: a closed-form OAuth error name and numeric AADSTS codes only.

    Never Microsoft's description, claims or correlation data. Admins need the number to look it up.
    """
    if not isinstance(result, dict):
        return ""
    parts = []
    name = result.get("error")
    if isinstance(name, str) and _ERROR_NAME.fullmatch(name):
        parts.append(f"error={name}")
    codes = result.get("error_codes")
    if isinstance(codes, (list, tuple)):
        digits = [
            str(c)
            for c in codes[:5]
            if isinstance(c, int) and not isinstance(c, bool) and 1000 <= c <= 9_999_999
        ]
        if digits:
            parts.append("AADSTS" + ",".join(digits))
    return f" [{' '.join(parts)}]" if parts else ""


def msal_failure(result: object) -> GraphError:
    """Use only numeric error codes or closed OAuth error names, never Microsoft text."""
    if not isinstance(result, dict):
        return GraphError("sign_in_required", SIGN_IN)
    codes = result.get("error_codes")
    exc = Exception()
    exc.error_codes = codes  # Existing safe numeric classifier; no error_description scanned.
    mapped = classify_token_failure(exc)
    if mapped.code == "graph_exchange_failed":
        if result.get("error") in ("interaction_required", "login_required"):
            return GraphError("graph_interaction_required", SIGN_IN)
        if result.get("error") == "consent_required":
            return GraphError("graph_consent_required", "Ask an administrator to confirm consent")
        if result.get("error") == "invalid_grant":
            return GraphError("graph_access_revoked", SIGN_IN)
    return GraphError(mapped.code, mapped.message + error_detail(result) + ". " + SIGN_IN)


class Session:
    def __init__(self, settings: Settings, app):
        self.settings = settings
        self.app = app
        self.scopes = authorize_scopes(settings.enabled_groups)
        # Serializes refresh network calls in worker threads ONLY. Never taken on the event loop,
        # so a slow refresh cannot freeze the stdio server (caller() and whoami stay responsive).
        self.refresh_lock = threading.Lock()

    def _caller(self) -> tuple[LocalCaller, Identity]:
        accounts = self.app.get_accounts()
        # No username selector or first-account fallback. One cache per tenant/app/OS user.
        if len(accounts) != 1:
            raise GraphError("sign_in_required", SIGN_IN)
        account = accounts[0]
        return LocalCaller(account), account_identity(account, self.settings)

    def caller(self) -> tuple[LocalCaller, Identity]:
        try:
            return self._caller()
        except GraphError as exc:
            raise ToolError(f"{exc.code}: {exc.message} (ref {uuid.uuid4()})") from None
        except Exception:
            raise ToolError(f"sign_in_required: {SIGN_IN} (ref {uuid.uuid4()})") from None

    async def token_for(self, caller: LocalCaller, identity: Identity, scope: str = GRAPH_SCOPE):
        require_known_scope(scope)  # The closed scope allowlist, before any MSAL call.
        if scope not in self.scopes:
            raise ScopeNotAllowedError("requested scope belongs to a disabled group")

        def silent():
            try:
                with self.refresh_lock:
                    current, current_identity = self._caller()
                    if current_identity != identity or current.account != caller.account:
                        raise GraphError("sign_in_required", SIGN_IN)
                    # Exactly one allowlisted Graph scope; never interactive from a tool.
                    result = self.app.acquire_token_silent([scope], account=current.account)
            except GraphError:
                raise
            except Exception as exc:
                mapped = classify_token_failure(exc)
                raise GraphError(mapped.code, mapped.message + ". " + SIGN_IN) from None
            if not isinstance(result, dict) or "error" in result:
                raise msal_failure(result)
            token, expiry = result.get("access_token"), result.get("expires_in")
            if (
                not isinstance(token, str)
                or not token
                or isinstance(expiry, bool)
                or not isinstance(expiry, (int, float))
                or not math.isfinite(expiry)
                or expiry <= 0
            ):
                raise GraphError(
                    "graph_token_invalid", "Microsoft returned an unusable Graph token"
                )
            # No decode, no claim inspection; cache/Entra may return a scope superset.
            return token

        try:
            return await asyncio.wait_for(asyncio.to_thread(silent), SILENT_TIMEOUT)
        except TimeoutError:
            raise GraphError(
                "graph_exchange_failed", "Microsoft sign-in timed out. " + SIGN_IN
            ) from None

    def _discard_accounts(self, keep: set | None = None) -> None:
        """Best effort: drop cached accounts (all, or those not in `keep`) after a failed sign-in.

        MSAL writes tokens to the cache before our claim checks run, so a rejected or aborted
        sign-in must not leave its account usable by the tool path.
        """
        try:
            for account in self.app.get_accounts():
                if keep is None or account.get("home_account_id") not in keep:
                    self.app.remove_account(account)
        except Exception:
            pass

    def login(self, *, device_code: bool = False) -> None:
        try:
            before = {a.get("home_account_id") for a in self.app.get_accounts()}
        except Exception:
            raise LocalError(CACHE_ERROR) from None
        try:
            if device_code:
                flow = self.app.initiate_device_flow(scopes=self.scopes)
                if not isinstance(flow, dict) or "user_code" not in flow:
                    raise msal_failure(flow)
                # Only the user-facing challenge, never MSAL's free-form message/device_code.
                code = flow["user_code"]
                if (
                    not isinstance(code, str)
                    or not code
                    or len(code) > 32
                    or not all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-" for c in code)
                ):
                    raise GraphError("graph_exchange_failed", "Invalid device challenge")
                print(f"Open https://microsoft.com/devicelogin and enter {code}", file=sys.stderr)
                result = self.app.acquire_token_by_device_flow(flow)
            else:
                require_loopback_browser()
                result = self.app.acquire_token_interactive(
                    scopes=self.scopes, prompt="select_account", timeout=300
                )
            if not isinstance(result, dict) or "error" in result or not result.get("access_token"):
                raise msal_failure(result)
            try:
                # MSAL token-endpoint ID claims, NEVER Graph access-token claims.
                claims = validate_id_claims(result.get("id_token_claims"), self.settings)
                _, identity = self._caller()
                if claims.get("oid") != identity.object_id:
                    raise GraphError("sign_in_required", SIGN_IN)
            except BaseException:
                self._discard_accounts()  # tokens that failed validation must not remain usable
                raise
        except BaseException as exc:
            self._discard_accounts(before)  # a failed or aborted sign-in leaves no new account
            if not isinstance(exc, Exception) or isinstance(exc, (GraphError, LocalError)):
                raise
            mapped = classify_token_failure(exc)
            kind = type(exc).__name__
            hint = f" [{kind}]" if _TYPE_NAME.fullmatch(kind) else ""
            raise GraphError(mapped.code, mapped.message + hint + ". " + SIGN_IN) from None

    def logout(self) -> None:
        # MSAL removes this app's cached account credentials, including refresh tokens.
        for account in self.app.get_accounts():
            self.app.remove_account(account)


def create_session(settings: Settings) -> Session:
    cache = encrypted_cache(settings)  # Fail before authority discovery or interactive sign-in.
    try:
        from msal import PublicClientApplication

        app = PublicClientApplication(
            str(settings.client_id),
            authority=f"https://login.microsoftonline.com/{settings.tenant_id}",
            token_cache=cache,
            enable_pii_log=False,
            enable_broker_on_windows=False,
            enable_broker_on_mac=False,
            timeout=HTTP_TIMEOUT,
        )
        return Session(settings, app)
    except Exception:
        raise LocalError(
            "Local authentication unavailable; check public-client configuration"
        ) from None


def main(argv: list[str] | None = None) -> int:
    configure_logging()
    parser = argparse.ArgumentParser(prog="intune-mcp")
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("serve", help="MCP stdio (default)")
    login = commands.add_parser("login", help="Interactive sign-in outside the harness")
    login.add_argument("--device-code", action="store_true", help="Headless fallback")
    commands.add_parser("logout", help="Remove locally cached credentials; not central revocation")
    commands.add_parser("status", help="Check cached account only; does not test Graph access")
    parser.add_argument("--version", action="version", version=updates.current_version())
    args = parser.parse_args(argv)
    try:
        settings = Settings()
        session = create_session(settings)
        if args.command == "login":
            session.login(device_code=args.device_code)
            print("Signed in (Graph access UNVERIFIED LIVE).", file=sys.stderr)
        elif args.command == "logout":
            session.logout()
            print("Local credentials removed. Entra sessions are not revoked.", file=sys.stderr)
        elif args.command == "status":
            session.caller()
            print("One tenant-matching cached account; access/expiry not checked.", file=sys.stderr)
            print(f"intune-mcp {updates.current_version()}", file=sys.stderr)
            print(groups_hint(settings), file=sys.stderr)
            updates.refresh()
            newer = updates.update_available()
            if newer:
                print(f"Update available: {newer}", file=sys.stderr)
        else:
            updates.refresh_in_background()
            mcp = build_server(
                settings,
                token_source=session,
                identity_provider=session.caller,
                version=updates.current_version(),
                update_available=updates.update_available,
            )
            mcp.run(transport="stdio", show_banner=False, log_level="WARNING")
        return 0
    except ValidationError:
        print(
            "Invalid local configuration. Set INTUNE_TENANT_ID and INTUNE_CLIENT_ID to GUIDs; "
            "check INTUNE_ENABLED_TOOL_GROUPS and INTUNE_ENABLE_TENANT_INVENTORY.",
            file=sys.stderr,
        )
    except (LocalError, ToolError) as exc:
        print(str(exc), file=sys.stderr)
    except GraphError as exc:
        print(f"{exc.code}: {exc.message} (ref {uuid.uuid4()})", file=sys.stderr)
    except Exception:
        print(f"Local operation unavailable (ref {uuid.uuid4()})", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
