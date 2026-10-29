"""Optional, non-blocking check for a newer release.

Privacy and safety rules:
- One unauthenticated GET to the public GitHub releases API, about once a day, in a background
  thread (size-capped while streaming, with a total deadline). No account, tenant or machine
  data is sent, only a User-Agent naming this version.
- Turn it off with INTUNE_UPDATE_CHECK=0.
- Only a strictly validated X.Y.Z version number is ever stored or shown. Release names, notes
  and URLs are never read into anything the model or the user sees (an injection channel).
- Every failure is silent: the check never blocks, raises or changes behaviour.
"""

import json
import os
import re
import tempfile
import threading
import time
from importlib import metadata
from pathlib import Path

import httpx2 as httpx
from platformdirs import user_cache_path

REPO = "sdkamer/intune-mcp"
CHECK_TTL_SECONDS = 24 * 3600
REQUEST_TIMEOUT_SECONDS = 3
TOTAL_DEADLINE_SECONDS = 5
ATTEMPT_LOCK_SECONDS = 120
MAX_RESPONSE_BYTES = 262_144
_VERSION = re.compile(r"v?([0-9]{1,4})\.([0-9]{1,4})\.([0-9]{1,4})", re.ASCII)


def current_version() -> str:
    try:
        return metadata.version("intune-mcp")
    except metadata.PackageNotFoundError:
        return "0.0.0"


def parse_version(text: object) -> tuple[int, int, int] | None:
    """Strict MAJOR.MINOR.PATCH (optional leading v), ASCII digits only; anything else is None."""
    match = _VERSION.fullmatch(text) if isinstance(text, str) else None
    return tuple(int(part) for part in match.groups()) if match else None


def enabled() -> bool:
    return os.environ.get("INTUNE_UPDATE_CHECK", "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def _cache_file() -> Path:
    return user_cache_path("intune-mcp", appauthor=False) / "latest-release.json"


def _read_cache() -> dict:
    try:
        data = json.loads(_cache_file().read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def cached_latest() -> str | None:
    """The newest known version from the local cache (no network), or None."""
    version = _read_cache().get("version")
    parsed = parse_version(version)
    return ".".join(map(str, parsed)) if parsed else None


def update_available(current: str | None = None) -> str | None:
    """A strictly validated newer version string, or None. Never touches the network."""
    if not enabled():
        return None
    latest, running = parse_version(cached_latest()), parse_version(current or current_version())
    if latest and running and latest > running:
        return ".".join(map(str, latest))
    return None


def _write_cache(version: str | None) -> None:
    directory = _cache_file().parent
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = {"checked": int(time.time())}
    if version:
        payload["version"] = version
    handle, name = tempfile.mkstemp(dir=directory, prefix="latest-", suffix=".tmp")
    try:
        with os.fdopen(handle, "w") as out:
            json.dump(payload, out)
        os.replace(name, _cache_file())
    except OSError:
        Path(name).unlink(missing_ok=True)


def _fetch_latest(client: httpx.Client | None) -> str | None:
    """One bounded request: decoded bytes are capped while streaming, with a total deadline."""
    owned = client is None
    client = client or httpx.Client(timeout=REQUEST_TIMEOUT_SECONDS, follow_redirects=False)
    try:
        deadline = time.monotonic() + TOTAL_DEADLINE_SECONDS
        chunks, size = [], 0
        with client.stream(
            "GET",
            f"https://api.github.com/repos/{REPO}/releases/latest",
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": f"intune-mcp/{current_version()}",
            },
        ) as response:
            if response.status_code != 200:
                return None
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES or time.monotonic() > deadline:
                    return None
                chunks.append(chunk)
    finally:
        if owned:
            client.close()
    body = json.loads(b"".join(chunks))
    parsed = parse_version(body.get("tag_name")) if isinstance(body, dict) else None
    return ".".join(map(str, parsed)) if parsed else None


def _claim_attempt() -> Path | None:
    """Best-effort cross-process admission: one process fetches, others skip for a short while."""
    lock = _cache_file().with_suffix(".lock")
    try:
        lock.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            if time.time() - lock.stat().st_mtime < ATTEMPT_LOCK_SECONDS:
                return None
            lock.unlink(missing_ok=True)  # a crashed or stuck attempt left it behind
        except FileNotFoundError:
            pass
        os.close(os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
        return lock
    except OSError:
        return None


def refresh(*, client: httpx.Client | None = None) -> None:
    """Fetch the latest release tag if the cache is older than a day. Silent on any failure."""
    if not enabled():
        return
    try:
        checked = _read_cache().get("checked")
        if isinstance(checked, int) and 0 <= time.time() - checked < CHECK_TTL_SECONDS:
            return
        lock = _claim_attempt()
        if lock is None:
            return
        try:
            try:
                version = _fetch_latest(client)
            except Exception:
                version = None
            # Always record the attempt so a failing check backs off for a day; keep a version
            # learned earlier instead of forgetting it because one check failed.
            _write_cache(version or cached_latest())
        finally:
            lock.unlink(missing_ok=True)
    except Exception:
        return


def refresh_in_background() -> None:
    if not enabled():
        return
    try:
        threading.Thread(target=refresh, name="intune-mcp-update-check", daemon=True).start()
    except Exception:
        return  # an optional check must never stop the server from starting
