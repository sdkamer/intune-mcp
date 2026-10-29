"""Delegated Microsoft Graph access for read-only Intune managed-device queries.

Every call carries the calling user's own Graph token. No shared or app-only credential exists.
"""

import asyncio
import base64
import json
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from http.cookiejar import DefaultCookiePolicy
from typing import Any, Protocol
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import httpx2 as httpx

from .config import (
    APPS_SCOPE,
    CONFIGURATION_SCOPE,
    GRAPH_SCOPE,
    KNOWN_READ_SCOPES,
    RBAC_SCOPE,
    SERVICE_CONFIG_SCOPE,
)
from .identity import Identity

GRAPH_HOST = "graph.microsoft.com"
GRAPH_API_PREFIX = "/v1.0"
GRAPH_BASE = f"https://{GRAPH_HOST}{GRAPH_API_PREFIX}"

# Deliberately excludes email, phone, IMEI/MEID and other personal or sensitive identifiers.
LIST_FIELDS = (
    "id",
    "deviceName",
    "operatingSystem",
    "osVersion",
    "complianceState",
    "managedDeviceOwnerType",
    "lastSyncDateTime",
)
DETAIL_FIELDS = (
    *LIST_FIELDS,
    "managementState",
    "enrolledDateTime",
    "manufacturer",
    "model",
    "serialNumber",
    "userPrincipalName",
    "isEncrypted",
)
DEVICE_DATETIME_FIELDS = ("lastSyncDateTime", "enrolledDateTime")  # picked as timestamps or null
MAX_PAGE_SIZE = 100
# Graph sub-collections (assignments, per-device states) may ignore $top, so a page can hold more
# rows than asked for. Up to this many are accepted and ALL are returned (never silently cut: with
# no nextLink the rest would be invisible); the response-size cap still applies; more fails closed.
MAX_ROWS_PER_PAGE = 1000
# count_devices counts rows Graph actually returns to the caller (never $count, which ignores
# Intune scope tags). The walk stops at whichever limit is hit first and then reports "at least n".
MAX_COUNT_ROWS = 5000
MAX_COUNT_PAGES = 60
# Whole-walk budget and per-process concurrency for count walks (each walk can issue up to
# MAX_COUNT_PAGES sequential Graph requests). Past the deadline the result is "at least n".
MAX_COUNT_SECONDS = 30.0
MAX_CONCURRENT_COUNTS = 4
# Free text from Graph is admin-written, untrusted data: capped per field (see _text).
MAX_TEXT_CHARS = 256
MAX_DESCRIPTION_CHARS = 500
TRUNCATION_MARKER = "\N{HORIZONTAL ELLIPSIS}"
_PAGE_KEYS = {"$skiptoken": "skiptoken", "$skip": "skip"}
_SKIP_RE = re.compile(r"[0-9]{1,9}")
MAX_CURSOR_CHARS = 4096
MAX_PAGE_TOKEN_CHARS = 8192
MAX_NEXT_LINK_CHARS = 16384
MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # decoded body of one Graph response
PAGE_TOKEN_VERSION = 1


class GraphError(Exception):
    """Safe-to-return failure. `code` is stable; `message` never contains tokens or Graph bodies."""

    def __init__(self, code: str, message: str, *, retry_after: int | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retry_after = retry_after


# Closed allowlist of Entra (AADSTS) codes -> (GraphError code, fixed message). Only the numeric
# code is ever read from a Microsoft error; its text, claims, ids and user data are discarded.
_CONSENT = (
    "graph_consent_required",
    "Microsoft Graph delegated access could not be obtained for this user. "
    "Ask an administrator to confirm admin consent for this app registration's Graph permissions",
)
_REVOKED = (
    "graph_access_revoked",
    "Microsoft no longer grants this account access. If signing in again fails, the account "
    "may have been removed or disabled",
)
_INTERACTION = (
    "graph_interaction_required",
    "Microsoft requires additional sign-in steps or a policy blocked the request (for example MFA "
    "or a compliant device). If signing in again does not resolve it, ask an administrator to "
    "review Conditional Access",
)
_EXCHANGE_FAILED = (
    "graph_exchange_failed",
    "Microsoft Graph delegated access could not be obtained. Try again, and contact an "
    "administrator if it persists",
)
_AADSTS_CATEGORIES = {
    **dict.fromkeys(("65001", "65004"), _CONSENT),
    **dict.fromkeys(("50105", "50057", "50034", "50173", "700082", "70008"), _REVOKED),
    **dict.fromkeys(("50076", "50079", "50158", "53000", "53003", "530032", "50074"), _INTERACTION),
}
# Not preceded by an alphanumeric and not followed by a digit, so neither a longer digit run
# (AADSTS65001123, AADSTS0650011) nor a 3-digit code can be mistaken for a listed code.
_AADSTS_RE = re.compile(r"(?<![A-Za-z0-9_])AADSTS(\d{4,7})(?!\d)")
_MAX_SCAN_CHARS = 16384
_MAX_CHAIN_DEPTH = 5


def _aadsts_code(exc: BaseException) -> str | None:
    """First AADSTS number found in the exception, its `message`, `error_codes` or its chain.

    Sources are tried in that order per exception and the first code found wins. Digits are kept
    as text (never normalised), so only an exact allowlisted number can match.
    """
    seen: set[int] = set()
    current: BaseException | None = exc
    for _ in range(_MAX_CHAIN_DEPTH):
        if current is None or id(current) in seen:
            break
        seen.add(id(current))
        texts = [str(current)]
        message = getattr(current, "message", None)
        if isinstance(message, str):
            texts.append(message)
        for text in texts:
            window = text[:_MAX_SCAN_CHARS]
            for found in _AADSTS_RE.finditer(window):
                # A match touching the cutoff may be a longer digit run that was cut off.
                if found.end() == len(window) < len(text):
                    break
                return found.group(1)
        codes = getattr(current, "error_codes", None)
        if isinstance(codes, (list, tuple)):
            for code in codes:
                if isinstance(code, bool) or not isinstance(code, (int, str)):
                    continue
                if isinstance(code, int):
                    if not 1000 <= code <= 9_999_999:  # bound before str(): huge ints can raise
                        continue
                    code = str(code)
                if re.fullmatch(r"\d{4,7}", code):
                    return code
        current = current.__cause__ or current.__context__
    return None


def classify_token_failure(exc: BaseException) -> GraphError:
    """Map a failed token acquisition to a safe GraphError; nothing from `exc` is echoed."""
    code, message = _AADSTS_CATEGORIES.get(_aadsts_code(exc) or "", _EXCHANGE_FAILED)
    return GraphError(code, message)


class ScopeNotAllowedError(Exception):
    """A Graph scope outside KNOWN_READ_SCOPES was requested: a programming error, never user input.

    Deliberately not a GraphError: nothing about it is returned to the client except a generic
    internal error with a reference (see server.run), and it is audited.
    """


def require_known_scope(scope: object) -> str:
    """Exact-match allowlist check; rejects `.default`, ReadWrite variants, other hosts, lists."""
    if not isinstance(scope, str) or scope not in KNOWN_READ_SCOPES:
        raise ScopeNotAllowedError("requested Graph scope is not an allowlisted read scope")
    return scope


class GraphTokenSource(Protocol):
    """Where a Graph token for exactly one allowlisted scope comes from (the local session)."""

    async def token_for(self, caller: Any, identity: Identity, scope: str = GRAPH_SCOPE) -> str: ...


# --- Safe generic read layer ------------------------------------------------------------------
# Every collection/object endpoint is declared once as a spec: Graph path, its single scope, a
# field allowlist (sent as $select and applied again locally), typed filter definitions and a page
# size cap. The model never supplies OData: it supplies typed arguments that are validated against
# strict patterns/enums BEFORE any token exchange and rendered into $filter by the server only.


def odata_string(value: str) -> str:
    """OData string literal: single-quoted, embedded single quotes doubled."""
    return "'" + value.replace("'", "''") + "'"


def _invalid_filter(name: str, hint: str) -> GraphError:
    # Names the argument and the rule, never the rejected value.
    return GraphError("invalid_filter", f"{name} is not valid: {hint}")


@dataclass(frozen=True)
class StringFilter:
    """`field eq 'value'` (op="eq") or `startswith(field,'value')` (op="startswith")."""

    name: str
    field: str
    pattern: re.Pattern[str]
    hint: str
    op: str = "eq"

    def check(self, value: Any) -> str:
        if not isinstance(value, str) or not self.pattern.fullmatch(value):
            raise ValueError
        return value

    def resolve(self, value: Any, now: datetime) -> str:
        try:
            return self.check(value)
        except ValueError:
            raise _invalid_filter(self.name, self.hint) from None

    def render(self, value: str) -> str:
        literal = odata_string(value)
        if self.op == "startswith":
            return f"startswith({self.field},{literal})"
        return f"{self.field} eq {literal}"


@dataclass(frozen=True)
class EnumFilter:
    """`field eq 'value'` for one of a closed set of values."""

    name: str
    field: str
    values: tuple[str, ...]

    @property
    def hint(self) -> str:
        return "one of " + ", ".join(self.values)

    def check(self, value: Any) -> str:
        if not isinstance(value, str) or value not in self.values:
            raise ValueError
        return value

    def resolve(self, value: Any, now: datetime) -> str:
        try:
            return self.check(value)
        except ValueError:
            raise _invalid_filter(self.name, self.hint) from None

    def render(self, value: str) -> str:
        return f"{self.field} eq {odata_string(value)}"


_CUTOFF_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


@dataclass(frozen=True)
class OlderThanDaysFilter:
    """`field lt <UTC cutoff>`: the integer day count is turned into a cutoff once, by the server.

    The cutoff (not the day count) is what a page token carries, so later pages are stable.
    """

    name: str
    field: str
    max_days: int

    @property
    def hint(self) -> str:
        return f"an integer from 1 to {self.max_days}"

    def check(self, value: Any) -> str:
        # Canonical form only: a real UTC timestamp, whole seconds, plausible year.
        if not isinstance(value, str) or not _CUTOFF_RE.fullmatch(value):
            raise ValueError
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")  # ValueError if not a real date
        if not 2000 <= parsed.year <= 2200:
            raise ValueError
        return value

    def resolve(self, value: Any, now: datetime) -> str:
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= self.max_days:
            raise _invalid_filter(self.name, self.hint)
        cutoff = now.astimezone(UTC) - timedelta(days=value)
        return cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

    def render(self, value: str) -> str:
        return f"{self.field} lt {value}"


Filter = StringFilter | EnumFilter | OlderThanDaysFilter
_PATH_PARAM_RE = re.compile(r"\{([a-z_]+)\}")


def _check_spec(spec: Any) -> None:
    if spec.scope not in KNOWN_READ_SCOPES:
        raise ValueError("endpoint scope is not an allowlisted read scope")
    if not spec.path.startswith("/") or "?" in spec.path:
        raise ValueError("endpoint path must be an absolute path without a query")
    leftover = _PATH_PARAM_RE.sub("", spec.path)
    if set(_PATH_PARAM_RE.findall(spec.path)) != set(spec.path_params) or re.search(
        r"[{}]", leftover
    ):
        raise ValueError("endpoint path parameters must match path_params")
    if re.search(r"[^/]\{|\}[^/]", spec.path):
        raise ValueError("endpoint path parameters must be whole path segments")
    parent = spec.parent
    if parent is not None:
        # The parent is the object the child hangs off, read with `$select=id` to prove the caller
        # may see it: one parent GUID parameter, and the child path extends the parent's.
        if (
            parent.parent is not None
            or parent.fields != ("id",)
            or parent.nested
            or len(parent.path_params) != 1
            or not set(parent.path_params).issubset(spec.path_params)
            or not spec.path.startswith(parent.path + "/")
        ):
            raise ValueError("endpoint parent must be the id-only object the child path extends")


@dataclass(frozen=True)
class CollectionSpec:
    """One collection endpoint. `key` identifies it inside page tokens (never reused)."""

    key: str
    path: str  # relative to /v1.0; {name} segments are GUID path parameters
    scope: str
    fields: tuple[str, ...]
    filters: tuple[Filter, ...] = ()
    path_params: tuple[str, ...] = ()
    max_page_size: int = MAX_PAGE_SIZE
    countable: bool = False
    select: bool = True  # send $select (False where the endpoint's support is not assumed)
    type_key: str | None = None  # output key for the sanitised type derived from @odata.type
    shape: Callable[[dict[str, Any]], dict[str, Any]] | None = None  # replaces field picking
    datetime_fields: tuple[str, ...] = ()  # fields in `fields` kept only if a valid timestamp
    subject: str = "managed device"  # what a 404 means, for the safe not_found message
    # Object this endpoint hangs off. Graph applies Intune scope tags to the parent object but NOT
    # to its child endpoints, so the parent is read first with the caller's own token and a child
    # is requested only if that returns the same ID (see GraphClient.verify_parent).
    parent: "ObjectSpec | None" = None

    def __post_init__(self) -> None:
        _check_spec(self)
        if len({f.name for f in self.filters}) != len(self.filters):
            raise ValueError("duplicate filter name")
        if not 1 <= self.max_page_size <= MAX_PAGE_SIZE:
            raise ValueError("invalid max page size")


@dataclass(frozen=True)
class ObjectSpec:
    """One single-object endpoint (selected fields only; optional nested allowlisted objects)."""

    key: str
    path: str
    scope: str
    fields: tuple[str, ...]
    path_params: tuple[str, ...] = ()
    nested: tuple[tuple[str, tuple[str, ...]], ...] = ()
    select: bool = True  # send $select (False where the endpoint's support is not assumed)
    integer_leaves: bool = False  # every allowlisted value must be a non-negative integer
    datetime_fields: tuple[str, ...] = ()  # timestamp fields: valid timestamp or null (see below)
    type_key: str | None = None  # output key for the sanitised type derived from @odata.type
    subject: str = "managed device"  # what a 404 means, for the safe not_found message
    parent: "ObjectSpec | None" = None  # as on CollectionSpec
    shape: Callable[[dict[str, Any]], dict[str, Any]] | None = None  # as on CollectionSpec

    def __post_init__(self) -> None:
        _check_spec(self)


def parse_guid(name: str, value: Any) -> str:
    try:
        return str(UUID(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise GraphError(f"invalid_{name}", f"{name} must be a GUID") from exc


# Intune's default enrollment configurations have composite IDs: a GUID, then optionally an
# underscore and a short alphanumeric suffix (found live; e.g. a limit or platform default).
_COMPOSITE_ID_RE = re.compile(r"([0-9A-Fa-f-]{36})(?:_([A-Za-z0-9]{1,64}))?")
_COMPOSITE_ID_PARAMS = frozenset({"configuration_id"})


def parse_composite_id(name: str, value: Any) -> str:
    """GUID with an optional `_<alphanumeric>` suffix; canonical GUID part, suffix kept as is.

    Nothing else can reach a URL path: no slash, dot, percent, whitespace or second separator.
    """
    match = _COMPOSITE_ID_RE.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise GraphError(f"invalid_{name}", f"{name} must be a GUID, optionally with a suffix")
    suffix = match.group(2)
    return parse_guid(name, match.group(1)) + (f"_{suffix}" if suffix else "")


def parse_path_id(name: str, value: Any) -> str:
    if name in _COMPOSITE_ID_PARAMS:
        return parse_composite_id(name, value)
    return parse_guid(name, value)


def _composite_or_none(value: Any) -> str | None:
    try:
        return parse_composite_id("id", value)
    except GraphError:
        return None


def _same_id_or_none(name: str, value: Any) -> str | None:
    """Canonical form of a response `id` for comparison with a validated path argument."""
    if name in _COMPOSITE_ID_PARAMS:
        return _composite_or_none(value)
    return _guid_or_none(value)


# Enrollment assignment ids start with a GUID and add up to two short opaque segments (live
# format not yet recorded). Anything else, including free text, is never echoed.
_ENROLLMENT_ASSIGNMENT_ID_RE = re.compile(r"([0-9A-Fa-f-]{36})((?:_[A-Za-z0-9-]{1,64}){0,2})")


def _enrollment_assignment_id_or_none(value: Any) -> str | None:
    match = _ENROLLMENT_ASSIGNMENT_ID_RE.fullmatch(value) if isinstance(value, str) else None
    guid = _guid_or_none(match.group(1)) if match else None
    return guid + match.group(2) if guid and match else None


def parse_device_id(device_id: str) -> str:
    return parse_guid("device_id", device_id)


def audit_target(spec: CollectionSpec | ObjectSpec, target: str) -> str:
    """What may appear as `target=` in an audit line.

    For endpoints scoped to one object (a device, compliance policy or configuration profile) the
    target is that object's ID: only its canonical GUID form, computed here from a successfully
    parsed value, is ever logged. Anything that does not parse (a UPN, a display name, a token,
    any text) is replaced by a fixed placeholder, never echoed or truncated. Other endpoints use a
    fixed label chosen by the tool, not caller text.
    """
    if spec.path_params:
        try:
            return parse_path_id(spec.path_params[-1], target)
        except GraphError:
            return "invalid"
    return target


def _resolve_path(spec: CollectionSpec | ObjectSpec, path_args: Mapping[str, str]) -> str:
    path = spec.path
    for name in spec.path_params:
        path = path.replace("{" + name + "}", path_args[name])
    return path


def _link_paths(spec: CollectionSpec | ObjectSpec, path_args: Mapping[str, str]) -> set[str]:
    """Casefolded paths a nextLink of this call may carry, as they appear in the URL.

    Graph writes navigation collections either as `/parent/{id}/child` or with an OData key,
    `/parent('{id}')/child`. Both are accepted, but only with the GUID already bound to this call
    (canonical, so compared casefolded) in ALL parameter positions of one form: another key,
    unquoted or percent-encoded quotes/parentheses, nested parentheses, extra segments and mixed
    forms never match.
    """
    segments = GRAPH_API_PREFIX + _resolve_path(spec, path_args)
    forms = {segments}
    if spec.path_params:
        keyed = spec.path
        for name in spec.path_params:
            keyed = keyed.replace("/{" + name + "}", "('" + path_args[name] + "')")
        forms.add(GRAPH_API_PREFIX + keyed)
    return {form.casefold() for form in forms}


def _validated_path_args(
    spec: CollectionSpec | ObjectSpec, supplied: Mapping[str, Any]
) -> dict[str, str]:
    return {name: parse_path_id(name, supplied.get(name)) for name in spec.path_params}


@dataclass(frozen=True)
class ReadPlan:
    """A fully validated collection read: nothing in it can still fail validation."""

    spec: CollectionSpec
    path: str
    path_args: dict[str, str]
    filters: dict[str, str]  # canonical, already-validated values by filter name
    top: int
    cursor: dict[str, str]
    parent_checked: bool = False  # set only by GraphClient.verify_parent


@dataclass(frozen=True)
class ObjectPlan:
    spec: ObjectSpec
    path: str
    path_args: Mapping[str, str]
    parent_checked: bool = False  # set only by GraphClient.verify_parent


def render_filter(spec: CollectionSpec, canonical: Mapping[str, str]) -> str:
    """Server-rendered $filter from validated values, in the spec's fixed order, joined by `and`."""
    return " and ".join(f.render(canonical[f.name]) for f in spec.filters if f.name in canonical)


def _resolve_filters(
    spec: CollectionSpec, supplied: Mapping[str, Any], now: datetime
) -> dict[str, str]:
    known = {f.name: f for f in spec.filters}
    if not set(supplied) <= set(known):
        raise ValueError("filter argument is not declared by the endpoint spec")  # internal bug
    return {
        f.name: f.resolve(supplied[f.name], now)
        for f in spec.filters
        if supplied.get(f.name) is not None
    }


def _check_page_size(spec: CollectionSpec, page_size: Any) -> int:
    if isinstance(page_size, bool) or not isinstance(page_size, int):
        raise GraphError("invalid_page_size", "page_size is not valid")
    if not 1 <= page_size <= spec.max_page_size:
        raise GraphError("invalid_page_size", "page_size is not valid")
    return page_size


@dataclass(frozen=True)
class PageCursor:
    params: dict[str, str]
    top: int
    path_args: dict[str, str]
    filters: dict[str, str]


def encode_page_token(
    next_link: str,
    top: int,
    spec: CollectionSpec | None = None,
    path_args: Mapping[str, str] | None = None,
    filters: Mapping[str, str] | None = None,
) -> str:
    """Convert Graph's nextLink into an opaque cursor bound to one endpoint spec.

    Only scheme, host, path and the `$skiptoken`/`$skip` cursor of the link are used; the link
    itself is never followed or echoed. The token carries the already-validated structured
    filter (never raw OData) and the validated path arguments; decode re-validates all of it.
    """
    spec = spec or LIST_DEVICES_SPEC
    path_args = dict(path_args or {})
    accepted = _link_paths(spec, path_args)
    bad_link = GraphError("bad_response", "Graph returned an unexpected pagination link")
    # Type and size first: nextLink comes from the response body and may be any JSON value.
    # Printable ASCII only: urlsplit silently drops tab/CR/LF, so control characters are refused.
    if (
        not isinstance(next_link, str)
        or not 0 < len(next_link) <= MAX_NEXT_LINK_CHARS
        or not (next_link.isascii() and next_link.isprintable())
    ):
        raise bad_link
    try:
        parts = urlsplit(next_link)  # ValueError for e.g. a malformed IPv6 host
        scheme, netloc, path = parts.scheme, parts.netloc, parts.path
        query = parse_qs(parts.query, keep_blank_values=True)
    except ValueError:
        raise bad_link from None
    # Graph treats paths case-insensitively; equality is otherwise exact, so a link for another
    # endpoint (or another device) can never be accepted.
    if (
        scheme != "https"
        or netloc.casefold() != GRAPH_HOST  # no userinfo, no port
        or path.casefold() not in accepted
    ):
        raise bad_link
    # Query keys are case-insensitive too (`$skipToken`); keys equal when casefolded are merged, so
    # duplicates that differ only by case are refused below.
    folded: dict[str, list[str]] = {}
    for key, values in query.items():
        folded.setdefault(key.casefold(), []).extend(values)
    present = [name for name in _PAGE_KEYS if name in folded]
    if len(present) != 1:  # exactly one cursor parameter
        raise GraphError("bad_response", "Graph pagination link has no supported cursor")
    graph_key = present[0]
    short = _PAGE_KEYS[graph_key]
    values = folded[graph_key]
    if len(values) == 1 and values[0] and len(values[0]) <= MAX_CURSOR_CHARS:
        payload = {
            "n": PAGE_TOKEN_VERSION,
            "e": spec.key,
            "k": short,
            "c": values[0],
            "t": top,
            "p": path_args,
            "f": dict(filters or {}),
        }
        token = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        if len(token) > MAX_PAGE_TOKEN_CHARS:
            raise GraphError("bad_response", "Graph pagination cursor is too large")
        return token
    raise GraphError("bad_response", "Graph pagination link has no supported cursor")


def decode_page_token(token: str, spec: CollectionSpec | None = None) -> PageCursor:
    """Validate a page token for exactly this endpoint spec; anything else is invalid_page_token."""
    spec = spec or LIST_DEVICES_SPEC
    try:
        if not isinstance(token, str) or len(token) > MAX_PAGE_TOKEN_CHARS:
            raise ValueError
        padded = token + "=" * (-len(token) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode()))
        if not isinstance(payload, dict) or set(payload) != {"n", "e", "k", "c", "t", "p", "f"}:
            raise ValueError
        key, value, top = payload["k"], payload["c"], payload["t"]
        if (
            type(payload["n"]) is not int  # strict: no bool, no 1.0
            or payload["n"] != PAGE_TOKEN_VERSION
            or payload["e"] != spec.key  # bound to one endpoint: no cross-endpoint replay
            or key not in _PAGE_KEYS.values()
            or not isinstance(value, str)
            or not value
            or len(value) > MAX_CURSOR_CHARS
            or isinstance(top, bool)
            or not isinstance(top, int)
            or not 1 <= top <= spec.max_page_size
            or (key == "skip" and not _SKIP_RE.fullmatch(value))
        ):
            raise ValueError
        path_args = payload["p"]
        if not isinstance(path_args, dict) or set(path_args) != set(spec.path_params):
            raise ValueError
        for name, arg in path_args.items():
            if not isinstance(arg, str) or parse_path_id(name, arg) != arg:
                raise ValueError
        stored = payload["f"]
        known = {f.name: f for f in spec.filters}
        if not isinstance(stored, dict) or not set(stored) <= set(known):
            raise ValueError
        # Same validators as for fresh input: a tampered token cannot smuggle OData in.
        filters = {name: known[name].check(item) for name, item in stored.items()}
    except (ValueError, KeyError, TypeError, RecursionError, GraphError) as exc:
        raise GraphError("invalid_page_token", "page_token is not valid") from exc
    param = "$skiptoken" if key == "skiptoken" else "$skip"
    return PageCursor({param: value}, top, dict(path_args), filters)


def plan_read(
    spec: CollectionSpec,
    *,
    path_args: Mapping[str, Any],
    filters: Mapping[str, Any],
    page_size: int,
    page_token: str | None,
    now: datetime,
) -> ReadPlan:
    """Validate everything for one page. Pure and synchronous: runs before any token exchange.

    With a page_token the token's own page size and filters win and the supplied filter arguments
    are ignored (like page_size). Path arguments are identity, not a filter: they must still be
    valid and must equal the ones the token was issued for.
    """
    supplied_args = _validated_path_args(spec, path_args)
    if page_token:
        cursor = decode_page_token(page_token, spec)
        if supplied_args != cursor.path_args:
            raise GraphError("invalid_page_token", "page_token is not valid")
        return ReadPlan(
            spec,
            _resolve_path(spec, cursor.path_args),
            cursor.path_args,
            cursor.filters,
            cursor.top,
            cursor.params,
        )
    canonical = _resolve_filters(spec, filters, now)
    top = _check_page_size(spec, page_size)
    return ReadPlan(spec, _resolve_path(spec, supplied_args), supplied_args, canonical, top, {})


def plan_count(spec: CollectionSpec, *, filters: Mapping[str, Any], now: datetime) -> ReadPlan:
    if not spec.countable:
        raise ValueError("endpoint is not declared countable")
    return ReadPlan(
        spec, spec.path, {}, _resolve_filters(spec, filters, now), spec.max_page_size, {}
    )


def plan_object(spec: ObjectSpec, *, path_args: Mapping[str, Any]) -> ObjectPlan:
    args = _validated_path_args(spec, path_args)
    return ObjectPlan(spec, _resolve_path(spec, args), args)


_DEVICES_PATH = "/deviceManagement/managedDevices"
_DEVICE_PATH = _DEVICES_PATH + "/{device_id}"
DEVICE_FILTERS: tuple[Filter, ...] = (
    StringFilter(
        "name_prefix",
        "deviceName",
        re.compile(r"[A-Za-z0-9._-]{1,64}"),
        "1-64 characters from A-Z a-z 0-9 . _ -",
        op="startswith",
    ),
    StringFilter(
        "operating_system",
        "operatingSystem",
        re.compile(r"[A-Za-z0-9 ().-]{1,40}"),
        "1-40 characters from A-Z a-z 0-9 space ( ) . -",
    ),
    EnumFilter(
        "compliance_state",
        "complianceState",
        (
            "unknown",
            "compliant",
            "noncompliant",
            "conflict",
            "error",
            "inGracePeriod",
            "configManager",
        ),
    ),
    EnumFilter("ownership", "managedDeviceOwnerType", ("unknown", "company", "personal")),
    OlderThanDaysFilter("not_synced_days", "lastSyncDateTime", 3650),
    StringFilter(
        "assigned_user",
        "userPrincipalName",
        re.compile(r"[A-Za-z0-9._%+@-]{3,256}"),
        "3-256 characters from A-Z a-z 0-9 . _ % + @ -",
    ),
)
# Separate keys: a list_devices token is not a search_devices token and vice versa.
LIST_DEVICES_SPEC = CollectionSpec(
    "devices.list", _DEVICES_PATH, GRAPH_SCOPE, LIST_FIELDS, datetime_fields=DEVICE_DATETIME_FIELDS
)
SEARCH_DEVICES_SPEC = CollectionSpec(
    "devices.search",
    _DEVICES_PATH,
    GRAPH_SCOPE,
    LIST_FIELDS,
    filters=DEVICE_FILTERS,
    countable=True,
    datetime_fields=DEVICE_DATETIME_FIELDS,
)
DEVICE_SPEC = ObjectSpec(
    "devices.get",
    _DEVICE_PATH,
    GRAPH_SCOPE,
    DETAIL_FIELDS,
    ("device_id",),
    datetime_fields=DEVICE_DATETIME_FIELDS,
)
# Aggregate counts only; no names. The OS counts are the v1.0-documented ones.
OVERVIEW_FIELDS = ("enrolledDeviceCount", "mdmEnrolledCount", "dualEnrolledDeviceCount")
OVERVIEW_OS_FIELDS = (
    "androidCount",
    "iosCount",
    "macOSCount",
    "windowsMobileCount",
    "windowsCount",
    "unknownCount",
)
DEVICE_OVERVIEW_SPEC = ObjectSpec(
    "devices.overview",
    "/deviceManagement/managedDeviceOverview",
    GRAPH_SCOPE,
    OVERVIEW_FIELDS,
    nested=(("deviceOperatingSystemSummary", OVERVIEW_OS_FIELDS),),
    select=False,
    integer_leaves=True,
)
# No userPrincipalName/userId and no per-setting detail. These two need the Configuration scope
# (live: `forbidden` with only the managed-devices scope), so they belong to group `configuration`.
STATE_FIELDS = ("displayName", "platformType", "state", "settingCount", "version")
# Visibility probe for the per-device state tools. It uses the MANAGED-DEVICES scope, not the tools'
# Configuration scope: that is the permission Graph documents for reading a managed device (and the
# one `get_device` is verified live to apply scope tags with), whereas whether this GET works with
# the Configuration scope alone is unknown. The configuration group declares that scope as its
# `parent_scope` (groups.py), which is what lets the second exchange happen.
DEVICE_PARENT_SPEC = ObjectSpec(
    "devices.visible", _DEVICE_PATH, GRAPH_SCOPE, ("id",), ("device_id",)
)
COMPLIANCE_STATES_SPEC = CollectionSpec(
    "devices.compliance_states",
    _DEVICE_PATH + "/deviceCompliancePolicyStates",
    CONFIGURATION_SCOPE,
    STATE_FIELDS,
    path_params=("device_id",),
    parent=DEVICE_PARENT_SPEC,
)
CONFIGURATION_STATES_SPEC = CollectionSpec(
    "devices.configuration_states",
    _DEVICE_PATH + "/deviceConfigurationStates",
    CONFIGURATION_SCOPE,
    STATE_FIELDS,
    path_params=("device_id",),
    parent=DEVICE_PARENT_SPEC,
)

# -- Group apps: v1.0 mobileApp base fields ONLY (see docs/tools/APPS.md). ------
APP_FIELDS = (
    "id",
    "displayName",
    "publisher",
    "createdDateTime",
    "lastModifiedDateTime",
    "publishingState",
)
APP_DETAIL_FIELDS = (*APP_FIELDS, "description")
APP_DATETIME_FIELDS = ("createdDateTime", "lastModifiedDateTime")
_APPS_PATH = "/deviceAppManagement/mobileApps"
_APP_PATH = _APPS_PATH + "/{app_id}"
APP_PARENT_SPEC = ObjectSpec(
    "apps.visible",
    _APP_PATH,
    APPS_SCOPE,
    ("id",),
    ("app_id",),
    subject="app",
)
LIST_APPS_SPEC = CollectionSpec(
    "apps.list",
    _APPS_PATH,
    APPS_SCOPE,
    APP_FIELDS,
    type_key="app_type",
    datetime_fields=APP_DATETIME_FIELDS,
    subject="app",
)
APP_SPEC = ObjectSpec(
    "apps.get",
    _APP_PATH,
    APPS_SCOPE,
    APP_DETAIL_FIELDS,
    ("app_id",),
    type_key="app_type",
    datetime_fields=APP_DATETIME_FIELDS,
    subject="app",
)


def app_assignment_summary(row: dict[str, Any]) -> dict[str, Any]:
    out = assignment_summary(row)
    intent = row.get("intent")
    out["intent"] = (
        intent
        if isinstance(intent, str)
        and intent
        in (
            "available",
            "required",
            "uninstall",
            "availableWithoutEnrollment",
        )
        else None
    )
    return out


APP_ASSIGNMENTS_SPEC = CollectionSpec(
    "apps.assignments",
    _APP_PATH + "/assignments",
    APPS_SCOPE,
    ("id", "target", "intent"),
    path_params=("app_id",),
    select=False,
    shape=app_assignment_summary,
    subject="app",
    parent=APP_PARENT_SPEC,
)

# -- Group rbac: documented v1.0 metadata only (docs/tools/RBAC.md). ------------
RBAC_FIELDS = ("id", "displayName", "description", "isBuiltIn", "rolePermissions")
ROLE_ASSIGNMENT_FIELDS = ("id", "displayName", "description", "resourceScopes", "members")
MAX_RBAC_ITEMS = 1000
_ROLES_PATH = "/deviceManagement/roleDefinitions"
_ROLE_PATH = _ROLES_PATH + "/{role_definition_id}"


def _rbac_metadata(row: dict[str, Any]) -> dict[str, Any]:
    return {
        name: _text(name, row[name]) if isinstance(row.get(name), str) else None
        for name in ("id", "displayName", "description")
    }


def role_definition_summary(row: dict[str, Any]) -> dict[str, Any]:
    permissions = row.get("rolePermissions")
    return {
        **_rbac_metadata(row),
        "isBuiltIn": row.get("isBuiltIn") if isinstance(row.get("isBuiltIn"), bool) else None,
        "role_permission_count": len(permissions) if isinstance(permissions, list) else None,
    }


def role_definition_detail(row: dict[str, Any]) -> dict[str, Any]:
    # Only allowed action strings, never resource-action objects or notAllowedResourceActions.
    # This is descriptive metadata, NOT an effective authorization calculation.
    actions: list[str] = []
    complete = True
    permissions = row.get("rolePermissions")
    if not isinstance(permissions, list):
        permissions, complete = [], False
    for permission in permissions:
        resources = permission.get("resourceActions") if isinstance(permission, dict) else None
        if not isinstance(resources, list):
            complete = False
            continue
        for resource in resources:
            values = resource.get("allowedResourceActions") if isinstance(resource, dict) else None
            if not isinstance(values, list):
                complete = False
                continue
            for value in values:
                if not isinstance(value, str):
                    complete = False
                elif len(actions) < MAX_RBAC_ITEMS:
                    actions.append(_text("action", value))
                    complete = complete and len(value) <= MAX_TEXT_CHARS
                else:
                    complete = False
    return {
        **role_definition_summary(row),
        "allowed_resource_actions": actions,
        "allowed_resource_actions_complete": complete,
    }


def role_assignment_summary(row: dict[str, Any]) -> dict[str, Any]:
    out = _rbac_metadata(row)
    for name in ("members", "resourceScopes"):
        values = row.get(name)
        if not isinstance(values, list):
            out[name] = None  # not reported, not an empty scope
            continue
        if len(values) > MAX_RBAC_ITEMS:
            raise GraphError("bad_response", "Microsoft Graph returned too many RBAC group IDs")
        out[name] = [guid for value in values if (guid := _guid_or_none(value)) is not None]
    return out


def role_assignment_detail(row: dict[str, Any]) -> dict[str, Any]:
    out = role_assignment_summary(row)
    # Internal counters are consumed by the tool's audit, never returned to the caller.
    for name in ("members", "resourceScopes"):
        values = row.get(name)
        out[name + "_dropped"] = len(values) - len(out[name]) if isinstance(values, list) else 0
    return out


ROLE_PARENT_SPEC = ObjectSpec(
    "rbac.visible",
    _ROLE_PATH,
    RBAC_SCOPE,
    ("id",),
    ("role_definition_id",),
    subject="role definition",
)
LIST_ROLE_DEFINITIONS_SPEC = CollectionSpec(
    "rbac.list",
    _ROLES_PATH,
    RBAC_SCOPE,
    RBAC_FIELDS,
    shape=role_definition_summary,
    subject="role definition",
)
ROLE_DEFINITION_SPEC = ObjectSpec(
    "rbac.get",
    _ROLE_PATH,
    RBAC_SCOPE,
    RBAC_FIELDS,
    ("role_definition_id",),
    shape=role_definition_detail,
    subject="role definition",
)
ROLE_ASSIGNMENTS_SPEC = CollectionSpec(
    "rbac.assignments",
    _ROLE_PATH + "/roleAssignments",
    RBAC_SCOPE,
    ROLE_ASSIGNMENT_FIELDS,
    path_params=("role_definition_id",),
    select=False,
    shape=role_assignment_summary,
    subject="role definition",
    parent=ROLE_PARENT_SPEC,
)

ROLE_ASSIGNMENT_SPEC = ObjectSpec(
    "rbac.assignment",
    _ROLE_PATH + "/roleAssignments/{role_assignment_id}",
    RBAC_SCOPE,
    ROLE_ASSIGNMENT_FIELDS,
    ("role_definition_id", "role_assignment_id"),
    select=False,
    shape=role_assignment_detail,
    subject="role assignment",
    parent=ROLE_PARENT_SPEC,
)

# -- Group `configuration`: compliance policies and device configuration profiles ---------------
# Only properties of the BASE types (deviceCompliancePolicy / deviceConfiguration) are selected:
# every derived type has them, and $select is not assumed valid for derived-type properties. The
# response is picked client-side from the same allowlist, so a derived type's extra properties
# (Wi-Fi keys, certificates, passwords, VPN secrets, ...) can never reach a tool result even if
# Graph returns them. G9 settings reads use separate full-object specs and typed allowlists below.
POLICY_FIELDS = (
    "id",
    "displayName",
    "description",
    "createdDateTime",
    "lastModifiedDateTime",
    "version",
)
POLICY_DATETIME_FIELDS = ("createdDateTime", "lastModifiedDateTime")
# Counts and one timestamp only. conflictCount is returned as null where Graph has no such field.
STATUS_COUNT_FIELDS = (
    "pendingCount",
    "notApplicableCount",
    "successCount",
    "errorCount",
    "failedCount",
    "conflictCount",
)
STATUS_DATETIME_FIELDS = ("lastUpdateDateTime",)
ASSIGNMENT_FIELDS = ("id", "target")  # raw shape; only the sanitised summary below is returned
_ASSIGNMENT_ID_RE = re.compile(r"[A-Za-z0-9_.-]{1,128}")
ASSIGNMENT_FILTER_TYPES = ("none", "include", "exclude")


def _guid_or_none(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(UUID(value))
    except ValueError:
        return None


def assignment_summary(row: dict[str, Any]) -> dict[str, Any]:
    """Sanitised view of one assignment: no display names, never the raw target object."""
    target = row.get("target")
    target = target if isinstance(target, dict) else {}
    assignment_id = row.get("id")
    filter_type = target.get("deviceAndAppManagementAssignmentFilterType")
    return {
        "id": assignment_id
        if isinstance(assignment_id, str) and _ASSIGNMENT_ID_RE.fullmatch(assignment_id)
        else None,
        "target_type": odata_type_name(target.get("@odata.type")),
        "group_id": _guid_or_none(target.get("groupId")),
        "filter_type": filter_type
        if isinstance(filter_type, str) and filter_type in ASSIGNMENT_FILTER_TYPES
        else None,
        "filter_id": _guid_or_none(target.get("deviceAndAppManagementAssignmentFilterId")),
    }


# G9: exact derived type AND exact property AND expected value type, never a denylist.
# Reviewed v1.0 Learn properties and deliberate exclusions: docs/tools/SETTINGS.md. New types/fields
# require review; do not infer safety from a name or accept arbitrary short strings as enums.
_PASSWORD_TYPE = ("deviceDefault", "alphanumeric", "numeric")
_ANDROID_PASSWORD_TYPE = (
    "deviceDefault",
    "alphabetic",
    "alphanumeric",
    "alphanumericWithSymbols",
    "lowSecurityBiometric",
    "numeric",
    "numericComplex",
    "any",
)
SettingRule = type[bool] | type[int] | tuple[str, ...]
COMPLIANCE_SETTINGS: dict[str, dict[str, SettingRule]] = {
    "windows10CompliancePolicy": {
        "passwordRequired": bool,
        "passwordMinimumLength": int,
        "passwordRequiredType": _PASSWORD_TYPE,
        "bitLockerEnabled": bool,
        "secureBootEnabled": bool,
        "codeIntegrityEnabled": bool,
        "storageRequireEncryption": bool,
    },
    "iosCompliancePolicy": {
        "passcodeRequired": bool,
        "passcodeMinimumLength": int,
        "passcodeRequiredType": _PASSWORD_TYPE,
        "securityBlockJailbrokenDevices": bool,
        "deviceThreatProtectionEnabled": bool,
    },
    "androidCompliancePolicy": {
        "passwordRequired": bool,
        "passwordMinimumLength": int,
        "passwordRequiredType": _ANDROID_PASSWORD_TYPE,
        "securityBlockJailbrokenDevices": bool,
        "storageRequireEncryption": bool,
        "securityPreventInstallAppsFromUnknownSources": bool,
    },
    "androidWorkProfileCompliancePolicy": {
        "passwordRequired": bool,
        "passwordMinimumLength": int,
        "passwordRequiredType": _ANDROID_PASSWORD_TYPE,
        "securityBlockJailbrokenDevices": bool,
        "storageRequireEncryption": bool,
        "securityPreventInstallAppsFromUnknownSources": bool,
    },
    "macOSCompliancePolicy": {
        "passwordRequired": bool,
        "passwordMinimumLength": int,
        "passwordRequiredType": _PASSWORD_TYPE,
        "firewallEnabled": bool,
        "storageRequireEncryption": bool,
    },
}
PROFILE_SETTINGS: dict[str, dict[str, SettingRule]] = {
    "windows10GeneralConfiguration": {
        "cameraBlocked": bool,
        "screenCaptureBlocked": bool,
        "defenderRequireRealTimeMonitoring": bool,
        "passwordRequired": bool,
        "passwordMinimumLength": int,
        "passwordRequiredType": _PASSWORD_TYPE,
    },
    "macOSGeneralDeviceConfiguration": {
        "passwordRequired": bool,
        "passwordBlockSimple": bool,
        "passwordMinimumLength": int,
        "passwordRequiredType": _PASSWORD_TYPE,
    },
    "iosGeneralDeviceConfiguration": {
        "cameraBlocked": bool,
        "screenCaptureBlocked": bool,
        "passcodeRequired": bool,
        "passcodeMinimumLength": int,
        "passcodeRequiredType": _PASSWORD_TYPE,
    },
    "androidGeneralDeviceConfiguration": {
        "cameraBlocked": bool,
        "screenCaptureBlocked": bool,
        "passwordRequired": bool,
        "passwordMinimumLength": int,
        "passwordRequiredType": _ANDROID_PASSWORD_TYPE,
        "storageRequireDeviceEncryption": bool,
    },
    "windowsUpdateForBusinessConfiguration": {
        "microsoftUpdateServiceAllowed": bool,
        "driversExcluded": bool,
        "qualityUpdatesDeferralPeriodInDays": int,
        "featureUpdatesDeferralPeriodInDays": int,
        "qualityUpdatesPaused": bool,
        "featureUpdatesPaused": bool,
    },
}
_SETTING_ENUM_RE = re.compile(r"[A-Za-z][A-Za-z0-9]{0,39}")


def settings_summary(
    body: dict[str, Any], base: ObjectSpec, types: Mapping[str, Mapping[str, SettingRule]]
) -> dict[str, Any]:
    """Full Graph object -> bounded metadata and a small typed settings subset. Never log body.

    Settings availability means a reviewed type, NOT a complete/effective policy. Missing/null
    or malformed settings are omitted, never coerced/truncated into something that looks valid.
    No free-form string, nested object or list is supported by this initial property set.
    """
    out = _pick_object(base, body)
    rules = types.get(odata_type_name(body.get("@odata.type")))
    settings: dict[str, Any] = {}
    for name, rule in (rules or {}).items():
        value = body.get(name)
        if (
            (rule is bool and type(value) is bool)
            or (rule is int and type(value) is int and 0 <= value <= 2_147_483_647)
            or (
                isinstance(rule, tuple)
                and isinstance(value, str)
                and _SETTING_ENUM_RE.fullmatch(value)
                and value in rule
            )
        ):
            settings[name] = value
    out.update(settings_available=rules is not None, settings=settings)
    return out


# App protection: reviewed v1.0 properties only; exact tables/exclusions in docs/tools/APPS.md.
# Version strings are not arbitrary text: at most four 1-5 digit numeric components.
_APP_VERSION_RE = re.compile(r"[0-9]{1,5}(?:\.[0-9]{1,5}){0,3}")
_APP_PROTECTION_COMMON: dict[str, SettingRule] = {
    "organizationalCredentialsRequired": bool,
    "dataBackupBlocked": bool,
    "deviceComplianceRequired": bool,
    "saveAsBlocked": bool,
    "pinRequired": bool,
    "maximumPinRetries": int,
    "simplePinBlocked": bool,
    "minimumPinLength": int,
    "contactSyncBlocked": bool,
    "printBlocked": bool,
    "fingerprintBlocked": bool,
    "disableAppPinIfDevicePinIsSet": bool,
    "pinCharacterSet": ("numeric", "alphanumericAndSymbol"),
    "allowedInboundDataTransferSources": ("allApps", "managedApps", "none"),
    "allowedOutboundDataTransferDestinations": ("allApps", "managedApps", "none"),
    "allowedOutboundClipboardSharingLevel": (
        "allApps",
        "managedAppsWithPasteIn",
        "managedApps",
        "blocked",
    ),
}
APP_PROTECTION_SETTINGS = {
    "iosManagedAppProtection": {**_APP_PROTECTION_COMMON, "faceIdBlocked": bool},
    "androidManagedAppProtection": {
        **_APP_PROTECTION_COMMON,
        "screenCaptureBlocked": bool,
        "encryptAppData": bool,
        "disableAppEncryptionIfDeviceEncryptionIsEnabled": bool,
    },
}
APP_PROTECTION_VERSION_FIELDS = (
    "minimumRequiredOsVersion",
    "minimumWarningOsVersion",
    "minimumRequiredAppVersion",
    "minimumWarningAppVersion",
)
_APP_POLICIES_PATH = "/deviceAppManagement/managedAppPolicies"
_APP_POLICY_PATH = _APP_POLICIES_PATH + "/{policy_id}"
APP_PROTECTION_BASE_SPEC = ObjectSpec(
    "apps.protection.metadata",
    _APP_POLICY_PATH,
    APPS_SCOPE,
    POLICY_FIELDS,
    ("policy_id",),
    datetime_fields=POLICY_DATETIME_FIELDS,
    type_key="policy_type",
    subject="app protection policy",
)


def app_protection_metadata(body: dict[str, Any]) -> dict[str, Any]:
    out = _pick_object(APP_PROTECTION_BASE_SPEC, body)
    out["id"] = _guid_or_none(body.get("id"))
    for name in ("displayName", "description"):
        if not isinstance(body.get(name), str):
            out[name] = None
    value = body.get("version")
    out["version"] = value if isinstance(value, str) and _APP_VERSION_RE.fullmatch(value) else None
    # Never expose an arbitrary derived-type string as free text.
    if out["policy_type"] not in APP_PROTECTION_SETTINGS:
        out["policy_type"] = "unknown"
    return out


def app_protection_summary(body: dict[str, Any]) -> dict[str, Any]:
    typed = settings_summary(body, APP_PROTECTION_BASE_SPEC, APP_PROTECTION_SETTINGS)
    out = app_protection_metadata(body)
    out.update(settings_available=typed["settings_available"], settings=typed["settings"])
    if out["settings_available"]:
        for name in APP_PROTECTION_VERSION_FIELDS:
            value = body.get(name)
            if isinstance(value, str) and _APP_VERSION_RE.fullmatch(value):
                out["settings"][name] = value
    return out


LIST_APP_PROTECTION_POLICIES_SPEC = CollectionSpec(
    "apps.protection.list",
    _APP_POLICIES_PATH,
    APPS_SCOPE,
    POLICY_FIELDS,
    shape=app_protection_metadata,
    subject="app protection policy",
)
APP_PROTECTION_POLICY_SPEC = ObjectSpec(
    "apps.protection.get",
    _APP_POLICY_PATH,
    APPS_SCOPE,
    POLICY_FIELDS,
    ("policy_id",),
    select=False,
    shape=app_protection_summary,
    subject="app protection policy",
)


def app_protection_assignment_summary(body: dict[str, Any]) -> dict[str, Any]:
    out = assignment_summary(body)
    out["id"] = _guid_or_none(body.get("id"))
    # No deprecated targetGroupId/isExcluded fallback or user-target entraObjectId.
    if out["target_type"] not in (
        "groupAssignmentTarget",
        "exclusionGroupAssignmentTarget",
        "allLicensedUsersAssignmentTarget",
        "allDevicesAssignmentTarget",
    ):
        out.update(target_type="unknown", group_id=None, filter_type=None, filter_id=None)
    elif out["target_type"] not in ("groupAssignmentTarget", "exclusionGroupAssignmentTarget"):
        out["group_id"] = None
    return out


APP_PROTECTION_ASSIGNMENTS_SPECS = {}
for _type, _collection in (
    ("iosManagedAppProtection", "iosManagedAppProtections"),
    ("androidManagedAppProtection", "androidManagedAppProtections"),
):
    _path = "/deviceAppManagement/" + _collection + "/{policy_id}"
    _parent = ObjectSpec(
        "apps.protection.visible." + _type,
        _path,
        APPS_SCOPE,
        ("id",),
        ("policy_id",),
        subject="app protection policy",
    )
    APP_PROTECTION_ASSIGNMENTS_SPECS[_type] = CollectionSpec(
        "apps.protection.assignments." + _type,
        _path + "/assignments",
        APPS_SCOPE,
        ("id", "target"),
        path_params=("policy_id",),
        select=False,
        shape=app_protection_assignment_summary,
        subject="app protection policy",
        parent=_parent,
    )

# G4: v1.0 ServiceConfig reads only. Exact reviewed fields: docs/tools/ENROLLMENT.md.
ENROLLMENT_FIELDS = (*POLICY_FIELDS, "priority")
_ENROLLMENTS_PATH = "/deviceManagement/deviceEnrollmentConfigurations"
_ENROLLMENT_PATH = _ENROLLMENTS_PATH + "/{configuration_id}"
ENROLLMENT_BASE_SPEC = ObjectSpec(
    "enrollment.metadata",
    _ENROLLMENT_PATH,
    SERVICE_CONFIG_SCOPE,
    ENROLLMENT_FIELDS,
    ("configuration_id",),
    datetime_fields=POLICY_DATETIME_FIELDS,
    type_key="configuration_type",
    subject="enrollment configuration",
)
ENROLLMENT_SETTINGS = {
    "deviceEnrollmentLimitConfiguration": {"limit": int},
    "windows10EnrollmentCompletionPageConfiguration": {"allowNonBlockingAppInstallation": bool},
}
ENROLLMENT_PLATFORMS = (
    "iosRestriction",
    "windowsRestriction",
    "windowsMobileRestriction",
    "androidRestriction",
    "macOSRestriction",
)


def enrollment_summary(body: dict[str, Any], *, detail: bool = False) -> dict[str, Any]:
    out = _pick_object(ENROLLMENT_BASE_SPEC, body)
    out["id"] = _composite_or_none(body.get("id"))
    for name in ("version", "priority"):
        value = body.get(name)
        out[name] = value if type(value) is int and 0 <= value <= 2_147_483_647 else None
    if detail:
        typed = settings_summary(body, ENROLLMENT_BASE_SPEC, ENROLLMENT_SETTINGS)
        out.update(settings_available=typed["settings_available"], settings=typed["settings"])
        if body.get("@odata.type") == (
            "#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration"
        ):
            out["settings_available"] = True
            for platform in ENROLLMENT_PLATFORMS:
                raw = body.get(platform)
                if isinstance(raw, dict):
                    out["settings"][platform] = {
                        key: raw[key]
                        for key in ("platformBlocked", "personalDeviceEnrollmentBlocked")
                        if type(raw.get(key)) is bool
                    }
    return out


def enrollment_assignment_summary(body: dict[str, Any]) -> dict[str, Any]:
    # All identifiers are GUIDs; no raw target strings or arbitrary type names.
    out = assignment_summary(body)
    out["id"] = _enrollment_assignment_id_or_none(body.get("id"))
    if out["target_type"] not in (
        "groupAssignmentTarget",
        "exclusionGroupAssignmentTarget",
        "allDevicesAssignmentTarget",
        "allLicensedUsersAssignmentTarget",
    ):
        out["target_type"] = "unknown"
    # A group id only belongs to a recognised group-bearing target; never echo one otherwise.
    if out["target_type"] not in ("groupAssignmentTarget", "exclusionGroupAssignmentTarget"):
        out["group_id"] = None
    # Assignment filter properties are not documented on the v1.0 base target.
    return {key: out[key] for key in ("id", "target_type", "group_id")}


def apple_certificate_summary(body: dict[str, Any]) -> dict[str, Any]:
    expiry = _timestamp_or_none(body.get("expirationDateTime"))
    return {
        "expirationDateTime": expiry,
        "lastModifiedDateTime": _timestamp_or_none(body.get("lastModifiedDateTime")),
        # Learn defines an unconstrained String, not an enum. Never echo arbitrary status text.
        "certificateUploadStatus": None,
        "days_until_expiry": (
            (datetime.fromisoformat(expiry) - datetime.now(UTC)).days if expiry else None
        ),
    }


ENROLLMENT_PARENT_SPEC = ObjectSpec(
    "enrollment.visible",
    _ENROLLMENT_PATH,
    SERVICE_CONFIG_SCOPE,
    ("id",),
    ("configuration_id",),
    subject="enrollment configuration",
)
LIST_ENROLLMENTS_SPEC = CollectionSpec(
    "enrollment.list",
    _ENROLLMENTS_PATH,
    SERVICE_CONFIG_SCOPE,
    ENROLLMENT_FIELDS,
    shape=enrollment_summary,
    subject="enrollment configuration",
)
ENROLLMENT_SPEC = ObjectSpec(
    "enrollment.get",
    _ENROLLMENT_PATH,
    SERVICE_CONFIG_SCOPE,
    ENROLLMENT_FIELDS,
    ("configuration_id",),
    select=False,
    shape=lambda body: enrollment_summary(body, detail=True),
    subject="enrollment configuration",
)
ENROLLMENT_ASSIGNMENTS_SPEC = CollectionSpec(
    "enrollment.assignments",
    _ENROLLMENT_PATH + "/assignments",
    SERVICE_CONFIG_SCOPE,
    ASSIGNMENT_FIELDS,
    path_params=("configuration_id",),
    select=False,
    shape=enrollment_assignment_summary,
    subject="enrollment configuration",
    parent=ENROLLMENT_PARENT_SPEC,
)
APPLE_CERTIFICATE_SPEC = ObjectSpec(
    "enrollment.apple_certificate",
    "/deviceManagement/applePushNotificationCertificate",
    SERVICE_CONFIG_SCOPE,
    ("expirationDateTime", "lastModifiedDateTime"),
    shape=apple_certificate_summary,
    subject="Apple push certificate",
)


_POLICIES_PATH = "/deviceManagement/deviceCompliancePolicies"
_POLICY_PATH = _POLICIES_PATH + "/{policy_id}"
COMPLIANCE_POLICY_PARENT_SPEC = ObjectSpec(
    "configuration.compliance_policies.visible",
    _POLICY_PATH,
    CONFIGURATION_SCOPE,
    ("id",),
    ("policy_id",),
    subject="compliance policy",
)
LIST_COMPLIANCE_POLICIES_SPEC = CollectionSpec(
    "configuration.compliance_policies.list",
    _POLICIES_PATH,
    CONFIGURATION_SCOPE,
    POLICY_FIELDS,
    type_key="policy_type",
    datetime_fields=POLICY_DATETIME_FIELDS,
    subject="compliance policy",
)
COMPLIANCE_POLICY_SPEC = ObjectSpec(
    "configuration.compliance_policies.get",
    _POLICY_PATH,
    CONFIGURATION_SCOPE,
    POLICY_FIELDS,
    ("policy_id",),
    type_key="policy_type",
    datetime_fields=POLICY_DATETIME_FIELDS,
    subject="compliance policy",
)
COMPLIANCE_POLICY_SETTINGS_SPEC = ObjectSpec(
    "configuration.compliance_policies.settings",
    _POLICY_PATH,
    CONFIGURATION_SCOPE,
    POLICY_FIELDS,
    ("policy_id",),
    select=False,
    shape=lambda body: settings_summary(body, COMPLIANCE_POLICY_SPEC, COMPLIANCE_SETTINGS),
    subject="compliance policy",
)
COMPLIANCE_POLICY_STATUS_SPEC = ObjectSpec(
    "configuration.compliance_policies.status",
    _POLICY_PATH + "/deviceStatusOverview",
    CONFIGURATION_SCOPE,
    STATUS_COUNT_FIELDS,
    ("policy_id",),
    select=False,
    integer_leaves=True,
    datetime_fields=STATUS_DATETIME_FIELDS,
    subject="compliance policy",
    parent=COMPLIANCE_POLICY_PARENT_SPEC,
)
COMPLIANCE_POLICY_ASSIGNMENTS_SPEC = CollectionSpec(
    "configuration.compliance_policies.assignments",
    _POLICY_PATH + "/assignments",
    CONFIGURATION_SCOPE,
    ASSIGNMENT_FIELDS,
    path_params=("policy_id",),
    select=False,
    shape=assignment_summary,
    subject="compliance policy",
    parent=COMPLIANCE_POLICY_PARENT_SPEC,
)

_PROFILES_PATH = "/deviceManagement/deviceConfigurations"
_PROFILE_PATH = _PROFILES_PATH + "/{profile_id}"
CONFIGURATION_PROFILE_PARENT_SPEC = ObjectSpec(
    "configuration.profiles.visible",
    _PROFILE_PATH,
    CONFIGURATION_SCOPE,
    ("id",),
    ("profile_id",),
    subject="configuration profile",
)
LIST_CONFIGURATION_PROFILES_SPEC = CollectionSpec(
    "configuration.profiles.list",
    _PROFILES_PATH,
    CONFIGURATION_SCOPE,
    POLICY_FIELDS,
    type_key="profile_type",
    datetime_fields=POLICY_DATETIME_FIELDS,
    subject="configuration profile",
)
CONFIGURATION_PROFILE_SPEC = ObjectSpec(
    "configuration.profiles.get",
    _PROFILE_PATH,
    CONFIGURATION_SCOPE,
    POLICY_FIELDS,
    ("profile_id",),
    type_key="profile_type",
    datetime_fields=POLICY_DATETIME_FIELDS,
    subject="configuration profile",
)
CONFIGURATION_PROFILE_SETTINGS_SPEC = ObjectSpec(
    "configuration.profiles.settings",
    _PROFILE_PATH,
    CONFIGURATION_SCOPE,
    POLICY_FIELDS,
    ("profile_id",),
    select=False,
    shape=lambda body: settings_summary(body, CONFIGURATION_PROFILE_SPEC, PROFILE_SETTINGS),
    subject="configuration profile",
)
CONFIGURATION_PROFILE_STATUS_SPEC = ObjectSpec(
    "configuration.profiles.status",
    _PROFILE_PATH + "/deviceStatusOverview",
    CONFIGURATION_SCOPE,
    STATUS_COUNT_FIELDS,
    ("profile_id",),
    select=False,
    integer_leaves=True,
    datetime_fields=STATUS_DATETIME_FIELDS,
    subject="configuration profile",
    parent=CONFIGURATION_PROFILE_PARENT_SPEC,
)
CONFIGURATION_PROFILE_ASSIGNMENTS_SPEC = CollectionSpec(
    "configuration.profiles.assignments",
    _PROFILE_PATH + "/assignments",
    CONFIGURATION_SCOPE,
    ASSIGNMENT_FIELDS,
    path_params=("profile_id",),
    select=False,
    shape=assignment_summary,
    subject="configuration profile",
    parent=CONFIGURATION_PROFILE_PARENT_SPEC,
)

# Tenant-wide device compliance counts (recalled from Graph documentation; unverified live, TASKS
# G8/G11). Counts only: the singleton's `id` is not returned; a non-integer value becomes null.
COMPLIANCE_SUMMARY_FIELDS = (
    "compliantDeviceCount",
    "nonCompliantDeviceCount",
    "inGracePeriodCount",
    "configManagerCount",
    "conflictDeviceCount",
    "errorDeviceCount",
    "notApplicableDeviceCount",
    "unknownDeviceCount",
    "remediatedDeviceCount",
)
COMPLIANCE_SUMMARY_SPEC = ObjectSpec(
    "configuration.compliance_summary",
    "/deviceManagement/deviceCompliancePolicyDeviceStateSummary",
    CONFIGURATION_SCOPE,
    COMPLIANCE_SUMMARY_FIELDS,
    select=False,
    integer_leaves=True,
    subject="compliance summary",
)


@dataclass(frozen=True)
class CollectionPage:
    rows: list[dict[str, Any]]
    next_page_token: str | None


@dataclass(frozen=True)
class CountResult:
    count: int
    complete: bool  # False: the walk hit MAX_COUNT_ROWS/MAX_COUNT_PAGES, so `count` is "at least"


@dataclass(frozen=True)
class DevicePage:
    devices: list[dict[str, Any]]
    next_page_token: str | None


_LONE_SURROGATE_RE = re.compile("[\ud800-\udfff]")


def _text(name: str, value: str) -> str:
    """Admin-written free text is untrusted data: bounded per field, cut with one trailing marker.

    `description` may be 500 characters, every other string field 256 (the marker counts toward
    the limit). Python strings hold whole code points, and a lone surrogate (invalid text that a
    JSON escape can produce, and that cannot be encoded for the client) is replaced by U+FFFD
    first, so a cut can never leave half of a surrogate pair behind.
    """
    value = _LONE_SURROGATE_RE.sub("\ufffd", value)
    limit = MAX_DESCRIPTION_CHARS if name == "description" else MAX_TEXT_CHARS
    if len(value) <= limit:
        return value
    return value[: limit - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER


def _scalar(name: str, value: Any) -> Any:
    """A JSON scalar (strings bounded) or None: a nested object or list under a name is dropped."""
    if isinstance(value, str):
        return _text(name, value)
    return value if value is None or isinstance(value, (int, float, bool)) else None


_ODATA_TYPE_PREFIX = "#microsoft.graph."
_ODATA_TYPE_RE = re.compile(r"[A-Za-z0-9.]{1,100}")


def odata_type_name(value: Any) -> str:
    """`#microsoft.graph.<Name>` -> `<Name>`; anything else, however long, is `unknown`.

    Only text matching a tight pattern is ever returned, so a hostile or malformed type can never
    put arbitrary text (or a log-forging newline) into a tool result.
    """
    if isinstance(value, str) and value.startswith(_ODATA_TYPE_PREFIX):
        name = value[len(_ODATA_TYPE_PREFIX) :]
        if _ODATA_TYPE_RE.fullmatch(name):
            return name
    return "unknown"


def _count_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


# Graph timestamps: ISO 8601 with `Z` or a numeric offset and any number of fractional digits
# (for example 2016-12-31T23:58:21.6459442-08:00). A value with no zone is read as UTC.
_TIMESTAMP_RE = re.compile(
    r"([0-9]{4}-[0-9]{2}-[0-9]{2}T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9])"
    r"(\.[0-9]{1,9})?(Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])?"
)


def _timestamp_or_none(value: Any) -> str | None:
    """A real instant as UTC `YYYY-MM-DDTHH:MM:SS[.fraction]Z`, else None.

    Impossible dates and any other shape are None. Offsets are converted to UTC (whole-minute
    offsets leave the fraction unchanged, so its digits are kept as received; an already valid
    `...Z` value comes back byte-identical).
    """
    if not isinstance(value, str) or len(value) > 64:
        return None
    match = _TIMESTAMP_RE.fullmatch(value)
    if not match:
        return None
    base, fraction, zone = match.groups()
    try:
        # fromisoformat validates the date; it gets at most 6 fractional digits (any more are
        # cut here, not left to the Python version) and a zone, defaulting to UTC.
        parsed = datetime.fromisoformat(base + (fraction or "")[:7] + (zone or "Z"))
        as_utc = parsed.astimezone(UTC)
    except (ValueError, OverflowError):
        return None
    return as_utc.replace(tzinfo=None).isoformat(timespec="seconds") + (fraction or "") + "Z"


def _pick(row: dict[str, Any], spec: CollectionSpec) -> dict[str, Any]:
    return {
        name: _timestamp_or_none(row.get(name))
        if name in spec.datetime_fields
        else _scalar(name, row.get(name))
        for name in spec.fields
    }


def _pick_row(spec: CollectionSpec, row: dict[str, Any]) -> dict[str, Any]:
    """The allowlisted view of one collection row (never the raw Graph row)."""
    if spec.shape is not None:
        return spec.shape(row)
    out = _pick(row, spec)
    if spec.type_key:
        out[spec.type_key] = odata_type_name(row.get("@odata.type"))
    return out


def _pick_object(spec: ObjectSpec, body: dict[str, Any]) -> dict[str, Any]:
    if spec.shape is not None:
        return spec.shape(body)

    def leaf(name: str, value: Any) -> Any:
        return _count_or_none(value) if spec.integer_leaves else _scalar(name, value)

    out: dict[str, Any] = {}
    for name in dict.fromkeys((*spec.fields, *spec.datetime_fields)):
        out[name] = (
            _timestamp_or_none(body.get(name))
            if name in spec.datetime_fields
            else leaf(name, body.get(name))
        )
    for name, sub in spec.nested:
        raw = body.get(name)
        out[name] = {n: leaf(n, raw.get(n)) for n in sub} if isinstance(raw, dict) else None
    if spec.type_key:
        out[spec.type_key] = odata_type_name(body.get("@odata.type"))
    return out


async def _read_bounded(response: httpx.Response) -> bytes:
    """The decoded body, or bad_response once it exceeds MAX_RESPONSE_BYTES.

    Content-Length is checked up front when present (it can be wrong or absent, so the bytes
    actually received are counted too).
    """
    too_big = GraphError("bad_response", "Microsoft Graph returned an oversized response")
    declared = response.headers.get("Content-Length", "")
    if declared.isdigit() and int(declared) > MAX_RESPONSE_BYTES:
        raise too_big
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        size += len(chunk)
        if size > MAX_RESPONSE_BYTES:
            raise too_big
        chunks.append(chunk)
    return b"".join(chunks)


class GraphClient:
    """Thin read-only client. Only GET is ever issued; the token is a per-call argument."""

    def __init__(
        self,
        *,
        client: httpx.AsyncClient | None = None,
        base_url: str = GRAPH_BASE,
        timeout: float = 20.0,
        clock: Callable[[], datetime] | None = None,
    ):
        self._base = base_url.rstrip("/")
        self._client = client or httpx.AsyncClient(timeout=timeout, follow_redirects=False)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._count_slots = asyncio.Semaphore(MAX_CONCURRENT_COUNTS)
        # A shared client must never retain Set-Cookie state across callers.
        self._client.cookies.jar.set_policy(DefaultCookiePolicy(allowed_domains=[]))

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _get(
        self,
        token: str,
        path: str,
        params: dict[str, str],
        correlation_id: str,
        subject: str = "managed device",
    ) -> dict[str, Any]:
        try:
            # Streamed so an oversized body is abandoned instead of being read into memory.
            async with self._client.stream(
                "GET",
                self._base + path,
                params=params,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                    "client-request-id": correlation_id,
                    "return-client-request-id": "true",
                },
            ) as response:
                status = response.status_code
                retry = response.headers.get("Retry-After", "")
                raw = await _read_bounded(response) if status == 200 else b""
        except httpx.TimeoutException as exc:
            raise GraphError("upstream_timeout", "Microsoft Graph did not respond in time") from exc
        except httpx.HTTPError as exc:
            raise GraphError("upstream_error", "Microsoft Graph could not be reached") from exc
        if status == 200:
            try:
                body = json.loads(raw)
            except (ValueError, RecursionError) as exc:  # ValueError includes bad UTF-8
                raise GraphError("bad_response", "Microsoft Graph returned invalid JSON") from exc
            if not isinstance(body, dict):
                raise GraphError("bad_response", "Microsoft Graph returned an unexpected body")
            return body
        if status == 400:
            # Graph's body (which can echo the query) is never forwarded.
            raise GraphError(
                "bad_request",
                "Microsoft Graph rejected the query; a filter or option may not be supported "
                "for this endpoint",
            )
        if status == 401:
            raise GraphError("graph_unauthorized", "Microsoft Graph rejected the user's token")
        if status == 403:
            # Either the user's Intune role or the permissions consented for this app.
            raise GraphError(
                "forbidden",
                "Microsoft denied access: this user, or this app's consented permissions, "
                "may not read this Intune data",
            )
        if status == 404:
            raise GraphError("not_found", f"No matching {subject} is visible to this user")
        if status in (429, 503):
            raise GraphError(
                "throttled",
                "Microsoft Graph is throttling or temporarily unavailable; retry later",
                retry_after=int(retry) if retry.isdigit() else None,
            )
        raise GraphError("upstream_error", f"Microsoft Graph returned HTTP {status}")

    # -- planning (validation only; no I/O) ----------------------------------------------------
    def plan(
        self,
        spec: CollectionSpec,
        *,
        path_args: Mapping[str, Any] | None = None,
        filters: Mapping[str, Any] | None = None,
        page_size: int,
        page_token: str | None,
    ) -> ReadPlan:
        return plan_read(
            spec,
            path_args=path_args or {},
            filters=filters or {},
            page_size=page_size,
            page_token=page_token,
            now=self._clock(),
        )

    def plan_count(self, spec: CollectionSpec, *, filters: Mapping[str, Any]) -> ReadPlan:
        return plan_count(spec, filters=filters, now=self._clock())

    # -- generic reads -------------------------------------------------------------------------
    @staticmethod
    def _query(plan: ReadPlan) -> dict[str, str]:
        params = {"$select": ",".join(plan.spec.fields)} if plan.spec.select else {}
        if plan.filters:
            params["$filter"] = render_filter(plan.spec, plan.filters)
        return params

    @staticmethod
    def _require_parent_checked(plan: ReadPlan | ObjectPlan) -> None:
        # A programming error (internal_error), never reachable through model input: an endpoint
        # that hangs off a parent must not be requested before verify_parent has succeeded.
        if plan.spec.parent is not None and not plan.parent_checked:
            raise ValueError("endpoint requires a parent visibility check first")

    async def verify_parent(
        self, token: str, plan: ReadPlan | ObjectPlan, correlation_id: str
    ) -> ReadPlan | ObjectPlan:
        """Prove the caller may see the plan's parent object; only then may the child be read.

        Graph applies Intune scope tags to a managed device, compliance policy or configuration
        profile itself (the GET returns 404 to a user outside scope) but not to the sub-resources
        of that object, which answer with data for anyone holding the permission. So the parent
        is read first, with the caller's own token (`token` must carry `spec.parent.scope`), and
        the child is requested only for a 200 whose `id` is the canonical GUID asked for. 404,
        403 and every other failure keep their usual safe mapping, and the child is never called.
        Returns the plan marked as checked; the check is repeated on every page.
        """
        parent = plan.spec.parent
        if parent is None:
            return plan
        parent_plan = plan_object(parent, path_args=plan.path_args)
        expected = parent_plan.path_args[parent.path_params[0]]
        body = await self._get(
            token,
            parent_plan.path,
            {"$select": ",".join(parent.fields)},
            correlation_id,
            parent.subject,
        )
        if _same_id_or_none(parent.path_params[0], body.get("id")) != expected:
            raise GraphError("bad_response", "Microsoft Graph returned an unexpected response")
        return replace(plan, parent_checked=True)

    async def fetch_page(self, token: str, plan: ReadPlan, correlation_id: str) -> CollectionPage:
        self._require_parent_checked(plan)
        params = self._query(plan)
        params.update(plan.cursor)
        params["$top"] = str(plan.top)
        body = await self._get(token, plan.path, params, correlation_id, plan.spec.subject)
        rows = body.get("value")
        if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
            raise GraphError("bad_response", "Microsoft Graph returned an unexpected page")
        # Sub-collections may ignore $top: accept (and return) up to the hard cap, never cut.
        if len(rows) > MAX_ROWS_PER_PAGE:
            raise GraphError("bad_response", "Microsoft Graph returned too many rows in one page")
        next_link = body.get("@odata.nextLink")
        # Absent or null means last page; any other value must be a valid link of this endpoint.
        next_token = (
            None
            if next_link is None
            else encode_page_token(next_link, plan.top, plan.spec, plan.path_args, plan.filters)
        )
        return CollectionPage([_pick_row(plan.spec, r) for r in rows], next_token)

    async def fetch_count(self, token: str, plan: ReadPlan, correlation_id: str) -> CountResult:
        """Rows the caller can actually read, counted by paging the filtered query.

        `$count`/`@odata.count` is never used: Graph computes it over the whole tenant, ignoring
        Intune scope tags, although the rows themselves are scoped. Pages of `$select=id` are
        walked with the same validated `nextLink` handling as fetch_page and only their lengths
        are summed (no row is kept or returned). The walk stops at MAX_COUNT_ROWS rows or
        MAX_COUNT_PAGES pages, whichever comes first; with more pages still available the result
        is incomplete ("at least"). Any failure on any page fails the whole call.
        """
        self._require_parent_checked(plan)
        async with self._count_slots:
            return await self._walk_count(token, plan, correlation_id)

    async def _walk_count(self, token: str, plan: ReadPlan, correlation_id: str) -> CountResult:
        deadline = time.monotonic() + MAX_COUNT_SECONDS
        total = 0
        cursor: dict[str, str] = {}
        for _ in range(MAX_COUNT_PAGES):
            params = {"$select": "id", **cursor, "$top": str(plan.top)}
            if plan.filters:
                params["$filter"] = render_filter(plan.spec, plan.filters)
            body = await self._get(token, plan.path, params, correlation_id, plan.spec.subject)
            rows = body.get("value")
            if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
                raise GraphError("bad_response", "Microsoft Graph returned an unexpected page")
            if len(rows) > MAX_ROWS_PER_PAGE:
                raise GraphError(
                    "bad_response", "Microsoft Graph returned too many rows in one page"
                )
            total += len(rows)
            if total > MAX_COUNT_ROWS:  # a page that ignored $top crossed the cap: report the cap
                return CountResult(MAX_COUNT_ROWS, False)
            next_link = body.get("@odata.nextLink")
            if next_link is None:
                return CountResult(total, True)
            # Same binding as paging: only a link for this endpoint, carrying a supported cursor.
            link_token = encode_page_token(next_link, plan.top, plan.spec, {}, plan.filters)
            if total >= MAX_COUNT_ROWS or time.monotonic() >= deadline:
                break
            cursor = decode_page_token(link_token, plan.spec).params
        return CountResult(total, False)

    async def fetch_object(
        self, token: str, plan: ObjectPlan, correlation_id: str
    ) -> dict[str, Any]:
        self._require_parent_checked(plan)
        params = {"$select": ",".join(plan.spec.fields)} if plan.spec.select else {}
        body = await self._get(token, plan.path, params, correlation_id, plan.spec.subject)
        return _pick_object(plan.spec, body)

    # -- original entry points (list_devices / get_device), now thin wrappers ------------------
    async def list_devices(
        self, token: str, *, page_size: int, page_token: str | None, correlation_id: str
    ) -> DevicePage:
        plan = self.plan(LIST_DEVICES_SPEC, page_size=page_size, page_token=page_token)
        page = await self.fetch_page(token, plan, correlation_id)
        return DevicePage(page.rows, page.next_page_token)

    async def get_device(self, token: str, device_id: str, correlation_id: str) -> dict[str, Any]:
        plan = plan_object(DEVICE_SPEC, path_args={"device_id": device_id})
        return await self.fetch_object(token, plan, correlation_id)


# -- Group apps: categories, app configuration policies (docs/tools/APP-CONFIGURATION.md).
# Base managedDeviceMobileAppConfiguration properties only. Derived types (iOS/Android) add
# `settings`, `encodedSettingXml` and `payloadJson`: never selected, never returned. The targeted
# app ids are only counted.
APP_CATEGORY_FIELDS = ("id", "displayName", "lastModifiedDateTime")
APP_CONFIGURATION_FIELDS = (*POLICY_FIELDS, "targetedMobileApps")
_APP_CATEGORIES_PATH = "/deviceAppManagement/mobileAppCategories"
_APP_CONFIGURATIONS_PATH = "/deviceAppManagement/mobileAppConfigurations"
_APP_CONFIGURATION_PATH = _APP_CONFIGURATIONS_PATH + "/{app_configuration_id}"


def app_category_summary(row: dict[str, Any]) -> dict[str, Any]:
    name = row.get("displayName")
    return {
        "id": _guid_or_none(row.get("id")),
        "displayName": _text("displayName", name) if isinstance(name, str) else None,
        "lastModifiedDateTime": _timestamp_or_none(row.get("lastModifiedDateTime")),
    }


def app_configuration_summary(row: dict[str, Any]) -> dict[str, Any]:
    name, description, version = row.get("displayName"), row.get("description"), row.get("version")
    targeted = row.get("targetedMobileApps")
    out: dict[str, Any] = {
        "id": _guid_or_none(row.get("id")),
        "displayName": _text("displayName", name) if isinstance(name, str) else None,
        "description": _text("description", description) if isinstance(description, str) else None,
        "createdDateTime": _timestamp_or_none(row.get("createdDateTime")),
        "lastModifiedDateTime": _timestamp_or_none(row.get("lastModifiedDateTime")),
        "version": version if type(version) is int and 0 <= version <= 2_147_483_647 else None,
        "configuration_type": odata_type_name(row.get("@odata.type")),
        # A count only (None: not reported); the app ids themselves are never returned.
        "targeted_app_count": len(targeted) if isinstance(targeted, list) else None,
    }
    return out


APP_CATEGORIES_SPEC = CollectionSpec(
    "apps.categories",
    _APP_CATEGORIES_PATH,
    APPS_SCOPE,
    APP_CATEGORY_FIELDS,
    shape=app_category_summary,
    subject="app category",
)
APP_CONFIGURATION_PARENT_SPEC = ObjectSpec(
    "apps.configurations.visible",
    _APP_CONFIGURATION_PATH,
    APPS_SCOPE,
    ("id",),
    ("app_configuration_id",),
    subject="app configuration policy",
)
LIST_APP_CONFIGURATIONS_SPEC = CollectionSpec(
    "apps.configurations.list",
    _APP_CONFIGURATIONS_PATH,
    APPS_SCOPE,
    APP_CONFIGURATION_FIELDS,
    shape=app_configuration_summary,
    subject="app configuration policy",
)
APP_CONFIGURATION_SPEC = ObjectSpec(
    "apps.configurations.get",
    _APP_CONFIGURATION_PATH,
    APPS_SCOPE,
    APP_CONFIGURATION_FIELDS,
    ("app_configuration_id",),
    shape=app_configuration_summary,
    subject="app configuration policy",
)
APP_CONFIGURATION_ASSIGNMENTS_SPEC = CollectionSpec(
    "apps.configurations.assignments",
    _APP_CONFIGURATION_PATH + "/assignments",
    APPS_SCOPE,
    ASSIGNMENT_FIELDS,
    path_params=("app_configuration_id",),
    select=False,
    shape=assignment_summary,
    subject="app configuration policy",
    parent=APP_CONFIGURATION_PARENT_SPEC,
)


# -- Group enrollment: terms and conditions, v1.0 reads (docs/tools/TERMS-CATEGORIES.md).
# bodyText and acceptanceStatement are never selected nor returned.
TERMS_FIELDS = (*POLICY_FIELDS, "title")
_TERMS_PATH = "/deviceManagement/termsAndConditions"
_TERM_PATH = _TERMS_PATH + "/{terms_id}"


def terms_summary(body: dict[str, Any]) -> dict[str, Any]:
    out = {
        "id": _guid_or_none(body.get("id")),
        "displayName": _scalar("displayName", body.get("displayName")),
        "description": _scalar("description", body.get("description")),
        "title": _scalar("title", body.get("title")),
        "createdDateTime": _timestamp_or_none(body.get("createdDateTime")),
        "lastModifiedDateTime": _timestamp_or_none(body.get("lastModifiedDateTime")),
    }
    for name in ("displayName", "description", "title"):
        if not isinstance(out[name], str):
            out[name] = None
    version = body.get("version")
    out["version"] = version if type(version) is int and 0 <= version <= 2_147_483_647 else None
    return out


def terms_assignment_summary(body: dict[str, Any]) -> dict[str, Any]:
    # Learn documents only an id and a target; the documented target example is an unusual
    # scopeTagGroupAssignmentTarget, so only closed type names and a groupId GUID are returned.
    out = enrollment_assignment_summary({**body, "id": None})
    out["id"] = _guid_or_none(body.get("id"))
    return out


TERMS_PARENT_SPEC = ObjectSpec(
    "terms.visible",
    _TERM_PATH,
    SERVICE_CONFIG_SCOPE,
    ("id",),
    ("terms_id",),
    subject="terms and conditions",
)
LIST_TERMS_SPEC = CollectionSpec(
    "terms.list",
    _TERMS_PATH,
    SERVICE_CONFIG_SCOPE,
    TERMS_FIELDS,
    shape=terms_summary,
    subject="terms and conditions",
)
TERMS_SPEC = ObjectSpec(
    "terms.get",
    _TERM_PATH,
    SERVICE_CONFIG_SCOPE,
    TERMS_FIELDS,
    ("terms_id",),
    shape=terms_summary,
    subject="terms and conditions",
)
TERMS_ASSIGNMENTS_SPEC = CollectionSpec(
    "terms.assignments",
    _TERM_PATH + "/assignments",
    SERVICE_CONFIG_SCOPE,
    ("id", "target"),
    path_params=("terms_id",),
    select=False,
    shape=terms_assignment_summary,
    subject="terms and conditions",
    parent=TERMS_PARENT_SPEC,
)


# -- Opt-in tenant inventory: v1.0 detectedApp collection (docs/tools/DETECTED-APPS.md).
DETECTED_APP_FIELDS = (
    "id",
    "displayName",
    "version",
    "sizeInByte",
    "deviceCount",
    "publisher",
    "platform",
)
DETECTED_APP_PLATFORMS = (
    "unknown",
    "windows",
    "windowsMobile",
    "windowsHolographic",
    "ios",
    "macOS",
    "chromeOS",
    "androidOSP",
    "androidDeviceAdministrator",
    "androidWorkProfile",
    "androidDedicatedAndFullyManaged",
    "unknownFutureValue",
)
_DETECTED_APP_ID_RE = re.compile(r"[A-Za-z0-9-]{1,128}")
_DETECTED_APP_VERSION_RE = re.compile(r"[A-Za-z0-9._+() -]{1,64}")
_DETECTED_APPS_PATH = "/deviceManagement/detectedApps"


def _text_or_none(name: str, value: Any) -> str | None:
    return _text(name, value) if isinstance(value, str) else None


def detected_app_summary(row: dict[str, Any]) -> dict[str, Any]:
    """Allowlisted view: bounded text, strict id/version, non-negative numbers, closed enum."""
    app_id, version, platform = row.get("id"), row.get("version"), row.get("platform")
    return {
        "id": app_id if isinstance(app_id, str) and _DETECTED_APP_ID_RE.fullmatch(app_id) else None,
        "displayName": _text_or_none("displayName", row.get("displayName")),
        "version": version
        if isinstance(version, str) and _DETECTED_APP_VERSION_RE.fullmatch(version)
        else None,
        "sizeInByte": _count_or_none(row.get("sizeInByte")),
        "deviceCount": _count_or_none(row.get("deviceCount")),
        "publisher": _text_or_none("publisher", row.get("publisher")),
        "platform": platform if platform in DETECTED_APP_PLATFORMS else None,
    }


LIST_DETECTED_APPS_SPEC = CollectionSpec(
    "devices.detected_apps",
    _DETECTED_APPS_PATH,
    GRAPH_SCOPE,
    DETECTED_APP_FIELDS,
    shape=detected_app_summary,
    subject="detected app",
)
DETECTED_APP_SPEC = ObjectSpec(
    "devices.detected_app",
    _DETECTED_APPS_PATH + "/{detected_app_id}",
    GRAPH_SCOPE,
    DETECTED_APP_FIELDS,
    ("detected_app_id",),
    shape=detected_app_summary,
    subject="detected app",
)


# -- configuration group: tenant-level state summaries (docs/tools/CONFIG-SUMMARIES.md).
# Both endpoints are tenant aggregates that Graph does not restrict by the caller's Intune scope
# tags (same residual as get_compliance_summary): counts may include devices outside a scoped
# user's scope. Allowlist only; endpoints documented for v1.0, UNVERIFIED LIVE.
STATE_SUMMARY_COUNT_FIELDS = (
    "compliantDeviceCount",
    "nonCompliantDeviceCount",
    "errorDeviceCount",
    "conflictDeviceCount",
    "notApplicableDeviceCount",
    "unknownDeviceCount",
    "remediatedDeviceCount",
)
# policyPlatformType, as documented on Learn for v1.0.
POLICY_PLATFORM_TYPES = frozenset(
    {
        "android",
        "iOS",
        "macOS",
        "windowsPhone81",
        "windows81AndLater",
        "windows10AndLater",
        "androidWorkProfile",
        "linux",
        "all",
    }
)
_SETTING_IDENTIFIER_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.]{0,127}")


def _identifier_or_none(value: Any) -> str | None:
    """Only a strict identifier (letters, digits, `_`, `.`) passes; any other text is null."""
    if isinstance(value, str) and _SETTING_IDENTIFIER_RE.fullmatch(value):
        return value
    return None


def _int32_count_or_none(value: Any) -> int | None:
    """The documented Int32 counts: a non-negative int no larger than 2147483647, else null."""
    count = _count_or_none(value)
    return count if count is not None and count <= 2_147_483_647 else None


def _state_counts(body: dict[str, Any]) -> dict[str, int | None]:
    return {name: _int32_count_or_none(body.get(name)) for name in STATE_SUMMARY_COUNT_FIELDS}


def configuration_state_summary(body: dict[str, Any]) -> dict[str, Any]:
    # Learn's sample wraps the singleton in `value`; accept either shape, read counts only.
    inner = body.get("value")
    return _state_counts(inner if isinstance(inner, dict) else body)


def compliance_setting_state_summary(row: dict[str, Any]) -> dict[str, Any]:
    platform = row.get("platformType")
    return {
        "id": _guid_or_none(row.get("id")),
        "setting": _identifier_or_none(row.get("setting")),
        "settingName": _identifier_or_none(row.get("settingName")),
        "platformType": platform
        if isinstance(platform, str) and platform in POLICY_PLATFORM_TYPES
        else None,
        **_state_counts(row),
    }


CONFIGURATION_STATE_SUMMARY_SPEC = ObjectSpec(
    "configuration.state_summary",
    "/deviceManagement/deviceConfigurationDeviceStateSummaries",
    CONFIGURATION_SCOPE,
    STATE_SUMMARY_COUNT_FIELDS,
    select=False,
    shape=configuration_state_summary,
    subject="configuration state summary",
)
COMPLIANCE_SETTING_SUMMARIES_SPEC = CollectionSpec(
    "configuration.compliance_setting_summaries",
    "/deviceManagement/deviceCompliancePolicySettingStateSummaries",
    CONFIGURATION_SCOPE,
    ("id", "setting", "settingName", "platformType", *STATE_SUMMARY_COUNT_FIELDS),
    select=False,
    shape=compliance_setting_state_summary,
    subject="compliance setting summaries",
)
