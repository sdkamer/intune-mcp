"""In-process harness: the real FastMCP server and tools over HTTP; only Microsoft is mocked.

The signed-in user is a fake local identity (`local-<oid>` bearer, test-only); Graph is a stub
that answers per user. Nothing here is live.
"""

import json
import re
from contextlib import asynccontextmanager
from types import SimpleNamespace
from urllib.parse import quote

import httpx2
import jwt
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_http_request

from intune_mcp.config import (
    APPS_SCOPE,
    CONFIGURATION_SCOPE_NAME,
    GRAPH_SCOPE,
    GRAPH_SCOPE_NAME,
    RBAC_SCOPE,
    SERVICE_CONFIG_SCOPE,
    Settings,
)
from intune_mcp.graph import GraphClient, classify_token_failure, require_known_scope
from intune_mcp.identity import Identity
from intune_mcp.local import LocalCaller
from intune_mcp.server import build_server

from .conftest import TENANT, graph_token


class FakeCredential:
    """What a token acquisition yields: one single-scope Graph token, recorded for assertions."""

    def __init__(self, harness, caller):
        self.h, self.caller = harness, caller

    async def get_token(self, *scopes):
        self.h.token_requests.append((self.caller.account["oid"], scopes))
        # Like Entra, the token's scp is the single scope that was asked for.
        name = scopes[0].rsplit("/", 1)[1] if len(scopes) == 1 else "+".join(scopes)
        oid = self.caller.account["oid"]
        return SimpleNamespace(token=graph_token(oid, scp=name), expires_on=9_999_999_999)


class FakeTokenSource:
    """Stands in for the signed-in session. Tests may replace `get_credential` to simulate a
    refused or failing acquisition; failures map through the same safe classifier as production."""

    def __init__(self, harness):
        self.h = harness
        self.get_credential = self._default_credential

    async def _default_credential(self, caller):
        return FakeCredential(self.h, caller)

    async def token_for(self, caller, identity, scope=GRAPH_SCOPE):
        require_known_scope(scope)  # the same closed guard as the real session
        credential = await self.get_credential(caller)
        try:
            result = await credential.get_token(scope)
        except Exception as exc:
            raise classify_token_failure(exc) from exc
        return result.token


class Harness:
    """A user is `local-<oid>`: `sign_in(oid)` returns that bearer for `call_tool`/`mcp`."""

    def __init__(self, settings: Settings, **server_kwargs):
        self.settings = settings
        self.graph_requests: list[httpx2.Request] = []
        self.token_requests: list[tuple] = []
        self.devices = {}  # oid -> list of devices
        self.children = {}  # oid -> {(device_id, collection name): rows}
        self.overview = {}  # oid -> managedDeviceOverview body
        # Group `configuration` data. oid -> {collection name: [rows]} for deviceCompliancePolicies
        # and deviceConfigurations; oid -> {(collection, id, "deviceStatusOverview"): body or
        # (collection, id, "assignments"): rows}.
        # oid -> {mobileApps/managedAppPolicies/iosManagedAppProtections/
        # androidManagedAppProtections: rows}; same leaky_children model as configuration.
        self.app_rows = {}
        self.app_children = {}  # oid -> {(collection, id, assignments): rows}
        self.rbac_rows = {}  # oid -> {roleDefinitions: rows}
        self.rbac_children = {}  # oid -> {(roleDefinitions, id, roleAssignments): rows}
        self.detected_rows = {}  # oid -> {"detectedApps": rows} (tenant inventory, opt-in)
        self.enrollment_rows = {}
        self.enrollment_children = {}
        self.apple_certificate = {}
        self.terms_rows = {}  # oid -> {termsAndConditions: rows}  (enrollment group, terms)
        self.terms_children = {}  # oid -> {(termsAndConditions, id, assignments): rows}
        self.config_rows = {}
        self.config_children = {}
        self.compliance_summary = {}  # oid -> deviceCompliancePolicyDeviceStateSummary body
        # -- config summaries (docs/tools/CONFIG-SUMMARIES.md): tenant aggregates, unscoped
        self.config_state_summary = {}  # oid -> deviceConfigurationDeviceStateSummary body
        self.setting_summaries = {}  # oid -> deviceCompliancePolicySettingStateSummary rows
        self.ignore_top = False  # True: collections return every row regardless of $top
        self.paren_links = False  # True: nextLink uses OData key parentheses, parent('id')/child
        # Like live Graph: `@odata.count` (sent when $count=true) covers the whole tenant, not the
        # caller's Intune scope. None: equal to the caller's scoped rows; int: the tenant total.
        self.odata_count_total = None
        # Like live Graph: the child endpoints of an object (per-device states, a policy's or
        # profile's status overview and assignments) answer with their data for ANY caller holding
        # the permission, even one for whom the parent object itself is 404 (outside their scope
        # tags). False: a child is hidden whenever the parent is not visible to the caller.
        self.leaky_children = True
        self.graph = GraphClient(
            client=httpx2.AsyncClient(transport=httpx2.MockTransport(self._graph_handler))
        )
        self.token_source = FakeTokenSource(self)
        self.mcp_server = build_server(
            settings,
            token_source=self.token_source,
            identity_provider=self._identity,
            graph=self.graph,
            **server_kwargs,
        )
        self.app = self.mcp_server.http_app(path="/mcp/intune", stateless_http=True)

    @staticmethod
    def _identity():
        """The request's fake local user; the real server gets this from the signed-in session."""
        bearer = get_http_request().headers.get("authorization", "").removeprefix("Bearer ")
        if not bearer.startswith("local-"):
            raise ToolError("Authentication required")
        oid = bearer.removeprefix("local-")
        return LocalCaller(account={"oid": oid}), Identity(TENANT, oid, f"sub-{oid}")

    _FILTER_FIELDS = (
        "deviceName",
        "operatingSystem",
        "complianceState",
        "managedDeviceOwnerType",
        "userPrincipalName",
        "lastSyncDateTime",
    )
    _STRING = r"'((?:[^']|'')*)'"
    _TERM = re.compile(
        rf"startswith\((\w+),{_STRING}\)|(\w+) eq {_STRING}"
        r"|(\w+) lt (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)"
    )

    def _filtered(self, rows, text):
        """Evaluate exactly the grammar the server renders; None means Graph would say 400."""
        pos, terms = 0, []
        while True:
            m = self._TERM.match(text, pos)
            if not m:
                return None
            terms.append(m)
            pos = m.end()
            if pos == len(text):
                break
            if not text.startswith(" and ", pos):
                return None
            pos += 5
        for m in terms:
            if m.group(1):
                kind, prop, value = "startswith", m.group(1), m.group(2)
            elif m.group(3):
                kind, prop, value = "eq", m.group(3), m.group(4)
            else:
                kind, prop, value = "lt", m.group(5), m.group(6)
            if prop not in self._FILTER_FIELDS:
                return None
            value = value.replace("''", "'")
            if kind == "lt":
                rows = [r for r in rows if str(r.get(prop) or "9999") < value]
            elif kind == "startswith":
                rows = [
                    r for r in rows if str(r.get(prop, "")).casefold().startswith(value.casefold())
                ]
            else:
                rows = [r for r in rows if str(r.get(prop, "")).casefold() == value.casefold()]
        return rows

    def _collection(self, request, rows):
        params = dict(request.url.params)
        if "$filter" in params:
            rows = self._filtered(rows, params["$filter"])
            if rows is None:
                return httpx2.Response(
                    400, json={"error": {"message": "bad filter SECRET-GRAPH-BODY"}}
                )
        body = {}
        if params.get("$count") == "true":
            body["@odata.count"] = (
                len(rows) if self.odata_count_total is None else self.odata_count_total
            )
        offset = int(params.get("$skiptoken", 0))
        top = int(params.get("$top", len(rows) or 1))
        if self.ignore_top:
            top = max(len(rows), 1)
        page = rows[offset : offset + top]
        body["value"] = page
        if offset + top < len(rows):
            query = {k: v for k, v in params.items() if k != "$skiptoken"}
            query["$skiptoken"] = str(offset + top)
            query_text = "&".join(f"{k}={quote(v, safe='')}" for k, v in query.items())
            path = request.url.path
            if self.paren_links:
                # /parent/<id>/child -> /parent('<id>')/child, as Graph writes navigation links
                head, _, child = path.rstrip("/").rpartition("/")
                if (
                    child.lower()
                    in ("assignments", "roleassignments", "devicecompliancepolicystates")
                    and head
                ):
                    parent, _, key = head.rpartition("/")
                    path = f"{parent}('{key}')/{child}"
            body["@odata.nextLink"] = f"https://graph.microsoft.com{path}?{query_text}"
        return httpx2.Response(200, json=body)

    def _graph_handler(self, request: httpx2.Request) -> httpx2.Response:
        self.graph_requests.append(request)
        bearer = request.headers["authorization"].removeprefix("Bearer ")
        claims = jwt.decode(bearer, options={"verify_signature": False})
        oid = claims["oid"]
        rows = self.devices.get(oid, [])
        if request.url.path.startswith("/v1.0/deviceAppManagement/"):
            if claims.get("scp") != APPS_SCOPE.rsplit("/", 1)[1]:
                return httpx2.Response(403, json={})
            parts = request.url.path.removeprefix("/v1.0/deviceAppManagement/").split("/")
            return self._configuration(
                request, oid, parts, rows_by_user=self.app_rows, children_by_user=self.app_children
            )
        segments = request.url.path.removeprefix("/v1.0/deviceManagement/").split("/")
        if segments[0] == "detectedApps":  # banner: opt-in tenant inventory, devices scope
            if claims.get("scp") != GRAPH_SCOPE_NAME:
                return httpx2.Response(403, json={})
            return self._configuration(
                request, oid, segments, rows_by_user=self.detected_rows, children_by_user={}
            )
        if segments[0] in ("deviceEnrollmentConfigurations", "applePushNotificationCertificate"):
            if claims.get("scp") != SERVICE_CONFIG_SCOPE.rsplit("/", 1)[1]:
                return httpx2.Response(403, json={})
            if segments == ["applePushNotificationCertificate"]:
                return httpx2.Response(200, json=self.apple_certificate.get(oid, {}))
            return self._configuration(
                request,
                oid,
                segments,
                rows_by_user=self.enrollment_rows,
                children_by_user=self.enrollment_children,
            )
        # -- terms and conditions (enrollment group, ServiceConfig scope) --
        if segments[0] == "termsAndConditions":
            if claims.get("scp") != SERVICE_CONFIG_SCOPE.rsplit("/", 1)[1]:
                return httpx2.Response(403, json={})
            return self._configuration(
                request,
                oid,
                segments,
                rows_by_user=self.terms_rows,
                children_by_user=self.terms_children,
            )
        if segments[0] == "roleDefinitions":
            if claims.get("scp") != RBAC_SCOPE.rsplit("/", 1)[1]:
                return httpx2.Response(403, json={})
            return self._configuration(
                request,
                oid,
                segments,
                rows_by_user=self.rbac_rows,
                children_by_user=self.rbac_children,
            )
        if segments[0] in (
            "deviceConfigurationDeviceStateSummaries",
            "deviceCompliancePolicySettingStateSummaries",
        ):
            if claims.get("scp") != CONFIGURATION_SCOPE_NAME:
                return httpx2.Response(403, json={"error": {"code": "Forbidden"}})
            if segments == ["deviceConfigurationDeviceStateSummaries"]:
                return httpx2.Response(200, json=self.config_state_summary.get(oid, {}))
            return self._collection(request, self.setting_summaries.get(oid, []))
        # Like Graph (as documented/assumed): managed devices need the managed-devices scope; the
        # per-device state collections and the policy/profile endpoints need the Configuration one.
        needs = CONFIGURATION_SCOPE_NAME if self._is_configuration(segments) else GRAPH_SCOPE_NAME
        if claims.get("scp") != needs:  # every endpoint here needs exactly one scope
            return httpx2.Response(403, json={"error": {"code": "Forbidden"}})
        if segments[0] in ("deviceCompliancePolicies", "deviceConfigurations"):
            return self._configuration(request, oid, segments)
        if segments == ["deviceCompliancePolicyDeviceStateSummary"]:
            return httpx2.Response(200, json=self.compliance_summary.get(oid, {}))
        if segments == ["managedDeviceOverview"]:
            return httpx2.Response(200, json=self.overview.get(oid, {}))
        if segments == ["managedDevices"]:
            return self._collection(request, rows)
        if len(segments) < 2:
            return httpx2.Response(404, json={"error": {"code": "NotFound"}})
        device = next((r for r in rows if r["id"] == segments[1]), None)
        if len(segments) == 2 and device is not None:
            return httpx2.Response(200, json=device)
        if len(segments) == 3 and (device is not None or self.leaky_children):
            kids = self.children.get(oid, {}).get((segments[1], segments[2]))
            if kids is not None:
                return self._collection(request, kids)
        return httpx2.Response(404, json={"error": {"code": "NotFound"}})

    @staticmethod
    def _is_configuration(segments):
        return segments[0] in (
            "deviceCompliancePolicies",
            "deviceConfigurations",
            "deviceCompliancePolicyDeviceStateSummary",
        ) or (
            len(segments) == 3
            and segments[0] == "managedDevices"
            and segments[2] in ("deviceCompliancePolicyStates", "deviceConfigurationStates")
        )

    def _configuration(self, request, oid, segments, *, rows_by_user=None, children_by_user=None):
        rows_by_user = self.config_rows if rows_by_user is None else rows_by_user
        children_by_user = self.config_children if children_by_user is None else children_by_user
        rows = rows_by_user.get(oid, {}).get(segments[0], [])
        if len(segments) == 1:
            return self._collection(request, rows)
        found = next((r for r in rows if r["id"] == segments[1]), None)
        if found is None and not (len(segments) in (3, 4) and self.leaky_children):
            return httpx2.Response(404, json={"error": {"code": "NotFound"}})
        if len(segments) == 2:
            return httpx2.Response(200, json=found)
        if len(segments) in (3, 4):
            child = children_by_user.get(oid, {}).get((segments[0], segments[1], segments[2]))
            if isinstance(child, list):
                if len(segments) == 4:
                    item = next((r for r in child if r["id"] == segments[3]), None)
                    return (
                        httpx2.Response(200, json=item) if item else httpx2.Response(404, json={})
                    )
                return self._collection(request, child)
            if isinstance(child, dict):
                return httpx2.Response(200, json=child)
        return httpx2.Response(404, json={"error": {"code": "NotFound"}})

    # -- client side --------------------------------------------------------------------
    @asynccontextmanager
    async def running(self):
        # Enter/exit the app lifespan inside one task (anyio cancel scopes are task-bound),
        # so this works as a pytest fixture whose setup and teardown run in different tasks.
        import asyncio

        ready, stop = asyncio.Event(), asyncio.Event()

        async def lifespan():
            async with self.app.router.lifespan_context(self.app):
                ready.set()
                await stop.wait()

        task = asyncio.create_task(lifespan())
        waiter = asyncio.create_task(ready.wait())
        await asyncio.wait({task, waiter}, return_when=asyncio.FIRST_COMPLETED)
        if task.done():
            task.result()
        try:
            yield self
        finally:
            stop.set()
            await task

    def browser(self) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=self.app),
            base_url="http://localhost",
            follow_redirects=False,
        )

    async def sign_in(self, oid: str):
        """The fake local sign-in: returns (None, response) with the user's bearer."""
        body = {"access_token": f"local-{oid}"}
        return None, SimpleNamespace(
            status_code=200, text=json.dumps(body), json=lambda: dict(body)
        )

    async def mcp(self, bearer: str | None, method: str, params=None, *, client=None):
        client = client or self.browser()
        headers = {"Accept": "application/json, text/event-stream"}
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        return await client.post(
            "/mcp/intune",
            json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
            headers=headers,
        )

    async def call_tool(self, bearer, name, arguments=None):
        init = {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "1"},
        }
        await self.mcp(bearer, "initialize", init)
        return rpc_body(
            await self.mcp(bearer, "tools/call", {"name": name, "arguments": arguments or {}})
        )


def rpc_body(response: httpx2.Response) -> dict:
    text = response.text
    if response.headers.get("content-type", "").startswith("text/event-stream"):
        data = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
        return json.loads(data[-1])
    return json.loads(text)
