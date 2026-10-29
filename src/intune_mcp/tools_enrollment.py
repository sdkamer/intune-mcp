"""Opt-in, read-only enrollment metadata and typed settings (docs/tools/ENROLLMENT.md)."""

from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field

from .graph import (
    APPLE_CERTIFICATE_SPEC,
    ENROLLMENT_ASSIGNMENTS_SPEC,
    ENROLLMENT_SPEC,
    LIST_ENROLLMENTS_SPEC,
    ObjectSpec,
    audit_target,
    plan_object,
)
from .tools_common import PAGE_SIZE, PAGE_TOKEN, PARTIAL_NOTE, make_read_page, paged
from .tools_terms import register_terms_tools

if TYPE_CHECKING:
    from .server import ToolContext

CONFIGURATION_ID = Annotated[
    str,
    Field(
        description=(
            "Intune enrollment configuration ID, exactly as listed: "
            "a GUID, sometimes followed by _<suffix>"
        )
    ),
]


def register_enrollment_tools(ctx: "ToolContext") -> None:
    read_page = make_read_page(ctx)

    async def read_object(tool: str, spec: ObjectSpec, configuration_id: str | None = None):
        args = {} if configuration_id is None else {"configuration_id": configuration_id}
        target = configuration_id or "applePushNotificationCertificate"
        identity, cid, body = await ctx.run(
            tool,
            target,
            spec,
            lambda token, correlation_id, plan: ctx.graph.fetch_object(token, plan, correlation_id),
            prepare=lambda: plan_object(spec, path_args=args),
        )
        ctx.audit(tool, identity, cid, "ok", target=audit_target(spec, target))
        return body

    @ctx.tool
    async def list_enrollment_configurations(
        page_size: PAGE_SIZE = 25,
        page_token: PAGE_TOKEN = None,
    ) -> dict[str, Any]:
        """Visible enrollment configuration metadata; text is bounded and untrusted data."""
        page = await read_page(
            "list_enrollment_configurations",
            "deviceEnrollmentConfigurations",
            LIST_ENROLLMENTS_SPEC,
            page_size=page_size,
            page_token=page_token,
        )
        return paged("configurations", page, PARTIAL_NOTE)

    @ctx.tool
    async def get_enrollment_configuration(configuration_id: CONFIGURATION_ID) -> dict[str, Any]:
        """Metadata plus reviewed typed settings only, not the complete/effective configuration.

        settings_available=false means unsupported type, not an empty configuration.
        """
        return await read_object("get_enrollment_configuration", ENROLLMENT_SPEC, configuration_id)

    @ctx.tool
    async def get_enrollment_configuration_assignments(
        configuration_id: CONFIGURATION_ID,
        page_size: PAGE_SIZE = 25,
        page_token: PAGE_TOKEN = None,
    ) -> dict[str, Any]:
        """Sanitized GUID targets, no names or filters; parent checked on every page."""
        page = await read_page(
            "get_enrollment_configuration_assignments",
            configuration_id,
            ENROLLMENT_ASSIGNMENTS_SPEC,
            path_args={"configuration_id": configuration_id},
            page_size=page_size,
            page_token=page_token,
            audit_id=True,
        )
        return paged("assignments", page, PARTIAL_NOTE)

    @ctx.tool
    async def get_apple_push_certificate_status() -> dict[str, Any]:
        """Certificate dates and days until expiry only; raw upload status withheld as null.

        No Apple ID, certificate, serial number, topic or failure reason.
        """
        return await read_object("get_apple_push_certificate_status", APPLE_CERTIFICATE_SPEC)

    register_terms_tools(ctx)
