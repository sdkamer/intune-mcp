"""Read-only terms and conditions metadata for the enrollment group.

See docs/tools/TERMS-CATEGORIES.md.
"""

from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field

from .graph import (
    LIST_TERMS_SPEC,
    TERMS_ASSIGNMENTS_SPEC,
    TERMS_SPEC,
    audit_target,
    plan_object,
)
from .tools_common import PAGE_SIZE, PAGE_TOKEN, PARTIAL_NOTE, make_read_page, paged

if TYPE_CHECKING:
    from .server import ToolContext

TERMS_ID = Annotated[str, Field(description="Terms and conditions ID (GUID), as listed")]


def register_terms_tools(ctx: "ToolContext") -> None:
    read_page = make_read_page(ctx)

    @ctx.tool
    async def list_terms_and_conditions(
        page_size: PAGE_SIZE = 25,
        page_token: PAGE_TOKEN = None,
    ) -> dict[str, Any]:
        """Terms and conditions metadata; the terms text itself is never returned."""
        page = await read_page(
            "list_terms_and_conditions",
            "termsAndConditions",
            LIST_TERMS_SPEC,
            page_size=page_size,
            page_token=page_token,
        )
        return paged("terms", page, PARTIAL_NOTE)

    @ctx.tool
    async def get_terms_and_conditions(terms_id: TERMS_ID) -> dict[str, Any]:
        """Name, description, title, version and dates only; no body text or acceptance text."""
        identity, cid, body = await ctx.run(
            "get_terms_and_conditions",
            terms_id,
            TERMS_SPEC,
            lambda token, correlation_id, plan: ctx.graph.fetch_object(token, plan, correlation_id),
            prepare=lambda: plan_object(TERMS_SPEC, path_args={"terms_id": terms_id}),
        )
        ctx.audit(
            "get_terms_and_conditions",
            identity,
            cid,
            "ok",
            target=audit_target(TERMS_SPEC, terms_id),
        )
        return body

    @ctx.tool
    async def get_terms_and_conditions_assignments(
        terms_id: TERMS_ID,
        page_size: PAGE_SIZE = 25,
        page_token: PAGE_TOKEN = None,
    ) -> dict[str, Any]:
        """Sanitized GUID targets, no names; parent checked on every page."""
        page = await read_page(
            "get_terms_and_conditions_assignments",
            terms_id,
            TERMS_ASSIGNMENTS_SPEC,
            path_args={"terms_id": terms_id},
            page_size=page_size,
            page_token=page_token,
            audit_id=True,
        )
        return paged("assignments", page, PARTIAL_NOTE)
