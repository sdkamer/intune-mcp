"""Helpers shared by the tool groups' registrars: paging output and the one-page read wrapper."""

from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field

from .graph import (
    MAX_PAGE_SIZE,
    CollectionPage,
    CollectionSpec,
    ReadPlan,
    audit_target,
)

if TYPE_CHECKING:
    from .server import ToolContext

PAGE_SIZE = Annotated[
    int,
    Field(ge=1, le=MAX_PAGE_SIZE, description="Items per page (ignored when page_token is set)"),
]
PAGE_TOKEN = Annotated[
    str | None, Field(description="next_page_token from the previous page; omit for page 1")
]
LIST_NOTE = "More pages exist; this is not the full inventory."
PARTIAL_NOTE = "More pages exist; this is not the complete result."


def paged(key: str, page: CollectionPage, note: str) -> dict[str, Any]:
    more = page.next_page_token is not None
    return {
        key: page.rows,
        "count": len(page.rows),
        "next_page_token": page.next_page_token,
        "complete": not more,
        "note": note if more else None,
    }


def filter_names(plan: ReadPlan) -> dict[str, str]:
    """Audited filter field names: the ones in the resolved plan, i.e. actually sent to Graph."""
    return {
        "filters": ",".join(f.name for f in plan.spec.filters if f.name in plan.filters) or "none"
    }


def planned_names(
    spec: CollectionSpec, filters: dict[str, Any] | None, page_token: str | None
) -> dict[str, str]:
    """Audited names when planning has not (yet) succeeded: the first page's own arguments.

    With a page_token the arguments are ignored (the token's filters apply), so none are named.
    """
    if page_token:
        return {"filters": "unresolved"}
    supplied = {name for name, value in (filters or {}).items() if value is not None}
    return {"filters": ",".join(f.name for f in spec.filters if f.name in supplied) or "none"}


def make_read_page(ctx: "ToolContext"):
    """The one-page collection read for a group's registrar, bound to its ToolContext."""
    graph = ctx.graph

    async def read_page(
        tool: str,
        target: str,
        spec: CollectionSpec,
        *,
        path_args: dict[str, Any] | None = None,
        filters: dict[str, Any] | None = None,
        page_size: int,
        page_token: str | None,
        audit_id: bool = False,
        audit_filters: bool = False,
    ) -> CollectionPage:
        pre = planned_names(spec, filters, page_token) if audit_filters else {}

        async def call(graph_token, cid, plan):
            return plan, await graph.fetch_page(graph_token, plan, cid)

        identity, correlation_id, (plan, page) = await ctx.run(
            tool,
            target,
            spec,
            call,
            prepare=lambda: graph.plan(
                spec,
                path_args=path_args,
                filters=filters,
                page_size=page_size,
                page_token=page_token,
            ),
            extra=pre,
            plan_extra=filter_names if audit_filters else None,
        )
        ok = {"target": audit_target(spec, target)} if audit_id else {}
        ctx.audit(
            tool,
            identity,
            correlation_id,
            "ok",
            **ok,
            returned=len(page.rows),
            more=page.next_page_token is not None,
            **(filter_names(plan) if audit_filters else {}),
        )
        return page

    return read_page
