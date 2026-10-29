"""Configuration group: tenant-level state summaries, counts only.

See docs/tools/CONFIG-SUMMARIES.md.
"""

from typing import TYPE_CHECKING, Any

from .graph import (
    COMPLIANCE_SETTING_SUMMARIES_SPEC,
    CONFIGURATION_STATE_SUMMARY_SPEC,
    plan_object,
)
from .tools_common import PAGE_SIZE, PAGE_TOKEN, PARTIAL_NOTE, make_read_page, paged

if TYPE_CHECKING:
    from .server import ToolContext


def register_config_summary_tools(ctx: "ToolContext") -> None:
    graph = ctx.graph

    @ctx.tool
    async def get_configuration_state_summary() -> dict[str, Any]:
        """Tenant-wide device configuration state counts (compliant, error, conflict, ...).

        Numbers only. A tenant-level aggregate that is NOT limited to this user's Intune scope:
        counts may include devices the user cannot otherwise see. Unverified live.
        """
        spec = CONFIGURATION_STATE_SUMMARY_SPEC
        target = "deviceConfigurationDeviceStateSummaries"
        identity, correlation_id, summary = await ctx.run(
            "get_configuration_state_summary",
            target,
            spec,
            lambda graph_token, cid, plan: graph.fetch_object(graph_token, plan, cid),
            prepare=lambda: plan_object(spec, path_args={}),
        )
        ctx.audit("get_configuration_state_summary", identity, correlation_id, "ok")
        return summary


def register_tenant_aggregate_tools(ctx: "ToolContext") -> None:
    """Opt-in (INTUNE_ENABLE_TENANT_INVENTORY): a live check showed they ignore scope."""
    read_page = make_read_page(ctx)

    @ctx.tool
    async def list_compliance_setting_state_summaries(
        page_size: PAGE_SIZE = 25,
        page_token: PAGE_TOKEN = None,
    ) -> dict[str, Any]:
        """Per compliance setting: identifier names, platform and device counts by state.

        No setting values. Tenant-level aggregates that are NOT limited to this user's Intune
        scope: counts may include devices the user cannot see. A null setting name means it was
        not a plain identifier. Unverified live.
        """
        page = await read_page(
            "list_compliance_setting_state_summaries",
            "deviceCompliancePolicySettingStateSummaries",
            COMPLIANCE_SETTING_SUMMARIES_SPEC,
            page_size=page_size,
            page_token=page_token,
        )
        return paged("setting_summaries", page, PARTIAL_NOTE)
