"""Closed registry of tool groups. Data only: no imports of graph, auth or server code.

A group is the unit of enablement and of least privilege: it names exactly ONE delegated Graph
read scope and the tools that use it. Enabling a group (INTUNE_ENABLED_TOOL_GROUPS) registers its
tools and adds its scope to the sign-in request; disabled groups' tools do not exist and their
scope is never requested. The tool implementations are attached in server.py (`GROUP_REGISTRARS`),
and build_server fails at startup if the two disagree.
"""

from dataclasses import dataclass

from .config import (
    APPS_SCOPE,
    CONFIGURATION_SCOPE,
    GRAPH_SCOPE,
    KNOWN_READ_SCOPES,
    RBAC_SCOPE,
    SERVICE_CONFIG_SCOPE,
)


@dataclass(frozen=True)
class ToolGroup:
    name: str
    scope: str
    tools: tuple[str, ...]
    # The ONE other scope a tool of this group may use for a single parent-visibility check (see
    # ARCHITECTURE "Authorization model"). It is exchanged only if the group that owns that
    # scope is enabled; otherwise the tool fails closed. Each exchange still requests one scope.
    parent_scope: str | None = None

    def __post_init__(self) -> None:
        if self.scope not in KNOWN_READ_SCOPES:
            raise ValueError("tool group scope is not an allowlisted read scope")
        if self.parent_scope is not None and (
            self.parent_scope not in KNOWN_READ_SCOPES or self.parent_scope == self.scope
        ):
            raise ValueError("tool group parent scope must be another allowlisted read scope")


TOOL_GROUPS: dict[str, ToolGroup] = {
    # Add + admin-consent ServiceConfig read BEFORE enabling: sign-in changes for everyone.
    "enrollment": ToolGroup(
        name="enrollment",
        scope=SERVICE_CONFIG_SCOPE,
        tools=(
            "list_enrollment_configurations",
            "get_enrollment_configuration",
            "get_enrollment_configuration_assignments",
            "get_apple_push_certificate_status",
            "list_terms_and_conditions",
            "get_terms_and_conditions",
            "get_terms_and_conditions_assignments",
        ),
    ),
    # Add + admin-consent RBAC read BEFORE enabling: sign-in changes for everyone.
    "rbac": ToolGroup(
        name="rbac",
        scope=RBAC_SCOPE,
        tools=(
            "list_role_definitions",
            "get_role_definition",
            "list_role_assignments",
            "get_role_assignment",
        ),
    ),
    # Add and admin-consent the apps permission BEFORE enabling (ENTRA-SETUP).
    "apps": ToolGroup(
        name="apps",
        scope=APPS_SCOPE,
        tools=(
            "list_apps",
            "get_app",
            "get_app_assignments",
            "list_app_protection_policies",
            "get_app_protection_policy",
            "get_app_protection_policy_assignments",
            "list_app_categories",
            "list_app_configuration_policies",
            "get_app_configuration_policy",
            "get_app_configuration_policy_assignments",
        ),
    ),
    "devices": ToolGroup(
        name="devices",
        scope=GRAPH_SCOPE,
        tools=(
            "list_devices",
            "get_device",
            "search_devices",
            "count_devices",
            "device_summary",
        ),
    ),
    # Needs DeviceManagementConfiguration.Read.All, a SECOND permission: add and admin-consent it
    # in Entra BEFORE enabling this group, or sign-in fails for everyone (see ENTRA-SETUP).
    # parent_scope: the per-device state tools confirm the device is visible with a GET of
    # managedDevices/{id}, which needs the managed-devices scope (group `devices`).
    "configuration": ToolGroup(
        name="configuration",
        scope=CONFIGURATION_SCOPE,
        parent_scope=GRAPH_SCOPE,
        tools=(
            "get_device_compliance_states",
            "get_device_configuration_states",
            "list_compliance_policies",
            "get_compliance_policy",
            "get_compliance_policy_settings",
            "get_compliance_policy_status_overview",
            "get_compliance_policy_assignments",
            "list_configuration_profiles",
            "get_configuration_profile",
            "get_configuration_profile_settings",
            "get_configuration_profile_status_overview",
            "get_configuration_profile_assignments",
            "get_compliance_summary",
            "get_configuration_state_summary",
        ),
    ),
}


def authorize_scopes(enabled: tuple[str, ...]) -> list[str]:
    """Graph scopes for the sign-in request: those of the enabled groups, in order, no repeats."""
    scopes: list[str] = []
    for name in enabled:
        scope = TOOL_GROUPS[name].scope
        if scope not in scopes:
            scopes.append(scope)
    return scopes


# Opt-in tenant inventory tools (INTUNE_ENABLE_TENANT_INVENTORY). They use the `devices` group's
# scope but are registered outside it: not part of the group's default tool list.
INVENTORY_GROUP = "devices"
INVENTORY_TOOLS = ("list_detected_apps", "get_detected_app")
# Same opt-in flag, `configuration` scope. A live scoped-user check showed these aggregates are NOT
# limited to the caller's Intune scope (counts and setting names). Needs the configuration group.
TENANT_AGGREGATE_GROUP = "configuration"
TENANT_AGGREGATE_TOOLS = ("list_compliance_setting_state_summaries",)
