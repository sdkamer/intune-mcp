"""Explicit, single-tenant configuration. Never discover deployment identity from requests."""

from uuid import UUID

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

GRAPH_SCOPE_BASE = "https://graph.microsoft.com/"
GRAPH_SCOPE_NAME = "DeviceManagementManagedDevices.Read.All"
GRAPH_SCOPE = f"{GRAPH_SCOPE_BASE}{GRAPH_SCOPE_NAME}"
# Closed allowlist of delegated Graph scopes this server may ever request: read only, full-URL
# form, exact match (no `.default`, no ReadWrite, no other hosts, never several at once). Defining
# a scope here does not enable it: only the tool groups the user enables
# (INTUNE_ENABLED_TOOL_GROUPS, see groups.py) put their scope into the sign-in request.
CONFIGURATION_SCOPE_NAME = "DeviceManagementConfiguration.Read.All"
CONFIGURATION_SCOPE = f"{GRAPH_SCOPE_BASE}{CONFIGURATION_SCOPE_NAME}"
APPS_SCOPE = f"{GRAPH_SCOPE_BASE}DeviceManagementApps.Read.All"
SERVICE_CONFIG_SCOPE = f"{GRAPH_SCOPE_BASE}DeviceManagementServiceConfig.Read.All"
RBAC_SCOPE = f"{GRAPH_SCOPE_BASE}DeviceManagementRBAC.Read.All"
KNOWN_READ_SCOPES: frozenset[str] = frozenset(
    {GRAPH_SCOPE, CONFIGURATION_SCOPE, APPS_SCOPE, SERVICE_CONFIG_SCOPE, RBAC_SCOPE}
)


class Settings(BaseSettings):
    """Public-client configuration only. There are no secrets in this project."""

    model_config = SettingsConfigDict(
        env_prefix="INTUNE_", extra="ignore", hide_input_in_errors=True
    )

    tenant_id: UUID
    client_id: UUID
    enabled_tool_groups: str = "devices"
    enable_tenant_inventory: bool = False

    @field_validator("enabled_tool_groups")
    @classmethod
    def validate_enabled_tool_groups(cls, value: str) -> str:
        # Messages never echo the configured value. Imported here: groups.py is data-only but
        # lives next to modules that import this one.
        from .groups import TOOL_GROUPS

        entries = [entry.strip() for entry in value.split(",")]
        if any(entry == "" for entry in entries):
            raise ValueError("tool group list must not contain empty entries")
        if len(set(entries)) != len(entries):
            raise ValueError("tool group list must not contain duplicates")
        if any(entry not in TOOL_GROUPS for entry in entries):
            raise ValueError(f"unknown tool group; known groups: {', '.join(sorted(TOOL_GROUPS))}")
        return ",".join(entries)

    @model_validator(mode="after")
    def inventory_needs_devices_group(self):
        if self.enable_tenant_inventory and "devices" not in self.enabled_groups:
            raise ValueError("tenant inventory tools require the devices tool group")
        return self

    @property
    def enabled_groups(self) -> tuple[str, ...]:
        return tuple(self.enabled_tool_groups.split(","))
