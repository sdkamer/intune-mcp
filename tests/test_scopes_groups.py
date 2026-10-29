"""Per-tool scope model and group gating at the unit level (everything mocked)."""

import dataclasses

import pytest
from pydantic import ValidationError

from intune_mcp import groups
from intune_mcp.config import (
    APPS_SCOPE,
    CONFIGURATION_SCOPE,
    GRAPH_SCOPE,
    KNOWN_READ_SCOPES,
    RBAC_SCOPE,
    SERVICE_CONFIG_SCOPE,
    Settings,
)
from intune_mcp.graph import (
    DEVICE_SPEC,
    CollectionSpec,
    ObjectSpec,
    ScopeNotAllowedError,
    require_known_scope,
)
from intune_mcp.groups import TOOL_GROUPS, ToolGroup, authorize_scopes
from intune_mcp.server import GROUP_REGISTRARS

from .conftest import make_settings

BASE = "https://graph.microsoft.com/"
BAD_SCOPES = [
    BASE + ".default",
    "https://graph.microsoft.com/.default",
    "https://graph.microsoft.com/DeviceManagementManagedDevices.ReadWrite.All",
    "https://graph.microsoft.com/DeviceManagementManagedDevices.PrivilegedOperations.All",
    "https://graph.microsoft.com/DeviceManagementConfiguration.ReadWrite.All",
    "https://graph.microsoft.com/User.Read",
    "https://graph.microsoft.com/Directory.Read.All",
    "DeviceManagementManagedDevices.Read.All",  # not the full-URL form
    "https://graph.microsoft.us/DeviceManagementManagedDevices.Read.All",  # other host
    "https://evil.example/DeviceManagementManagedDevices.Read.All",
    "https://graph.microsoft.com/devicemanagementmanageddevices.read.all",  # case
    GRAPH_SCOPE + " ",
    " " + GRAPH_SCOPE,
    GRAPH_SCOPE + " " + CONFIGURATION_SCOPE,  # several at once
    f"{GRAPH_SCOPE},{CONFIGURATION_SCOPE}",
    "api://11111111-1111-4111-8111-111111111111/mcp-access",
    "openid",
    "",
    None,
    b"x",
    ["https://graph.microsoft.com/DeviceManagementManagedDevices.Read.All"],
    ("https://graph.microsoft.com/DeviceManagementManagedDevices.Read.All",),
]


def test_known_read_scopes_are_exactly_the_five_read_scopes():
    assert KNOWN_READ_SCOPES == {
        BASE + "DeviceManagementManagedDevices.Read.All",
        BASE + "DeviceManagementConfiguration.Read.All",
        BASE + "DeviceManagementApps.Read.All",
        BASE + "DeviceManagementServiceConfig.Read.All",
        BASE + "DeviceManagementRBAC.Read.All",
    }
    assert {GRAPH_SCOPE, CONFIGURATION_SCOPE, APPS_SCOPE, SERVICE_CONFIG_SCOPE, RBAC_SCOPE} == (
        KNOWN_READ_SCOPES
    )
    assert all(s.endswith(".Read.All") and "ReadWrite" not in s for s in KNOWN_READ_SCOPES)


@pytest.mark.parametrize("scope", sorted(KNOWN_READ_SCOPES))
def test_every_known_scope_is_accepted(scope):
    assert require_known_scope(scope) == scope


@pytest.mark.parametrize("scope", BAD_SCOPES)
def test_scopes_outside_the_allowlist_are_rejected(scope):
    with pytest.raises(ScopeNotAllowedError):
        require_known_scope(scope)


# -- INTUNE_ENABLED_TOOL_GROUPS ---------------------------------------------------------------
def test_default_enables_only_devices():
    s = make_settings()
    assert s.enabled_groups == ("devices",) and s.enabled_tool_groups == "devices"


def test_whitespace_around_entries_is_trimmed(monkeypatch):
    other = ToolGroup("other", CONFIGURATION_SCOPE, ("x",))
    monkeypatch.setitem(TOOL_GROUPS, "other", other)
    assert make_settings(enabled_tool_groups=" devices , other ").enabled_groups == (
        "devices",
        "other",
    )


@pytest.mark.parametrize(
    "value",
    [
        "",  # a single empty entry
        " ",
        ",",
        "devices,",
        ",devices",
        "devices,,devices",
        "devices,devices",
        "devices, devices ",
        "SECRETVALUE",
        "devices,SECRETVALUE",
        "Devices",  # case sensitive
        "devices;compliance",
        "devices\x00",
        "all",
        "*",
    ],
)
def test_invalid_group_lists_are_rejected_without_echoing_the_value(value):
    with pytest.raises(ValidationError) as exc:
        make_settings(enabled_tool_groups=value)
    # What operators and logs see: the rendered error and each message, never the input value.
    text = str(exc.value) + " ".join(e["msg"] for e in exc.value.errors())
    assert "SECRETVALUE" not in text
    assert "enabled_tool_groups" in text


def test_unknown_group_message_lists_known_groups_only():
    with pytest.raises(ValidationError) as exc:
        make_settings(enabled_tool_groups="nope")
    assert "known groups: apps, configuration, devices, enrollment, rbac" in str(exc.value)
    assert "nope" not in str(exc.value)


def test_environment_variable_is_read(monkeypatch):
    for name, value in {
        "INTUNE_TENANT_ID": "11111111-1111-4111-8111-111111111111",
        "INTUNE_CLIENT_ID": "22222222-2222-4222-8222-222222222222",
    }.items():
        monkeypatch.setenv(name, value)
    from cryptography.fernet import Fernet

    monkeypatch.setenv("INTUNE_STORAGE_ENCRYPTION_KEY", Fernet.generate_key().decode())
    assert Settings().enabled_groups == ("devices",)  # unset: default
    monkeypatch.setenv("INTUNE_ENABLED_TOOL_GROUPS", "devices")
    assert Settings().enabled_groups == ("devices",)
    monkeypatch.setenv("INTUNE_ENABLED_TOOL_GROUPS", "bogus")
    with pytest.raises(ValidationError):
        Settings()


# -- the registry ----------------------------------------------------------------------------
def test_registry_scopes_are_allowlisted_and_each_group_has_an_implementation():
    assert set(TOOL_GROUPS) == {"devices", "configuration", "apps", "rbac", "enrollment"}
    assert set(GROUP_REGISTRARS) == set(TOOL_GROUPS)
    for group in TOOL_GROUPS.values():
        assert group.scope in KNOWN_READ_SCOPES and group.tools


def test_only_released_group_scopes_are_used_by_any_group():
    # G4 deliberately activates the existing ServiceConfig allowlist entry.
    assert {g.scope for g in TOOL_GROUPS.values()} == {
        GRAPH_SCOPE,
        CONFIGURATION_SCOPE,
        APPS_SCOPE,
        RBAC_SCOPE,
        SERVICE_CONFIG_SCOPE,
    }
    assert {n: g.scope for n, g in TOOL_GROUPS.items()} == {
        "devices": GRAPH_SCOPE,
        "configuration": CONFIGURATION_SCOPE,
        "apps": APPS_SCOPE,
        "rbac": RBAC_SCOPE,
        "enrollment": SERVICE_CONFIG_SCOPE,
    }


def test_a_group_cannot_declare_a_scope_outside_the_allowlist():
    for scope in BAD_SCOPES[:12]:
        with pytest.raises(ValueError):
            ToolGroup("x", scope, ("t",))


def test_tool_names_are_unique_across_groups():
    names = [t for g in TOOL_GROUPS.values() for t in g.tools]
    assert len(names) == len(set(names))


def test_authorize_scopes_follow_enabled_groups_in_order_without_repeats(monkeypatch):
    monkeypatch.setitem(TOOL_GROUPS, "cfg", ToolGroup("cfg", CONFIGURATION_SCOPE, ("c",)))
    monkeypatch.setitem(TOOL_GROUPS, "cfg2", ToolGroup("cfg2", CONFIGURATION_SCOPE, ("c2",)))
    assert authorize_scopes(("devices",)) == [GRAPH_SCOPE]
    assert authorize_scopes(("devices", "cfg", "cfg2")) == [GRAPH_SCOPE, CONFIGURATION_SCOPE]
    assert authorize_scopes(("cfg",)) == [CONFIGURATION_SCOPE]
    assert groups.TOOL_GROUPS is TOOL_GROUPS


# -- specs ------------------------------------------------------------------------------------
def test_endpoint_specs_must_use_an_allowlisted_scope_and_consistent_path_params():
    with pytest.raises(ValueError):
        dataclasses.replace(DEVICE_SPEC, scope=BASE + ".default")
    with pytest.raises(ValueError):
        ObjectSpec("k", "/a/{device_id}", GRAPH_SCOPE, ("id",))  # undeclared parameter
    with pytest.raises(ValueError):
        CollectionSpec("k", "/a", GRAPH_SCOPE, ("id",), path_params=("device_id",))
    with pytest.raises(ValueError):
        CollectionSpec("k", "/a?$top=1", GRAPH_SCOPE, ("id",))
    with pytest.raises(ValueError):
        CollectionSpec("k", "/a/{device_id", GRAPH_SCOPE, ("id",))
    with pytest.raises(ValueError):
        CollectionSpec("k", "/a", GRAPH_SCOPE, ("id",), max_page_size=101)
