"""Configuration: public-client settings only; invalid values fail without echoing them."""

import pytest
from pydantic import ValidationError

from intune_mcp.config import Settings

from .conftest import CLIENT_ID, TENANT


def make(**kwargs):
    return Settings(tenant_id=TENANT, client_id=CLIENT_ID, **kwargs)


def test_defaults_enable_only_the_devices_group_and_no_inventory():
    s = make()
    assert s.enabled_groups == ("devices",)
    assert s.enable_tenant_inventory is False


def test_settings_come_from_the_environment(monkeypatch):
    monkeypatch.setenv("INTUNE_TENANT_ID", TENANT)
    monkeypatch.setenv("INTUNE_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("INTUNE_ENABLED_TOOL_GROUPS", "devices, configuration")
    s = Settings()
    assert s.enabled_groups == ("devices", "configuration")


@pytest.mark.parametrize("value", ["", "devices,", ",devices", "devices,,configuration"])
def test_empty_group_entries_are_rejected(value):
    with pytest.raises(ValidationError):
        make(enabled_tool_groups=value)


def test_duplicate_and_unknown_groups_are_rejected():
    for value in ("devices,devices", "devices,nonexistent"):
        with pytest.raises(ValidationError):
            make(enabled_tool_groups=value)


def test_group_errors_do_not_echo_the_value():
    with pytest.raises(ValidationError) as info:
        make(enabled_tool_groups="secret-looking-group-name")
    assert "secret-looking-group-name" not in str(info.value)


def test_tenant_inventory_requires_the_devices_group():
    with pytest.raises(ValidationError):
        make(enabled_tool_groups="configuration", enable_tenant_inventory=True)
    assert make(enable_tenant_inventory=True).enable_tenant_inventory is True


@pytest.mark.parametrize("field", ["tenant_id", "client_id"])
def test_ids_must_be_guids_and_are_not_echoed(field):
    values = {"tenant_id": TENANT, "client_id": CLIENT_ID, field: "not-a-guid-SECRETISH"}
    with pytest.raises(ValidationError) as info:
        Settings(**values)
    assert "SECRETISH" not in str(info.value)
