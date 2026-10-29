"""Shared fixtures. Microsoft Entra and Graph are mocked here; nothing in this suite is live."""

import time
import uuid

import jwt
import pytest

from intune_mcp.config import GRAPH_SCOPE_NAME, Settings

TENANT = "11111111-1111-4111-8111-111111111111"
OTHER_TENANT = "99999999-9999-4999-8999-999999999999"
CLIENT_ID = "22222222-2222-4222-8222-222222222222"
OID_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
OID_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def graph_token(oid: str = OID_A, **overrides) -> str:
    """Stand-in for an opaque Graph token. Only the test Graph stub reads it (oid, scp);
    the server itself never decodes a Graph token."""
    now = int(time.time())
    claims = {
        "aud": "https://graph.microsoft.com",
        "tid": TENANT,
        "oid": oid,
        "scp": GRAPH_SCOPE_NAME,
        "iat": now,
        "exp": now + 3600,
    }
    claims.update(overrides)
    return jwt.encode({k: v for k, v in claims.items() if v is not None}, "k" * 32, "HS256")


def make_settings(**overrides) -> Settings:
    return Settings(
        **{"tenant_id": uuid.UUID(TENANT), "client_id": uuid.UUID(CLIENT_ID), **overrides}
    )


@pytest.fixture(autouse=True)
def no_update_check(monkeypatch):
    """The suite never touches the network or the user's cache for the release check
    (also inherited by subprocesses). Updater tests turn it back on in an isolated cache."""
    monkeypatch.setenv("INTUNE_UPDATE_CHECK", "0")


@pytest.fixture
def settings() -> Settings:
    return make_settings()
