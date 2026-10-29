"""The signed-in caller: stable identifiers only, never names or UPNs."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Identity:
    tenant_id: str
    object_id: str
    subject: str
