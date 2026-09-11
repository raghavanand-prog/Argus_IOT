"""Wraps NftablesAdapter behind the same 3-argument ``apply(action_id, tier,
device_id)`` / ``revert(action_id)`` shape argus/respond/ladder.py already calls
(the ``EnforcementAdapter`` protocol), so it can be handed to
``decide_and_respond()`` exactly like ``DryRunAdapter`` -- the safety guard and the
whole response ladder need no changes to drive real enforcement.

Resolving which physical interface (and, for block_destination, which destination
IP) a given device_id maps to is fabric-specific context the generic ladder doesn't
have, so it's supplied once at construction from the live orchestrator's
``NetworkFabric`` -- not threaded through the ladder's call signature, which stays
identical for every adapter.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from argus.respond.adapters.nft_adapter import NftablesAdapter
from argus.testbed.fabric import DeviceLink


@dataclass
class LiveNftablesAdapter:
    links: dict[str, DeviceLink]
    last_target_ip: dict[str, str] = field(default_factory=dict)
    _inner: NftablesAdapter = field(default_factory=NftablesAdapter)

    def apply(self, action_id: str, tier: int, device_id: str) -> dict:
        link = self.links.get(device_id)
        if link is None:
            return {"action_id": action_id, "tier": tier, "device_id": device_id,
                     "dry_run": False, "rule": None, "error": "unknown device -- no interface to enforce on"}
        dst_ip = self.last_target_ip.get(device_id)
        return self._inner.apply(action_id, tier, device_id, iface=link.root_iface, dst_ip=dst_ip)

    def revert(self, action_id: str) -> dict:
        return self._inner.revert(action_id)

    def list_active(self) -> list[str]:
        return self._inner.list_active()

    def flush(self) -> None:
        """The kill-switch's live-enforcement counterpart: remove every rule this
        adapter (or any other run of it) has installed, in one call."""
        from argus.respond.adapters.nft_adapter import flush_all

        flush_all()
