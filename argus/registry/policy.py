"""Declared, MUD-style (RFC 8520-inspired, not conformant) per-device-type policy.

A device that contacts something outside its declared policy is a high-precision,
zero-model detection (docs/02). This also gates enrollment: if a device violates its
own declared policy *during* its learning window, enrollment is refused -- this is what
makes baseline poisoning hard (docs/00 / docs/01 "why enrollment exists").
"""

from __future__ import annotations

from dataclasses import dataclass

from argus.sim.devices import FLEET


@dataclass(frozen=True)
class PolicyRule:
    allowed_ports: frozenset[int]
    allowed_destinations: frozenset[str]


def declared_policy(device_type: str) -> PolicyRule:
    profile = FLEET[device_type]
    return PolicyRule(
        allowed_ports=frozenset(profile.port_pool),
        allowed_destinations=frozenset(profile.dst_pool),
    )


def violates_policy(device_type: str, dst_ip: str, dst_port: int) -> bool:
    """True if a flow falls outside the device type's declared allowlist.

    Attack traffic in the sim always targets synthetic IPs / out-of-policy ports
    that are never in ``dst_pool``/``port_pool`` for that device type, so this
    catches every implemented scenario by construction -- and does so without any
    model, which is the point (docs/02: "highest-precision features in the system").
    """
    policy = declared_policy(device_type)
    return dst_port not in policy.allowed_ports or dst_ip not in policy.allowed_destinations
