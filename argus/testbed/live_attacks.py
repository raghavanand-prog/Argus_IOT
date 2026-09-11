"""Real attack scripts: actual TCP/UDP socket operations against actual testbed
namespaces, containment-checked in code (CLAUDE.md rule 3, docs/04's "containment is
enforced in code, not assumed"). Every target IP is validated against the testbed
subnet before a single packet is sent; the check is unconditional, not configurable,
and there is no code path in this module that accepts a caller-supplied bypass.

Two scenarios, matching BUILD-ORDER.md's "never cut" priority: ``mirai`` (the easy
case) and ``low_and_slow`` (the deliberately hard beaconing case). The other five
scenarios from docs/02 exist as synthetic-only generators in argus/sim/attacks.py
(see STATUS.md) -- porting all seven to real sockets was judged lower-value than
getting the two load-bearing scenarios solid on the real path.
"""

from __future__ import annotations

import socket
import time
import uuid
from datetime import UTC, datetime

from pyroute2 import netns as pyroute2_netns

from argus.schemas import GroundTruthEvent
from argus.testbed.fabric import SUBNET


class ContainmentViolation(ValueError):
    pass


def assert_in_testbed(ip: str) -> None:
    import ipaddress

    if ipaddress.ip_address(ip) not in SUBNET:
        raise ContainmentViolation(
            f"refusing to target {ip}: outside the testbed subnet {SUBNET}. "
            "This check is unconditional -- see docs/04b and CLAUDE.md rule 3."
        )


def _now() -> datetime:
    return datetime.now(UTC)


def _try_connect(ip: str, port: int, timeout: float = 0.3) -> None:
    assert_in_testbed(ip)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
    except OSError:
        pass  # a refused/unreachable connect attempt is still a real, capturable SYN


def run_mirai_live(ns_name: str, attacker_ip: str, victim_ip: str, c2_ip: str,
                    scan_targets: list[str]) -> list[GroundTruthEvent]:
    pyroute2_netns.setns(ns_name)
    for ip in [attacker_ip, victim_ip, c2_ip, *scan_targets]:
        assert_in_testbed(ip)

    events: list[GroundTruthEvent] = []

    t0 = _now()
    for target in scan_targets:
        for port in (22, 23, 80, 8080):
            _try_connect(target, port, timeout=0.15)
    t1 = _now()
    events.append(GroundTruthEvent(
        event_id=str(uuid.uuid4()), scenario="mirai", phase="scan",
        t_start=t0, t_end=t1, src=attacker_ip, dst=scan_targets, technique="T1595",
    ))

    t0 = _now()
    for _ in range(15):
        _try_connect(victim_ip, 23, timeout=0.1)
        time.sleep(0.05)
    t1 = _now()
    events.append(GroundTruthEvent(
        event_id=str(uuid.uuid4()), scenario="mirai", phase="bruteforce",
        t_start=t0, t_end=t1, src=attacker_ip, dst=[victim_ip], technique="T1110.001",
    ))

    t0 = _now()
    _try_connect(c2_ip, 6667, timeout=0.3)
    t1 = _now()
    events.append(GroundTruthEvent(
        event_id=str(uuid.uuid4()), scenario="mirai", phase="c2_registration",
        t_start=t0, t_end=t1, src=attacker_ip, dst=[c2_ip], technique="T1071",
    ))

    t0 = _now()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for _ in range(40):
            s.sendto(b"\x00" * 512, (c2_ip, 53))
            time.sleep(0.02)
    t1 = _now()
    events.append(GroundTruthEvent(
        event_id=str(uuid.uuid4()), scenario="mirai", phase="ddos",
        t_start=t0, t_end=t1, src=attacker_ip, dst=[c2_ip], technique="T1498",
    ))

    return events


def run_low_and_slow_live(ns_name: str, attacker_ip: str, c2_ip: str,
                           duration_s: float, interval_s: float = 8.0) -> list[GroundTruthEvent]:
    """Compressed-timescale beaconing: real, small, evenly-spaced TCP bursts to a
    local C2 stand-in. ``interval_s`` is far shorter than the original design's
    "8 minutes" (docs/04) so a live demo run finishes in a reasonable wall-clock
    time; the *shape* -- regular spacing, small payload, single destination -- is
    what the periodicity feature actually keys on, and that's preserved exactly."""
    pyroute2_netns.setns(ns_name)
    assert_in_testbed(attacker_ip)
    assert_in_testbed(c2_ip)

    t_start = _now()
    deadline = time.monotonic() + duration_s
    while time.monotonic() < deadline:
        _try_connect(c2_ip, 443, timeout=0.2)
        time.sleep(interval_s)
    t_end = _now()

    return [GroundTruthEvent(
        event_id=str(uuid.uuid4()), scenario="low_and_slow", phase="beacon",
        t_start=t_start, t_end=t_end, src=attacker_ip, dst=[c2_ip], technique="T1071.001",
    )]
