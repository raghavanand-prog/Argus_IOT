"""Simulated testbed engine.

This replaces the original plan's 12-container Docker network for local development and
demo purposes (see the scope decision recorded in CLAUDE.md and decisions.md): it
generates the same *shaped* data -- FlowRecords with realistic per-device-type
statistics, diurnal patterns, and labelled attack windows -- deterministically and in
seconds instead of hours. A `compose/` profile for a real-Docker testbed is a documented
follow-on, not a hidden shortcut.
"""

from __future__ import annotations

import random
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from argus.schemas import FlowRecord, GroundTruthEvent
from argus.sim.attacks import SCENARIOS
from argus.sim.devices import FLEET, diurnal_multiplier, sample_flow, sample_interval


@dataclass
class SimulatedDevice:
    device_id: str
    device_type: str


def synthetic_ip(device_id: str) -> str:
    """Deterministic pseudo-IP for a simulated device -- the single source of truth
    for this mapping (previously inlined separately in run_benign_window, which
    risked drifting out of sync with anything that needed to resolve an IP back to
    a device, e.g. the risk engine's blast-radius lookup in argus/pipeline.py)."""
    return f"10.10.0.{100 + hash(device_id) % 100}"


def build_ip_to_type(devices: list[SimulatedDevice]) -> dict[str, str]:
    return {synthetic_ip(d.device_id): d.device_type for d in devices}


def default_fleet(counts: dict[str, int] | None = None) -> list[SimulatedDevice]:
    """Two instances of at least one type (smart-plug) so fleet-correlation has signal
    for the drift monitor later, per docs/00."""
    counts = counts or {
        "smart-plug": 2, "ip-camera": 1, "thermostat": 1, "smart-speaker": 1,
        "smart-tv": 1, "doorbell": 1, "air-sensor": 1, "smart-lock": 1,
        "hub": 1, "user-laptop": 1,
    }
    devices: list[SimulatedDevice] = []
    for device_type, n in counts.items():
        for i in range(n):
            suffix = f"-{i:02d}" if n > 1 else "-00"
            devices.append(SimulatedDevice(f"{device_type}{suffix}", device_type))
    return devices


def run_benign_window(devices: list[SimulatedDevice], t_start: datetime,
                       duration_minutes: int, seed: int) -> list[FlowRecord]:
    rng = random.Random(seed)
    flows: list[FlowRecord] = []
    t_end = t_start + timedelta(minutes=duration_minutes)

    for dev in devices:
        profile = FLEET[dev.device_type]
        t = t_start
        while t < t_end:
            mult = diurnal_multiplier(t.hour + t.minute / 60)
            wait = sample_interval(profile, rng) / max(mult, 0.15)
            t = t + timedelta(seconds=wait)
            if t >= t_end:
                break
            payload = sample_flow(profile, rng)
            flows.append(FlowRecord(
                flow_id=str(uuid.uuid4()), device_id=dev.device_id,
                ts_start=t, ts_end=t + timedelta(milliseconds=rng.randint(50, 3000)),
                src_ip=synthetic_ip(dev.device_id),
                dst_ip=payload["dst"], dst_port=payload["port"], proto=payload["proto"],
                pkts_out=payload["pkts_out"], pkts_in=payload["pkts_in"],
                bytes_out=payload["bytes_out"], bytes_in=payload["bytes_in"],
                tls_ja4=f"ja4-{dev.device_type}" if "tls" in profile.protocols else None,
                dns_qname=f"{payload['dst']}." if rng.random() < 0.3 else None,
                label="benign",
            ))
    flows.sort(key=lambda f: f.ts_start)
    return flows


def run_scenario(scenario: str, device_id: str, t_start: datetime, seed: int
                  ) -> tuple[list[FlowRecord], list[GroundTruthEvent]]:
    rng = random.Random(seed)
    attack_flows, events = SCENARIOS[scenario](device_id, t_start, rng)
    records = [
        FlowRecord(
            flow_id=str(uuid.uuid4()), device_id=af.device_id, ts_start=af.ts,
            ts_end=af.ts + timedelta(milliseconds=200), src_ip="10.10.0.199",
            dst_ip=af.dst, dst_port=af.port, proto=af.proto,
            pkts_out=max(1, af.bytes_out // 300), pkts_in=max(1, af.bytes_in // 300),
            bytes_out=af.bytes_out, bytes_in=af.bytes_in, tls_ja4=af.tls_ja4, dns_qname=af.dns_qname,
            label=af.label,
        )
        for af in attack_flows
    ]
    return records, events
