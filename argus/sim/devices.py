"""Device behaviour models.

Why a model per device type instead of one traffic generator: "normal" for a smart TV
and "normal" for an air-quality sensor share nothing. Per-device-type behaviour is what
makes downstream baselining meaningful to test at all (see docs/00 and docs/02).

Each profile describes a *distribution* devices sample from, not a fixed script —
jitter and randomness matter, because a replayed fixed trace would make detection
trivially easy and the whole evaluation meaningless (docs/00, design principle 2).
"""

from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass(frozen=True)
class DeviceProfile:
    device_type: str
    protocols: list[str]
    period_s: float  # mean seconds between benign flows
    jitter_s: float
    dst_pool: list[str]  # endpoints this device type talks to when behaving
    port_pool: list[int]
    bytes_out_range: tuple[int, int]
    bytes_in_range: tuple[int, int]
    criticality: float  # 0..1, used later by the risk engine


FLEET: dict[str, DeviceProfile] = {
    "smart-plug": DeviceProfile(
        "smart-plug", ["mqtt"], period_s=30, jitter_s=5,
        dst_pool=["mqtt.mockcloud.local"], port_pool=[8883],
        bytes_out_range=(80, 220), bytes_in_range=(40, 120), criticality=0.3,
    ),
    "ip-camera": DeviceProfile(
        "ip-camera", ["tls", "http"], period_s=15, jitter_s=6,
        dst_pool=["video.mockcloud.local"], port_pool=[443],
        bytes_out_range=(4000, 60000), bytes_in_range=(200, 900), criticality=0.6,
    ),
    "thermostat": DeviceProfile(
        "thermostat", ["coap"], period_s=60, jitter_s=8,
        dst_pool=["weather.mockcloud.local"], port_pool=[5683],
        bytes_out_range=(60, 150), bytes_in_range=(60, 150), criticality=0.4,
    ),
    "smart-speaker": DeviceProfile(
        "smart-speaker", ["tls"], period_s=45, jitter_s=4,
        dst_pool=["voice.mockcloud.local"], port_pool=[443],
        bytes_out_range=(300, 4000), bytes_in_range=(300, 4000), criticality=0.35,
    ),
    "smart-tv": DeviceProfile(
        "smart-tv", ["http", "tls"], period_s=20, jitter_s=10,
        dst_pool=["content.mockcloud.local", "ads.mockcloud.local", "telemetry.mockcloud.local"],
        port_pool=[443, 80], bytes_out_range=(500, 15000), bytes_in_range=(2000, 90000),
        criticality=0.2,
    ),
    "doorbell": DeviceProfile(
        "doorbell", ["tls", "mqtt"], period_s=120, jitter_s=90,
        dst_pool=["video.mockcloud.local"], port_pool=[443, 8883],
        bytes_out_range=(1000, 20000), bytes_in_range=(200, 800), criticality=0.55,
    ),
    "air-sensor": DeviceProfile(
        "air-sensor", ["mqtt"], period_s=300, jitter_s=20,
        dst_pool=["mqtt.mockcloud.local"], port_pool=[8883],
        bytes_out_range=(50, 90), bytes_in_range=(40, 60), criticality=0.15,
    ),
    "smart-lock": DeviceProfile(
        "smart-lock", ["mqtt", "tls"], period_s=90, jitter_s=15,
        dst_pool=["mqtt.mockcloud.local"], port_pool=[8883, 443],
        bytes_out_range=(60, 200), bytes_in_range=(60, 200), criticality=0.85,
    ),
    "hub": DeviceProfile(
        "hub", ["mqtt", "tls"], period_s=10, jitter_s=2,
        dst_pool=["mqtt.mockcloud.local", "video.mockcloud.local"], port_pool=[8883, 443],
        bytes_out_range=(200, 3000), bytes_in_range=(200, 3000), criticality=0.9,
    ),
    "user-laptop": DeviceProfile(
        "user-laptop", ["http", "tls"], period_s=8, jitter_s=6,
        dst_pool=["web1.example", "web2.example", "web3.example", "mail.example"],
        port_pool=[443, 80], bytes_out_range=(300, 20000), bytes_in_range=(1000, 150000),
        criticality=0.5,
    ),
}


def sample_interval(profile: DeviceProfile, rng: random.Random) -> float:
    return max(0.5, rng.gauss(profile.period_s, profile.jitter_s))


def sample_flow(profile: DeviceProfile, rng: random.Random) -> dict:
    return {
        "proto": "udp" if profile.protocols[0] == "coap" else "tcp",
        "dst": rng.choice(profile.dst_pool),
        "port": rng.choice(profile.port_pool),
        "bytes_out": rng.randint(*profile.bytes_out_range),
        "bytes_in": rng.randint(*profile.bytes_in_range),
        "pkts_out": max(1, rng.randint(*profile.bytes_out_range) // 300),
        "pkts_in": max(1, rng.randint(*profile.bytes_in_range) // 300),
    }


def diurnal_multiplier(hour: float) -> float:
    """Activity multiplier following a quiet-night / evening-peak daily curve."""
    import math

    return 0.35 + 0.65 * (0.5 + 0.5 * math.sin((hour - 8) / 24 * 2 * math.pi))
