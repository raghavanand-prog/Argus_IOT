"""Metadata-only feature extraction (docs/02).

Every feature group here maps to a written justification -- an attack behaviour it's
meant to expose. A feature with no justification doesn't belong here (Arp et al.'s
"spurious correlations" pitfall starts with unjustified features).

Features are computed per (device_id, destination) over a rolling window of flows, so
that periodicity -- the feature the low-and-slow hard case depends on -- has enough
history to be measurable at all.
"""

from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime

from argus.schemas import FeatureVector, FlowRecord

EXTRACTOR_VERSION = "v1"


def _entropy(counts: dict[str, int]) -> float:
    total = sum(counts.values())
    if total == 0:
        return 0.0
    ent = 0.0
    for c in counts.values():
        p = c / total
        if p > 0:
            ent -= p * math.log2(p)
    return ent


def _periodicity_score(timestamps: list[datetime]) -> float:
    """Coefficient-of-variation-based periodicity: low variance in inter-arrival time
    relative to its mean means "regular" -- the beaconing signature (docs/02)."""
    if len(timestamps) < 3:
        return 0.0
    ts = sorted(timestamps)
    gaps = [(ts[i + 1] - ts[i]).total_seconds() for i in range(len(ts) - 1)]
    mean = sum(gaps) / len(gaps)
    if mean == 0:
        return 0.0
    var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
    cv = math.sqrt(var) / mean
    # low CV (regular spacing) -> high periodicity score
    return max(0.0, 1.0 - min(cv, 1.0))


def extract_device_window(device_id: str, flows: list[FlowRecord],
                           window_start: datetime, window_end: datetime) -> FeatureVector:
    """One FeatureVector per device per window, aggregating all its flows in-window.

    Groups implemented: volume/shape, timing, periodicity, destination behaviour, DNS,
    TLS-fingerprint stability. Policy-violation and L2/identity groups are left as
    TODO -- see STATUS.md -- because they need the device registry (Phase 2) to exist
    first (a violation is only defined relative to a declared policy).
    """
    dev_flows = [f for f in flows if f.device_id == device_id]
    if not dev_flows:
        return FeatureVector(
            flow_id="", device_id=device_id, window_start=window_start,
            window_end=window_end, values={}, extractor_version=EXTRACTOR_VERSION,
        )

    bytes_out = [f.bytes_out for f in dev_flows]
    bytes_in = [f.bytes_in for f in dev_flows]
    dst_counts: dict[str, int] = defaultdict(int)
    dns_qnames: set[str] = set()
    ja4s: set[str] = set()
    for f in dev_flows:
        dst_counts[f.dst_ip] += 1
        if f.dns_qname:
            dns_qnames.add(f.dns_qname)
        if f.tls_ja4:
            ja4s.add(f.tls_ja4)

    timestamps = [f.ts_start for f in dev_flows]
    per_dst_periodicity = max(
        (_periodicity_score([f.ts_start for f in dev_flows if f.dst_ip == d]) for d in dst_counts),
        default=0.0,
    )

    values = {
        # volume/shape -- exposes exfiltration, DDoS participation
        "flow_count": float(len(dev_flows)),
        "bytes_out_mean": sum(bytes_out) / len(bytes_out),
        "bytes_out_std": _std(bytes_out),
        "bytes_in_mean": sum(bytes_in) / len(bytes_in),
        "bytes_ratio": (sum(bytes_out) + 1) / (sum(bytes_in) + 1),
        # timing -- exposes scanning cadence / brute force rate
        "mean_iat_s": _mean_iat(timestamps),
        "burstiness": _burstiness(timestamps),
        # periodicity -- exposes beaconing (the low-and-slow hard case)
        "periodicity_score": per_dst_periodicity,
        # destination behaviour -- exposes scanning, C2, lateral movement
        "distinct_destinations": float(len(dst_counts)),
        "destination_entropy": _entropy(dst_counts),
        "fanout_rate": len(dst_counts) / max(len(dev_flows), 1),
        # DNS -- exposes tunnelling
        "distinct_dns_qnames": float(len(dns_qnames)),
        # TLS -- a fingerprint change on a device is a strong compromise signal
        "distinct_ja4": float(len(ja4s)),
    }
    return FeatureVector(
        flow_id=dev_flows[-1].flow_id, device_id=device_id,
        window_start=window_start, window_end=window_end,
        values=values, extractor_version=EXTRACTOR_VERSION,
    )


def _std(xs: list[float]) -> float:
    if len(xs) < 2:
        return 0.0
    m = sum(xs) / len(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / len(xs))


def _mean_iat(ts: list[datetime]) -> float:
    if len(ts) < 2:
        return 0.0
    ts = sorted(ts)
    gaps = [(ts[i + 1] - ts[i]).total_seconds() for i in range(len(ts) - 1)]
    return sum(gaps) / len(gaps)


def _burstiness(ts: list[datetime]) -> float:
    """(std - mean) / (std + mean) of inter-arrival times; near 1 = bursty, near -1 = regular."""
    if len(ts) < 3:
        return 0.0
    ts = sorted(ts)
    gaps = [(ts[i + 1] - ts[i]).total_seconds() for i in range(len(ts) - 1)]
    m = sum(gaps) / len(gaps)
    s = _std(gaps)
    if s + m == 0:
        return 0.0
    return (s - m) / (s + m)
