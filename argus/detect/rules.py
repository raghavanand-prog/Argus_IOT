"""Rule/policy detection track: precision, coverage of known attacks, explanations
that need no model (docs/02). Two rule families, both cheap and deterministic:

- policy violation (declared allowlist),
- volume/fanout thresholds standing in for a Suricata/ET-Open-style signature layer
  (the real thing is a documented follow-on -- see STATUS.md).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from argus.registry.policy import violates_policy
from argus.schemas import Detection, FeatureVector, FlowRecord

FANOUT_THRESHOLD = 8
DEST_ENTROPY_THRESHOLD = 2.0


def policy_detections(device_id: str, device_type: str, flows: list[FlowRecord], ts: datetime) -> list[Detection]:
    violating = [f for f in flows if f.device_id == device_id and violates_policy(device_type, f.dst_ip, f.dst_port)]
    if not violating:
        return []
    example = violating[0]
    return [Detection(
        detection_id=str(uuid.uuid4()), ts=ts, device_id=device_id, source="policy",
        signal_name="declared_policy_violation", severity=0.6, confidence=1.0,
        explanation=(
            f"{device_id} contacted {example.dst_ip}:{example.dst_port}, which its "
            f"declared policy for device type '{device_type}' does not permit "
            f"({len(violating)} violating flow(s) in window)."
        ),
        evidence_refs=[f.flow_id for f in violating[:20]],
    )]


def signature_detections(device_id: str, fv: FeatureVector, ts: datetime) -> list[Detection]:
    out: list[Detection] = []
    if fv.values.get("distinct_destinations", 0) >= FANOUT_THRESHOLD:
        out.append(Detection(
            detection_id=str(uuid.uuid4()), ts=ts, device_id=device_id, source="rules",
            signal_name="scan_fanout", severity=0.7, confidence=0.9,
            explanation=(
                f"{device_id} contacted {int(fv.values['distinct_destinations'])} distinct "
                f"destinations in one window (threshold {FANOUT_THRESHOLD}) -- signature of "
                f"a scanning phase."
            ),
            evidence_refs=[fv.flow_id],
        ))
    dns_entropy = fv.values.get("dns_qname_entropy_mean", 0.0)
    dns_len = fv.values.get("dns_qname_length_mean", 0.0)
    if dns_entropy >= 3.5 and dns_len >= 25:
        out.append(Detection(
            detection_id=str(uuid.uuid4()), ts=ts, device_id=device_id, source="rules",
            signal_name="dns_tunnel_suspected", severity=0.65, confidence=0.85,
            explanation=(
                f"{device_id}'s DNS queries this window average {dns_entropy:.2f} bits of "
                f"character entropy over {dns_len:.0f}-character labels -- consistent with "
                f"data encoded into DNS queries rather than a normal hostname lookup."
            ),
            evidence_refs=[fv.flow_id],
        ))
    return out


def identity_detections(device_id: str, observed_ja4: set[str], baseline, ts: datetime) -> list[Detection]:
    """Device identity spoofing (docs/02 scenario 5): a TLS fingerprint never seen
    during this device's enrollment baseline is a strong, subtle compromise signal
    -- subtle because volume/timing can look completely normal (docs/02: "Hard" --
    "subtle profile mismatch against baseline")."""
    if baseline is None or not baseline.ja4_fingerprints or not observed_ja4:
        return []
    unknown = observed_ja4 - set(baseline.ja4_fingerprints)
    if not unknown:
        return []
    return [Detection(
        detection_id=str(uuid.uuid4()), ts=ts, device_id=device_id, source="rules",
        signal_name="identity_fingerprint_mismatch", severity=0.75, confidence=0.8,
        explanation=(
            f"{device_id} presented TLS fingerprint(s) {sorted(unknown)}, none of which were "
            f"observed during its enrollment baseline ({sorted(baseline.ja4_fingerprints)}) -- "
            f"possible identity spoofing (docs/02 scenario 5)."
        ),
        evidence_refs=[],
    )]
