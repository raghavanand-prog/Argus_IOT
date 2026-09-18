"""Baseline-building for live-discovered devices.

argus.registry.enrollment.enroll() is the natural fit -- a bounded learning
window building robust (median/MAD) per-feature statistics from real observed
traffic -- except its policy-violation guard (argus.registry.policy.
violates_policy) does ``FLEET[device_type]``, a hard KeyError for any
device_type that isn't one of the ten synthetic profiles. A live-discovered
device's type is legitimately "unknown" (see sensor/discovery.py) -- there is
no declared policy for "unknown" to check against, because the whole concept
of a *declared* per-type allowlist presupposes knowing the type. That's not a
bug to work around; it means the policy-guard step structurally does not
apply here, so this module builds the same Baseline output
(argus.registry.enrollment.Baseline) without it, rather than fabricating a
policy or silently reusing FLEET's guard on the wrong assumption.

Practical effect, stated plainly: live-discovered devices get identity-
fingerprint drift detection (needs a baseline) and the unsupervised anomaly
detector (sensor/live_detect.py), but never policy-violation detection
(argus.detect.rules.policy_detections) or enrollment refusal on policy
grounds -- both structurally require a declared type this sensor never
invents. A user who manually confirms a device's real type could, as a
documented future extension, opt that specific device into the synthetic
FLEET's policy detectors; not implemented here.
"""

from __future__ import annotations

from datetime import datetime

from argus.registry.enrollment import Baseline
from argus.schemas import FeatureVector, FlowRecord


def build_live_baseline(device_id: str, flows_in_window: list[FlowRecord],
                         feature_windows: list[FeatureVector]) -> Baseline | None:
    """Returns None if no traffic was observed during the window -- there is
    nothing to build a baseline from, and returning an empty-but-present
    Baseline would misrepresent "no data" as "a real, if thin, baseline"."""
    if not feature_windows:
        return None

    medians: dict[str, float] = {}
    mads: dict[str, float] = {}
    keys = feature_windows[0].values.keys()
    for k in keys:
        vals = sorted(fw.values[k] for fw in feature_windows)
        med = vals[len(vals) // 2]
        mad = sorted(abs(v - med) for v in vals)[len(vals) // 2]
        medians[k] = med
        mads[k] = mad

    dest_counts: dict[str, int] = {}
    for f in flows_in_window:
        dest_counts[f.dst_ip] = dest_counts.get(f.dst_ip, 0) + 1
    ja4_fingerprints = frozenset(f.tls_ja4 for f in flows_in_window if f.tls_ja4)

    return Baseline(
        device_id=device_id, device_type="unknown", version=1,
        built_at=datetime.utcnow(), medians=medians, mads=mads,
        destinations=dest_counts, ja4_fingerprints=ja4_fingerprints,
    )
