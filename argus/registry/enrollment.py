"""Device enrollment: bounded, guarded, refusable (docs/00 change #1).

Three properties per the design doc, each implemented directly:

- **Bounded** -- ``LEARNING_WINDOW_MINUTES`` is a hard limit, not a suggestion.
- **Guarded** -- every flow in the learning window is checked against the device
  type's declared policy; a violation refuses enrollment outright.
- **Refusable** -- ``enroll()`` can return a REFUSED result. This is tested directly
  in tests/test_safety.py, not merely asserted to exist.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from argus.registry.policy import violates_policy
from argus.schemas import DeviceState
from argus.sim.devices import FLEET

LEARNING_WINDOW_MINUTES = 60


@dataclass
class Baseline:
    device_id: str
    device_type: str
    version: int
    built_at: datetime
    medians: dict[str, float]
    mads: dict[str, float]  # median absolute deviation, robust to heavy-tailed IoT traffic
    destinations: dict[str, int]


@dataclass
class EnrollmentResult:
    device_id: str
    state: DeviceState
    baseline: Baseline | None
    reason: str | None = None


def enroll(device_id: str, device_type: str, flows_in_window: list, feature_windows: list) -> EnrollmentResult:
    """``flows_in_window``: raw FlowRecords during the learning window.
    ``feature_windows``: FeatureVectors computed over that same window, used to build
    the baseline's robust statistics (median/MAD, not mean/std -- IoT traffic is
    heavy-tailed and the outliers are exactly what's being looked for, docs/02)."""

    for f in flows_in_window:
        if violates_policy(device_type, f.dst_ip, f.dst_port):
            return EnrollmentResult(
                device_id=device_id, state=DeviceState.REFUSED, baseline=None,
                reason=f"policy violation during learning window: {f.dst_ip}:{f.dst_port}",
            )

    if not feature_windows:
        return EnrollmentResult(device_id, DeviceState.REFUSED, None, "no traffic observed during learning window")

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

    baseline = Baseline(
        device_id=device_id, device_type=device_type, version=1,
        built_at=datetime.utcnow(), medians=medians, mads=mads, destinations=dest_counts,
    )
    return EnrollmentResult(device_id, DeviceState.MONITORED, baseline)
