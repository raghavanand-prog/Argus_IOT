"""Drift monitor: separate from the behaviour engine on purpose (docs/01, change #2).

Benign change (a firmware update) and malicious change look identical to a raw
deviation score. Conflating them is the classic failure of baseline-deviation
detection. ADWIN (via river) gives an online, cheap, interpretable change-point signal
per (device, feature) stream. Drift *suppresses* escalation; it never triggers it --
that's a deliberate bias toward not breaking things (docs/01, docs/02, docs/03).
"""

from __future__ import annotations

from river.drift import ADWIN


class DeviceDriftMonitor:
    """One ADWIN detector per (device_id, feature_name), lazily created."""

    def __init__(self) -> None:
        self._detectors: dict[tuple[str, str], ADWIN] = {}
        self._drifting: dict[str, bool] = {}

    def update(self, device_id: str, feature_values: dict[str, float]) -> bool:
        """Feed one window's features for a device; returns True if drift was just
        detected on *any* tracked feature for that device."""
        drifted_now = False
        for name, value in feature_values.items():
            key = (device_id, name)
            det = self._detectors.setdefault(key, ADWIN())
            det.update(value)
            if det.drift_detected:
                drifted_now = True
        if drifted_now:
            self._drifting[device_id] = True
        return drifted_now

    def is_drifting(self, device_id: str) -> bool:
        return self._drifting.get(device_id, False)

    def clear(self, device_id: str) -> None:
        """Called after a re-baseline is accepted."""
        self._drifting[device_id] = False


def is_benign_drift(fleet_correlated_count: int, policy_violation: bool) -> bool:
    """Discriminator from docs/02: fleet correlation (other devices of the same type
    drifting together) is the strongest single signal of benign drift; a concurrent
    policy violation points the other way, toward compromise."""
    return fleet_correlated_count >= 2 and not policy_violation
