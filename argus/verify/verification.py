"""Post-response verification (docs/03): did the threat stop, did the device recover,
did something legitimate break (the false-isolation detector). In the sim engine this
is evaluated against the ground-truth ledger rather than a live connectivity probe --
the real-network version is a documented follow-on (see STATUS.md).
"""

from __future__ import annotations

from datetime import datetime, timedelta

from argus.schemas import GroundTruthEvent, VerificationResult

OUTCOMES = ("contained", "partially_contained", "not_contained", "collateral_damage", "inconclusive")


def verify(action_id: str, device_id: str, action_ts: datetime, tier: int,
           ground_truth: list[GroundTruthEvent], offset_seconds: int = 120) -> VerificationResult:
    checked_at = action_ts + timedelta(seconds=offset_seconds)
    active_attacks = [
        e for e in ground_truth
        if e.src == device_id and e.t_start <= checked_at <= e.t_end + timedelta(seconds=offset_seconds)
    ]

    if tier == 0:
        outcome = "inconclusive"
    elif not active_attacks:
        # nothing malicious was happening on this device -- an action here is a false isolation
        outcome = "collateral_damage" if tier >= 3 else "inconclusive"
    elif tier >= 3:
        outcome = "contained"
    elif tier == 2:
        outcome = "partially_contained"
    else:
        outcome = "not_contained"

    return VerificationResult(
        action_id=action_id, checked_at=checked_at, offset_seconds=offset_seconds,
        outcome=outcome, details={"active_attacks": str(len(active_attacks)), "tier": str(tier)},
    )
