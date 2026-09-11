"""Evidence replay: contribution C2 as a measured property (docs/02, docs/09).

Takes a stored bundle, re-runs the decision path from the values recorded in it, and
compares the outcome to what was stored. The **decision reproducibility rate** this
produces across many bundles is published whatever it is -- a rate below 100% locates
non-determinism, and that's a finding, not a failure to hide (docs/09).
"""

from __future__ import annotations

from dataclasses import dataclass

from argus.evidence.bundle import EvidenceBundle
from argus.respond.guard import ActionRateLimiter, KillSwitch, evaluate
from argus.respond.ladder import tier_for_risk


@dataclass
class ReplayResult:
    bundle_id: str
    reproduced: bool
    original_action: str
    replayed_action: str
    original_tier: int
    replayed_tier: int


def replay(bundle: EvidenceBundle) -> ReplayResult:
    risk_score = bundle.risk["score"]
    conformal_set = bundle.detection.get("conformal_set")
    is_drifting = bundle.device.get("is_drifting", False)
    device_type = bundle.device.get("device_type", "")
    device_id = bundle.device.get("device_id", "")
    enforce_enabled = bundle.decision.get("dry_run") is False

    singleton = bool(conformal_set) and len(conformal_set) == 1
    tier = tier_for_risk(risk_score, singleton, is_drifting)

    # a fresh guard state -- kill switch disengaged, no rate-limit history -- matches
    # the assumption that the bundle records a self-contained decision (docs/09)
    verdict = evaluate(
        device_type=device_type, tier=tier, risk_score=risk_score, conformal_set=conformal_set,
        is_drifting=is_drifting, kill_switch=KillSwitch(), rate_limiter=ActionRateLimiter(),
        device_id=device_id, enforce_enabled=enforce_enabled,
    )
    from argus.respond.ladder import TIERS
    replayed_action = TIERS[tier if verdict.allow else 0]
    replayed_tier = tier if verdict.allow else 0

    original_action = bundle.decision["action"]
    original_tier = bundle.decision["tier"]

    return ReplayResult(
        bundle_id=bundle.bundle_id,
        reproduced=(replayed_action == original_action and replayed_tier == original_tier),
        original_action=original_action, replayed_action=replayed_action,
        original_tier=original_tier, replayed_tier=replayed_tier,
    )


def reproducibility_rate(bundles: list[EvidenceBundle]) -> float:
    if not bundles:
        return 0.0
    results = [replay(b) for b in bundles]
    return sum(r.reproduced for r in results) / len(results)
