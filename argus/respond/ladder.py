"""Response ladder + enforcement adapters (docs/03).

Prefer the narrowest effective action. ``DryRunAdapter`` is the default and the only
one wired into the demo pipeline; ``NoOpAdapter`` represents the detection-only "L0"
baseline used by the ablation runner (eval/harness.py).
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Protocol

from argus.respond.guard import ActionRateLimiter, GuardVerdict, KillSwitch, evaluate

TIERS = {
    0: "observe", 1: "alert", 2: "rate_limit", 3: "block_destination",
    4: "isolate", 5: "require_approval",
}


def tier_for_risk(risk_score: float, singleton: bool, is_drifting: bool) -> int:
    if is_drifting:
        return 1 if risk_score >= 0.3 else 0
    if risk_score >= 0.8 and singleton:
        return 4
    if risk_score >= 0.6 and singleton:
        return 3
    if risk_score >= 0.5 and singleton:
        return 2
    if risk_score >= 0.3:
        return 1
    return 0


class EnforcementAdapter(Protocol):
    def apply(self, action_id: str, tier: int, device_id: str) -> dict: ...
    def revert(self, action_id: str) -> dict: ...


@dataclass
class DryRunAdapter:
    """Default adapter: logs intent, changes nothing (docs/03)."""

    log: list[dict] = field(default_factory=list)

    def apply(self, action_id: str, tier: int, device_id: str) -> dict:
        entry = {"action_id": action_id, "tier": tier, "device_id": device_id,
                  "applied_at": time.time(), "dry_run": True, "rule": None}
        self.log.append(entry)
        return entry

    def revert(self, action_id: str) -> dict:
        return {"action_id": action_id, "reverted": True, "dry_run": True}


@dataclass
class NoOpAdapter:
    """Ablation baseline: the detection-only system the field actually builds (A6)."""

    def apply(self, action_id: str, tier: int, device_id: str) -> dict:
        return {"action_id": action_id, "tier": tier, "device_id": device_id, "noop": True}

    def revert(self, action_id: str) -> dict:
        return {"action_id": action_id, "noop": True}


@dataclass
class ResponseOutcome:
    bundle_id: str
    action: str
    tier: int
    dry_run: bool
    guard: GuardVerdict
    action_id: str | None
    adapter_result: dict | None


def decide_and_respond(
    *, device_id: str, device_type: str, risk_score: float, conformal_set: list[str] | None,
    is_drifting: bool, kill_switch: KillSwitch, rate_limiter: ActionRateLimiter,
    enforce_enabled: bool, adapter: EnforcementAdapter, now: float | None = None,
) -> ResponseOutcome:
    """``now``: simulated-clock seconds, not wall-clock (CLAUDE.md's determinism rule).
    Rate-limiting against ``time.time()`` would make a fast pipeline run over
    simulated hours look like a real-time burst and corrupt evidence replay -- this
    was caught by exactly the replay check docs/09 says should catch it."""
    singleton = bool(conformal_set) and len(conformal_set) == 1
    tier = tier_for_risk(risk_score, singleton, is_drifting)
    verdict = evaluate(
        device_type=device_type, tier=tier, risk_score=risk_score, conformal_set=conformal_set,
        is_drifting=is_drifting, kill_switch=kill_switch, rate_limiter=rate_limiter,
        device_id=device_id, enforce_enabled=enforce_enabled, now=now,
    )
    action = TIERS[tier if verdict.allow else 0]
    action_id = None
    result = None
    if verdict.allow and tier > 0:
        action_id = str(uuid.uuid4())
        rate_limiter.record(device_id, now)
        if enforce_enabled:
            result = adapter.apply(action_id, tier, device_id)
        else:
            result = DryRunAdapter().apply(action_id, tier, device_id)

    return ResponseOutcome(
        bundle_id="", action=action, tier=tier if verdict.allow else 0,
        dry_run=not enforce_enabled, guard=verdict, action_id=action_id, adapter_result=result,
    )
