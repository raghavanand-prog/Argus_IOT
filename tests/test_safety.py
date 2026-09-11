"""Safety-mechanism tests (docs/03: "a safety mechanism that has never been exercised
is decoration"). Each of these is required, not optional, per CLAUDE.md.
"""

from argus.respond.guard import ActionRateLimiter, KillSwitch, evaluate
from argus.respond.ladder import DryRunAdapter, decide_and_respond


def test_kill_switch_vetoes_every_tier():
    ks = KillSwitch()
    ks.engage()
    try:
        verdict = evaluate(
            device_type="smart-plug", tier=4, risk_score=0.95, conformal_set=["attack"],
            is_drifting=False, kill_switch=ks, rate_limiter=ActionRateLimiter(),
            device_id="d1", enforce_enabled=True,
        )
        assert not verdict.allow
        assert "kill_switch_disengaged" in verdict.gates_failed
    finally:
        ks.disengage()


def test_protected_device_cannot_be_isolated_even_at_max_risk():
    verdict = evaluate(
        device_type="hub", tier=4, risk_score=1.0, conformal_set=["attack"],
        is_drifting=False, kill_switch=KillSwitch(), rate_limiter=ActionRateLimiter(),
        device_id="hub-00", enforce_enabled=True,
    )
    assert not verdict.allow
    assert "protected_device_list" in verdict.gates_failed


def test_non_singleton_conformal_set_blocks_escalation():
    verdict = evaluate(
        device_type="smart-tv", tier=3, risk_score=0.9, conformal_set=["benign", "attack"],
        is_drifting=False, kill_switch=KillSwitch(), rate_limiter=ActionRateLimiter(),
        device_id="tv-00", enforce_enabled=True,
    )
    assert not verdict.allow
    assert "conformal_singleton_for_escalation" in verdict.gates_failed


def test_drift_caps_action_at_alert():
    verdict = evaluate(
        device_type="smart-plug", tier=4, risk_score=0.9, conformal_set=["attack"],
        is_drifting=True, kill_switch=KillSwitch(), rate_limiter=ActionRateLimiter(),
        device_id="p1", enforce_enabled=True,
    )
    assert not verdict.allow
    assert "drift_gate" in verdict.gates_failed


def test_action_rate_limit_stops_a_detection_storm():
    limiter = ActionRateLimiter()
    allowed = 0
    for i in range(10):
        outcome = decide_and_respond(
            device_id="storm-device", device_type="smart-tv", risk_score=0.9,
            conformal_set=["attack"], is_drifting=False, kill_switch=KillSwitch(),
            rate_limiter=limiter, enforce_enabled=False, adapter=DryRunAdapter(),
        )
        if outcome.guard.allow and outcome.tier > 0:
            allowed += 1
    assert allowed <= 5, "per-device rate limit (5/hour) must cap a detection storm"


def test_dry_run_never_produces_a_non_dry_run_adapter_result():
    outcome = decide_and_respond(
        device_id="p2", device_type="smart-plug", risk_score=0.9, conformal_set=["attack"],
        is_drifting=False, kill_switch=KillSwitch(), rate_limiter=ActionRateLimiter(),
        enforce_enabled=False, adapter=DryRunAdapter(),
    )
    assert outcome.dry_run is True
    assert outcome.adapter_result is not None
    assert outcome.adapter_result["dry_run"] is True
