"""Integration tests for the ablation mechanism (eval/ablation.py) -- kept to a
single seed and a subset of configs so it stays fast in the main suite; the full
5-seed x 9-config run is `make evaluate` / eval/harness.py, not part of pytest.
"""

from eval.ablation import CONFIGS, run_one


def test_a6_detection_only_never_contains_by_construction():
    """The plan's central baseline claim (docs/13 baseline B4/A6): detection-only
    must never show contained=True, regardless of how high risk gets -- it's the
    field's actual L0 system, and the whole point is that it never acts."""
    cfg = next(c for c in CONFIGS if c.name == "A6_detection_only")
    for scenario, dev_id, dev_type in (("mirai", "smart-plug-00", "smart-plug"),
                                        ("low_and_slow", "smart-speaker-00", "smart-speaker")):
        result = run_one(cfg, scenario, dev_id, dev_type, seed=1)
        assert result.contained is False
        assert result.tp > 0, "detection-only must still detect -- only response is disabled"


def test_a6_detection_metrics_match_a0_by_construction():
    """docs/13: A6 is "identical to A0" in detection metrics by construction --
    both run the exact same detection stack; only response/verification differ."""
    a0 = next(c for c in CONFIGS if c.name == "A0_full_system")
    a6 = next(c for c in CONFIGS if c.name == "A6_detection_only")
    r0 = run_one(a0, "mirai", "smart-plug-00", "smart-plug", seed=3)
    r6 = run_one(a6, "mirai", "smart-plug-00", "smart-plug", seed=3)
    assert (r0.tp, r0.fp, r0.fn, r0.tn) == (r6.tp, r6.fp, r6.fn, r6.tn)


def test_rules_only_and_ml_only_detect_differently():
    """A7 (rules only) and A8 (ML only) must not be silently identical -- if they
    were, the two detection tracks wouldn't actually be adding independent
    coverage, contradicting docs/02's stated reason for having both."""
    a7 = next(c for c in CONFIGS if c.name == "A7_rules_only")
    a8 = next(c for c in CONFIGS if c.name == "A8_ml_only")
    r7 = run_one(a7, "low_and_slow", "smart-speaker-00", "smart-speaker", seed=2)
    r8 = run_one(a8, "low_and_slow", "smart-speaker-00", "smart-speaker", seed=2)
    assert (r7.tp, r7.fp, r7.fn) != (r8.tp, r8.fp, r8.fn) or r7.alerts_raised != r8.alerts_raised


def test_all_nine_configs_are_distinct_objects_with_the_expected_names():
    names = [c.name for c in CONFIGS]
    assert names == [
        "A0_full_system", "A1_no_correlator", "A2_no_risk_engine", "A3_no_conformal_gate",
        "A4_no_drift_monitor", "A5_no_policy_layer", "A6_detection_only", "A7_rules_only", "A8_ml_only",
    ]
