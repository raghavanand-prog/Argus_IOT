"""Tests for the dataset-track subsampling protocol (argus/data/subsample.py) and
feature-parity check (argus/data/parity.py).

These use a small *synthetic* fixture built in this file -- mimicking the general
shape of a labelled flow-feature dataset release (a label column, a timestamp, a
couple of numeric features) -- never a real downloaded dataset. See
docs/05-data-pipeline.md for why: general internet access, including the actual
CICIoT2023/IoT-23 hosts, is blocked by this environment's outbound proxy allowlist
(verified, not assumed). This is what makes the protocol itself testable and ready
to run the moment real data is reachable, without pretending a download happened.
"""

from datetime import datetime, timedelta

from argus.data.parity import parity_report
from argus.data.subsample import (
    preserve_base_rate_in_test,
    stratified_subsample,
    temporal_split,
)


def _synthetic_rows(n_benign: int = 200, n_ddos: int = 500, n_recon: int = 50) -> list[dict]:
    rows = []
    t0 = datetime(2026, 1, 1)
    idx = 0
    for label, count in (("benign", n_benign), ("ddos", n_ddos), ("recon", n_recon)):
        for i in range(count):
            rows.append({
                "label": label, "ts": t0 + timedelta(seconds=idx),
                "pkt_size_mean": 100.0 + i % 50, "flow_duration": 1.0 + i % 10,
            })
            idx += 1
    return rows


def test_stratified_subsample_caps_dominant_class_but_keeps_small_classes_whole():
    rows = _synthetic_rows(n_benign=200, n_ddos=500, n_recon=50)
    sampled, report = stratified_subsample(rows, label_key="label", cap=100, seed=42)

    assert report.per_class_before == {"benign": 200, "ddos": 500, "recon": 50}
    assert report.per_class_after["ddos"] == 100, "the dominant class must be capped"
    assert report.per_class_after["recon"] == 50, "a class smaller than the cap must be kept whole"
    assert report.per_class_after["benign"] == 100
    assert len(sampled) == report.total_after == 250


def test_stratified_subsample_is_deterministic_for_a_fixed_seed():
    rows = _synthetic_rows()
    s1, r1 = stratified_subsample(rows, "label", cap=100, seed=7)
    s2, r2 = stratified_subsample(rows, "label", cap=100, seed=7)
    assert [r["ts"] for r in s1] == [r["ts"] for r in s2]
    assert r1.input_hash == r2.input_hash


def test_stratified_subsample_different_seeds_can_pick_different_rows():
    rows = _synthetic_rows(n_benign=10, n_ddos=500, n_recon=10)
    s1, _ = stratified_subsample(rows, "label", cap=50, seed=1)
    s2, _ = stratified_subsample(rows, "label", cap=50, seed=2)
    ddos_ts_1 = {r["ts"] for r in s1 if r["label"] == "ddos"}
    ddos_ts_2 = {r["ts"] for r in s2 if r["label"] == "ddos"}
    assert ddos_ts_1 != ddos_ts_2, "different seeds must be able to select a different subsample"


def test_temporal_split_never_leaks_the_future_into_training():
    rows = _synthetic_rows(n_benign=10, n_ddos=10, n_recon=0)
    train, test = temporal_split(rows, ts_key="ts", test_fraction=0.2)
    assert max(r["ts"] for r in train) <= min(r["ts"] for r in test), (
        "every training timestamp must precede every test timestamp -- this is the "
        "whole point of a temporal split (Pendlebury et al., docs/01)"
    )


def test_preserve_base_rate_matches_training_ratio_not_a_fixed_constant():
    train = [{"label": "benign"}] * 90 + [{"label": "ddos"}] * 10  # 90% benign in training
    test = [{"label": "benign"}] * 20 + [{"label": "ddos"}] * 20  # artificially 50/50
    rebalanced = preserve_base_rate_in_test(train, test, "label", "benign", seed=1)
    benign_count = sum(1 for r in rebalanced if r["label"] == "benign")
    attack_count = len(rebalanced) - benign_count
    ratio = benign_count / len(rebalanced)
    assert ratio > 0.8, f"expected the test set to reflect training's 90% benign rate, got {ratio:.2f}"
    assert attack_count < 20, "attack rows must have been downsampled, not benign rows"


def test_parity_report_flags_a_real_disagreement_and_skips_uncomparable_features():
    live = {"pkt_size_mean": 105.0, "flow_duration": 2.0, "periodicity_score": 0.9}
    dataset = {"Header_Length": 105.4, "Duration": 2.0}
    name_map = {"pkt_size_mean": "Header_Length", "flow_duration": "Duration"}

    results = parity_report(live, dataset, name_map)
    assert len(results) == 2, "periodicity_score has no dataset column and must be skipped, not flagged"
    pkt_size_result = next(r for r in results if r.feature_name == "pkt_size_mean")
    assert pkt_size_result.absolute_difference > 0
    duration_result = next(r for r in results if r.feature_name == "flow_duration")
    assert duration_result.absolute_difference == 0
