"""Tests for the CICIoT2023 evaluation track (docs/17-cicioT2023-validation.md).

Unlike tests/test_subsampling.py's dataset-agnostic protocol tests (which use a
synthetic fixture because no real dataset was reachable at the time), these run
against argus/data/fixtures/cicioT2023_eval_subset.csv -- a real, committed slice of
the actual uploaded CICIoT2023 export (the held-out test split from one real run of
scripts/export_cicioT2023_snapshot.py). Real data is now available; these tests use
it rather than a stand-in.

The integration test below calls argus.pipeline.run_cicioT2023_evaluation directly
-- the same function the API and the export script call -- with small split sizes
appropriate to this 2,000-row fixture, so it stays fast while exercising the real
production code path end-to-end: load -> split -> fit detector -> predict ->
compare to ground truth -> correlate -> risk -> respond -> evidence -> persist.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from argus.data.cicioT2023 import (
    CICIOT_FEATURE_KEYS,
    load_rows,
    split_dataset,
    to_feature_vector,
)
from argus.data.metrics import binary_metrics, classify_outcome, confusion_matrix
from argus.db.models import EvidenceBundleRow, IncidentRow, init_db, make_engine
from argus.evidence.bundle import EvidenceBundle
from argus.evidence.replay import replay
from argus.pipeline import run_cicioT2023_evaluation

FIXTURE = Path(__file__).parent.parent / "argus" / "data" / "fixtures" / "cicioT2023_eval_subset.csv"


# ---- metrics.py: hand-verified against a known example ----------------------------

def test_confusion_matrix_counts_are_correct():
    y_true = [1, 1, 0, 0, 1]
    y_pred = [1, 0, 0, 1, 1]
    cm = confusion_matrix(y_true, y_pred)
    assert (cm.tp, cm.tn, cm.fp, cm.fn) == (2, 1, 1, 1)
    assert cm.total == 5


def test_confusion_matrix_rejects_mismatched_lengths():
    with pytest.raises(ValueError):
        confusion_matrix([1, 0], [1])


def test_binary_metrics_match_hand_computed_values():
    # tp=2, tn=1, fp=1, fn=1 -> accuracy=3/5, precision=2/3, recall=2/3, f1=2/3
    cm = confusion_matrix([1, 1, 0, 0, 1], [1, 0, 0, 1, 1])
    m = binary_metrics(cm)
    assert m["accuracy"] == pytest.approx(0.6)
    assert m["precision"] == pytest.approx(2 / 3)
    assert m["recall"] == pytest.approx(2 / 3)
    assert m["f1"] == pytest.approx(2 / 3)
    assert m["false_positive_rate"] == pytest.approx(0.5)
    assert m["false_negative_rate"] == pytest.approx(1 / 3)


def test_classify_outcome_covers_all_four_cases():
    assert classify_outcome(1, 1) == "TP"
    assert classify_outcome(0, 0) == "TN"
    assert classify_outcome(0, 1) == "FP"
    assert classify_outcome(1, 0) == "FN"


# ---- cicioT2023.py: against the real committed fixture -----------------------------

def test_load_rows_reads_the_real_fixture_without_fabrication():
    rows = load_rows(FIXTURE)
    assert len(rows) == 2000
    assert {r.label for r in rows} == {0, 1}
    # exactly the 8 real feature columns -- never the label, never the row index
    assert set(rows[0].features) == set(CICIOT_FEATURE_KEYS)
    assert "sub_label" not in rows[0].features


def test_split_dataset_is_disjoint_deterministic_and_seed_sensitive():
    rows = load_rows(FIXTURE)
    split = split_dataset(rows, seed=42, n_train_benign=400, n_calib_per_class=150, n_test_per_class=200)

    train_idx = {r.row_index for r in split.train}
    calib_idx = {r.row_index for r in split.calib}
    test_idx = {r.row_index for r in split.test}
    assert not (train_idx & calib_idx)
    assert not (train_idx & test_idx)
    assert not (calib_idx & test_idx)
    assert len(split.train) == 400
    assert len(split.calib) == 300
    assert len(split.test) == 400

    split_again = split_dataset(rows, seed=42, n_train_benign=400, n_calib_per_class=150, n_test_per_class=200)
    assert [r.row_index for r in split.test] == [r.row_index for r in split_again.test]

    split_other_seed = split_dataset(rows, seed=7, n_train_benign=400, n_calib_per_class=150, n_test_per_class=200)
    assert {r.row_index for r in split.test} != {r.row_index for r in split_other_seed.test}


def test_split_dataset_raises_when_not_enough_rows_of_a_class():
    rows = load_rows(FIXTURE)
    with pytest.raises(ValueError):
        split_dataset(rows, seed=42, n_train_benign=100_000)  # only ~1000 benign rows exist


def test_to_feature_vector_never_touches_the_label():
    rows = load_rows(FIXTURE)
    fv = to_feature_vector(rows[0], datetime(2026, 1, 1))
    assert fv.values == rows[0].features
    assert "sub_label" not in fv.values
    assert set(fv.values) == set(CICIOT_FEATURE_KEYS)


# ---- integration: the real production code path, against real committed data -------

def test_run_cicioT2023_evaluation_end_to_end_against_real_data():
    """CLAUDE.md's integration-test requirement, for this track: runs the full real
    loop (load -> split -> fit -> predict -> compare -> correlate -> risk -> respond
    -> evidence -> persist) against real committed CICIoT2023 rows, and asserts the
    exact measured counts at seed=42 -- a real regression lock, not a loose
    "should detect something" check (see tests/test_ids_validation.py's docstring
    for why exact counts are asserted rather than ranges)."""
    engine = make_engine("sqlite:///:memory:")
    db = init_db(engine)()

    result = run_cicioT2023_evaluation(
        db, str(FIXTURE), seed=42, n_train_benign=400, n_calib_per_class=150, n_test_per_class=200,
    )

    assert result["confusion_matrix"] == {"tp": 198, "tn": 197, "fp": 3, "fn": 2}
    assert result["metrics"]["accuracy"] == pytest.approx(0.9875)
    assert result["n_incidents_generated"] == 201  # tp + fp: every predicted-positive row, never predicted-negative ones
    assert len(result["records"]) == 400

    # sub_label must never have influenced the prediction: FN=2 means at least two
    # ground-truth attacks were genuinely missed, and FP=3 means at least three
    # ground-truth benign rows were genuinely misclassified -- neither could happen
    # if ground truth were leaking into the decision.
    fns = [r for r in result["records"] if r["outcome"] == "FN"]
    fps = [r for r in result["records"] if r["outcome"] == "FP"]
    assert len(fns) == 2 and all(r["ground_truth"] == "attack" and r["prediction"] == "benign" for r in fns)
    assert len(fps) == 3 and all(r["ground_truth"] == "benign" and r["prediction"] == "attack" for r in fps)

    # a benign-labelled row that was also predicted benign must never have an incident
    tns = [r for r in result["records"] if r["outcome"] == "TN"]
    assert tns and all(r["incident_id"] is None for r in tns)
    # every predicted-attack row (TP or FP) must have a real incident
    positives = [r for r in result["records"] if r["prediction"] == "attack"]
    assert positives and all(r["incident_id"] is not None for r in positives)

    # real DB rows, not just an in-memory dict
    assert db.query(IncidentRow).filter_by(scenario="cicioT2023_eval").count() == 201
    assert db.query(EvidenceBundleRow).count() == 201

    # evidence replay (contribution C2) reproduces identically for a real bundle
    # generated by this track, exactly as it must for the synthetic pipeline's.
    one_incident_id = positives[0]["incident_id"]
    bundle_row = db.query(EvidenceBundleRow).filter_by(incident_id=one_incident_id).first()
    bundle = EvidenceBundle(
        bundle_id=bundle_row.bundle_id, incident_id=bundle_row.incident_id, created_at=bundle_row.created_at,
        device=bundle_row.device, feature_vector=bundle_row.feature_vector, detection=bundle_row.detection,
        baseline=bundle_row.baseline, risk=bundle_row.risk, decision=bundle_row.decision,
        trace=bundle_row.trace, prev_bundle_hash=bundle_row.prev_bundle_hash,
    )
    replay_result = replay(bundle)
    assert replay_result.reproduced is True


def test_run_cicioT2023_evaluation_manifest_records_reproducibility_fields():
    engine = make_engine("sqlite:///:memory:")
    db = init_db(engine)()
    result = run_cicioT2023_evaluation(
        db, str(FIXTURE), seed=42, n_train_benign=400, n_calib_per_class=150, n_test_per_class=200,
    )
    m = result["manifest"]
    assert m["seed"] == 42
    assert m["feature_keys"] == CICIOT_FEATURE_KEYS
    assert m["label_column"] == "sub_label"
    assert m["detection_threshold"] == 0.5
    assert m["n_test_benign"] == 200 and m["n_test_attack"] == 200
    assert "dataset_sha256" in m and len(m["dataset_sha256"]) == 64
    assert "label_map_assumption" in m  # flags the inferred label direction, not silently assumed
