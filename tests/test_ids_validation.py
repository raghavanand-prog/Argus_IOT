"""IDS validation Test 1 / Test 4 (docs/16-ids-validation.md), locked in as a
regression test. Per CLAUDE.md rule 6 (seeds fixed and recorded), this asserts the
*exact* measured counts at seed=42, not a looser "should be low" check -- if a future
change to the sim engine, feature extraction, or detector genuinely changes this
number, that's a real behavioural change this test is supposed to catch, and the
expected value should be updated deliberately, with the reason recorded in
decisions.md, not silently.

The counts asserted here are a known, honestly-reported limitation, not a target:
see docs/16-ids-validation.md's Test 1/4 writeup for why (an IsolationForest trained
on a single ~4-hour benign window, one RNG seed, does not generalise to a genuinely
fresh benign window -- a real calibration-diversity gap, not a bug in this test).
"""

from __future__ import annotations

from argus.db.models import IncidentRow, init_db, make_engine
from argus.pipeline import run_benign_validation


def test_benign_validation_runs_against_the_real_detectors():
    engine = make_engine("sqlite:///:memory:")
    db = init_db(engine)()
    result = run_benign_validation(db, seed=42)

    assert result["devices_tested"] == 11
    assert set(result["clean_devices"]) == {"smart-tv-00", "hub-00", "user-laptop-00"}
    # Known, measured calibration gap (see docs/16) -- not asserting 0.
    assert result["total_detections"] == 75
    assert result["detections_that_would_escalate_to_tier2plus"] == 40
    # A validation run must never write to the database, regardless of what it finds.
    assert db.query(IncidentRow).count() == 0
