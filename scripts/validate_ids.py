"""ARGUS IDS validation (docs/16-ids-validation.md), Tests 1-4.

Runs the real pipeline code -- the same functions the FastAPI backend and the
Control screen's "Run demo pipeline" button call -- against a fresh in-memory
database, and reports exactly what happened. No results are pre-decided or
invented; this script's own stdout/JSON output is the source of truth for the
test matrix in docs/16-ids-validation.md.

Tests 5 (response/kill-switch gating) and 6 (replay) are HTTP/UI-level and live
in scripts/validate_ids_http.py, since they need a running server.
"""

from __future__ import annotations

import json
from pathlib import Path

from argus.db.models import (
    ActionRow,
    DeviceRow,
    EvidenceBundleRow,
    IncidentRow,
    RiskAssessmentRow,
    VerificationRow,
    init_db,
    make_engine,
)
from argus.pipeline import run_benign_validation, run_demo_pipeline

OUT_PATH = Path(__file__).parent.parent / "eval" / "ids_validation_1_4.json"


def _incident_rows(db):
    out = []
    for r in db.query(IncidentRow).order_by(IncidentRow.last_seen.desc()).all():
        risk = db.query(RiskAssessmentRow).filter_by(incident_id=r.incident_id).first()
        bundle = db.query(EvidenceBundleRow).filter_by(incident_id=r.incident_id).first()
        action = db.query(ActionRow).filter_by(bundle_id=bundle.bundle_id).first() if bundle else None
        verification = db.query(VerificationRow).filter_by(action_id=action.action_id).first() if action else None
        out.append({
            "incident_id": r.incident_id, "device_id": r.device_id, "scenario": r.scenario,
            "first_seen": r.first_seen.isoformat(), "last_seen": r.last_seen.isoformat(),
            "chain_position": r.chain_position, "agreement_score": r.agreement_score,
            "detection_sources": r.detection_sources.split(",") if r.detection_sources else [],
            "risk_score": risk.score if risk else None, "risk_terms": risk.terms if risk else None,
            "bundle_id": bundle.bundle_id if bundle else None,
            "action": action.action if action else None, "tier": action.tier if action else None,
            "dry_run": action.dry_run if action else None,
            "verification_outcome": verification.outcome if verification else None,
        })
    return out


def main() -> None:
    results: dict = {}

    # --- Test 1: baseline / normal traffic, whole fleet -----------------------
    print("=== TEST 1 -- baseline / normal traffic (whole fleet) ===")
    engine1 = make_engine("sqlite:///:memory:")
    db1 = init_db(engine1)()
    fleet_before = [
        {"device_id": r.device_id, "state": r.state}
        for r in db1.query(DeviceRow).all()
    ]
    t1 = run_benign_validation(db1, seed=42)
    fleet_after = [
        {"device_id": r.device_id, "state": r.state, "is_drifting": r.is_drifting}
        for r in db1.query(DeviceRow).all()
    ]
    incidents_after_t1 = _incident_rows(db1)
    results["test_1_baseline"] = {
        "fleet_before_devices": len(fleet_before),
        "fleet_after": fleet_after,
        "total_detections": t1["total_detections"],
        "detections_that_would_escalate_to_tier2plus": t1["detections_that_would_escalate_to_tier2plus"],
        "false_positives_by_device": t1["false_positives_by_device"],
        "clean_devices": t1["clean_devices"],
        "incidents_created": len(incidents_after_t1),
        "pass": t1["total_detections"] == 0 and len(incidents_after_t1) == 0,
    }
    print(json.dumps(results["test_1_baseline"], indent=2, default=str))

    # --- Tests 2 & 3: run the real, full, existing demo pipeline --------------
    # This is the exact function "Run demo pipeline" calls -- all 7 scenarios,
    # unmodified. Test 2 inspects the mqtt_abuse incident (a moderate, policy-
    # driven case); Test 3 inspects the mirai incident (the highest-severity
    # case, the only one that reaches tier 4 / isolate).
    print("\n=== TESTS 2 & 3 -- full demo pipeline run (all 7 scenarios) ===")
    engine23 = make_engine("sqlite:///:memory:")
    db23 = init_db(engine23)()
    summary23 = run_demo_pipeline(db23, seed=42)
    all_incidents = _incident_rows(db23)
    print(f"pipeline summary: {summary23}, {len(all_incidents)} incident rows total")

    def first_for_scenario(name: str):
        return next((i for i in all_incidents if i["scenario"] == name), None)

    mqtt = first_for_scenario("mqtt_abuse")
    mirai = first_for_scenario("mirai")

    results["test_2_suspicious_mqtt_abuse"] = {
        "scenario": "mqtt_abuse",
        "incident": mqtt,
        "pass": bool(
            mqtt and mqtt["bundle_id"] and mqtt["risk_score"] is not None
            and mqtt["action"] and mqtt["device_id"] == "smart-lock-00"
        ),
    }
    results["test_3_high_severity_mirai"] = {
        "scenario": "mirai",
        "incident": mirai,
        "pass": bool(
            mirai and mirai["bundle_id"] and mirai["tier"] == 4 and mirai["action"] == "isolate"
            and mirai["device_id"] == "smart-plug-00"
        ),
    }
    print("\nTest 2 (mqtt_abuse):", json.dumps(results["test_2_suspicious_mqtt_abuse"], indent=2, default=str))
    print("\nTest 3 (mirai):", json.dumps(results["test_3_high_severity_mirai"], indent=2, default=str))

    # --- Test 4: closer look at the hardest false-positive case ---------------
    # low_and_slow's attack traffic is deliberately shaped to look like
    # smart-speaker-00's own normal beaconing (see argus/sim/attacks.py's own
    # docstring). Its *benign* traffic, from Test 1's run, is therefore the
    # single most meaningful "does ordinary activity get misclassified" check
    # in this codebase -- stronger evidence than a generic benign event.
    print("\n=== TEST 4 -- false positive stress test (smart-speaker-00 benign traffic) ===")
    speaker_findings = t1["false_positives_by_device"].get("smart-speaker-00", [])
    results["test_4_false_positive_stress"] = {
        "device": "smart-speaker-00",
        "reason": (
            "smart-speaker-00 is the device whose real attack scenario (low_and_slow) "
            "is deliberately shaped to resemble its own normal beaconing -- the "
            "hardest real false-positive case in this codebase, per argus/sim/attacks.py."
        ),
        "findings_on_benign_traffic": speaker_findings,
        "pass": len(speaker_findings) == 0,
    }
    print(json.dumps(results["test_4_false_positive_stress"], indent=2, default=str))

    OUT_PATH.parent.mkdir(exist_ok=True)
    OUT_PATH.write_text(json.dumps(results, indent=2, default=str))
    print(f"\nwrote {OUT_PATH}")


if __name__ == "__main__":
    main()
