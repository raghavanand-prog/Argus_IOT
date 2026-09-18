"""Runs the real CICIoT2023 evaluation once, locally (this needs numpy/scikit-learn/
shap -- Vercel's serverless function does not have them, see api/index.py's module
docstring), and exports two things a fresh clone of this repo can use without ever
needing the full 600,000-row original file:

1. ``argus/data/fixtures/cicioT2023_eval_subset.csv`` -- the actual held-out test
   split (2,000 real rows: 8 real features + the real ``sub_label``), committed to
   the repo. Small enough to commit; real enough to re-verify predictions against.
2. ``api/cicioT2023_eval_snapshot.json`` -- the full run result (manifest, confusion
   matrix, metrics, and every test record's actual prediction/score/incident_id),
   which the production serverless API serves read-only (it cannot re-run
   scikit-learn per request). Every number in it traces to this script's own run --
   see docs/17-cicioT2023-validation.md.

Run: ``python scripts/export_cicioT2023_snapshot.py`` (needs the full original file
at the path below, or override with ARGUS_CICIOT2023_CSV).
"""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path

from argus.db.models import init_db, make_engine
from argus.pipeline import run_cicioT2023_evaluation

CSV_PATH = os.getenv(
    "ARGUS_CICIOT2023_CSV",
    str(Path(__file__).parent.parent / "data" / "cicioT2023" / "df_Binary_FL_CICIoT2023.csv"),
)
SUBSET_OUT = Path(__file__).parent.parent / "argus" / "data" / "fixtures" / "cicioT2023_eval_subset.csv"
SNAPSHOT_OUT = Path(__file__).parent.parent / "api" / "cicioT2023_eval_snapshot.json"


def main() -> None:
    engine = make_engine("sqlite:///:memory:")
    db = init_db(engine)()
    result = run_cicioT2023_evaluation(db, CSV_PATH, seed=42)

    print("confusion_matrix:", result["confusion_matrix"])
    print("metrics:", result["metrics"])
    print("n_incidents_generated:", result["n_incidents_generated"])

    # Fetch the real incidents/evidence this run actually wrote, keyed the same way
    # the production snapshot merge (api/index.py) expects.
    from argus.db.models import EvidenceBundleRow, IncidentRow, RiskAssessmentRow

    incidents = []
    for r in db.query(IncidentRow).filter_by(scenario="cicioT2023_eval").order_by(IncidentRow.last_seen.desc()).all():
        risk = db.query(RiskAssessmentRow).filter_by(incident_id=r.incident_id).first()
        bundle = db.query(EvidenceBundleRow).filter_by(incident_id=r.incident_id).first()
        incidents.append({
            "incident_id": r.incident_id, "device_id": r.device_id, "scenario": r.scenario,
            "first_seen": r.first_seen.isoformat(), "last_seen": r.last_seen.isoformat(),
            "chain_position": r.chain_position, "agreement_score": r.agreement_score,
            "detection_sources": r.detection_sources.split(",") if r.detection_sources else [],
            "status": r.status, "risk_score": risk.score if risk else None,
            "risk_terms": risk.terms if risk else None,
            "bundle_id": bundle.bundle_id if bundle else None,
            "action": None, "dry_run": True, "verification_outcome": None,
        })

    evidence = {}
    for row in db.query(EvidenceBundleRow).all():
        evidence[row.bundle_id] = {
            "bundle_id": row.bundle_id, "incident_id": row.incident_id, "created_at": row.created_at,
            "device": row.device, "feature_vector": row.feature_vector, "detection": row.detection,
            "baseline": row.baseline, "risk": row.risk, "decision": row.decision, "trace": row.trace,
            "prev_bundle_hash": row.prev_bundle_hash, "merkle_root": row.merkle_root,
        }

    snapshot = {
        "run_id": result["run_id"], "manifest": result["manifest"],
        "confusion_matrix": result["confusion_matrix"], "metrics": result["metrics"],
        "n_incidents_generated": result["n_incidents_generated"],
        "n_evidence_bundles": result["n_evidence_bundles"],
        "records": result["records"], "incidents": incidents, "evidence": evidence,
    }
    SNAPSHOT_OUT.write_text(json.dumps(snapshot, indent=2, default=str))
    print(f"wrote {SNAPSHOT_OUT} ({SNAPSHOT_OUT.stat().st_size / 1024:.0f} KB)")

    SUBSET_OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(SUBSET_OUT, "w", newline="") as f:
        writer = csv.writer(f)
        feature_keys = result["manifest"]["feature_keys"]
        writer.writerow(["row_index", *feature_keys, "sub_label"])
        for rec in result["records"]:
            label = 1 if rec["ground_truth"] == "attack" else 0
            writer.writerow([rec["row_index"], *(rec["features"][k] for k in feature_keys), label])
    print(f"wrote {SUBSET_OUT} ({len(result['records'])} rows)")


if __name__ == "__main__":
    main()
