"""Exports a real, actually-computed run of the synthetic pipeline
(argus.pipeline.run_demo_pipeline) to a static JSON snapshot that the
serverless production API (api/index.py) serves.

Why this exists: Vercel's serverless Python functions have no persistent
filesystem across invocations and can't run the real network-namespace
testbed (no root/CAP_NET_ADMIN) or comfortably fit numpy/scikit-learn/shap
inside the platform's function-size budget alongside FastAPI. Rather than
fabricate example data, this script runs the actual pipeline once, locally,
and exports its real output -- the production deployment serves a real,
reproducible snapshot instead of a live re-simulation. See
docs/06-vercel-deployment.md for the full reasoning.

Every number in the exported file traces to this script's own run: re-run it
and commit the new api/seed_snapshot.json to update the production demo data.
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
from argus.pipeline import run_demo_pipeline

OUT_PATH = Path(__file__).parent.parent / "api" / "seed_snapshot.json"


def main() -> None:
    engine = make_engine("sqlite:///:memory:")
    Session = init_db(engine)
    db = Session()
    summary = run_demo_pipeline(db)
    print(f"pipeline summary: {summary}")

    devices = [
        {
            "device_id": r.device_id, "device_type": r.device_type, "state": r.state,
            "criticality": r.criticality, "is_drifting": r.is_drifting,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
        }
        for r in db.query(DeviceRow).all()
    ]

    incidents = []
    for r in db.query(IncidentRow).order_by(IncidentRow.last_seen.desc()).all():
        risk = db.query(RiskAssessmentRow).filter_by(incident_id=r.incident_id).first()
        bundle = db.query(EvidenceBundleRow).filter_by(incident_id=r.incident_id).first()
        action = db.query(ActionRow).filter_by(bundle_id=bundle.bundle_id).first() if bundle else None
        verification = db.query(VerificationRow).filter_by(action_id=action.action_id).first() if action else None
        incidents.append({
            "incident_id": r.incident_id, "device_id": r.device_id, "scenario": r.scenario,
            "first_seen": r.first_seen.isoformat(), "last_seen": r.last_seen.isoformat(),
            "chain_position": r.chain_position, "agreement_score": r.agreement_score,
            "detection_sources": r.detection_sources.split(",") if r.detection_sources else [],
            "status": r.status, "risk_score": risk.score if risk else None,
            "risk_terms": risk.terms if risk else None,
            "bundle_id": bundle.bundle_id if bundle else None,
            "action": action.action if action else None,
            "dry_run": action.dry_run if action else None,
            "verification_outcome": verification.outcome if verification else None,
        })

    evidence = {}
    for row in db.query(EvidenceBundleRow).all():
        evidence[row.bundle_id] = {
            "bundle_id": row.bundle_id, "incident_id": row.incident_id, "created_at": row.created_at,
            "device": row.device, "feature_vector": row.feature_vector, "detection": row.detection,
            "baseline": row.baseline, "risk": row.risk, "decision": row.decision, "trace": row.trace,
            "prev_bundle_hash": row.prev_bundle_hash, "merkle_root": row.merkle_root,
        }

    actions = [
        {"action_id": r.action_id, "device_id": r.device_id, "tier": r.tier, "action": r.action,
         "dry_run": r.dry_run, "applied_at": r.applied_at.isoformat() if r.applied_at else None,
         "ttl_seconds": r.ttl_seconds}
        for r in db.query(ActionRow).all()
    ]

    # The demo scenario replays several windows for the same device (e.g. seven
    # separate low_and_slow windows on smart-speaker-00), which produces many
    # near-identical incidents/bundles. Cap each (device, scenario) pair at 2 kept
    # incidents so the exported file stays small -- every kept row is still
    # untouched real output from this same run, just not every repeat of it.
    seen: dict[tuple[str, str], int] = {}
    kept_incidents = []
    for inc in incidents:
        key = (inc["device_id"], inc["scenario"])
        seen.setdefault(key, 0)
        if seen[key] < 2:
            kept_incidents.append(inc)
            seen[key] += 1
    kept_bundle_ids = {inc["bundle_id"] for inc in kept_incidents if inc["bundle_id"]}
    kept_evidence = {bid: b for bid, b in evidence.items() if bid in kept_bundle_ids}

    snapshot = {
        "generated_by": (
            "scripts/export_seed_snapshot.py -- a real run of argus.pipeline.run_demo_pipeline, "
            "capped at 2 incidents per (device, scenario) pair to keep the exported file small "
            "(every kept row is untouched real output from that run)"
        ),
        "pipeline_summary": summary,
        "devices": devices,
        "incidents": kept_incidents,
        "evidence": kept_evidence,
        "actions": actions,
    }
    OUT_PATH.parent.mkdir(exist_ok=True)
    OUT_PATH.write_text(json.dumps(snapshot, indent=2, default=str))
    print(f"wrote {OUT_PATH} ({OUT_PATH.stat().st_size} bytes)")
    print(
        f"devices={len(devices)} incidents={len(kept_incidents)} (of {len(incidents)}) "
        f"evidence={len(kept_evidence)} actions={len(actions)}"
    )


if __name__ == "__main__":
    main()
