"""FastAPI service (docs/11, condensed). Read endpoints are open; anything
state-changing requires a bearer token from ARGUS_ADMIN_TOKEN (docs/14: "there is no
default token and startup fails loudly if one is unset").
"""

from __future__ import annotations

import os

from fastapi import Depends, FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from argus.db.models import (
    ActionRow, DeviceRow, EvidenceBundleRow, IncidentRow, RiskAssessmentRow,
    VerificationRow, init_db, make_engine,
)
from argus.evidence.bundle import EvidenceBundle
from argus.evidence.replay import replay
from argus.pipeline import run_demo_pipeline
from argus.respond.guard import KillSwitch

ADMIN_TOKEN = os.getenv("ARGUS_ADMIN_TOKEN")
if not ADMIN_TOKEN:
    raise RuntimeError(
        "ARGUS_ADMIN_TOKEN is not set. Per docs/14, a default credential in a security "
        "tool is an irony worth avoiding -- copy .env.example to .env and set it."
    )

engine = make_engine()
SessionLocal = init_db(engine)
kill_switch = KillSwitch()

app = FastAPI(title="ARGUS API", version="0.1.0")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def require_auth(authorization: str | None = Header(default=None)) -> None:
    if authorization != f"Bearer {ADMIN_TOKEN}":
        raise HTTPException(status_code=401, detail="missing or invalid bearer token")


@app.get("/health")
def health():
    return {"status": "ok", "enforce": os.getenv("ARGUS_ENFORCE", "false"), "kill_switch": kill_switch.is_engaged()}


@app.get("/control/status")
def control_status():
    return {"enforce": os.getenv("ARGUS_ENFORCE", "false").lower() == "true", "kill_switch_engaged": kill_switch.is_engaged()}


@app.post("/control/kill-switch")
def toggle_kill_switch(engage: bool, _: None = Depends(require_auth)):
    if engage:
        kill_switch.engage()
    else:
        kill_switch.disengage()
    return {"kill_switch_engaged": kill_switch.is_engaged()}


@app.post("/control/seed-demo")
def seed_demo(db: Session = Depends(get_db), _: None = Depends(require_auth)):
    summary = run_demo_pipeline(db)
    return {"seeded": True, **summary}


@app.get("/devices")
def list_devices(db: Session = Depends(get_db)):
    rows = db.query(DeviceRow).all()
    return [
        {
            "device_id": r.device_id, "device_type": r.device_type, "state": r.state,
            "criticality": r.criticality, "is_drifting": r.is_drifting,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
        }
        for r in rows
    ]


@app.get("/incidents")
def list_incidents(db: Session = Depends(get_db)):
    rows = db.query(IncidentRow).order_by(IncidentRow.last_seen.desc()).all()
    out = []
    for r in rows:
        risk = db.query(RiskAssessmentRow).filter_by(incident_id=r.incident_id).first()
        bundle = db.query(EvidenceBundleRow).filter_by(incident_id=r.incident_id).first()
        action = db.query(ActionRow).filter_by(bundle_id=bundle.bundle_id).first() if bundle else None
        verification = db.query(VerificationRow).filter_by(action_id=action.action_id).first() if action else None
        out.append({
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
    return out


@app.get("/evidence/{bundle_id}")
def get_evidence(bundle_id: str, db: Session = Depends(get_db)):
    row = db.query(EvidenceBundleRow).filter_by(bundle_id=bundle_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="bundle not found")
    return {
        "bundle_id": row.bundle_id, "incident_id": row.incident_id, "created_at": row.created_at,
        "device": row.device, "feature_vector": row.feature_vector, "detection": row.detection,
        "baseline": row.baseline, "risk": row.risk, "decision": row.decision, "trace": row.trace,
        "prev_bundle_hash": row.prev_bundle_hash, "merkle_root": row.merkle_root,
    }


@app.post("/evidence/{bundle_id}/replay")
def replay_evidence(bundle_id: str, db: Session = Depends(get_db), _: None = Depends(require_auth)):
    row = db.query(EvidenceBundleRow).filter_by(bundle_id=bundle_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="bundle not found")
    bundle = EvidenceBundle(
        bundle_id=row.bundle_id, incident_id=row.incident_id, created_at=row.created_at,
        device=row.device, feature_vector=row.feature_vector, detection=row.detection,
        baseline=row.baseline, risk=row.risk, decision=row.decision, trace=row.trace,
        prev_bundle_hash=row.prev_bundle_hash,
    )
    result = replay(bundle)
    return {
        "bundle_id": result.bundle_id, "reproduced": result.reproduced,
        "original_action": result.original_action, "replayed_action": result.replayed_action,
        "original_tier": result.original_tier, "replayed_tier": result.replayed_tier,
    }


@app.get("/actions")
def list_actions(db: Session = Depends(get_db)):
    rows = db.query(ActionRow).all()
    return [
        {"action_id": r.action_id, "device_id": r.device_id, "tier": r.tier, "action": r.action,
         "dry_run": r.dry_run, "applied_at": r.applied_at.isoformat() if r.applied_at else None,
         "ttl_seconds": r.ttl_seconds}
        for r in rows
    ]
