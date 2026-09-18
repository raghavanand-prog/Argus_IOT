"""FastAPI service (docs/11, condensed). Read endpoints are open; anything
state-changing requires a bearer token from ARGUS_ADMIN_TOKEN (docs/14: "there is no
default token and startup fails loudly if one is unset").
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from argus.db.models import (
    ActionRow,
    CicioTEvaluationRunRow,
    DeviceRow,
    EvidenceBundleRow,
    IncidentRow,
    LiveDeviceRow,
    RiskAssessmentRow,
    SensorHeartbeatRow,
    VerificationRow,
    init_db,
    make_engine,
)
from argus.evidence.bundle import EvidenceBundle
from argus.evidence.replay import replay
from argus.pipeline import (
    ingest_live_observation,
    run_benign_validation,
    run_cicioT2023_evaluation,
    run_demo_pipeline,
)
from argus.respond.guard import KillSwitch

SENSOR_STALE_AFTER_SECONDS = 90  # 3x a sensor's default 30s poll interval

CICIOT2023_CSV = os.getenv(
    "ARGUS_CICIOT2023_CSV",
    str(Path(__file__).resolve().parent.parent.parent / "data" / "cicioT2023" / "df_Binary_FL_CICIoT2023.csv"),
)

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


@app.post("/control/validate-benign")
def validate_benign(db: Session = Depends(get_db), _: None = Depends(require_auth)):
    """IDS validation Test 1 / Test 4 (docs/16-ids-validation.md): runs the real
    detectors against fresh, held-out benign-only traffic and reports what (if
    anything) fired. Writes nothing to the database -- a clean run leaves no trace,
    matching what "no false incident" means on the Incidents page."""
    return run_benign_validation(db)


@app.get("/devices")
def list_devices(db: Session = Depends(get_db)):
    """Every device here came from run_demo_pipeline (argus.sim, synthetic) or
    run_live_demo_pipeline (argus.testbed, real network namespaces) -- never
    from a dataset evaluation. run_cicioT2023_evaluation never writes a
    DeviceRow at all (see docs/17-cicioT2023-validation.md: this dataset export
    has no device identity to enroll). "source" says so explicitly on every
    object, so any consumer of this API gets the same honest label the console
    shows."""
    rows = db.query(DeviceRow).all()
    return [
        {
            "device_id": r.device_id, "device_type": r.device_type, "state": r.state,
            "criticality": r.criticality, "is_drifting": r.is_drifting,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            "source": "argus-testbed",
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


@app.post("/control/run-cicioT2023-eval")
def run_cicioT2023_eval(db: Session = Depends(get_db), _: None = Depends(require_auth)):
    """Actually runs the real CICIoT2023 evaluation pipeline (argus.pipeline.
    run_cicioT2023_evaluation) against the real uploaded dataset -- trains a fresh
    dataset-specific detector, scores the held-out test split, and persists real
    incidents/evidence. Requires the full original CSV at ARGUS_CICIOT2023_CSV (or
    the default data/cicioT2023/ path) -- not committed to the repo (see
    docs/17-cicioT2023-validation.md); the committed fixture at
    argus/data/fixtures/cicioT2023_eval_subset.csv is the *output* of a run like
    this one, not an input to it."""
    if not os.path.exists(CICIOT2023_CSV):
        raise HTTPException(
            status_code=404,
            detail=(
                f"CICIoT2023 source file not found at {CICIOT2023_CSV}. Set "
                "ARGUS_CICIOT2023_CSV to the full df_Binary_FL_CICIoT2023.csv "
                "(see docs/17-cicioT2023-validation.md)."
            ),
        )
    result = run_cicioT2023_evaluation(db, CICIOT2023_CSV)
    return {
        "run_id": result["run_id"], "manifest": result["manifest"],
        "confusion_matrix": result["confusion_matrix"], "metrics": result["metrics"],
        "n_incidents_generated": result["n_incidents_generated"],
        "n_evidence_bundles": result["n_evidence_bundles"],
    }


@app.get("/cicioT2023/evaluations")
def list_cicioT2023_evaluations(db: Session = Depends(get_db)):
    rows = db.query(CicioTEvaluationRunRow).order_by(CicioTEvaluationRunRow.created_at.desc()).all()
    return [
        {
            "run_id": r.run_id, "created_at": r.created_at.isoformat(),
            "dataset_filename": r.dataset_filename, "seed": r.seed,
            "confusion_matrix": r.confusion_matrix, "metrics": r.metrics,
            "n_incidents_generated": r.n_incidents_generated,
        }
        for r in rows
    ]


@app.get("/cicioT2023/evaluations/{run_id}")
def get_cicioT2023_evaluation(run_id: str, db: Session = Depends(get_db)):
    r = db.query(CicioTEvaluationRunRow).filter_by(run_id=run_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="evaluation run not found")
    return _run_detail(r)


def _run_detail(r: CicioTEvaluationRunRow) -> dict:
    return {
        "run_id": r.run_id, "created_at": r.created_at.isoformat(),
        "dataset_filename": r.dataset_filename, "dataset_sha256": r.dataset_sha256,
        "seed": r.seed, "feature_keys": r.feature_keys, "model_config": r.model_config_json,
        "threshold": r.threshold, "n_total_rows": r.n_total_rows,
        "n_train_benign": r.n_train_benign, "n_calib_benign": r.n_calib_benign,
        "n_calib_attack": r.n_calib_attack, "n_test_benign": r.n_test_benign, "n_test_attack": r.n_test_attack,
        "confusion_matrix": r.confusion_matrix, "metrics": r.metrics,
        "n_incidents_generated": r.n_incidents_generated, "records": r.records,
    }


def _latest_run(db: Session) -> CicioTEvaluationRunRow | None:
    return db.query(CicioTEvaluationRunRow).order_by(CicioTEvaluationRunRow.created_at.desc()).first()


@app.get("/cicioT2023/eval")
def cicioT2023_eval_summary(db: Session = Depends(get_db)):
    """Same response shape as production's /api/cicioT2023/eval, sourced from the
    most recent real run in the local database instead of a static snapshot file --
    lets the console use one code path against either backend."""
    r = _latest_run(db)
    if not r:
        raise HTTPException(
            status_code=404,
            detail="No CICIoT2023 evaluation has been run yet. POST /control/run-cicioT2023-eval first.",
        )
    detail = _run_detail(r)
    return {
        "run_id": detail["run_id"], "manifest": {
            "run_id": detail["run_id"], "dataset_filename": detail["dataset_filename"],
            "dataset_sha256": detail["dataset_sha256"], "seed": detail["seed"],
            "feature_keys": detail["feature_keys"], "model_config": detail["model_config"],
            "detection_threshold": detail["threshold"], "generated_at": detail["created_at"],
            "n_train_benign": detail["n_train_benign"], "n_calib_benign": detail["n_calib_benign"],
            "n_calib_attack": detail["n_calib_attack"], "n_test_benign": detail["n_test_benign"],
            "n_test_attack": detail["n_test_attack"], "n_total_rows_in_file": detail["n_total_rows"],
        },
        "confusion_matrix": detail["confusion_matrix"], "metrics": detail["metrics"],
        "n_incidents_generated": detail["n_incidents_generated"], "n_records": len(detail["records"]),
        "mode": "local-live",
    }


@app.get("/cicioT2023/eval/records")
def cicioT2023_eval_records(db: Session = Depends(get_db)):
    r = _latest_run(db)
    if not r:
        raise HTTPException(status_code=404, detail="No CICIoT2023 evaluation has been run yet.")
    return r.records


@app.get("/cicioT2023/eval/records/{record_id}")
def cicioT2023_eval_record(record_id: str, db: Session = Depends(get_db)):
    r = _latest_run(db)
    if not r:
        raise HTTPException(status_code=404, detail="No CICIoT2023 evaluation has been run yet.")
    for rec in r.records:
        if rec["record_id"] == record_id:
            return rec
    raise HTTPException(status_code=404, detail="record not found")


@app.post("/live/ingest")
def live_ingest(payload: dict, db: Session = Depends(get_db), _: None = Depends(require_auth)):
    """Receives a real local sensor's actual observations (sensor/agent.py)
    and persists them for real -- see argus.pipeline.ingest_live_observation.
    Authenticated with the same ARGUS_ADMIN_TOKEN as every other state-
    changing endpoint; no separate sensor credential to manage."""
    result = ingest_live_observation(
        db, sensor_id=payload["sensor_id"], hostname=payload.get("hostname", "unknown"),
        monitoring_active=payload.get("monitoring_active", False),
        devices=payload.get("devices", []), detections=payload.get("detections", []),
    )
    return result


@app.get("/live/devices")
def list_live_devices(db: Session = Depends(get_db)):
    rows = db.query(LiveDeviceRow).order_by(LiveDeviceRow.last_seen.desc()).all()
    return [
        {
            "identifier": r.identifier, "ip": r.ip, "mac": r.mac, "vendor": r.vendor,
            "device_type": r.device_type, "interface": r.interface,
            "first_seen": r.first_seen.isoformat(), "last_seen": r.last_seen.isoformat(),
            "flow_count": r.flow_count, "monitored": r.monitored, "sensor_id": r.sensor_id,
        }
        for r in rows
    ]


@app.get("/live/status")
def live_status(db: Session = Depends(get_db)):
    """"No live network sensor connected" is a real fact derived from
    whether any sensor has ever reported in, and if so, how long ago --
    never assumed true or false."""
    sensors = db.query(SensorHeartbeatRow).all()
    now = datetime.utcnow()
    out = []
    for s in sensors:
        age_s = (now - s.last_seen).total_seconds()
        out.append({
            "sensor_id": s.sensor_id, "hostname": s.hostname, "monitoring_active": s.monitoring_active,
            "devices_discovered": s.devices_discovered, "last_seen": s.last_seen.isoformat(),
            "connected": age_s <= SENSOR_STALE_AFTER_SECONDS,
        })
    return {
        "sensors": out,
        "any_connected": any(s["connected"] for s in out),
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
