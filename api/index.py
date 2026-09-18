"""Production API for the Vercel deployment.

This is deliberately a *separate, lighter* entrypoint from `argus/api/main.py`
(the full local/dev API), not a duplicate of it by accident. Three real
platform constraints forced that split, and they're recorded here rather than
left implicit -- see `docs/06-vercel-deployment.md` for the full reasoning:

1. **No root / CAP_NET_ADMIN.** `argus/testbed/` (the real network-namespace
   testbed) needs Linux capabilities no serverless sandbox grants. It cannot
   run here, full stop -- not a size or time problem, a permissions one.
2. **No persistent filesystem across invocations.** `argus/db/models.py`'s
   SQLite file would not reliably survive between separate function
   invocations/instances, so a live, stateful "seed then browse" flow the way
   the local API works doesn't hold up in this runtime.
3. **Function size/time budget.** numpy + scikit-learn + shap + scipy
   (`argus/detect/ml.py`'s real dependencies) push close to serverless
   function size limits, and re-fitting a detector per request is wasteful
   even where it fits.

What this endpoint keeps genuinely real, not mocked:

- **The data.** `api/seed_snapshot.json` is not fabricated -- it's the actual
  output of one real run of `argus.pipeline.run_demo_pipeline`
  (`scripts/export_seed_snapshot.py`), captured because Vercel can't run that
  pipeline live on every request. Regenerate it any time by re-running that
  script and redeploying.
- **Evidence replay.** `argus.evidence.replay.replay()` runs unmodified here
  -- it and everything it imports (`argus.respond.guard`, `argus.respond.ladder`,
  `argus.evidence.bundle`) are pure standard-library code with no ML
  dependency, so the actual replay mechanism (contribution C2) is live in
  production, not simulated.
- **The kill switch.** `argus.respond.guard.KillSwitch` runs unmodified too.
  Its state lives in this function instance's memory, which is honestly
  *not* guaranteed to persist between cold starts on a serverless platform --
  documented, not hidden, in the /control/status response and the README.
"""

from __future__ import annotations

import copy
import json
import os
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402

from argus.correlate.correlator import correlate  # noqa: E402
from argus.evidence.bundle import EvidenceBundle, EvidenceLedger  # noqa: E402
from argus.evidence.replay import replay  # noqa: E402
from argus.respond.guard import ActionRateLimiter, KillSwitch  # noqa: E402
from argus.respond.ladder import DryRunAdapter, decide_and_respond  # noqa: E402
from argus.risk.engine import assess_risk  # noqa: E402
from argus.schemas import Detection  # noqa: E402

# ARGUS_ADMIN_TOKEN gates only the write/admin endpoints below (kill switch, seed
# reset, replay). It deliberately has no default (docs/14: a default credential in
# a security tool is an irony worth avoiding) -- but its *absence* must not crash
# read-only endpoints that need no auth at all. An earlier version of this module
# raised at import time here, which took down /health, /devices, /incidents, and
# /actions too -- a misconfigured optional admin credential should not be able to
# fail the whole deployment. Missing-token is now handled per-request, at the one
# place (require_auth) that actually needs it.
ADMIN_TOKEN = os.getenv("ARGUS_ADMIN_TOKEN")

SNAPSHOT_PATH = Path(__file__).resolve().parent / "seed_snapshot.json"
_ORIGINAL_SNAPSHOT = json.loads(SNAPSHOT_PATH.read_text())
_STATE = copy.deepcopy(_ORIGINAL_SNAPSHOT)
kill_switch = KillSwitch()

# The CICIoT2023 evaluation (docs/17-cicioT2023-validation.md): a real, actually-
# executed run of argus.pipeline.run_cicioT2023_evaluation
# (scripts/export_cicioT2023_snapshot.py), for the exact same reason seed_snapshot.json
# exists -- this platform cannot run scikit-learn/train a detector per request (no
# numpy/scikit-learn/shap in api/requirements.txt, no persistent filesystem across
# invocations). The incidents/evidence this real run generated are merged into the
# same _STATE the rest of this API reads from, so they appear on /api/incidents like
# any other real incident (tagged scenario="cicioT2023_eval"), not kept in a separate
# silo pretending to be a different kind of data.
CICIOT2023_SNAPSHOT_PATH = Path(__file__).resolve().parent / "cicioT2023_eval_snapshot.json"
_CICIOT2023_SNAPSHOT = json.loads(CICIOT2023_SNAPSHOT_PATH.read_text())
_STATE["incidents"] = _CICIOT2023_SNAPSHOT["incidents"] + _STATE["incidents"]
_STATE["evidence"].update(_CICIOT2023_SNAPSHOT["evidence"])

# Live-network track: real devices discovered/detected by a user's local sensor
# (sensor/agent.py -- see docs/18-live-sensor.md), POSTed here. Kept in its own
# in-memory store, deliberately separate from _STATE -- /control/seed-demo resets
# _STATE back to the synthetic/CICIoT2023 snapshot, and a live sensor's real
# observations must never be wiped by that (or by anything unrelated to the sensor
# itself disconnecting). Same "warm instance only, not guaranteed across cold
# starts" honesty as the kill switch and _STATE -- see module docstring.
SENSOR_STALE_AFTER_SECONDS = 90
_LIVE_DEVICES: dict[str, dict] = {}
_LIVE_SENSORS: dict[str, dict] = {}
_LIVE_INCIDENTS: list[dict] = []
_LIVE_EVIDENCE: dict[str, dict] = {}
live_ledger = EvidenceLedger()
live_rate_limiter = ActionRateLimiter()
live_adapter = DryRunAdapter()

app = FastAPI(title="ARGUS API (production snapshot)", version="0.1.0")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

# Routes are mounted under /api because that's the literal path Vercel's rewrite
# rule (vercel.json: "/api/(.*)" -> this function) forwards to this ASGI app --
# unlike the local dev proxy (console/vite.config.ts), Vercel does not strip the
# /api prefix before the request reaches here.
api = APIRouter(prefix="/api")


def require_auth(authorization: str | None = Header(default=None)) -> None:
    if not ADMIN_TOKEN:
        raise HTTPException(
            status_code=503,
            detail=(
                "ARGUS_ADMIN_TOKEN is not configured on this deployment. Admin actions "
                "(kill switch, seed reset, evidence replay) are disabled until it is "
                "set as a Vercel project environment variable and redeployed -- "
                "see docs/06-vercel-deployment.md."
            ),
        )
    if authorization != f"Bearer {ADMIN_TOKEN}":
        raise HTTPException(status_code=401, detail="missing or invalid bearer token")


@api.get("/health")
def health():
    return {
        "status": "ok", "mode": "production-snapshot",
        "enforce": os.getenv("ARGUS_ENFORCE", "false"), "kill_switch": kill_switch.is_engaged(),
        "admin_token_configured": bool(ADMIN_TOKEN),
    }


@api.get("/control/status")
def control_status():
    return {
        "enforce": os.getenv("ARGUS_ENFORCE", "false").lower() == "true",
        "kill_switch_engaged": kill_switch.is_engaged(),
        "mode": "production-snapshot",
        "admin_token_configured": bool(ADMIN_TOKEN),
    }


@api.post("/control/kill-switch")
def toggle_kill_switch(engage: bool, _: None = Depends(require_auth)):
    if engage:
        kill_switch.engage()
    else:
        kill_switch.disengage()
    return {"kill_switch_engaged": kill_switch.is_engaged()}


@api.post("/control/seed-demo")
def seed_demo(_: None = Depends(require_auth)):
    """Production cannot run the real ML pipeline live (see module docstring) --
    this resets the in-memory store back to the real exported snapshot rather
    than pretending to re-simulate. Honest about what it actually does."""
    global _STATE
    _STATE = copy.deepcopy(_ORIGINAL_SNAPSHOT)
    _STATE["incidents"] = _CICIOT2023_SNAPSHOT["incidents"] + _STATE["incidents"]
    _STATE["evidence"].update(_CICIOT2023_SNAPSHOT["evidence"])
    return {
        "seeded": True, "mode": "reset-to-snapshot",
        "note": (
            "Production serves a real, pre-computed pipeline run (see "
            "docs/06-vercel-deployment.md) rather than re-simulating live. "
            "This reset the in-memory store back to that snapshot. For a live "
            "re-run of the actual pipeline, use the local dev server."
        ),
        **_STATE["pipeline_summary"],
    }


@api.get("/devices")
def list_devices():
    """These are ARGUS's own synthetic simulation-testbed devices
    (argus.sim.engine.default_fleet), not derived from any uploaded dataset --
    CICIoT2023's binary export has no device/IP identity at all (see
    docs/17-cicioT2023-validation.md). The "source" field says so explicitly on
    every object, not just in the console's own presentation of it, so any
    consumer of this API gets the same honest label."""
    return [{**d, "source": "synthetic-demo-testbed"} for d in _STATE["devices"]]


@api.get("/incidents")
def list_incidents():
    # live_network incidents first (most recent real activity), then the
    # precomputed synthetic/CICIoT2023 snapshot -- distinguished by scenario,
    # same convention used throughout (see docs/17, this module's docstring).
    return _LIVE_INCIDENTS + _STATE["incidents"]


@api.get("/evidence/{bundle_id}")
def get_evidence(bundle_id: str):
    bundle = _STATE["evidence"].get(bundle_id) or _LIVE_EVIDENCE.get(bundle_id)
    if not bundle:
        raise HTTPException(status_code=404, detail="bundle not found")
    return bundle


@api.post("/evidence/{bundle_id}/replay")
def replay_evidence(bundle_id: str, _: None = Depends(require_auth)):
    row = _STATE["evidence"].get(bundle_id) or _LIVE_EVIDENCE.get(bundle_id)
    if not row:
        raise HTTPException(status_code=404, detail="bundle not found")
    bundle = EvidenceBundle(
        bundle_id=row["bundle_id"], incident_id=row["incident_id"], created_at=row["created_at"],
        device=row["device"], feature_vector=row["feature_vector"], detection=row["detection"],
        baseline=row["baseline"], risk=row["risk"], decision=row["decision"], trace=row["trace"],
        prev_bundle_hash=row["prev_bundle_hash"],
    )
    result = replay(bundle)  # the real replay mechanism -- see module docstring
    return {
        "bundle_id": result.bundle_id, "reproduced": result.reproduced,
        "original_action": result.original_action, "replayed_action": result.replayed_action,
        "original_tier": result.original_tier, "replayed_tier": result.replayed_tier,
    }


@api.get("/actions")
def list_actions():
    return _STATE["actions"]


@api.get("/cicioT2023/eval")
def cicioT2023_eval_summary():
    """Real, precomputed results (see module docstring above): manifest, confusion
    matrix, and metrics from one actual run of run_cicioT2023_evaluation against the
    real uploaded CICIoT2023 export. Not re-computed per request -- this platform
    cannot run scikit-learn per invocation; the numbers themselves are real."""
    s = _CICIOT2023_SNAPSHOT
    return {
        "run_id": s["run_id"], "manifest": s["manifest"], "confusion_matrix": s["confusion_matrix"],
        "metrics": s["metrics"], "n_incidents_generated": s["n_incidents_generated"],
        "n_evidence_bundles": s["n_evidence_bundles"], "n_records": len(s["records"]),
        "mode": "production-snapshot",
    }


@api.get("/cicioT2023/eval/records")
def cicioT2023_eval_records():
    return _CICIOT2023_SNAPSHOT["records"]


@api.get("/cicioT2023/eval/records/{record_id}")
def cicioT2023_eval_record(record_id: str):
    for rec in _CICIOT2023_SNAPSHOT["records"]:
        if rec["record_id"] == record_id:
            return rec
    raise HTTPException(status_code=404, detail="record not found")


def _process_live_detection(dev_id: str, detections: list[Detection]) -> int:
    """Serverless counterpart to argus.pipeline._process_live_detection: the
    same correlate -> risk -> decide -> evidence tail, using the exact same
    argus.correlate/argus.risk/argus.respond/argus.evidence modules -- these
    are pure Python (no numpy/scikit-learn), unlike argus.detect.ml, so unlike
    the CICIoT2023 track this one genuinely runs live in this function rather
    than serving a precomputed snapshot. Writes to this module's own in-memory
    live-incident store instead of a SQLAlchemy DB, for the same
    no-persistent-filesystem reason _STATE and kill_switch already are.

    Never enforces against a real device (enforce_enabled=False, always) and
    never runs verify() -- no environment-recovery check exists for a live
    device found by a user's own sensor. Risk terms deviation/blast_radius
    are 0.0: a device the sensor only just discovered has no drift history or
    communication-graph view computed here.
    """
    if not detections:
        return 0
    incidents = correlate(detections)
    det_map = {d.detection_id: d for d in detections}
    n_created = 0

    for incident in incidents:
        risk = assess_risk(incident, detections, "unknown", 0.0, 0.0)
        incident_dets = [det_map[i] for i in incident.detection_ids if i in det_map]
        best_conformal = next((d.conformal_set for d in incident_dets if d.conformal_set), None)

        outcome = decide_and_respond(
            device_id=dev_id, device_type="unknown", risk_score=risk.score,
            conformal_set=best_conformal, is_drifting=False,
            kill_switch=kill_switch, rate_limiter=live_rate_limiter,
            enforce_enabled=False,  # never live enforcement against a real discovered device
            adapter=live_adapter, now=incident.last_seen.timestamp(),
        )

        bundle = live_ledger.append(
            incident_id=incident.incident_id,
            device={
                "device_id": dev_id, "device_type": "unknown", "source": "live_network",
                "note": "Real device discovered by a local sensor via passive ARP/neighbour-table "
                        "observation; device_type is unknown because nothing in passive discovery "
                        "can legitimately determine it.",
            },
            feature_vector={"window": incident.chain_position},
            detection={
                "sources": list({d.source for d in incident_dets}),
                "conformal_set": best_conformal,
                "signals": [d.signal_name for d in incident_dets],
                "explanations": [d.explanation for d in incident_dets],
                "attribution": next((d.attribution for d in incident_dets if d.attribution), None),
            },
            baseline={"note": "per-device baseline built from this device's own real observed traffic (sensor/baseline.py)"},
            risk={"score": risk.score, "terms": risk.terms},
            decision={
                "action": outcome.action, "tier": outcome.tier, "dry_run": outcome.dry_run,
                "gates_passed": outcome.guard.gates_passed, "gates_failed": outcome.guard.gates_failed,
            },
            trace=[f"detected via {d.source}:{d.signal_name}" for d in incident_dets] + [
                f"correlated into incident {incident.incident_id}",
                f"risk={risk.score:.2f}", f"guard_verdict={'allow' if outcome.guard.allow else 'veto'}",
                f"action={outcome.action}",
                "no enforcement adapter exists for real discovered devices -- dry-run only, always",
                "post-response verification skipped: no environment-recovery check is implemented for live devices",
            ],
        )

        _LIVE_INCIDENTS.insert(0, {
            "incident_id": incident.incident_id, "device_id": dev_id,
            "first_seen": incident.first_seen.isoformat(), "last_seen": incident.last_seen.isoformat(),
            "chain_position": incident.chain_position, "agreement_score": incident.agreement_score,
            "detection_sources": list({d.source for d in incident_dets}), "scenario": "live_network",
            "risk_score": risk.score, "bundle_id": bundle.bundle_id,
        })
        _LIVE_EVIDENCE[bundle.bundle_id] = {
            "bundle_id": bundle.bundle_id, "incident_id": bundle.incident_id, "created_at": bundle.created_at,
            "device": bundle.device, "feature_vector": bundle.feature_vector, "detection": bundle.detection,
            "baseline": bundle.baseline, "risk": bundle.risk, "decision": bundle.decision, "trace": bundle.trace,
            "prev_bundle_hash": bundle.prev_bundle_hash, "merkle_root": bundle.merkle_root,
        }
        n_created += 1

    return n_created


@api.post("/live/ingest")
def live_ingest(payload: dict, _: None = Depends(require_auth)):
    """Receives a real local sensor's actual observations (sensor/agent.py).
    ``devices``: dicts matching sensor.discovery.DiscoveredDevice's fields.
    ``detections``: dicts matching argus.schemas.Detection's fields, already
    produced by the sensor's own detector run against real captured traffic
    -- this endpoint persists what the sensor already computed, it does not
    run detection itself. Never creates an incident from discovery alone,
    only from detections the sensor actually found (mirrors the CICIoT2023
    track's "ground truth never forces a detection" rule; here there is no
    ground truth at all, only what the detectors themselves found)."""
    sensor_id = payload["sensor_id"]
    devices = payload.get("devices", [])
    detections_in = payload.get("detections", [])

    for d in devices:
        _LIVE_DEVICES[d["identifier"]] = {**d, "sensor_id": sensor_id}
    _LIVE_SENSORS[sensor_id] = {
        "sensor_id": sensor_id, "hostname": payload.get("hostname", "unknown"),
        "monitoring_active": payload.get("monitoring_active", False),
        "devices_discovered": len(devices), "last_seen": datetime.utcnow().isoformat(),
    }

    by_device: dict[str, list[Detection]] = {}
    for det_dict in detections_in:
        det = Detection(
            detection_id=det_dict["detection_id"], ts=datetime.fromisoformat(det_dict["ts"]),
            device_id=det_dict["device_id"], source=det_dict["source"], signal_name=det_dict["signal_name"],
            severity=det_dict["severity"], confidence=det_dict["confidence"], explanation=det_dict["explanation"],
            evidence_refs=det_dict.get("evidence_refs", []), conformal_set=det_dict.get("conformal_set"),
            attribution=det_dict.get("attribution"),
        )
        by_device.setdefault(det.device_id, []).append(det)

    incidents_generated = sum(_process_live_detection(dev_id, dets) for dev_id, dets in by_device.items())

    return {
        "devices_ingested": len(devices), "detections_received": len(detections_in),
        "incidents_generated": incidents_generated, "bundles_generated": incidents_generated,
    }


@api.get("/live/devices")
def list_live_devices():
    """Real devices a local sensor has actually discovered and reported --
    empty if no sensor has ever POSTed to this warm instance. Never fabricated;
    see /live/status for whether a sensor is currently connected."""
    return list(_LIVE_DEVICES.values())


@api.get("/live/status")
def live_status():
    now = datetime.utcnow()
    sensors = []
    for s in _LIVE_SENSORS.values():
        age_s = (now - datetime.fromisoformat(s["last_seen"])).total_seconds()
        sensors.append({**s, "connected": age_s <= SENSOR_STALE_AFTER_SECONDS})
    return {
        "sensors": sensors, "any_connected": any(s["connected"] for s in sensors),
        "note": (
            "Sensor state lives only in this deployment's current warm function "
            "instance and is not guaranteed to persist across cold starts -- the "
            "same limitation already documented for the kill switch and the demo "
            "snapshot state (see module docstring)."
        ),
    }


app.include_router(api)
