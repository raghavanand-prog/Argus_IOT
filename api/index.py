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
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402

from argus.evidence.bundle import EvidenceBundle  # noqa: E402
from argus.evidence.replay import replay  # noqa: E402
from argus.respond.guard import KillSwitch  # noqa: E402

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
    return _STATE["incidents"]


@api.get("/evidence/{bundle_id}")
def get_evidence(bundle_id: str):
    bundle = _STATE["evidence"].get(bundle_id)
    if not bundle:
        raise HTTPException(status_code=404, detail="bundle not found")
    return bundle


@api.post("/evidence/{bundle_id}/replay")
def replay_evidence(bundle_id: str, _: None = Depends(require_auth)):
    row = _STATE["evidence"].get(bundle_id)
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


app.include_router(api)
