# ARGUS

Closed-loop, evidence-bound IoT intrusion detection and autonomous response.

Most IoT intrusion detection research stops at the alert and is evaluated offline.
ARGUS closes the loop — **detect → correlate → assess risk → explain → decide → enforce
→ verify → feed back** — and binds every autonomous action to a hash-chained,
replayable evidence bundle, so "why did it act" has a measurable, checkable answer
instead of a plot. See `MASTER-PLAN.md` for the full contribution claims and
`BUILD-ORDER.md` for the 4-phase build order this repo actually follows.

## What's here right now

A working, tested, end-to-end system, on **two parallel data sources** feeding the
identical downstream pipeline:

- A deterministic **synthetic testbed** (`argus/sim/`) — 10 IoT device behaviour
  profiles and **all 7 attack scenarios** from the threat model (Mirai-style
  recruitment, low-and-slow beaconing, MQTT abuse, ARP spoofing, DNS tunnelling,
  identity spoofing, OTA update spoofing) with a labelled ground-truth ledger. Fast
  (the full 9-config ablation runs in ~30s) and fully deterministic.
- A **real network-namespace testbed** (`argus/testbed/`) — genuine Linux network
  namespaces and veth pairs on a real bridge, carrying real packets, captured with
  a custom multi-interface `scapy` sniffer into an actual pcap file, parsed into
  the *identical* flow schema the synthetic engine produces. Built because this
  environment's outbound proxy blocks Docker image pulls — see
  `docs/04b-live-testbed.md` for the full story, including two real kernel
  networking interactions found and fixed along the way.
- **Metadata-only feature extraction**, device **enrollment** (bounded, policy-guarded,
  refusable), a **behaviour engine** + **drift monitor**.
- A **rule/policy detection track** and a **calibrated ML track** (Isolation Forest +
  isotonic calibration + an inductive conformal prediction gate written from scratch).
- A **correlator** and a **risk engine** with device-criticality-weighted blast radius.
- **SHAP (TreeSHAP) attribution** — real per-feature contributions for every ML
  detection, flowing into the evidence bundle and rendering live in the console.
- A **hash-chained evidence bundle** for every incident, with a **replay harness** that
  measures decision reproducibility rather than assuming it (100% on the current run —
  the mechanism found and led to fixing a real non-determinism bug; see `decisions.md`).
- A **safety guard** with veto power (kill switch, dry-run default, protected-device
  list, conformal/drift gates, rate limiting, rollback TTL) and a **response ladder**.
- **Real `nftables` enforcement** (`argus/respond/adapters/`) — genuinely blocks and
  un-blocks real socket connections, verified against actual connection attempts, not
  just `nft`'s exit code. Never the default adapter anywhere; opt-in only.
- **Post-response verification** and a **FastAPI** backend over SQLite.
- A polished **React + TypeScript + Tailwind analyst console** — Fleet, Incidents
  (with live evidence, SHAP attribution charts, and one-click replay), and Control
  (enforcement mode, kill switch, active actions) — with a real accessibility pass
  (keyboard-operable, a real ARIA dialog, `aria-live` status regions).
- A full **A0–A8 ablation** (`eval/harness.py`, `eval/ablation.py`) — 9 configurations
  × 5 seeds, real Mann-Whitney U / Holm-Bonferroni / Cliff's delta statistics, against
  a genuine benign holdout so F1 is a real, non-trivial number.

See `STATUS.md` for exactly what's stubbed or not yet built — it's a longer, more
honest list than most READMEs carry, on purpose.

## Tech stack

| Layer | Technology |
|---|---|
| Backend API | Python 3.11+, FastAPI, Uvicorn |
| Detection / ML | scikit-learn (Isolation Forest), a hand-written conformal prediction gate, SHAP (TreeSHAP) |
| Database | SQLAlchemy ORM, SQLite by default (any SQLAlchemy-supported DB via `ARGUS_DATABASE_URL`) |
| Real-time drift | `river` (online ADWIN drift detector) |
| Frontend | React 19 + TypeScript, Vite, Tailwind CSS v4, TanStack Query, React Router |
| Real testbed (optional, Linux only) | `pyroute2` (network namespaces/veth), `scapy` (packet capture), `dpkt` (pcap parsing) |
| Testing | pytest (backend), `tsc --noEmit` + `oxlint` (frontend) |
| Production hosting | Vercel (static console + a Python serverless function) — see [Production deployment](#production-deployment-vercel) |

## Prerequisites

- **Python 3.11 or newer** (`python3 --version`). The codebase uses modern type-hint
  syntax (`X | None`, `dict[str, Any]`) that requires 3.11+.
- **Node.js 20.19+ or 22.12+** and **npm** (`node --version`) — required by Vite 8 and
  the `@tailwindcss/oxide` native binary the console depends on. Older Node versions
  will fail `npm install` with an `EBADENGINE` or native-binding error.
- **Linux** if you want the *optional* real network-namespace testbed
  (`argus/testbed/`) — it needs root and `CAP_NET_ADMIN` to create network namespaces.
  Everything else (the synthetic simulation engine, detection, evidence, the API, the
  console) runs on macOS/Linux/WSL without any special privileges.
- **`nftables`** (Linux only) if you want to exercise the real enforcement adapter
  (`argus/respond/adapters/`) — this is opt-in and never the default; the system ships
  dry-run and only logs intended actions unless you wire this in explicitly.
- No Docker and no external database are required to run ARGUS locally.

## Local setup

```bash
git clone <this-repo-url> argus && cd argus

make install          # creates .venv, installs Python deps (pip install -e ".[dev]"),
                       # then npm install inside console/
cp .env.example .env  # then edit .env and set a real ARGUS_ADMIN_TOKEN (see below)
```

### Environment variables (`.env`)

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `ARGUS_ADMIN_TOKEN` | **Yes** | none — startup fails if unset | Bearer token required for any state-changing API call (`/control/*`, `/evidence/*/replay`). Deliberately has no default: CLAUDE.md/docs/14's rule is "a default credential in a security tool is an irony worth avoiding." Pick any string for local dev. |
| `ARGUS_ENFORCE` | No | `false` | `true` would let the response ladder call a real enforcement adapter instead of the dry-run default. Never flip this casually — see `docs/03-response-and-safety.md`. |
| `ARGUS_DATABASE_URL` | No | `sqlite:///./argus.db` | Any SQLAlchemy-supported DSN. SQLite needs no setup; point this at Postgres if you want it. |
| `ARGUS_CONFORMAL_ALPHA` | No | `0.05` | Significance level for the conformal prediction gate used in detection. |

### Run the tests

```bash
make test    # .venv/bin/python -m pytest tests/ -v -- 45 tests, ~65s
```

### Start the dev servers

```bash
# terminal 1 -- backend API on http://localhost:8000
export $(cat .env | xargs) && make api

# terminal 2 -- console on http://localhost:5173 (Vite dev server, proxies /api to :8000)
make console
```

Open `http://localhost:5173`. The Fleet and Incidents tabs will be empty until you
seed data: go to the **Control** tab, paste your `ARGUS_ADMIN_TOKEN` into the "Admin
token" box and click **Save**, then click **Run demo pipeline** — this actually runs
the full detect → correlate → risk → evidence → respond → verify loop against the
synthetic testbed and persists the result to SQLite; it is not canned data.

Or headless, without the console:

```bash
make seed       # runs the synthetic pipeline once, prints a summary
make evaluate   # full A0-A8 ablation, writes results/<timestamp>/results.json
```

### Build the console for production

```bash
cd console && npm run build   # tsc -b && vite build -> console/dist/
npm run preview               # optional: serve the production build locally
```

`npm run build` runs a full TypeScript typecheck (`tsc -b`) before bundling, so a
type error fails the build rather than shipping silently.

### The real network-namespace testbed (optional, Linux + root only)

```bash
pip install -e ".[live-testbed]"
```

```python
from argus.db.models import make_engine, init_db
from argus.pipeline import run_live_demo_pipeline

db = init_db(make_engine())()
print(run_live_demo_pipeline(db))  # real packets, real capture, real detection
```

### Common errors and fixes

| Symptom | Cause | Fix |
|---|---|---|
| `RuntimeError: ARGUS_ADMIN_TOKEN is not set` on `make api` | `.env` wasn't loaded into the shell, or was never created | `cp .env.example .env`, edit it, then `export $(cat .env \| xargs)` before `make api` |
| Console shows "Could not reach the API" | The FastAPI backend (`make api`) isn't running, or is on a different port | Start `make api` in a separate terminal; confirm `http://localhost:8000/health` responds |
| `npm install` fails with a native binding / `EBADENGINE` error | Node.js is older than 20.19 | Upgrade Node (nvm: `nvm install 22 && nvm use 22`) |
| `401 missing or invalid bearer token` clicking Replay/Kill Switch/Run demo pipeline in the console | No admin token saved in the console, or it doesn't match `.env`'s `ARGUS_ADMIN_TOKEN` | Control tab → paste the exact token from `.env` → Save |
| `pytest` failures mentioning `pyroute2`/`scapy` | Optional `live-testbed` extras aren't installed and you're running testbed-specific tests without them | `pip install -e ".[live-testbed]"`, or ignore — the core 45-test suite doesn't require these |
| `ModuleNotFoundError: No module named 'argus'` running a script directly | Running Python outside the project venv / without an editable install | Use `.venv/bin/python`, or re-run `make install` |

## Production deployment (Vercel)

The full local system (live SQLite, the real network-namespace testbed, real
`nftables` enforcement, on-demand ML fitting) intentionally does **not** all run in
a serverless environment — see `docs/06-vercel-deployment.md` for exactly why and
what the tradeoffs are. Production instead runs:

- `console/` built as a static site (`vercel.json`'s `buildCommand`).
- `api/index.py` — a smaller FastAPI app (`api/requirements.txt` installs only
  `fastapi`) that serves a real, pre-computed snapshot of one actual
  `argus.pipeline.run_demo_pipeline` run (`api/seed_snapshot.json`, produced by
  `scripts/export_seed_snapshot.py`), while running the genuine, unmodified
  evidence-replay and kill-switch code (`argus.evidence.replay`,
  `argus.respond.guard`) live on every request.

**Vercel project settings:**

- Build command: `cd console && npm install && npm run build`
- Output directory: `console/dist`
- Required environment variable: `ARGUS_ADMIN_TOKEN` (same purpose as local; the
  production API fails to start without it, on purpose — no default credential)

To redeploy after changes, either connect the repository to a Vercel project (git
push triggers a build) or use the Vercel CLI/dashboard's "Deploy" against this
repository root. To refresh the production demo data with a new real pipeline run:

```bash
python scripts/export_seed_snapshot.py
git add api/seed_snapshot.json && git commit -m "Refresh production demo snapshot"
```

## Findings so far (from the real A0-A8 ablation)

A real 5-seed run shows the project's actual argument, measured rather than
asserted: **`A6_detection_only`** — a configuration whose detection stack (policy +
rules + ML + correlation + risk scoring) is byte-for-byte identical to the full
system, with only the response ladder disabled — has **detection metrics identical
to `A0_full_system` by construction** and **0% containment against A0's 100%**
(`tests/test_ablation.py` asserts this directly). `A1_no_correlator` and
`A3_no_conformal_gate` both show a "negligible" effect on F1 but a "large" effect on
time-to-contain (Cliff's delta). Not every ablation matched the hypothesis, though:
`A2_no_risk_engine` and `A4_no_drift_monitor` showed only small/negligible
containment effects — reported as a real, mixed result rather than smoothed over.
See `research/experiment-plan.md` for the full table.

## Scope decisions, stated up front

Two real environmental constraints shaped this build, and both are handled by
building a genuine alternative rather than falling back to something weaker:

1. **Docker image pulls are blocked** (verified: 403 from Docker Hub's CDN) — so
   the original plan's 12-container testbed became a real Linux network-namespace
   testbed instead (`argus/testbed/`, `docs/04b`).
2. **General internet access for dataset hosts is blocked** (verified: 403 from
   CICIoT2023's host, same failure mode) — so the dataset track's *logic*
   (subsampling, feature parity) is built and tested against a synthetic fixture,
   ready to run the moment real data is reachable (`argus/data/`, `docs/05`).

Both are documented in detail, with the actual verification steps, in
`decisions.md` — not asserted, tested.

## Repository layout

```
argus/          the local/dev system: sim, collector, features, registry, behavior,
                 detect, correlate, evidence, respond, verify, db, api, testbed
console/        React + TypeScript + Tailwind analyst UI (Vite)
api/            production-only: a lighter FastAPI entrypoint (api/index.py) for
                 Vercel's Python serverless runtime, plus its own requirements.txt
                 and a real, exported pipeline-run snapshot (seed_snapshot.json)
scripts/        scripts/export_seed_snapshot.py -- regenerates api/seed_snapshot.json
vercel.json     Vercel build + routing configuration
docs/           design docs (00-15) including 06-vercel-deployment.md
research/       paper outline, experiment plan, baselines
resume/         resume bullets, interview prep
tests/          pytest suite
eval/           evaluation harness (A0-A8 ablation)
```

See `CLAUDE.md` for the full non-negotiable rules (dry-run by default,
metadata-only features, no fabricated results, determinism).
