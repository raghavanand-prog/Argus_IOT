# BUILD-ORDER.md — 4 phases, condensed from the original 6-phase/12-week plan

The original plan (preserved in `docs/`) lays out 12 weeks across 6 phases (A–F). This
repo executes the same dependency order but merged into **4 phases**, each ending in a
working, demoable increment instead of a calendar week. Each phase ends at a gate — a
command that runs and a condition that must hold.

## Phase 1 — Ground truth & signal (testbed sim, collection, features)

Merges original Phase A (testbed) + Phase B (collection/features).

Build: device behaviour simulator (multiple device types, diurnal patterns, jitter),
attack scenario orchestrator emitting a labelled ground-truth ledger, flow assembly,
metadata-only feature extraction (volume/timing/periodicity/destination/DNS/TLS/policy
groups).

**Gate:** `pytest tests/test_features.py` passes against fixtures; running the simulator
produces flows with visibly different per-device-type statistics and at least one
attack scenario with labelled ground-truth events aligned to the flows.

## Phase 2 — Know the devices, detect (registry, behaviour, drift, detection, risk)

Merges original Phase C (registry/behaviour/drift) + Phase D (detection/conformal/risk).

Build: device registry + bounded/guarded enrollment + declared policy; baseline builder;
deviation scoring; drift monitor (benign-drift vs compromise discriminator); rule/policy
detection track; ML track (Isolation Forest + Random Forest) with probability
calibration; conformal prediction gate; correlator; risk engine.

**Gate:** a scripted attack scenario produces detections from more than one source that
agree; correlator groups them into one incident; risk engine produces a score with a
term-by-term breakdown; conformal coverage on held-out data is within tolerance of
nominal.

## Phase 3 — Close the loop (evidence, safety guard, response, verify, API/datastore)

Merges original Phase E (evidence/response) + Phase F's datastore/API pieces.

Build: hash-chained evidence bundle + replay harness; safety guard (kill switch,
dry-run default, protected list, conformal/drift gates, rate limit, rollback timer);
response ladder with a dry-run enforcement adapter; post-response verification; SQLite
(Postgres-compatible via SQLAlchemy) datastore; FastAPI service exposing devices,
incidents, evidence, replay, control.

**Gate:** with `ARGUS_ENFORCE=false`, a full attack scenario produces a logged intended
action chain and a stored evidence bundle; replaying ≥100 stored bundles reports a
measured decision-reproducibility rate; kill switch and rollback timer are exercised by
an actual test, not read.

## Phase 4 — Experience & evaluation (analyst console, evaluation harness)

Merges original Phase F's console + evaluation-harness pieces (console was originally
optional/lowest-priority; it's promoted here because a strong UI was requested).

Build: React + TypeScript + Tailwind console — Fleet, Incident, Evidence (with live
Replay), Control screens; evaluation harness producing per-class P/R/F1, FP/device-hour,
TTD, TTC, FIR, containment efficacy, decision-reproducibility from one command; ablation
runner disabling correlator/risk/conformal/drift in turn.

**Gate:** `make evaluate` (or equivalent) produces a results table from a single command;
the console renders live data from the FastAPI backend end to end; an ablation table
exists (even if run on a short synthetic window) showing the shape of the C4 argument.

## What to cut if behind (same as the original plan, honoured in this order)

1. Attack scenarios beyond Mirai + low-and-slow.
2. The cross-dataset test against a second public dataset.
3. The public CICIoT2023 comparison track entirely (run simulation-only).

**Never cut:** the ground-truth ledger, the evidence replay test, the safety guard, the
ablation shape.
