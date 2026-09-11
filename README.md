# ARGUS

Closed-loop, evidence-bound IoT intrusion detection and autonomous response.

Most IoT intrusion detection research stops at the alert and is evaluated offline.
ARGUS closes the loop — **detect → correlate → assess risk → explain → decide → enforce
→ verify → feed back** — and binds every autonomous action to a hash-chained,
replayable evidence bundle, so "why did it act" has a measurable, checkable answer
instead of a plot. See `MASTER-PLAN.md` for the full contribution claims and
`BUILD-ORDER.md` for the 4-phase build order this repo actually follows.

## What's here right now

A working, tested, end-to-end system:

- A deterministic **synthetic testbed** (`argus/sim/`) — 10 IoT device behaviour
  profiles and two attack scenarios (Mirai-style recruitment, and a deliberately hard
  low-and-slow beaconing case) with a labelled ground-truth ledger.
- **Metadata-only feature extraction**, device **enrollment** (bounded, policy-guarded,
  refusable), a **behaviour engine** + **drift monitor**.
- A **rule/policy detection track** and a **calibrated ML track** (Isolation Forest +
  isotonic calibration + an inductive conformal prediction gate).
- A **correlator** and **risk engine**.
- A **hash-chained evidence bundle** for every incident, with a **replay harness** that
  measures decision reproducibility rather than assuming it.
- A **safety guard** with veto power (kill switch, dry-run default, protected-device
  list, conformal/drift gates, rate limiting, rollback TTL) and a **response ladder**.
- **Post-response verification** and a **FastAPI** backend over SQLite.
- A polished **React + TypeScript + Tailwind analyst console** — Fleet, Incidents
  (with live evidence + one-click replay), and Control (enforcement mode, kill switch,
  active actions).
- An **evaluation harness** (`eval/harness.py`) producing detection + containment
  metrics from one command, plus a condensed ablation showing the shape of the
  project's central argument (see "Findings so far" below).

See `STATUS.md` for exactly what's stubbed or not yet built, and `docs/` for design
rationale carried over from the original planning bundle.

## Quick start

```bash
make install          # python venv + deps, npm install for the console
cp .env.example .env  # set ARGUS_ADMIN_TOKEN
make test             # 16 tests, everything in Phases 1-3

# terminal 1
export $(cat .env | xargs) && make api        # http://localhost:8000
# terminal 2
make console                                   # http://localhost:5173

# in the Control tab of the console: paste your ARGUS_ADMIN_TOKEN, click
# "Run demo pipeline" -- this seeds real data by actually running the loop.
```

Or headless:

```bash
make seed       # runs the pipeline once, prints a summary
make evaluate   # writes results/<timestamp>/results.json
```

## Findings so far (from the condensed ablation)

Running `make evaluate` on the current scenarios shows the shape of the project's
actual argument: disabling the correlator does **not** change detection precision/
recall (both tracks still fire the same raw detections), but it roughly **doubles the
time-to-contain censoring rate** and fragments one incident into many separate,
weaker-risk alerts, because ungrouped detections never accumulate enough risk to
escalate past `alert`. This is a small, fast, honest demonstration of H1/H2 (see
`MASTER-PLAN.md`), not yet the full 9-configuration × 5-seed statistical study the
original plan describes — see `STATUS.md` for what a fuller run would need.

## Scope decision, stated up front

The original plan's testbed is 12 real Docker containers with real packet capture. This
build ships a **deterministic simulation engine** that generates the same *shaped* data
(flow records with realistic per-device statistics, diurnal patterns, labelled attack
windows) in seconds instead of hours, so the full loop is testable and demoable without
a live network. This is a documented trade, not a hidden shortcut — see `CLAUDE.md` and
`decisions.md`.

## Repository layout

See `CLAUDE.md` for the full layout and non-negotiable rules (dry-run by default,
metadata-only features, no fabricated results, determinism).
