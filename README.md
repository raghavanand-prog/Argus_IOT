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

## Quick start

```bash
make install          # python venv + deps, npm install for the console
cp .env.example .env  # set ARGUS_ADMIN_TOKEN
make test             # 45 tests (~65s)

# terminal 1
export $(cat .env | xargs) && make api        # http://localhost:8000
# terminal 2
make console                                   # http://localhost:5173

# in the Control tab of the console: paste your ARGUS_ADMIN_TOKEN, click
# "Run demo pipeline" -- this seeds real data by actually running the loop.
```

Or headless:

```bash
make seed       # runs the synthetic pipeline once, prints a summary
make evaluate   # full A0-A8 ablation, writes results/<timestamp>/results.json
```

The real network-namespace testbed needs Linux + root/CAP_NET_ADMIN + the
`live-testbed` extra (`pip install -e ".[live-testbed]"`):

```python
from argus.db.models import make_engine, init_db
from argus.pipeline import run_live_demo_pipeline

db = init_db(make_engine())()
print(run_live_demo_pipeline(db))  # real packets, real capture, real detection
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

See `CLAUDE.md` for the full layout and non-negotiable rules (dry-run by default,
metadata-only features, no fabricated results, determinism).
