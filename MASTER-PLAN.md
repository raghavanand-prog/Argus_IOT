# ARGUS — Master Plan (condensed)

Closed-loop, evidence-bound IoT intrusion detection and autonomous response.

Full source planning bundle (problem statement, literature review, threat model,
per-component design docs 00–15, evaluation protocol, paper outline, resume/interview
material) is preserved in `docs/`, `research/`, and `resume/`. This file states the
condensed execution contract this repository actually builds against.

## The one-sentence version

Most IoT intrusion detection research stops at the alert and is evaluated offline;
ARGUS closes the loop — detect → explain → decide → enforce → verify — on real traffic,
binds every autonomous action to a replayable evidence bundle, and measures containment
quality (time-to-contain, false-isolation rate) rather than only classification accuracy.

## Four contribution claims

- **C1 — the artifact.** An open, containerised, packet-level IoT testbed where the full
  loop runs end to end, reproducible from one command.
- **C2 — evidence-bound decisions.** Every autonomous action is bound to a hash-chained,
  replayable evidence bundle. Decision reproducibility is a measured property.
- **C3 — conformal gating.** Autonomous escalation requires a singleton conformal
  prediction set, giving a distribution-free bound on the error rate of unattended actions.
- **C4 — the headline finding.** Classification F1 is a weak predictor of containment
  outcome; components that don't move F1 (correlator, risk engine, drift monitor) move
  time-to-contain and false-isolation rate. Measured by ablation.

## Non-goals

Not a SOTA classifier. Not deep packet inspection (metadata-only, permanently). Not a
cloud project — local Docker only. Not reinforcement learning for response (explicit,
auditable ladder). Not real-device validation (testbed is simulated, stated honestly).
Not line-rate real-time.

## Two design commitments

1. **Metadata-only feature extraction** — flow stats, timing, entropy, DNS, TLS
   fingerprints, beaconing periodicity. No payload inspection, ever.
2. **Dry-run by default, everywhere** — `ARGUS_ENFORCE=false` unless explicitly flipped,
   protected-device list, rollback timer, kill switch.

## System shape

```
Testbed → Collection → Feature Extraction
   → Device Registry / Enrollment / Baseline
   → Behaviour Engine ↔ Drift Monitor
   → Rule/Policy Detection + Calibrated ML Detection (+ conformal gate)
   → Correlator → Risk Engine
   → Evidence & Explanation Engine (hash-chained bundle)
   → Safety Guard → Response Decision → Enforcement (dry-run by default)
   → Post-Response Verification → feedback into Risk + Behaviour
   → Append-only Audit Ledger
```

## Kill criteria

- A published open artifact already closes this loop on real traffic → pivot to
  comparison/replication.
- Ablation shows F1 fully predicts containment → report as a legitimate negative result.
- Testbed traffic is too easy (stock Isolation Forest gets >0.9 F1 on the hard
  low-and-slow case) → stop and redesign the testbed before building downstream.
- Disk/RAM budget (100GB / 16GB) blown → cut the dataset track, run testbed-only.

## What "done" looks like

A one-command reproducible loop; an evidence bundle per action with a measured
reproducibility rate; an evaluation harness producing every metric from one command; an
ablation table supporting or refuting C4; an honest limitations list.

See `BUILD-ORDER.md` for the condensed 4-phase execution plan actually used in this repo,
and `docs/00`–`docs/15` for full design rationale carried over from the original planning
bundle.
