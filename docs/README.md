# docs/ — design rationale

This folder is the condensed design record for ARGUS, distilled from the original
planning bundle (problem statement, literature/gap analysis, threat model, architecture,
testbed/data-pipeline design, detection/correlation/risk design, evidence design,
response/safety design, datastore/API, console, evaluation protocol, securing ARGUS
itself, runbook). Each numbered file below covers one topic; consult `MASTER-PLAN.md`
and `BUILD-ORDER.md` at the repo root for the execution contract.

- `00-problem-and-threat-model.md` — the operational problem, the gap in the literature,
  hypotheses, threat model, adversary model, attack scenarios.
- `01-architecture.md` — component diagram, data-flow contracts, the seven deliberate
  changes from the original sketch, resource budget.
- `02-detection-and-evidence.md` — feature groups, detection tracks, calibration,
  conformal gating, correlation, risk scoring, the evidence-bundle argument.
- `03-response-and-safety.md` — the safety guard, the action ladder, enforcement
  adapters, post-response verification, the metrics this all feeds.
- `04-evaluation-protocol.md` — experimental tracks, metrics, the ablation, baselines,
  Arp et al. pitfalls and how each is addressed.

The full literature citations, per-week build gates, and interview/resume material from
the original planning bundle are preserved in `research/` and `resume/`.
