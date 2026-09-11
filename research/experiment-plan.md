# Experiment plan

## Hypotheses (from `MASTER-PLAN.md`, restated with actual current status)

- **H1** — classification F1 is a weak predictor of containment outcome.
  *Status: supported, provisionally, by the measured ablation* — A1/A3/A6 all show
  "negligible" F1 effect (Cliff's delta) relative to A0 while showing "large" TTC
  effect. Provisional because this is 5 seeds against 2 scenarios on synthetic/live
  testbed data, not the dataset track's larger sample.
- **H2** — components that don't move F1 (correlator, risk engine, conformal gate,
  drift monitor) move containment metrics. *Status: mixed, honestly reported* — A1
  (no correlator) and A3 (no conformal gate) show large TTC effects as predicted.
  A2 (no risk engine) and A4 (no drift monitor) show only small/negligible TTC
  effects in the current measured run — a real result, not the expected one for
  those two components, and reported as such rather than adjusted to fit.
- **H3** — evidence binding yields measurable decision reproducibility without
  materially degrading latency. *Status: supported* — 19/19 = 100% decision
  reproducibility measured on the current seeded run (commit `39ddb4a1`); replay
  latency has not been separately profiled (see STATUS.md).

## Variables

**Independent**: ablation configuration (A0–A8, `eval/ablation.py`), attack
scenario (2 of the 7 implemented run through the ablation: `mirai`,
`low_and_slow` — the two `BUILD-ORDER.md` marks "never cut"), seed.

**Dependent**: precision/recall/F1 against a real benign holdout, time-to-detect,
time-to-contain (censored), false-isolation events, decision reproducibility rate.

**Controlled**: seeds (1–5, fixed and recorded in every `results/<timestamp>/results.json`
manifest alongside the git commit); device fleet composition; window size (300s).

## Runs actually executed

| Run | What | Where | Status |
|---|---|---|---|
| Ablation (A0–A8 × 5 seeds × 2 scenarios) | `eval/harness.py` / `eval/ablation.py` | `results/<timestamp>/` (gitignored, regenerate with `make evaluate`) | **Done** — ~30s wall time |
| Evidence replay | `argus/evidence/replay.py` | ad hoc script (see this doc's numbers above) | **Done** — 100% on 19 bundles |
| Live-testbed real-packet run | `argus/testbed/orchestrator.py` | `tests/test_live_testbed.py` | **Done**, 2 scenarios only |
| Dataset-track training/eval | `argus/data/subsample.py` | — | **Not run** — verified infeasible in this environment, `docs/05` |
| Cross-dataset generalisation (CICIoT2023 → IoT-23) | — | — | **Not run**, same reason |
| Human evaluation of explanations | — | — | **Not run** — needs real human participants, which an AI agent building this cannot supply; the protocol design from the original plan is preserved below as future work |

## Statistics

Non-parametric throughout (`eval/stats.py`): Mann-Whitney U per pairwise
comparison against A0, Holm-Bonferroni correction across the 8-comparison family,
Cliff's delta as the primary effect-size measure given 5-seed power is limited.
`tests/test_eval_stats.py` verifies the statistics functions themselves against
hand-computed examples, independent of any simulation run.

## Optional: human evaluation of explanations — design preserved, not run

The original plan's protocol (8–10 participants, 6 evidence bundles each, asked to
state what happened and whether the action was appropriate, scored against ground
truth, full bundle vs. SHAP-only ablated view) is sound and unchanged by anything
built in this session. It requires real human subjects and, per the original plan,
institutional ethics-approval awareness — nothing an autonomous build session can
supply. If this project continues with human collaborators, this is the next piece
of the evidence story to complete (`docs/09` already names this as the "weakest
part of the evidence story if it is not done" — it has not been done).
