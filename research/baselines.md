# Baselines

Rule from `docs/04-evaluation-protocol.md`: numbers from published papers are cited
as context, never placed in a table next to this project's own numbers as if
comparable — different splits, sampling, and hardware make that comparison
meaningless.

## What's actually implemented and measured

| # | Baseline | Status | Where |
|---|---|---|---|
| B1 | Suricata + ET Open (signature only) | Not built — no Suricata integration; `argus/detect/rules.py::signature_detections` is a documented threshold stand-in (see STATUS.md) | — |
| B2 | Isolation Forest on raw flow features (no per-device baselining) | Not isolated as a standalone comparison; the project's own Isolation Forest *is* baselined per-device by construction (`CalibratedDetector`) | `argus/detect/ml.py` |
| B3 | Random Forest on a published feature set | Not run — needs the dataset track (`docs/05`), verified infeasible in this environment | — |
| **B4** | **Detection-only (A6, `NoOpAdapter`-equivalent) — the field's actual L0 system** | **Implemented and measured** | `eval/ablation.py::A6_detection_only` |
| B5 | Published CICIoT2023/third-party results, cited only | Cited in `docs/01` (Sallam et al. 2026, Varol & Karakaya 2026) — never tabulated against this project's own numbers | `docs/01-architecture.md`, `docs/00` |

B4 is the one that matters most, and it's the one that's real: `eval/ablation.py`'s
`A6_detection_only` configuration runs the exact same detection stack as the full
system (`A0`) — same policy/rules/ML detections, same correlator, same risk
scoring — but the response ladder and verification are never invoked. A real,
5-seed measured run (commit `39ddb4a1`, `make evaluate`) shows:

- **A6's detection metrics are identical to A0's by construction**
  (`tests/test_ablation.py::test_a6_detection_metrics_match_a0_by_construction`
  asserts this directly: same TP/FP/FN/TN tuple for the same seed).
- **A6's containment rate is 0%** against A0's 100% (5/5 seeds contained).

That's the project's actual headline finding (see `docs/13`/`MASTER-PLAN.md`'s C4):
a system with identical detection accuracy to the field's typical published system
can differ completely in whether it ever acts.

## What's deliberately not compared against

- **ENTRUST** (Sanjalawe et al. 2026) — simulation-only, no released packet-level
  artifact to benchmark against. Discussed in `docs/01`'s related-work section, not
  benchmarked.
- **CAGE/CybORG agents** — different problem formulation (abstract state
  transitions, not packets).
- **Commercial NDR products** — no access, no reproducibility.

## Honest gaps

B1, B2 (as an isolated comparison), and B3 are not implemented. B1 needs a real
Suricata integration (a documented next step in `STATUS.md`); B3 needs the dataset
track, verified infeasible in this specific environment (`docs/05`). Neither is
faked or approximated with a number that looks like a measurement.
