# progress.md

Dated, append-only session log.

## 2026-09-11 — initial build session

Given the full ARGUS planning bundle (master plan, CLAUDE.md, 12-week/6-phase
BUILD-ORDER.md, docs/00-15, research/, resume/) and asked to execute it in fewer,
larger phases with a strong UI, rather than plan further.

Condensed the original 6-phase/12-week plan into 4 execution phases (`BUILD-ORDER.md`)
and built all four in one session:

- **Phase 1** — deterministic sim engine (10 device profiles, 2 attack scenarios with
  ground truth), flow windowing, metadata-only feature extraction. 5 tests.
- **Phase 2** — device registry/enrollment (bounded, policy-guarded, refusable),
  behaviour engine + ADWIN drift monitor, rule/policy + calibrated ML detection with an
  inductive conformal prediction wrapper, correlator, risk engine. 2 more tests
  (7 total), including a required "enrollment refused on policy violation" test.
- **Phase 3** — hash-chained evidence bundles + replay harness, safety guard (5
  mechanisms each exercised by a dedicated test), response ladder with a dry-run
  adapter, post-response verification, SQLAlchemy datastore, FastAPI backend, and
  `argus/pipeline.py` wiring the whole loop into one persisted run. 9 more tests
  (16 total). **Found and fixed a real determinism bug** via the replay test itself —
  see `decisions.md`.
- **Phase 4** — React + TypeScript + Tailwind analyst console (Fleet / Incidents+
  Evidence / Control), verified live against the real API with a browser automation
  pass including clicking the actual "Replay decision" button and confirming
  "Reproduced identically" against real backend logic. Plus a condensed evaluation
  harness (`eval/harness.py`) with a 3-configuration ablation.

Verified end to end: `pytest` (16/16), `make seed` (14 incidents/bundles/actions
persisted), the FastAPI backend hit directly with `curl`, the console built
(`npm run build`, `tsc --noEmit` clean) and screenshotted live against the running
backend on all three routes, and `eval/harness.py` run to completion producing a
results file.

Wrote `README.md`, `STATUS.md` (this session's honest scope-reduction list),
`decisions.md`, and condensed `docs/00`-`04` covering problem/threat-model,
architecture, detection/evidence, response/safety, and evaluation protocol.

Not done this session: real Docker/packet-capture testbed, additional attack
scenarios beyond the two "never cut" ones, nftables enforcement adapter, the public
dataset track. All listed in `STATUS.md` as next steps, not silently dropped.
