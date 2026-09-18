# STATUS.md

Last updated: 2026-09-18 (fourth session — Vercel production deployment confirmed live).

## This session's additions

- Production-ready serverless API (`api/index.py`) for Vercel, verified end-to-end
  in an isolated venv before deployment — real evidence replay and kill switch,
  serving a real (non-fabricated) exported snapshot. See `docs/06-vercel-deployment.md`.
- Expanded `README.md` with full local + production setup instructions.
- Two portfolio PDFs: an IEEE-style paper and a 23-section technical project guide
  (`docs/paper/`), both drawn from real, inspected project content.
- **Vercel deployment status: CONFIRMED LIVE** (2026-09-18). The prior session's
  account/role permission gap was resolved by the user reauthorizing the Vercel
  MCP connector with full project access (`list_projects`/`get_project` went from
  empty/404 to returning `argus-iot` correctly). A real bug was then found and
  fixed: `api/index.py` crashed the entire API (`FUNCTION_INVOCATION_FAILED` on
  every route) if `ARGUS_ADMIN_TOKEN` was unset, because the check ran at module
  import time instead of inside `require_auth()`. Fixed, redeployed, and directly
  verified against the live URL: `GET /api/health`, `/api/devices`, `/api/incidents`,
  `/api/actions`, `/api/evidence/{id}`, `/api/control/status` all return real `200`
  data. After the user set `ARGUS_ADMIN_TOKEN` as a Vercel project env var and a
  fresh deploy picked it up, `/api/health` and `/api/control/status` both confirm
  `admin_token_configured: true`. **One honest gap**: the three admin-only endpoints
  (`kill-switch`, `seed-demo`, `evidence/*/replay`) need a `POST` with a custom
  `Authorization` header, which no tool available in this session can send to a
  live URL (this sandbox's egress proxy blocks direct requests to `*.vercel.app`,
  and the Vercel MCP's own URL-fetch tool is GET-only). That exact auth logic
  *was* verified — in an isolated local venv, byte-identical code, both the
  missing-token 503 path and the correct-token 200/401 paths, including a real
  evidence replay reproducing correctly — but the live production request was not
  independently sent. Production URL: `https://argus-iot.vercel.app`. See
  `decisions.md`'s 2026-09-18 entries for both fixes and `progress.md` for the
  full account.
- **Universal-access audit (2026-09-18).** Confirmed directly, not assumed:
  the frontend has zero real dependency on `localhost`/`127.0.0.1` in the
  built production bundle (grepped the actual shipped JS); `ARGUS_ADMIN_TOKEN`
  never appears as a real value in frontend code, only as UI label text; CORS
  is already open (`allow_origins=["*"]`); every API route was re-verified
  live from outside. Found and fixed two real mobile-layout bugs (horizontal
  scroll on every page at phone widths, in `Nav.tsx`, `Incidents.tsx`, and
  `Control.tsx`) via real headless-Chromium screenshots of the production
  build at iPhone SE/14 and Pixel 7 sizes -- not hypothetical, measured. One
  open trade-off, not silently resolved: the kill-switch/in-memory `_STATE`
  is per-serverless-instance and not backed by a real database (Vercel
  KV/Postgres); the read data (devices/incidents/evidence) doesn't have this
  problem since it ships inside the deployed bundle itself. No tool available
  in this session can provision Vercel storage, and doing so is a real
  infrastructure/cost decision for the user, not a bug fix. **User decision
  (2026-09-18): stay on the free Hobby plan, no database added.**
- **User-confirmed on a real phone (2026-09-18).** After the sandbox-side
  mobile-viewport verification above, the user independently opened
  `https://argus-iot.vercel.app` on their own phone, over their own network,
  and confirmed it works -- the one check this session's sandboxed network
  policy could never perform itself (outbound to `*.vercel.app` is blocked
  here). This is the actual "any device, any network" confirmation, not a
  simulated stand-in for it.

## What works right now (verified by running it, not just reading the code)

- `pytest tests/` — **45/45 passing**, ~65s. Covers: feature extraction fixtures,
  enrollment/refusal, detection→correlation→risk integration, all 5 safety-guard
  mechanisms exercised directly, evidence hash-chain tamper detection, decision
  replay, **6 real network-namespace tests** (fabric setup/teardown leaves no
  state, real UDP delivery between namespaces, real captured mirai/low_and_slow
  attack flows against real wall-clock ground truth, the containment check), **4
  real nftables tests** (isolate blocks and revert restores an actual socket
  connection; block_destination is verified narrower than isolate against two real
  targets; a kill-switch-style flush restores connectivity; the ladder-shaped
  wrapper works end to end), **SHAP attribution tests**, **ablation mechanism
  tests** (A6 never contains, A6's detection metrics equal A0's by construction),
  **eval-statistics unit tests**, and **dataset-subsampling tests** against a
  synthetic fixture.
- `make seed` (synthetic) — runs the full loop for **all 7 attack scenarios**
  against 7 distinct fleet devices, persists to SQLite. Verified: 19 incidents/19
  evidence bundles/19 actions on the current build.
- **`run_live_demo_pipeline`** — the real-packet counterpart, sourcing flows from
  actual Linux network namespaces instead of the synthetic generator, running the
  identical downstream detect→respond→verify code. Verified end to end.
- Evidence replay measured at **100% reproducibility** (19/19 bundles, synthetic
  path). The mechanism caught and led to fixing a real non-determinism bug (see
  `decisions.md`).
- **`eval/harness.py`** — the full **A0–A8 ablation** (9 configurations × 5 seeds ×
  2 scenarios), each toggling real parameters on the real pipeline (not a parallel
  ablation-mode implementation), against a genuine benign holdout so F1 is a real
  number. Real Mann-Whitney U + Holm-Bonferroni + Cliff's delta statistics
  (`eval/stats.py`). A real run (commit `39ddb4a1`) shows A1/A3/A6 all producing
  "negligible" F1 effect but "large" time-to-contain effect relative to A0 —
  measured support for the project's central claim, not asserted.
- **A real network-namespace testbed** (`argus/testbed/`) — Linux network
  namespaces + veth pairs + a bridge, carrying genuine packets, captured with a
  custom multi-interface `scapy` sniffer, parsed into the exact same `FlowRecord`
  schema the synthetic engine produces. Built because Docker image pulls are
  blocked in this environment (verified: 403 from Docker Hub's CDN) — see
  `docs/04b-live-testbed.md`.
- **Real `nftables` enforcement** (`argus/respond/adapters/`) — genuinely blocks
  and un-blocks real socket connections; a `LiveNftablesAdapter` is a drop-in
  replacement for `DryRunAdapter` matching the exact 3-argument shape
  `decide_and_respond()` already calls, so the response ladder needed zero changes
  to drive it. Never wired in as a default anywhere — still opt-in, per CLAUDE.md
  rule 2.
- **SHAP (TreeSHAP) attribution** — a `RandomForestClassifier` trained on the same
  labelled calibration split the conformal detector uses; real per-feature
  contributions verified flowing into 19/19 evidence bundles and rendering live in
  the console.
- FastAPI backend + React console — all endpoints and all three screens (Fleet,
  Incidents+Evidence, Control) verified live via browser automation, including
  clicking the real "Replay decision" button and a real accessibility pass
  (keyboard-operable rows, a real ARIA dialog with focus management and
  Escape-to-close, `aria-live` status regions).
- `ruff check` clean (scoped to pyflakes/pycodestyle-errors/import-sort — see
  `pyproject.toml`).

## What's stubbed or simplified (named honestly, not hidden)

- **Live-testbed scenario coverage.** Only `mirai` and `low_and_slow` run on the
  real network-namespace path. The other five (`mqtt_abuse`, `arp_spoof`,
  `dns_tunnel`, `identity_spoof`, `ota_spoof`) are fully implemented and wired into
  the *synthetic* pipeline and the detection layer, but not yet ported to real
  socket-based attack scripts.
- **Ablation scenario coverage.** `eval/ablation.py` runs its 9 configurations
  against the same 2 scenarios, not all 7 — porting the other 5 in is
  straightforward (they already work in `run_demo_pipeline`) but not yet done.
- **Dataset track.** Verified infeasible in this specific environment — CICIoT2023's
  host returns 403 at this session's outbound proxy, the same failure mode as
  Docker Hub. The subsampling/parity logic is built and tested against a synthetic
  fixture (`argus/data/`), ready to run the moment real data is reachable. See
  `docs/05-data-pipeline.md`.
- **Live-testbed traffic realism.** Real packets, real sockets, real capture — but
  *metadata-realistic*, not full protocol implementations (no real MQTT broker, no
  real TLS handshake). This costs nothing feature-wise since ARGUS is
  metadata-only by design; see `docs/04b`.
- **Rate limiting via `nft limit rate over ... drop`, not `tc`.** `tc`/iproute2's
  CLI isn't installable in this environment (no apt/package-mirror access). A real,
  verifiable substitute — packets over a threshold are actually dropped — but drops
  rather than queues/shapes.
- **Blast radius for unresolvable neighbours** (true external IPs) still falls back
  to a fixed modest weight — the only case left un-upgraded from the original
  placeholder, and it's the case that structurally can never be resolved (an
  external IP has no device-type identity to look up).
- **Evidence replay sample size.** 100% measured on 19 bundles; the original plan's
  own gate wants ≥100. Mechanism is proven; sample is small.
- **SHAP training data.** Trained on the same small labelled calibration split the
  conformal detector uses (dozens of rows), not the full CICIoT2023 dataset track
  the original plan assumed — same root cause as the dataset-track gap above.

## Not implemented at all

- Real Zeek/Suricata integration (the rule/signature track is a documented
  threshold stand-in — see `argus/detect/rules.py`).
- The IoT-23 cross-dataset generalisation test (needs the dataset track).
- The optional human evaluation of explanations — needs real human participants,
  which cannot be supplied by an autonomous build session. Protocol design
  preserved in `research/experiment-plan.md` as explicit future work.
- A `compose/` real-Docker profile (superseded by `argus/testbed/`'s
  network-namespace approach for this environment; `compose/README.md` still notes
  it as a documented option for an environment where Docker pulls work).

## Immediate next steps, in priority order

1. **Broaden the ML detector's benign training corpus** (multi-seed, longer
   duration) — the real, identified fix for the false-positive rate `docs/16-
   ids-validation.md` measured (75/198 held-out benign windows flagged, 40 of
   those with a singleton conformal set). Not applied yet, deliberately — see
   `decisions.md`'s 2026-09-18 entry for why doing it now, using knowledge of
   the validation's own held-out seed, would itself be a form of tuning to
   the test.
2. Port the 5 synthetic-only attack scenarios to the live-testbed path
   (`argus/testbed/live_attacks.py`) and into `eval/ablation.py`'s scenario list.
3. Run the evidence-replay mechanism against ≥100 bundles (multiple seeded runs)
   to close the original plan's own gate.
4. ~~If/when run in an environment with normal internet access: the dataset
   track, per `docs/05-data-pipeline.md`'s closing section.~~ **Done
   (2026-09-18)** — not via internet access (still blocked, unchanged), but the
   project owner uploaded a real CICIoT2023 export directly. See the
   2026-09-18 entry below and `docs/17-cicioT2023-validation.md`.
5. The human evaluation of explanations, if the project continues with human
   collaborators (`research/experiment-plan.md`).

## IDS validation (2026-09-18) — `docs/16-ids-validation.md`

A real, reproducible 6-test end-to-end validation (telemetry → detection →
classification → incident → evidence → response → replay), executed once
locally at a fixed seed, results not adjusted after the fact:

- **PASS**: Test 2 (suspicious activity / mqtt_abuse), Test 3 (high-severity /
  mirai, reaches `isolate`/tier 4), Test 5 (kill-switch gating — verified the
  switch actually vetoes new automated actions, not just that the UI toggles),
  Test 6 (evidence replay — `reproduced: true`, original bundle unaltered).
- **FAIL**: Test 1 (baseline, whole fleet) and Test 4 (benign stress test on
  the hardest real case, smart-speaker-00) — a real, measured false-positive
  rate from the ML detector on genuinely held-out benign traffic, root-caused
  to a narrow (single-seed, ~4-hour) benign training corpus, not fixed in this
  pass to avoid tuning to the validation's own test seed. See "Immediate next
  steps" above and `decisions.md`.
- Added `argus.pipeline.run_benign_validation()` (and the shared
  `_enroll_and_train()` refactor it and `run_demo_pipeline` both call) as the
  minimal missing capability needed to make Tests 1/4 executable at all —
  no existing code path could previously test the detectors against
  attack-free traffic. Locked in as `tests/test_ids_validation.py` (46/46
  full suite still green).

## CICIoT2023 real-dataset evaluation (2026-09-18) — `docs/17-cicioT2023-validation.md`

The dataset track is real and run, not stubbed. The project owner uploaded a real
CICIoT2023 export (`df_Binary_FL_CICIoT2023.rar`, 600,000 rows, 8 pre-computed
features + binary `sub_label`) after direct verification confirmed the full
authoritative CICIoT2023/TON_IoT/Edge-IIoTset hosts remain unreachable from this
environment (still true — this is a real upload, not a changed network policy).

Built new: `argus/data/cicioT2023.py` (loader, inferred label-mapping documented
with evidence, `FeatureVector` builder, seeded disjoint train/calib/test split —
no temporal split possible, no timestamp column in this export), `argus/data/
metrics.py` (dependency-free confusion-matrix/precision/recall/F1/FPR/FNR),
`argus.pipeline.run_cicioT2023_evaluation()` (the real detect → correlate → risk →
respond → evidence chain per test row), and a new `CicioTEvaluationRunRow` table.
One adaptation to existing code: `CalibratedDetector`/`ShapExplainer`
(`argus/detect/ml.py`) gained an injectable `feature_keys` field (default:
unchanged, the synthetic pipeline's 14-key `FEATURE_KEYS`) so a *separate,
same-class instance* could be fit on this dataset's own 8 features rather than
reusing a model trained on an incompatible feature space. Post-response
`verify()` is deliberately skipped for these detections (documented in
`_process_cicioT2023_detection`'s docstring): it checks environment recovery
against a ground-truth ledger of attack phases with start/end times, which a
static dataset row has none of.

Real, measured result at seed=42 (2,000-row held-out test split, 1,020 real
incidents generated, one full run, not cherry-picked): confusion matrix
TP=1000 TN=980 FP=20 FN=0 → accuracy 99.0%, precision 98.04%, recall 100%,
F1 99.01%, FPR 2.0%, FNR 0.0%. Verified directly (not assumed) that this isn't
label leakage: train/calib/test row-index sets are disjoint by construction and
checked pairwise-empty, the label column never appears in the feature dict passed
to the detector, and both FP and FN examples (where they occur) show the
prediction genuinely diverging from ground truth in both directions. Full 20-section
report, real example records, and stated limitations (binary-only ground truth, only
the ML track exercised, inferred label direction, no live-network claim) in
`docs/17-cicioT2023-validation.md`.

Shipped end-to-end, not just as a script: a new "IDS Evaluation" console page
(metrics, confusion matrix, reproducibility manifest, paginated per-record table,
a per-record "Live Evaluation/Replay" detail drawer), local dev API endpoints to
run it live and browse history, and — because Vercel's serverless function has no
scikit-learn (documented constraint, unchanged from `docs/06`) — a precomputed
snapshot (`api/cicioT2023_eval_snapshot.json`, 4.8MB, from one real local run) the
production API serves read-only, with its real incidents/evidence merged into the
same `_STATE` `/api/incidents` already reads. Verified live in a headless browser
against the real local API (screenshots: full page, a TN record's drawer, an FP
record's drawer) and via direct HTTP calls (run, read, evidence replay on a real
CICIoT2023-sourced bundle — `reproduced: true`).

**Also found and fixed while building this**: `.gitignore`'s bare `data/` line was
matching `argus/data/` too (gitignore patterns without a leading `/` match at any
depth), which meant `argus/data/subsample.py`/`parity.py` — the dataset-track
scaffolding from the prior session — were never actually committed. A fresh clone
of this repo before today would have been missing them, silently breaking
`tests/test_subsampling.py`'s imports. Fixed by anchoring both `data/` and
`results/` to the repo root (`/data/`, `/results/`); `argus/data/` is committed now.

**Known limitation carried forward**: this result's FN=0/near-perfect separation
reflects unusually clean class separation in this specific 8-feature export (see
docs/17 section 6 and 20) — not evidence this detector generalizes to adversarial
or evasive traffic, which this benchmark, by construction, does not contain.
