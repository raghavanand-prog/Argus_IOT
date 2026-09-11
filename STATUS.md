# STATUS.md

Last updated: 2026-09-11 (second build session — "complete it fully").

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

1. Port the 5 synthetic-only attack scenarios to the live-testbed path
   (`argus/testbed/live_attacks.py`) and into `eval/ablation.py`'s scenario list.
2. Run the evidence-replay mechanism against ≥100 bundles (multiple seeded runs)
   to close the original plan's own gate.
3. If/when run in an environment with normal internet access: the dataset track,
   per `docs/05-data-pipeline.md`'s closing section.
4. The human evaluation of explanations, if the project continues with human
   collaborators (`research/experiment-plan.md`).
