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

## 2026-09-11 — second session: "complete it fully"

Asked directly whether the project was complete (answered honestly: no, per
`STATUS.md`'s own gap list from the first session), then asked to complete it.
Rather than assume the first session's scope cuts were permanent, checked each one
directly against this specific environment before deciding how to close it:

- **Docker**: `dockerd` actually runs here (root, working bridge/NAT), but every
  image pull is blocked (verified: 403 from Docker Hub's CDN). Rather than accept
  the synthetic-only testbed as final, built a real alternative: Linux network
  namespaces + veth pairs + a bridge via `pyroute2` (pip-installable, unlike Docker
  images), carrying genuine packets captured with `scapy`. Found and fixed two real
  kernel-networking interactions along the way (Docker's iptables FORWARD
  drop-policy silently absorbing our bridge traffic via `bridge-nf-call-iptables`;
  the `nftables` bridge-family hook needed once that sysctl is disabled) — see
  `decisions.md` for both.
- **Enforcement**: real `nftables` rules, verified against actual socket
  connections (a connection that provably fails during isolation and provably
  succeeds again after revert or a kill-switch-style flush), not just `nft`'s exit
  code. `block_destination` verified narrower than `isolate` against two real
  targets. Wrapped to the exact 3-argument shape the response ladder already calls,
  so zero changes were needed to `argus/respond/ladder.py` to drive it.
- **Attack scenarios**: implemented the remaining 5 from docs/02 (MQTT abuse, ARP
  spoofing, DNS tunnelling, identity spoofing, OTA spoofing), plus two new real
  detection signals to make them actually detectable (JA4-fingerprint-mismatch
  rule for identity spoofing; DNS query-name entropy features for tunnelling) —
  all 7 now run end to end in `run_demo_pipeline` against 7 distinct fleet devices.
- **Evaluation**: replaced the first session's 3-config, single-seed harness with
  the full A0-A8 ablation (9 configs × 5 seeds), each toggling real pipeline
  parameters rather than a parallel ablation-mode implementation, against a
  genuine benign holdout so F1 is a real number. Added real statistics
  (Mann-Whitney U, Holm-Bonferroni, Cliff's delta). A real run shows A1/A3/A6 all
  "negligible" on F1 but "large" on time-to-contain relative to A0 — and also shows
  A2/A4 *not* matching that pattern, reported honestly as a mixed result.
- **SHAP attribution**: added the missing Layer 2 explanation (docs/09) — TreeSHAP
  over a RandomForest trained on the same labelled calibration split the conformal
  detector uses. Verified flowing into real evidence bundles and rendering in the
  console as a real diverging bar chart.
- **Dataset track**: directly tested whether it was reachable (403 from CICIoT2023's
  host, same failure mode as Docker Hub) rather than assuming the first session's
  cut was permanent. Built and tested the subsampling/parity *logic*
  dataset-agnostically against a synthetic fixture, ready to run for real the
  moment an environment with normal internet access is available.
- **Console**: added the SHAP attribution chart and a real accessibility pass
  (keyboard-operable rows, a real ARIA dialog with focus management and
  Escape-to-close, `aria-live` regions) — verified live with browser automation,
  not just code review.
- **research/, resume/**: populated with real numbers from an actual run (commit
  `39ddb4a1`), each traced to a reproducible command — nothing estimated.

Verified throughout: 45/45 tests passing (up from 16), `ruff check` clean, the
full console flow re-screenshotted live against the real backend including the new
SHAP chart, Escape-to-close, and keyboard navigation.

Not done, honestly: the 5 newer scenarios don't yet run on the live-testbed path or
in the ablation harness (only `mirai`/`low_and_slow` do, on both); the dataset
track has zero real data behind it, anywhere; the evidence-replay sample (19
bundles) is smaller than the original plan's own 100-bundle gate; the human
evaluation of explanations was not run (cannot be, by an autonomous session) and is
named as such. All in `STATUS.md`'s next-steps list, in priority order.
