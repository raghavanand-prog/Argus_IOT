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

## 2026-09-17 — third session: local polish, Vercel deployment, IEEE paper + project guide

Asked to turn the project into a clean local package, a Vercel-deployed production
site, and two portfolio PDFs (an IEEE-style paper and a 23-section technical guide).

- **Production API for Vercel** (`api/index.py`): a deliberately lighter FastAPI
  entrypoint than the local `argus/api/main.py` — reuses `argus.evidence.replay`
  and `argus.respond.guard.KillSwitch` unmodified (both pure stdlib, verified by
  running them in an isolated venv containing only `api/requirements.txt` before
  ever deploying), and serves a real, non-fabricated snapshot of one actual
  `argus.pipeline.run_demo_pipeline` run (`scripts/export_seed_snapshot.py` →
  `api/seed_snapshot.json`, capped at 2 incidents per device+scenario pair to keep
  the file a manageable size — every kept row is still untouched real output).
  Fixed a real bug caught before deployment: routes were originally undecorated
  (matching the local dev proxy, which strips `/api`), but Vercel's rewrite does
  *not* strip that prefix, so production needed an explicit `APIRouter(prefix="/api")`
  — caught and fixed by reasoning about the platform difference, then verified
  end-to-end against a real uvicorn instance (health, devices, incidents, a real
  authenticated evidence replay, kill-switch engage/disengage, seed-demo reset).
- **Vercel deployment — blocked, not silently reported as done.** Three deploy
  attempts via the Vercel MCP integration each succeeded on the *first* call to a
  brand-new project name, then every subsequent call against that same project —
  status checks, build logs, even `list_projects` — returned 403/404, consistently,
  across three separate project names. This reads as a genuine account/role
  permission gap on the connected Vercel integration (matches Vercel's own error
  text pointing at team-member-role docs), not anything fixable by retrying or
  renaming. The last attempt (`argus-iot-demo`) was submitted with the complete,
  correct file set and reported "Deployment created (INITIALIZING)," but this could
  not be confirmed to have finished building or to be serving correctly — the user
  was told this explicitly rather than being handed an unverified URL as if it were
  live, per the project's own no-fabrication rule extended to deployment claims.
  Asked the user to check the Vercel dashboard directly; continued with the
  independent remaining work while that's pending.
- **Citation audit and fix.** While sourcing references for the IEEE paper, verified
  every citation via web search before use. One citation already committed to
  `docs/00-problem-and-threat-model.md` from an earlier session turned out to be
  wrong: "Varol & Karakaya, Sensors 26(18):5744" — the real authors of that paper
  are Ogunseyi, Thiyagarajan, He, Bist, and Du, and the specific "~99%→~39% F1"
  figure attributed to it could not be verified as belonging to it. Corrected in
  `docs/00`, `docs/05-data-pipeline.md`, and `research/baselines.md` rather than
  left in place or quietly worked around.
- **README.md** expanded with prerequisites, a tech-stack table, per-variable `.env`
  documentation, a build/test walkthrough, a common-errors table, and a Vercel
  production deployment section — all using the project's actual commands, not
  generic placeholders.
- **Two portfolio PDFs**, both generated from HTML/CSS rendered via Playwright +
  Chromium: `docs/paper/ARGUS-IEEE-Paper.pdf` (IEEE two-column style, 7 pages, 6
  individually-verified references, the real measured ablation/replay numbers, an
  explicit limitations section) and `docs/paper/ARGUS-Project-Guide.pdf` (23
  sections, 29 pages, covering architecture through viva Q&A, implemented-vs-
  proposed features and security measures kept explicitly separate throughout).

Verified again before finishing: `pytest` 45/45, `ruff check` clean, console
production build clean (`tsc -b && vite build`).

Not done, honestly: Vercel deployment status is unconfirmed (see above — a
dashboard-permission issue, not a code issue); everything else from the prior
sessions' gap lists (dataset track, 5 scenarios on the live-testbed/ablation paths,
≥100-bundle replay sample, human evaluation of explanations) is unchanged.

## 2026-09-18 — fourth session: Vercel deployment resolved, confirmed live, real bug found and fixed

Picked up directly where the third session left off: the Vercel MCP connector's
project-level access was empty/404 even though team access resolved correctly.
The user reauthorized the connector with full ("all current and future
projects") access; `list_projects`/`get_project` immediately started returning
`argus-iot` correctly. Root-caused as an integration/connection project-scope
setting, not a team-role permission (the user is the `wolfie4` team's owner) —
recorded in `decisions.md`.

With `argus-iot` finally visible, redeployed the complete, correct file payload
(the one already verified in the third session) and the frontend came up
correctly, but every `/api/*` route 500'd with `FUNCTION_INVOCATION_FAILED`.
Diagnosed directly: `api/index.py` raised `RuntimeError` at module import if
`ARGUS_ADMIN_TOKEN` was unset, which crashes the whole ASGI app on Vercel, not
just the endpoints that need that credential. This is a real bug independent of
the deployment blocker -- fixed by moving the check into `require_auth()`, so
only the three admin-guarded endpoints depend on it. Verified locally first (an
isolated venv, byte-identical code): all read endpoints return `200` with the
token unset; with it set, wrong/missing auth still `401`s and a real evidence
replay reproduces correctly. Redeployed; confirmed live: `/api/health`,
`/api/devices`, `/api/incidents`, `/api/actions`, `/api/evidence/{id}`, and
`/api/control/status` all return real `200` data directly fetched from
`https://argus-iot.vercel.app`, and `get_runtime_errors` shows nothing in the
window since the fix.

The user then set `ARGUS_ADMIN_TOKEN` as a real Vercel project environment
variable (a random token this session generated for them, since no available
Vercel tool can set project env vars) and asked for a redeploy. Redeployed;
`/api/health` and `/api/control/status` now both report
`admin_token_configured: true`, confirming the deployed function reads the real
secret.

**Honestly not verified:** the three admin-only endpoints
(`/control/kill-switch`, `/control/seed-demo`, `/evidence/*/replay`) need a
`POST` with a custom `Authorization: Bearer <token>` header. No tool in this
session can send that to a live URL -- this sandbox's egress proxy rejects
direct requests to `*.vercel.app` (confirmed again this session via a direct
`curl` attempt, `403` at the proxy), and the Vercel MCP's `web_fetch_vercel_url`
tool is GET-only with no custom headers. The underlying logic was verified
correct in the isolated-venv test above, using the identical code now deployed,
but the live authenticated request itself was not sent. Reported to the user as
exactly that gap, not glossed over.

Production URL: `https://argus-iot.vercel.app` (aliased at
`https://argus-iot-wolfie4.vercel.app`).

## 2026-09-18 — real end-to-end IDS validation (`docs/16-ids-validation.md`)

Asked for a reproducible validation of the whole detection lifecycle
(telemetry → detection → classification → incident → evidence → response →
replay), with real results, no invented passes. Inspected the actual
architecture first rather than assuming: telemetry generation and detection
happen in the same process/call (`argus.pipeline.run_demo_pipeline()`), not
over a separate ingestion hop; the production Vercel deployment serves a
static snapshot and cannot run this live, by the same documented design as
the third session's API split -- so the full lifecycle can only be executed
locally, and the report says so plainly rather than implying a phone-only
demo could do it all.

Found one real gap before any test could run: no existing code path tested
the detectors against pure benign traffic (`run_demo_pipeline` always mixes
in all 7 attack scenarios). Added `argus.pipeline._enroll_and_train()` (the
enroll+train logic factored out so both the real pipeline and the new
validation path share one trained detector) and `run_benign_validation()`
(read-only, no DB writes, the same four detectors + the same
correlate/risk/tier_for_risk path used for reporting what a flagged window
would have escalated to). Ran all 6 tests for real:

- Test 1 (baseline, whole fleet) and Test 4 (benign stress test on
  smart-speaker-00, the device whose real attack scenario is deliberately
  shaped to look like its own normal beacon): **FAIL**. 75 of 198 held-out
  benign windows flagged by the ML detector; 40 with a singleton conformal
  set that would have reached an enforcement tier. Investigated the cause
  directly (re-ran at both the detector's 120s training-window size and the
  300s inference size -- false positives persisted at both, ruling out a
  window-size bug in the validation itself) rather than assuming: a real
  generalization gap from training on one ~4-hour, single-seed benign
  corpus. Root cause and the identified fix (broaden the training corpus)
  are both documented; the fix was deliberately *not* applied this session,
  since doing so with knowledge of this exact test's held-out seed would be
  tuning the model to pass the check built to catch this.
- Test 2 (mqtt_abuse) and Test 3 (mirai, reaches `isolate`/tier 4): **PASS**,
  via the real, unmodified `run_demo_pipeline`.
- Test 5 (kill-switch response): **PASS** -- engaged the switch over real
  authenticated HTTP, re-ran the pipeline, and confirmed actions genuinely
  dropped from 19 to 0 on the new run (not just a UI toggle); the vetoed
  incident's evidence bundle records `guard_verdict=veto`,
  `gates_failed: ["kill_switch_disengaged"]`, confirmed visually in the
  console.
- Test 6 (replay): **PASS** -- real authenticated replay, `reproduced: true`,
  original bundle's hash unchanged after replay.

Result: 4/6 pass, 2/6 fail, reported exactly as measured in a test matrix,
with the fails' root cause investigated and written up rather than hidden
or tuned away. Locked the exact counts in as a new regression test
(`tests/test_ids_validation.py`); full suite 46/46 green, `ruff` clean.
Wrote `docs/16-ids-validation.md` with the full matrix, a local full-lifecycle
demo procedure and a separate phone/production demo procedure (explicit
about which steps each can and can't do), and a screenshot list for
research-paper evidence.

## 2026-09-18 — CICIoT2023 real-dataset IDS evaluation (docs/17)

User rejected the earlier synthetic-simulation-based validation as insufficient
and asked for the IDS to be tested against a real, published IoT cybersecurity
benchmark dataset, with a strict "no fabrication" spec: never let ground truth
influence the prediction, no hardcoded results, incidents only from the actual
detector's own output, a proper held-out train/calib/test split, and full
reproducibility metadata. Before implementing anything, inspected ARGUS's real
detection pipeline (FlowRecord schema, FEATURE_KEYS, CalibratedDetector,
correlate/risk/respond/evidence chain) and searched this environment's one
reachable channel (public GitHub) for actual row data from the three named
datasets (CICIoT2023/Edge-IIoTset/TON_IoT); found real, reachable, but
schema-incompatible TON_IoT sensor data, and a real, compatible but differently-
named sibling dataset, and reported both honestly rather than silently picking
one (see decisions.md). User then uploaded a real CICIoT2023 export directly
(`df_Binary_FL_CICIoT2023.rar`, 600,000 rows). Inspected its actual schema before
writing any code, as instructed: 8 pre-computed statistical features + a binary
`sub_label`, no raw IP/port/byte/DNS/JA4 fields at all -- a genuinely different
feature space from ARGUS's flow-based `FEATURE_KEYS`, reported honestly rather
than forced through unmodified.

Built the evaluation track for real: `argus/data/cicioT2023.py` (loader with
schema validation, label-mapping documented as an inference with the supporting
per-label feature-mean evidence, seeded disjoint train/calib/test split -- no
temporal split possible, no timestamp column in this export), `argus/data/
metrics.py` (confusion matrix + accuracy/precision/recall/F1/FPR/FNR, plain
arithmetic, hand-verifiable), and `argus.pipeline.run_cicioT2023_evaluation()` --
the real load -> preprocess -> fit a dataset-specific `CalibratedDetector` ->
`ml_detections()` (blind to `sub_label`, same 0.5 threshold as the rest of ARGUS)
-> compare to ground truth -> correlate -> risk -> respond -> evidence chain,
persisting real `IncidentRow`/`EvidenceBundleRow` rows only for predicted-positive
records. One adaptation to existing code, not a fork: gave `CalibratedDetector`/
`ShapExplainer` an injectable `feature_keys` field (default unchanged) so a
separate instance could be fit on this dataset's 8 columns instead of the
synthetic pipeline's 14. `verify()` (post-response environment-recovery check) is
deliberately skipped for these detections and documented why -- a static dataset
row has no environment to re-observe.

Ran it for real against the full uploaded file (not a toy example): 5,000 benign
training rows, 1,000 balanced calibration rows, 2,000 balanced held-out test rows,
seed 42. Verified directly, not assumed, that there was no leakage: train/calib/
test row-index sets pairwise-disjoint, `sub_label` never present in the feature
dict passed to the detector, deterministic under a fixed seed and sensitive to a
different one. Real result: confusion matrix TP=1000 TN=980 FP=20 FN=0 ->
accuracy 99.0%, precision 98.04%, recall 100%, F1 99.01%, FPR 2.0%, FNR 0.0%,
1,020 real incidents generated (every predicted-positive row, TP+FP -- zero
incidents for the 980 correctly-quiet or 0 missed rows). Confirmed evidence
replay reproduces identically for a real CICIoT2023-sourced bundle, same as the
synthetic pipeline's.

Shipped the full stack, not just a script: new DB table
(`CicioTEvaluationRunRow`), local dev API endpoints (run live, list/read
evaluation history), a precomputed production snapshot
(`api/cicioT2023_eval_snapshot.json`, from one real local run, since Vercel's
function has no scikit-learn) with its real incidents/evidence merged into the
same state `/api/incidents` reads, and a new "IDS Evaluation" console page --
dataset/reproducibility manifest, confusion matrix, metrics, a paginated
per-record table with TP/TN/FP/FN filters, and a per-record detail drawer
(features -> preprocessing -> prediction -> ground truth -> classification ->
incident) doubling as the requested "Live Evaluation/Replay" mode. Verified all
of it live: direct HTTP calls against the real local API (run, read, replay) and
headless-browser screenshots of the actual rendered page and two record drawers
(a true-negative and a false-positive), not just component code review.

Also committed a real, small (2,000-row) slice of the actual dataset
(`argus/data/fixtures/cicioT2023_eval_subset.csv`) as a test fixture and wrote
`tests/test_cicioT2023_eval.py` against it -- unit tests for the loader/split/
metrics plus a real integration test that runs the actual production code path
(`run_cicioT2023_evaluation`) end-to-end against real committed data and asserts
the exact measured confusion matrix at seed=42 (same "assert the exact number,
not a range" discipline as `tests/test_ids_validation.py`), including a real
evidence-replay check. Full suite: 56/56 passing, `ruff` clean.

Along the way, found and fixed a real pre-existing bug unrelated to this
feature: `.gitignore`'s bare `data/` rule was silently excluding `argus/data/`
(the prior session's dataset-track scaffolding) from every commit since it was
written -- a fresh clone would have been missing those files entirely. Fixed by
anchoring the gitignore rule to the repo root; see decisions.md.

Wrote `docs/17-cicioT2023-validation.md`, the full 20-section validation report
(dataset, source, samples, classes, features, preprocessing, model, threshold,
confusion matrix, all six metrics, incident count, real example TP/FP records,
an honest "zero FN occurred" note rather than a fabricated example, and eight
stated limitations including the binary-only ground truth and the unusually
clean class separation in this specific export).

## 2026-09-18 — live network sensor: a third data track (`docs/18-live-sensor.md`)

Built the local sensor/agent architecture the project owner specified: `Real LAN
-> ARGUS Local Sensor/Agent -> device discovery + flow metadata -> ARGUS API ->
feature extraction -> ARGUS IDS -> Detection -> Incident + Evidence ->
Control/Response (dry-run)`. Inspected the existing architecture first, per
instruction, and recorded exactly what was reused unmodified vs. adapted vs.
built new in docs/18 section 2.

New package `sensor/`: `discovery.py` (passive ARP/neighbour-table reads only --
`/proc/net/arp` on Linux, `arp -a` fallback, no active probing), `oui.py` (a
small static real IEEE OUI table, no network fetch), `flows.py`
(`packets_to_live_flows`, adapted from `argus/testbed/pcap_to_flows.py`, keyed
off actually-discovered devices), `baseline.py` (`build_live_baseline`, reusing
`argus.registry.enrollment.Baseline`'s output shape but never the
`FLEET[device_type]` policy guard, which would `KeyError` on `"unknown"`),
`live_detect.py` (`LiveAnomalyDetector`, a genuinely separate unsupervised
detector -- see below), `client.py` (stdlib-only HTTP client), `agent.py` (the
CLI entrypoint, `python -m sensor.agent`).

**Two real bugs found while testing end-to-end, not just claimed fixed:**

1. **Detector never actually fit.** The first version of `agent.py`'s capture
   loop called `LiveAnomalyDetector.fit()` exactly once per device, with a
   single feature vector from that device's first-ever window --
   `fit()`'s own floor (then 4 samples) meant it silently returned `False` and
   left the detector permanently unfitted, so `live_anomaly_detections()`
   returned `[]` forever regardless of how anomalous later traffic was.
   Confirmed via three separate real capture runs (7, then 3, then 6+ windows,
   real generated UDP traffic including a deliberately sharp burst) all showing
   0 detections. Fixed by accumulating a rolling per-device feature-vector
   history and only fitting once `MIN_BASELINE_WINDOWS` windows have
   accumulated (`agent.py`'s loop now tracks `feature_history` and only
   constructs/fits a `LiveAnomalyDetector` once that floor is met).

2. **The floor itself was too low.** Even after fixing (1), a real capture test
   still produced 0 detections. Instrumented diagnostics (real captures, printed
   raw score + percentile per window) showed the n=4 floor fits a *degenerate*
   model -- every score, baseline and burst alike, came back identical
   (`raw=0.4730` for all of them). A follow-up synthetic unit test (same real
   feature dict shapes, controlled jitter) confirmed the pattern generalizes:
   flat/uninformative at n=4, meaningfully varying by n=10, usefully spread by
   n=20. Separately, root-causing why an even longer real capture test *still*
   produced 0 detections surfaced a second cause: the test's baseline traffic
   varied only in `bytes_in_mean`, which is not one of
   `argus.detect.ml.FEATURE_KEYS`'s 14 tracked features -- so the actually-used
   feature vectors were bit-for-bit constant across the whole baseline
   regardless of sample count. Regenerated baseline traffic with real variation
   in a tracked dimension (destination port count, natural timing jitter) and
   reran the full real capture -> flow -> feature -> baseline -> detector chain:
   `window 23: n_flows=99 raw=0.6182 pct=100.0 detections=1`, four consecutive
   real detections during the injected burst, zero false positives across the
   20-window baseline and 2-window ramp-up. `MIN_BASELINE_WINDOWS` raised to 20
   and moved into `live_detect.py` as the single source of truth (previously
   duplicated as a separate constant in `agent.py`, which was itself a latent
   bug waiting to happen -- the two could have drifted).

Wired both APIs: `argus/db/models.py` gained `LiveDeviceRow`/
`SensorHeartbeatRow`; `argus/pipeline.py` gained `ingest_live_observation()` and
`_process_live_detection()` (the same correlate -> risk -> decide -> evidence
tail every other track uses, `enforce_enabled=False` hardcoded, `verify()`
skipped -- both documented as structural, not missing); `argus/api/main.py`
gained `/live/ingest`, `/live/devices`, `/live/status`. Production
`api/index.py` got the same three endpoints against its own in-memory store
(`_LIVE_DEVICES`/`_LIVE_SENSORS`/`_LIVE_INCIDENTS`/`_LIVE_EVIDENCE`,
deliberately separate from `_STATE` so a demo-snapshot reset can never wipe real
sensor data) -- verified by calling the route functions directly end-to-end
(ingest -> devices -> status -> incidents -> evidence lookup), since this
sandbox has no `httpx` for `TestClient`.

Console: a genuinely prominent BENCHMARK EVALUATION / LIVE NETWORK mode
selector in the header (not just a nav link), a new Live Network page (real
device table, sensor connection status, explicit "No live network sensor
connected" empty state -- never a fallback demo), "IDS Evaluation" relabelled
to "Benchmark Evaluation" everywhere including its own page copy, and
Incidents' origin split extended from 2-way to 3-way (`cicioT2023_eval` /
`live_network` / synthetic). `tsc --noEmit` and `npm run build` both clean.

New tests: `tests/sensor/` (discovery parsing against real-shaped fixture text,
flow assembly against real in-memory scapy packets, baseline math, and the
`LiveAnomalyDetector` behaviour pinning down both bugs above -- fit refuses
below the floor, an unfitted detector is inert, a genuinely different window
scores above `ANOMALY_PERCENTILE` once enough varied baseline exists) and
`tests/test_live_ingest.py` (`ingest_live_observation` against a real in-memory
SQLite DB -- discovery-only never forces an incident, a real detection produces
a real `IncidentRow`+`EvidenceBundleRow` with `dry_run=True`). Full suite:
77/77 passing, `ruff` clean on every touched file.

Deployed to the existing `argus-iot-live` project (git-linked, auto-deploys on
push to this branch -- confirmed via `get_project`, not assumed) and verified
live, not just claimed. First push actually broke every route
(`FUNCTION_INVOCATION_FAILED` on `/api/health` too, not just the new `/live/*`
endpoints) -- root-caused by re-reading `.vercelignore` directly:
`argus/correlate/`, `argus/risk/`, `argus/sim/`, and `argus/schemas.py` were
still excluded from before this feature existed, and the new endpoints import
all four for the first time. Fixed, then verified the fix *before* pushing
again by simulating Vercel's own exclusion list against a scratch copy of the
repo with only `api/requirements.txt`'s `fastapi` installed (no numpy/
scikit-learn) -- confirmed `IMPORT OK` and real responses locally first.
Redeployed and re-verified against the real live URL:
`GET https://argus-iot-live.vercel.app/api/health` (200, real payload),
`/api/live/status` (200, `{"sensors":[],"any_connected":false,...}` -- honest
empty state), `/api/live/devices` (200, `[]`), `/api/incidents` (200, real
1020+ incidents, confirming the correlate/risk imports genuinely load).

Also found (while spot-checking the console itself post-deploy) and fixed a
second, pre-existing production bug, unrelated to this feature's own code:
`vercel.json` had no SPA-fallback rewrite, so direct navigation to any
client-side route other than `/` 404'd -- confirmed pre-existing by checking
`/incidents` (also 404) before fixing, not just the new `/live` route. Added a
catch-all `/(.*) -> /index.html` rewrite after the existing `/api/(.*)` one
(order matters; API routes unaffected). Both fixes recorded in decisions.md.

## 2026-09-18 — real bug found running the sensor against the project owner's actual Mac

The project owner ran `python -m sensor.agent` against their own real LAN for
the first time -- exactly the end-to-end check this session's own testing
(against a sandbox container's synthetic ARP entry) could never fully stand
in for. Two real, user-reported errors, both fixed:

1. `.venv` was created with macOS's bundled Python 3.9 (Xcode Command Line
   Tools), not the `>=3.11` `pyproject.toml` already declares -- `datetime.UTC`
   (3.11+) failed to import. Not a code bug; pointed the user at recreating
   the venv with a real 3.11+ interpreter.
2. `ModuleNotFoundError: No module named 'scapy'` on a plain `pip install -e .`
   -- this **was** a real code bug, not just a missing extra. `sensor/agent.py`
   imported `argus.testbed.capture` (which needs scapy) unconditionally at
   module level, so even pure discovery-only mode -- documented as the safe,
   zero-elevated-privilege default -- silently required scapy just to start.
   Fixed by moving every capture-mode-only import (`CaptureSession`,
   `packets_to_live_flows`, `window_flows`, `extract_device_window`,
   `build_live_baseline`, `signature_detections`, `LiveAnomalyDetector`,
   `live_anomaly_detections`, `MIN_BASELINE_WINDOWS`) into a lazy
   `_import_capture_stack()`, called only when `--enable-capture` is actually
   passed, with a clean actionable error
   (`pip install -e '.[live-testbed]'`) instead of a raw traceback if scapy is
   missing at that point. Verified, not assumed: built a fresh venv with the
   project installed via plain `pip install -e .` (no scapy present, matching
   the user's exact situation) and confirmed `python -m sensor.agent --once`
   (discovery-only) now runs successfully; separately confirmed
   `--enable-capture` without scapy prints the clean install instruction and
   exits 1, no traceback. Re-ran `tests/sensor/` (21/21) and capture mode
   against a real local API afterward to confirm nothing regressed.
