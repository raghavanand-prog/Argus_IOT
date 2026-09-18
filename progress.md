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
