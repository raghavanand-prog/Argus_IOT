# decisions.md

Dated, append-only architectural decisions with reasoning and rejected alternatives.

## 2026-09-11 — condense 6 phases/12 weeks into 4 execution phases

**Decision:** Merge the original plan's Phase A+B, C+D, E+(part of F), and (rest of
F) into four phases (see `BUILD-ORDER.md`), each ending in a working, demoable
increment instead of a calendar week.

**Why:** Explicitly requested — "don't make it way more phases, execute in fewer
phases." The original plan itself says (BUILD-ORDER.md's own intro) that a 150-hour
budget doesn't comfortably build everything described, and that cutting is a working
part of the plan, not a contingency. Merging phases doesn't change what gets built,
only how the work is chunked and gated.

**Rejected alternative:** Keep all 6 original phases as separate execution units. Would
have added ceremony (more gate documents, more intermediate states) without changing
scope, directly against the instruction received.

## 2026-09-11 — synthetic simulation engine instead of a real 12-container Docker testbed

**Decision:** `argus/sim/` generates FlowRecords with realistic per-device-type
statistics, diurnal patterns, and a labelled ground-truth ledger, deterministically, in
under a second — instead of standing up 12 real containers with real packet capture,
nftables, and tc.

**Why:** The original testbed is itself a multi-week infrastructure project (Docker
networking, Zeek integration, real enforcement adapters) that would have consumed the
entire session without producing a working detect→respond→verify loop or any UI. The
project's actual contribution claims (C2 evidence-binding, C3 conformal gating, C4 the
containment-vs-F1 argument) don't depend on packets being real; they depend on the
loop's *logic* being real and testable. The sim engine makes every downstream stage
(features, detection, risk, evidence, response, verification) exercise real code
against real, if synthetic, data.

**Rejected alternative:** Build the real Docker testbed first, per the original
week-by-week order. Rejected because it front-loads infrastructure risk (Docker
networking inside this environment is itself uncertain) ahead of anything that would
be visible as "the system", and the user explicitly asked to execute toward a working
system with a UI, not toward infrastructure setup.

**Consequence, stated honestly:** Every metric this build currently produces is a
metric about the simulation's shape, not about real network behaviour. `STATUS.md`
lists a real-Docker profile as a named next step, not a hidden gap.

## 2026-09-11 — SQLite by default, not Postgres

**Decision:** `argus/db/models.py` uses SQLAlchemy against `sqlite:///./argus.db` by
default; `ARGUS_DATABASE_URL` can point it at Postgres and nothing else changes.

**Why:** Zero-setup local dev and demo — `make seed` should not require a running
Postgres container. SQLAlchemy's ORM layer is the actual portability boundary, not the
specific engine.

**Rejected alternative:** Postgres-only, per the original plan's schema doc. Rejected
for this build because it would gate every test and the entire demo behind a running
database container, for no benefit at the current data volume.

## 2026-09-11 — rate limiter used wall-clock time, found via the evidence-replay test

**What happened:** While smoke-testing the full pipeline against the API, a bundle
whose stored decision was `observe` (tier 0, vetoed) replayed to `alert` (tier 1,
allowed). Root cause: `ActionRateLimiter` gated on `time.time()`. The entire simulated
pipeline — which spans several *simulated* hours of device behaviour and multiple
attack scenarios — runs in well under one second of *real* time, so every action taken
during a single pipeline run looked, to a wall-clock rate limiter, like a burst within
the same real-world hour. Some actions got vetoed by the per-device rate limit as a
side effect of how fast the simulation runs, not because of anything the evidence
bundle actually recorded. Replay then used a *fresh* rate limiter (no history), so it
didn't reproduce that particular veto.

**Fix:** Threaded a `now: float | None` parameter (simulated-clock seconds, derived
from each incident's own timestamp) through `guard.evaluate()` and
`ladder.decide_and_respond()`, and `pipeline.py` now passes
`incident.last_seen.timestamp()` instead of leaving it to default to `time.time()`.

**Why this matters enough to record:** This is exactly the category of bug
`docs/02`/`docs/09` describe the replay mechanism as existing to catch — "a
reproducibility rate below 100% locates non-determinism... that other systems have and
never discover because they never check." It was caught within the first hour of
having a working replay path, by actually running it against real pipeline output
instead of only synthetic unit-test fixtures. Reproducibility on the demo run went from
intermittent to a measured 100% after the fix.

**Rejected alternative:** Leave it and document the reproducibility rate as "not 100%,
investigate why" per the original plan's instruction for an honestly-reported low rate.
Rejected because the root cause was identified immediately and was a straightforward,
correct fix (rate limiting should always be relative to the clock the decision is made
on, not the wall clock of whoever happens to be running the pipeline) — there was no
reason to ship a known, fixable bug and call it a finding.

## 2026-09-11 (second session) — a real network-namespace testbed instead of accepting the synthetic-only cut as permanent

**Decision:** When asked to complete the project fully, re-verified rather than
assumed the first session's biggest scope cut (no real testbed). Found `dockerd`
actually runs in this environment (root, working bridge/NAT) but every image pull
is blocked — 403 from Docker Hub's CDN, tested directly. Built
`argus/testbed/` instead: real Linux network namespaces + veth pairs + a bridge via
`pyroute2` (installable from PyPI, which *is* reachable), carrying genuine packets
captured with `scapy`.

**Two real bugs found and fixed while building it:**
1. Bridge traffic was silently vanishing — Docker's iptables-nft ruleset sets
   `FORWARD` to policy-drop, and `bridge-nf-call-iptables=1` routes *any*
   L2-bridged traffic through that hook, including a bridge Docker has nothing to
   do with. Fixed by disabling that sysctl in `fabric.py`.
2. That fix then meant `nftables` enforcement rules using the `inet`/`ip` table
   family would never see the traffic either (same sysctl). Fixed by using
   nftables' `bridge` table family instead, which filters at the bridging layer
   directly, independent of that sysctl — the documented-correct way to filter
   bridged L2 traffic, not a workaround for the workaround.

**Why this matters enough to record twice** (also in `docs/04b-live-testbed.md`,
which has the full detail): both bugs were only findable by actually exercising
the real path, not by reasoning about it — exactly the argument for building the
real testbed over settling for synthetic-only in the first place.

**Rejected alternative:** Accept the first session's Docker cut as final and only
harden the synthetic engine further. Rejected because the user's instruction was
to complete the project fully, and "the planned infrastructure doesn't work here"
turned out to have a real, buildable alternative once actually investigated,
rather than being a dead end.

## 2026-09-11 (second session) — ablation toggles real pipeline parameters, not a parallel implementation

**Decision:** `eval/ablation.py`'s 9 configurations (A0-A8) each toggle an actual
parameter on the actual pipeline code — `assess_risk`'s own `weights` argument for
"no risk engine", a `correlate()` bypass for "no correlator", forced-singleton
conformal sets for "no conformal gate", which detector functions get called for
the rules/ML/policy splits — rather than a separate "ablation mode" that
reimplements simplified versions of each component.

**Why:** A parallel implementation can silently drift out of sync with the real
one, and a bug fixed in the real pipeline wouldn't necessarily get fixed in the
ablation's copy. Every ablation result is therefore evidence about the actual
shipped system, not about a model of it.

**Consequence:** `tests/test_ablation.py::test_a6_detection_metrics_match_a0_by_construction`
can assert byte-for-byte identical detection tuples between A0 and A6 — a
guarantee that would be much weaker (an implementation claim, not a construction
guarantee) if A6 were a separately-coded "detection-only" path.

## 2026-09-11 (second session) — verified the dataset-track network block directly rather than assuming it

**Decision:** Before writing off the dataset track again, tested a direct request
to `https://www.unb.ca/cic/datasets/iotdataset-2023.html` (CICIoT2023's host).
Result: 403 at this session's outbound proxy — the identical failure mode already
documented for Docker Hub. Confirmed via the proxy's own status endpoint that its
allowlist covers package registries (pypi, npm, crates, Go modules) and a handful
of first-party hosts, nothing else.

**Why this is worth a separate decision entry**: the instruction was to complete
the project fully, which means every previously-cut piece deserves a fresh check
rather than an inherited assumption — the Docker cut above turned out to have a
real alternative; the dataset-track cut, checked with the same rigor, turned out
not to (no network-namespace-style workaround exists for "the actual file is
hosted on a server this session cannot reach"). Both outcomes are reported with
the same evidence standard.

**What was still worth doing**: `argus/data/subsample.py` and
`argus/data/parity.py` implement the parts of docs/05's protocol that are pure
logic, tested against a synthetic fixture — real, tested code, just not yet
exercised against real data. See `docs/05-data-pipeline.md`.

## 2026-09-17 (third session) — a separate, lighter API for the Vercel deployment

**Decision:** `api/index.py` is a deliberately different, smaller FastAPI app from
`argus/api/main.py`, not a copy-with-tweaks. It imports only `argus.evidence.bundle`,
`argus.evidence.replay`, and `argus.respond.guard` (verified pure-stdlib, no ML
dependency, by running the app end-to-end in a venv containing nothing but
`api/requirements.txt` before ever deploying) and serves a static, real, exported
snapshot of one `run_demo_pipeline` execution instead of a live SQLite-backed run.

**Why:** Three real Vercel serverless constraints, not a stylistic preference: no
root/`CAP_NET_ADMIN` (the live network-namespace testbed structurally cannot run
there), no persistent filesystem guaranteed across separate function invocations
(a live "seed then browse" SQLite flow doesn't hold up), and a function size/time
budget that excludes numpy/scikit-learn/shap. Full reasoning in
`docs/06-vercel-deployment.md`.

**Rejected alternative:** Deploy the full `argus/api/main.py` unmodified and hope
the platform tolerates it. Rejected because two of the three constraints above are
hard platform limits, not soft ones — the app would fail at import or at first
write, not merely run slowly.

**Consequence, stated honestly:** As of this session, the actual live Vercel
deployment status could not be confirmed. Every deploy attempt through the
connected Vercel MCP integration succeeded on the first call to a brand-new
project name and then returned 403/404 on every subsequent call against that same
project — including plain status/log reads — across three independently-named
attempts. This matches a team-member-role permission gap on Vercel's side (the
platform's own error text points at team-role documentation), not a bug in
`api/index.py` or `vercel.json`. Reported to the user as unverified rather than as
a working production URL; see `progress.md`'s third-session entry for the full
sequence.

## 2026-09-17 (third session) — corrected a misattributed citation rather than reuse it

**What happened:** While sourcing references for the IEEE paper deliverable, every
candidate citation was checked against a live web search before use — including
one already committed to `docs/00-problem-and-threat-model.md` by an earlier
session ("Varol & Karakaya, Sensors 26(18):5744"). That citation turned out to be
wrong: the paper at that exact venue/volume/issue/article number has different,
verifiable authors (Ogunseyi, Thiyagarajan, He, Bist, Du), and the specific
"~99%→~39% F1" figure attributed to it could not be verified as belonging to it.

**Fix:** Removed the specific figure and corrected the citation note in `docs/00`,
`docs/05-data-pipeline.md`, and `research/baselines.md`, rather than silently
dropping it from the new paper while leaving the wrong claim live elsewhere in the
repository. The one citation that *was* verified accurate (Sallam, El Barachi & Li,
2026, DOI 10.3390/iot7010016 — title, authors, and the specific "29 of 32" and
scalability-testing claims all confirmed) is the sole third-party gap-analysis
citation the paper and `docs/00` now rely on.

**Why this matters enough to record:** CLAUDE.md's no-fabrication rule doesn't
carve out an exception for content inherited from an earlier session or already
committed — a wrong number found during unrelated work still gets fixed at the
source, not just avoided in the new document.

## 2026-09-18 — scoped the missing-admin-token failure to only the endpoints that need it

**What happened:** Once the Vercel account/team permission issue (see the prior
entry) was resolved by the user re-authorizing the integration with full project
access, `argus-iot` deployed successfully and the frontend served correctly --
but every `/api/*` route returned `FUNCTION_INVOCATION_FAILED`. Root cause:
`api/index.py` raised `RuntimeError` at *module import time* if
`ARGUS_ADMIN_TOKEN` was unset, which crashes the entire ASGI app on cold start,
not just the three admin-guarded endpoints (`/control/kill-switch`,
`/control/seed-demo`, `/evidence/*/replay`) that actually need that credential.
`/health`, `/devices`, `/incidents`, and `/actions` need no auth at all and were
taken down by a missing *optional* variable regardless.

**Fix:** Moved the check from module scope into `require_auth()`, the one place
that's actually reached only by the three admin endpoints. Missing token now
means those three return a clear `503` naming the fix, while every read-only
endpoint works unconditionally. `admin_token_configured` was added to
`/health` and `/control/status` so the state is visible in the response rather
than inferred. Verified locally in the same isolated venv discipline as the
original build: all read endpoints return `200` with the variable unset; with it
set, unauthenticated/wrong-token requests to admin endpoints still correctly
`401`, and a real evidence replay against the actual snapshot data reproduces
correctly end to end.

**Rejected alternative:** Generate a random admin token at cold start when none
is configured. Rejected because serverless instances don't share memory, so a
generated token would be unknown to the person trying to use the Control screen
and would silently change on every cold start -- worse than an honest `503`.

**Rejected alternative:** Switch production to `argus/api/main.py` (the local/
dev API) since the user's bug report referenced it by name. Rejected because
that module needs numpy/scikit-learn/shap (serverless function size budget),
a persistent SQLite file (not guaranteed across invocations), and for some
code paths root/CAP_NET_ADMIN (the live-testbed) -- all real platform blockers
recorded in this file's 2026-09-17 entry and `docs/06-vercel-deployment.md`,
not an oversight to fix by switching entrypoints.

## 2026-09-18 — the Vercel blocker was connector project-scope, not team role

**What happened:** The third session's Vercel deploys all failed with
`list_projects` returning empty and `get_project` 404ing for `argus-iot`, even
though `list_teams` correctly resolved the `wolfie4` team. The user confirmed
via the dashboard that their account is the team's *Owner* -- ruling out a
team-role explanation. The actual cause: the Vercel MCP connector/integration
itself had a project-access scope (separate from both team role and this
session's own per-tool-call approval setting) that didn't include `argus-iot`.
Reauthorizing the connector with "all current and future projects" access
fixed it immediately -- `list_projects` and `get_project` started returning
real data on the next call, no code or project changes needed.

**Why this matters enough to record:** three different permission layers
looked similar from the outside (team role, session tool-approval, connector
project-scope) but only fixing the right one mattered. Verified each layer
directly rather than guessing, per CLAUDE.md's evidence standard.

## 2026-09-18 — could not independently verify the admin-authenticated endpoints against the live URL

**What happened:** After the user set `ARGUS_ADMIN_TOKEN` as a real Vercel
project environment variable and asked for a redeploy, `/api/health` and
`/api/control/status` confirmed the deployed function reads it
(`admin_token_configured: true`). But testing the three admin endpoints
themselves requires a `POST` with a custom `Authorization: Bearer <token>`
header, and no tool available in this session can do that against a live URL:
this sandbox's egress proxy rejects direct requests to `*.vercel.app`
(re-confirmed via a direct `curl` attempt -- `403` at the proxy), and the
Vercel MCP's `web_fetch_vercel_url` tool only supports unauthenticated `GET`.

**What was and wasn't verified:** The exact `require_auth()` logic now running
in production was verified correct in an isolated local venv against
byte-identical code -- missing-token returns `503`, wrong/missing token
returns `401`, correct token returns `200`, and a real evidence replay
reproduces correctly. What was *not* independently confirmed is that this
specific live deployment, reached over the real network, behaves identically
-- reasonable to expect given the code is unchanged and the read endpoints all
verified correctly, but reported as inferred, not directly observed, per
CLAUDE.md rule 1.

**Rejected alternative:** Report the admin endpoints as "tested" based on the
local venv result alone. Rejected because the whole point of live verification
is catching platform-specific surprises the local run can't see (as happened
twice already this session, with connector scope and the import-time crash) --
claiming a live test that wasn't actually sent would defeat that purpose.

## 2026-09-18 — IDS validation found a real calibration gap; reported it, did not tune around it

**What happened:** Asked for a real, reproducible end-to-end IDS validation
(docs/16-ids-validation.md). Building Tests 1 and 4 ("confirm normal traffic
doesn't raise false incidents") required a capability that didn't exist:
nothing in the codebase ran the real detectors against pure benign traffic --
`run_demo_pipeline` always mixes in all 7 attack scenarios. Added
`argus.pipeline._enroll_and_train()` (the enroll+train logic, factored out of
`run_demo_pipeline` so both it and the new validation path share one trained
detector, not two that could drift apart) and `run_benign_validation()`
(read-only: fresh held-out benign window per device through the same four
detectors, then the same correlate/risk/tier_for_risk path, no DB writes).

**The result:** a real, measured 75/198 window-level false-positive rate from
the ML detector on genuinely held-out benign traffic (only 3 of 11 devices
stayed clean), 40 of which carried a singleton conformal set and would have
reached an enforcement tier. Investigated the cause directly rather than
guessing: re-ran the same check at the detector's own 120s training-window
size as well as the 300s inference size used elsewhere -- false positives
persisted at both (142 and 75 respectively), ruling out a window-size
mismatch in the validation script itself. Root cause: the `IsolationForest`
is trained on one ~4-hour benign window at one RNG seed -- too narrow a
benign distribution to generalize to a genuinely different slice of equally
legitimate traffic.

**Why this wasn't fixed by retraining on more data before reporting it:**
the obvious fix (a broader, multi-seed benign training corpus) is a real
methodology change. Applying it now, with direct knowledge of this specific
test's held-out seed, would mean tuning the model to pass the one check
built to catch this -- the exact "fake PASS indicator" the validation was
explicitly asked not to produce. Reported as a genuine `FAIL` for Tests 1
and 4 in the test matrix, with the root cause and the identified-but-not-
applied fix both stated plainly, and locked in as an exact-count regression
test (`tests/test_ids_validation.py`) so it can't silently drift either
better or worse without the change being deliberate and recorded.

**Rejected alternative:** Loosen the validation's definition of "false
positive" (e.g., only count non-singleton conformal sets, or only count
detections above a higher tier) until the number looked acceptable.
Rejected for the same reason as above -- redefining the test to fit the
result is a more subtle version of the same fakery the user explicitly
ruled out, and the raw ML detector genuinely does fire on this traffic at
the same p_attack>=0.5 threshold `argus/detect/ml.py`'s own production code
uses, singleton set or not.

## 2026-09-18 — full "any device, any network" architecture audit; two real mobile layout bugs found and fixed

**What happened:** Asked directly to confirm ARGUS is a universally-accessible
web app with no dependency on localhost, the developer's machine, or any local
server. Rather than assume the existing architecture already satisfied this
(it mostly did), audited it directly:

- Grepped `console/src` and the *built production bundle* for `localhost`,
  `127.0.0.1`, and hardcoded ports. Found zero real references -- the one
  `localhost` string in the built JS is `react-router`'s internal dummy
  `new URL('http://localhost')` base for its URL-parsing API, never an actual
  network call. `console/src/lib/api.ts` already calls only a relative `/api`
  path, which resolves against whatever origin serves the page -- already
  correct for any device on any network, no code change needed.
- Grepped the built bundle for `ARGUS_ADMIN_TOKEN` to confirm it never appears
  as a real secret value, only as UI label/placeholder text -- confirmed.
- Re-verified CORS (`allow_origins=["*"]` already set), the Vercel rewrite,
  and every API route live against the real production URL.
- Took real headless-Chromium screenshots of the *actual production build*
  (not dev mode) at three phone viewports (iPhone SE 320px, iPhone 14 390px,
  Pixel 7 412px) across all three pages. Found genuine horizontal-scroll bugs
  on every page at every size -- not a hypothetical, a measured
  `scrollWidth > clientWidth` on real rendered DOM. Root-caused to three
  separate CSS mistakes (`Nav.tsx`'s header not wrapping, `Incidents.tsx`'s
  table wrapper using `overflow-hidden` instead of `overflow-x-auto`,
  `Control.tsx`'s token input missing `min-w-0` and the actions-row list
  missing `flex-wrap`) and fixed each, re-screenshotting after every change
  until all 9 (3 devices x 3 pages) came back clean. Desktop re-screenshotted
  at 1440px afterward and confirmed pixel-identical to before -- no regression.

**What was deliberately not done:** Replacing the in-memory mutable state
(kill switch, in-memory `_STATE` reset by `/control/seed-demo`) with a real
persistent database (Vercel KV/Postgres/Blob). No tool available in this
session can provision Vercel storage, and doing so is a real infrastructure
and cost decision, not a bug fix -- raised to the user explicitly rather than
silently added or silently skipped. See the trade-off recorded in
`STATUS.md`'s 2026-09-18 update: the read data (devices/incidents/evidence)
is already "persistent" in the sense that matters here -- it ships inside the
deployed function bundle, not read from any local file -- and only the
kill-switch toggle state is genuinely ephemeral per function instance.

**Why this matters enough to record:** the instruction was specifically to
verify rather than assume, and two of three findings (the mobile scroll bugs)
were real defects an assumption-based answer would have missed entirely.

**Follow-up, same day:** asked directly whether to add real persistent storage
for the kill-switch/demo-reset state (Vercel KV/Postgres/Blob). User's answer:
stay on the free tier, skip the database for now. Decision recorded rather
than silently revisited later: `argus-iot` stays on Vercel's Hobby plan with
no attached storage add-on; kill-switch state remains per-serverless-instance
in-memory, exactly as documented above. `/health` and `/control/status`
already surface `admin_token_configured` and the in-memory nature of this
state is documented in `docs/06-vercel-deployment.md`, so this isn't a hidden
limitation -- it's a deliberate scope line, the same kind CLAUDE.md's scope
section already draws elsewhere in this project.

## 2026-09-18 — CICIoT2023 real-dataset evaluation: dataset substitution presented as a trade-off, then resolved by direct upload

Continuing the CLAUDE.md instruction to present real trade-offs rather than
silently choosing: the user's request specifically named CICIoT2023, Edge-IIoTset,
or TON_IoT. Before writing any evaluation code, searched this environment's one
reachable channel (anonymous public GitHub repo cloning -- direct requests to
Kaggle/UNSW/UNB/UQ/IEEE Dataport all independently re-confirmed blocked, not
assumed from memory) for actual row-level data from any of those three. Found:
the official TON_IoT "IoT Telemetry" files (real, reachable, but sensor-schema --
incompatible with ARGUS's flow-based pipeline without a second input mode);
NF-ToN-IoT-v2 (the correct network-flow-schema reissue of TON_IoT) referenced by
many research repos but its actual row data not committed anywhere reachable at a
usable size; and a real, reachable, schema-compatible sibling dataset
(NF-CSE-CIC-IDS2018-v2, 80k rows) that was *not* one of the three named datasets.
Presented this honestly as four options (use the sibling dataset now; the user
downloads and uploads a real subset themselves; adapt ARGUS for TON_IoT's sensor
schema; keep searching) rather than silently picking one. User chose to provide a
real CICIoT2023 export directly (`df_Binary_FL_CICIoT2023.rar`) -- resolved
without needing any of the four fallbacks.

## 2026-09-18 — CalibratedDetector/ShapExplainer: feature_keys made injectable

The uploaded CICIoT2023 export ships 8 pre-computed statistical features
(`rst_count, ICMP, Min, AVG, IAT, Number, Variance, Weight`), a completely
different feature space from the synthetic pipeline's 14-key `FEATURE_KEYS`
(derived from `FlowRecord` via `extract_device_window`). Reusing the
flow-trained detector unchanged would silently misalign feature values by
position; reusing its *class* while forking a parallel copy for the new feature
space would duplicate ~100 lines of calibration/conformal logic CLAUDE.md's own
style guidance says to keep short and singular. Chose instead to add one
injectable `feature_keys: list[str]` field to `CalibratedDetector` and
`ShapExplainer` (default: unchanged, so the synthetic pipeline's behaviour and
every existing test are untouched), so a same-class, separately-fitted instance
can be trained on the dataset's own 8 named columns. This is the "minimum
scientifically valid adaptation" the user explicitly authorized if the existing
model proved incompatible -- documented in the class docstring and in
`docs/17-cicioT2023-validation.md` section 7, not silently done.

## 2026-09-18 — Post-response verification skipped (not faked) for CICIoT2023 detections

`argus.verify.verification.verify()` checks whether a live/simulated environment
recovered after an enforcement action, by matching against a ground-truth ledger
of attack phases with start/end times and a source device. A single CICIoT2023
row is a static, already-captured record: there is no environment left to
re-observe after "acting" on it, and no attack-phase ground truth with a
start/end time to check against. Two options considered: call `verify()` with an
empty ground-truth list (produces a plausible-looking "inconclusive" outcome for
every single detection, silently implying a check happened) or skip it outright
and say why. Per CLAUDE.md rule 4 (no fabricated results) and the user's explicit
"do not invent values" instruction, chose to skip it -- `verification_outcome` is
`None` for every CICIoT2023-derived incident, and the reason is written directly
into that incident's evidence-bundle trace, not just this file.

## 2026-09-18 — `.gitignore`'s bare `data/` rule fixed to `/data/` (root-anchored)

Discovered while adding `argus/data/cicioT2023.py` and `argus/data/metrics.py`:
`git ls-files argus/data/` returned nothing. The prior session's dataset-track
scaffolding (`argus/data/subsample.py`, `argus/data/parity.py`, their
`__init__.py`) existed on disk and were imported successfully by
`tests/test_subsampling.py` in this working directory, but had never actually
been committed -- `.gitignore`'s `data/` line (intended for the top-level
`data/`/`results/` output directories) matches a directory named `data`
*anywhere* in the tree, not just at the repo root, because it has no leading
`/`. A fresh clone of this repo, at any point before today, would have been
missing `argus/data/` entirely and failed that test file's imports at collection
time -- a real, previously-undetected bug, not a hypothetical one. Fixed by
anchoring both `data/` and `results/` to `/data/`/`/results/`; confirmed via
`git check-ignore -v` that `argus/data/*` is no longer matched while the
top-level `data/cicioT2023/` (where the real, un-committed 40MB original
CICIoT2023 CSV lives locally) still is.

## 2026-09-18 — CICIoT2023 evaluation deployed to a new git-linked Vercel project, not the original `argus-iot`

Deploying this feature to production hit a real infrastructure constraint:
the existing `argus-iot` Vercel project (serving `argus-iot.vercel.app`) was
never connected to GitHub -- every prior deploy there was a one-off manual
upload -- and `create_git_project` cannot reconnect an existing unlinked
project of the same name (confirmed: attempting `projectName: "argus-iot"`
returned a 409 conflict). Linking also required installing the Vercel GitHub
App on the user's account first, a one-time action only they could take
(done, confirmed by the user). Rather than attempt a risky, hard-to-reverse
domain move without asking, created a new project (`argus-iot-live`, prj_
Z2qwga7RAqza8h8yWH1BHudwDz4C) git-linked to `raghavanand-prog/Argus_IOT`,
production branch `claude/nifty-ramanujan-ruaew2` -- auto-deploys on every
push now, unlike the original project. Live at
`https://argus-iot-live.vercel.app`, verified via real HTTP calls (health,
`/api/cicioT2023/eval` returning the exact same real numbers as the local
run, `/api/incidents` showing 1028 = 1020 CICIoT2023 + 8 original synthetic-
seed incidents correctly merged). Whether to move the `argus-iot.vercel.app`
custom domain onto this project is the user's call, not made unilaterally.

Two real build failures fixed along the way (both now recorded in
`.vercelignore`'s own comments, not just here):
1. Vercel's framework auto-detection found the repo-root `pyproject.toml`
   (the full local ML dependency set -- numpy/scikit-learn/river/shap) and
   tried to build the entire repo as one FastAPI app via `uv sync`, which
   failed (`river` pulls in `llvmlite`, which doesn't compile in Vercel's
   build sandbox). Fixed with `"framework": null` in `vercel.json` plus a
   `.vercelignore` excluding `pyproject.toml` and the non-deployment parts of
   the repo, so the build falls back to vercel.json's own buildCommand/
   rewrites (the console static build + the lightweight `api/index.py`
   function with its own `api/requirements.txt`) -- the same shape the
   original manual deploy always used.
2. That first fix over-excluded: `.vercelignore`'s blanket `argus/` rule also
   hid `argus/evidence/` and `argus/respond/`, which `api/index.py` genuinely
   imports at runtime (pure standard-library code, no ML dependency -- see
   its own module docstring). Caused `ModuleNotFoundError: No module named
   'argus'` in production. Fixed by excluding only the specific subpackages/
   files `api/index.py`'s import graph never reaches, verified locally first
   by simulating the exact surviving file set and confirming the import
   succeeds before pushing again.

## 2026-09-18 — Fleet page no longer default; synthetic devices explicitly labelled everywhere

User (correctly) rejected the Fleet page as-is: it renders ARGUS's own
synthetic-testbed devices (smart-plug-00, ip-camera-00, etc. --
argus.sim.engine.default_fleet(), 11 hardcoded devices) as the default
landing page with zero labelling distinguishing them from the CICIoT2023
evaluation, which has no device identity at all. Inspected before changing
anything (per the user's explicit instruction): confirmed via grep and
direct code reading that no CICIoT2023 row is or was ever mapped to any of
these 11 device IDs -- run_cicioT2023_evaluation uses a wholly separate
device_id namespace (`cicioT2023-eval-<row_index>`) and never writes a
DeviceRow at all. The bug was presentational, not a data-fabrication bug,
but presentational-enough to reasonably read as a fabrication from the
Fleet page alone.

Fixed by making the honesty explicit at every layer rather than just the
frontend's own copy, per "if the data does not contain it, ARGUS must not
pretend it exists" applied literally:
- `/api/devices` (both api/index.py's production snapshot and
  argus/api/main.py's local dev path) now tags every object with
  `"source": "synthetic-demo-testbed"` / `"argus-testbed"` -- an honest
  claim visible to *any* consumer of the API, not just this project's own
  console.
- Console: default route `/` changed from Fleet to IDS Evaluation (the
  real, dataset-derived experience); Fleet moved to `/fleet`, renamed
  "Demo Fleet (Synthetic)" in the nav, and given an unmissable banner
  explaining it's ARGUS's simulation testbed, not CICIoT2023-derived, with
  a link to IDS Evaluation.
- IDS Evaluation page now states, verbatim, in the dataset panel: "Device
  identity is not available in this benchmark export."
- Control page's "Demo data" section now says explicitly that it seeds the
  synthetic testbed, unrelated to the CICIoT2023 evaluation.

Deliberately NOT touched: `argus/sim/engine.py`, `run_demo_pipeline`,
`api/seed_snapshot.json`, or any of the synthetic-testbed pipeline code --
that is a real, working, honestly-documented part of the project (the
"two parallel data sources" architecture stated in README.md/STATUS.md),
not a fabrication, and removing it was never what was asked; only its
unlabelled presentation as the production-facing default was the problem.
`/api/incidents` still legitimately mixes real CICIoT2023 incidents with
synthetic-scenario ones (1020 vs 8 in the current snapshot) -- left as-is,
since each incident's own `scenario` field already truthfully names its
origin (`cicioT2023_eval` vs `mirai`/`mqtt_abuse`/etc.) and nothing there
claims a synthetic incident is dataset-derived or vice versa.

## 2026-09-18 — live-network detector kept structurally separate from CalibratedDetector

`argus.detect.ml.CalibratedDetector`'s isotonic calibration and conformal
prediction gate both require labelled calibration data -- some feature-vector
windows known-benign, some known-attack -- to fit. No such labels exist for real
LAN traffic: nothing tells a passive sensor which of a user's own real devices,
if any, were ever compromised, and no ground-truth ledger exists to check
against. Fabricating labels to force-fit that class would be exactly the kind of
invented ground truth CLAUDE.md's no-fabrication rule (`no fabricated results`,
`metadata-only features`) forbids.

Decision: built a genuinely separate `sensor.live_detect.LiveAnomalyDetector` --
an unsupervised `IsolationForest` fit on a device's own historical baseline
windows, scored by percentile rank against that same baseline's own score
distribution. Its output is explicitly "how unusual relative to this device's
own history," never a calibrated probability, and every `Detection` it emits
carries `conformal_set=None` so nothing downstream can mistake it for the
calibrated/conformal-backed benchmark track's output. Same 14-feature schema
(`argus.detect.ml.FEATURE_KEYS`, unmodified) so the rest of the pipeline
(correlate/risk/respond/evidence) needs no adaptation -- only the model and its
scoring logic differ, because only the calibration inputs differ.

## 2026-09-18 — MIN_BASELINE_WINDOWS raised from 4 to 20 (measured, not guessed)

`LiveAnomalyDetector.fit()`'s original floor was 4 samples -- `IsolationForest`'s
bare minimum to not raise on `.fit()`. Real end-to-end testing (see progress.md's
same-dated entry for the full sequence) showed this floor is not just weak but
*degenerate*: fit on 4 near-identical real captured windows, the model scored
every input identically, including its own training data, regardless of how
different a later window actually was. A model that cannot distinguish itself
from an obvious outlier is not a conservative detector, it's a non-functional
one -- worse than having none, because it looks like real detection coverage
exists when it structurally cannot fire.

Root-caused with a synthetic unit test isolating sample count from traffic
shape: scores stayed flat through n=4-8, started meaningfully varying by n=10,
were usefully spread by n=20-40. Chose 20 as the new floor -- enough to be
reliably non-degenerate in testing, not tuned to any specific attack shape (no
labelled live-attack data exists to tune against, consistent with the decision
above). Recorded explicitly in `live_detect.py` as measured-not-guessed and
"subject to revision once real longitudinal deployment data exists," per
CLAUDE.md's rule that a number must come from a recorded run or be `TBD`.

Practical cost, stated plainly: with the default `--window-seconds 60`, a
device needs ~20 minutes of continuous observation before its first anomaly
score is even possible. Accepted as the correct trade-off -- fitting a model
that can't tell anything apart is not a smaller cost, it's zero benefit at any
speed.

## 2026-09-18 — no enforcement and no post-response verification for live-network incidents (structural, not missing)

Two things `_process_live_detection` (both `argus/pipeline.py`'s local-DB
version and `api/index.py`'s in-memory production version) deliberately never
does, hardcoded rather than left as a flag:

- **`enforce_enabled=False`**, always, regardless of `ARGUS_ENFORCE`. The
  project's safety requirement is explicit: no destructive actions against real
  discovered devices. No enforcement adapter for a real device exists at all --
  there is nothing an operator could set a flag to enable.
- **`verify()` is not called.** Post-response verification checks a simulated or
  testbed environment's actual recovered state against a ground-truth ledger of
  attack phases. A real device discovered by passive ARP observation has no such
  ledger and no environment this process controls to check. Calling `verify()`
  anyway and reporting *some* outcome would be fabricating a result CLAUDE.md's
  "no fabricated results" rule forbids just as much as a fake number would.

Both are documented in the functions' own docstrings and in docs/18 section 2,
not just here -- the goal is that reading the code alone tells the same story as
this decision log.
