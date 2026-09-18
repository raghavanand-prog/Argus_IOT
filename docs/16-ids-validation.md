# 16 — IDS validation: end-to-end test procedure and real results

This document is the record of an actual validation run, executed once, locally, on
2026-09-18, at a fixed seed (42) so anyone can reproduce it exactly. Every number in
the test matrix below comes from that run — see `eval/ids_validation_1_4.json` and
this document's own "how to reproduce" section. Per CLAUDE.md rule 1/4, nothing here
is asserted without having been run, and nothing was tuned after the fact to make a
result look better.

## Architecture: how telemetry actually enters ARGUS (read this before running anything)

There is **no HTTP ingestion endpoint** that a device or agent POSTs events to. ARGUS's
synthetic pipeline generates flow-level telemetry and runs detection on it **in the same
process, in the same function call** — `argus.pipeline.run_demo_pipeline()` (what the
Control screen's "Run demo pipeline" button and the local API's
`POST /control/seed-demo` both call) does enrollment, detector training, attack-scenario
generation, and the full detect → correlate → risk → decide → evidence → persist →
verify chain in one call. "Telemetry reaches the backend" is therefore true *by
construction* for every test below that uses this path — there is no separate network
hop to fail.

The **production Vercel deployment does not run this pipeline live** — this is a
deliberate, documented architecture decision (`docs/06-vercel-deployment.md`), not an
oversight: no root/CAP_NET_ADMIN for the live-testbed path, no persistent filesystem
across invocations, and numpy/scikit-learn/shap don't fit the serverless function size
budget. Production serves a static, real, pre-computed snapshot instead. This has a
direct, unavoidable consequence for this validation:

| Capability | Local (`make api` + `make console`, or this doc's scripts) | Production (`https://argus-iot.vercel.app`) |
|---|---|---|
| Generate fresh telemetry / run detection | **Yes, real** | No — static snapshot only |
| Fleet / Incidents data | Whatever you seed locally | The one real run baked into the deployment |
| Kill switch toggle | Real, and **gates new pipeline runs** | Real state change, but nothing live to gate |
| Evidence replay | Real | **Real** — identical code path |

**Tests 1–5 below therefore had to be executed locally** — there is no way to generate
new telemetry from a phone against the deployed site, by design. Test 6 (replay) is
real and live on both. The "PHONE DEMO PROCEDURE" section at the end is explicit about
which of its steps are live-production and which are inspecting results from this
local run.

## What was missing, and what was added to make Tests 1 and 4 executable at all

Before this validation, there was no code path that ran the real detectors
(`policy_detections`, `signature_detections`, `ml_detections`, `identity_detections`)
against **pure benign traffic** and reported what fired — every existing entrypoint
(`run_demo_pipeline`) always mixes in all 7 attack scenarios. Without this, "confirm
normal activity does not generate false incidents" was not a test that could be run at
all, just asserted.

Added, reusing the exact same detector/training code (not a parallel implementation):

- `argus.pipeline._enroll_and_train()` — the enrollment + detector-training logic,
  extracted out of `run_demo_pipeline` into a function both it and the new validation
  path call, so a benign-only test run exercises the identical trained detector a real
  demo run would.
- `argus.pipeline.run_benign_validation()` — enrolls and trains as above, then runs a
  **fresh, held-out** benign window per device (different RNG seed and time offset than
  training/calibration) through the same four detectors, with zero attack traffic
  mixed in. Any raw detection is then run through the same `correlate` → `assess_risk`
  → `tier_for_risk` path the real pipeline uses (read-only — no `decide_and_respond`
  call, no evidence bundle, no DB write) so the report can distinguish a low-confidence
  flag from one with a singleton `{"attack"}` conformal set that could actually have
  reached an enforcement tier.
- `POST /control/validate-benign` on the local dev API (`argus/api/main.py`), mirroring
  `/control/seed-demo`'s pattern, for anyone who wants to trigger this from the Control
  screen / curl rather than the script.
- `tests/test_ids_validation.py` — locks in the exact counts below as a regression
  test, per CLAUDE.md's determinism rule.

No change was made to `run_demo_pipeline`'s own behavior, the detectors, the risk
engine, or the response ladder — confirmed by the full existing test suite (46/46,
unchanged in count from before this session's 45, plus the one new test) still passing
after this addition.

## Test matrix — actual results, 2026-09-18, seed=42

| ID | Test | Input/Event | Expected IDS Behaviour | Actual Result | Incident? | Severity | Evidence? | Pass/Fail |
|---|---|---|---|---|---|---|---|---|
| 1 | Baseline / normal traffic | Fresh held-out benign window, all 11 fleet devices (~198 windows total) | 0 detections, 0 incidents | **75 raw ML detections** across 8/11 devices (smart-tv-00, hub-00, user-laptop-00 stayed clean); 40 of the 75 carried a singleton `{"attack"}` conformal set and would have reached tier ≥2 (`rate_limit` or higher) had this been live | 0 (read-only test; see root cause below) | would-be risk 0.54–0.68 | N/A (read-only by design) | **FAIL** |
| 2 | Suspicious activity | `mqtt_abuse` scenario, `smart-lock-00`, via the real `run_demo_pipeline` (same function "Run demo pipeline" calls) | Detected via policy + ML, correlated, moderate risk, `block_destination` | Detected via `policy` + `ml`; risk **0.80**; action **block_destination**, tier 3; `verification_outcome: contained` | Yes | 0.80 | Yes (bundle + hash chain) | **PASS** |
| 3 | High-severity attack simulation | `mirai` scenario, `smart-plug-00` (scan → bruteforce → C2 → DDoS), same mechanism as Test 2 | Highest severity in the scenario set, `isolate` | Detected via `policy`+`ml`+`rules`; risk **0.86** (highest of all 7 scenarios this run); action **isolate**, tier 4; `verification_outcome: contained` | Yes | 0.86 | Yes | **PASS** |
| 4 | False-positive stress test | Fresh benign traffic, `smart-speaker-00` specifically — the one device whose real attack scenario (`low_and_slow`) is deliberately shaped to resemble its own normal beacon | 0 detections | **2 detections**, both singleton `{"attack"}`, would-be tier 2 (`rate_limit`) | 0 (read-only) | would-be 0.58 | N/A | **FAIL** |
| 5 | Incident response (kill switch) | `POST /control/kill-switch?engage=true` (authenticated) → re-run `/control/seed-demo` | Unauthenticated request rejected; new incidents' actions vetoed while engaged; veto recorded in evidence | Unauth request → **401**. Pre-engagement run: 19 actions (incl. `isolate` for mirai). Post-engagement run: 19 *new* incidents/bundles, **0 actions**. The mirai incident's evidence bundle: `decision.action: "observe"`, `tier: 0`, trace `guard_verdict=veto`, `gates_failed: ["kill_switch_disengaged"]` — confirmed in the UI (`Gates failed: kill_switch_disengaged`) | Yes (both) | n/a | Yes, veto is recorded in the bundle | **PASS** |
| 6 | Replay / evidence validation | `POST /evidence/{mqtt_abuse bundle_id}/replay` (authenticated) | Unauthenticated rejected; replay reproduces original decision; original bundle unaltered | Unauth → **401**. Replay: `reproduced: true`, original `block_destination` (tier 3) = replayed `block_destination` (tier 3). Re-fetched original bundle afterward: `merkle_root` and `decision` unchanged | Yes (existing) | 0.80 | Yes, both original and replay shown | **PASS** |

**4 of 6 pass. 2 of 6 fail — reported exactly as measured, not adjusted.**

## Root cause of the Test 1 / Test 4 failures (read before treating this as "the IDS is broken")

The `CalibratedDetector` (Isolation Forest + isotonic calibration, `argus/detect/ml.py`)
is trained on a **single ~4-hour synthetic benign window, one RNG seed**
(`run_demo_pipeline`'s `train_flows`). Investigated directly rather than assumed: I
re-ran the same held-out check at the detector's *own* training window size (120s) as
well as the 300s window the real attack-detection path uses — false positives persisted
at both (142 flagged windows at 120s, 75 at 300s, out of the same fleet) — so this is
**not** a window-size artifact in the validation script. It is a genuine generalization
gap: an unsupervised model trained on one narrow slice of synthetic benign traffic
does not reliably recognize a *different* slice of equally-legitimate benign traffic as
normal. This is consistent with the project's own stated non-goal (`argus/detect/ml.py`:
"Deliberately simple models, on purpose... not a SOTA classifier") — but this validation
is the first time it's been directly measured against genuinely held-out data rather
than the calibration split the conformal coverage numbers elsewhere in this project are
computed against.

**Why this wasn't silently "fixed" to force a pass:** the fix that would most directly
address it — training on a broader, multi-seed benign corpus — is a real methodology
change, not a bug fix, and applying it using knowledge of this exact test's seed would
risk tuning the model to pass this specific check rather than genuinely improving
generalization. That's the opposite of what a validation exercise is for. Recorded as
a real, open finding, with the concrete fix identified but not applied — see
`decisions.md`'s entry for this test run.

**What this does and doesn't mean for the shipped system:** every real attack-scenario
detection in Tests 2/3 (and the whole existing evidence-replay/ablation evidence base)
remains genuinely correct — those are true positives against real attack-shaped
traffic, unaffected by this finding. What this finding adds is: on traffic the detector
hasn't specifically been calibrated against, a meaningful fraction of purely benign
activity would currently be flagged, and roughly half of that fraction has high enough
confidence to reach an actual enforcement tier. The response ladder's conformal-gate
design (`tier_for_risk` requiring a singleton set to reach tier ≥2) is doing real work —
it didn't zero out the false-escalation risk here, but it is the only reason this
finding is "40 detections could have escalated" rather than "75 detections could have
escalated."

## How to reproduce this exact run

```bash
source .venv/bin/activate   # or: .venv/bin/python directly
python scripts/validate_ids.py          # Tests 1-4, writes eval/ids_validation_1_4.json
pytest tests/test_ids_validation.py -v  # locks in the same counts as a regression test
```

Tests 5 and 6 were run against a live local server (not scripted into one file, since
they exercise the real HTTP/auth layer):

```bash
cp .env.example .env   # set your own ARGUS_ADMIN_TOKEN -- never reuse a production one
make api      # terminal 1
make console  # terminal 2
```

Then, with `$TOKEN` set to your own `.env`'s `ARGUS_ADMIN_TOKEN`:

```bash
curl -X POST localhost:8000/control/seed-demo -H "Authorization: Bearer $TOKEN"
curl -X POST "localhost:8000/control/kill-switch?engage=true" -H "Authorization: Bearer $TOKEN"
curl -X POST localhost:8000/control/seed-demo -H "Authorization: Bearer $TOKEN"   # compare actions: N here to the first call
curl -X POST "localhost:8000/control/kill-switch?engage=false" -H "Authorization: Bearer $TOKEN"
curl localhost:8000/incidents -H "Authorization: Bearer $TOKEN"   # find a bundle_id
curl -X POST localhost:8000/evidence/<bundle_id>/replay -H "Authorization: Bearer $TOKEN"
```

## DEMO PROCEDURE

Two separate procedures, because the architecture genuinely separates them (see the
table above) — presenting them as one continuous phone-only flow would misrepresent
what the deployed site can actually do.

### A. Full lifecycle (local machine — this is the one that exercises TELEMETRY → DETECTION → CLASSIFICATION)

1. On your computer: `make api` (terminal 1), `make console` (terminal 2).
2. Open `http://localhost:5173/control` in a browser, paste your local `.env`'s
   `ARGUS_ADMIN_TOKEN`, click **Save**.
3. Click **Run demo pipeline**. This is the real TELEMETRY step — it generates all 7
   attack scenarios' synthetic flows fresh, right now.
4. Observe: the button's own result line reports real counts (19 incidents / 19
   bundles / 19 actions).
5. Open **Incidents**. This is DETECTION → CLASSIFICATION → INCIDENT, visible per row
   (device, scenario, sources, risk score).
6. Click the `mirai` / `smart-plug-00` row. Verify the drawer shows risk breakdown,
   decision trace ending in `action=isolate`, and the SHAP attribution chart —
   TELEMETRY → ... → EVIDENCE, end to end, in one screen.
7. Go to **Control**, click **Engage** on the kill switch.
8. Go back to **Control**, click **Run demo pipeline** again.
9. Open **Incidents** again — find the *new* `mirai` row and open it. Verify the
   decision trace now ends `guard_verdict=veto`, `action=observe`, and shows
   **"Gates failed: kill_switch_disengaged."** This is RESPONSE, genuinely gated,
   not simulated.
10. Click **Disengage** on Control to restore normal state.
11. Back in Incidents, open the *original* (pre-engagement) `mqtt_abuse` row and click
    **Replay decision**. Verify **"✓ Reproduced identically"** — REPLAY / AUDIT.

### B. What's live from your phone, right now, against the real deployment

Production doesn't re-run the pipeline, so steps 3–4 and 7–9 above can't be repeated
from here — this walks through the same real data from procedure A's kind of run
(a snapshot from one earlier such run) plus two things that ARE live: replay and the
kill switch's own state.

1. Open `https://argus-iot.vercel.app` on your phone.
2. Tap **Fleet** — confirm real enrolled devices, no login needed.
3. Tap **Incidents** — confirm real incidents with real risk scores and scenario names.
4. Tap any row with a red/high risk badge (e.g. a `mirai` or `mqtt_abuse` row).
5. Verify the drawer shows a real decision trace, SHAP attribution, and an evidence
   bundle ID/hash.
6. Tap **Replay decision**. Verify **"✓ Reproduced identically"** appears with matching
   original/replayed action and tier — this is a real computation, run live, right now,
   on your phone, over your own network.
7. Tap **Control**. Paste your production `ARGUS_ADMIN_TOKEN`, tap **Save**.
8. Tap **Engage**, confirm the kill-switch badge changes to **"KILL SWITCH ENGAGED"**
   in the header — a real, authenticated state change.
9. Tap **Disengage** to restore it.

Step 8's honest caveat, stated plainly rather than implied: engaging the kill switch in
production changes real server state and is a genuine authenticated action, but there is
no live pipeline running in production for it to gate — the observable "it vetoes new
actions" effect from procedure A, step 9 is a local-only demonstration, by the
architecture's own design.

## Screenshots to capture for project/research-paper evidence

1. **Procedure A, step 3** — Control screen immediately after "Run demo pipeline,"
   showing the real seeded counts.
2. **Procedure A, step 6** — the `mirai`/`isolate` incident drawer: risk breakdown +
   decision trace + SHAP attribution together in one frame (this is the single most
   information-dense "the system really works" screenshot).
3. **Procedure A, step 9** — the *post-kill-switch* `mirai` incident drawer, specifically
   the **"Gates failed: kill_switch_disengaged"** line — this is the direct visual
   proof of Test 5's safety-gating result.
4. **Procedure A, step 11 / Procedure B, step 6** — the replay confirmation banner,
   "✓ Reproduced identically — original: X (tier N), replayed: X (tier N)."
5. **`eval/ids_validation_1_4.json`**, or a terminal screenshot of
   `python scripts/validate_ids.py`'s own stdout — the raw Test 1/4 numbers, unedited.
   Pairs with this document's root-cause section as the honest, harder half of the
   evidence: a validation that finds and reports a real gap is stronger evidence of
   rigor than an all-green dashboard.
6. **Procedure B, steps 2–3** — Fleet and Incidents loading on an actual phone screen,
   for the "universally accessible" claim specifically (STATUS.md's 2026-09-18 entry).
