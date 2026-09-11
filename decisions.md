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
