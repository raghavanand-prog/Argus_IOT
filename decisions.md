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
