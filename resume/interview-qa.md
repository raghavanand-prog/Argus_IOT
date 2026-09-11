# Interview preparation

Answers reflect the system as it actually exists (commit `39ddb4a1` and later), not
the original planning document. Where the two differ, that difference is usually
the most interesting part of the answer.

## Design

**1. Why not one model for the whole network?**
Normal for a smart TV and normal for an air-quality sensor share nothing. A single
model is either too loose to detect anything or too tight to alert constantly.
Per-device baselining (`argus/registry/enrollment.py`) makes the problem tractable
— and creates the enrollment-poisoning problem, which is why enrollment is bounded
and policy-guarded, and refuses outright if the device violates its own declared
policy during the learning window (tested directly, not just asserted).

**2. Why both rule-based and ML detection?**
Rules give precision and free explanations on known attacks; ML covers the
unknown. The correlator reconciles them, and I report their disagreement rather
than hiding it (`incident.agreement_score`).

**3. Why metadata-only features?**
Most IoT traffic is TLS. `argus/features/extract.py` never inspects a payload —
flow stats, timing, periodicity, DNS query-name entropy, TLS fingerprints. This
turned out to make the "real vs. synthetic" pivot (see Q9) nearly free: since no
feature depends on payload semantics, replacing full protocol implementations with
metadata-realistic filler traffic in the real network testbed cost nothing
downstream.

**4. Why conformal prediction instead of a probability threshold?**
A threshold on a calibrated probability is still an arbitrary line. Conformal
prediction gives a set with a distribution-free coverage guarantee: escalation
past `alert` requires a singleton set, bounding the error rate of unattended
actions. I wrote the inductive wrapper from scratch (~40 lines,
`argus/detect/ml.py`) rather than pulling in a library, specifically so I could
defend every line of it. The caveat I'd raise before you do: the guarantee
assumes exchangeability, which drift breaks — that's why the drift monitor gates
escalation independently rather than the conformal gate alone.

## Implementation

**5. Walk me through what happens from packet to enforcement.**
(Practice this against the real code path: `argus/testbed/pcap_to_flows.py` →
`argus/features/extract.py` → `argus/detect/{rules,ml}.py` →
`argus/correlate/correlator.py` → `argus/risk/engine.py` →
`argus/evidence/bundle.py` → `argus/respond/guard.py` →
`argus/respond/ladder.py` → `argus/respond/adapters/nft_adapter.py` →
`argus/verify/verification.py`. Name the schema at each boundary.)

**6. The plan called for a 12-container Docker testbed. What actually exists?**
Docker image pulls were blocked by the build environment's outbound proxy
(verified: 403 from Docker Hub's CDN — not assumed, tested directly). Rather than
fall back to pure synthetic simulation, I built a real alternative: Linux network
namespaces and veth pairs into a shared bridge, all inside `10.10.0.0/24`, using
`pyroute2` (pure-Python netlink — no image needed). Real sockets, real Ethernet
frames, a real `scapy`-captured pcap file. It's arguably more real than the
originally planned Docker network would have been, since it's genuinely separate
kernel network stacks rather than container networking Docker would have set up
the same way regardless.

**7. What's the hardest bug you hit building this?**
Two, both real infrastructure interactions I had to diagnose from first
principles. First: my bridge traffic was silently vanishing — Docker's
iptables-nft ruleset sets `FORWARD` to policy-drop, and `bridge-nf-call-iptables`
routes *any* bridged traffic through that hook, including a bridge Docker has
nothing to do with. Fixed by disabling that sysctl — which then meant my own
`nftables` enforcement rules needed to use the `bridge` table family instead of
`inet`/`ip`, since that same sysctl removes bridged traffic from those hooks too.
Second: the evidence-replay mechanism itself caught a real non-determinism bug —
my rate limiter used wall-clock time, so a pipeline that runs in under a second
covering several *simulated* hours looked like an implausible burst to a
real-time rate limit, and vetoed actions inconsistently between the original run
and replay. Fixed by threading simulated event time through instead. That's
exactly the class of bug the replay design exists to catch.

**8. How do you know the testbed isn't trivially easy?**
This is a currently-honest gap, not a solved problem: the original plan's
week-3 triviality check (a stock Isolation Forest against the hardest scenario)
hasn't been formally re-run against the current feature set. What I can say is
measured: the low-and-slow beaconing scenario produces a real, distinguishable
periodicity signature (`periodicity_score` in the feature vector) verified against
real captured packets, not just the synthetic generator.

**9. Why keep both a synthetic engine and a real network testbed?**
Speed and determinism for the synthetic path (the full 9-configuration × 5-seed
ablation runs in about 30 seconds), and authenticity for the real path. They
produce the identical `FlowRecord` schema, so every downstream stage — features
through response — runs unmodified against either. That's not an accident; it's
the point of the data-flow-contract design (`docs/01`).

## Evaluation — expect the most pressure here

**10. Your F1 is around 0.95–0.98. Is that good?**
It's not the point. The project's own non-goal list says explicitly it doesn't
aim to beat published F1. What's actually measured and reported is the *contrast*:
`A6_detection_only` has detection metrics identical to the full system, by
construction, and containment metrics of zero. That identity — not the absolute
F1 number — is the finding.

**11. Five seeds isn't much statistical power.**
Correct, and `eval/stats.py` is built around that fact: Cliff's delta effect
sizes are reported as primary, Holm-Bonferroni-corrected p-values as secondary,
and the harness doesn't claim significance it doesn't have.

**12. Did every ablation confirm your hypothesis?**
No, and I'd tell you that before you asked. A2 (no risk engine) and A4 (no drift
monitor) showed only small/negligible time-to-contain effects in the measured
run — not the "large effect" pattern A1, A3, and A6 showed. That's reported as a
real, mixed result in `research/experiment-plan.md`, not adjusted or omitted to
make the story cleaner.

**13. What's the biggest thing you didn't get to?**
The dataset track — training/testing against CICIoT2023 and the IoT-23
cross-dataset generalisation check. I verified directly that the build
environment's network policy blocks the actual dataset host (403, same failure
mode as Docker Hub), so this isn't a time trade-off I chose, it's an
environmental constraint I hit and documented (`docs/05`). The subsampling and
feature-parity logic is built and tested against a synthetic fixture, ready to run
the moment real data is reachable.

## Research

**14. What's the actual gap in the literature?**
No open, reproducible, packet-level environment closes the IoT
detect-and-respond loop on real traffic with real enforcement, and the field has
no accepted metric for response quality distinct from detection accuracy — this
project's C4 contribution (`A6` vs `A0`) is a direct, measured instance of that
gap.

**15. Is any of this genuinely novel?**
The honest ranking, unchanged from the original plan: the artifact and the
response-quality-metric argument are the strongest claims (nobody's measuring
this, and the gap papers say so in print). The evidence-binding/replay mechanism
is a moderate claim — the idea exists in digital forensics, applying it as a hard,
*measured* property of an autonomous decision is less common. Conformal prediction
as the escalation gate is the weakest claim — conformal prediction applied to
intrusion detection isn't new; using prediction-set size specifically as the gate
is a narrow, defensible design choice, not a methods contribution. If pushed on
it, I'd concede that directly.

## Career

**16. This is a detection/response project. You're targeting cloud security roles.**
Deliberately. Detection engineering, evidence handling, safety-gated automation,
and honest evaluation transfer directly to cloud detection-and-response work — the
substrate (IoT vs. cloud control-plane events) changes, the discipline doesn't.
The two real infrastructure bugs I hit and fixed (a kernel networking interaction,
a wall-clock-vs-event-time race) are the kind of thing that shows up in cloud
environments just as often as in this one.
