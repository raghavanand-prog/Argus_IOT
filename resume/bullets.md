# Resume material

Rule (unchanged from the original plan, and from CLAUDE.md rule 4): no bullet goes
on an actual resume until the number in it exists in a `results/` file from a run
you can reproduce. Every number below traces to a run described in
`research/experiment-plan.md`, commit `39ddb4a1` or later. Nothing here is a
projection or a hoped-for result.

## Project entry

**ARGUS — Closed-Loop IoT Intrusion Detection and Autonomous Response**
Independent engineering project · Python, FastAPI, SQLAlchemy, React/TypeScript,
scikit-learn, SHAP, pyroute2, nftables · [repo link]

## Bullets, strongest first

- Built a closed-loop IoT intrusion detection and response system — detect →
  correlate → assess risk → explain → decide → enforce → verify — and measured
  the field's actual blind spot directly: an ablated configuration with detection
  metrics *identical* to the full system by construction showed 0% containment
  versus the full system's 100% (5/5 seeds), demonstrating that classification
  accuracy alone cannot distinguish a system that acts from one that doesn't.
- When the planned containerised testbed turned out to be infeasible in the build
  environment (outbound image-registry access blocked), designed and built a real
  alternative from first principles: genuine Linux network namespaces and veth
  pairs carrying actual packets, captured with a custom multi-interface `scapy`
  sniffer, feeding the exact same detection pipeline unchanged — verified the
  architecture's own data-flow-contract design by swapping the traffic source
  under it with zero downstream code changes.
- Implemented real network enforcement with `nftables`, working around a
  non-obvious kernel networking interaction (Docker's iptables-nft `FORWARD` drop
  policy silently absorbing unrelated bridge traffic via `bridge-nf-call-iptables`)
  and verifying every enforcement tier against actual socket connections — a
  connection that provably fails during isolation and provably succeeds again
  after either a targeted revert or a kill-switch-style full flush.
- Designed an evidence-bound alert format: every autonomous decision is bound to a
  hash-chained bundle (feature vector, model identity, calibration state, decision
  trace, SHAP attribution) and is replayable — measured decision reproducibility
  at 100% (19/19 bundles) on a seeded run, and used that replay mechanism to find
  and fix a genuine non-determinism bug (a rate limiter keyed to wall-clock time
  instead of simulated event time) within the first hour of the mechanism
  existing.
- Gated autonomous escalation on a from-scratch inductive conformal prediction
  wrapper rather than a raw confidence threshold, giving a distribution-free bound
  on the error rate of unattended actions; verified empirical coverage against
  held-out data rather than assuming the implementation was correct.
- Built a 9-configuration ablation harness (`eval/ablation.py`) with real
  Mann-Whitney U / Holm-Bonferroni-corrected statistics and Cliff's delta effect
  sizes, run against a genuine benign holdout so precision/recall reflect real
  false-positive/negative behaviour rather than a trivial 1.0.
- Shipped a full React/TypeScript analyst console with a live-working "replay this
  decision" button against the real backend, and a real accessibility pass
  (keyboard-operable incident list, a real ARIA dialog with focus management and
  Escape-to-close, `aria-live` status regions) — verified with browser automation,
  not just code review.

## Skills this evidences

| Area | Evidence |
|---|---|
| Network security | Linux network namespaces, veth/bridge networking, `nftables` (bridge-family filtering), `scapy`-based capture and flow reconstruction |
| Detection engineering | Rule authoring, per-device behavioural baselining, correlation, conformal-gated ML detection |
| ML for security | Calibration, conformal prediction implemented from scratch, TreeSHAP attribution, honest evaluation against a real holdout |
| Systems engineering | FastAPI, SQLAlchemy, structured evidence schemas, a full-stack React console |
| Security architecture | Threat modelling, safety-guard design (kill switch, rollback, rate limiting — each tested by actually using it), enforcement adapter design |
| Debugging under real infrastructure constraints | Diagnosed and fixed two genuine kernel-networking interactions (bridge-netfilter/Docker FORWARD policy; a wall-clock-vs-simulated-time race) that only surfaced when the "real" path was actually exercised, not assumed to work |
| Research method | Non-parametric statistics, effect-size reporting under limited seed count, honest scope documentation when a planned approach (dataset download, Docker containers) turned out to be environmentally infeasible |

## Cover-letter paragraph

I built ARGUS to test a specific claim: that IoT intrusion detection research
measures the wrong thing, reporting classification accuracy while almost never
measuring whether a system actually contains an attack. Partway through, the
infrastructure I'd planned to use — a Docker-based testbed — turned out to be
blocked by the build environment's network policy, so I built a real alternative
instead: genuine Linux network namespaces carrying real packets, with real
`nftables` enforcement, rather than falling back to a purely synthetic simulation.
The result I care about most is a single measured comparison: a version of the
system with detection metrics identical to the full one, by construction, showed
zero successful containments against the full system's 100%. That's the whole
argument, measured rather than asserted.

## LinkedIn / GitHub README opening

Most IoT intrusion detection systems tell you something is wrong. ARGUS decides
what to do about it, does it on a real (if small) network, proves afterward why it
did it, and measures whether it actually worked — with an evidence trail you can
replay yourself.
