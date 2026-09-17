# 00 — Problem statement & threat model

## The operational problem

Small IoT networks (home, clinic, shop, lab — 5-50 devices) have no analyst, no SIEM, no
budget. A device compromise is effectively permanent: it keeps working while scanning,
beaconing, or joining a botnet, because nothing is watching and nothing would act even
if it were.

## Why "deploy an IDS" doesn't fix it

Per the most recent systematic gap analysis (Sallam, El Barachi & Li, "Intrusion Detection
on the Internet of Things: A Comprehensive Review and Gap Analysis Toward Real-Time,
Lightweight, Adaptive, and Autonomous Security," *IoT*, vol. 7, no. 1, art. 16, 2026,
doi:10.3390/iot7010016): 29 of 32 reviewed IoT IDS studies were evaluated solely offline,
none were tested under realistic multi-node conditions, scalability was untested under
realistic multi-node/high-traffic conditions in every reviewed system, and mitigation
capability was "often absent" — detection without action.

*(Correction: an earlier version of this document also cited a specific "~99% F1 to ~39%
cross-dataset" figure attributed to "Varol & Karakaya, Sensors 26(18):5744." That citation
was wrong on inspection — the actual authors of Sensors 26(18):5744 are Ogunseyi,
Thiyagarajan, He, Bist, and Du, and the specific figure could not be verified as belonging
to that paper. Removed rather than left uncorrected, per CLAUDE.md rule 4: no fabricated
numbers, no matter how minor.)*

## The falsifiable question

*On a network with no human operator, can an automated system detect a compromised IoT
device, decide whether to act, act on the real network, prove afterwards why it acted,
and not break the network's legitimate function — and by what measure would we know?*

## Hypotheses

- **H1** — classification F1 is a weak predictor of containment outcome.
- **H2** — components that don't move F1 (correlator, risk engine, drift monitor) move
  containment metrics (time-to-contain, false-isolation rate).
- **H3** — binding every action to a hash-linked evidence bundle makes the decision
  reproducible at a measurable rate.

## Threat model (condensed)

- **Adversary:** remote attacker who gains a foothold on one LAN device; can scan,
  brute-force, run code on that device, spoof L2 identity, talk to external
  infrastructure over TLS. Assumed *not* to have ARGUS's model weights or baselines.
- **Trust boundary:** Internet (untrusted) → Gateway (assumed uncompromised, a stated
  assumption) → IoT network (untrusted, any device may be compromised at any time) →
  ARGUS (trusted computing base — if this falls, everything falls).
- **Out of scope:** physical access, radio-layer attacks, firmware supply chain, cloud
  account compromise, a fully adaptive attacker who observes and counters ARGUS live.

## Attack scenarios implemented (see `argus/sim/attacks.py`)

1. **Mirai-style recruitment** — scan → credential brute force → C2 registration →
   DDoS participation. Easy: fan-out, new ports, sustained egress.
2. **Low-and-slow beaconing** — encrypted C2 at long jittered intervals, small payloads,
   indistinguishable per-flow from telemetry. Hard by design — this is the case that
   keeps the evaluation honest; if a stock detector catches it trivially, the simulated
   traffic is too easy and the testbed needs to be redesigned before anything downstream
   is trusted (this is a stated kill criterion — see `MASTER-PLAN.md` §7).

3. **MQTT topic enumeration + unauthorised publish** — broker interaction outside the
   device's declared policy. Easy-moderate; zero-model detection via the policy rule.
4. **ARP spoofing / lateral movement** — a burst of unusual intra-LAN traffic to a
   device never contacted before, following a simulated poisoning window.
5. **DNS-tunnelled C2** — high query-name character entropy and volume to the
   resolver, exposing the DNS feature group (`dns_qname_entropy_mean`).
6. **Device identity spoofing** — a TLS fingerprint (JA4) never seen during the
   device's enrollment baseline. Hard: volume/timing look normal; only the
   fingerprint mismatch gives it away (`argus/detect/rules.py::identity_detections`).
7. **OTA update spoofing** — a firmware fetch from an endpoint outside the device's
   declared policy. Same detection mechanism as scenario 3, different attack phase.

All seven now run in `argus/sim/attacks.py` and are exercised end to end by
`run_demo_pipeline` (`argus/pipeline.py`), each against a distinct device from the
default fleet. Only scenarios 1 and 2 run on the real network-namespace testbed path
(`argus/testbed/`, see `docs/04b`) — the other five are synthetic-only; see
`STATUS.md` for the honest reasoning behind that split.

## What the defender can and cannot see

Can see: L2/L3 headers, flow timing/volume, DNS queries, TLS handshake metadata (SNI,
JA4/JA3-style fingerprints), protocol identification. Cannot see: TLS payloads. This is
the central constraint — see `MASTER-PLAN.md`'s metadata-only commitment.
