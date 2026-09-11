# 00 — Problem statement & threat model

## The operational problem

Small IoT networks (home, clinic, shop, lab — 5-50 devices) have no analyst, no SIEM, no
budget. A device compromise is effectively permanent: it keeps working while scanning,
beaconing, or joining a botnet, because nothing is watching and nothing would act even
if it were.

## Why "deploy an IDS" doesn't fix it

Per the most recent systematic gap analysis (Sallam, El Barachi & Li, 2026, *IoT* 7(1):16):
29 of 32 reviewed IoT IDS studies were evaluated solely offline, none were tested under
realistic multi-node conditions, and mitigation capability was "often absent" — detection
without action. A second 2026 review (Varol & Karakaya, *Sensors* 26(18):5744) found
explainable-IDS models collapsing from ~99% F1 to ~39% cross-dataset, with explanation
quality rarely validated by anyone.

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

Additional scenarios from the original plan (MQTT abuse, ARP spoofing, DNS tunnelling,
identity spoofing, OTA spoofing) are documented but deprioritised per `BUILD-ORDER.md`'s
cut list — they are the first thing to add back once the two above are solid.

## What the defender can and cannot see

Can see: L2/L3 headers, flow timing/volume, DNS queries, TLS handshake metadata (SNI,
JA4/JA3-style fingerprints), protocol identification. Cannot see: TLS payloads. This is
the central constraint — see `MASTER-PLAN.md`'s metadata-only commitment.
