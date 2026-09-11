# 04b — The real network testbed (`argus/testbed/`)

This supersedes part of `STATUS.md`'s original "biggest scope reduction" note: a
real, packet-level testbed now exists alongside the synthetic simulation engine
(`argus/sim/`), built to work inside this specific sandboxed environment's actual
constraints rather than the original plan's assumed ones.

## Why not the original plan's Docker testbed

The original design is 12 Docker containers on an isolated bridge with real capture.
Verified in this environment: `dockerd` runs and a bridge/NAT setup works, but
**every image pull is blocked** — Docker Hub's CDN (`production.cloudfront.docker.com`)
returns 403 through this sandbox's outbound proxy, which allowlists only package
registries (pypi, npm, crates, Go modules) and a few first-party hosts, not general
container registries or arbitrary websites. `FROM python:3.11-slim` cannot complete
here. This isn't a guess — it was tested directly (see `decisions.md`).

## What's here instead: real Linux network namespaces

Each simulated device gets its own network namespace and a veth pair into a shared
Linux bridge (`argus-br0`), all confined to `10.10.0.0/24`, built via `pyroute2`
(pure-Python netlink, installable from PyPI — which *is* reachable). No image pull
is needed: a network namespace is a kernel feature, not a container.

This gives the same isolation property Docker networking would (each "device" has
its own network stack, can't see another device's sockets or files, is reachable
only through the shared bridge) and, arguably, is *more* real than a container-based
testbed would have been: these are genuine, separate kernel network stacks passing
genuine Ethernet frames, not container network namespaces Docker itself would have
set up the same way under the hood anyway.

**Containment**, per CLAUDE.md rule 3, is structural, not just a runtime check: a
device namespace has exactly one interface and no default route, so nothing outside
`10.10.0.0/24` is reachable *at all* — there's no IP forwarding toward the host's
real interface anywhere in this design. `argus/testbed/live_attacks.py` additionally
enforces an unconditional code-level check (`assert_in_testbed`) before every attack
socket operation, so containment doesn't rely on the network topology alone.

## What "real" means and doesn't mean here

- Real: actual TCP/UDP sockets, actual Ethernet frames crossing an actual Linux
  bridge, an actual `scapy`-captured pcap file you can open in Wireshark, actual
  `nft` rules that actually block an actual socket connection (verified by
  connecting before, during, and after — see `tests/test_nftables_adapter.py`).
- Not real: full protocol semantics. There is no real MQTT broker, no real TLS
  handshake. Traffic is *metadata-realistic* — real packets with realistic sizes,
  timing, ports, and destinations shaped by the same per-device behaviour profiles
  the synthetic engine samples from — but payload content is filler bytes. This
  happens to cost nothing, because ARGUS's own design commitment (`docs/02`) is
  metadata-only feature extraction: no feature ARGUS computes would change if the
  payload were a real MQTT PUBLISH instead of filler.

## Why capture doesn't need port mirroring

A Linux bridge is a real L2 switch: unicast traffic between two ports is forwarded
directly and won't appear on a third "mirror" interface without `tc` (not
installable here — see below). But every packet a device sends or receives
necessarily crosses *that device's own* bridge port. `argus/testbed/capture.py`
sniffs every device's own root-side veth simultaneously, which gives full
visibility into every flow — including intra-LAN traffic between two devices — with
no mirroring trick needed at all.

## The bridge-netfilter gotcha (and why it's not a workaround)

Docker's iptables-nft ruleset sets `FORWARD` to `policy drop`. With
`bridge-nf-call-iptables=1` (the kernel default when Docker is running), *any*
L2-bridged traffic — including ours, on a bridge Docker has nothing to do with —
gets funneled through that drop policy and silently disappears. `fabric.py` disables
`bridge-nf-call-iptables`/`ip6tables`, which makes bridged traffic bypass the host's
`inet`/`ip`-family netfilter hooks entirely.

That has a direct consequence for enforcement: those same `inet`/`ip` hooks are what
a naive `nft add chain inet argus forward {...}` would attach to — and with the
sysctl disabled, such a chain would never see this traffic either. The real fix,
used in `argus/respond/adapters/nft_adapter.py`, is nftables' **bridge family**
(`nft add table bridge argus`), which filters at the bridging layer directly,
independent of that sysctl. This is the documented, correct way to filter bridged
L2 traffic — not a workaround for the workaround.

## Why rate-limiting uses `nft limit rate over ... drop`, not `tc`

`tc`/iproute2's CLI is not installed in this environment and can't be installed (no
apt/package-mirror access). nftables has its own native rate limiter, which drops
packets exceeding a threshold — a real, verifiable substitute, though it drops
rather than queues/delays traffic the way `tc` HTB shaping would. Stated as a scope
difference from the original design, not hidden.

## Scope, honestly

- Only the two "never cut" scenarios (`mirai`, `low_and_slow`) run on the live path;
  the other five exist as synthetic-only generators (`argus/sim/attacks.py`).
- The device fleet is five representative types plus a hub and a C2 stand-in, not
  the full twelve — chosen to keep run time and flakiness bounded while still
  exercising fleet correlation (two smart-plugs) and cross-device attack chains.
- `argus/testbed/` requires Linux + root/CAP_NET_ADMIN and the `live-testbed` extra
  (`pip install -e ".[live-testbed]"`). It's optional — `argus/sim/` and everything
  downstream of it works without any of this, and `argus/pipeline.py` exposes both
  `run_demo_pipeline` (synthetic) and `run_live_demo_pipeline` (real) as peers.
- Enforcement via `NftablesAdapter`/`LiveNftablesAdapter` is real and tested, but is
  never wired in as the default adapter anywhere — `run_live_demo_pipeline` still
  uses `DryRunAdapter` by default, per CLAUDE.md rule 2. Driving real enforcement
  requires deliberately constructing `LiveNftablesAdapter` yourself, exactly as
  deliberate as flipping `ARGUS_ENFORCE=true`.

## What this proves that the synthetic engine alone couldn't

`argus/testbed/pcap_to_flows.py` produces the exact same `FlowRecord` schema
`argus/sim/engine.py` does, and every downstream stage — feature extraction,
enrollment, detection, correlation, risk, evidence, response, verification — runs
against it completely unchanged (`tests/test_live_testbed.py::
test_real_captured_flows_feed_the_existing_feature_extractor_unchanged`,
`run_live_demo_pipeline` in `argus/pipeline.py`). That's docs/01's data-flow-contract
design working exactly as intended: swapping the source of truth from a generator to
an actual network required touching nothing between collection and response.
