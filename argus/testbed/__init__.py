"""The real network testbed: Linux network namespaces + veth pairs + a bridge,
carrying real packets, captured with a real packet sniffer, enforced with real
nftables rules. See docs/04b-live-testbed.md for why this exists alongside
argus/sim/ (the synthetic engine) rather than instead of it, and for the containment
guarantees that keep every packet inside 10.10.0.0/24 and off the host's real network.

Everything in this package requires Linux + root/CAP_NET_ADMIN and the
``live-testbed`` extra (``pip install -e ".[live-testbed]"``). It is optional:
argus/sim/ and everything downstream of it works without this package at all.
"""
