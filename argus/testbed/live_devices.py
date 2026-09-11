"""Real device traffic generators: each runs as its own OS process, joined to its
own network namespace, sending real UDP/TCP packets shaped by the same per-device
behaviour profile (`argus.sim.devices.FLEET`) the synthetic engine samples from.

Scope, stated plainly (see docs/04b-live-testbed.md): this sends *metadata-realistic*
traffic -- real packets with realistic sizes, timing, ports, and destinations -- not
a full MQTT broker or a real TLS handshake. That is a deliberate scope choice given
the time available, and it happens to align with ARGUS's own design commitment
(docs/02): every feature ARGUS extracts is metadata-only by design, so payload
semantics were never going to affect a single downstream measurement anyway.
"""

from __future__ import annotations

import logging
import random
import socket
import time

from pyroute2 import netns as pyroute2_netns

from argus.sim.devices import FLEET, diurnal_multiplier, sample_flow, sample_interval

logger = logging.getLogger(__name__)


def run_device(ns_name: str, device_id: str, device_type: str, peers: list[tuple[str, int]],
                duration_s: float, seed: int, start_hour: float = 9.0) -> None:
    """Entry point for a spawned child process. Joins ``ns_name`` first, then loops
    sending real packets to real peer sockets until ``duration_s`` elapses.
    ``peers``: concrete (ip, port) pairs this device is allowed to talk to, resolved
    by the orchestrator from the device type's declared policy (argus/registry/policy.py)
    against the live fabric -- so a live run enforces the exact same policy shape a
    synthetic run does."""
    pyroute2_netns.setns(ns_name)
    profile = FLEET[device_type]
    rng = random.Random(seed)
    deadline = time.monotonic() + duration_s
    sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sim_hour = start_hour
    while time.monotonic() < deadline:
        mult = diurnal_multiplier(sim_hour)
        wait = sample_interval(profile, rng) / max(mult, 0.15)
        wait = min(wait, 3.0)  # cap so a live demo run finishes in reasonable wall time
        time.sleep(wait)
        sim_hour = (sim_hour + wait / 3600) % 24

        if not peers:
            continue
        peer_ip, peer_port = rng.choice(peers)
        payload = sample_flow(profile, rng)
        body = os_urandom_like(max(payload["bytes_out"], 8))
        try:
            if payload["proto"] == "udp" or "coap" in profile.protocols or "mqtt" in profile.protocols:
                sock_udp.sendto(body, (peer_ip, peer_port))
            else:
                _tcp_burst(peer_ip, peer_port, body, payload["bytes_in"])
        except OSError as e:
            logger.debug("%s: send to %s:%s failed (%s) -- peer may not be listening yet", device_id, peer_ip, peer_port, e)

    sock_udp.close()


def _tcp_burst(ip: str, port: int, body: bytes, reply_len: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        s.connect((ip, port))
        s.sendall(body)
        try:
            s.recv(min(reply_len, 65536))
        except socket.timeout:
            pass


def os_urandom_like(n: int) -> bytes:
    """Realistic-sized filler payload. Not meaningful content -- ARGUS is
    metadata-only by design (docs/02) and never inspects it."""
    return bytes((i % 251) for i in range(min(n, 65000)))


def run_peer_listener(ns_name: str, ip: str, port: int, duration_s: float) -> None:
    """A trivial UDP+TCP echo-ish listener standing in for the hub/mock-cloud
    endpoint devices talk to -- so their TCP bursts get a real SYN/ACK/FIN sequence
    and their UDP sends land on an actual open socket instead of hitting a closed
    port (which would still be a real, capturable packet -- an ICMP port-unreachable
    -- but a duller one for the demo)."""
    pyroute2_netns.setns(ns_name)
    deadline = time.monotonic() + duration_s

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((ip, port))
    udp.settimeout(0.2)

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((ip, port))
    tcp.listen(8)
    tcp.settimeout(0.2)

    while time.monotonic() < deadline:
        try:
            udp.recvfrom(65536)
        except socket.timeout:
            pass
        try:
            conn, _ = tcp.accept()
            conn.settimeout(0.5)
            try:
                data = conn.recv(65536)
                conn.sendall(b"ack" + data[:64])
            except OSError:
                pass
            conn.close()
        except socket.timeout:
            pass

    udp.close()
    tcp.close()
