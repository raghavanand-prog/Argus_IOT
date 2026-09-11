"""Ties fabric + live device processes + live attack scripts + capture +
flow-assembly into one runnable live-testbed pass. This is the real-packet
counterpart to ``argus.sim.engine`` -- same output type (``FlowRecord`` +
``GroundTruthEvent`` lists), sourced from an actual network instead of a generator,
so everything downstream (features, registry, detection, ...) is unchanged.
"""

from __future__ import annotations

import logging
import multiprocessing
import time
from dataclasses import dataclass, field

from argus.schemas import FlowRecord, GroundTruthEvent
from argus.sim.devices import FLEET
from argus.testbed.capture import CaptureSession
from argus.testbed.fabric import NetworkFabric, cleanup_stale_fabric
from argus.testbed.live_attacks import run_low_and_slow_live, run_mirai_live
from argus.testbed.live_devices import run_device, run_peer_listener
from argus.testbed.pcap_to_flows import packets_to_flows

logger = logging.getLogger(__name__)

HUB_PORT = 8883
C2_PORT_TCP = 6667
C2_PORT_ALT = 443

BENIGN_FLEET = {
    "smart-plug-00": "smart-plug", "smart-plug-01": "smart-plug",
    "ip-camera-00": "ip-camera", "smart-speaker-00": "smart-speaker",
    "hub-00": "hub",
}


@dataclass
class LiveTestbedResult:
    flows: list[FlowRecord]
    ground_truth: list[GroundTruthEvent]
    device_ips: dict[str, str]
    pcap_path: str | None


def run_live_testbed(scenario: str | None, *, benign_duration_s: float = 12.0,
                      attack_duration_s: float = 10.0, seed: int = 42,
                      pcap_path: str | None = "/tmp/argus_live_capture.pcap") -> LiveTestbedResult:
    """Builds the fabric, runs benign traffic + a live attack scenario concurrently
    with capture, tears the fabric down (always, even on error), and returns real
    FlowRecords + real-timestamped GroundTruthEvents ready for the existing
    detect->respond->verify pipeline. Requires root/CAP_NET_ADMIN on Linux."""
    cleanup_stale_fabric()
    ctx = multiprocessing.get_context("fork")

    with NetworkFabric() as fabric:
        for device_id, device_type in BENIGN_FLEET.items():
            fabric.add_device(device_id)
        c2 = fabric.add_device("c2-00")  # the "external" C2 endpoint -- no device_type,
        # same as an external IP in the synthetic engine: unresolvable by the risk
        # engine's blast-radius lookup, which is the correct, honest fallback (docs/02)

        capture = CaptureSession(ifaces=fabric.root_interfaces(), pcap_path=pcap_path)
        capture.start()
        time.sleep(0.3)  # let AsyncSniffer's raw sockets actually open before traffic starts

        procs: list[multiprocessing.Process] = []
        hub_link = fabric.links["hub-00"]
        listener = ctx.Process(target=run_peer_listener, args=(
            hub_link.ns_name, hub_link.ip, HUB_PORT, benign_duration_s + attack_duration_s + 3,
        ))
        procs.append(listener)
        c2_listener = ctx.Process(target=run_peer_listener, args=(
            c2.ns_name, c2.ip, C2_PORT_ALT, benign_duration_s + attack_duration_s + 3,
        ))
        procs.append(c2_listener)
        for p in (listener, c2_listener):
            p.start()
        time.sleep(0.3)

        for i, (device_id, device_type) in enumerate(BENIGN_FLEET.items()):
            if device_id == "hub-00":
                continue
            link = fabric.links[device_id]
            p = ctx.Process(target=run_device, args=(
                link.ns_name, device_id, device_type, [(hub_link.ip, HUB_PORT)],
                benign_duration_s + attack_duration_s, seed + i,
            ))
            procs.append(p)
            p.start()

        time.sleep(benign_duration_s)

        # the attacker is a real fleet member, "compromised" -- not a separate role.
        # This matches run_demo_pipeline's synthetic convention exactly (dev_id
        # "smart-plug-00" / "smart-speaker-00"), which is what lets both paths share
        # _process_scenario() and resolve the same device_type from the same id.
        ground_truth: list[GroundTruthEvent] = []
        if scenario is None:
            time.sleep(attack_duration_s)
        elif scenario == "mirai":
            attacker = fabric.links["smart-plug-00"]
            victim = fabric.links["smart-plug-01"]
            scan_targets = [fabric.links[d].ip for d in ("ip-camera-00", "smart-speaker-00", "smart-plug-01")]
            ground_truth = run_mirai_live(attacker.ns_name, attacker.ip, victim.ip, c2.ip, scan_targets)
        elif scenario == "low_and_slow":
            attacker = fabric.links["smart-speaker-00"]
            ground_truth = run_low_and_slow_live(
                attacker.ns_name, attacker.ip, c2.ip,
                duration_s=attack_duration_s, interval_s=2.0,
            )
        else:
            raise ValueError(f"unknown live scenario: {scenario}")

        time.sleep(1.0)  # let the last few packets land before stopping capture

        for p in procs:
            p.join(timeout=5)
            if p.is_alive():
                p.terminate()

        packets = capture.stop()
        device_ips = {did: link.ip for did, link in fabric.links.items()}

        def label_fn(src_ip: str, dst_ip: str, dst_port: int, ts) -> str:
            for ev in ground_truth:
                src_match = src_ip == ev.src or dst_ip == ev.src
                dst_match = any(d in (src_ip, dst_ip) for d in ev.dst) if ev.dst else False
                if src_match and dst_match and ev.t_start <= ts <= ev.t_end:
                    return f"attack:{ev.scenario}:{ev.phase}"
            return "benign"

        flows = packets_to_flows(packets, fabric.links, label_fn=label_fn)

    logger.info("live testbed run complete: %d packets -> %d flows, %d ground-truth events",
                len(packets), len(flows), len(ground_truth))
    return LiveTestbedResult(flows=flows, ground_truth=ground_truth, device_ips=device_ips, pcap_path=pcap_path)
