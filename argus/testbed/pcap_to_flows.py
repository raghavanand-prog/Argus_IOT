"""Real-packet flow assembly: groups captured scapy packets into bidirectional
FlowRecords -- the exact same schema argus/collector/windows.py and
argus/features/extract.py already consume from the synthetic sim engine.

This is the payoff of docs/01's data-flow-contract design: every stage downstream of
collection was built against ``FlowRecord``, never against "however the synthetic
engine happens to represent a flow" -- so swapping the source from synthetic
generation to a real captured pcap requires touching nothing else in the pipeline.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone

from argus.schemas import FlowRecord
from argus.testbed.fabric import DeviceLink

IDLE_TIMEOUT_S = 5.0  # short on purpose: live-testbed runs are minutes, not hours


def _ip_to_device(links: dict[str, DeviceLink]) -> dict[str, str]:
    return {link.ip: device_id for device_id, link in links.items()}


def packets_to_flows(packets: list, links: dict[str, DeviceLink],
                      label_fn=None) -> list[FlowRecord]:
    """``label_fn(src_ip, dst_ip, dst_port, ts) -> str`` optionally labels each flow
    against a ground-truth window (see live_attacks.py); defaults to "benign"."""
    ip_to_device = _ip_to_device(links)
    label_fn = label_fn or (lambda *a: "benign")

    # key on the *unordered* 5-tuple so both directions of one conversation merge
    buckets: dict[tuple, list] = defaultdict(list)
    for pkt in packets:
        if "IP" not in pkt:
            continue
        ip_layer = pkt["IP"]
        proto = "tcp" if "TCP" in pkt else ("udp" if "UDP" in pkt else None)
        if proto is None:
            continue
        l4 = pkt["TCP"] if proto == "tcp" else pkt["UDP"]
        a, b = ip_layer.src, ip_layer.dst
        pa, pb = l4.sport, l4.dport
        key = tuple(sorted([(a, pa), (b, pb)])) + (proto,)
        buckets[key].append(pkt)

    flows: list[FlowRecord] = []
    for key, pkts in buckets.items():
        (ip1, port1), (ip2, port2), proto = key
        pkts = sorted(pkts, key=lambda p: float(p.time))
        first_ip = pkts[0]["IP"].src
        # "device" side is whichever endpoint we recognise; dst is the other
        if first_ip in ip_to_device:
            device_ip, dst_ip = first_ip, pkts[0]["IP"].dst
        else:
            device_ip, dst_ip = pkts[0]["IP"].dst, first_ip
        device_id = ip_to_device.get(device_ip)
        if device_id is None:
            continue  # neither side is a known testbed device -- drop (shouldn't happen)

        dst_port = port2 if device_ip == ip1 else port1
        ts_start = datetime.fromtimestamp(float(pkts[0].time), tz=timezone.utc)
        ts_end = datetime.fromtimestamp(float(pkts[-1].time), tz=timezone.utc)
        pkts_out = sum(1 for p in pkts if p["IP"].src == device_ip)
        pkts_in = len(pkts) - pkts_out
        bytes_out = sum(len(p) for p in pkts if p["IP"].src == device_ip)
        bytes_in = sum(len(p) for p in pkts) - bytes_out

        flows.append(FlowRecord(
            flow_id=str(uuid.uuid4()), device_id=device_id,
            ts_start=ts_start, ts_end=ts_end,
            src_ip=device_ip, dst_ip=dst_ip, dst_port=dst_port, proto=proto,
            pkts_out=pkts_out, pkts_in=pkts_in, bytes_out=bytes_out, bytes_in=bytes_in,
            tls_ja4=None, dns_qname=None,
            label=label_fn(device_ip, dst_ip, dst_port, ts_start),
        ))
    flows.sort(key=lambda f: f.ts_start)
    return flows
