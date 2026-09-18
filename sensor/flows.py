"""Real-packet flow assembly for the live sensor -- the same logic as
argus/testbed/pcap_to_flows.py, adapted for *discovered* devices instead of a
testbed's pre-provisioned DeviceLink map. A real LAN has no pre-known device
list; devices are whatever discovery.py has actually observed via ARP, keyed
by their real MAC (or IP, if no MAC was resolved) -- never an invented ID.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import UTC, datetime

from argus.schemas import FlowRecord

IDLE_TIMEOUT_S = 5.0


def packets_to_live_flows(packets: list, known_identifiers: dict[str, str]) -> list[FlowRecord]:
    """``known_identifiers``: ip -> device identifier (from discovery.py's
    DiscoveredDevice.identifier), for whichever devices have actually been
    seen in the ARP table. A packet whose source AND destination IP are both
    unknown is dropped -- there is no device to attribute it to without
    inventing one."""
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
        if first_ip in known_identifiers:
            device_ip, dst_ip = first_ip, pkts[0]["IP"].dst
        elif pkts[0]["IP"].dst in known_identifiers:
            device_ip, dst_ip = pkts[0]["IP"].dst, first_ip
        else:
            continue  # neither endpoint is a discovered device -- nothing to attribute this to

        device_id = known_identifiers[device_ip]
        dst_port = port2 if device_ip == ip1 else port1
        ts_start = datetime.fromtimestamp(float(pkts[0].time), tz=UTC)
        ts_end = datetime.fromtimestamp(float(pkts[-1].time), tz=UTC)
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
            label="unknown",  # no ground truth exists for real LAN traffic -- never "benign"/"attack"
        ))
    flows.sort(key=lambda f: f.ts_start)
    return flows
