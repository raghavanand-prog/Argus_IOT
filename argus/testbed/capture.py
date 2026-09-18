"""Real packet capture: sniffs every device's bridge-port interface simultaneously
from the root namespace and writes a real, standard pcap file.

Why sniffing every root-side veth instead of one "mirror port": a Linux bridge is a
real L2 switch -- unicast traffic between two ports is forwarded directly and does
not appear on a third interface without explicit port mirroring (which needs `tc`,
not installed in this environment -- see docs/04b). But every packet a device sends
or receives necessarily crosses *that device's own* bridge port, so sniffing across
all of them together gives full visibility into every flow, including intra-LAN
traffic between two devices, without any mirroring trick at all.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field

from scapy.all import wrpcap
from scapy.config import conf as scapy_conf
from scapy.sendrecv import AsyncSniffer

logger = logging.getLogger(__name__)
scapy_conf.verb = 0


@dataclass
class CaptureSession:
    ifaces: list[str]
    pcap_path: str | None = None
    # A real BPF filter string (e.g. "host 192.168.1.50"), applied by libpcap in
    # the kernel before a packet ever reaches this process -- not a post-hoc
    # Python filter. This is what lets sensor/agent.py's --target-host scope a
    # capture to exactly one device: on a shared network the operator doesn't
    # administer (e.g. a college LAN), capturing every packet on the interface
    # means capturing other people's traffic shapes without their consent, which
    # needs network-owner authorization the operator likely doesn't have. Scoping
    # to a single host they do own/control sidesteps that entirely -- packets
    # to/from anyone else are dropped by the kernel, never captured at all.
    bpf_filter: str | None = None
    packets: list = field(default_factory=list)
    _sniffer: AsyncSniffer | None = field(default=None, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def _on_packet(self, pkt) -> None:
        with self._lock:
            self.packets.append(pkt)

    def start(self) -> None:
        self._sniffer = AsyncSniffer(
            iface=self.ifaces, prn=self._on_packet, store=False, filter=self.bpf_filter,
        )
        self._sniffer.start()
        logger.info(
            "capture started on %d interfaces%s", len(self.ifaces),
            f" (filter: {self.bpf_filter!r})" if self.bpf_filter else "",
        )

    def stop(self) -> list:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                # a sniffer-thread failure (e.g. an interface that vanished mid-run)
                # shouldn't discard whatever packets were already captured -- log it
                # and return what we have rather than losing a real capture over it
                logger.exception("sniffer.stop() raised -- returning packets captured so far")
        with self._lock:
            pkts = list(self.packets)
        if self.pcap_path and pkts:
            wrpcap(self.pcap_path, pkts)
            logger.info("wrote %d packets to %s", len(pkts), self.pcap_path)
        return pkts
