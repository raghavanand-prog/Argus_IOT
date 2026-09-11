"""Network fabric: a Linux bridge plus one veth pair + network namespace per
simulated device, all inside a single, code-enforced 10.10.0.0/24 subnet.

Why a bridge of veth pairs instead of Docker containers: Docker image pulls are
blocked by this environment's outbound proxy allowlist (verified: 403 from Docker
Hub's CDN), so no ``FROM python:3.11-slim`` build can complete here. Network
namespaces need no image at all -- they're a kernel feature, reachable via the
``pyroute2`` netlink library, and they give the same isolation property (each
"device" has its own network stack, can't see another device's sockets, and is
reachable only through the shared bridge). See decisions.md for the full trade-off.

Why this is safe to run in a shared sandbox: every namespace, veth, and bridge is
named ``argus-*`` so it's trivially identifiable and cleanable; no default route or
IP forwarding is ever configured toward the host's real interface (eth0); a device
namespace has exactly one interface (its veth end) and one reachable subnet
(10.10.0.0/24). There is no code path in this module that can route a packet
anywhere but onto that bridge.
"""

from __future__ import annotations

import ipaddress
import logging
import uuid
from dataclasses import dataclass, field

from pyroute2 import IPRoute, NetNS
from pyroute2.netlink.exceptions import NetlinkError

logger = logging.getLogger(__name__)

BRIDGE_NAME = "argus-br0"
SUBNET = ipaddress.ip_network("10.10.0.0/24")
GATEWAY_IP = "10.10.0.1"  # the bridge device itself, in the root namespace


def _disable_bridge_netfilter() -> None:
    """If Docker (or anything else) is running on this host, its iptables-nft
    ruleset typically sets FORWARD to policy drop and br_netfilter is loaded, which
    means our bridge's pure-L2 traffic between two veth ports gets routed through
    that DROP policy even though nothing about it should touch Docker's rules at
    all. Disabling bridge-nf-call-iptables/ip6tables makes bridged traffic bypass
    the host iptables/nftables FORWARD hook entirely -- verified necessary and
    sufficient in this environment (see decisions.md). This is a reversible sysctl,
    not a persistent config change, and only affects L2-bridged traffic."""
    for proc_path in (
        "/proc/sys/net/bridge/bridge-nf-call-iptables",
        "/proc/sys/net/bridge/bridge-nf-call-ip6tables",
    ):
        try:
            with open(proc_path, "w") as f:
                f.write("0")
        except OSError:
            logger.warning("could not write %s (bridge netfilter module may not be loaded, which is fine)", proc_path)


def _veth_names(salt: str, device_id: str) -> tuple[str, str]:
    """Linux interface names are capped at 15 bytes. ``salt`` is unique per
    NetworkFabric *instance* (not per device_id's hash, which is stable across
    separate fabric instances within one process and caused exactly the collision
    this comment now documents: two sequential live-testbed runs reused identical
    veth names, and a still-shutting-down capture thread from the first run raced
    against the second run's freshly-created interface of the same name -- see
    decisions.md)."""
    short = f"{abs(hash((salt, device_id))) % 0xFFFFFF:06x}"
    return f"a{short}0", f"a{short}1"  # root-side (bridge port), netns-side


@dataclass
class DeviceLink:
    device_id: str
    ns_name: str
    ip: str
    root_iface: str  # the bridge-side veth end, visible from the root namespace
    ns_iface: str = "eth0"


@dataclass
class NetworkFabric:
    """Owns the bridge and every device link created through it. ``teardown()`` is
    idempotent and safe to call even if setup partially failed -- always call it in
    a ``finally`` block (or use this as a context manager)."""

    links: dict[str, DeviceLink] = field(default_factory=dict)
    _next_host: int = 10  # .1 is the gateway/bridge, .2-.9 reserved
    _salt: str = field(default_factory=lambda: uuid.uuid4().hex[:6])

    def __enter__(self) -> NetworkFabric:
        self.setup_bridge()
        return self

    def __exit__(self, *exc) -> None:
        self.teardown()

    def setup_bridge(self) -> None:
        _disable_bridge_netfilter()
        with IPRoute() as ipr:
            existing = ipr.link_lookup(ifname=BRIDGE_NAME)
            if existing:
                logger.warning("%s already exists -- reusing (prior run may not have torn down cleanly)", BRIDGE_NAME)
                br_idx = existing[0]
            else:
                ipr.link("add", ifname=BRIDGE_NAME, kind="bridge")
                br_idx = ipr.link_lookup(ifname=BRIDGE_NAME)[0]
            addrs = [a.get_attrs("IFA_ADDRESS") for a in ipr.get_addr(index=br_idx)]
            if not any(GATEWAY_IP in a for a in addrs):
                ipr.addr("add", index=br_idx, address=GATEWAY_IP, prefixlen=SUBNET.prefixlen)
            ipr.link("set", index=br_idx, state="up")

    def add_device(self, device_id: str) -> DeviceLink:
        if device_id in self.links:
            return self.links[device_id]
        self._next_host += 1
        if self._next_host > 254:
            raise RuntimeError("testbed subnet exhausted (max ~244 devices)")
        ip = str(SUBNET.network_address + self._next_host)
        ns_name = f"argus-{device_id}"
        root_if, ns_if_tmp = _veth_names(self._salt, device_id)

        # the namespace file under /var/run/netns must exist before a netlink
        # request can reference it by name (net_ns_fd opens that path) -- create
        # it first, empty, then move the veth peer into it below
        NetNS(ns_name).close()

        with IPRoute() as ipr:
            br_idx = ipr.link_lookup(ifname=BRIDGE_NAME)[0]
            try:
                ipr.link("add", ifname=root_if, kind="veth", peer=ns_if_tmp)
            except NetlinkError as e:
                if "File exists" not in str(e):
                    raise
                ipr.link("del", ifname=root_if)
                ipr.link("add", ifname=root_if, kind="veth", peer=ns_if_tmp)
            root_idx = ipr.link_lookup(ifname=root_if)[0]
            ns_peer_idx = ipr.link_lookup(ifname=ns_if_tmp)[0]

            ipr.link("set", index=root_idx, master=br_idx)
            ipr.link("set", index=root_idx, state="up")
            ipr.link("set", index=ns_peer_idx, net_ns_fd=ns_name)

        with NetNS(ns_name) as ns:
            idx = ns.link_lookup(ifname=ns_if_tmp)[0]
            ns.link("set", index=idx, ifname="eth0")
            idx = ns.link_lookup(ifname="eth0")[0]
            ns.addr("add", index=idx, address=ip, prefixlen=SUBNET.prefixlen)
            ns.link("set", index=idx, state="up")
            lo_idx = ns.link_lookup(ifname="lo")[0]
            ns.link("set", index=lo_idx, state="up")
            # deliberately no default route -- nothing outside 10.10.0.0/24 is
            # reachable from a device namespace, structurally, not just by policy

        link = DeviceLink(device_id=device_id, ns_name=ns_name, ip=ip, root_iface=root_if)
        self.links[device_id] = link
        return link

    def root_interfaces(self) -> list[str]:
        """Every bridge-port interface, visible from the root namespace -- sniffing
        all of these together sees every packet each device sends or receives,
        without needing bridge port-mirroring (docs/04's "capture sees intra-LAN
        traffic too" requirement, met structurally)."""
        return [link.root_iface for link in self.links.values()]

    def teardown(self) -> None:
        with IPRoute() as ipr:
            for link in list(self.links.values()):
                idx = ipr.link_lookup(ifname=link.root_iface)
                if idx:
                    try:
                        ipr.link("del", index=idx[0])
                    except NetlinkError:
                        pass
            br = ipr.link_lookup(ifname=BRIDGE_NAME)
            if br:
                try:
                    ipr.link("del", index=br[0])
                except NetlinkError:
                    pass
        for link in list(self.links.values()):
            try:
                NetNS(link.ns_name).remove()
            except Exception:
                pass
        self.links.clear()


def cleanup_stale_fabric() -> None:
    """Standalone cleanup for a crashed prior run -- removes anything named
    ``argus-*`` so state never silently accumulates across sessions."""
    import os

    with IPRoute() as ipr:
        for link in ipr.get_links():
            name = link.get_attr("IFLA_IFNAME") or ""
            if name == BRIDGE_NAME or name.startswith("a") and len(name) == 7:
                try:
                    ipr.link("del", index=link["index"])
                except NetlinkError:
                    pass
    netns_dir = "/var/run/netns"
    if os.path.isdir(netns_dir):
        for name in os.listdir(netns_dir):
            if name.startswith("argus-"):
                try:
                    NetNS(name).remove()
                except Exception:
                    pass
