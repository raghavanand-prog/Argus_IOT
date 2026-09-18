"""Passive device discovery: reads the operating system's *own already-
populated* ARP/neighbour cache -- built by normal network activity, not by
this sensor sending anything. No port scanning, no OS fingerprinting, no
credential probing, by design: this is the "passive/minimal by default"
local-network discovery the project's safety requirements call for.

Two ARP backends, platform-selected automatically:
- Linux: parses /proc/net/arp directly (pure Python, no subprocess, no
  external binary dependency).
- macOS (and Linux as a fallback if /proc is unavailable, e.g. inside some
  containers): parses the output of the standard `arp -a -n` command, present
  by default on every macOS and Linux install.

Two further sources, both opt-in (never on by default, matching the ARP
read's own "minimal by default" posture) and layered in by DiscoveryState:
- Reverse DNS (sensor/hostnames.py), a real network call bounded to a few
  new lookups per poll so it stays safe on a network with thousands of
  neighbours (see progress.md's 2026-09-18 college-LAN entry).
- mDNS (sensor/mdns.py), the same standard multicast-DNS discovery any
  Chromecast/AirPlay/printer-finder app uses -- not port scanning.

Every field is either read verbatim from the OS's neighbour table (ip, mac),
a real response from a real network protocol (hostname, from reverse DNS or
mDNS), or a deterministic derivation of observed data (vendor via the static
OUI table, device_type via an unambiguous mDNS service advertisement).
device_type stays "unknown" and hostname stays None whenever none of those
actually resolved something -- never guessed.
"""

from __future__ import annotations

import platform
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime

from sensor.hostnames import resolve_hostname
from sensor.identifier import device_identifier
from sensor.oui import lookup_vendor

_MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
_INCOMPLETE_MACS = {"00:00:00:00:00:00", "<incomplete>"}


@dataclass
class ObservedNeighbour:
    ip: str
    mac: str | None  # None if the OS's own neighbour entry has no resolved MAC yet
    interface: str | None = None


def _normalise_mac(mac: str) -> str | None:
    mac = mac.strip().upper()
    if not _MAC_RE.fullmatch(mac) or mac in {m.upper() for m in _INCOMPLETE_MACS}:
        return None
    return mac


def _read_proc_net_arp(path: str = "/proc/net/arp") -> list[ObservedNeighbour]:
    """Linux: kernel's own ARP table. Format (whitespace-separated, header row
    first): IP address, HW type, Flags, HW address, Mask, Device."""
    out: list[ObservedNeighbour] = []
    with open(path) as f:
        lines = f.readlines()[1:]  # skip header
    for line in lines:
        parts = line.split()
        if len(parts) < 6:
            continue
        ip, _hw_type, flags, hw_address, _mask, device = parts[:6]
        if flags == "0x0":  # incomplete entry -- kernel hasn't resolved a MAC yet
            continue
        mac = _normalise_mac(hw_address)
        out.append(ObservedNeighbour(ip=ip, mac=mac, interface=device))
    return out


def _parse_arp_a_output(text: str) -> list[ObservedNeighbour]:
    """Parses `arp -a` output, which looks like (macOS/BSD and Linux both):
    ``hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]``
    or the Linux net-tools variant:
    ``? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0``."""
    out: list[ObservedNeighbour] = []
    ip_re = re.compile(r"\((\d{1,3}(?:\.\d{1,3}){3})\)")
    iface_re = re.compile(r"\bon\s+(\S+)")
    for line in text.splitlines():
        ip_match = ip_re.search(line)
        if not ip_match:
            continue
        mac_match = _MAC_RE.search(line)
        mac = _normalise_mac(mac_match.group(0)) if mac_match else None
        iface_match = iface_re.search(line)
        out.append(ObservedNeighbour(
            ip=ip_match.group(1), mac=mac,
            interface=iface_match.group(1) if iface_match else None,
        ))
    return out


def _read_arp_a() -> list[ObservedNeighbour]:
    # -n suppresses reverse-DNS hostname lookups. Without it, BSD/macOS arp -a tries
    # to resolve a hostname for every neighbour before printing anything -- on a real
    # home/office LAN where the router doesn't answer PTR queries quickly, this
    # routinely blows past a 5s timeout (confirmed: a real run on a real Mac hung on
    # exactly this). -n makes the command itself fast; _parse_arp_a_output already
    # handles the unresolved-hostname ("? (ip) at mac ...") output shape either way,
    # so this changes nothing about what's parsed, only how long it takes to get it.
    try:
        result = subprocess.run(["arp", "-a", "-n"], capture_output=True, text=True, timeout=10, check=False)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        # a single bad poll (arp still slow for some other reason, binary missing,
        # permission issue) must not crash the whole sensor process -- same
        # never-let-one-failure-kill-the-loop principle agent.py's ingest already
        # follows. The next poll just tries again.
        return []
    return _parse_arp_a_output(result.stdout)


def read_neighbour_table() -> list[ObservedNeighbour]:
    """The one public entry point: reads whatever real neighbour table this OS
    exposes. Tries the platform-appropriate backend first, falls back to the
    other rather than raising, since which one is available varies by
    environment (e.g. some Linux containers lack /proc/net/arp)."""
    if platform.system() == "Linux":
        try:
            return _read_proc_net_arp()
        except (FileNotFoundError, PermissionError):
            pass
    return _read_arp_a()


@dataclass
class DiscoveredDevice:
    """Everything here is either read verbatim from the OS (ip, mac,
    interface), a real network response (hostname, via reverse DNS or mDNS),
    or a deterministic derivation of observed data (identifier, vendor via
    the static OUI table, device_type via an mDNS service advertisement) --
    never invented. device_type stays "unknown" unless a device is genuinely
    advertising an unambiguous mDNS service (sensor/mdns.py's
    SERVICE_TYPE_HINTS); hostname stays None unless reverse DNS or mDNS
    actually resolved one."""

    identifier: str  # stable key: mac-<mac> if a MAC was resolved, else ip-<ip>
    ip: str
    mac: str | None
    vendor: str | None
    interface: str | None
    device_type: str = "unknown"
    hostname: str | None = None
    discovery_sources: list[str] = field(default_factory=lambda: ["arp"])
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    flow_count: int = 0  # set by the agent's capture loop; 0 in discovery-only mode
    monitored: bool = False  # True once a real baseline/detector has been fit for this device


class DiscoveryState:
    """Tracks first_seen/last_seen across repeated polls -- the only
    "memory" this module keeps beyond what's observed, and it's bookkeeping
    (when did *we* first observe this entry), never a fabricated field.

    ``resolve_hostnames``: opt-in reverse-DNS lookups (a real network call,
    unlike the ARP read). Bounded to ``max_hostname_lookups_per_poll`` never-
    yet-attempted IPs per poll to stay safe on a network with thousands of
    neighbours (see progress.md's 2026-09-18 college-LAN entry) -- resolving
    thousands of hostnames one at a time would otherwise make a single poll
    take hours.
    ``mdns``: an already-started sensor.mdns.MDNSListener, or None to skip
    mDNS entirely (also opt-in -- see that module's docstring for why sending
    standard mDNS queries is legitimate discovery, not scanning, but still
    kept off by default alongside ARP-only being the safe default)."""

    def __init__(self, resolve_hostnames: bool = False, mdns: object = None,
                 max_hostname_lookups_per_poll: int = 5) -> None:
        self._devices: dict[str, DiscoveredDevice] = {}
        self._hostname_attempted: set[str] = set()
        self.resolve_hostnames = resolve_hostnames
        self.mdns = mdns
        self.max_hostname_lookups_per_poll = max_hostname_lookups_per_poll

    def poll(self, now: datetime | None = None) -> list[DiscoveredDevice]:
        now = now or datetime.utcnow()
        neighbours = read_neighbour_table()
        mdns_records = self.mdns.snapshot() if self.mdns is not None else {}
        hostname_lookups_this_poll = 0
        for n in neighbours:
            identifier = device_identifier(n.ip, n.mac)
            existing = self._devices.get(identifier)
            if existing:
                existing.ip = n.ip
                existing.last_seen = now
                if n.interface:
                    existing.interface = n.interface
                device = existing
            else:
                device = DiscoveredDevice(
                    identifier=identifier, ip=n.ip, mac=n.mac,
                    vendor=lookup_vendor(n.mac) if n.mac else None,
                    interface=n.interface, first_seen=now, last_seen=now,
                )
                self._devices[identifier] = device

            mdns_rec = mdns_records.get(n.ip)
            if mdns_rec:
                if mdns_rec.hostname and not device.hostname:
                    device.hostname = mdns_rec.hostname
                elif mdns_rec.instance_name and not device.hostname:
                    device.hostname = mdns_rec.instance_name
                if mdns_rec.device_type_hint and device.device_type == "unknown":
                    device.device_type = mdns_rec.device_type_hint
                if "mdns" not in device.discovery_sources:
                    device.discovery_sources.append("mdns")

            if (
                self.resolve_hostnames and not device.hostname
                and n.ip not in self._hostname_attempted
                and hostname_lookups_this_poll < self.max_hostname_lookups_per_poll
            ):
                self._hostname_attempted.add(n.ip)
                hostname_lookups_this_poll += 1
                resolved = resolve_hostname(n.ip)
                if resolved:
                    device.hostname = resolved
                    if "reverse-dns" not in device.discovery_sources:
                        device.discovery_sources.append("reverse-dns")

        return list(self._devices.values())

    def all(self) -> list[DiscoveredDevice]:
        return list(self._devices.values())
