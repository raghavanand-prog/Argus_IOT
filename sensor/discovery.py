"""Passive device discovery: reads the operating system's *own already-
populated* ARP/neighbour cache -- built by normal network activity, not by
this sensor sending anything. No active probing (no ARP requests sent, no
port scanning, no OS fingerprinting), by design: this is exactly the
"passive/read-only, minimal local-network discovery" the project's safety
requirements call for.

Two backends, platform-selected automatically:
- Linux: parses /proc/net/arp directly (pure Python, no subprocess, no
  external binary dependency).
- macOS (and Linux as a fallback if /proc is unavailable, e.g. inside some
  containers): parses the output of the standard `arp -a` command, present
  by default on every macOS and Linux install.

Every field returned is either read verbatim from the OS's neighbour table
(ip, mac) or looked up in the static OUI table (vendor). device_type is
always "unknown" -- nothing this module reads can legitimately determine
what kind of device an IP/MAC belongs to, so it never guesses.
"""

from __future__ import annotations

import platform
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime

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
    interface) or a deterministic derivation of it (identifier, vendor via
    the static OUI table) -- never invented. device_type is always "unknown":
    nothing in passive ARP-table discovery can legitimately determine it."""

    identifier: str  # stable key: mac-<mac> if a MAC was resolved, else ip-<ip>
    ip: str
    mac: str | None
    vendor: str | None
    interface: str | None
    device_type: str = "unknown"
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    flow_count: int = 0  # set by the agent's capture loop; 0 in discovery-only mode
    monitored: bool = False  # True once a real baseline/detector has been fit for this device


class DiscoveryState:
    """Tracks first_seen/last_seen across repeated polls -- the only
    "memory" this module keeps, and it's bookkeeping (when did *we* first
    observe this entry), never a fabricated field."""

    def __init__(self) -> None:
        self._devices: dict[str, DiscoveredDevice] = {}

    def poll(self, now: datetime | None = None) -> list[DiscoveredDevice]:
        now = now or datetime.utcnow()
        neighbours = read_neighbour_table()
        for n in neighbours:
            identifier = f"mac-{n.mac.replace(':', '').lower()}" if n.mac else f"ip-{n.ip}"
            existing = self._devices.get(identifier)
            if existing:
                existing.ip = n.ip
                existing.last_seen = now
                if n.interface:
                    existing.interface = n.interface
            else:
                self._devices[identifier] = DiscoveredDevice(
                    identifier=identifier, ip=n.ip, mac=n.mac,
                    vendor=lookup_vendor(n.mac) if n.mac else None,
                    interface=n.interface, first_seen=now, last_seen=now,
                )
        return list(self._devices.values())

    def all(self) -> list[DiscoveredDevice]:
        return list(self._devices.values())
