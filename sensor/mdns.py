"""Real mDNS (multicast DNS / Bonjour) discovery -- opt-in (--enable-mdns),
not part of the default ARP-only discovery. Uses the same standard mDNS query
mechanism every consumer app uses to find a Chromecast, an AirPlay speaker, or
a network printer (macOS's own `dns-sd -B`, Bonjour Browser, etc. all work
this way): a periodic standard multicast query for a known service type, and
a passive listen for announcements. This is not port scanning or intrusive
probing -- it's the protocol's own, intended discovery mechanism, and it's
exactly how a real device-management tool would find a controllable projector
or smart display in the first place.

Runs as a long-lived background listener (started once, not re-browsed every
poll) because a fresh mDNS browse needs real wall-clock time to collect
announcements -- polling it fresh every 30s would mean never seeing most
devices. sensor/discovery.py reads its accumulated snapshot on each poll.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Well-known, standard service types for devices this project's control layer
# cares about or that commonly reveal a real hostname. Not exhaustive --
# intentionally curated to services with an unambiguous meaning, so a
# device_type_hint derived from one is a real derivation (the device is
# genuinely advertising this service), never a guess.
SERVICE_TYPE_HINTS: dict[str, str] = {
    "_googlecast._tcp.local.": "chromecast",
    "_airplay._tcp.local.": "airplay-device",
    "_raop._tcp.local.": "airplay-device",
    "_ipp._tcp.local.": "printer",
    "_ipps._tcp.local.": "printer",
    "_hap._tcp.local.": "homekit-accessory",
    "_sonos._tcp.local.": "sonos-speaker",
    "_projector._tcp.local.": "projector",
    "_pjlink._tcp.local.": "projector",
}
# Service types browsed purely for the hostname/instance-name information
# they carry, without an unambiguous device_type_hint.
SERVICE_TYPES_HOSTNAME_ONLY = ["_workstation._tcp.local.", "_http._tcp.local.", "_https._tcp.local."]

ALL_SERVICE_TYPES = list(SERVICE_TYPE_HINTS.keys()) + SERVICE_TYPES_HOSTNAME_ONLY


@dataclass
class MDNSRecord:
    ip: str
    hostname: str | None = None
    instance_name: str | None = None
    service_types: set[str] = field(default_factory=set)
    device_type_hint: str | None = None


class MDNSListener:
    """Wraps python-zeroconf's ServiceBrowser. Imports zeroconf lazily --
    it's an optional dependency (pyproject.toml's `live-testbed` extra),
    matching the same lazy-import discipline sensor/agent.py already uses for
    scapy, so plain discovery-only mode never needs it."""

    def __init__(self) -> None:
        self._records: dict[str, MDNSRecord] = {}
        self._lock = threading.Lock()
        self._zc = None
        self._browsers: list = []

    def start(self) -> None:
        try:
            from zeroconf import ServiceBrowser as ZCServiceBrowser
            from zeroconf import ServiceListener, Zeroconf
        except ImportError as e:
            raise ImportError(
                "--enable-mdns needs the optional 'live-testbed' extra (zeroconf) -- "
                "install it with: pip install -e '.[live-testbed]'"
            ) from e

        listener_self = self

        class _Listener(ServiceListener):
            def add_service(self, zc, service_type, name):
                listener_self._on_service(zc, service_type, name)

            def update_service(self, zc, service_type, name):
                listener_self._on_service(zc, service_type, name)

            def remove_service(self, zc, service_type, name):
                pass  # a device going quiet on mDNS doesn't mean it's gone -- leave the record

        self._zc = Zeroconf()
        for service_type in ALL_SERVICE_TYPES:
            self._browsers.append(ZCServiceBrowser(self._zc, service_type, _Listener()))
        logger.info("mDNS discovery started, browsing %d service types", len(ALL_SERVICE_TYPES))

    def _on_service(self, zc, service_type: str, name: str) -> None:
        info = zc.get_service_info(service_type, name, timeout=2000)
        if info is None:
            return
        addresses = info.parsed_addresses()
        if not addresses:
            return
        hint = SERVICE_TYPE_HINTS.get(service_type)
        hostname = info.server.rstrip(".") if info.server else None
        instance_name = name.split(".")[0] if name else None
        with self._lock:
            for ip in addresses:
                rec = self._records.setdefault(ip, MDNSRecord(ip=ip))
                rec.service_types.add(service_type)
                if hostname:
                    rec.hostname = hostname
                if instance_name:
                    rec.instance_name = instance_name
                if hint and not rec.device_type_hint:
                    rec.device_type_hint = hint

    def snapshot(self) -> dict[str, MDNSRecord]:
        with self._lock:
            return dict(self._records)

    def stop(self) -> None:
        if self._zc is not None:
            self._zc.close()
