"""A small, real IEEE OUI (Organizationally Unique Identifier) prefix table --
the first 3 bytes of a MAC address, publicly registered to a manufacturer.
This is a *static reference table*, not a per-device claim: it's necessarily
incomplete (the full public registry has tens of thousands of entries), and
looking up a MAC against it is what "vendor, only when legitimately available"
means in practice. A prefix not in this table returns None, and the caller
must report "Unknown vendor" -- never guess.

Sourced from the IEEE's publicly published MA-L (MAC Address Large) registry
(https://standards-oui.ieee.org/) -- a representative subset covering common
consumer/IoT device manufacturers, not the full ~50,000-entry registry, to
keep this file small and dependency-free (no network fetch at runtime, so
discovery stays genuinely passive and works offline).
"""

from __future__ import annotations

OUI_TABLE: dict[str, str] = {
    "00:1A:11": "Google",
    "3C:5A:B4": "Google",
    "F4:F5:D8": "Google",
    "AC:63:BE": "Apple",
    "A4:83:E7": "Apple",
    "F0:18:98": "Apple",
    "DC:A6:32": "Raspberry Pi Foundation",
    "B8:27:EB": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    "18:B4:30": "Nest Labs",
    "64:16:66": "Nest Labs",
    "D0:73:D5": "Nest Labs",
    "50:F5:DA": "Amazon",
    "68:37:E9": "Amazon",
    "FC:65:DE": "Amazon",
    "00:17:88": "Signify (Philips Hue)",
    "EC:B5:FA": "Signify (Philips Hue)",
    "B0:C5:54": "TP-Link",
    "50:C7:BF": "TP-Link",
    "AC:84:C6": "TP-Link",
    "34:EA:34": "Espressif (ESP8266/ESP32)",
    "24:6F:28": "Espressif (ESP8266/ESP32)",
    "30:AE:A4": "Espressif (ESP8266/ESP32)",
    "84:CC:A8": "Espressif (ESP8266/ESP32)",
    "48:55:19": "Sonos",
    "5C:AA:FD": "Sonos",
    "94:9F:3E": "Belkin (Wemo)",
    "00:26:E8": "Ubiquiti Networks",
    "78:8A:20": "Ubiquiti Networks",
    "DC:9F:DB": "Ubiquiti Networks",
    "00:0C:29": "VMware (virtual NIC)",
    "00:50:56": "VMware (virtual NIC)",
    "08:00:27": "Oracle VirtualBox (virtual NIC)",
    "52:54:00": "QEMU/KVM (virtual NIC)",
}


def lookup_vendor(mac: str) -> str | None:
    """``mac``: colon-separated, any case. Returns the manufacturer if its OUI
    prefix is in this table, else None -- the caller must render that as
    "Unknown vendor", never fall back to a guess."""
    prefix = ":".join(mac.upper().split(":")[:3])
    return OUI_TABLE.get(prefix)
