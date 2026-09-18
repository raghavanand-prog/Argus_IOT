"""The one place the mac-<hex>/ip-<ip> stable device-identifier convention is
defined. Used by sensor/discovery.py (where a device is first observed) and
sensor/control_cli.py (where a device is looked up by IP for authorization/
control) -- previously these existed as two independent inline
implementations, a real drift risk this module removes: get it wrong in one
place and authorization/audit records silently stop matching what discovery
reports.
"""

from __future__ import annotations


def device_identifier(ip: str, mac: str | None) -> str:
    if mac:
        return f"mac-{mac.replace(':', '').lower()}"
    return f"ip-{ip}"
