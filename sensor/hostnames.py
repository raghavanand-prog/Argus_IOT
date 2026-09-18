"""Reverse-DNS hostname resolution -- a real, standard, extremely common
operation (any router admin page, `nslookup`, `dig -x`, does the same thing),
but a real network call, unlike the ARP-table read, so it needs real
bounding: a network with thousands of neighbours (a college LAN, say -- see
progress.md's 2026-09-18 entry) could otherwise make hostname resolution
alone take hours. Bounding lives in sensor/discovery.py (only a few
never-yet-attempted IPs per poll); this module is just the single-IP
resolver itself.
"""

from __future__ import annotations

import socket


def resolve_hostname(ip: str, timeout: float = 1.5) -> str | None:
    """Returns the PTR-resolved hostname for ``ip``, or None if there isn't
    one, resolution fails, or it doesn't complete within ``timeout`` seconds.
    Never guesses, never raises to the caller -- a hostname that can't be
    resolved is genuinely unavailable, not an error condition."""
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        hostname, _aliases, _addrs = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None
    finally:
        socket.setdefaulttimeout(previous_timeout)
