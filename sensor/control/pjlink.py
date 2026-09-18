"""Real PJLink Class 1 client, implemented against the published PJLink
specification (JBMIA -- Japan Business Machine and Information System
Industries Association -- "PJLink Specifications", the documented,
vendor-neutral standard for projector/display network control the project
owner named explicitly). Talks to a real device over a real TCP socket using
the real wire protocol -- nothing simulated at the protocol level.

Wire protocol, in full (this is the whole of PJLink Class 1):
- TCP port 4352.
- On connect, the device sends a greeting: "PJLINK 0\\r" (no auth) or
  "PJLINK 1 <8-char-seed>\\r" (MD5-challenge auth required).
- A command is "%1<CMD> <param>\\r", e.g. "%1POWR ?" to query power,
  "%1POWR 1" to power on. If auth is required, the client prepends
  MD5(seed + password) as 32 lowercase hex chars directly before the
  command bytes, no separator.
- The device replies "%1<CMD>=<value>\\r" (e.g. "%1POWR=1") or
  "%1<CMD>=ERR1\\r".."ERR4" for a protocol-level error, or "PJLINK ERRA\\r"
  for a failed auth attempt.

Class 2 (extended commands -- lens control, extended input lists, etc.) is
not implemented; Class 1's core commands (POWR/INPT/AVMT + status queries)
cover this project's capability model (power, input, mute, status).

Tested against tests/control/mock_pjlink_server.py, a real TCP server
speaking this exact protocol (both no-auth and MD5-auth-challenge modes) --
NOT against real projector hardware, since none was available when this was
built. See docs/19-device-control.md for that limitation stated plainly.
"""

from __future__ import annotations

import hashlib
import socket

PJLINK_PORT = 4352
DEFAULT_TIMEOUT_S = 5.0

PJLINK_ERROR_MEANINGS = {
    "ERR1": "undefined command",
    "ERR2": "out of parameter",
    "ERR3": "unavailable time (device busy, warming up, or cooling down)",
    "ERR4": "projector/display failure",
}

POWER_VALUES = {"0": "off", "1": "on", "2": "cooling", "3": "warming"}
MUTE_VALUES = {
    "10": "video-unmuted", "11": "video-muted",
    "20": "audio-unmuted", "21": "audio-muted",
    "30": "av-unmuted", "31": "av-muted",
}


class PJLinkError(Exception):
    """A real protocol-level error from the device (ERR1..ERR4), an auth
    failure, a malformed/unexpected response, or a connection failure --
    never silently swallowed; the caller (sensor/control/registry.py's
    executor) always sees exactly what went wrong."""


class PJLinkClient:
    def __init__(self, host: str, password: str | None = None,
                 timeout: float = DEFAULT_TIMEOUT_S, port: int = PJLINK_PORT):
        self.host = host
        self.password = password
        self.timeout = timeout
        self.port = port

    @staticmethod
    def _read_line(sock: socket.socket) -> str:
        buf = b""
        while not buf.endswith(b"\r"):
            chunk = sock.recv(1)
            if not chunk:
                break
            buf += chunk
        return buf.decode(errors="replace").rstrip("\r\n")

    def _send_command(self, cmd_body: str) -> str:
        """``cmd_body``: e.g. "%1POWR ?". Returns the raw value after "="."""
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                greeting = self._read_line(sock)
                if greeting.startswith("PJLINK 1"):
                    parts = greeting.split()
                    if len(parts) < 3:
                        raise PJLinkError(f"malformed PJLINK auth greeting: {greeting!r}")
                    seed = parts[2]
                    if not self.password:
                        raise PJLinkError(
                            "this device requires PJLink authentication but no password is configured"
                        )
                    digest = hashlib.md5((seed + self.password).encode()).hexdigest()  # noqa: S324 -- PJLink's own spec mandates MD5 here, not a security choice of ours
                    payload = f"{digest}{cmd_body}\r"
                elif greeting.startswith("PJLINK 0"):
                    payload = f"{cmd_body}\r"
                else:
                    raise PJLinkError(f"not a PJLink device (unexpected greeting: {greeting!r})")

                sock.sendall(payload.encode())
                response = self._read_line(sock)
        except OSError as e:
            raise PJLinkError(f"connection to {self.host}:{self.port} failed: {e}") from e

        if response.startswith("PJLINK ERRA"):
            raise PJLinkError("PJLink authorization error -- wrong password")
        if "=" not in response:
            raise PJLinkError(f"malformed PJLink response: {response!r}")
        _, _, value = response.partition("=")
        if value in PJLINK_ERROR_MEANINGS:
            raise PJLinkError(f"{value}: {PJLINK_ERROR_MEANINGS[value]}")
        return value

    def probe(self, timeout: float = 2.0) -> bool:
        """True if this host answers with a real PJLink greeting. A single,
        minimal, protocol-legitimate TCP connection attempt on the standard
        PJLink port -- the same thing any PJLink control app does to find
        controllable projectors, not a vulnerability scan. Called only
        per-device, on explicit user request (sensor/control CLI), never as
        an automatic bulk crawl of every discovered device."""
        try:
            with socket.create_connection((self.host, self.port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                greeting = self._read_line(sock)
            return greeting.startswith("PJLINK 0") or greeting.startswith("PJLINK 1")
        except OSError:
            return False

    def query_power(self) -> str:
        return POWER_VALUES.get(self._send_command("%1POWR ?"), "unknown")

    def power_on(self) -> None:
        self._send_command("%1POWR 1")

    def power_off(self) -> None:
        self._send_command("%1POWR 0")

    def query_input(self) -> str:
        return self._send_command("%1INPT ?")

    def set_input(self, code: str) -> None:
        self._send_command(f"%1INPT {code}")

    def query_mute(self) -> str:
        return MUTE_VALUES.get(self._send_command("%1AVMT ?"), "unknown")

    def set_mute(self, code: str) -> None:
        self._send_command(f"%1AVMT {code}")

    def query_name(self) -> str:
        return self._send_command("%1NAME ?")
