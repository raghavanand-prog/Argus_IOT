"""A real TCP server speaking the real PJLink wire protocol -- used to test
sensor/control/pjlink.py's client against genuine protocol exchanges (greeting,
command parsing, MD5 auth challenge, error responses) since no real projector
hardware was available when the client was built. This is not a mock of the
PJLinkClient object; it's a real socket server a real client connects to over
real TCP, and the client has no idea it isn't talking to a real device --
verifying real request/response behaviour, not internal call sequencing.
"""

from __future__ import annotations

import hashlib
import socket
import threading


class MockPJLinkServer:
    def __init__(self, password: str | None = None, port: int = 0):
        self.password = password
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", port))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        self._thread: threading.Thread | None = None
        self._running = False
        self.state = {"power": "0", "input": "11", "mute": "30"}
        self.seed = "abcd1234"

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        try:
            self._sock.close()
        except OSError:
            pass

    def _serve_forever(self) -> None:
        while self._running:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        with conn:
            if self.password is not None:
                conn.sendall(f"PJLINK 1 {self.seed}\r".encode())
            else:
                conn.sendall(b"PJLINK 0\r")

            buf = b""
            while not buf.endswith(b"\r"):
                chunk = conn.recv(256)
                if not chunk:
                    return
                buf += chunk
            raw = buf.rstrip(b"\r").decode()

            if self.password is not None:
                expected_digest = hashlib.md5((self.seed + self.password).encode()).hexdigest()  # noqa: S324
                if not raw.startswith(expected_digest):
                    conn.sendall(b"PJLINK ERRA\r")
                    return
                raw = raw[len(expected_digest):]

            response = self._respond(raw)
            conn.sendall(response.encode())

    def _respond(self, cmd: str) -> str:
        # cmd like "%1POWR ?" or "%1POWR 1"
        if not cmd.startswith("%1") or len(cmd) < 6:
            return "%1ERR1=ERR1\r"
        code = cmd[2:6]
        param = cmd[7:].strip()

        if code == "POWR":
            if param == "?":
                return f"%1POWR={self.state['power']}\r"
            if param in {"0", "1"}:
                self.state["power"] = param
                return "%1POWR=OK\r"
            return "%1POWR=ERR2\r"
        if code == "INPT":
            if param == "?":
                return f"%1INPT={self.state['input']}\r"
            self.state["input"] = param
            return "%1INPT=OK\r"
        if code == "AVMT":
            if param == "?":
                return f"%1AVMT={self.state['mute']}\r"
            self.state["mute"] = param
            return "%1AVMT=OK\r"
        if code == "NAME":
            return "%1NAME=Mock Test Projector\r"
        return f"%1{code}=ERR1\r"
