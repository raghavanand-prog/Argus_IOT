"""Local, sensor-owned device-authorization store -- the project owner's
explicit choice (this session) over a cloud-DB-backed authorization system:
the machine with actual LAN access is the one that decides, and enforces,
whether it will act on a device, never the cloud API. A discovered device
starts unauthorized; nothing here is ever auto-authorized.

Stored as plain JSON at ``~/.argus/authorized_devices.json`` by default --
not a secrets store (it holds device identifiers and protocol/capability
metadata, never credentials; PJLink passwords are handled separately, see
sensor/control/credentials.py, and never written here).
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

DEFAULT_STORE_PATH = Path.home() / ".argus" / "authorized_devices.json"


@dataclass
class AuthorizedDevice:
    identifier: str
    ip: str
    mac: str | None
    protocol: str
    capabilities: list[str] = field(default_factory=list)
    authorized_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


class AuthorizationStore:
    def __init__(self, path: Path | None = None):
        self.path = path or DEFAULT_STORE_PATH
        self._devices: dict[str, AuthorizedDevice] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError):
            # a corrupted store must not crash the sensor or silently pretend
            # everything is unauthorized-and-fine -- surface it, don't guess
            raise RuntimeError(
                f"authorization store at {self.path} exists but is not valid JSON -- "
                "fix or remove it manually before continuing"
            ) from None
        for identifier, d in raw.items():
            self._devices[identifier] = AuthorizedDevice(**d)

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {k: asdict(v) for k, v in self._devices.items()}
        # atomic write: temp file + rename, so a crash mid-write never leaves
        # a truncated/corrupted store behind
        fd, tmp_path = tempfile.mkstemp(dir=self.path.parent, prefix=".auth-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(payload, f, indent=2)
            os.replace(tmp_path, self.path)
        except BaseException:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    def is_authorized(self, identifier: str) -> bool:
        return identifier in self._devices

    def get(self, identifier: str) -> AuthorizedDevice | None:
        return self._devices.get(identifier)

    def authorize(self, identifier: str, ip: str, mac: str | None, protocol: str,
                  capabilities: list[str]) -> AuthorizedDevice:
        device = AuthorizedDevice(identifier=identifier, ip=ip, mac=mac, protocol=protocol,
                                   capabilities=capabilities)
        self._devices[identifier] = device
        self._save()
        return device

    def revoke(self, identifier: str) -> bool:
        if identifier not in self._devices:
            return False
        del self._devices[identifier]
        self._save()
        return True

    def list(self) -> list[AuthorizedDevice]:
        return list(self._devices.values())
