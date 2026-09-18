"""Local, append-only device-control audit log -- the source of truth (per
the project owner's explicit choice), stored at
``~/.argus/control_audit.jsonl`` (one JSON object per line). Every control
action attempt is recorded here, including denied/unauthorized attempts --
completeness matters more than tidiness for an audit trail. The sensor also
reports these entries to the cloud API for console display (a read-only
mirror), but this local file is what's actually authoritative.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

DEFAULT_LOG_PATH = Path.home() / ".argus" / "control_audit.jsonl"


@dataclass
class ControlAuditEntry:
    device_identifier: str
    device_ip: str
    action: str
    protocol: str
    result: str  # "SUCCESS" | "FAILURE" | "DENIED"
    authorization_state: str  # "authorized" | "not_authorized"
    requested_by: str  # "local-cli" | "cloud-console" | sensor_id of the requester
    detail: str = ""
    ts: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


class AuditLog:
    def __init__(self, path: Path | None = None):
        self.path = path or DEFAULT_LOG_PATH

    def record(self, entry: ControlAuditEntry) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a") as f:
            f.write(json.dumps(asdict(entry)) + "\n")

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        entries = []
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries

    def read_since(self, seq: int) -> list[dict]:
        """Entries at or after line index ``seq`` -- used when reporting new
        entries to the cloud without re-sending the whole history every poll."""
        return self.read_all()[seq:]
