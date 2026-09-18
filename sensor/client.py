"""Thin HTTP client for the sensor to talk to an ARGUS API -- local dev
(argus/api/main.py) or the deployed production one (api/index.py) -- over
plain HTTPS with a bearer token. Stdlib-only (urllib), so the sensor has no
dependency beyond what's already in pyproject.toml (scapy, for optional
capture) -- kept installable with one command on a Mac or a Raspberry Pi.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass
class ArgusApiClient:
    base_url: str  # e.g. "http://localhost:8000" or "https://argus-iot-live.vercel.app/api"
    token: str
    timeout_s: float = 10.0

    def _post(self, path: str, payload: dict) -> dict:
        url = self.base_url.rstrip("/") + path
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.token}"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
            return json.loads(resp.read())

    def _get(self, path: str) -> object:
        url = self.base_url.rstrip("/") + path
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self.token}"})
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
            return json.loads(resp.read())

    def ingest(self, sensor_id: str, hostname: str, monitoring_active: bool,
               devices: list[dict], detections: list[dict]) -> dict:
        return self._post("/live/ingest", {
            "sensor_id": sensor_id, "hostname": hostname, "monitoring_active": monitoring_active,
            "devices": devices, "detections": detections,
        })

    def report_control_state(self, sensor_id: str, control_devices: list[dict],
                              audit_entries: list[dict]) -> dict:
        """Reports this sensor's own local authorization/capability state
        (never decided by the cloud -- see sensor/control/registry.py) and any
        new local audit-log entries, purely for console display."""
        return self._post("/live/control/report", {
            "sensor_id": sensor_id, "control_devices": control_devices, "audit_entries": audit_entries,
        })

    def poll_control_commands(self, sensor_id: str) -> list[dict]:
        """Pending commands the console has queued for this sensor_id. The
        sensor must independently re-verify authorization against its own
        local store before executing any of these -- this list is an
        *intent*, never a pre-authorized instruction (see
        sensor/control/registry.py::execute_command)."""
        return self._get(f"/live/control/commands?sensor_id={sensor_id}&status=pending")

    def report_command_result(self, command_id: str, status: str, result: dict) -> dict:
        return self._post(f"/live/control/commands/{command_id}/result", {
            "status": status, "result": result,
        })

    def check_reachable(self) -> tuple[bool, str]:
        url = self.base_url.rstrip("/") + "/health"
        try:
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self.token}"})
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                return True, f"{resp.status} {url}"
        except urllib.error.URLError as e:
            return False, f"{url}: {e}"
