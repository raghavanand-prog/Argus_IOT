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

    def ingest(self, sensor_id: str, hostname: str, monitoring_active: bool,
               devices: list[dict], detections: list[dict]) -> dict:
        return self._post("/live/ingest", {
            "sensor_id": sensor_id, "hostname": hostname, "monitoring_active": monitoring_active,
            "devices": devices, "detections": detections,
        })

    def check_reachable(self) -> tuple[bool, str]:
        url = self.base_url.rstrip("/") + "/health"
        try:
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self.token}"})
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                return True, f"{resp.status} {url}"
        except urllib.error.URLError as e:
            return False, f"{url}: {e}"
