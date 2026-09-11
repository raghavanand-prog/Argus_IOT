"""Risk engine: risk = weighted sum of severity, criticality, confidence, deviation,
blast radius (docs/02). Weights are authored, not learned -- and that's stated, not
hidden; a sensitivity analysis lives in eval/harness.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from argus.schemas import Detection, Incident, RiskAssessment
from argus.sim.devices import FLEET

UNRESOLVED_NEIGHBOUR_WEIGHT = 0.15  # fallback for neighbours we can't identify (e.g. true external IPs)
RESOLVED_NEIGHBOUR_SCALE = 0.3  # a single maximally-critical (1.0) known neighbour contributes 0.3

DEFAULT_WEIGHTS = {
    "severity": 0.25, "criticality": 0.20, "confidence": 0.25,
    "deviation": 0.10, "blast_radius": 0.20,
}


@dataclass
class BlastRadiusGraph:
    """Communication-graph blast radius: one-hop neighbours this device has talked
    to, weighted by their criticality when their identity is known (docs/02: "the
    hub scores highest, the air sensor lowest")."""

    edges: dict[str, set[str]]

    def score(self, device_id: str, device_type_of: Callable[[str], str | None] | None = None) -> float:
        """``device_type_of``: resolves a neighbour (an IP, or a device_id) to its
        device_type, e.g. via the device registry. A neighbour it can't resolve
        (typically a true external IP, which by construction has no registry entry)
        falls back to a fixed modest weight rather than being dropped -- an
        unidentifiable neighbour is still a neighbour, just a less informative one."""
        neighbours = self.edges.get(device_id, set())
        if not neighbours:
            return 0.0
        total = 0.0
        for n in neighbours:
            device_type = device_type_of(n) if device_type_of else None
            if device_type and device_type in FLEET:
                total += FLEET[device_type].criticality * RESOLVED_NEIGHBOUR_SCALE
            else:
                total += UNRESOLVED_NEIGHBOUR_WEIGHT
        return min(1.0, total)


def assess_risk(incident: Incident, detections: list[Detection], device_type: str,
                 deviation: float, blast_radius: float, weights: dict[str, float] | None = None
                 ) -> RiskAssessment:
    weights = weights or DEFAULT_WEIGHTS
    det_map = {d.detection_id: d for d in detections}
    incident_dets = [det_map[i] for i in incident.detection_ids if i in det_map]

    severity = max((d.severity for d in incident_dets), default=0.0)
    confidence = max((d.confidence for d in incident_dets), default=0.0)
    # a non-singleton conformal set caps confidence hard (docs/02, docs/10)
    if any(d.conformal_set and len(d.conformal_set) > 1 for d in incident_dets):
        confidence = min(confidence, 0.4)
    criticality = FLEET.get(device_type).criticality if device_type in FLEET else 0.3

    terms = {
        "severity": severity, "criticality": criticality, "confidence": confidence,
        "deviation": deviation, "blast_radius": blast_radius,
    }
    score = sum(weights[k] * v for k, v in terms.items())
    return RiskAssessment(incident_id=incident.incident_id, score=min(1.0, score), terms=terms)
