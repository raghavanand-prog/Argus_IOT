"""Risk engine: risk = weighted sum of severity, criticality, confidence, deviation,
blast radius (docs/02). Weights are authored, not learned -- and that's stated, not
hidden; a sensitivity analysis lives in eval/harness.py.
"""

from __future__ import annotations

from dataclasses import dataclass

from argus.schemas import Detection, Incident, RiskAssessment
from argus.sim.devices import FLEET

DEFAULT_WEIGHTS = {
    "severity": 0.25, "criticality": 0.20, "confidence": 0.25,
    "deviation": 0.10, "blast_radius": 0.20,
}


@dataclass
class BlastRadiusGraph:
    """Minimal communication-graph blast radius: number of other devices this device
    has talked to (one-hop neighbours), weighted by their criticality (docs/02)."""

    edges: dict[str, set[str]]

    def score(self, device_id: str) -> float:
        """Neighbours are IPs (usually external); a fixed modest per-neighbour weight
        stands in for "weighted by their criticality" until the registry tracks
        IP-to-device-type identity for intra-LAN neighbours too (see STATUS.md)."""
        neighbours = self.edges.get(device_id, set())
        return min(1.0, len(neighbours) * 0.15)


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
