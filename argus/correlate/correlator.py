"""Correlator: groups raw detections into incidents (docs/02).

Effect on F1 is expected to be ~zero -- it neither finds nor loses detections. Its
effect is on alert volume and time-to-contain, which is why it's instrumented
separately in the evaluation harness (this asymmetry is the direct evidence for H2).
"""

from __future__ import annotations

import uuid
from datetime import timedelta

from argus.schemas import Detection, Incident

WINDOW = timedelta(minutes=5)


def correlate(detections: list[Detection]) -> list[Incident]:
    if not detections:
        return []
    by_device: dict[str, list[Detection]] = {}
    for d in detections:
        by_device.setdefault(d.device_id, []).append(d)

    incidents: list[Incident] = []
    for device_id, dets in by_device.items():
        dets = sorted(dets, key=lambda d: d.ts)
        group: list[Detection] = [dets[0]]
        for d in dets[1:]:
            if d.ts - group[-1].ts <= WINDOW:
                group.append(d)
            else:
                incidents.append(_to_incident(device_id, group))
                group = [d]
        incidents.append(_to_incident(device_id, group))
    return incidents


def _to_incident(device_id: str, group: list[Detection]) -> Incident:
    sources = {d.source for d in group}
    agreement = len(sources) / 3.0  # 3 possible sources: policy, rules, ml
    return Incident(
        incident_id=str(uuid.uuid4()),
        first_seen=min(d.ts for d in group),
        last_seen=max(d.ts for d in group),
        device_ids=[device_id],
        detection_ids=[d.detection_id for d in group],
        chain_position="/".join(sorted({d.signal_name for d in group})),
        agreement_score=agreement,
    )
