"""Typed data-flow contracts shared across every stage of the loop.

Each pipeline stage consumes only these schemas, never another stage's internal state.
That's what makes the ablation runner possible later: a stage can be swapped for a
pass-through without touching its neighbours (see docs/01-architecture.md).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class DeviceState(str, Enum):
    ENROLLING = "ENROLLING"
    MONITORED = "MONITORED"
    DRIFTING = "DRIFTING"
    QUARANTINED = "QUARANTINED"
    REFUSED = "REFUSED"


@dataclass
class FlowRecord:
    """One bidirectional flow, produced by collection."""

    flow_id: str
    device_id: str
    ts_start: datetime
    ts_end: datetime
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str  # "tcp" | "udp"
    pkts_out: int
    pkts_in: int
    bytes_out: int
    bytes_in: int
    tls_ja4: str | None
    dns_qname: str | None
    label: str  # "benign" | "attack:<scenario>:<phase>"


@dataclass
class FeatureVector:
    """Metadata-only features for one flow, grouped per docs/02."""

    flow_id: str
    device_id: str
    window_start: datetime
    window_end: datetime
    values: dict[str, float]
    extractor_version: str = "v1"


@dataclass
class GroundTruthEvent:
    """One labelled attack phase, emitted by the orchestrator at action time."""

    event_id: str
    scenario: str
    phase: str
    t_start: datetime
    t_end: datetime
    src: str
    dst: list[str]
    technique: str
    expected_observable: bool = True


@dataclass
class Detection:
    """Common schema regardless of which source fired."""

    detection_id: str
    ts: datetime
    device_id: str
    source: str  # "policy" | "rules" | "ml"
    signal_name: str
    severity: float  # 0..1
    confidence: float  # calibrated where meaningful
    explanation: str
    evidence_refs: list[str] = field(default_factory=list)
    conformal_set: list[str] | None = None
    attribution: list[dict] | None = None  # SHAP top-N contributions (docs/09 Layer 2), ML detections only


@dataclass
class Incident:
    incident_id: str
    first_seen: datetime
    last_seen: datetime
    device_ids: list[str]
    detection_ids: list[str]
    chain_position: str
    agreement_score: float
    status: str = "open"


@dataclass
class RiskAssessment:
    incident_id: str
    score: float
    terms: dict[str, float]
    weights_version: str = "v1"


@dataclass
class Decision:
    bundle_id: str
    action: str
    tier: int
    dry_run: bool
    gates_passed: list[str]
    gates_failed: list[str]
    guard_verdict: str  # "allow" | "veto"


@dataclass
class VerificationResult:
    action_id: str
    checked_at: datetime
    offset_seconds: int
    outcome: str  # contained | partially_contained | not_contained | collateral_damage | inconclusive
    details: dict[str, str] = field(default_factory=dict)
