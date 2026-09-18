"""SQLAlchemy models -- a condensed subset of docs/11's Postgres schema, backed by
SQLite by default (set ARGUS_DATABASE_URL for Postgres; the ORM layer doesn't care).
"""

from __future__ import annotations

import os
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class DeviceRow(Base):
    __tablename__ = "devices"
    device_id: Mapped[str] = mapped_column(String, primary_key=True)
    device_type: Mapped[str] = mapped_column(String)
    criticality: Mapped[float] = mapped_column(Float, default=0.3)
    state: Mapped[str] = mapped_column(String, default="ENROLLING")
    is_drifting: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    baseline_version: Mapped[int] = mapped_column(Integer, default=0)


class IncidentRow(Base):
    __tablename__ = "incidents"
    incident_id: Mapped[str] = mapped_column(String, primary_key=True)
    device_id: Mapped[str] = mapped_column(String)
    first_seen: Mapped[datetime] = mapped_column(DateTime)
    last_seen: Mapped[datetime] = mapped_column(DateTime)
    chain_position: Mapped[str] = mapped_column(String)
    agreement_score: Mapped[float] = mapped_column(Float)
    detection_sources: Mapped[str] = mapped_column(String, default="")
    scenario: Mapped[str] = mapped_column(String, default="")
    status: Mapped[str] = mapped_column(String, default="open")


class RiskAssessmentRow(Base):
    __tablename__ = "risk_assessments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String, ForeignKey("incidents.incident_id"))
    score: Mapped[float] = mapped_column(Float)
    terms: Mapped[dict] = mapped_column(JSON)


class EvidenceBundleRow(Base):
    __tablename__ = "evidence_bundles"
    bundle_id: Mapped[str] = mapped_column(String, primary_key=True)
    incident_id: Mapped[str] = mapped_column(String, ForeignKey("incidents.incident_id"))
    created_at: Mapped[str] = mapped_column(String)
    device: Mapped[dict] = mapped_column(JSON)
    feature_vector: Mapped[dict] = mapped_column(JSON)
    detection: Mapped[dict] = mapped_column(JSON)
    baseline: Mapped[dict] = mapped_column(JSON)
    risk: Mapped[dict] = mapped_column(JSON)
    decision: Mapped[dict] = mapped_column(JSON)
    trace: Mapped[list] = mapped_column(JSON)
    prev_bundle_hash: Mapped[str] = mapped_column(String)
    merkle_root: Mapped[str] = mapped_column(String)


class ActionRow(Base):
    __tablename__ = "actions"
    action_id: Mapped[str] = mapped_column(String, primary_key=True)
    bundle_id: Mapped[str] = mapped_column(String, ForeignKey("evidence_bundles.bundle_id"))
    device_id: Mapped[str] = mapped_column(String)
    tier: Mapped[int] = mapped_column(Integer)
    action: Mapped[str] = mapped_column(String)
    dry_run: Mapped[bool] = mapped_column(Boolean)
    applied_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    reverted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ttl_seconds: Mapped[int] = mapped_column(Integer, default=900)


class VerificationRow(Base):
    __tablename__ = "verifications"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    action_id: Mapped[str] = mapped_column(String, ForeignKey("actions.action_id"))
    outcome: Mapped[str] = mapped_column(String)
    checked_at: Mapped[datetime] = mapped_column(DateTime)
    offset_seconds: Mapped[int] = mapped_column(Integer)


class CicioTEvaluationRunRow(Base):
    """One real, actually-executed CICIoT2023 evaluation run (argus/pipeline.py's
    ``run_cicioT2023_evaluation``). ``records`` and ``metrics``/``confusion_matrix``
    are computed from actual detector predictions vs. the dataset's ``sub_label``
    ground truth for this run -- never hardcoded (see docs/17). Multiple rows here
    are the "evaluation history" the IDS Evaluation page lists."""

    __tablename__ = "cicioT2023_evaluation_runs"
    run_id: Mapped[str] = mapped_column(String, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    dataset_filename: Mapped[str] = mapped_column(String)
    dataset_sha256: Mapped[str] = mapped_column(String)
    seed: Mapped[int] = mapped_column(Integer)
    feature_keys: Mapped[list] = mapped_column(JSON)
    model_config_json: Mapped[dict] = mapped_column(JSON)
    threshold: Mapped[float] = mapped_column(Float)
    n_total_rows: Mapped[int] = mapped_column(Integer)
    n_train_benign: Mapped[int] = mapped_column(Integer)
    n_calib_benign: Mapped[int] = mapped_column(Integer)
    n_calib_attack: Mapped[int] = mapped_column(Integer)
    n_test_benign: Mapped[int] = mapped_column(Integer)
    n_test_attack: Mapped[int] = mapped_column(Integer)
    confusion_matrix: Mapped[dict] = mapped_column(JSON)
    metrics: Mapped[dict] = mapped_column(JSON)
    n_incidents_generated: Mapped[int] = mapped_column(Integer)
    records: Mapped[list] = mapped_column(JSON)  # per-row: record_id, ground_truth, prediction, score, incident_id, outcome


class LiveDeviceRow(Base):
    """A device observed by a local sensor (sensor/agent.py) via passive ARP/
    neighbour-table discovery on a real LAN -- every field here is either
    read verbatim from the sensor's own observation or a deterministic,
    documented derivation of it (see sensor/discovery.py). Never seeded,
    never fabricated. identifier is stable across polls (mac-<mac> or
    ip-<ip> if no MAC was resolved)."""

    __tablename__ = "live_devices"
    identifier: Mapped[str] = mapped_column(String, primary_key=True)
    ip: Mapped[str] = mapped_column(String)
    mac: Mapped[str | None] = mapped_column(String, nullable=True)
    vendor: Mapped[str | None] = mapped_column(String, nullable=True)
    device_type: Mapped[str] = mapped_column(String, default="unknown")
    hostname: Mapped[str | None] = mapped_column(String, nullable=True)
    discovery_sources: Mapped[list] = mapped_column(JSON, default=list)
    interface: Mapped[str | None] = mapped_column(String, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime)
    last_seen: Mapped[datetime] = mapped_column(DateTime)
    flow_count: Mapped[int] = mapped_column(Integer, default=0)
    monitored: Mapped[bool] = mapped_column(Boolean, default=False)  # has a baseline/detector been fit for it
    sensor_id: Mapped[str] = mapped_column(String, default="")
    # Device Control fields below are a read-only MIRROR of state the sensor decides
    # and enforces locally (see docs/19-device-control.md) -- authorization is never
    # decided here, the cloud only displays what the sensor reports about its own
    # local authorization file and capability probes.
    control_protocol: Mapped[str | None] = mapped_column(String, nullable=True)
    control_capabilities: Mapped[list] = mapped_column(JSON, default=list)
    authorized: Mapped[bool] = mapped_column(Boolean, default=False)


class SensorHeartbeatRow(Base):
    """One row per local sensor that has ever reported in. Not a claim about
    whether it's still connected right now -- last_seen age is what the API/
    console use to decide that, exactly like any heartbeat."""

    __tablename__ = "sensor_heartbeats"
    sensor_id: Mapped[str] = mapped_column(String, primary_key=True)
    hostname: Mapped[str] = mapped_column(String)
    monitoring_active: Mapped[bool] = mapped_column(Boolean, default=False)
    devices_discovered: Mapped[int] = mapped_column(Integer, default=0)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ControlCommandRow(Base):
    """A device-control command queue entry (docs/19-device-control.md). The
    cloud API is the authoritative *queue* (console click -> row here,
    status="pending") but never the authority on whether the command is
    *allowed* -- that decision is made twice, independently: once here as a
    display-only capability/authorization check before queuing (so the
    console doesn't even show a control the sensor hasn't reported as
    authorized+supported), and again, for real, on the sensor itself against
    its own local authorization file, before it ever touches a real device.
    A row the sensor's local check rejects is recorded here as status="denied"
    with why, not silently dropped."""

    __tablename__ = "control_commands"
    command_id: Mapped[str] = mapped_column(String, primary_key=True)
    sensor_id: Mapped[str] = mapped_column(String)
    device_identifier: Mapped[str] = mapped_column(String)
    action: Mapped[str] = mapped_column(String)  # e.g. "power_on", "power_off", "get_status"
    requested_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    status: Mapped[str] = mapped_column(String, default="pending")  # pending|fulfilled|failed|denied
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ControlAuditRow(Base):
    """Read-only mirror of the sensor's own local control-action audit log
    (source of truth is the sensor's local file, per the project owner's
    explicit choice to keep authorization+audit local -- see
    docs/19-device-control.md), reported here purely for console display."""

    __tablename__ = "control_audit"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    sensor_id: Mapped[str] = mapped_column(String)
    device_identifier: Mapped[str] = mapped_column(String)
    device_ip: Mapped[str] = mapped_column(String)
    action: Mapped[str] = mapped_column(String)
    protocol: Mapped[str] = mapped_column(String)
    result: Mapped[str] = mapped_column(String)  # SUCCESS|FAILURE|DENIED
    authorization_state: Mapped[str] = mapped_column(String)


class AuditLogRow(Base):
    __tablename__ = "audit_log"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    actor: Mapped[str] = mapped_column(String)
    event_type: Mapped[str] = mapped_column(String)
    payload: Mapped[dict] = mapped_column(JSON)


def make_engine(url: str | None = None):
    url = url or os.getenv("ARGUS_DATABASE_URL", "sqlite:///./argus.db")
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=connect_args)


def init_db(engine) -> sessionmaker:
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)
