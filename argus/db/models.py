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
