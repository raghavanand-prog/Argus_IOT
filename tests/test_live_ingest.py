"""argus.pipeline.ingest_live_observation: the production code path a real
local sensor's POST body runs through (argus/api/main.py's /live/ingest calls
this directly). Exercises real persistence through the same SQLAlchemy models
every other track uses -- LiveDeviceRow, SensorHeartbeatRow, IncidentRow,
EvidenceBundleRow -- with device/detection dicts shaped exactly like
sensor/agent.py's own _device_to_payload/_detection_to_payload output.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from argus.db.models import (
    EvidenceBundleRow,
    IncidentRow,
    LiveDeviceRow,
    SensorHeartbeatRow,
    init_db,
    make_engine,
)
from argus.pipeline import ingest_live_observation


def _device_payload(identifier="mac-aabbccddeeff"):
    now = datetime.now(UTC).isoformat()
    return {
        "identifier": identifier, "ip": "192.168.1.50", "mac": "AA:BB:CC:DD:EE:FF",
        "vendor": None, "device_type": "unknown", "interface": "eth0",
        "first_seen": now, "last_seen": now, "flow_count": 42, "monitored": True,
    }


def _detection_payload(device_id="mac-aabbccddeeff", severity=0.9):
    return {
        "detection_id": str(uuid.uuid4()), "ts": datetime.now(UTC).isoformat(),
        "device_id": device_id, "source": "live-anomaly", "signal_name": "unsupervised_baseline_deviation",
        "severity": severity, "confidence": severity, "explanation": "test detection",
        "evidence_refs": [], "conformal_set": None, "attribution": None,
    }


def test_discovery_only_ingest_persists_device_and_heartbeat_without_incident():
    engine = make_engine("sqlite:///:memory:")
    db = init_db(engine)()

    result = ingest_live_observation(
        db, sensor_id="sensor-test", hostname="test-host", monitoring_active=False,
        devices=[_device_payload()], detections=[],
    )

    assert result["devices_ingested"] == 1
    assert result["detections_received"] == 0
    assert result["incidents_generated"] == 0  # discovery alone never creates an incident

    row = db.query(LiveDeviceRow).filter_by(identifier="mac-aabbccddeeff").one()
    assert row.ip == "192.168.1.50"
    assert row.device_type == "unknown"

    heartbeat = db.query(SensorHeartbeatRow).filter_by(sensor_id="sensor-test").one()
    assert heartbeat.devices_discovered == 1
    assert heartbeat.monitoring_active is False


def test_detection_ingest_creates_real_incident_and_evidence_bundle():
    engine = make_engine("sqlite:///:memory:")
    db = init_db(engine)()

    result = ingest_live_observation(
        db, sensor_id="sensor-test", hostname="test-host", monitoring_active=True,
        devices=[_device_payload()], detections=[_detection_payload()],
    )

    assert result["detections_received"] == 1
    assert result["incidents_generated"] == 1
    assert result["bundles_generated"] == 1

    incident = db.query(IncidentRow).filter_by(scenario="live_network").one()
    assert incident.device_id == "mac-aabbccddeeff"

    bundle = db.query(EvidenceBundleRow).filter_by(incident_id=incident.incident_id).one()
    assert bundle.decision["dry_run"] is True  # never live enforcement against a real discovered device
    assert bundle.device["source"] == "live_network"


def test_empty_detections_for_a_device_never_forces_an_incident():
    engine = make_engine("sqlite:///:memory:")
    db = init_db(engine)()

    result = ingest_live_observation(
        db, sensor_id="sensor-test", hostname="test-host", monitoring_active=True,
        devices=[_device_payload(), _device_payload(identifier="mac-000000000001")],
        detections=[],
    )
    assert result["devices_ingested"] == 2
    assert result["incidents_generated"] == 0
    assert db.query(IncidentRow).filter_by(scenario="live_network").count() == 0
