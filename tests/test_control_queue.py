"""Real assertions on argus.control's command queue + state-mirror logic,
against a real in-memory SQLite DB -- the same code path
argus/api/main.py's /live/control/* endpoints call, verified directly with
its own real integration test earlier this session (see progress.md), now
pinned down as proper pytest coverage.
"""

from datetime import datetime

from argus.control import (
    append_control_audit,
    list_control_audit,
    list_pending_commands,
    queue_control_command,
    report_command_result,
    upsert_control_device_state,
)
from argus.db.models import LiveDeviceRow, init_db, make_engine


def _db():
    engine = make_engine("sqlite:///:memory:")
    return init_db(engine)()


def _seed_device(db, identifier="mac-projector1", ip="192.168.1.50"):
    db.add(LiveDeviceRow(
        identifier=identifier, ip=ip, mac="AA:BB:CC:DD:EE:FF", vendor=None,
        device_type="unknown", interface="en0",
        first_seen=datetime.utcnow(), last_seen=datetime.utcnow(),
        flow_count=0, monitored=False, sensor_id="sensor-test",
    ))
    db.commit()


def test_queue_command_returns_pending_status():
    db = _db()
    result = queue_control_command(db, sensor_id="sensor-test", device_identifier="mac-x", action="power_on")
    assert result["status"] == "pending"
    assert "command_id" in result


def test_list_pending_commands_filters_by_sensor():
    db = _db()
    queue_control_command(db, sensor_id="sensor-a", device_identifier="mac-x", action="power_on")
    queue_control_command(db, sensor_id="sensor-b", device_identifier="mac-y", action="power_off")

    pending_a = list_pending_commands(db, "sensor-a")
    assert len(pending_a) == 1
    assert pending_a[0]["device_identifier"] == "mac-x"


def test_report_result_removes_command_from_pending():
    db = _db()
    result = queue_control_command(db, sensor_id="sensor-a", device_identifier="mac-x", action="power_on")
    command_id = result["command_id"]

    assert len(list_pending_commands(db, "sensor-a")) == 1
    found = report_command_result(db, command_id, "fulfilled", {"result": "SUCCESS"})
    assert found is True
    assert len(list_pending_commands(db, "sensor-a")) == 0


def test_report_result_for_unknown_command_returns_false():
    db = _db()
    found = report_command_result(db, "nonexistent-id", "fulfilled", {})
    assert found is False


def test_upsert_control_device_state_preserved_across_rediscovery():
    """Regression test for the real bug found and fixed this session: a plain
    discovery re-ingest (db.merge with a fresh LiveDeviceRow) must never wipe
    control_protocol/control_capabilities/authorized -- see the dated
    decisions.md entry and argus/pipeline.py::ingest_live_observation."""
    db = _db()
    _seed_device(db)
    upsert_control_device_state(db, "sensor-test", [
        {"identifier": "mac-projector1", "protocol": "pjlink", "capabilities": ["power", "status"], "authorized": True},
    ])
    row = db.query(LiveDeviceRow).filter_by(identifier="mac-projector1").first()
    assert row.control_protocol == "pjlink"
    assert row.authorized is True

    # simulate a subsequent plain re-ingest via the same merge pattern ingest_live_observation uses
    from argus.pipeline import ingest_live_observation
    ingest_live_observation(
        db, sensor_id="sensor-test", hostname="test-mac", monitoring_active=False,
        devices=[{
            "identifier": "mac-projector1", "ip": "192.168.1.50", "mac": "AA:BB:CC:DD:EE:FF",
            "vendor": None, "device_type": "unknown",
            "first_seen": datetime.utcnow().isoformat(), "last_seen": datetime.utcnow().isoformat(),
            "flow_count": 5, "monitored": False,
        }],
        detections=[],
    )
    row = db.query(LiveDeviceRow).filter_by(identifier="mac-projector1").first()
    assert row.control_protocol == "pjlink", "control state must survive a plain re-discovery ingest"
    assert row.authorized is True
    assert row.flow_count == 5  # the re-ingest's own real field update did take effect


def test_upsert_control_device_state_ignores_unknown_device():
    db = _db()
    # no device seeded -- upsert must not crash or create a phantom row
    upsert_control_device_state(db, "sensor-test", [
        {"identifier": "mac-never-discovered", "protocol": "pjlink", "capabilities": [], "authorized": True},
    ])
    assert db.query(LiveDeviceRow).filter_by(identifier="mac-never-discovered").first() is None


def test_control_audit_append_and_list():
    db = _db()
    append_control_audit(db, "sensor-test", [{
        "ts": datetime.utcnow().isoformat(), "device_identifier": "mac-x", "device_ip": "10.0.0.1",
        "action": "power_off", "protocol": "pjlink", "result": "SUCCESS", "authorization_state": "authorized",
    }])
    entries = list_control_audit(db)
    assert len(entries) == 1
    assert entries[0]["result"] == "SUCCESS"


def test_control_audit_orders_newest_first():
    db = _db()
    append_control_audit(db, "sensor-test", [{
        "ts": "2026-01-01T00:00:00", "device_identifier": "mac-x", "device_ip": "10.0.0.1",
        "action": "get_status", "protocol": "pjlink", "result": "SUCCESS", "authorization_state": "authorized",
    }])
    append_control_audit(db, "sensor-test", [{
        "ts": "2026-01-02T00:00:00", "device_identifier": "mac-x", "device_ip": "10.0.0.1",
        "action": "power_off", "protocol": "pjlink", "result": "SUCCESS", "authorization_state": "authorized",
    }])
    entries = list_control_audit(db)
    assert entries[0]["action"] == "power_off"  # most recent first
