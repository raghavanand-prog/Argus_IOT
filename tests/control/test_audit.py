from sensor.control.audit import AuditLog, ControlAuditEntry


def test_empty_log_returns_empty_list(tmp_path):
    log = AuditLog(path=tmp_path / "audit.jsonl")
    assert log.read_all() == []


def test_record_then_read_back(tmp_path):
    log = AuditLog(path=tmp_path / "audit.jsonl")
    entry = ControlAuditEntry(
        device_identifier="mac-x", device_ip="10.0.0.1", action="power_off",
        protocol="pjlink", result="SUCCESS", authorization_state="authorized",
        requested_by="local-cli", detail="power off command sent",
    )
    log.record(entry)
    entries = log.read_all()
    assert len(entries) == 1
    assert entries[0]["device_identifier"] == "mac-x"
    assert entries[0]["result"] == "SUCCESS"


def test_multiple_entries_preserve_order(tmp_path):
    log = AuditLog(path=tmp_path / "audit.jsonl")
    for i in range(5):
        log.record(ControlAuditEntry(
            device_identifier=f"mac-{i}", device_ip="10.0.0.1", action="get_status",
            protocol="pjlink", result="SUCCESS", authorization_state="authorized",
            requested_by="local-cli",
        ))
    entries = log.read_all()
    assert [e["device_identifier"] for e in entries] == [f"mac-{i}" for i in range(5)]


def test_read_since_returns_only_new_entries(tmp_path):
    log = AuditLog(path=tmp_path / "audit.jsonl")
    for i in range(3):
        log.record(ControlAuditEntry(
            device_identifier=f"mac-{i}", device_ip="10.0.0.1", action="get_status",
            protocol="pjlink", result="SUCCESS", authorization_state="authorized",
            requested_by="local-cli",
        ))
    new_entries = log.read_since(2)
    assert len(new_entries) == 1
    assert new_entries[0]["device_identifier"] == "mac-2"


def test_denied_attempts_are_recorded_not_dropped(tmp_path):
    log = AuditLog(path=tmp_path / "audit.jsonl")
    log.record(ControlAuditEntry(
        device_identifier="mac-unauth", device_ip="10.0.0.2", action="power_off",
        protocol="unknown", result="DENIED", authorization_state="not_authorized",
        requested_by="cloud-console", detail="device is not authorized for control on this machine",
    ))
    entries = log.read_all()
    assert len(entries) == 1
    assert entries[0]["result"] == "DENIED"
