"""Real tests for the capability probe + the single enforcement checkpoint
(execute_command) -- the core safety property of this whole subsystem: local
authorization is checked every time, regardless of who's asking, and nothing
happens without it. Uses tmp_path for real (not mocked) file-backed
AuthorizationStore/AuditLog instances, and a real MockPJLinkServer for actual
protocol calls.
"""

from sensor.control.audit import AuditLog
from sensor.control.authorization import AuthorizationStore
from sensor.control.registry import (
    CONFIRMATION_REQUIRED_ACTIONS,
    execute_command,
    probe_capability,
)
from tests.control.mock_pjlink_server import MockPJLinkServer


def test_probe_capability_detects_real_pjlink_device():
    server = MockPJLinkServer(password=None)
    server.start()
    try:
        cap = probe_capability("mac-aabbccddeeff", "127.0.0.1", timeout=1.0, port=server.port)
        assert cap.reachable is True
        assert cap.protocol == "pjlink"
        assert cap.capabilities == ["power", "input", "mute", "status"]
    finally:
        server.stop()


def test_probe_capability_no_response_reports_unsupported():
    cap = probe_capability("mac-000000000001", "127.0.0.1", timeout=0.3)
    assert cap.reachable is False
    assert cap.protocol is None
    assert cap.capabilities == []


def test_execute_command_denied_when_not_authorized(tmp_path):
    auth_store = AuthorizationStore(path=tmp_path / "auth.json")
    audit_log = AuditLog(path=tmp_path / "audit.jsonl")

    result = execute_command(
        "mac-aabbccddeeff", "192.168.1.50", "power_off",
        auth_store=auth_store, audit_log=audit_log, requested_by="cloud-console",
    )
    assert result["result"] == "DENIED"

    entries = audit_log.read_all()
    assert len(entries) == 1
    assert entries[0]["result"] == "DENIED"
    assert entries[0]["authorization_state"] == "not_authorized"
    assert entries[0]["requested_by"] == "cloud-console"


def test_execute_command_denied_even_when_cloud_claims_authorization(tmp_path):
    """The critical property: execute_command NEVER trusts a caller's claim
    that a device is authorized -- it only trusts its own local store. This
    test simulates exactly the attack scenario the design defends against: a
    compromised/malicious caller invoking execute_command for a device that
    was never actually authorized on this machine."""
    auth_store = AuthorizationStore(path=tmp_path / "auth.json")
    audit_log = AuditLog(path=tmp_path / "audit.jsonl")
    # deliberately NOT calling auth_store.authorize() -- nothing has authorized this device

    result = execute_command(
        "mac-attacker-target", "192.168.1.99", "power_off",
        auth_store=auth_store, audit_log=audit_log, requested_by="cloud-console",
    )
    assert result["result"] == "DENIED"
    assert auth_store.is_authorized("mac-attacker-target") is False


def test_execute_command_succeeds_when_authorized_and_supported(tmp_path):
    server = MockPJLinkServer(password=None)
    server.start()
    try:
        auth_store = AuthorizationStore(path=tmp_path / "auth.json")
        audit_log = AuditLog(path=tmp_path / "audit.jsonl")
        auth_store.authorize("mac-projector1", "127.0.0.1", "AA:BB:CC:DD:EE:FF", "pjlink",
                              capabilities=["power", "status"])

        result = execute_command(
            "mac-projector1", "127.0.0.1", "power_on",
            auth_store=auth_store, audit_log=audit_log, port=server.port,
        )
        assert result["result"] == "SUCCESS"
        assert server.state["power"] == "1"

        entries = audit_log.read_all()
        assert len(entries) == 1
        assert entries[0]["result"] == "SUCCESS"
        assert entries[0]["authorization_state"] == "authorized"
        assert entries[0]["protocol"] == "pjlink"
    finally:
        server.stop()


def test_execute_command_get_status_needs_no_confirmation_and_reflects_real_state(tmp_path):
    server = MockPJLinkServer(password=None)
    server.start()
    try:
        server.state["power"] = "1"
        auth_store = AuthorizationStore(path=tmp_path / "auth.json")
        audit_log = AuditLog(path=tmp_path / "audit.jsonl")
        auth_store.authorize("mac-projector1", "127.0.0.1", None, "pjlink", capabilities=["status"])

        result = execute_command(
            "mac-projector1", "127.0.0.1", "get_status",
            auth_store=auth_store, audit_log=audit_log, port=server.port,
        )
        assert result["result"] == "SUCCESS"
        assert "power=on" in result["detail"]
    finally:
        server.stop()


def test_execute_command_unsupported_action_fails_cleanly(tmp_path):
    auth_store = AuthorizationStore(path=tmp_path / "auth.json")
    audit_log = AuditLog(path=tmp_path / "audit.jsonl")
    auth_store.authorize("mac-projector1", "192.168.1.50", None, "pjlink", capabilities=["power"])

    result = execute_command(
        "mac-projector1", "192.168.1.50", "self_destruct",
        auth_store=auth_store, audit_log=audit_log,
    )
    assert result["result"] == "FAILURE"
    assert "unsupported action" in result["detail"]


def test_execute_command_unsupported_protocol_fails_cleanly(tmp_path):
    auth_store = AuthorizationStore(path=tmp_path / "auth.json")
    audit_log = AuditLog(path=tmp_path / "audit.jsonl")
    auth_store.authorize("mac-other-device", "192.168.1.60", None, "some-other-protocol", capabilities=[])

    result = execute_command(
        "mac-other-device", "192.168.1.60", "power_on",
        auth_store=auth_store, audit_log=audit_log,
    )
    assert result["result"] == "FAILURE"
    assert "no control implementation" in result["detail"]


def test_disruptive_actions_require_confirmation_set_is_correct():
    assert "power_off" in CONFIRMATION_REQUIRED_ACTIONS
    assert "power_on" in CONFIRMATION_REQUIRED_ACTIONS
    assert "get_status" not in CONFIRMATION_REQUIRED_ACTIONS


def test_revoked_device_is_denied_again(tmp_path):
    auth_store = AuthorizationStore(path=tmp_path / "auth.json")
    audit_log = AuditLog(path=tmp_path / "audit.jsonl")
    auth_store.authorize("mac-projector1", "192.168.1.50", None, "pjlink", capabilities=["power"])
    assert auth_store.is_authorized("mac-projector1") is True

    auth_store.revoke("mac-projector1")
    assert auth_store.is_authorized("mac-projector1") is False

    result = execute_command(
        "mac-projector1", "192.168.1.50", "power_off",
        auth_store=auth_store, audit_log=audit_log,
    )
    assert result["result"] == "DENIED"
