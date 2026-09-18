from sensor.control.authorization import AuthorizationStore
from sensor.control_cli import _resolve_identifier, main


def test_resolve_identifier_finds_by_stored_ip(tmp_path):
    auth_store = AuthorizationStore(path=tmp_path / "auth.json")
    auth_store.authorize("mac-aabbccddeeff", "192.168.1.50", "AA:BB:CC:DD:EE:FF", "pjlink", [])
    identifier, ip = _resolve_identifier(auth_store, "192.168.1.50")
    assert identifier == "mac-aabbccddeeff"
    assert ip == "192.168.1.50"


def test_resolve_identifier_falls_back_to_ip_convention_for_unknown_ip(tmp_path):
    auth_store = AuthorizationStore(path=tmp_path / "auth.json")
    identifier, ip = _resolve_identifier(auth_store, "192.168.1.99")
    assert identifier == "ip-192.168.1.99"
    assert ip == "192.168.1.99"


def test_resolve_identifier_accepts_already_built_identifier(tmp_path):
    auth_store = AuthorizationStore(path=tmp_path / "auth.json")
    auth_store.authorize("mac-x", "10.0.0.1", None, "pjlink", [])
    identifier, ip = _resolve_identifier(auth_store, "mac-x")
    assert identifier == "mac-x"
    assert ip == "10.0.0.1"


def test_list_with_no_devices(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr("sensor.control_cli.AuthorizationStore", lambda: AuthorizationStore(path=tmp_path / "auth.json"))
    main_argv = ["list"]
    import sys
    monkeypatch.setattr(sys, "argv", ["control_cli.py", *main_argv])
    rc = main()
    out = capsys.readouterr().out
    assert rc == 0
    assert "No devices authorized" in out


def test_discover_capability_reports_unsupported_for_unreachable_device(monkeypatch, capsys):
    import sys
    monkeypatch.setattr(sys, "argv", ["control_cli.py", "discover-capability", "127.0.0.1"])
    # nothing is listening on the default PJLink port in this test environment
    rc = main()
    out = capsys.readouterr().out
    assert rc == 0
    assert "no supported control protocol detected" in out
