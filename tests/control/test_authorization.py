from sensor.control.authorization import AuthorizationStore


def test_device_starts_unauthorized(tmp_path):
    store = AuthorizationStore(path=tmp_path / "auth.json")
    assert store.is_authorized("mac-aabbccddeeff") is False
    assert store.get("mac-aabbccddeeff") is None


def test_authorize_then_persists_across_new_instance(tmp_path):
    path = tmp_path / "auth.json"
    store = AuthorizationStore(path=path)
    store.authorize("mac-aabbccddeeff", "192.168.1.50", "AA:BB:CC:DD:EE:FF", "pjlink", ["power", "status"])

    reloaded = AuthorizationStore(path=path)
    assert reloaded.is_authorized("mac-aabbccddeeff") is True
    device = reloaded.get("mac-aabbccddeeff")
    assert device.ip == "192.168.1.50"
    assert device.protocol == "pjlink"
    assert device.capabilities == ["power", "status"]


def test_revoke_removes_authorization(tmp_path):
    store = AuthorizationStore(path=tmp_path / "auth.json")
    store.authorize("mac-x", "10.0.0.1", None, "pjlink", [])
    assert store.is_authorized("mac-x") is True
    assert store.revoke("mac-x") is True
    assert store.is_authorized("mac-x") is False


def test_revoke_unknown_device_returns_false(tmp_path):
    store = AuthorizationStore(path=tmp_path / "auth.json")
    assert store.revoke("mac-never-authorized") is False


def test_list_returns_all_authorized_devices(tmp_path):
    store = AuthorizationStore(path=tmp_path / "auth.json")
    store.authorize("mac-a", "10.0.0.1", None, "pjlink", [])
    store.authorize("mac-b", "10.0.0.2", None, "pjlink", [])
    identifiers = {d.identifier for d in store.list()}
    assert identifiers == {"mac-a", "mac-b"}


def test_corrupted_store_raises_rather_than_silently_treating_everything_as_unauthorized(tmp_path):
    path = tmp_path / "auth.json"
    path.write_text("{not valid json")
    try:
        AuthorizationStore(path=path)
        raised = False
    except RuntimeError:
        raised = True
    assert raised, "a corrupted store must surface loudly, not silently degrade"
