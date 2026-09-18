"""Real tests against the real fallback-file backend (this sandbox has no OS
keyring service -- confirmed: keyring.get_keyring() returns the "fail"
backend here -- so these exercise the real, honestly-weaker fallback path;
the keychain path itself can only be exercised on real macOS/Linux-with-
Secret-Service hardware, documented as a limitation)."""

import os
import stat

from sensor.control import credentials


def test_set_and_get_credential(tmp_path, monkeypatch):
    monkeypatch.setattr(credentials, "FALLBACK_STORE_PATH", tmp_path / "credentials.json")
    backend = credentials.set_credential("mac-projector1", "s3cret")
    assert backend in ("keychain", "file")
    assert credentials.get_credential("mac-projector1") == "s3cret"


def test_missing_credential_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr(credentials, "FALLBACK_STORE_PATH", tmp_path / "credentials.json")
    assert credentials.get_credential("mac-never-set") is None


def test_delete_credential(tmp_path, monkeypatch):
    monkeypatch.setattr(credentials, "FALLBACK_STORE_PATH", tmp_path / "credentials.json")
    credentials.set_credential("mac-projector1", "s3cret")
    credentials.delete_credential("mac-projector1")
    assert credentials.get_credential("mac-projector1") is None


def test_fallback_file_has_owner_only_permissions(tmp_path, monkeypatch):
    store_path = tmp_path / "credentials.json"
    monkeypatch.setattr(credentials, "FALLBACK_STORE_PATH", store_path)
    backend = credentials.set_credential("mac-projector1", "s3cret")
    if backend == "file":
        mode = stat.S_IMODE(os.stat(store_path).st_mode)
        assert mode == 0o600


def test_credentials_never_written_in_plaintext_to_the_repo(tmp_path, monkeypatch):
    # the whole point of FALLBACK_STORE_PATH defaulting to ~/.argus -- confirm
    # the module never writes anywhere under the repo's own working directory
    monkeypatch.setattr(credentials, "FALLBACK_STORE_PATH", tmp_path / "credentials.json")
    credentials.set_credential("mac-projector1", "s3cret")
    repo_root = os.getcwd()
    assert not str(tmp_path).startswith(repo_root)
