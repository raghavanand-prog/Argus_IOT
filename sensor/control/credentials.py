"""Local device-control credential storage (e.g. a PJLink password). Never in
the repository, never in Git, never logged, never sent to the frontend --
the cloud console never even asks for one; credentials are configured on the
machine running the sensor, where they're actually used.

Prefers the OS's real keychain (macOS Keychain, via the `keyring` package --
an optional dependency, `pyproject.toml`'s `live-testbed` extra) -- genuinely
never written to disk in plaintext when available. Falls back to a local
JSON file at ``~/.argus/credentials.json`` with owner-only permissions
(chmod 600) when no OS keyring backend is available (e.g. a headless Linux
box with no Secret Service running) -- a real, working, but honestly weaker
guarantee than the OS keychain, and this module says so out loud rather than
silently degrading.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

SERVICE_NAME = "argus-device-control"
FALLBACK_STORE_PATH = Path.home() / ".argus" / "credentials.json"


class CredentialStoreWarning(UserWarning):
    """Raised (as a warning, not an error) when falling back to the weaker
    file-based store because no OS keyring backend is available."""


def _try_keyring():
    try:
        import keyring
        from keyring.errors import KeyringError

        # a "fail" backend (no real OS keyring service available, e.g. this
        # sandbox, or a headless Linux box with no Secret Service running)
        # raises on first real use -- probe it rather than trusting import
        # success alone, since `keyring` always imports even with no usable backend.
        keyring.get_password(SERVICE_NAME, "__argus_probe__")
        return keyring, KeyringError
    except Exception:
        return None, None


def set_credential(identifier: str, secret: str) -> str:
    """Stores ``secret`` for device ``identifier``. Returns "keychain" or
    "file" indicating which backend was actually used -- callers (the CLI)
    should tell the user which one happened, since the security guarantee
    differs."""
    keyring, KeyringError = _try_keyring()
    if keyring is not None:
        try:
            keyring.set_password(SERVICE_NAME, identifier, secret)
            return "keychain"
        except KeyringError:
            pass  # fall through to the file backend

    FALLBACK_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    store = {}
    if FALLBACK_STORE_PATH.exists():
        try:
            store = json.loads(FALLBACK_STORE_PATH.read_text())
        except json.JSONDecodeError:
            store = {}
    store[identifier] = secret
    FALLBACK_STORE_PATH.write_text(json.dumps(store, indent=2))
    os.chmod(FALLBACK_STORE_PATH, stat.S_IRUSR | stat.S_IWUSR)  # 0600: owner read/write only
    return "file"


def get_credential(identifier: str) -> str | None:
    keyring, KeyringError = _try_keyring()
    if keyring is not None:
        try:
            value = keyring.get_password(SERVICE_NAME, identifier)
            if value is not None:
                return value
        except KeyringError:
            pass

    if FALLBACK_STORE_PATH.exists():
        try:
            store = json.loads(FALLBACK_STORE_PATH.read_text())
            return store.get(identifier)
        except json.JSONDecodeError:
            return None
    return None


def delete_credential(identifier: str) -> None:
    keyring, KeyringError = _try_keyring()
    if keyring is not None:
        try:
            keyring.delete_password(SERVICE_NAME, identifier)
        except KeyringError:
            pass

    if FALLBACK_STORE_PATH.exists():
        try:
            store = json.loads(FALLBACK_STORE_PATH.read_text())
        except json.JSONDecodeError:
            return
        if identifier in store:
            del store[identifier]
            FALLBACK_STORE_PATH.write_text(json.dumps(store, indent=2))
