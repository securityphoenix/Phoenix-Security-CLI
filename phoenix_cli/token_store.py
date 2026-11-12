"""Login tokens in the operating system keychain.

One stored login per base URL (keyring service ``phoenix-cli``, username =
base URL). A token is never written to a file and never logged.
"""

from __future__ import annotations

import json

SERVICE = "phoenix-cli"
_MISSING = "install phoenix-security-cli[keyring] to store a login"
_NO_KEYCHAIN = ("no operating system keychain is available to store a login "
                "(a file-based keyring backend is not accepted)")


def _keyring():
    try:
        import keyring
    except ImportError:
        return None
    return keyring


# Backends that keep a token in a file or throw it away are not a keychain.
_NOT_A_KEYCHAIN = ("keyrings.alt", "keyring.backends.fail",
                   "keyring.backends.null")


def ensure_available() -> None:
    """Raise ``RuntimeError`` unless an operating system keychain can hold a
    login: the extra is installed and the backend that would take the write
    is not a file, null or failing backend."""
    kr = _keyring()
    if kr is None:
        raise RuntimeError(_MISSING)
    get_backend = getattr(kr, "get_keyring", None)
    if get_backend is None:
        return
    backend = get_backend()
    chain = getattr(backend, "backends", None)
    if chain is not None:  # chained backends: the first one takes the write
        chain = list(chain)
        if not chain:
            raise RuntimeError(_NO_KEYCHAIN)
        backend = chain[0]
    if type(backend).__module__.startswith(_NOT_A_KEYCHAIN):
        raise RuntimeError(_NO_KEYCHAIN)


def _key(base_url: str) -> str:
    return base_url.rstrip("/")


def save_token(base_url: str, token: str, expires_at: int) -> None:
    ensure_available()
    kr = _keyring()
    kr.set_password(SERVICE, _key(base_url),
                    json.dumps({"token": token, "expires_at": int(expires_at)}))


def load_token(base_url: str) -> tuple[str, int] | None:
    kr = _keyring()
    if kr is None:
        return None
    try:
        raw = kr.get_password(SERVICE, _key(base_url))
    except Exception:  # noqa: BLE001 - any keychain failure means no login
        return None
    if not raw:
        return None
    try:
        data = json.loads(raw)
        return str(data["token"]), int(data["expires_at"])
    except (ValueError, KeyError, TypeError):
        return None


def clear_token(base_url: str) -> None:
    kr = _keyring()
    if kr is None:
        return
    try:
        kr.delete_password(SERVICE, _key(base_url))
    except Exception as exc:  # noqa: BLE001 - a backend raises its own errors
        # An entry that is already absent is success; anything else is not.
        try:
            still_there = kr.get_password(SERVICE, _key(base_url))
        except Exception:  # noqa: BLE001
            still_there = True
        if still_there:
            raise RuntimeError(
                "could not remove the stored login from the keychain") from exc
