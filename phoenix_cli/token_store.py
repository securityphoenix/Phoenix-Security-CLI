"""Login tokens in the operating system keychain.

One stored login per base URL (keyring service ``phoenix-cli``, username =
base URL). A token is never written to a file and never logged.
"""

from __future__ import annotations

import json

SERVICE = "phoenix-cli"
_MISSING = "install phoenix-security-cli[keyring] to store a login"


def _keyring():
    try:
        import keyring
    except ImportError:
        return None
    return keyring


def _key(base_url: str) -> str:
    return base_url.rstrip("/")


def save_token(base_url: str, token: str, expires_at: int) -> None:
    kr = _keyring()
    if kr is None:
        raise RuntimeError(_MISSING)
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
    except Exception:  # noqa: BLE001, S110 - nothing to clear is fine
        pass
