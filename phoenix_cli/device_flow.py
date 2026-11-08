"""OAuth 2.0 device authorisation (RFC 8628) against Phoenix.

``device_login`` shows the person a code and a link, then polls until they
approve in the browser. The token is returned to the caller; this module never
stores or prints it.
"""

from __future__ import annotations

import time

import click
import requests

from phoenix_cli.errors import PhoenixAPIError, PhoenixAuthError

CODE_PATH = "/v1/auth/device/code"
TOKEN_PATH = "/v1/auth/device/token"
SLOW_DOWN_STEP = 5
DEFAULT_INTERVAL = 5
DEFAULT_EXPIRES_IN = 900


def _post(base_url: str, path: str, body: dict, timeout: int):
    return requests.post(base_url.rstrip("/") + path, json=body, timeout=timeout)


def _json(response) -> dict:
    try:
        data = response.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def device_login(base_url: str, client_name: str, *, sleep=time.sleep,
                 echo=click.echo, timeout: int = 30) -> tuple[str, int]:
    """Run the device flow; returns ``(token, expires_at)`` (unix seconds)."""
    response = _post(base_url, CODE_PATH, {"clientName": client_name}, timeout)
    if response.status_code != 200:
        raise PhoenixAPIError(response.status_code, response.text[:500],
                              "POST", CODE_PATH, body=response.text)
    grant = _json(response)
    device_code = grant["device_code"]
    interval = int(grant.get("interval") or DEFAULT_INTERVAL)
    expires_in = int(grant.get("expires_in") or DEFAULT_EXPIRES_IN)
    echo("Open this link in your browser and approve the login:")
    echo(f"  {grant.get('verification_uri_complete') or grant.get('verification_uri')}")
    echo(f"Code: {grant['user_code']}")

    waited = 0
    while True:
        reply = _post(base_url, TOKEN_PATH, {"device_code": device_code}, timeout)
        data = _json(reply)
        if reply.status_code == 200 and data.get("access_token"):
            token_expires_in = int(data.get("expires_in") or 3600)
            return data["access_token"], int(time.time()) + token_expires_in
        error = data.get("error")
        if error == "authorization_pending":
            pass
        elif error == "slow_down":
            interval += SLOW_DOWN_STEP
        elif error == "expired_token":
            raise PhoenixAuthError("The login code expired. Run \"phx login\" again.")
        elif error == "access_denied":
            raise PhoenixAuthError("The login was denied in Phoenix.")
        else:
            raise PhoenixAPIError(reply.status_code, reply.text[:500],
                                  "POST", TOKEN_PATH, body=reply.text)
        if waited >= expires_in:
            raise PhoenixAuthError("The login code expired. Run \"phx login\" again.")
        sleep(interval)
        waited += interval
