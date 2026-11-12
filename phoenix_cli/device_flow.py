"""OAuth 2.0 device authorisation (RFC 8628) against Phoenix.

``device_login`` shows the person a code and a link, then polls until they
approve in the browser. The token is returned to the caller; this module never
stores or prints it.
"""

from __future__ import annotations

import re
import time
from urllib.parse import urlsplit

import click
import requests

from phoenix_cli.config import is_secure_base_url, require_secure_base_url
from phoenix_cli.errors import PhoenixAPIError, PhoenixAuthError

CODE_PATH = "/v1/auth/device/code"
TOKEN_PATH = "/v1/auth/device/token"
SLOW_DOWN_STEP = 5
DEFAULT_INTERVAL = 5
DEFAULT_EXPIRES_IN = 900


_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _clean(text) -> str:
    """Drop control characters (terminal escape sequences) from server text."""
    return _CONTROL.sub("", str(text))


def _tenant_domain(host: str) -> str:
    """The domain a tenant's API and web app share.

    Rule: drop the first label of the base host when it has 3 or more labels
    (``api.demo.appsecphx.io`` -> ``demo.appsecphx.io``); otherwise keep it.
    A link host is accepted if it equals this domain or is a subdomain of it.
    No public-suffix list: a base host like ``x.co.uk`` would give ``co.uk``
    (known limit). IP literals must match exactly.
    """
    labels = host.split(".")
    if ":" in host or all(label.isdigit() for label in labels):
        return host
    return ".".join(labels[1:]) if len(labels) >= 3 else host


def _link_to_show(base_url: str, grant: dict):
    """A server-supplied link, only if https (or local), no userinfo, no
    odd port, and on the base URL's tenant domain (the web app host differs
    from the API host)."""
    try:
        base = urlsplit(base_url)
        base_host = (base.hostname or "").lower()
        base_port = base.port
    except ValueError:
        return None
    tenant = _tenant_domain(base_host)
    for key in ("verification_uri_complete", "verification_uri"):
        value = grant.get(key)
        if not isinstance(value, str) or _CONTROL.search(value) or " " in value:
            continue
        try:
            link = urlsplit(value)
            host = (link.hostname or "").lower()
            port = link.port
        except ValueError:
            continue
        if "@" in link.netloc or not is_secure_base_url(value):
            continue
        if port is not None and port != base_port \
                and port != (443 if link.scheme == "https" else 80):
            continue
        if host == base_host or host == tenant or host.endswith("." + tenant):
            return value
    return None


def _post(session, base_url: str, path: str, body: dict, timeout: int):
    return session.post(base_url.rstrip("/") + path, json=body, timeout=timeout)


def _json(response) -> dict:
    try:
        data = response.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def device_login(base_url: str, client_name: str, *, sleep=time.sleep,
                 echo=click.echo, timeout: int = 30,
                 verify_tls: bool = True, session=None) -> tuple[str, int]:
    """Run the device flow; returns ``(token, expires_at)`` (unix seconds).

    ``timeout`` and ``verify_tls`` come from the CLI settings. The session
    honours proxy environment variables like the rest of the CLI.
    """
    require_secure_base_url(base_url)
    if session is None:
        session = requests.Session()
        session.verify = verify_tls
    response = _post(session, base_url, CODE_PATH, {"clientName": client_name}, timeout)
    if response.status_code != 200:
        raise PhoenixAPIError(response.status_code, response.text[:500],
                              "POST", CODE_PATH, body=response.text)
    grant = _json(response)
    device_code = grant.get("device_code")
    user_code = grant.get("user_code")
    if not isinstance(device_code, str) or not device_code \
            or not isinstance(user_code, str) or not user_code:
        raise PhoenixAPIError(response.status_code,
                              "The login grant is missing a device or user code.",
                              "POST", CODE_PATH)
    try:
        interval = int(grant.get("interval") or DEFAULT_INTERVAL)
        expires_in = int(grant.get("expires_in") or DEFAULT_EXPIRES_IN)
    except (TypeError, ValueError):
        raise PhoenixAPIError(response.status_code,
                              "The login grant has a non-numeric interval or expiry.",
                              "POST", CODE_PATH) from None
    link = _link_to_show(base_url, grant)
    if link:
        echo("Open this link in your browser and approve the login:")
        echo(f"  {link}")
    else:
        echo("The server sent a login link that is not an https link on "
             f"{_clean(base_url)}, so it is not shown.")
        echo(f"Open {_clean(base_url.rstrip('/'))} in your browser and enter "
             "the code to approve the login.")
    echo(f"Code: {_clean(user_code)}")

    waited = 0
    while True:
        reply = _post(session, base_url, TOKEN_PATH, {"device_code": device_code}, timeout)
        data = _json(reply)
        if reply.status_code == 200 and data.get("access_token"):
            try:
                token_expires_in = int(data.get("expires_in") or 3600)
            except (TypeError, ValueError):
                raise PhoenixAPIError(reply.status_code,
                                      "The login token has a non-numeric expiry.",
                                      "POST", TOKEN_PATH) from None
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
