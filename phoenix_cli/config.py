"""Configuration resolution for the Phoenix Security CLI.

Precedence (highest wins):
    1. Explicit CLI arguments (--client-id / --client-secret / --api-base-url / --env)
    2. Environment variables
    3. config.ini file ([phoenix] section)
    4. Defaults

Environment variables (aliases accepted for compatibility with existing
Phoenix tooling):
    PHOENIX_CLIENT_ID      (alias: CLIENT_ID)
    PHOENIX_CLIENT_SECRET  (alias: CLIENT_SECRET)
    PHOENIX_API_BASE_URL   (aliases: PHOENIX_BASE_URL, PHOENIX_DOMAIN)

config.ini ([phoenix] section) keys — lowercase canonical, uppercase legacy
accepted:
    client_id / PHOENIX_CLIENT_ID
    client_secret / PHOENIX_CLIENT_SECRET
    api_base_url / PHOENIX_BASE_URL
"""

import configparser
import os
import sys
import time
from urllib.parse import urlsplit

from phoenix_cli.errors import PhoenixConfigError
from phoenix_cli.token_store import load_token

# Named environments -> base URLs (Phoenix Security API v1.27)
ENVIRONMENTS = {
    "prod": "https://api.securityphoenix.cloud",
    "production": "https://api.securityphoenix.cloud",
    "demo": "https://api.demo.appsecphx.io",
    "poc": "https://api.poc1.appsecphx.io",
    "poc1": "https://api.poc1.appsecphx.io",
}

DEFAULT_BASE_URL = ENVIRONMENTS["prod"]

_ENV_CLIENT_ID = ("PHOENIX_CLIENT_ID", "CLIENT_ID")
_ENV_CLIENT_SECRET = ("PHOENIX_CLIENT_SECRET", "CLIENT_SECRET")
_ENV_BASE_URL = ("PHOENIX_API_BASE_URL", "PHOENIX_BASE_URL", "PHOENIX_DOMAIN")

_INI_CLIENT_ID = ("client_id", "phoenix_client_id")
_INI_CLIENT_SECRET = ("client_secret", "phoenix_client_secret")
_INI_BASE_URL = ("api_base_url", "phoenix_base_url", "base_url")

# Searched in order when --config is not given.
DEFAULT_CONFIG_PATHS = (
    "config.ini",
    os.path.join("~", ".config", "phoenix", "config.ini"),
    os.path.join("~", ".phoenix", "config.ini"),
)


LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")


def is_secure_base_url(url):
    """True for https, or http to a loopback host (local development)."""
    try:
        parts = urlsplit(url or "")
        host = (parts.hostname or "").lower()
    except ValueError:
        return False
    if parts.scheme == "https":
        return bool(host)
    return parts.scheme == "http" and host in LOCAL_HOSTS


def require_secure_base_url(url):
    """Refuse a base URL that would send credentials in clear text."""
    if not is_secure_base_url(url):
        raise PhoenixConfigError(
            f"Refusing base URL {url!r}: it is not https. The device code, "
            "access token and API credentials would be sent in clear text. "
            "Use an https:// URL (http:// is allowed only for localhost, "
            "127.0.0.1 and [::1])."
        )
    return url


class Settings:
    """Resolved credentials and connection settings."""

    def __init__(self, client_id=None, client_secret=None, base_url=None,
                 timeout=60, verify_tls=True, config_source=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.config_source = config_source  # where credentials came from

    def _has_login_token(self):
        stored = load_token(self.base_url)
        return bool(stored and stored[1] > time.time())

    def require_credentials(self):
        if (not self.client_id or not self.client_secret) \
                and not self._has_login_token():
            raise PhoenixConfigError(
                "Phoenix API credentials not found. Provide them via one of:\n"
                "  - CLI flags:  --client-id / --client-secret\n"
                "  - Env vars:   PHOENIX_CLIENT_ID / PHOENIX_CLIENT_SECRET\n"
                "  - config.ini: [phoenix] client_id / client_secret\n"
                "  - A login:    phx login\n"
                "Credentials are created in the Phoenix UI under "
                "Organisation > API Access."
            )
        return self


def _first(mapping_get, keys):
    for key in keys:
        value = mapping_get(key)
        if value:
            return value.strip()
    return None


def _read_ini(path):
    parser = configparser.ConfigParser()
    parser.read(path)
    if not parser.has_section("phoenix"):
        return {}
    section = {k.lower(): v for k, v in parser.items("phoenix")}
    return section


def load_settings(client_id=None, client_secret=None, base_url=None, env=None,
                  config_path=None, timeout=60, verify_tls=True):
    """Resolve settings using the documented precedence chain."""
    if env:
        env_key = env.lower()
        if env_key not in ENVIRONMENTS:
            raise PhoenixConfigError(
                f"Unknown environment '{env}'. Choose from: "
                f"{', '.join(sorted(set(ENVIRONMENTS)))} — or pass --api-base-url."
            )
        env_base_url = ENVIRONMENTS[env_key]
    else:
        env_base_url = None

    # 3) config file
    ini = {}
    config_source = None
    candidates = [config_path] if config_path else [os.path.expanduser(p) for p in DEFAULT_CONFIG_PATHS]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            ini = _read_ini(candidate)
            config_source = candidate
            break
    if config_path and not config_source:
        raise PhoenixConfigError(f"Config file not found: {config_path}")

    ini_get = ini.get
    ini_base_url = _first(ini_get, _INI_BASE_URL)
    # A ./config.ini is picked up from the current directory without being
    # asked for. When it is what sets the base URL, say so: a hostile
    # directory could otherwise redirect the CLI (and its credentials).
    if (not config_path and config_source == "config.ini" and ini_base_url
            and not (base_url or env_base_url
                     or _first(os.environ.get, _ENV_BASE_URL))):
        print(f"warning: using api_base_url {ini_base_url} from "
              f"{os.path.abspath(config_source)} (current directory). "
              "Pass --api-base-url or --config to be explicit.",
              file=sys.stderr)

    resolved_client_id = (
        client_id
        or _first(os.environ.get, _ENV_CLIENT_ID)
        or _first(ini_get, _INI_CLIENT_ID)
    )
    resolved_client_secret = (
        client_secret
        or _first(os.environ.get, _ENV_CLIENT_SECRET)
        or _first(ini_get, _INI_CLIENT_SECRET)
    )
    resolved_base_url = (
        base_url
        or env_base_url
        or _first(os.environ.get, _ENV_BASE_URL)
        or ini_base_url
        or DEFAULT_BASE_URL
    )

    return Settings(
        client_id=resolved_client_id,
        client_secret=resolved_client_secret,
        base_url=resolved_base_url,
        timeout=timeout,
        verify_tls=verify_tls,
        config_source=config_source,
    )
