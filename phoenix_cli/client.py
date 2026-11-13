"""PhoenixClient — the single public entry point of the client library.

Usage:
    from phoenix_cli import PhoenixClient

    client = PhoenixClient(client_id="...", client_secret="...",
                           base_url="https://api.securityphoenix.cloud")
    apps = client.list_applications()
    findings = client.search_findings(status=["OPEN"], max_items=500)

Full API-key visibility: every capability of Phoenix Security REST API v1.27
is reachable with just a client_id/client_secret pair. Methods accept plain
inputs and return decoded JSON; token handling, retries, pagination and
payload construction are internal.
"""

from urllib.parse import urlsplit

from phoenix_cli.errors import PhoenixConfigError
from phoenix_cli.api.applications import ApplicationsAPI
from phoenix_cli.api.assets import AssetsAPI
from phoenix_cli.api.autopatcher import AutopatcherAPI
from phoenix_cli.api.campaigns import CampaignsAPI
from phoenix_cli.api.components import ComponentsAPI
from phoenix_cli.api.copilot import CopilotAPI
from phoenix_cli.api.findings import FindingsAPI
from phoenix_cli.api.imports import ImportsAPI
from phoenix_cli.api.teams import TeamsAPI
from phoenix_cli.api.users import UsersAPI
from phoenix_cli.config import Settings, load_settings
from phoenix_cli.http import Transport


_FORBIDDEN_PATH_PARTS = ("..", "//", "\\", "@", "://", "%2e", "%2f", "%5c", "%40")


def _check_raw_path(path, base_url):
    """Refuse any raw path that could leave the base host or the /v1 API."""
    if not isinstance(path, str) or not path.startswith("/v1/"):
        raise PhoenixConfigError(
            f"raw API path must start with '/v1/': {path!r}")
    low = path.lower()
    bad = [p for p in _FORBIDDEN_PATH_PARTS if p in low]
    if bad or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in path):
        raise PhoenixConfigError(
            "raw API path must be a plain /v1 path without '..', '//', '@', "
            f"backslashes, schemes, encoded separators or whitespace: {path!r}")
    base, target = urlsplit(base_url), urlsplit(base_url + path)
    if (target.scheme, target.netloc) != (base.scheme, base.netloc):
        raise PhoenixConfigError(
            f"raw API path would change the target host: {path!r}")


class PhoenixClient(AssetsAPI, FindingsAPI, ImportsAPI, ApplicationsAPI,
                    ComponentsAPI, TeamsAPI, UsersAPI, CampaignsAPI,
                    AutopatcherAPI, CopilotAPI):

    def __init__(self, client_id=None, client_secret=None, base_url=None,
                 env=None, config_path=None, timeout=60, verify_tls=True,
                 settings=None):
        if settings is None:
            settings = load_settings(
                client_id=client_id, client_secret=client_secret,
                base_url=base_url, env=env, config_path=config_path,
                timeout=timeout, verify_tls=verify_tls,
            )
        settings.require_credentials()
        self.settings = settings
        self.transport = Transport(
            client_id=settings.client_id,
            client_secret=settings.client_secret,
            base_url=settings.base_url,
            timeout=settings.timeout,
            verify_tls=settings.verify_tls,
        )

    @classmethod
    def from_settings(cls, settings: Settings):
        return cls(settings=settings)

    # -- connection-level helpers --------------------------------------------

    def test_connection(self):
        """Authenticate and perform a minimal read; returns a summary dict."""
        token_info = self.transport.authenticate()
        page = self.transport.request(
            "GET", "/v1/applications", params={"pageNumber": 0, "pageSize": 1})
        return {
            "base_url": self.transport.base_url,
            "authenticated": True,
            "token_expiry_unix": token_info["expiry"],
            "visible_applications_and_environments": (page or {}).get("totalElements", 0),
        }

    def raw_request(self, method, path, params=None, json_body=None):
        """Escape hatch: call any /v1 path directly (still authenticated,
        retried and paginated-envelope aware via the transport).

        The path is checked before the bearer token is attached, so it can
        never send the token to another host."""
        _check_raw_path(path, self.transport.base_url)
        return self.transport.request(method, path, params=params,
                                      json_body=json_body)
