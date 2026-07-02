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

from phoenix_cli.api.applications import ApplicationsAPI
from phoenix_cli.api.assets import AssetsAPI
from phoenix_cli.api.components import ComponentsAPI
from phoenix_cli.api.findings import FindingsAPI
from phoenix_cli.api.imports import ImportsAPI
from phoenix_cli.api.teams import TeamsAPI
from phoenix_cli.api.users import UsersAPI
from phoenix_cli.config import Settings, load_settings
from phoenix_cli.http import Transport


class PhoenixClient(AssetsAPI, FindingsAPI, ImportsAPI, ApplicationsAPI,
                    ComponentsAPI, TeamsAPI, UsersAPI):

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
        retried and paginated-envelope aware via the transport)."""
        return self.transport.request(method, path, params=params,
                                      json_body=json_body)
