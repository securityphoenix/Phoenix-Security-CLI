"""Autopatcher API, /v1/autopatcher/**.

Each method is one call to an autopatcher route, except
``get_autopatch_findings``, which pages through the findings (up to 21 calls). Usage confirmation and
accepting a plan by hand belong to a person in Phoenix; ``accept_patch_plan``
exists only for the autopatcher's own interactive terminal flow. When an
organisation turns on automatic acceptance for a usage, Phoenix itself
accepts a new plan whose actions are all ``auto``, with no person.
"""

from __future__ import annotations

from phoenix_cli.errors import (PhoenixAPIError, PhoenixError, error_code,
                                 expect_mapping)

FINDINGS_PAGE_SIZE = 1000
MAX_FINDINGS_PAGES = 20


class AutopatcherAPI:

    def lookup_asset(self, hostname: str | None = None,
                     ip: str | None = None) -> dict:
        """Assets that match a hostname and/or an IP address."""
        params = {}
        if hostname:
            params["hostname"] = hostname
        if ip:
            params["ip"] = ip
        return self.transport.request(
            "GET", "/v1/autopatcher/assets/lookup", params=params or None)

    def set_asset_usage(self, asset_id: str, usage: str) -> dict:
        """Confirm the usage of an asset (needs a person, not an API key)."""
        return self.transport.request(
            "PUT", f"/v1/autopatcher/assets/{asset_id}/usage",
            json_body={"usage": usage})

    def get_patch_policy(self, usage: str) -> dict:
        """The patch policy for a usage."""
        return self.transport.request(
            "GET", "/v1/autopatcher/policy", params={"usage": usage})

    def submit_patch_plan(self, asset_id: str, actions: list[dict], *,
                          source: str = "llm") -> dict:
        """Submit a plan written by a model.

        ``source`` is ``llm`` (default: a model inside a program, which an
        organisation may let Phoenix accept by policy) or ``mcp`` (an agent
        wrote it through an MCP server: Phoenix never accepts it by policy).
        Any other value raises ``ValueError`` before a request is made.
        """
        if source not in ("llm", "mcp"):
            raise ValueError(
                f"source must be 'llm' or 'mcp', got {source!r}")
        return self.transport.request(
            "POST", "/v1/autopatcher/plans",
            json_body={"assetId": asset_id, "source": source,
                       "actions": actions})

    def get_patch_plan(self, plan_id: str) -> dict:
        """One plan with its actions and state."""
        return self.transport.request(
            "GET", f"/v1/autopatcher/plans/{plan_id}")

    def get_latest_accepted_plan(self, asset_id: str) -> dict | None:
        """The newest accepted, unexpired plan, or None."""
        try:
            return self.transport.request(
                "GET",
                f"/v1/autopatcher/assets/{asset_id}/plans/latest-accepted")
        except PhoenixAPIError as exc:
            if exc.status_code == 404 and error_code(exc) == "NO_VALID_PLAN":
                return None
            raise

    def list_pending_plans(self, asset_id: str) -> list[dict]:
        """Plans of the asset that wait for acceptance."""
        reply = self.transport.request(
            "GET", f"/v1/autopatcher/assets/{asset_id}/plans",
            params={"state": "PENDING_ACCEPTANCE"})
        reply = expect_mapping({} if reply is None else reply, "the pending plans")
        return list(reply.get("plans") or [])

    def accept_patch_plan(self, plan_id: str, plan_hash: str) -> dict:
        """Accept a plan. Used only by the autopatcher's terminal flow."""
        return self.transport.request(
            "POST", f"/v1/autopatcher/plans/{plan_id}/accept",
            json_body={"hash": plan_hash},
            headers={"X-Autopatcher-Confirm": plan_hash[:8]})

    def upload_patch_run(self, record: dict) -> dict:
        """Upload the record of a run."""
        return self.transport.request(
            "POST", "/v1/autopatcher/runs", json_body=record)

    def get_autopatch_findings(self, asset_id: str) -> list[dict]:
        """Every open finding of the asset, once each, in server order."""
        seen: set = set()
        out: list[dict] = []
        for page in range(MAX_FINDINGS_PAGES + 1):
            reply = self.transport.request(
                "GET", f"/v1/autopatcher/assets/{asset_id}/findings",
                params={"page": page, "size": FINDINGS_PAGE_SIZE})
            reply = expect_mapping({} if reply is None else reply, "the findings")
            items = reply.get("findings") or []
            if not all(isinstance(item, dict) for item in items):
                raise PhoenixError("Unexpected response from Phoenix for the findings")
            if page == MAX_FINDINGS_PAGES and items:
                raise ValueError("too many findings")
            for item in items:
                key = item.get("id")
                if key in seen:
                    continue
                seen.add(key)
                out.append(item)
            if len(items) < FINDINGS_PAGE_SIZE:
                break
        return out
