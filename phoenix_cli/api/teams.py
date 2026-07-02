"""Teams API — /v1/teams, membership and auto-link configuration."""

from phoenix_cli.api.common import drop_none, name_selector, parse_tags, user_ref
from phoenix_cli.errors import PhoenixConfigError, PhoenixNotSupportedError

TEAM_TYPES = ("GENERAL", "SECURITY")
AUTO_LINK_MATCH = ("ANY", "ALL")


class TeamsAPI:

    def list_teams(self, page_size=100, max_items=None):
        return list(self.transport.paginate(
            "GET", "/v1/teams", page_size=page_size, max_items=max_items))

    def get_team(self, team_id):
        return self.transport.request("GET", f"/v1/teams/{team_id}")

    def get_team_members(self, team_id):
        """Returns a bare array of {'id','email'} (not paged)."""
        return self.transport.request("GET", f"/v1/teams/{team_id}/users")

    def create_team(self, name, team_type):
        if team_type not in TEAM_TYPES:
            raise PhoenixConfigError(f"Team type must be one of {TEAM_TYPES}.")
        return self.transport.request(
            "POST", "/v1/teams", json_body={"name": name, "type": team_type})

    def add_team_members(self, users, team_id=None, team_name=None,
                         case_sensitive=None, auto_create_users=None):
        """Add members by id/email; auto_create_users=True creates missing
        users (Org User role) instead of failing with 400."""
        body = drop_none({
            "users": [user_ref(u) for u in users],
            "autoCreateUsers": auto_create_users,
        })
        if team_id:
            return self.transport.request(
                "PUT", f"/v1/teams/{team_id}/users", json_body=body)
        body["teamSelector"] = name_selector(team_name, case_sensitive=case_sensitive)
        return self.transport.request("PUT", "/v1/teams/users", json_body=body)

    def remove_team_member(self, team_id, user_email):
        return self.transport.request(
            "DELETE", f"/v1/teams/{team_id}/users/{user_email}",
            expect_json=False)

    # -- auto-link -----------------------------------------------------------

    def _auto_link_path(self, team_id, scope):
        if scope not in ("applications", "components"):
            raise PhoenixConfigError("scope must be applications|components.")
        return f"/v1/teams/{team_id}/{scope}/auto-link"

    def set_auto_link_tags(self, team_id, scope, tags, match=None):
        """Configure tags that auto-link apps/envs (scope=applications) or
        components/services (scope=components) to the team."""
        if match and match not in AUTO_LINK_MATCH:
            raise PhoenixConfigError(f"match must be one of {AUTO_LINK_MATCH}.")
        body = drop_none({"match": match, "tags": parse_tags(tags)})
        return self.transport.request(
            "POST", self._auto_link_path(team_id, scope) + "/tags",
            json_body=body)

    def remove_auto_link_tags(self, team_id, scope, tags=None):
        """Remove specific auto-link tags, or ALL of them when tags is None."""
        path = self._auto_link_path(team_id, scope) + "/tags"
        if tags:
            body = {"action": "delete", "tags": parse_tags(tags)}
            return self.transport.request("PATCH", path, json_body=body)
        return self.transport.request("DELETE", path, expect_json=False)

    def set_auto_link_by_members(self, team_id, enabled):
        """Enable/disable auto-linking apps the team members are responsible
        for (applications scope only, per v1.27)."""
        path = self._auto_link_path(team_id, "applications") + "/users"
        if enabled:
            return self.transport.request("POST", path, expect_json=False)
        return self.transport.request("DELETE", path, expect_json=False)

    def delete_team(self, team_id=None):
        """NOT SUPPORTED — flagged gap."""
        raise PhoenixNotSupportedError(
            "teams delete",
            "API v1.27 exposes no endpoint to delete or rename a team.",
            "Delete the team in the platform UI.",
        )
