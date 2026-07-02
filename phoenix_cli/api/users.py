"""Users API — /v1/users (list, create, activate, deactivate)."""

from phoenix_cli.errors import PhoenixConfigError, PhoenixNotSupportedError

USER_ROLES = ("ORG_ADMIN", "ORG_APP_ADMIN", "ORG_USER", "ORG_ADMIN_LITE",
              "ORG_SEC_ADMIN", "ORG_SEC_DEV")


class UsersAPI:

    def list_users(self, page_size=100, max_items=None):
        return list(self.transport.paginate(
            "GET", "/v1/users", page_size=page_size, max_items=max_items))

    def create_user(self, email, first_name, last_name, role):
        """Create a user; the platform emails a welcome + one-time password."""
        if role not in USER_ROLES:
            raise PhoenixConfigError(f"role must be one of {USER_ROLES}.")
        return self.transport.request("POST", "/v1/users", json_body={
            "email": email,
            "firstName": first_name,
            "lastName": last_name,
            "role": role,
        })

    def _activation(self, path, ids=None, emails=None):
        if not ids and not emails:
            raise PhoenixConfigError("Provide at least one user id or email.")
        body = {}
        if ids:
            body["ids"] = list(ids)
        if emails:
            body["emails"] = list(emails)
        return self.transport.request("POST", path, json_body=body,
                                      expect_json=False)

    def deactivate_users(self, ids=None, emails=None):
        """Deactivate users (immediate loss of platform access)."""
        return self._activation("/v1/users/deactivate", ids, emails)

    def activate_users(self, ids=None, emails=None):
        """Re-activate previously deactivated users."""
        return self._activation("/v1/users/activate", ids, emails)

    def delete_user(self, user_id=None, email=None):
        """NOT SUPPORTED — flagged gap."""
        raise PhoenixNotSupportedError(
            "users delete",
            "API v1.27 exposes no user delete endpoint (deactivate only) and "
            "no role-update endpoint.",
            "Use 'phx users deactivate'; delete or change roles in the UI.",
        )
