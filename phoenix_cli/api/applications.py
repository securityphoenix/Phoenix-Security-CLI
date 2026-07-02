"""Applications & Environments API — /v1/applications.

Covers BOTH Applications (type=APPLICATION) and Environments
(type=ENVIRONMENT, subType=CLOUD|INFRA). Endpoints taking an ID also have a
name-selector variant (same URL without the ID + applicationSelector body).
"""

from phoenix_cli.api.common import drop_none, name_selector, parse_tags, user_ref
from phoenix_cli.errors import PhoenixConfigError, PhoenixNotSupportedError

APP_TYPES = ("APPLICATION", "ENVIRONMENT")
ENV_SUBTYPES = ("CLOUD", "INFRA")


class ApplicationsAPI:

    def list_applications(self, entity_type=None, page_size=100, max_items=None):
        """List applications and/or environments."""
        params = drop_none({"type": entity_type})
        return list(self.transport.paginate(
            "GET", "/v1/applications", params=params,
            page_size=page_size, max_items=max_items,
        ))

    def get_application(self, application_id):
        return self.transport.request("GET", f"/v1/applications/{application_id}")

    def get_application_posture(self, application_id=None, name=None,
                                case_sensitive=None, exclude_risk_accepted=None):
        """Posture (risk + finding/asset counts) by ID or by name."""
        if application_id:
            params = drop_none({"excludeRiskAccepted": exclude_risk_accepted})
            return self.transport.request(
                "GET", f"/v1/applications/{application_id}/posture", params=params)
        if not name:
            raise PhoenixConfigError("Provide an application id or name.")
        body = drop_none({
            "applicationSelector": name_selector(name, case_sensitive=case_sensitive),
            "excludeRiskAccepted": exclude_risk_accepted,
        })
        return self.transport.request("POST", "/v1/applications/posture",
                                      json_body=body)

    def create_application(self, name, entity_type, criticality, owner,
                           sub_type=None, threshold=None, value=None,
                           responsible_users=None, tags=None,
                           ticketing=None, messaging=None):
        """Create an Application or Environment.

        owner: email/id string or {'id','email'} dict. criticality: 1-10.
        entity_type: APPLICATION | ENVIRONMENT (sub_type CLOUD|INFRA required
        for environments).
        """
        if entity_type not in APP_TYPES:
            raise PhoenixConfigError(f"type must be one of {APP_TYPES}.")
        if entity_type == "ENVIRONMENT" and sub_type not in ENV_SUBTYPES:
            raise PhoenixConfigError(
                f"Environments require subType in {ENV_SUBTYPES}.")
        body = drop_none({
            "name": name,
            "type": entity_type,
            "subType": sub_type,
            "criticality": criticality,
            "threshold": threshold,
            "value": value,
            "owner": user_ref(owner),
            "responsibleUsers": [user_ref(u) for u in responsible_users] if responsible_users else None,
            "tags": parse_tags(tags) if tags else None,
            "ticketing": ticketing,
            "messaging": messaging,
        })
        return self.transport.request("POST", "/v1/applications", json_body=body)

    def update_application(self, name=None, case_sensitive=None, new_name=None,
                           criticality=None, threshold=None, value=None,
                           owner=None, ticketing=None, messaging=None):
        """Update an app/env identified by name (applicationSelector)."""
        body = drop_none({
            "applicationSelector": name_selector(name, case_sensitive=case_sensitive),
            "name": new_name,
            "criticality": criticality,
            "threshold": threshold,
            "value": value,
            "owner": user_ref(owner) if owner else None,
            "ticketing": ticketing,
            "messaging": messaging,
        })
        return self.transport.request("PATCH", "/v1/applications", json_body=body)

    def add_application_tags(self, tags, application_id=None, name=None,
                             case_sensitive=None):
        parsed = parse_tags(tags)
        if application_id:
            return self.transport.request(
                "PUT", f"/v1/applications/{application_id}/tags",
                json_body={"tags": parsed})
        body = {"applicationSelector": name_selector(name, case_sensitive=case_sensitive),
                "tags": parsed}
        return self.transport.request("PUT", "/v1/applications/tags", json_body=body)

    def remove_application_tags(self, tags, application_id=None, name=None,
                                case_sensitive=None):
        parsed = parse_tags(tags)
        body = {"action": "delete", "tags": parsed}
        if application_id:
            return self.transport.request(
                "PATCH", f"/v1/applications/{application_id}/tags", json_body=body)
        body["applicationSelector"] = name_selector(name, case_sensitive=case_sensitive)
        return self.transport.request("PATCH", "/v1/applications/tags", json_body=body)

    def add_responsible_users(self, users, application_id=None, name=None,
                              case_sensitive=None):
        body = {"responsibleUsers": [user_ref(u) for u in users]}
        if application_id:
            return self.transport.request(
                "PUT", f"/v1/applications/{application_id}/responsible-users",
                json_body=body)
        body["applicationSelector"] = name_selector(name, case_sensitive=case_sensitive)
        return self.transport.request(
            "PUT", "/v1/applications/responsible-users", json_body=body)

    def add_application_deployment(self, application_id=None, name=None,
                                   case_sensitive=None, service_ids=None,
                                   service_names=None, service_tags=None,
                                   match_asset_tags=None, replace_existing=None):
        """Link an Application to the Service(s) it deploys onto."""
        selectors = drop_none({
            "ids": service_ids,
            "names": service_names,
            "caseSensitive": case_sensitive,
            "tags": parse_tags(service_tags) if service_tags else None,
            "matchAssetTags": match_asset_tags,
        })
        if not selectors:
            raise PhoenixConfigError(
                "Provide service ids, names or tags to deploy onto.")
        body = drop_none({
            "serviceSelectors": selectors,
            "replaceExisting": replace_existing,
        })
        if application_id:
            return self.transport.request(
                "PATCH", f"/v1/applications/{application_id}/deploy", json_body=body)
        body["applicationSelector"] = name_selector(name, case_sensitive=case_sensitive)
        return self.transport.request("PATCH", "/v1/applications/deploy",
                                      json_body=body)

    def link_repository(self, repository, application_id=None, name=None,
                        case_sensitive=None, search=None, component=None):
        """Add a repository rule (associates repo assets) to an app/env.

        component: optional {'id'|'name', 'criticality', 'tags'} — target
        component; a new one named after the repository is created if omitted.
        """
        if component and component.get("tags"):
            component = dict(component)
            component["tags"] = parse_tags(component["tags"])
        body = drop_none({
            "repository": repository,
            "search": search,
            "component": component,
        })
        if application_id:
            return self.transport.request(
                "POST", f"/v1/applications/{application_id}/repository",
                json_body=body)
        body["applicationSelector"] = name_selector(name, case_sensitive=case_sensitive)
        return self.transport.request("POST", "/v1/applications/repository",
                                      json_body=body)

    def delete_application(self, application_id=None, name=None):
        """NOT SUPPORTED — flagged gap."""
        raise PhoenixNotSupportedError(
            "apps delete",
            "API v1.27 exposes no endpoint to delete an Application or "
            "Environment (components/services can be deleted, apps cannot).",
            "Delete the application/environment in the platform UI.",
        )
