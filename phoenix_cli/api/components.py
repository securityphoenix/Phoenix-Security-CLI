"""Components & Services API — /v1/components.

Covers Components (inside Applications) and Services (inside Environments),
plus Asset Association Rules (/v1/components/.../rules).
"""

from phoenix_cli.api.common import drop_none, name_selector, parse_tags
from phoenix_cli.errors import PhoenixConfigError

COMPONENT_TYPES = ("COMPONENT", "SERVICE")


def _pair_selector(app_name=None, app_id=None, component_name=None,
                   case_sensitive=None):
    return {
        "applicationSelector": name_selector(app_name, app_id, case_sensitive),
        "componentSelector": name_selector(component_name,
                                           case_sensitive=case_sensitive),
    }


class ComponentsAPI:

    def list_components(self, parent_id=None, entity_type=None,
                        page_size=100, max_items=None):
        params = drop_none({"parentId": parent_id, "type": entity_type})
        return list(self.transport.paginate(
            "GET", "/v1/components", params=params,
            page_size=page_size, max_items=max_items,
        ))

    def get_component(self, component_id):
        return self.transport.request("GET", f"/v1/components/{component_id}")

    def get_component_posture(self, component_id=None, app_name=None,
                              component_name=None, case_sensitive=None,
                              exclude_risk_accepted=None):
        if component_id:
            params = drop_none({"excludeRiskAccepted": exclude_risk_accepted})
            return self.transport.request(
                "GET", f"/v1/components/{component_id}/posture", params=params)
        if not (app_name and component_name):
            raise PhoenixConfigError(
                "Provide component id, or app_name + component_name.")
        body = drop_none({
            "selector": _pair_selector(app_name, None, component_name,
                                       case_sensitive),
            "excludeRiskAccepted": exclude_risk_accepted,
        })
        return self.transport.request("POST", "/v1/components/posture",
                                      json_body=body)

    def create_component(self, name, app_name=None, app_id=None,
                         case_sensitive=None, criticality=None, tags=None,
                         ticketing=None, messaging=None):
        """Create a Component (in an Application) or Service (in an Environment)."""
        body = drop_none({
            "applicationSelector": name_selector(app_name, app_id, case_sensitive),
            "name": name,
            "criticality": criticality,
            "tags": parse_tags(tags) if tags else None,
            "ticketing": ticketing,
            "messaging": messaging,
        })
        return self.transport.request("POST", "/v1/components", json_body=body)

    def update_component(self, component_id, new_name=None, criticality=None,
                         tags=None, ticketing=None, messaging=None):
        """Update a component/service. Note: tags supplied here are ADDED."""
        body = drop_none({
            "name": new_name,
            "criticality": criticality,
            "tags": parse_tags(tags) if tags else None,
            "ticketing": ticketing,
            "messaging": messaging,
        })
        if not body:
            raise PhoenixConfigError("Nothing to update.")
        return self.transport.request(
            "PATCH", f"/v1/components/{component_id}", json_body=body)

    def add_component_tags(self, component_id, tags):
        """Add tags to a component (via PATCH update — tags are additive)."""
        return self.update_component(component_id, tags=tags)

    def remove_component_tags(self, component_id, tags):
        body = {"action": "delete", "tags": parse_tags(tags)}
        return self.transport.request(
            "PATCH", f"/v1/components/{component_id}/tags", json_body=body)

    def delete_component(self, component_id=None, app_name=None, app_id=None,
                         component_name=None, case_sensitive=None):
        """Delete a component/service by ID or by app+component selector."""
        if component_id:
            return self.transport.request(
                "DELETE", f"/v1/components/{component_id}", expect_json=False)
        if not component_name:
            raise PhoenixConfigError(
                "Provide component id, or app + component names.")
        body = _pair_selector(app_name, app_id, component_name, case_sensitive)
        return self.transport.request("DELETE", "/v1/components",
                                      json_body=body, expect_json=False)

    def add_component_deployment(self, component_id, service_ids=None,
                                 service_names=None, service_tags=None,
                                 case_sensitive=None, match_asset_tags=None,
                                 inherit_from_app=None, replace_existing=None):
        """Link a Component to the Service(s) it deploys onto."""
        selectors = drop_none({
            "ids": service_ids,
            "names": service_names,
            "caseSensitive": case_sensitive,
            "tags": parse_tags(service_tags) if service_tags else None,
            "matchAssetTags": match_asset_tags,
        })
        body = drop_none({
            "inheritFromApp": inherit_from_app,
            "serviceSelectors": selectors or None,
            "replaceExisting": replace_existing,
        })
        if not body:
            raise PhoenixConfigError(
                "Provide inherit_from_app or service ids/names/tags.")
        return self.transport.request(
            "PATCH", f"/v1/components/{component_id}/deploy", json_body=body)

    # -- asset association rules ---------------------------------------------

    def add_component_rules(self, rules, component_id=None, app_name=None,
                            app_id=None, component_name=None,
                            case_sensitive=None, reset_rules=None):
        """Add (or replace, with reset_rules=True) asset association rules.

        rules: list of {'name': str, 'filter': {...}} objects. Filter fields:
        ids, keyLike, tags, providerAccountId/Name, resourceGroup, assetType,
        cidrs, ipRanges, hostnames, osNames, netbios, fqdn, repository, and an
        optional non-nested negateFilter of the same shape.
        """
        for rule in rules:
            fltr = rule.get("filter") or {}
            if fltr.get("tags"):
                fltr["tags"] = parse_tags(fltr["tags"])
            negate = fltr.get("negateFilter")
            if negate and negate.get("negateFilter"):
                raise PhoenixConfigError("negateFilter cannot be nested.")
        body = drop_none({"rules": rules, "resetRules": reset_rules})
        if component_id:
            return self.transport.request(
                "POST", f"/v1/components/{component_id}/rules", json_body=body)
        body["selector"] = _pair_selector(app_name, app_id, component_name,
                                          case_sensitive)
        return self.transport.request("POST", "/v1/components/rules",
                                      json_body=body)
