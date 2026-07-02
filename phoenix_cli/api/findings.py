"""Findings (vulnerabilities) API — search, retrieve, enrich.

Direct REST coverage: POST /v1/findings (search), GET /v1/findings/<id>.
(/v1/vulnerabilities is an alias of /v1/findings.)

There is NO single-finding update endpoint in API v1.27: severity overrides,
risk acceptance, false-positive requests, comments and status changes cannot
be performed via the API. Finding enrichment is therefore implemented through
the import pipeline (merge) and everything else raises a flagged gap error.
See docs/GAP_ANALYSIS.md.
"""

from phoenix_cli.api.common import drop_none, parse_tags
from phoenix_cli.errors import PhoenixNotSupportedError

FINDING_TYPES = ("WEB", "CLOUD", "FOSS", "SAST", "CONTAINER", "INFRA")
FINDING_STATUSES = ("OPEN", "CLOSED")
ASSET_LOCALITIES = ("INTERNAL", "EXTERNAL", "DMZ")
TAG_CATEGORIES = ("TECH_STACK", "ALERT", "COMPLIANCE", "BUSINESS_UNIT", "GENERAL")


class FindingsAPI:

    def search_findings(self, application_environment_id=None,
                        component_service_id=None, asset_id=None,
                        asset_assigned_status=None, asset_localities=None,
                        finding_type=None, scanner_types=None, status=None,
                        suggested_to_fix=None, zero_day_alert=None,
                        date_from=None, date_to=None,
                        severity_score_from=None, severity_score_to=None,
                        cves=None, epss_score_from=None, epss_score_to=None,
                        workflow_ticket_statuses=None, sla_breach=None,
                        workflow_ticket_sla_breach=None, tag_keys=None,
                        tag_values=None, tag_categories=None, team_ids=None,
                        page_size=100, max_items=None):
        """Search findings with any combination of the v1.27 filters."""
        body = drop_none({
            "applicationEnvironmentId": application_environment_id,
            "componentServiceId": component_service_id,
            "assetId": asset_id,
            "assetAssignedStatus": asset_assigned_status,
            "assetLocalities": asset_localities,
            "type": finding_type,
            "scannerTypes": scanner_types,
            "status": status,
            "suggestedToFix": suggested_to_fix,
            "zeroDayAlert": zero_day_alert,
            "dateFrom": date_from,
            "dateTo": date_to,
            "severityScoreFrom": severity_score_from,
            "severityScoreTo": severity_score_to,
            "cves": cves,
            "epssScoreFrom": epss_score_from,
            "epssScoreTo": epss_score_to,
            "workflowTicketStatuses": workflow_ticket_statuses,
            "slaBreach": sla_breach,
            "workflowTicketSlaBreach": workflow_ticket_sla_breach,
            "tagKeys": tag_keys,
            "tagValues": tag_values,
            "tagCategories": tag_categories,
            "teamIds": team_ids,
        })
        return list(self.transport.paginate(
            "POST", "/v1/findings", json_body=body,
            page_size=page_size, max_items=max_items,
        ))

    def get_finding(self, finding_id):
        """Get one finding by its Phoenix ID."""
        return self.transport.request("GET", f"/v1/findings/{finding_id}")

    # -- enrichment ----------------------------------------------------------

    def enrich_finding(self, asset_type, asset_attributes, finding,
                       assessment_name=None):
        """Enrich/update a finding via the only available write path:
        POST /v1/import/assets with importType=merge.

        The target asset is matched by `asset_attributes`; `finding` must
        carry at least name/description/remedy/severity so Phoenix can match
        and update it. Supported enrichment: severity, description, remedy,
        location, referenceIds (CVEs), cwes, details, tags.
        """
        finding = dict(finding)
        if finding.get("tags"):
            finding["tags"] = parse_tags(finding["tags"])
        return self.import_assets(
            import_type="merge",
            assessment_name=assessment_name or "CLI Finding Enrichment",
            asset_type=asset_type,
            assets=[{
                "attributes": asset_attributes,
                "findings": [drop_none(finding)],
            }],
        )

    def update_finding_status(self, finding_id=None, status=None):
        """NOT SUPPORTED — flagged gap."""
        raise PhoenixNotSupportedError(
            "findings update-status",
            "API v1.27 exposes no endpoint to change a finding's status "
            "(open/close/risk-accept/false-positive).",
            "Statuses change via imports: an asset's findings absent from a "
            "'new'/'merge' import are auto-closed. Risk acceptance and "
            "false-positive workflows are UI-only.",
        )

    def add_finding_comment(self, finding_id=None, comment=None):
        """NOT SUPPORTED — flagged gap."""
        raise PhoenixNotSupportedError(
            "findings comment",
            "API v1.27 exposes no endpoint to comment on a finding.",
            "Use the platform UI, or attach context via the finding's "
            "'details' JSON on import (phx findings enrich).",
        )

    def override_finding_severity(self, finding_id=None, severity=None):
        """NOT SUPPORTED directly — flagged gap."""
        raise PhoenixNotSupportedError(
            "findings set-severity",
            "API v1.27 exposes no per-finding severity override endpoint.",
            "Re-import the finding with the new severity via "
            "'phx findings enrich' (importType=merge).",
        )
