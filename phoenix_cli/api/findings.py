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
from phoenix_cli.errors import PhoenixConfigError, PhoenixNotSupportedError


def _finding_to_import(finding):
    """Convert a search/get finding object back into import format
    (best effort — used when rebuilding an asset report to close one
    finding via merge semantics)."""
    data = (finding.get("data") or [{}])[0]
    severity_score = finding.get("severityScore") or 0
    severity = max(1.0, min(10.0, round(float(severity_score) / 100.0, 1)))
    reference_ids = [d.get("cve") for d in (finding.get("data") or [])
                     if d.get("cve")]
    tags = [{k: v for k, v in t.items() if k in ("key", "value") and v}
            for t in (finding.get("tags") or []) if t.get("value")]
    return drop_none({
        "name": data.get("name"),
        "description": data.get("description") or data.get("name"),
        "remedy": data.get("remedy") or "See original finding",
        "severity": str(severity),
        "location": finding.get("location"),
        "referenceIds": reference_ids or None,
        "tags": tags or None,
    })

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

    # -- write operations (via the import pipeline) ---------------------------

    def add_finding(self, asset_type, asset_attributes, finding,
                    assessment_name=None):
        """Add a NEW vulnerability/finding to an asset.

        Uses importType='delta' — adds/updates only what is in the payload
        and never closes other findings. The target asset is matched by
        `asset_attributes` (created if absent). `finding` requires name,
        description, remedy, severity ("1.0"-"10.0"); optional location,
        referenceIds, cwes, details, tags.
        """
        finding = dict(finding)
        if finding.get("tags"):
            finding["tags"] = parse_tags(finding["tags"])
        return self.import_assets(
            import_type="delta",
            assessment_name=assessment_name or "CLI Finding Additions",
            asset_type=asset_type,
            assets=[{
                "attributes": asset_attributes,
                "findings": [drop_none(finding)],
            }],
        )

    def close_finding(self, finding_id, assessment_name, dry_run=False):
        """Close a finding via the only mechanism API v1.27 offers:
        re-import the asset within the SAME assessment with importType=
        'merge', omitting the target finding — Phoenix closes findings
        absent from a merge report.

        assessment_name MUST be the assessment that owns the finding
        (closure is assessment-scoped). dry_run=True returns the payload
        that would be sent without importing.

        Returns a summary dict. Raises PhoenixNotSupportedError context via
        docs — a direct close endpoint does not exist (see gaps registry).
        """
        finding = self.get_finding(finding_id)
        if str(finding.get("status", "")).upper() == "CLOSED":
            return {"status": "already-closed", "findingId": finding_id}
        asset_id = finding.get("assetId")
        if not asset_id:
            raise PhoenixConfigError(
                f"Finding {finding_id} carries no assetId; cannot rebuild "
                "the asset report to close it.")
        asset = self.get_asset(asset_id)
        attributes = {}
        for entry in asset.get("data") or []:
            for key, value in (entry.get("attributes") or {}).items():
                attributes.setdefault(key, value)
        if not attributes:
            raise PhoenixConfigError(
                f"Asset {asset_id} exposes no attributes; cannot rebuild "
                "its import payload.")
        siblings = [
            f for f in self.search_findings(asset_id=asset_id,
                                            status=["OPEN"])
            if f.get("id") != finding_id
        ]
        kept = [_finding_to_import(f) for f in siblings]
        payload_assets = [{"attributes": attributes, "findings": kept}]
        summary = {
            "findingId": finding_id,
            "assetId": asset_id,
            "assessment": assessment_name,
            "keptOpenFindings": len(kept),
            "mechanism": "merge re-import omitting the finding "
                         "(no direct close endpoint in API v1.27)",
        }
        if dry_run:
            summary["payload"] = {
                "importType": "merge",
                "assessment": {"assetType": asset.get("type"),
                               "name": assessment_name},
                "assets": payload_assets,
            }
            summary["status"] = "dry-run"
            return summary
        self.import_assets(
            import_type="merge",
            assessment_name=assessment_name,
            asset_type=asset.get("type"),
            assets=payload_assets,
        )
        summary["status"] = "close-requested"
        return summary

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
