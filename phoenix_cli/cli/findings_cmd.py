"""`phx findings` (alias `phx vulns`) — search, retrieve, enrich findings."""

import click

from phoenix_cli.api.assets import ASSET_TYPES
from phoenix_cli.api.findings import (
    ASSET_LOCALITIES,
    FINDING_STATUSES,
    FINDING_TYPES,
    TAG_CATEGORIES,
)
from phoenix_cli.cli.context import (
    load_json_arg,
    parse_kv_pairs,
    pass_state,
    run,
)

FINDING_COLUMNS = ["id", "severityScore", "status", "scannerType",
                   "location", "assetId", "daysOpen"]


@click.group()
def findings():
    """Findings (vulnerabilities): search, get, enrich."""


@findings.command("list")
@click.option("--app-env-id", help="Application/Environment ID.")
@click.option("--component-service-id", help="Component/Service ID.")
@click.option("--asset-id", help="Asset ID.")
@click.option("--team-id", "team_ids", multiple=True, help="Team ID (repeatable).")
@click.option("--type", "finding_type", type=click.Choice(FINDING_TYPES))
@click.option("--status", "statuses", multiple=True,
              type=click.Choice(FINDING_STATUSES), help="OPEN/CLOSED (repeatable).")
@click.option("--scanner-type", "scanner_types", multiple=True,
              help="Scanner code (repeatable).")
@click.option("--locality", "localities", multiple=True,
              type=click.Choice(ASSET_LOCALITIES))
@click.option("--assigned", "assigned_status",
              type=click.Choice(["ASSIGNED", "UNASSIGNED"]))
@click.option("--severity-from", help="Min severity score (0-1000).")
@click.option("--severity-to", help="Max severity score (0-1000).")
@click.option("--epss-from", help="Min EPSS score (0.0-1.0).")
@click.option("--epss-to", help="Max EPSS score (0.0-1.0).")
@click.option("--cve", "cves", multiple=True, help="CVE-... (repeatable).")
@click.option("--date-from", help="yyyy-MM-dd")
@click.option("--date-to", help="yyyy-MM-dd")
@click.option("--suggested-to-fix", is_flag=True, default=None)
@click.option("--zero-day", is_flag=True, default=None)
@click.option("--sla-breach", type=click.Choice(["true", "false"]))
@click.option("--ticket-sla-breach", type=click.Choice(["true", "false"]))
@click.option("--ticket-status", "ticket_statuses", multiple=True)
@click.option("--tag-key", "tag_keys", multiple=True)
@click.option("--tag-value", "tag_values", multiple=True)
@click.option("--tag-category", "tag_categories", multiple=True,
              type=click.Choice(TAG_CATEGORIES))
@click.option("--limit", type=int, help="Max findings to return.")
@click.option("--page-size", type=int, default=100, show_default=True)
@pass_state
@run
def list_findings(state, app_env_id, component_service_id, asset_id, team_ids,
                  finding_type, statuses, scanner_types, localities,
                  assigned_status, severity_from, severity_to, epss_from,
                  epss_to, cves, date_from, date_to, suggested_to_fix,
                  zero_day, sla_breach, ticket_sla_breach, ticket_statuses,
                  tag_keys, tag_values, tag_categories, limit, page_size):
    """Search findings with any v1.27 filter combination."""
    result = state.client.search_findings(
        application_environment_id=app_env_id,
        component_service_id=component_service_id,
        asset_id=asset_id,
        team_ids=list(team_ids) or None,
        finding_type=finding_type,
        status=list(statuses) or None,
        scanner_types=list(scanner_types) or None,
        asset_localities=list(localities) or None,
        asset_assigned_status=assigned_status,
        severity_score_from=severity_from,
        severity_score_to=severity_to,
        epss_score_from=epss_from,
        epss_score_to=epss_to,
        cves=list(cves) or None,
        date_from=date_from,
        date_to=date_to,
        suggested_to_fix=suggested_to_fix,
        zero_day_alert=zero_day,
        sla_breach=sla_breach,
        workflow_ticket_sla_breach=ticket_sla_breach,
        workflow_ticket_statuses=list(ticket_statuses) or None,
        tag_keys=list(tag_keys) or None,
        tag_values=list(tag_values) or None,
        tag_categories=list(tag_categories) or None,
        page_size=page_size,
        max_items=limit,
    )
    state.emit(result, columns=FINDING_COLUMNS)


@findings.command()
@click.argument("finding_id")
@pass_state
@run
def get(state, finding_id):
    """Get one finding by ID."""
    state.emit(state.client.get_finding(finding_id))


@findings.command()
@click.option("--asset-type", required=True, type=click.Choice(ASSET_TYPES),
              help="Type of the asset carrying the finding.")
@click.option("--asset-attr", "asset_attrs", multiple=True, required=True,
              help="Asset matching attributes key=value (repeatable). The "
                   "asset is created if it does not exist.")
@click.option("--name", required=True, help="Finding name.")
@click.option("--description", required=True)
@click.option("--remedy", required=True)
@click.option("--severity", required=True, help='"1.0"–"10.0"')
@click.option("--location", help="Source file / asset location.")
@click.option("--cve", "cves", multiple=True, help="Reference ID (repeatable).")
@click.option("--cwe", "cwes", multiple=True, help="CWE-xxxx (repeatable).")
@click.option("--tag", "tags", multiple=True, help="Tag key:value (repeatable).")
@click.option("--details", help="Extra details JSON (inline or @file.json).")
@click.option("--assessment", help="Assessment name (default: CLI Finding "
                                   "Additions).")
@pass_state
@run
def add(state, asset_type, asset_attrs, name, description, remedy, severity,
        location, cves, cwes, tags, details, assessment):
    """Add a NEW vulnerability/finding to an asset (import delta — never
    closes or alters other findings)."""
    finding = {
        "name": name,
        "description": description,
        "remedy": remedy,
        "severity": severity,
        "location": location,
        "referenceIds": list(cves) or None,
        "cwes": list(cwes) or None,
        "tags": list(tags) or None,
        "details": load_json_arg(details, "details"),
    }
    result = state.client.add_finding(
        asset_type=asset_type,
        asset_attributes=parse_kv_pairs(asset_attrs, "asset-attr"),
        finding={k: v for k, v in finding.items() if v is not None},
        assessment_name=assessment,
    )
    state.emit(result)


@findings.command()
@click.argument("finding_id")
@click.option("--assessment", required=True,
              help="Assessment that owns the finding (closure is "
                   "assessment-scoped in Phoenix).")
@click.option("--dry-run", is_flag=True,
              help="Show the merge payload without importing.")
@click.option("--yes", is_flag=True, help="Skip confirmation.")
@pass_state
@run
def close(state, finding_id, assessment, dry_run, yes):
    """Close a finding (workaround — no direct close endpoint in v1.27).

    Re-imports the finding's asset within the SAME assessment via merge,
    omitting this finding: Phoenix then closes it. The asset's other OPEN
    findings are re-sent so they stay open. See `phx gaps --required`.
    """
    if dry_run:
        state.emit(state.client.close_finding(finding_id, assessment,
                                              dry_run=True))
        return
    if not yes:
        click.confirm(
            f"Close finding {finding_id} by re-importing its asset into "
            f"assessment '{assessment}' (merge, omitting this finding)?",
            abort=True)
    state.emit(state.client.close_finding(finding_id, assessment))


@findings.command()
@click.option("--asset-type", required=True, type=click.Choice(ASSET_TYPES),
              help="Type of the asset carrying the finding.")
@click.option("--asset-attr", "asset_attrs", multiple=True, required=True,
              help="Asset matching attributes key=value (repeatable).")
@click.option("--name", required=True, help="Finding name (as imported).")
@click.option("--description", required=True)
@click.option("--remedy", required=True)
@click.option("--severity", required=True, help='"1.0"–"10.0"')
@click.option("--location", help="Source file / asset location.")
@click.option("--cve", "cves", multiple=True, help="Reference ID (repeatable).")
@click.option("--cwe", "cwes", multiple=True, help="CWE-xxxx (repeatable).")
@click.option("--tag", "tags", multiple=True, help="Tag key:value (repeatable).")
@click.option("--details", help="Extra details JSON (inline or @file.json).")
@click.option("--assessment", help="Assessment name for the merge import.")
@pass_state
@run
def enrich(state, asset_type, asset_attrs, name, description, remedy,
           severity, location, cves, cwes, tags, details, assessment):
    """Enrich/update a finding via import merge (the only API write path).

    Phoenix has no single-finding update endpoint (see `phx gaps`); this
    re-imports the finding with updated fields against the matching asset.
    """
    finding = {
        "name": name,
        "description": description,
        "remedy": remedy,
        "severity": severity,
        "location": location,
        "referenceIds": list(cves) or None,
        "cwes": list(cwes) or None,
        "tags": list(tags) or None,
        "details": load_json_arg(details, "details"),
    }
    result = state.client.enrich_finding(
        asset_type=asset_type,
        asset_attributes=parse_kv_pairs(asset_attrs, "asset-attr"),
        finding={k: v for k, v in finding.items() if v is not None},
        assessment_name=assessment,
    )
    state.emit(result)


@findings.command("update-status")
@click.argument("finding_id", required=False)
@click.option("--status")
@pass_state
@run
def update_status(state, finding_id, status):
    """[NOT SUPPORTED] Change a finding's status — flagged API gap."""
    state.client.update_finding_status(finding_id, status)


@findings.command("set-severity")
@click.argument("finding_id", required=False)
@click.option("--severity")
@pass_state
@run
def set_severity(state, finding_id, severity):
    """[NOT SUPPORTED] Override a finding's severity — flagged API gap."""
    state.client.override_finding_severity(finding_id, severity)


@findings.command()
@click.argument("finding_id", required=False)
@click.option("--message")
@pass_state
@run
def comment(state, finding_id, message):
    """[NOT SUPPORTED] Comment on a finding — flagged API gap."""
    state.client.add_finding_comment(finding_id, message)


# `phx vulns` is a full alias of `phx findings` (matching the
# /v1/vulnerabilities API alias).
vulns = click.Group(name="vulns", help="Alias of `findings`.",
                    commands=findings.commands)
