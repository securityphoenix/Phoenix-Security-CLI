"""`phx assets` — asset search, tagging, creation and enrichment."""

import click

from phoenix_cli.api.assets import ASSET_TYPES
from phoenix_cli.api.imports import IMPORT_TYPES
from phoenix_cli.cli.context import (
    load_json_arg,
    parse_kv_pairs,
    pass_state,
    run,
)

ASSET_COLUMNS = ["id", "key", "type", "resourceType", "locality", "tags"]


@click.group()
def assets():
    """Assets: search, get, tag, create, enrich."""


@assets.command("list")
@click.option("--type", "types", multiple=True,
              type=click.Choice(ASSET_TYPES), help="Asset type (repeatable).")
@click.option("--app-env-id", help="Application/Environment ID scope.")
@click.option("--component-service-id", help="Component/Service ID scope.")
@click.option("--only-unassigned", is_flag=True, default=None,
              help="Only assets not assigned to any environment.")
@click.option("--filter", "filter_json",
              help="Raw filter JSON (inline or @file.json) — see docs.")
@click.option("--limit", type=int, help="Max assets to return.")
@click.option("--page-size", type=int, default=100, show_default=True)
@pass_state
@run
def list_assets(state, types, app_env_id, component_service_id,
                only_unassigned, filter_json, limit, page_size):
    """Search the asset registry."""
    filters = load_json_arg(filter_json, "filter")
    if isinstance(filters, dict):
        filters = [filters]
    result = state.client.search_assets(
        types=list(types) or None,
        application_environment_id=app_env_id,
        component_service_id=component_service_id,
        only_unassigned=only_unassigned,
        filters=filters,
        page_size=page_size,
        max_items=limit,
    )
    state.emit(result, columns=ASSET_COLUMNS)


@assets.command()
@click.argument("asset_id")
@pass_state
@run
def get(state, asset_id):
    """Get one asset by ID."""
    state.emit(state.client.get_asset(asset_id))


@assets.command()
@click.option("--asset-id", "asset_ids", multiple=True, required=True,
              help="Asset ID (repeatable for bulk tagging).")
@click.option("--tag", "tags", multiple=True, required=True,
              help="Tag as key:value or bare value (repeatable).")
@pass_state
@run
def tag(state, asset_ids, tags):
    """Add tags to one or more assets."""
    if len(asset_ids) == 1:
        result = state.client.add_asset_tags(tags, asset_id=asset_ids[0])
    else:
        result = state.client.add_asset_tags(tags, asset_ids=list(asset_ids))
    state.emit(result if result is not None
               else {"status": "ok", "tagged": list(asset_ids)})


def _software(entries):
    out = []
    for entry in entries or ():
        parts = str(entry).split(":")
        if len(parts) < 3:
            raise click.UsageError(
                f"--software expects vendor:name:version[:cpe], got '{entry}'")
        item = {"vendor": parts[0], "name": parts[1], "version": parts[2]}
        if len(parts) > 3 and parts[3]:
            item["cpe"] = parts[3]
        out.append(item)
    return out


@assets.command()
@click.option("--type", "asset_type", required=True,
              type=click.Choice(ASSET_TYPES), help="Asset type.")
@click.option("--attr", "attrs", multiple=True, required=True,
              help="Attribute key=value (repeatable). Required keys depend on "
                   "type: INFRA ip/hostname, WEB ip|fqdn, CLOUD providerType/"
                   "providerAccountId, CONTAINER dockerfile, REPOSITORY "
                   "repository, BUILD buildFile, CODE scannerSource.")
@click.option("--tag", "tags", multiple=True, help="Tag key:value (repeatable).")
@click.option("--software", "software", multiple=True,
              help="Installed software vendor:name:version[:cpe] (repeatable).")
@click.option("--assessment", help="Assessment name for the import.")
@click.option("--import-type", type=click.Choice(IMPORT_TYPES),
              default="merge", show_default=True)
@pass_state
@run
def create(state, asset_type, attrs, tags, software, assessment, import_type):
    """Create (upsert) an asset — implemented via POST /v1/import/assets.

    Phoenix has no direct asset-create endpoint (see `phx gaps`); assets are
    matched server-side by attributes, so re-running updates rather than
    duplicates.
    """
    result = state.client.create_asset(
        asset_type=asset_type,
        attributes=parse_kv_pairs(attrs, "attr"),
        tags=list(tags) or None,
        installed_software=_software(software) or None,
        assessment_name=assessment,
        import_type=import_type,
    )
    state.emit(result)


@assets.command()
@click.option("--type", "asset_type", required=True,
              type=click.Choice(ASSET_TYPES))
@click.option("--attr", "attrs", multiple=True, required=True,
              help="Matching + new attributes key=value (repeatable).")
@click.option("--tag", "tags", multiple=True, help="Tags to add (repeatable).")
@click.option("--software", "software", multiple=True,
              help="Installed software vendor:name:version[:cpe] (repeatable).")
@click.option("--assessment", help="Assessment name for the merge import.")
@pass_state
@run
def enrich(state, asset_type, attrs, tags, software, assessment):
    """Enrich an existing asset (attributes/tags/software) via import merge.

    The asset is matched by its attributes (ip/hostname, repository, ...).
    For tag-only enrichment by asset ID, use `phx assets tag` instead.
    """
    result = state.client.enrich_asset(
        asset_type=asset_type,
        attributes=parse_kv_pairs(attrs, "attr"),
        tags=list(tags) or None,
        installed_software=_software(software) or None,
        assessment_name=assessment,
    )
    state.emit(result)


@assets.command()
@click.argument("asset_id", required=False)
@pass_state
@run
def delete(state, asset_id):
    """[NOT SUPPORTED] Delete an asset — flagged API gap."""
    state.client.delete_asset(asset_id)


@assets.command("remove-tags")
@click.option("--asset-id")
@click.option("--tag", "tags", multiple=True)
@pass_state
@run
def remove_tags(state, asset_id, tags):
    """[NOT SUPPORTED] Remove asset tags — flagged API gap."""
    state.client.remove_asset_tags(asset_id, tags)
