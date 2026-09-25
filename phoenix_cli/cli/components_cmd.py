"""`phx components` / `phx services` — Components, Services & asset rules."""

import click

from phoenix_cli.cli.context import load_json_arg, pass_state, run

COMPONENT_COLUMNS = ["id", "applicationId", "name", "criticality",
                     "effectiveExposure", "tags"]


@click.group()
def components():
    """Components & Services: list, posture, create, rules, deploy."""


@components.command("list")
@click.option("--parent-id", help="Application/Environment ID scope.")
@click.option("--type", "entity_type",
              type=click.Choice(["COMPONENT", "SERVICE"]))
@click.option("--limit", type=int)
@click.option("--page-size", type=int, default=100, show_default=True)
@pass_state
@run
def list_components(state, parent_id, entity_type, limit, page_size):
    """List components and services.

    `effectiveExposure` is the exposure Phoenix calculated (INTERNAL, DMZ or
    EXTERNAL), or the declared exposure if none has been calculated yet.
    """
    result = state.client.list_components(parent_id=parent_id,
                                          entity_type=entity_type,
                                          page_size=page_size,
                                          max_items=limit)
    state.emit(result, columns=COMPONENT_COLUMNS)


@components.command()
@click.argument("component_id")
@pass_state
@run
def get(state, component_id):
    """Get one component/service by ID."""
    state.emit(state.client.get_component(component_id))


@components.command()
@click.option("--id", "component_id", help="Component/Service ID.")
@click.option("--app-name", help="Parent application name (selector).")
@click.option("--name", "component_name", help="Component name (selector).")
@click.option("--exclude-risk-accepted", is_flag=True, default=None)
@pass_state
@run
def posture(state, component_id, app_name, component_name,
            exclude_risk_accepted):
    """Risk posture by ID, or by app-name + name."""
    state.emit(state.client.get_component_posture(
        component_id=component_id, app_name=app_name,
        component_name=component_name,
        exclude_risk_accepted=exclude_risk_accepted))


@components.command()
@click.option("--app-name", help="Parent application/environment name.")
@click.option("--app-id", help="Parent application/environment ID.")
@click.option("--name", required=True, help="New component/service name.")
@click.option("--criticality", type=click.IntRange(1, 10))
@click.option("--tag", "tags", multiple=True)
@pass_state
@run
def create(state, app_name, app_id, name, criticality, tags):
    """Create a component (in an app) or service (in an environment)."""
    state.emit(state.client.create_component(
        name=name, app_name=app_name, app_id=app_id,
        criticality=criticality, tags=list(tags) or None))


@components.command()
@click.argument("component_id")
@click.option("--new-name")
@click.option("--criticality", type=click.IntRange(1, 10))
@click.option("--tag", "tags", multiple=True, help="Tags to ADD (repeatable).")
@pass_state
@run
def update(state, component_id, new_name, criticality, tags):
    """Update a component/service (tags are additive)."""
    state.emit(state.client.update_component(
        component_id, new_name=new_name, criticality=criticality,
        tags=list(tags) or None))


@components.command("add-tags")
@click.argument("component_id")
@click.option("--tag", "tags", multiple=True, required=True)
@pass_state
@run
def add_tags(state, component_id, tags):
    """Add tags to a component/service."""
    state.emit(state.client.add_component_tags(component_id, tags))


@components.command("remove-tags")
@click.argument("component_id")
@click.option("--tag", "tags", multiple=True, required=True)
@pass_state
@run
def remove_tags(state, component_id, tags):
    """Remove tags from a component/service."""
    result = state.client.remove_component_tags(component_id, tags)
    state.emit(result if result is not None else {"status": "removed"})


@components.command()
@click.option("--id", "component_id", help="Component/Service ID.")
@click.option("--app-name", help="Parent app name (selector variant).")
@click.option("--app-id", help="Parent app ID (selector variant).")
@click.option("--name", "component_name", help="Component name (selector).")
@click.option("--yes", is_flag=True, help="Skip confirmation.")
@pass_state
@run
def delete(state, component_id, app_name, app_id, component_name, yes):
    """Delete a component/service (by ID, or app + name selector)."""
    target = component_id or f"{app_name or app_id}/{component_name}"
    if not yes:
        click.confirm(f"Delete component/service '{target}'?", abort=True)
    state.client.delete_component(component_id=component_id,
                                  app_name=app_name, app_id=app_id,
                                  component_name=component_name)
    state.emit({"status": "deleted", "target": target})


@components.command()
@click.argument("component_id")
@click.option("--service-id", "service_ids", multiple=True)
@click.option("--service-name", "service_names", multiple=True)
@click.option("--service-tag", "service_tags", multiple=True)
@click.option("--inherit-from-app", is_flag=True, default=None,
              help="Inherit deployment config from the application.")
@click.option("--no-replace", is_flag=True,
              help="Add to existing links instead of replacing.")
@pass_state
@run
def deploy(state, component_id, service_ids, service_names, service_tags,
           inherit_from_app, no_replace):
    """Link a component to the service(s) it deploys onto."""
    result = state.client.add_component_deployment(
        component_id,
        service_ids=list(service_ids) or None,
        service_names=list(service_names) or None,
        service_tags=list(service_tags) or None,
        inherit_from_app=inherit_from_app,
        replace_existing=False if no_replace else None)
    state.emit(result if result is not None else {"status": "linked"})


@components.command("add-rules")
@click.option("--id", "component_id", help="Component/Service ID.")
@click.option("--app-name", help="Parent app name (selector variant).")
@click.option("--name", "component_name", help="Component name (selector).")
@click.option("--rules", "rules_json", required=True,
              help="Rules JSON array (inline or @file.json): "
                   '[{"name":"...","filter":{...}}]')
@click.option("--reset", is_flag=True, default=None,
              help="Replace ALL existing rules with these.")
@pass_state
@run
def add_rules(state, component_id, app_name, component_name, rules_json,
              reset):
    """Add asset-association rules to a component/service.

    Filter fields: ids, keyLike, tags, providerAccountId/Name, resourceGroup,
    assetType, cidrs, ipRanges, hostnames, osNames, netbios, fqdn,
    repository, negateFilter (non-nested).
    """
    rules = load_json_arg(rules_json, "rules")
    if isinstance(rules, dict):
        rules = [rules]
    result = state.client.add_component_rules(
        rules, component_id=component_id, app_name=app_name,
        component_name=component_name, reset_rules=reset)
    state.emit(result if result is not None else {"status": "rules added"})


# `phx services` is a full alias of `phx components` (Environments side).
services = click.Group(name="services", help="Alias of `components`.",
                       commands=components.commands)
