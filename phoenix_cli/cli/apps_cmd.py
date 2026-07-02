"""`phx apps` / `phx envs` — Applications & Environments."""

import click

from phoenix_cli.cli.context import load_json_arg, pass_state, run

APP_COLUMNS = ["id", "name", "type", "subType", "criticality", "risk",
               "threshold", "aboveThreshold"]


def _ticketing(project, integration_type):
    if not project:
        return None
    block = {"projectName": project}
    if integration_type:
        block["integrationType"] = integration_type
    return block


def _messaging(channel):
    return {"channelName": channel} if channel else None


@click.group()
def apps():
    """Applications & Environments: list, posture, create, update, link."""


@apps.command("list")
@click.option("--type", "entity_type",
              type=click.Choice(["APPLICATION", "ENVIRONMENT"]),
              help="Filter by entity type.")
@click.option("--limit", type=int)
@click.option("--page-size", type=int, default=100, show_default=True)
@pass_state
@run
def list_apps(state, entity_type, limit, page_size):
    """List applications and environments."""
    result = state.client.list_applications(entity_type=entity_type,
                                            page_size=page_size,
                                            max_items=limit)
    state.emit(result, columns=APP_COLUMNS)


@apps.command()
@click.argument("application_id")
@pass_state
@run
def get(state, application_id):
    """Get one application/environment by ID."""
    state.emit(state.client.get_application(application_id))


@apps.command()
@click.option("--id", "application_id", help="Application/Environment ID.")
@click.option("--name", help="Application/Environment name (selector).")
@click.option("--ignore-case", is_flag=True, default=None)
@click.option("--exclude-risk-accepted", is_flag=True, default=None)
@pass_state
@run
def posture(state, application_id, name, ignore_case, exclude_risk_accepted):
    """Risk posture (findings by risk, asset counts) by ID or name."""
    state.emit(state.client.get_application_posture(
        application_id=application_id, name=name,
        case_sensitive=(not ignore_case) if ignore_case else None,
        exclude_risk_accepted=exclude_risk_accepted))


@apps.command()
@click.option("--name", required=True)
@click.option("--type", "entity_type", default="APPLICATION",
              show_default=True,
              type=click.Choice(["APPLICATION", "ENVIRONMENT"]))
@click.option("--sub-type", type=click.Choice(["CLOUD", "INFRA"]),
              help="Required for ENVIRONMENT.")
@click.option("--criticality", type=click.IntRange(1, 10), required=True)
@click.option("--owner", required=True, help="Owner email (or user ID).")
@click.option("--threshold", type=click.IntRange(0, 1000))
@click.option("--value", type=click.IntRange(1000, 10000000),
              help="Business value.")
@click.option("--responsible-user", "responsible_users", multiple=True,
              help="Responsible user email/ID (repeatable).")
@click.option("--tag", "tags", multiple=True, help="Tag key:value (repeatable).")
@click.option("--ticketing-project", help="Ticketing project name/key.")
@click.option("--ticketing-type",
              type=click.Choice(["JIRA", "JIRA_DC", "ADO", "GITHUB",
                                 "SERVICE_NOW"]))
@click.option("--messaging-channel", help="Messaging (Slack) channel name.")
@pass_state
@run
def create(state, name, entity_type, sub_type, criticality, owner, threshold,
           value, responsible_users, tags, ticketing_project, ticketing_type,
           messaging_channel):
    """Create an application or environment."""
    state.emit(state.client.create_application(
        name=name, entity_type=entity_type, sub_type=sub_type,
        criticality=criticality, owner=owner, threshold=threshold,
        value=value, responsible_users=list(responsible_users) or None,
        tags=list(tags) or None,
        ticketing=_ticketing(ticketing_project, ticketing_type),
        messaging=_messaging(messaging_channel)))


@apps.command()
@click.option("--name", required=True, help="Current name (selector).")
@click.option("--ignore-case", is_flag=True, default=None)
@click.option("--new-name")
@click.option("--criticality", type=click.IntRange(1, 10))
@click.option("--threshold", type=click.IntRange(0, 1000))
@click.option("--value", type=click.IntRange(1000, 10000000))
@click.option("--owner", help="New owner email/ID.")
@click.option("--ticketing-project")
@click.option("--ticketing-type",
              type=click.Choice(["JIRA", "JIRA_DC", "ADO", "GITHUB",
                                 "SERVICE_NOW"]))
@click.option("--messaging-channel")
@pass_state
@run
def update(state, name, ignore_case, new_name, criticality, threshold, value,
           owner, ticketing_project, ticketing_type, messaging_channel):
    """Update an application/environment (identified by name)."""
    state.emit(state.client.update_application(
        name=name,
        case_sensitive=(not ignore_case) if ignore_case else None,
        new_name=new_name, criticality=criticality, threshold=threshold,
        value=value, owner=owner,
        ticketing=_ticketing(ticketing_project, ticketing_type),
        messaging=_messaging(messaging_channel)))


@apps.command("add-tags")
@click.option("--id", "application_id")
@click.option("--name")
@click.option("--tag", "tags", multiple=True, required=True)
@pass_state
@run
def add_tags(state, application_id, name, tags):
    """Add tags to an app/env (by ID or name)."""
    state.emit(state.client.add_application_tags(
        tags, application_id=application_id, name=name))


@apps.command("remove-tags")
@click.option("--id", "application_id")
@click.option("--name")
@click.option("--tag", "tags", multiple=True, required=True)
@pass_state
@run
def remove_tags(state, application_id, name, tags):
    """Remove tags from an app/env (by ID or name)."""
    result = state.client.remove_application_tags(
        tags, application_id=application_id, name=name)
    state.emit(result if result is not None else {"status": "removed"})


@apps.command("add-users")
@click.option("--id", "application_id")
@click.option("--name")
@click.option("--user", "users", multiple=True, required=True,
              help="Responsible user email/ID (repeatable).")
@pass_state
@run
def add_users(state, application_id, name, users):
    """Add responsible users to an app/env."""
    state.emit(state.client.add_responsible_users(
        list(users), application_id=application_id, name=name))


@apps.command()
@click.option("--id", "application_id")
@click.option("--name")
@click.option("--service-id", "service_ids", multiple=True)
@click.option("--service-name", "service_names", multiple=True)
@click.option("--service-tag", "service_tags", multiple=True)
@click.option("--no-replace", is_flag=True,
              help="Add to existing deployment links instead of replacing.")
@pass_state
@run
def deploy(state, application_id, name, service_ids, service_names,
           service_tags, no_replace):
    """Link an application to the service(s) it deploys onto."""
    state.emit(state.client.add_application_deployment(
        application_id=application_id, name=name,
        service_ids=list(service_ids) or None,
        service_names=list(service_names) or None,
        service_tags=list(service_tags) or None,
        replace_existing=False if no_replace else None))


@apps.command("link-repo")
@click.option("--id", "application_id")
@click.option("--name")
@click.option("--repository", required=True, help="Repository name.")
@click.option("--search", help="Asset-ID substring filter within the repo.")
@click.option("--component", "component_json",
              help='Target component JSON, e.g. \'{"name":"api"}\' '
                   "(inline or @file.json); omitted = new component named "
                   "after the repository.")
@pass_state
@run
def link_repo(state, application_id, name, repository, search, component_json):
    """Add a repository rule to an app/env."""
    state.emit(state.client.link_repository(
        repository, application_id=application_id, name=name, search=search,
        component=load_json_arg(component_json, "component")))


@apps.command()
@click.argument("application_id", required=False)
@pass_state
@run
def delete(state, application_id):
    """[NOT SUPPORTED] Delete an app/env — flagged API gap."""
    state.client.delete_application(application_id)


# `phx envs` — convenience view over environments.
@click.group()
def envs():
    """Environments (convenience wrappers over `apps`)."""


@envs.command("list")
@click.option("--limit", type=int)
@click.option("--page-size", type=int, default=100, show_default=True)
@pass_state
@run
def list_envs(state, limit, page_size):
    """List environments only."""
    result = state.client.list_applications(entity_type="ENVIRONMENT",
                                            page_size=page_size,
                                            max_items=limit)
    state.emit(result, columns=APP_COLUMNS)


@envs.command("create")
@click.option("--name", required=True)
@click.option("--sub-type", required=True, type=click.Choice(["CLOUD", "INFRA"]))
@click.option("--criticality", type=click.IntRange(1, 10), required=True)
@click.option("--owner", required=True, help="Owner email (or user ID).")
@click.option("--threshold", type=click.IntRange(0, 1000))
@click.option("--tag", "tags", multiple=True)
@pass_state
@run
def create_env(state, name, sub_type, criticality, owner, threshold, tags):
    """Create an environment (shortcut for apps create --type ENVIRONMENT)."""
    state.emit(state.client.create_application(
        name=name, entity_type="ENVIRONMENT", sub_type=sub_type,
        criticality=criticality, owner=owner, threshold=threshold,
        tags=list(tags) or None))
