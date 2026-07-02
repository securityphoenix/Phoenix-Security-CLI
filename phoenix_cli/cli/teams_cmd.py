"""`phx teams` — teams, membership, auto-link configuration."""

import click

from phoenix_cli.cli.context import pass_state, run

TEAM_COLUMNS = ["id", "name", "type", "usersCount"]


@click.group()
def teams():
    """Teams: list, members, create, auto-link rules."""


@teams.command("list")
@click.option("--limit", type=int)
@click.option("--page-size", type=int, default=100, show_default=True)
@pass_state
@run
def list_teams(state, limit, page_size):
    """List teams."""
    state.emit(state.client.list_teams(page_size=page_size, max_items=limit),
               columns=TEAM_COLUMNS)


@teams.command()
@click.argument("team_id")
@pass_state
@run
def get(state, team_id):
    """Get one team by ID."""
    state.emit(state.client.get_team(team_id))


@teams.command()
@click.argument("team_id")
@pass_state
@run
def members(state, team_id):
    """List team members."""
    state.emit(state.client.get_team_members(team_id))


@teams.command()
@click.option("--name", required=True)
@click.option("--type", "team_type", required=True,
              type=click.Choice(["GENERAL", "SECURITY"]))
@pass_state
@run
def create(state, name, team_type):
    """Create a team."""
    state.emit(state.client.create_team(name, team_type))


@teams.command("add-members")
@click.option("--id", "team_id", help="Team ID.")
@click.option("--name", "team_name", help="Team name (selector).")
@click.option("--user", "users", multiple=True, required=True,
              help="User email/ID (repeatable).")
@click.option("--auto-create", is_flag=True, default=None,
              help="Auto-create missing users (Org User role).")
@pass_state
@run
def add_members(state, team_id, team_name, users, auto_create):
    """Add members to a team."""
    result = state.client.add_team_members(
        list(users), team_id=team_id, team_name=team_name,
        auto_create_users=auto_create)
    state.emit(result if result is not None
               else {"status": "ok", "added": list(users)})


@teams.command("remove-member")
@click.argument("team_id")
@click.argument("user_email")
@pass_state
@run
def remove_member(state, team_id, user_email):
    """Remove one member from a team."""
    state.client.remove_team_member(team_id, user_email)
    state.emit({"status": "removed", "user": user_email})


@teams.command("auto-link")
@click.argument("team_id")
@click.option("--scope", type=click.Choice(["applications", "components"]),
              default="applications", show_default=True)
@click.option("--tag", "tags", multiple=True,
              help="Auto-link tag key:value (repeatable).")
@click.option("--match", type=click.Choice(["ANY", "ALL"]),
              help="Tag match mode.")
@click.option("--remove", is_flag=True,
              help="Remove the given tags instead of adding.")
@click.option("--clear", is_flag=True, help="Remove ALL auto-link tags.")
@click.option("--by-members/--no-by-members", default=None,
              help="Enable/disable auto-link by team members "
                   "(applications scope).")
@pass_state
@run
def auto_link(state, team_id, scope, tags, match, remove, clear, by_members):
    """Configure team auto-link rules (tags or by-members)."""
    if by_members is not None:
        state.client.set_auto_link_by_members(team_id, by_members)
        state.emit({"status": "ok",
                    "auto_link_by_members": "enabled" if by_members else "disabled"})
        return
    if clear:
        state.client.remove_auto_link_tags(team_id, scope)
        state.emit({"status": "ok", "cleared": scope})
        return
    if not tags:
        raise click.UsageError("Provide --tag, --clear or --by-members.")
    if remove:
        state.client.remove_auto_link_tags(team_id, scope, tags=list(tags))
        state.emit({"status": "ok", "removed": list(tags)})
    else:
        result = state.client.set_auto_link_tags(team_id, scope, list(tags),
                                                 match=match)
        state.emit(result if result is not None
                   else {"status": "ok", "configured": list(tags)})


@teams.command()
@click.argument("team_id", required=False)
@pass_state
@run
def delete(state, team_id):
    """[NOT SUPPORTED] Delete a team — flagged API gap."""
    state.client.delete_team(team_id)
