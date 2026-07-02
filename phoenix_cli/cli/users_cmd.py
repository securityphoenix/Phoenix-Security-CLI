"""`phx users` — organisation users."""

import click

from phoenix_cli.api.users import USER_ROLES
from phoenix_cli.cli.context import pass_state, run

USER_COLUMNS = ["id", "email", "firstName", "lastName", "role", "active"]


@click.group()
def users():
    """Users: list, create, activate, deactivate."""


@users.command("list")
@click.option("--limit", type=int)
@click.option("--page-size", type=int, default=100, show_default=True)
@pass_state
@run
def list_users(state, limit, page_size):
    """List organisation users."""
    state.emit(state.client.list_users(page_size=page_size, max_items=limit),
               columns=USER_COLUMNS)


@users.command()
@click.option("--email", required=True)
@click.option("--first-name", required=True)
@click.option("--last-name", required=True)
@click.option("--role", required=True, type=click.Choice(USER_ROLES))
@pass_state
@run
def create(state, email, first_name, last_name, role):
    """Create a user (the platform emails a welcome + one-time password)."""
    state.emit(state.client.create_user(email, first_name, last_name, role))


@users.command()
@click.option("--id", "ids", multiple=True, help="User ID (repeatable).")
@click.option("--email", "emails", multiple=True,
              help="User email (repeatable).")
@pass_state
@run
def activate(state, ids, emails):
    """Re-activate previously deactivated users."""
    state.client.activate_users(ids=list(ids) or None,
                                emails=list(emails) or None)
    state.emit({"status": "activated", "ids": list(ids),
                "emails": list(emails)})


@users.command()
@click.option("--id", "ids", multiple=True, help="User ID (repeatable).")
@click.option("--email", "emails", multiple=True,
              help="User email (repeatable).")
@click.option("--yes", is_flag=True, help="Skip confirmation.")
@pass_state
@run
def deactivate(state, ids, emails, yes):
    """Deactivate users (immediate loss of platform access)."""
    targets = list(ids) + list(emails)
    if not yes:
        click.confirm(f"Deactivate {len(targets)} user(s): "
                      f"{', '.join(targets)}?", abort=True)
    state.client.deactivate_users(ids=list(ids) or None,
                                  emails=list(emails) or None)
    state.emit({"status": "deactivated", "ids": list(ids),
                "emails": list(emails)})


@users.command()
@click.argument("user", required=False)
@pass_state
@run
def delete(state, user):
    """[NOT SUPPORTED] Delete a user — flagged API gap."""
    state.client.delete_user(user)
