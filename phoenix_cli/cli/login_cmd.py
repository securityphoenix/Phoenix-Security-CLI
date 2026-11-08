"""`phx login` and `phx logout`: device login stored in the OS keychain."""

from __future__ import annotations

import click

from phoenix_cli import token_store
from phoenix_cli.cli.context import pass_state, run
from phoenix_cli.device_flow import device_login


@click.command()
@click.option("--client-name", default="phx", show_default=True,
              help="Name shown to the person who approves the login.")
@pass_state
@run
def login(state, client_name):
    """Log in as yourself through the browser (device login).

    The token goes to the operating system keychain. It is never printed.
    Needs: pip install "phoenix-security-cli[keyring]".
    """
    base_url = state.settings().base_url
    token, expires_at = device_login(base_url, client_name)
    try:
        token_store.save_token(base_url, token, expires_at)
    except RuntimeError as exc:
        raise click.ClickException(str(exc))
    click.echo(f"Logged in to {base_url}.")


@click.command()
@pass_state
@run
def logout(state):
    """Remove the stored login for the current base URL."""
    base_url = state.settings().base_url
    token_store.clear_token(base_url)
    click.echo(f"Logged out of {base_url}.")
