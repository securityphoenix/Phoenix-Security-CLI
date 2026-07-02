"""`phx auth` — authentication commands."""

import click

from phoenix_cli.cli.context import pass_state, run


@click.group()
def auth():
    """Authentication: verify credentials, mint tokens."""


@auth.command()
@pass_state
@run
def test(state):
    """Verify credentials and connectivity (auth + one minimal read)."""
    state.emit(state.client.test_connection())


@auth.command()
@pass_state
@run
def token(state):
    """Print a fresh Bearer access token (for use with curl etc.).

    Note: the token is printed to stdout — avoid pasting it into logs.
    """
    state.client.transport.authenticate()
    click.echo(state.client.transport._token)
