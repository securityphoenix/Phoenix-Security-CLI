"""`phx autopatcher` — read-only autopatcher commands.

There is no command that accepts a plan or sets an asset usage: a person does
that in Phoenix. When an organisation turns on automatic acceptance for a
usage, Phoenix accepts a new plan whose actions are all auto by itself.
"""

from __future__ import annotations

import click

from phoenix_cli.cli.context import pass_state, run


@click.group()
def autopatcher():
    """Autopatcher: asset lookup, patch policy and patch plans (read-only)."""


@autopatcher.command()
@click.option("--hostname", help="Host name or FQDN to look up.")
@click.option("--ip", help="IP address to look up.")
@pass_state
@run
def lookup(state, hostname, ip):
    """Find the Phoenix assets that match a host name and/or an IP address."""
    state.emit(state.client.lookup_asset(hostname=hostname, ip=ip))


@autopatcher.command()
@click.option("--usage", required=True,
              help="Asset usage, e.g. server or developer-laptop.")
@pass_state
@run
def policy(state, usage):
    """Show the patch policy for a usage."""
    state.emit(state.client.get_patch_policy(usage))


@autopatcher.group()
def plan():
    """Patch plans."""


@plan.command("get")
@click.argument("plan_id")
@pass_state
@run
def plan_get(state, plan_id):
    """Show a patch plan by ID."""
    state.emit(state.client.get_patch_plan(plan_id))
