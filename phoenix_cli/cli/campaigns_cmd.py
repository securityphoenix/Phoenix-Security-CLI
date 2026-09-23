"""`phx campaigns` — Campaign statistics (read-only)."""

import click

from phoenix_cli.cli.context import pass_state, run


@click.group()
def campaigns():
    """Campaigns: aggregated statistics."""


@campaigns.command()
@click.argument("campaign_id")
@pass_state
@run
def stats(state, campaign_id):
    """Aggregated risk/finding/asset/SLA stats for a campaign (by ID).

    The campaign ID is the UUID from the campaign's page URL in the platform.
    `stats` is null if no daily snapshot has been generated yet.
    """
    state.emit(state.client.get_campaign_stats(campaign_id))
