"""`phx copilot` — Copilot patch plans."""

from __future__ import annotations

import uuid

import click

from phoenix_cli.cli.context import pass_state, run


@click.group()
def copilot():
    """Copilot: patch plans for an asset."""


@copilot.command()
@click.option("--asset-id", required=True, help="Asset to plan patches for.")
@click.option("--wait", is_flag=True,
              help="Wait for the job and print the plan instead of the job ID.")
@pass_state
@run
def plan(state, asset_id, wait):
    """Ask Copilot for a patch plan (a person still accepts it in Phoenix)."""
    if wait:
        try:
            result = state.client.wait_for_patch_plan(asset_id)
        except TimeoutError as exc:
            raise click.ClickException(str(exc))
        state.emit(result)
    else:
        job_id = state.client.start_patch_plan(asset_id, str(uuid.uuid4()))
        state.emit({"jobId": job_id})


@copilot.command()
@click.argument("job_id")
@pass_state
@run
def job(state, job_id):
    """Show the state of a Copilot job."""
    state.emit(state.client.get_job(job_id))
