"""`phx import` — bulk asset/finding imports (POST /v1/import/assets)."""

import json

import click

from phoenix_cli.api.imports import ASSESSMENT_ASSET_TYPES, IMPORT_TYPES
from phoenix_cli.cli.context import pass_state, run

TEMPLATES = {
    "INFRA": {
        "importType": "delta",
        "assessment": {"assetType": "INFRA", "name": "My Infra Scan"},
        "assets": [{
            "attributes": {"ip": "10.1.2.3", "hostname": "web-01",
                           "os": "Ubuntu 22.04", "fqdn": "web-01.example.com"},
            "tags": [{"key": "env", "value": "production"}],
            "installedSoftware": [
                {"vendor": "openssl", "name": "openssl", "version": "3.0.13"}],
            "findings": [{
                "name": "Example vulnerability",
                "description": "What is wrong",
                "remedy": "How to fix it",
                "severity": "7.5",
                "location": "web-01",
                "referenceIds": ["CVE-2024-0001"],
                "cwes": ["CWE-79"],
            }],
        }],
    },
    "CONTAINER": {
        "importType": "delta",
        "assessment": {"assetType": "CONTAINER", "name": "My Container Scan"},
        "assets": [{
            "attributes": {"dockerfile": "myorg/api:1.4.2", "origin": "github"},
            "tags": [{"value": "backend"}],
            "findings": [{
                "name": "Vulnerable base image package",
                "description": "What is wrong",
                "remedy": "Upgrade the package",
                "severity": "9.8",
                "referenceIds": ["CVE-2024-0002"],
            }],
        }],
    },
    "CLOUD": {
        "importType": "delta",
        "assessment": {"assetType": "CLOUD", "name": "My Cloud Scan"},
        "assets": [{
            "attributes": {"providerType": "AWS",
                           "providerAccountId": "123456789012",
                           "region": "eu-west-1"},
            "findings": [{
                "name": "Public S3 bucket",
                "description": "Bucket allows public read",
                "remedy": "Block public access",
                "severity": "8.0",
            }],
        }],
    },
}


@click.group(name="import")
def import_group():
    """Import assets & findings (the platform's bulk write path)."""


@import_group.command()
@click.argument("payload_file", type=click.Path(exists=True))
@click.option("--import-type", type=click.Choice(IMPORT_TYPES),
              help="Override the payload's importType. WARNING: new/merge "
                   "close findings absent from the payload; delta never "
                   "closes anything.")
@click.option("--assessment", help="Override the assessment name.")
@pass_state
@run
def file(state, payload_file, import_type, assessment):
    """Import a /v1/import/assets JSON payload from disk."""
    result = state.client.import_file(payload_file, import_type=import_type,
                                      assessment_name=assessment)
    state.emit(result)


@import_group.command()
@click.argument("request_id")
@pass_state
@run
def status(state, request_id):
    """Poll an asynchronous import request (undocumented endpoint — see
    `phx gaps`)."""
    state.emit(state.client.get_import_status(request_id))


@import_group.command()
@click.argument("asset_type", type=click.Choice(sorted(TEMPLATES)),
                default="INFRA")
def template(asset_type):
    """Print an example import payload for ASSET_TYPE (pipe to a file)."""
    click.echo(json.dumps(TEMPLATES[asset_type], indent=2))


@import_group.command()
def types():
    """List valid importType values and assessment asset types."""
    click.echo("importType (semantics):")
    click.echo("  delta  add/update only what is in the payload; never closes")
    click.echo("  merge  update matching data; absent findings are CLOSED")
    click.echo("  new    replace assessment data; absent findings are CLOSED")
    click.echo("assessment.assetType: " + ", ".join(ASSESSMENT_ASSET_TYPES))
