"""Root command group for the Phoenix Security CLI (`phx` / `phoenix-cli`)."""

import click

from phoenix_cli import API_VERSION, __version__
from phoenix_cli.cli.context import CliState, load_json_arg, pass_state, run
from phoenix_cli.output import FORMATS


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, message=(
    f"phoenix-security-cli %(version)s (Phoenix API v{API_VERSION})"))
@click.option("--client-id", envvar="PHOENIX_CLIENT_ID",
              help="Phoenix API client ID (Organisation > API Access).")
@click.option("--client-secret", envvar="PHOENIX_CLIENT_SECRET",
              help="Phoenix API client secret.")
@click.option("--api-base-url", envvar="PHOENIX_API_BASE_URL",
              help="API base URL, e.g. https://api.securityphoenix.cloud")
@click.option("--env", type=click.Choice(["prod", "demo", "poc1"]),
              help="Named environment shortcut for --api-base-url.")
@click.option("--config", "config", type=click.Path(),
              help="Path to config.ini ([phoenix] section).")
@click.option("-o", "--output", type=click.Choice(FORMATS), default="table",
              show_default=True, help="Output format.")
@click.option("--timeout", type=int, default=60, show_default=True,
              help="HTTP timeout in seconds.")
@click.option("--insecure", is_flag=True, help="Skip TLS verification.")
@click.pass_context
def cli(ctx, **options):
    """Phoenix Security CLI — full platform visibility and automation with
    just an API key (client_id/client_secret).

    Covers Phoenix Security REST API Enterprise v1.27: assets, findings
    (vulnerabilities), imports, applications & environments, components &
    services, asset-association rules, teams and users.

    \b
    Credentials (precedence): flags > env vars > config.ini
      PHOENIX_CLIENT_ID / PHOENIX_CLIENT_SECRET / PHOENIX_API_BASE_URL

    Operations the API cannot perform are flagged explicitly — run
    `phx gaps` for the list.
    """
    ctx.obj = CliState(**options)


@cli.command()
@click.option("--required", is_flag=True,
              help="Show the endpoints the Phoenix API should add "
                   "(the formal wishlist behind the gaps).")
@pass_state
@run
def gaps(state, required):
    """Show operations NOT supported by Phoenix API v1.27 (and workarounds)."""
    from phoenix_cli.gaps import as_rows, required_endpoint_rows
    if required:
        state.emit(required_endpoint_rows(),
                   columns=["method", "path", "purpose", "workaround today"])
    else:
        state.emit(as_rows(), columns=["area", "operation", "severity", "gap",
                                       "workaround"])


@cli.command()
@click.argument("method",
                type=click.Choice(["GET", "POST", "PUT", "PATCH", "DELETE"],
                                  case_sensitive=False))
@click.argument("path")
@click.option("--body", help="JSON request body (inline or @file.json).")
@click.option("--param", "params", multiple=True,
              help="Query parameter key=value (repeatable).")
@pass_state
@run
def api(state, method, path, body, params):
    """Escape hatch: call any /v1 API path directly (authenticated).

    Example: phx api POST /v1/findings --body '{"status":["OPEN"]}'
    """
    from phoenix_cli.cli.context import parse_kv_pairs
    query = parse_kv_pairs(params, "param")
    json_body = load_json_arg(body, "body")
    result = state.client.raw_request(method.upper(), path,
                                      params=query or None,
                                      json_body=json_body)
    state.emit(result if result is not None else {"status": "ok (no content)"})


def _register_commands():
    from phoenix_cli.cli import (
        apps_cmd,
        assets_cmd,
        auth_cmd,
        components_cmd,
        findings_cmd,
        import_cmd,
        teams_cmd,
        users_cmd,
    )
    cli.add_command(auth_cmd.auth)
    cli.add_command(assets_cmd.assets)
    cli.add_command(findings_cmd.findings)
    cli.add_command(findings_cmd.vulns)
    cli.add_command(import_cmd.import_group)
    cli.add_command(apps_cmd.apps)
    cli.add_command(apps_cmd.envs)
    cli.add_command(components_cmd.components)
    cli.add_command(components_cmd.services)
    cli.add_command(teams_cmd.teams)
    cli.add_command(users_cmd.users)


_register_commands()


if __name__ == "__main__":
    cli()
