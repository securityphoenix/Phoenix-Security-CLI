"""Shared CLI context: lazy client construction, output emission, errors."""

import json
import sys

import click

from phoenix_cli.client import PhoenixClient
from phoenix_cli.config import load_settings
from phoenix_cli.errors import (
    PhoenixAPIError,
    PhoenixAuthError,
    PhoenixConfigError,
    PhoenixError,
    PhoenixNotSupportedError,
)
from phoenix_cli.output import render

EXIT_CONFIG = 2
EXIT_AUTH = 3
EXIT_API = 4
EXIT_NOT_SUPPORTED = 5


class CliState:
    """Holds global options; builds the client on first use."""

    def __init__(self, **options):
        self.options = options
        self.output_format = options.get("output") or "table"
        self._client = None

    @property
    def client(self):
        if self._client is None:
            settings = load_settings(
                client_id=self.options.get("client_id"),
                client_secret=self.options.get("client_secret"),
                base_url=self.options.get("api_base_url"),
                env=self.options.get("env"),
                config_path=self.options.get("config"),
                timeout=self.options.get("timeout") or 60,
                verify_tls=not self.options.get("insecure"),
            )
            self._client = PhoenixClient.from_settings(settings)
        return self._client

    def emit(self, data, columns=None):
        click.echo(render(data, self.output_format, columns=columns))


pass_state = click.make_pass_decorator(CliState)


def run(func):
    """Decorator translating Phoenix errors into clean CLI failures."""
    import functools

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except PhoenixNotSupportedError as exc:
            click.secho("NOT SUPPORTED BY PHOENIX API v1.27", fg="yellow", err=True)
            click.echo(str(exc), file=sys.stderr)
            sys.exit(EXIT_NOT_SUPPORTED)
        except PhoenixConfigError as exc:
            click.secho(f"Configuration error: {exc}", fg="red", err=True)
            sys.exit(EXIT_CONFIG)
        except PhoenixAuthError as exc:
            click.secho(f"Authentication error: {exc}", fg="red", err=True)
            sys.exit(EXIT_AUTH)
        except PhoenixAPIError as exc:
            click.secho(f"API error: {exc}", fg="red", err=True)
            sys.exit(EXIT_API)
        except PhoenixError as exc:
            click.secho(f"Error: {exc}", fg="red", err=True)
            sys.exit(1)
    return wrapper


def parse_kv_pairs(pairs, option_name):
    """Turn repeated key=value options into a dict."""
    out = {}
    for pair in pairs or ():
        key, sep, value = str(pair).partition("=")
        if not sep or not key:
            raise PhoenixConfigError(
                f"--{option_name} expects key=value, got '{pair}'.")
        out[key.strip()] = value.strip()
    return out


def load_json_arg(value, option_name):
    """Accept inline JSON or @file.json for complex structures."""
    if value is None:
        return None
    if value.startswith("@"):
        with open(value[1:], "r", encoding="utf-8") as fh:
            return json.load(fh)
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise PhoenixConfigError(
            f"--{option_name} is not valid JSON (use @file.json to load "
            f"from a file): {exc}")
