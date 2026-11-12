"""Error types for the Phoenix Security CLI and client library."""

from __future__ import annotations

import json


class PhoenixError(Exception):
    """Base error for all Phoenix CLI failures."""


class PhoenixConfigError(PhoenixError):
    """Raised when credentials or configuration are missing/invalid."""


class PhoenixAuthError(PhoenixError):
    """Raised when authentication against the Phoenix API fails (401)."""


class PhoenixAPIError(PhoenixError):
    """Raised when the Phoenix API returns an error response."""

    def __init__(self, status_code, message, method=None, path=None, body=None):
        self.status_code = status_code
        self.method = method
        self.path = path
        self.body = body
        detail = f"HTTP {status_code}"
        if method and path:
            detail += f" on {method} {path}"
        if message:
            detail += f": {message}"
        super().__init__(detail)


class PhoenixNotSupportedError(PhoenixError):
    """Raised for operations that SHOULD exist but are not supported by
    Phoenix Security REST API v1.27.

    Every operation that raises this error is documented in
    docs/GAP_ANALYSIS.md, together with the closest available workaround.
    """

    def __init__(self, operation, reason, workaround=None):
        self.operation = operation
        self.reason = reason
        self.workaround = workaround
        msg = f"'{operation}' is not supported by Phoenix API v1.27: {reason}"
        if workaround:
            msg += f"\nWorkaround: {workaround}"
        msg += "\nSee docs/GAP_ANALYSIS.md (or run: phx gaps) for the full list."
        super().__init__(msg)


def error_body(exc: PhoenixAPIError):
    """The error body parsed as JSON, or None when it is not JSON."""
    body = getattr(exc, "body", None)
    if isinstance(body, (dict, list)):
        return body
    if not body:
        return None
    try:
        return json.loads(body)
    except (TypeError, ValueError):
        return None


def error_code(exc: PhoenixAPIError) -> str | None:
    """``body["error"]`` of an API error, or None."""
    parsed = error_body(exc)
    if isinstance(parsed, dict) and isinstance(parsed.get("error"), str):
        return parsed["error"]
    return None


def expect_mapping(reply, what: str) -> dict:
    """Return ``reply`` if it is a JSON object, else raise ``PhoenixError``."""
    if not isinstance(reply, dict):
        raise PhoenixError(f"Unexpected response from Phoenix for {what}")
    return reply
