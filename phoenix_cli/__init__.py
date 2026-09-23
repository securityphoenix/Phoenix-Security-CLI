"""Phoenix Security CLI — command-line interface and Python client for the
Phoenix Security platform (REST API Enterprise v1.27).

Public surface:
    from phoenix_cli import PhoenixClient
"""

from phoenix_cli.client import PhoenixClient
from phoenix_cli.errors import (
    PhoenixAPIError,
    PhoenixAuthError,
    PhoenixConfigError,
    PhoenixError,
    PhoenixNotSupportedError,
)

__version__ = "1.2.0"
API_VERSION = "1.27"

__all__ = [
    "PhoenixClient",
    "PhoenixError",
    "PhoenixAPIError",
    "PhoenixAuthError",
    "PhoenixConfigError",
    "PhoenixNotSupportedError",
    "__version__",
    "API_VERSION",
]
