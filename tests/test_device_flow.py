"""Device login, stored-token transport and the login commands (offline)."""

from __future__ import annotations

import sys
import time

import pytest
import responses
from click.testing import CliRunner
from responses import matchers

from phoenix_cli import PhoenixClient, token_store
from phoenix_cli.cli.main import cli
from phoenix_cli.config import load_settings
from phoenix_cli.device_flow import device_login
from phoenix_cli.errors import PhoenixAuthError, PhoenixConfigError
from phoenix_cli.http import Transport

BASE = "https://api.demo.appsecphx.io"
CODE = f"{BASE}/v1/auth/device/code"
TOKEN = f"{BASE}/v1/auth/device/token"
GRANT = {"device_code": "dc", "user_code": "ABCD-EFGH",
         "verification_uri": "https://app/device",
         "verification_uri_complete": "https://app/device?c=ABCD-EFGH",
         "expires_in": 900, "interval": 5}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    for var in ("PHOENIX_CLIENT_ID", "PHOENIX_CLIENT_SECRET",
                "PHOENIX_API_BASE_URL", "PHOENIX_BASE_URL", "CLIENT_ID",
                "CLIENT_SECRET", "PHOENIX_DOMAIN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.delitem(sys.modules, "keyring", raising=False)
    monkeypatch.chdir(tmp_path)


@responses.activate
def test_device_login_polls_until_token():
    responses.post(CODE, json=GRANT,
                   match=[matchers.json_params_matcher({"clientName": "phx"})])
    responses.post(TOKEN, status=400, json={"error": "authorization_pending"})
    responses.post(TOKEN, status=400, json={"error": "slow_down"})
    responses.post(TOKEN, json={"access_token": "tok", "token_type": "Bearer",
                                "expires_in": 3600})
    sleeps, lines = [], []
    token, exp = device_login(BASE, "phx", sleep=sleeps.append, echo=lines.append)
    assert token == "tok" and sleeps == [5, 10]  # interval 5, +5 after slow_down
    assert abs(exp - (time.time() + 3600)) < 5
    assert any("ABCD-EFGH" in line for line in lines)
    assert any("https://app/device?c=ABCD-EFGH" in line for line in lines)
    assert not any("tok" == line.strip() for line in lines)


@responses.activate
@pytest.mark.parametrize("error", ["access_denied", "expired_token"])
def test_device_login_terminal_errors_raise(error):
    responses.post(CODE, json=GRANT)
    responses.post(TOKEN, status=400, json={"error": error})
    with pytest.raises(PhoenixAuthError):
        device_login(BASE, "phx", sleep=lambda s: None, echo=lambda s: None)


@responses.activate
def test_device_login_gives_up_after_expires_in():
    responses.post(CODE, json=dict(GRANT, expires_in=10))
    responses.post(TOKEN, status=400, json={"error": "authorization_pending"})
    with pytest.raises(PhoenixAuthError, match="expired"):
        device_login(BASE, "phx", sleep=lambda s: None, echo=lambda s: None)


# -- transport ---------------------------------------------------------------

@responses.activate
def test_request_sends_extra_headers():
    responses.get(f"{BASE}/v1/auth/access_token",
                  json={"token": "tok", "expiry": 9999999999})
    responses.get(f"{BASE}/v1/x", json={},
                  match=[matchers.header_matcher(
                      {"X-Extra": "1", "Authorization": "Bearer tok"})])
    Transport("cid", "sec", BASE).request("GET", "/v1/x", headers={"X-Extra": "1"})


@responses.activate
def test_stored_token_is_used_as_bearer(keyring):
    token_store.save_token(BASE, "login-tok", int(time.time()) + 3600)
    responses.get(f"{BASE}/v1/x", json={"ok": True},
                  match=[matchers.header_matcher(
                      {"Authorization": "Bearer login-tok"})])
    client = PhoenixClient(base_url=BASE)
    assert client.transport.request("GET", "/v1/x") == {"ok": True}
    assert len(responses.calls) == 1  # no access_token call


@responses.activate
def test_api_key_wins_over_stored_token(keyring):
    token_store.save_token(BASE, "login-tok", int(time.time()) + 3600)
    responses.get(f"{BASE}/v1/auth/access_token",
                  json={"token": "key-tok", "expiry": 9999999999})
    responses.get(f"{BASE}/v1/x", json={},
                  match=[matchers.header_matcher(
                      {"Authorization": "Bearer key-tok"})])
    PhoenixClient(client_id="c", client_secret="s",
                  base_url=BASE).transport.request("GET", "/v1/x")


@responses.activate
def test_401_with_login_token_does_not_reauth(keyring):
    token_store.save_token(BASE, "login-tok", int(time.time()) + 3600)
    responses.get(f"{BASE}/v1/x", status=401, json={})
    client = PhoenixClient(base_url=BASE)
    with pytest.raises(PhoenixAuthError, match='run "phx login" again'):
        client.transport.request("GET", "/v1/x")
    assert len(responses.calls) == 1  # never called /v1/auth/access_token


def test_expired_stored_token_is_not_credentials(keyring):
    token_store.save_token(BASE, "old", int(time.time()) - 10)
    with pytest.raises(PhoenixConfigError):
        load_settings(base_url=BASE).require_credentials()


def test_stored_token_counts_as_credentials(keyring):
    token_store.save_token(BASE, "t", int(time.time()) + 100)
    load_settings(base_url=BASE).require_credentials()


# -- commands ----------------------------------------------------------------

@responses.activate
def test_login_command_stores_token_and_never_prints_it(keyring):
    responses.post(CODE, json=GRANT)
    responses.post(TOKEN, json={"access_token": "SECRET-TOK", "expires_in": 3600})
    result = CliRunner().invoke(cli, ["--api-base-url", BASE, "login"])
    assert result.exit_code == 0, result.output
    assert "SECRET-TOK" not in result.output
    assert token_store.load_token(BASE)[0] == "SECRET-TOK"
    out = CliRunner().invoke(cli, ["--api-base-url", BASE, "logout"])
    assert out.exit_code == 0 and token_store.load_token(BASE) is None


@responses.activate
def test_login_without_keyring_fails_clearly():
    responses.post(CODE, json=GRANT)
    responses.post(TOKEN, json={"access_token": "SECRET-TOK", "expires_in": 3600})
    result = CliRunner().invoke(cli, ["--api-base-url", BASE, "login"])
    assert result.exit_code != 0
    assert "phoenix-security-cli[keyring]" in result.output
    assert "SECRET-TOK" not in result.output
