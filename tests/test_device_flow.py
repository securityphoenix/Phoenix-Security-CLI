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
         "verification_uri": f"{BASE}/device",
         "verification_uri_complete": f"{BASE}/device?c=ABCD-EFGH",
         "expires_in": 900, "interval": 5}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    for var in ("PHOENIX_CLIENT_ID", "PHOENIX_CLIENT_SECRET",
                "PHOENIX_API_BASE_URL", "PHOENIX_BASE_URL", "CLIENT_ID",
                "CLIENT_SECRET", "PHOENIX_DOMAIN"):
        monkeypatch.delenv(var, raising=False)
    # Never reach the real OS keychain: a None entry makes `import keyring`
    # raise ImportError whether or not the extra is installed. Tests that need
    # a keyring request the in-memory `keyring` fixture, which replaces this.
    monkeypatch.setitem(sys.modules, "keyring", None)
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
    assert any(f"{BASE}/device?c=ABCD-EFGH" in line for line in lines)
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
def test_login_without_keyring_fails_clearly(monkeypatch):
    monkeypatch.setitem(sys.modules, "keyring", None)  # explicit: absent
    responses.post(CODE, json=GRANT)
    responses.post(TOKEN, json={"access_token": "SECRET-TOK", "expires_in": 3600})
    result = CliRunner().invoke(cli, ["--api-base-url", BASE, "login"])
    assert result.exit_code != 0
    assert "phoenix-security-cli[keyring]" in result.output
    assert "SECRET-TOK" not in result.output


# -- AC-4: transport security, settings, link and cwd config ------------------

@responses.activate
@pytest.mark.parametrize("url", ["http://api.example.com", "ftp://x",
                                 "http://localhost.evil.test", "api.example.com"])
def test_device_login_refuses_non_https_with_no_network(url):
    with pytest.raises(PhoenixConfigError, match="not https"):
        device_login(url, "phx", sleep=lambda s: None, echo=lambda s: None)
    assert len(responses.calls) == 0


@pytest.mark.parametrize("url", ["http://api.example.com",
                                 "http://user:pw@evil.test"])
def test_transport_refuses_non_https(url):
    with pytest.raises(PhoenixConfigError, match="clear text"):
        Transport("cid", "sec", url)


@responses.activate
@pytest.mark.parametrize("host", ["localhost:8080", "127.0.0.1:8080", "[::1]:8080"])
def test_local_http_is_allowed(host):
    base = f"http://{host}"
    responses.post(f"{base}/v1/auth/device/code",
                   json=dict(GRANT, verification_uri_complete=f"{base}/device?c=1"))
    responses.post(f"{base}/v1/auth/device/token",
                   json={"access_token": "tok", "expires_in": 60})
    lines = []
    token, _ = device_login(base, "phx", sleep=lambda s: None, echo=lines.append)
    assert token == "tok"
    assert any(f"{base}/device?c=1" in line for line in lines)
    Transport("cid", "sec", base)  # no error


@responses.activate
def test_device_flow_uses_settings_timeout_verify_and_proxy(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.test:3128")
    responses.post(CODE, json=GRANT)
    responses.post(TOKEN, json={"access_token": "tok", "expires_in": 60})
    device_login(BASE, "phx", sleep=lambda s: None, echo=lambda s: None,
                 timeout=7, verify_tls=False)
    assert len(responses.calls) == 2
    for call in responses.calls:
        kwargs = call.request.req_kwargs
        assert kwargs["timeout"] == 7
        assert kwargs["verify"] is False
        assert kwargs["proxies"].get("https") == "http://proxy.test:3128"


@responses.activate
def test_login_command_passes_timeout_and_insecure(keyring):
    responses.post(CODE, json=GRANT)
    responses.post(TOKEN, json={"access_token": "t", "expires_in": 3600})
    result = CliRunner().invoke(cli, ["--api-base-url", BASE, "--timeout", "9",
                                      "--insecure", "login"])
    assert result.exit_code == 0, result.output
    assert responses.calls[0].request.req_kwargs["timeout"] == 9
    assert responses.calls[0].request.req_kwargs["verify"] is False


@responses.activate
@pytest.mark.parametrize("link", [
    "https://evil.test/approve",
    "javascript:alert(1)",
    f"{BASE.replace('https', 'http')}/device",
    f"{BASE}/device\x1b[31m",
    f"{BASE}/device with space",
    "https://api.demo.appsecphx.io.evil.test/device",
])
def test_hostile_verification_uri_is_not_printed(link):
    responses.post(CODE, json=dict(GRANT, verification_uri_complete=link,
                                   verification_uri=link))
    responses.post(TOKEN, json={"access_token": "tok", "expires_in": 60})
    lines = []
    device_login(BASE, "phx", sleep=lambda s: None, echo=lines.append)
    text = "\n".join(lines)
    assert link not in text and "\x1b" not in text
    assert "evil.test" not in text and "javascript" not in text
    assert BASE in text and "ABCD-EFGH" in text  # safe fallback + code


@responses.activate
def test_plain_verification_uri_used_when_complete_is_hostile():
    responses.post(CODE, json=dict(GRANT,
                                   verification_uri_complete="https://evil.test/x"))
    responses.post(TOKEN, json={"access_token": "tok", "expires_in": 60})
    lines = []
    device_login(BASE, "phx", sleep=lambda s: None, echo=lines.append)
    assert any(line.strip() == f"{BASE}/device" for line in lines)
    assert not any("evil.test" in line for line in lines)


@responses.activate
def test_user_code_control_characters_are_stripped():
    responses.post(CODE, json=dict(GRANT, user_code="AB\x1b[2JCD"))
    responses.post(TOKEN, json={"access_token": "tok", "expires_in": 60})
    lines = []
    device_login(BASE, "phx", sleep=lambda s: None, echo=lines.append)
    assert not any("\x1b" in line for line in lines)
    assert any("AB[2JCD" in line for line in lines)


def test_cwd_config_base_url_warns_on_stderr(tmp_path, capsys):
    (tmp_path / "config.ini").write_text(
        "[phoenix]\napi_base_url=https://attacker.test\n")
    settings = load_settings()
    assert settings.base_url == "https://attacker.test"  # documented behaviour kept
    err = capsys.readouterr().err
    assert "config.ini" in err and "https://attacker.test" in err


def test_cwd_config_without_base_url_is_silent(tmp_path, capsys):
    (tmp_path / "config.ini").write_text("[phoenix]\nclient_id=a\n")
    load_settings()
    assert capsys.readouterr().err == ""


def test_cwd_config_warning_skipped_when_flag_or_env_sets_url(tmp_path, capsys,
                                                              monkeypatch):
    (tmp_path / "config.ini").write_text(
        "[phoenix]\napi_base_url=https://attacker.test\n")
    assert load_settings(base_url=BASE).base_url == BASE
    monkeypatch.setenv("PHOENIX_API_BASE_URL", BASE)
    assert load_settings().base_url == BASE
    assert capsys.readouterr().err == ""


# -- AC-4 follow-up: web app host differs from API host -----------------------

@responses.activate
@pytest.mark.parametrize("link", [
    "https://demo.appsecphx.io/app/device?user_code=X",
    "https://app.demo.appsecphx.io/app/device",
    "https://api.demo.appsecphx.io/app/device",
])
def test_web_app_link_on_tenant_domain_is_printed(link):
    responses.post(CODE, json=dict(GRANT, verification_uri_complete=link))
    responses.post(TOKEN, json={"access_token": "tok", "expires_in": 60})
    lines = []
    device_login(BASE, "phx", sleep=lambda s: None, echo=lines.append)
    assert any(line.strip() == link for line in lines)


@responses.activate
@pytest.mark.parametrize("link", [
    "https://evil.test/app/device",
    "https://appsecphx.io.evil.test/app/device",
    "https://appsecphx.io@evil.test/app/device",
    "https://api.demo.appsecphx.io@evil.test/app/device",
    "https://user:pw@demo.appsecphx.io/app/device",
    "https://demo.appsecphx.io:8443/app/device",
    "https://notdemo.appsecphx.io/app/device",
    "https://appsecphx.io/app/device",
])
def test_hostile_or_odd_link_near_tenant_domain_is_refused(link):
    responses.post(CODE, json=dict(GRANT, verification_uri_complete=link,
                                   verification_uri=link))
    responses.post(TOKEN, json={"access_token": "tok", "expires_in": 60})
    lines = []
    device_login(BASE, "phx", sleep=lambda s: None, echo=lines.append)
    assert not any(link in line for line in lines)
    assert not any("evil.test" in line for line in lines)
