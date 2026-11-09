"""Autopatcher API mixin, error codes and the keychain token store (offline)."""

from __future__ import annotations

import builtins
import json
import sys

import pytest
import responses
from click.testing import CliRunner
from responses import matchers

from phoenix_cli import PhoenixClient, token_store
from phoenix_cli.cli.main import cli
from phoenix_cli.errors import PhoenixAPIError, error_code

BASE = "https://api.demo.appsecphx.io"
AP = f"{BASE}/v1/autopatcher"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    for var in ("PHOENIX_CLIENT_ID", "PHOENIX_CLIENT_SECRET",
                "PHOENIX_API_BASE_URL", "PHOENIX_BASE_URL", "CLIENT_ID",
                "CLIENT_SECRET", "PHOENIX_DOMAIN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def client():
    return PhoenixClient(client_id="cid", client_secret="secret", base_url=BASE)


def _mock_token(rsps):
    rsps.get(f"{BASE}/v1/auth/access_token",
             json={"token": "tok", "expiry": 9999999999})


@responses.activate
def test_lookup_asset_sends_both_filters(client):
    _mock_token(responses)
    responses.get(f"{AP}/assets/lookup", json={"matches": []},
                  match=[matchers.query_param_matcher(
                      {"hostname": "phx-alf", "ip": "10.0.0.5"})])
    assert client.lookup_asset(hostname="phx-alf", ip="10.0.0.5") == {"matches": []}


@responses.activate
def test_lookup_asset_sends_only_given_filter(client):
    _mock_token(responses)
    responses.get(f"{AP}/assets/lookup", json={"matches": []},
                  match=[matchers.query_param_matcher({"ip": "10.0.0.5"})])
    client.lookup_asset(ip="10.0.0.5")


@responses.activate
def test_latest_accepted_plan_none_on_no_valid_plan(client):
    _mock_token(responses)
    responses.get(f"{AP}/assets/a1/plans/latest-accepted", status=404,
                  json={"error": "NO_VALID_PLAN"})
    assert client.get_latest_accepted_plan("a1") is None


@responses.activate
def test_latest_accepted_plan_reraises_feature_disabled(client):
    _mock_token(responses)
    responses.get(f"{AP}/assets/a1/plans/latest-accepted", status=404,
                  json={"error": "FEATURE_DISABLED"})
    with pytest.raises(PhoenixAPIError) as info:
        client.get_latest_accepted_plan("a1")
    assert error_code(info.value) == "FEATURE_DISABLED"


@responses.activate
def test_feature_disabled_is_a_clear_error(client):
    _mock_token(responses)
    responses.get(f"{AP}/policy", status=404, json={"error": "FEATURE_DISABLED"})
    with pytest.raises(PhoenixAPIError, match="FEATURE_DISABLED") as info:
        client.get_patch_policy("server")
    assert info.value.status_code == 404
    assert error_code(info.value) == "FEATURE_DISABLED"


def test_error_code_is_none_for_non_json_body():
    assert error_code(PhoenixAPIError(502, "bad gateway", body="<html>")) is None
    assert error_code(PhoenixAPIError(502, "x")) is None
    assert error_code(PhoenixAPIError(400, "x", body="[1]")) is None


@responses.activate
def test_policy_passes_usage(client):
    _mock_token(responses)
    responses.get(f"{AP}/policy", json={"version": 3},
                  match=[matchers.query_param_matcher({"usage": "server"})])
    assert client.get_patch_policy("server") == {"version": 3}


@responses.activate
def test_set_usage_puts_body(client):
    _mock_token(responses)
    responses.put(f"{AP}/assets/a1/usage", json={"assetId": "a1"},
                  match=[matchers.json_params_matcher({"usage": "server"})])
    assert client.set_asset_usage("a1", "server") == {"assetId": "a1"}


@responses.activate
def test_submit_plan_forces_source_llm(client):
    _mock_token(responses)
    actions = [{"id": "a1"}]
    responses.post(f"{AP}/plans", json={"planId": "p1"},
                   match=[matchers.json_params_matcher(
                       {"assetId": "a1", "source": "llm", "actions": actions})])
    assert client.submit_patch_plan("a1", actions) == {"planId": "p1"}


@responses.activate
def test_submit_plan_source_mcp_is_sent(client):
    _mock_token(responses)
    actions = [{"id": "a1"}]
    responses.post(f"{AP}/plans", json={"planId": "p1"},
                   match=[matchers.json_params_matcher(
                       {"assetId": "a1", "source": "mcp", "actions": actions})])
    assert client.submit_patch_plan("a1", actions, source="mcp") == {"planId": "p1"}


@responses.activate
@pytest.mark.parametrize("bad", ["copilot", "", "LLM", None])
def test_submit_plan_rejects_other_sources_without_a_request(client, bad):
    _mock_token(responses)
    with pytest.raises(ValueError, match="source must be 'llm' or 'mcp'"):
        client.submit_patch_plan("a1", [], source=bad)
    assert not [c for c in responses.calls if c.request.method == "POST"
                and c.request.url.endswith("/plans")]


@responses.activate
def test_get_plan_and_pending_list(client):
    _mock_token(responses)
    responses.get(f"{AP}/plans/p1", json={"planId": "p1"})
    responses.get(f"{AP}/assets/a1/plans", json={"plans": [{"planId": "p2"}]},
                  match=[matchers.query_param_matcher(
                      {"state": "PENDING_ACCEPTANCE"})])
    assert client.get_patch_plan("p1") == {"planId": "p1"}
    assert client.list_pending_plans("a1") == [{"planId": "p2"}]


@responses.activate
def test_accept_sends_confirm_header(client):
    _mock_token(responses)
    h = "abcdef0123456789"
    responses.post(f"{AP}/plans/p1/accept", json={"state": "ACCEPTED"},
                   match=[matchers.json_params_matcher({"hash": h}),
                          matchers.header_matcher(
                              {"X-Autopatcher-Confirm": "abcdef01"})])
    assert client.accept_patch_plan("p1", h) == {"state": "ACCEPTED"}


@responses.activate
def test_upload_run_posts_record(client):
    _mock_token(responses)
    responses.post(f"{AP}/runs", json={"runId": "r1", "taggedFindingIds": []},
                   match=[matchers.json_params_matcher({"runId": "r1"})])
    assert client.upload_patch_run({"runId": "r1"})["runId"] == "r1"


def _findings_pages(rsps, counts, dup=None):
    n = 0
    for page, count in enumerate(counts):
        items = [{"id": f"f{n + i}"} for i in range(count)]
        n += count
        if dup and page == 1:
            items[0] = {"id": "f0"}
        rsps.get(f"{AP}/assets/a1/findings", json={"findings": items},
                 match=[matchers.query_param_matcher(
                     {"page": page, "size": 1000})])


@responses.activate
def test_findings_loop_three_pages(client):
    _mock_token(responses)
    _findings_pages(responses, [1000, 1000, 248])
    out = client.get_autopatch_findings("a1")
    assert len(out) == 2248
    assert out[0]["id"] == "f0" and out[-1]["id"] == "f2247"


@responses.activate
def test_findings_duplicate_across_pages_kept_once(client):
    _mock_token(responses)
    _findings_pages(responses, [1000, 5], dup=True)
    out = client.get_autopatch_findings("a1")
    assert len(out) == 1004
    assert [f["id"] for f in out].count("f0") == 1


@responses.activate
def test_findings_more_than_20_pages_raises(client):
    _mock_token(responses)
    _findings_pages(responses, [1000] * 20 + [1])
    with pytest.raises(ValueError, match="too many findings"):
        client.get_autopatch_findings("a1")


@responses.activate
def test_findings_exactly_20_full_pages_ok(client):
    _mock_token(responses)
    _findings_pages(responses, [1000] * 20 + [0])
    assert len(client.get_autopatch_findings("a1")) == 20000


@responses.activate
def test_cli_lookup_command():
    _mock_token(responses)
    responses.get(f"{AP}/assets/lookup", json={"matches": []},
                  match=[matchers.query_param_matcher({"hostname": "h"})])
    result = CliRunner().invoke(cli, [
        "--client-id", "cid", "--client-secret", "s", "--api-base-url", BASE,
        "-o", "json", "autopatcher", "lookup", "--hostname", "h"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {"matches": []}


def test_no_accept_or_usage_command():
    runner = CliRunner()
    assert runner.invoke(cli, ["autopatcher", "plan", "accept", "x"]).exit_code != 0
    assert runner.invoke(cli, ["autopatcher", "usage", "set"]).exit_code != 0
    out = runner.invoke(cli, ["autopatcher", "--help"]).output
    assert "accept" not in out and "usage set" not in out


# -- token store -------------------------------------------------------------

def test_token_store_round_trip_per_base_url(keyring):
    kr = keyring
    token_store.save_token("https://a.example/", "t1", 100)
    token_store.save_token("https://b.example", "t2", 200)
    assert token_store.load_token("https://a.example") == ("t1", 100)
    assert token_store.load_token("https://b.example/") == ("t2", 200)
    assert ("phoenix-cli", "https://a.example") in kr.items
    token_store.save_token("https://a.example", "t3", 300)  # a new login replaces
    assert token_store.load_token("https://a.example") == ("t3", 300)
    token_store.clear_token("https://a.example")
    assert token_store.load_token("https://a.example") is None


def test_token_store_refuses_plain_file(monkeypatch, tmp_path):
    monkeypatch.delitem(sys.modules, "keyring", raising=False)
    real_import = builtins.__import__

    def no_keyring(name, *a, **k):
        if name == "keyring":
            raise ImportError(name)
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_keyring)
    with pytest.raises(RuntimeError,
                       match=r"install phoenix-security-cli\[keyring\] to store a login"):
        token_store.save_token("https://a.example", "secret-token", 1)
    assert token_store.load_token("https://a.example") is None
    assert list(tmp_path.iterdir()) == []  # nothing written to disk
