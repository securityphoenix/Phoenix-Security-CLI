"""Copilot patch plan client (offline)."""

from __future__ import annotations

import json

import pytest
import responses
from click.testing import CliRunner
from responses import matchers

from phoenix_cli import PhoenixClient
from phoenix_cli.cli.main import cli
from phoenix_cli.errors import PhoenixError

BASE = "https://api.demo.appsecphx.io"
CP = f"{BASE}/v1/copilot"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    for var in ("PHOENIX_CLIENT_ID", "PHOENIX_CLIENT_SECRET",
                "PHOENIX_API_BASE_URL", "PHOENIX_BASE_URL", "CLIENT_ID",
                "CLIENT_SECRET", "PHOENIX_DOMAIN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def client():
    responses.get(f"{BASE}/v1/auth/access_token",
                  json={"token": "tok", "expiry": 9999999999})
    return PhoenixClient(client_id="cid", client_secret="s", base_url=BASE)


PLAN = {"planId": "p1", "actions": [{"id": "a1"}], "source": "copilot"}


@responses.activate
def test_copilot_start_sends_idempotency_key(client):
    responses.post(f"{CP}/patch-plans", json={"jobId": "j1"},
                   match=[matchers.header_matcher({"Idempotency-Key": "k-1"}),
                          matchers.json_params_matcher(
                              {"assetId": "a1", "staleCopies": []})])
    assert client.start_patch_plan("a1", "k-1") == "j1"


@responses.activate
def test_copilot_start_sends_stale_copies(client):
    stale = [{"path": "/x", "sha256": "ab", "product": "p", "findingIds": ["f"]}]
    responses.post(f"{CP}/patch-plans", json={"jobId": "j1"},
                   match=[matchers.json_params_matcher(
                       {"assetId": "a1", "staleCopies": stale})])
    client.start_patch_plan("a1", "k", stale_copies=stale)


@responses.activate
def test_get_job_and_plan(client):
    responses.get(f"{CP}/jobs/j1", json={"jobId": "j1", "state": "RUNNING"})
    responses.get(f"{CP}/patch-plans/p1", json=PLAN)
    assert client.get_job("j1")["state"] == "RUNNING"
    assert client.get_copilot_patch_plan("p1") == PLAN


@responses.activate
def test_wait_for_patch_plan_returns_actions(client):
    responses.post(f"{CP}/patch-plans", json={"jobId": "j1"})
    responses.get(f"{CP}/jobs/j1", json={"state": "RUNNING"})
    responses.get(f"{CP}/jobs/j1", json={"state": "DONE", "planId": "p1"})
    responses.get(f"{CP}/patch-plans/p1", json=PLAN)
    sleeps = []
    plan = client.wait_for_patch_plan("a1", sleep=sleeps.append, poll_s=5)
    assert plan["actions"] == [{"id": "a1"}] and sleeps == [5]


@responses.activate
def test_wait_for_patch_plan_times_out(client):
    responses.post(f"{CP}/patch-plans", json={"jobId": "j1"})
    responses.get(f"{CP}/jobs/j1", json={"state": "RUNNING"})
    sleeps, now = [], [0.0]

    def sleep(s):
        sleeps.append(s)
        now[0] += s

    with pytest.raises(TimeoutError):
        client.wait_for_patch_plan("a1", timeout_s=10, poll_s=5,
                                   sleep=sleep, clock=lambda: now[0])
    assert sleeps == [5, 5]


@responses.activate
def test_wait_for_patch_plan_timeout_counts_request_time(client):
    """Slow job replies use up the budget: sleeps shrink, no poll after it."""
    now, polls, sleeps = [0.0], [], []

    def slow_running(request):
        polls.append(now[0])
        now[0] += 6  # each job request takes six seconds
        return 200, {}, '{"state": "RUNNING"}'

    responses.post(f"{CP}/patch-plans", json={"jobId": "j1"})
    responses.add_callback(responses.GET, f"{CP}/jobs/j1", callback=slow_running,
                           content_type="application/json")

    def sleep(s):
        sleeps.append(s)
        now[0] += s

    with pytest.raises(TimeoutError):
        client.wait_for_patch_plan("a1", timeout_s=10, poll_s=5,
                                   sleep=sleep, clock=lambda: now[0])
    assert polls == [0.0] and sleeps == [4]


@responses.activate
def test_wait_for_patch_plan_budget_counts_job_creation(client):
    """A slow job creation uses up the budget: no job poll at all."""
    now = [0.0]

    def slow_create(request):
        now[0] += 30  # creation, auth and retries take thirty seconds
        return 200, {}, '{"jobId": "j1"}'

    responses.add_callback(responses.POST, f"{CP}/patch-plans",
                           callback=slow_create, content_type="application/json")
    with pytest.raises(TimeoutError):
        client.wait_for_patch_plan("a1", timeout_s=10, poll_s=5,
                                   sleep=lambda s: None, clock=lambda: now[0])
    assert not [c for c in responses.calls if "/jobs/" in c.request.url]


@responses.activate
def test_caller_headers_cannot_override_authorization(client):
    responses.get(f"{BASE}/v1/x", json={},
                  match=[matchers.header_matcher(
                      {"Authorization": "Bearer tok",
                       "Content-Type": "application/json", "X-Extra": "1"})])
    client.transport.request(
        "GET", "/v1/x",
        headers={"Authorization": "Bearer evil", "X-Extra": "1"})


@responses.activate
def test_wait_for_patch_plan_failed_job(client):
    responses.post(f"{CP}/patch-plans", json={"jobId": "j1"})
    responses.get(f"{CP}/jobs/j1", json={"state": "FAILED", "error": "boom"})
    with pytest.raises(PhoenixError, match="boom"):
        client.wait_for_patch_plan("a1", sleep=lambda s: None)


@responses.activate
def test_cli_copilot_plan_prints_job_id(client):
    responses.post(f"{CP}/patch-plans", json={"jobId": "j9"},
                   match=[matchers.header_matcher({})])
    result = CliRunner().invoke(cli, [
        "--client-id", "cid", "--client-secret", "s", "--api-base-url", BASE,
        "-o", "json", "copilot", "plan", "--asset-id", "a1"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {"jobId": "j9"}
    sent = next(c for c in responses.calls if c.request.method == "POST").request
    assert sent.headers["Idempotency-Key"]


@responses.activate
def test_cli_copilot_job(client):
    responses.get(f"{CP}/jobs/j1", json={"state": "DONE"})
    result = CliRunner().invoke(cli, [
        "--client-id", "cid", "--client-secret", "s", "--api-base-url", BASE,
        "-o", "json", "copilot", "job", "j1"])
    assert result.exit_code == 0 and json.loads(result.output) == {"state": "DONE"}


# -- malformed replies stay inside PhoenixError -------------------------------

@responses.activate
@pytest.mark.parametrize("body", [[], {}, {"jobId": ""}])
def test_start_patch_plan_malformed_reply_is_phoenix_error(client, body):
    responses.post(f"{CP}/patch-plans", json=body)
    with pytest.raises(PhoenixError):
        client.start_patch_plan("a1", "key")


@responses.activate
@pytest.mark.parametrize("job", [["x"], {"state": "DONE"}])
def test_wait_for_patch_plan_malformed_job_is_phoenix_error(client, job):
    responses.post(f"{CP}/patch-plans", json={"jobId": "j1"})
    responses.get(f"{CP}/jobs/j1", json=job)
    with pytest.raises(PhoenixError):
        client.wait_for_patch_plan("a1", sleep=lambda s: None)
