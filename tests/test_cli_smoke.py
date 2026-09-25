"""Offline smoke tests: command tree, config precedence, payload builders,
transport behaviour (mocked HTTP), and gap stubs."""

import json
import os

import pytest
import responses
from click.testing import CliRunner

from phoenix_cli import PhoenixClient
from phoenix_cli.api.common import parse_tag, user_ref
from phoenix_cli.cli.main import cli
from phoenix_cli.config import load_settings
from phoenix_cli.errors import PhoenixNotSupportedError

BASE = "https://api.demo.appsecphx.io"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ("PHOENIX_CLIENT_ID", "PHOENIX_CLIENT_SECRET",
                "PHOENIX_API_BASE_URL", "PHOENIX_BASE_URL", "CLIENT_ID",
                "CLIENT_SECRET", "PHOENIX_DOMAIN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(os.path.dirname(__file__))  # avoid stray config.ini


@pytest.fixture
def client():
    return PhoenixClient(client_id="cid", client_secret="secret",
                         base_url=BASE)


def _mock_token(rsps):
    rsps.get(f"{BASE}/v1/auth/access_token",
             json={"token": "tok", "expiry": 9999999999})


def test_help_tree():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    for group in ("auth", "assets", "findings", "vulns", "import", "apps",
                  "envs", "components", "services", "teams", "users",
                  "campaigns", "gaps", "api"):
        assert group in result.output


@pytest.mark.parametrize("args", [
    ["assets", "--help"], ["assets", "list", "--help"],
    ["assets", "remove-tags", "--help"],
    ["findings", "list", "--help"], ["findings", "enrich", "--help"],
    ["import", "file", "--help"], ["apps", "create", "--help"],
    ["components", "add-rules", "--help"], ["components", "list", "--help"],
    ["teams", "auto-link", "--help"],
    ["users", "create", "--help"], ["campaigns", "stats", "--help"],
])
def test_subcommand_help(args):
    assert CliRunner().invoke(cli, args).exit_code == 0


def test_gaps_command():
    result = CliRunner().invoke(cli, ["gaps"])
    assert result.exit_code == 0
    assert "findings update" in result.output
    assert "apps delete" in result.output
    assert "assets remove-tags" not in result.output


def test_config_precedence(tmp_path, monkeypatch):
    ini = tmp_path / "config.ini"
    ini.write_text("[phoenix]\nclient_id=ini_id\nclient_secret=ini_secret\n"
                   "api_base_url=https://api.poc1.appsecphx.io\n")
    settings = load_settings(config_path=str(ini))
    assert settings.client_id == "ini_id"
    assert settings.base_url == "https://api.poc1.appsecphx.io"
    monkeypatch.setenv("PHOENIX_CLIENT_ID", "env_id")
    settings = load_settings(config_path=str(ini))
    assert settings.client_id == "env_id"          # env beats ini
    settings = load_settings(client_id="cli_id", config_path=str(ini))
    assert settings.client_id == "cli_id"          # flag beats env


def test_env_shortcut():
    assert load_settings(env="demo").base_url == "https://api.demo.appsecphx.io"


def test_tag_and_user_parsing():
    assert parse_tag("env:prod") == {"key": "env", "value": "prod"}
    assert parse_tag("standalone") == {"value": "standalone"}
    assert user_ref("a@b.co") == {"email": "a@b.co"}
    assert user_ref("1234-uuid") == {"id": "1234-uuid"}


@responses.activate
def test_auth_and_pagination(client):
    _mock_token(responses)
    responses.get(
        f"{BASE}/v1/applications",
        json={"content": [{"id": "1", "name": "App1"}], "last": False,
              "totalPages": 2, "pageNumber": 0})
    responses.get(
        f"{BASE}/v1/applications",
        json={"content": [{"id": "2", "name": "App2"}], "last": True,
              "totalPages": 2, "pageNumber": 1})
    apps = client.list_applications()
    assert [a["id"] for a in apps] == ["1", "2"]
    token_calls = [c for c in responses.calls
                   if "access_token" in c.request.url]
    assert len(token_calls) == 1  # token cached across pages


@responses.activate
def test_reauth_on_401(client):
    _mock_token(responses)
    responses.get(f"{BASE}/v1/assets/abc", status=401)
    _mock_token(responses)
    responses.get(f"{BASE}/v1/assets/abc", json={"id": "abc"})
    assert client.get_asset("abc") == {"id": "abc"}


@responses.activate
def test_import_payload_shape(client):
    _mock_token(responses)
    captured = {}

    def _capture(request):
        captured.update(json.loads(request.body))
        return (200, {}, "")

    responses.add_callback(responses.POST, f"{BASE}/v1/import/assets",
                           callback=_capture)
    client.create_asset("INFRA", {"ip": "10.0.0.1", "hostname": "h1"},
                        tags=["env:prod"])
    assert captured["importType"] == "merge"
    asset = captured["assets"][0]
    assert "id" not in asset                      # attribute-based matching
    assert asset["findings"] == []                # asset-only creation
    assert asset["tags"] == [{"key": "env", "value": "prod"}]


@responses.activate
def test_remove_asset_tags_single(client):
    _mock_token(responses)
    response = {"results": [{
        "entityId": "a-1",
        "tag": {"key": "team", "value": "platform"},
        "status": "DELETED",
        "remainingOwnership": [],
    }]}
    responses.patch(f"{BASE}/v1/assets/a-1/tags", json=response)

    result = client.remove_asset_tags(
        ["team:platform", "temporary"], asset_id="a-1")

    assert result == response
    assert json.loads(responses.calls[-1].request.body) == {
        "tags": [
            {"key": "team", "value": "platform"},
            {"value": "temporary"},
        ]
    }


@responses.activate
def test_remove_asset_tags_bulk(client):
    _mock_token(responses)
    response = {"results": [{
        "entityId": "a-2",
        "tag": {"key": "team", "value": "platform"},
        "status": "SOURCE_REMOVED",
        "remainingOwnership": ["SCANNER_OR_SYSTEM"],
    }]}
    responses.patch(f"{BASE}/v1/assets/tags", json=response)

    result = client.remove_asset_tags(
        ["team:platform"], asset_ids=["a-1", "a-2"])

    assert result == response
    assert json.loads(responses.calls[-1].request.body) == {
        "tags": [{"key": "team", "value": "platform"}],
        "assetIds": ["a-1", "a-2"],
    }


@responses.activate
def test_remove_asset_tags_command_uses_bulk_endpoint():
    _mock_token(responses)
    responses.patch(f"{BASE}/v1/assets/tags", json={"results": [{
        "entityId": "a-1",
        "tag": {"value": "temporary"},
        "status": "PROTECTED",
        "remainingOwnership": ["REST_API_IMPORT"],
    }]})

    result = CliRunner().invoke(cli, [
        "--client-id", "cid", "--client-secret", "secret",
        "--api-base-url", BASE, "--output", "json",
        "assets", "remove-tags",
        "--asset-id", "a-1", "--asset-id", "a-2",
        "--tag", "temporary",
    ])

    assert result.exit_code == 0
    assert json.loads(result.output)["results"][0]["status"] == "PROTECTED"
    assert json.loads(responses.calls[-1].request.body)["assetIds"] == [
        "a-1", "a-2"]


def _components_page(*components):
    return {"content": list(components), "last": True, "totalPages": 1}


@responses.activate
def test_list_components_returns_effective_exposure(client):
    _mock_token(responses)
    responses.get(f"{BASE}/v1/components", json=_components_page(
        {"id": "c-1", "name": "backend", "effectiveExposure": "EXTERNAL"},
        {"id": "c-2", "name": "worker", "effectiveExposure": None},
    ))

    result = client.list_components(parent_id="app-1")

    assert [c["effectiveExposure"] for c in result] == ["EXTERNAL", None]


@responses.activate
def test_components_list_table_shows_effective_exposure():
    _mock_token(responses)
    responses.get(f"{BASE}/v1/components", json=_components_page(
        {"id": "c-1", "applicationId": "app-1", "name": "backend",
         "criticality": 9, "effectiveExposure": "DMZ", "tags": []},
        # Neither calculated nor declared — must render blank, not INTERNAL.
        {"id": "c-2", "applicationId": "app-1", "name": "worker",
         "criticality": 5, "effectiveExposure": None, "tags": []},
    ))

    result = CliRunner().invoke(cli, [
        "--client-id", "cid", "--client-secret", "secret",
        "--api-base-url", BASE, "components", "list", "--parent-id", "app-1",
    ])

    assert result.exit_code == 0
    assert "effectiveExposure" in result.output
    assert "DMZ" in result.output
    assert "INTERNAL" not in result.output


@responses.activate
def test_finding_search_body(client):
    _mock_token(responses)
    captured = {}

    def _capture(request):
        captured.update(json.loads(request.body))
        return (200, {}, json.dumps({"content": [], "last": True}))

    responses.add_callback(responses.POST, f"{BASE}/v1/findings",
                           callback=_capture)
    client.search_findings(status=["OPEN"], cves=["CVE-2024-1"],
                           severity_score_from="700")
    assert captured == {"status": ["OPEN"], "cves": ["CVE-2024-1"],
                        "severityScoreFrom": "700"}


@responses.activate
def test_add_finding_uses_delta(client):
    _mock_token(responses)
    captured = {}

    def _capture(request):
        captured.update(json.loads(request.body))
        return (200, {}, "")

    responses.add_callback(responses.POST, f"{BASE}/v1/import/assets",
                           callback=_capture)
    client.add_finding("CONTAINER", {"dockerfile": "org/api:1.0"},
                       {"name": "F1", "description": "d", "remedy": "r",
                        "severity": "9.0"})
    assert captured["importType"] == "delta"          # never closes others
    assert captured["assets"][0]["findings"][0]["name"] == "F1"


@responses.activate
def test_close_finding_rebuilds_merge_payload(client):
    _mock_token(responses)
    responses.get(f"{BASE}/v1/findings/f-target", json={
        "id": "f-target", "status": "OPEN", "assetId": "a-1",
        "severityScore": 800,
        "data": [{"name": "Target", "description": "d", "remedy": "r"}]})
    responses.get(f"{BASE}/v1/assets/a-1", json={
        "id": "a-1", "type": "INFRA",
        "data": [{"source": "s1",
                  "attributes": {"ip": "10.0.0.1", "hostname": "h1"}}]})
    responses.post(f"{BASE}/v1/findings", json={"content": [
        {"id": "f-target", "status": "OPEN", "severityScore": 800,
         "data": [{"name": "Target", "description": "d", "remedy": "r"}]},
        {"id": "f-keep", "status": "OPEN", "severityScore": 500,
         "location": "loc",
         "data": [{"name": "Keep", "description": "kd", "remedy": "kr",
                   "cve": "CVE-2024-1"}]},
    ], "last": True})
    result = client.close_finding("f-target", "Assessment-X", dry_run=True)
    payload = result["payload"]
    assert payload["importType"] == "merge"
    assert payload["assessment"]["name"] == "Assessment-X"
    kept = payload["assets"][0]["findings"]
    assert [f["name"] for f in kept] == ["Keep"]      # target omitted
    assert kept[0]["severity"] == "5.0"               # 500/100 scale mapping
    assert kept[0]["referenceIds"] == ["CVE-2024-1"]
    assert payload["assets"][0]["attributes"]["ip"] == "10.0.0.1"


def test_new_commands_help():
    runner = CliRunner()
    for args in (["findings", "add", "--help"],
                 ["findings", "close", "--help"],
                 ["assets", "update", "--help"],
                 ["gaps", "--required"]):
        assert runner.invoke(cli, args).exit_code == 0


def test_required_endpoints_listed():
    result = CliRunner().invoke(cli, ["gaps", "--required"])
    assert "PATCH" in result.output
    assert "/v1/findings/<finding-id>" in result.output
    assert "DELETE" in result.output
    assert "/v1/assets/<asset-id>/tags" not in result.output


def test_gap_stubs_raise(client):
    for call in (lambda: client.delete_asset("x"),
                 lambda: client.update_finding_status("x", "CLOSED"),
                 lambda: client.delete_application("x"),
                 lambda: client.delete_team("x"),
                 lambda: client.delete_user("x")):
        with pytest.raises(PhoenixNotSupportedError):
            call()


def test_not_supported_exit_code():
    result = CliRunner().invoke(
        cli, ["--client-id", "a", "--client-secret", "b", "apps", "delete",
              "some-id"])
    assert result.exit_code == 5
