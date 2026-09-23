# Phoenix Security CLI

Full-featured command-line interface and Python client library for the
[Phoenix Security](https://phoenix.security) platform, covering the complete
**REST API Enterprise v1.27** surface — with **just an API key**
(client ID + client secret).

```
pipx install git+https://github.com/Security-Phoenix-demo/Phoenix-Security-CLI
phx auth test
phx findings list --status OPEN --severity-from 700 -o json
```

## What you get

| Area | Commands | Coverage |
|------|----------|----------|
| Auth | `phx auth test`, `phx auth token` | Token flow (Basic → Bearer) |
| Assets | `phx assets list/get/tag/create/update/enrich` | Search, tagging + creation & (additive) editing via the import pipeline |
| Findings | `phx findings list/get/add/close/enrich` (alias `phx vulns`) | Every v1.27 search filter; add (delta), close (merge workaround) and enrich |
| Import | `phx import file/status/template/types` | Bulk asset+finding imports (`new`/`merge`/`delta`) |
| Applications & Environments | `phx apps …`, `phx envs …` | List, posture, create, update, tags, users, deploy links, repo rules |
| Components & Services | `phx components …`, `phx services …` | Full CRUD, posture, tags, deploy links, asset-association rules |
| Teams | `phx teams …` | CRUD-ish, membership, auto-link by tags/members |
| Users | `phx users …` | List, create, activate, deactivate |
| Campaigns | `phx campaigns stats <id>` | Aggregated campaign statistics (risk, finding/asset/SLA counts, ticket summary) — read-only, post-v1.27 |
| Anything else | `phx api METHOD /v1/...` | Authenticated escape hatch for any endpoint |
| API gaps | `phx gaps` | Flags what the API **cannot** do (with workarounds) |

Design principle: **clean input/output boundary**. Commands accept simple
flags/JSON and return normalized JSON/tables. Token management, retries
(`Retry-After` on 429/503, backoff on 5xx), pagination and Phoenix payload
quirks are handled internally and never leak into your scripts.

## Installation

Requires Python 3.9+.

```bash
# pipx (recommended for CLI use)
pipx install git+https://github.com/Security-Phoenix-demo/Phoenix-Security-CLI

# pip
pip install git+https://github.com/Security-Phoenix-demo/Phoenix-Security-CLI

# uv
uv tool install git+https://github.com/Security-Phoenix-demo/Phoenix-Security-CLI

# from a clone (development)
git clone https://github.com/Security-Phoenix-demo/Phoenix-Security-CLI
cd Phoenix-Security-CLI
pip install -e ".[dev]"
```

Both `phx` and `phoenix-cli` entry points are installed.
See [docs/INSTALLATION.md](docs/INSTALLATION.md) for full platform notes.

## Credentials

Create API credentials in the Phoenix UI under **Organisation → API Access**
(the client secret is shown only once). Then, in order of precedence:

```bash
# 1. flags
phx --client-id XXX --client-secret YYY --env prod auth test

# 2. environment variables
export PHOENIX_CLIENT_ID=XXX
export PHOENIX_CLIENT_SECRET=YYY
export PHOENIX_API_BASE_URL=https://api.securityphoenix.cloud

# 3. config.ini (./config.ini, ~/.config/phoenix/config.ini or ~/.phoenix/config.ini)
[phoenix]
client_id = XXX
client_secret = YYY
api_base_url = https://api.securityphoenix.cloud
```

Environments: `--env prod` (`api.securityphoenix.cloud`), `--env demo`
(`api.demo.appsecphx.io`), `--env poc1` (`api.poc1.appsecphx.io`), or any
dedicated-enterprise URL via `--api-base-url https://api.<tenant>.securityphoenix.cloud`.

**Never commit `config.ini` with real credentials** — it is git-ignored here.

## Quick tour

```bash
# Verify connectivity
phx auth test

# Posture of an application, by name
phx apps posture --name "Payments API" --exclude-risk-accepted

# All open critical findings, as JSON for jq
phx findings list --status OPEN --severity-from 900 -o json | jq '.[].id'

# Create an asset (no scanner required)
phx assets create --type INFRA --attr ip=10.1.2.3 --attr hostname=web-01 \
    --tag env:production --software openssl:openssl:3.0.13

# Enrich an existing asset (matched by attributes)
phx assets enrich --type INFRA --attr ip=10.1.2.3 --attr hostname=web-01 \
    --attr os="Ubuntu 22.04" --tag team:platform

# Add a brand-new vulnerability to an asset (delta — never closes others)
phx findings add --asset-type CONTAINER --asset-attr dockerfile=myorg/api:1.4 \
    --name "Hardcoded credential in entrypoint" --description "..." \
    --remedy "rotate + remove" --severity 8.5 --cwe CWE-798

# Close a finding (workaround: merge re-import omitting it; see phx gaps --required)
phx findings close <finding-id> --assessment "Nightly Trivy" --dry-run

# Enrich a finding (the only API write path — import merge)
phx findings enrich --asset-type CONTAINER --asset-attr dockerfile=myorg/api:1.4 \
    --name "CVE-2024-0001 in libssl" --description "..." --remedy "upgrade" \
    --severity 9.8 --cve CVE-2024-0001 --tag triaged:true

# Bulk import scanner output already in Phoenix format
phx import template CONTAINER > payload.json   # start from a template
phx import file payload.json --import-type delta

# Structure: apps, components, rules
phx apps create --name "Payments API" --criticality 8 --owner fc@example.com
phx components create --app-name "Payments API" --name backend --criticality 9
phx components add-rules --app-name "Payments API" --name backend \
    --rules '[{"name":"repo rule","filter":{"repository":["org/payments"]}}]'

# Teams & users
phx teams create --name "AppSec" --type SECURITY
phx teams add-members --name "AppSec" --user alice@example.com --auto-create
phx users deactivate --email leaver@example.com

# Anything the CLI doesn't wrap
phx api POST /v1/findings --body '{"cves":["CVE-2024-3094"]}'
```

Global flags: `-o table|json|csv`, `--env`, `--config`, `--timeout`, `--insecure`.

## What the API cannot do (flagged, not hidden)

Some operations you'd expect are **not possible in Phoenix API v1.27**. The
CLI ships them as explicit stubs that exit with code `5` and a clear
explanation instead of failing mysteriously:

- `phx findings update-status` / `set-severity` / `comment` — no per-finding
  write endpoint (enrich via `phx findings enrich` import-merge instead)
- `phx assets delete` / `remove-tags` — no asset delete or tag-removal endpoint
- `phx apps delete`, `phx teams delete`, `phx users delete` — not exposed by the API

Run **`phx gaps`** for the full, always-current table with workarounds, and
**`phx gaps --required`** for the endpoints the API should add
(`PATCH/DELETE /v1/assets`, `PATCH /v1/findings`, …). Details:
[docs/GAP_ANALYSIS.md](docs/GAP_ANALYSIS.md).

## Python library

```python
from phoenix_cli import PhoenixClient

client = PhoenixClient()  # resolves env vars / config.ini automatically
for finding in client.search_findings(status=["OPEN"], max_items=200):
    print(finding["id"], finding["severityScore"])

client.create_asset("CLOUD", {
    "providerType": "AWS", "providerAccountId": "123456789012",
    "region": "eu-west-1",
}, tags=["env:prod"])
```

## Documentation

- [docs/INSTALLATION.md](docs/INSTALLATION.md) — installation on macOS/Linux/Windows/CI
- [docs/API_REFERENCE.md](docs/API_REFERENCE.md) — human-readable v1.27 API reference
- [openapi/phoenix-security-api-v1.27.yaml](openapi/) — OpenAPI (Swagger) spec: browse in Swagger UI, import into Postman, generate clients
- [docs/GAP_ANALYSIS.md](docs/GAP_ANALYSIS.md) — API capability gaps & workarounds
- [docs/REQUIRED_ENDPOINTS.md](docs/REQUIRED_ENDPOINTS.md) — detailed specification of the endpoints the API should add (priorities, proposed schemas)
- MCP server (use Phoenix from Claude & other AI agents): [Pheonix-Security-Orange-MPC](https://github.com/Security-Phoenix-demo/Pheonix-Security-Orange-MPC)
- AI platform skills (Claude, ChatGPT, Codex, Cursor) wrapping this CLI + the MCP server: [skills/](https://github.com/Security-Phoenix-demo/Pheonix-Security-Orange-MPC/tree/main/skills)

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 2 | Configuration error (missing/invalid credentials or flags) |
| 3 | Authentication failed (401 on token) |
| 4 | API error (4xx/5xx after retries) |
| 5 | Operation not supported by API v1.27 (see `phx gaps`) |

## Development

```bash
pip install -e ".[dev]"
pytest            # offline test-suite (mocked HTTP)
```

## License

MIT — see [LICENSE](LICENSE).
