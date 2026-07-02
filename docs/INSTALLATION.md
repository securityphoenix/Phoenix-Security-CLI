# Installation Guide — Phoenix Security CLI

## Requirements

- Python **3.9 or newer** (`python3 --version`)
- Network access to your Phoenix Security API environment
- Phoenix API credentials (**Organisation → API Access** in the platform UI)

## Install

### pipx (recommended — isolated, on PATH)

```bash
pipx install git+https://github.com/Security-Phoenix-demo/Phoenix-Security-CLI
```

### uv

```bash
uv tool install git+https://github.com/Security-Phoenix-demo/Phoenix-Security-CLI
```

### pip

```bash
python3 -m pip install git+https://github.com/Security-Phoenix-demo/Phoenix-Security-CLI
```

### From source (development)

```bash
git clone https://github.com/Security-Phoenix-demo/Phoenix-Security-CLI
cd Phoenix-Security-CLI
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest   # offline suite, no credentials needed
```

All methods install two identical entry points: **`phx`** (short) and
**`phoenix-cli`**.

## Verify

```bash
phx --version
# phoenix-security-cli 1.0.0 (Phoenix API v1.27)

export PHOENIX_CLIENT_ID=...
export PHOENIX_CLIENT_SECRET=...
phx --env demo auth test
```

Expected output includes `"authenticated": true` and the number of
applications/environments visible to your credentials.

## Configure credentials

Precedence: **flags → environment variables → config.ini → defaults**.

### Environment variables

```bash
export PHOENIX_CLIENT_ID="your-client-id"
export PHOENIX_CLIENT_SECRET="your-client-secret"
export PHOENIX_API_BASE_URL="https://api.securityphoenix.cloud"
```

Legacy aliases also accepted: `CLIENT_ID`, `CLIENT_SECRET`,
`PHOENIX_BASE_URL`, `PHOENIX_DOMAIN`.

### config.ini

Searched in order: `./config.ini`, `~/.config/phoenix/config.ini`,
`~/.phoenix/config.ini` (or pass `--config path`):

```ini
[phoenix]
client_id = your-client-id
client_secret = your-client-secret
api_base_url = https://api.securityphoenix.cloud
```

> Security: never commit config.ini. This repository git-ignores it.
> Prefer environment variables (or a secret manager) in CI.

### Environments

| Name | Base URL |
|------|----------|
| `--env prod` | https://api.securityphoenix.cloud |
| `--env demo` | https://api.demo.appsecphx.io |
| `--env poc1` | https://api.poc1.appsecphx.io |
| Dedicated enterprise | `--api-base-url https://api.<tenant>.securityphoenix.cloud` |

## CI/CD usage

```yaml
# GitHub Actions example
- name: Gate on critical findings
  env:
    PHOENIX_CLIENT_ID: ${{ secrets.PHOENIX_CLIENT_ID }}
    PHOENIX_CLIENT_SECRET: ${{ secrets.PHOENIX_CLIENT_SECRET }}
  run: |
    pipx install git+https://github.com/Security-Phoenix-demo/Phoenix-Security-CLI
    phx apps posture --name "$APP_NAME" -o json > posture.json
    jq -e '.posture.findings.openByRisk.critical == 0' posture.json
```

```bash
# Jenkins / generic shell
phx import file scan-results.json --import-type delta
```

## Windows

```powershell
py -m pip install git+https://github.com/Security-Phoenix-demo/Phoenix-Security-CLI
setx PHOENIX_CLIENT_ID "your-client-id"
setx PHOENIX_CLIENT_SECRET "your-client-secret"
phx auth test
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `Configuration error: Phoenix API credentials not found` (exit 2) | Set `PHOENIX_CLIENT_ID`/`PHOENIX_CLIENT_SECRET` or pass flags |
| `Authentication error ... 401` (exit 3) | Credentials wrong, or created for a different environment — check `--env`/`--api-base-url` |
| `API error: HTTP 404` on an ID (exit 4) | The item doesn't exist **or your credentials can't see it** (Phoenix returns 404 for both) |
| `NOT SUPPORTED BY PHOENIX API v1.27` (exit 5) | Real API gap — run `phx gaps` for workarounds |
| Corporate TLS interception | `--insecure` (last resort) or fix the CA bundle via `REQUESTS_CA_BUNDLE` |
