# Phoenix Security API v1.27 — Gap Analysis

This document flags operations that **should be possible via the API/CLI but
are not** in REST API Enterprise v1.27. The CLI surfaces these as explicit
stub commands that exit with code `5` and point here, so gaps are visible
rather than silently missing. The same registry powers `phx gaps`.

Source: the official *Phoenix Security API — Enterprise v1.27* documentation,
cross-checked against the internal Phoenix tooling (PYRUS engine and the
Loading Script V5 importer) to confirm no undocumented public path exists.

## High-impact gaps

### 1. No single-finding write API (status, risk-accept, false-positive, comments)

The findings resource is **read-only** (`POST /v1/findings` search,
`GET /v1/findings/<id>`). There is no endpoint to:

- change a finding's status (open/close/reopen)
- risk-accept a finding or request false-positive review
  (the API *returns* `hasFalsePositiveRequest` but cannot set it)
- override severity/risk at the platform level
- add comments or triage notes

**Workarounds implemented by the CLI/MCP** (all built on
`POST /v1/import/assets`, the only write path):
- `phx findings add` / `phoenix_add_finding` — add a new finding
  (`delta`, never touches other findings).
- `phx findings close` / `phoenix_close_finding` — close a finding by
  re-importing its asset within the owning assessment via `merge`,
  omitting the target (supports `--dry-run`). Assessment-scoped and
  best-effort by nature.
- `phx findings enrich` / `phoenix_enrich_finding` — update severity,
  description, remedy, location, CVEs, CWEs, tags, `details` JSON.

Risk-accept, false-positive and platform severity overrides remain UI-only.

**Should exist**: `PATCH /v1/findings/<finding-id>` accepting
`status`, `severityOverride`, `riskAccepted`, `falsePositive`, `comment`.

### 2. No direct asset CRUD

- **Create**: assets exist only as a side effect of `POST /v1/import/assets`.
  There is no synchronous "create asset, return its ID" call, and no
  get-or-create contract — matching is attribute-based and server-side.
- **Update**: attributes (IP, hostname, OS, criticality…) cannot be edited
  directly; only re-imports (merge) touch them.
- **Delete / decommission**: no endpoint at all.
- **Tags**: can be added (`PUT /v1/assets/<id>/tags`) but **not removed** —
  unlike application and component tags.

**Workaround**: `phx assets create` / `update` / `enrich` wrap the import
endpoint (empty `findings` array, `merge`) — additive edits only; tag
additions use the direct endpoint; attribute removal, identity changes and
deletion are UI-only.

**Should exist**: `POST /v1/assets` (create), `PATCH /v1/assets/<id>`,
`DELETE /v1/assets/<id>`, `PATCH /v1/assets/<id>/tags` (remove).

## Required endpoints (formal API wishlist)

Full specifications — proposed request/response schemas, priorities and
migration notes — live in **[REQUIRED_ENDPOINTS.md](REQUIRED_ENDPOINTS.md)**.
The machine-readable registry lives in `phoenix_cli/gaps.py`
(`REQUIRED_ENDPOINTS`) and is surfaced by **`phx gaps --required`** and the
MCP `phoenix_api_gaps` tool (`requiredEndpoints`). Current list:
`PATCH /v1/findings/<id>` (status/override/risk-accept/false-positive),
`POST /v1/findings/<id>/comments`, `POST /v1/assets` (direct create),
`PATCH /v1/assets/<id>`, `DELETE /v1/assets/<id>`,
`PATCH /v1/assets/<id>/tags` (remove), `DELETE /v1/applications/<id>`,
`GET /v1/scanners`, `GET /v1/import/requests/<id>` (+ webhooks).

## Medium-impact gaps

### 3. Applications/Environments cannot be deleted

`DELETE /v1/components[/<id>]` exists, but there is no
`DELETE /v1/applications/...`. Cleanup of apps/envs is UI-only.
(`phx apps delete` is a flagged stub.)

### 4. Import pipeline is asynchronous and opaque

- `POST /v1/import/assets` may return an **empty 200 body** on success.
- The status-polling endpoint used by official Phoenix tooling
  (`GET /v1/import/assets/file/translate/request/<request-id>`) is **not in
  the v1.27 documentation** — `phx import status` calls it but flags it as
  undocumented.
- No webhooks/callbacks for import completion or new findings.

**Should exist**: a documented import-job resource with status transitions,
plus webhook subscriptions.

### 5. No scanner-type enumeration

`POST /v1/findings` accepts a `scannerTypes` filter, but the valid codes are
not queryable ("request the list from Phoenix", per the docs). Clients must
hardcode or reverse-engineer codes from existing findings' `scannerType`.

**Should exist**: `GET /v1/scanners`.

### 6. Ticketing/workflow is configuration-only

Apps/components accept `ticketing`/`messaging` blocks and findings expose
`workflowTickets` read-only, but tickets cannot be created, linked or
transitioned via the API, and SLA policies are read-only.

**Should exist**: `POST /v1/findings/<id>/tickets`, SLA policy endpoints.

## Low-impact gaps

| Gap | Detail | Workaround |
|-----|--------|------------|
| Teams: no delete/rename | `POST /v1/teams` only; membership managed separately | UI |
| Users: no delete, no role change | create/activate/deactivate only | `phx users deactivate`; UI for roles |
| No rate-limit documentation | 429 handling is guesswork | CLI honours `Retry-After`, retries with backoff |
| No health/introspection endpoint | can't check API availability without auth | `phx auth test` performs auth + minimal read |
| 404 ambiguity | "not found" and "no permission" are indistinguishable | documented in troubleshooting |
| Severity scale mismatch | search filters use 0–1000; import uses `"1.0"`–`"10.0"` strings | CLI documents both; no conversion applied |
| `PATCH /v1/applications` identification | update-by-selector is implied, not explicit, in the official docs | CLI always sends `applicationSelector` |

## Confirmed working (no gap)

For contrast, these are fully supported with an API key and covered by the
CLI: asset/finding search with all filters, posture at app/env/component
level, application & environment creation/update, component/service full
CRUD, asset-association rules (incl. `negateFilter`), deployment links,
repository rules, team creation/membership/auto-link, user lifecycle
(create/activate/deactivate), and bulk import of assets + findings.

---

*Maintained alongside `phoenix_cli/gaps.py` — update both when the API
adds capabilities.*
