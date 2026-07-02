# Phoenix Security API — Required Endpoints Specification

**Status**: proposal / API wishlist · **Baseline**: REST API Enterprise v1.27
**Audience**: Phoenix Security platform/API team
**Machine-readable registry**: `phoenix_cli/gaps.py` (`REQUIRED_ENDPOINTS`),
surfaced by `phx gaps --required` and the MCP `phoenix_api_gaps` tool.

This document specifies the endpoints that are missing from API v1.27 but
required for complete programmatic (CLI/MCP/CI) operation of the platform.
Each proposal follows the existing v1.27 conventions: Bearer auth, the
standard paged envelope, `{key?, value}` tag objects, selector alternatives
for ID paths, and the documented HTTP status-code table.

Priorities: **P1** = blocks common automation daily · **P2** = forces
awkward/lossy workarounds · **P3** = quality-of-life.

| # | Priority | Method & Path | Purpose |
|---|----------|---------------|---------|
| 1 | P1 | `PATCH /v1/findings/<finding-id>` | Update a finding (status, overrides, triage) |
| 2 | P2 | `POST /v1/findings/<finding-id>/comments` | Comment on a finding |
| 3 | P1 | `POST /v1/assets` (direct) | Synchronous asset creation with ID return |
| 4 | P1 | `PATCH /v1/assets/<asset-id>` | Edit an asset |
| 5 | P1 | `DELETE /v1/assets/<asset-id>` | Remove/decommission an asset |
| 6 | P2 | `PATCH /v1/assets/<asset-id>/tags` | Remove asset tags |
| 7 | P2 | `DELETE /v1/applications/<application-id>` | Delete an application/environment |
| 8 | P3 | `GET /v1/scanners` | Enumerate scanner type codes |
| 9 | P2 | `GET /v1/import/requests/<request-id>` (+ webhooks) | Documented import job tracking |

---

## 1. PATCH /v1/findings/&lt;finding-id&gt; — Update a finding (P1)

**Why.** Findings are read-only in v1.27. Every triage action — closing,
reopening, risk acceptance, false-positive marking, severity override —
is UI-only. The only workaround is re-importing the finding's entire asset
report with `merge` semantics (implemented by `phx findings close` /
`phoenix_close_finding`), which is assessment-scoped, lossy (rebuilt from
search data), and can unintentionally affect sibling findings. This is the
single largest automation gap in the API.

**Proposed request** (all fields optional; only supplied fields change):

```
PATCH /v1/findings/<finding-id>
```
```json
{
  "status": "OPEN" | "CLOSED",
  "closeReason": "FIXED" | "NOT_APPLICABLE" | "DUPLICATE" | "OTHER",
  "riskAccepted": true,
  "riskAcceptedUntil": "2026-12-31",
  "falsePositive": true,
  "severityOverride": 850,
  "tags": [ { "key": "triage", "value": "reviewed" } ],
  "comment": "string (optional audit note attached to the change)"
}
```

- `severityOverride`: 0–1000 (search scale); `null` clears the override,
  restoring the scanner-reported severity.
- Selector variant per convention: `PATCH /v1/findings` with a
  `findingSelector: { "ids": ["uuid"] }` body for bulk triage.
- **Responses**: `200` updated Finding object · `400` invalid field ·
  `404` unknown/not visible · `409` no-op transition (already closed).
- Audit: changes should appear in the platform audit trail attributed to
  the API credential.

**Today**: `phx findings close` (merge re-import omitting the finding,
`--dry-run` supported); enrichment of scanner fields via
`phx findings enrich`; risk-accept/false-positive UI-only.

## 2. POST /v1/findings/&lt;finding-id&gt;/comments — Triage comments (P2)

**Why.** Teams document triage decisions where the finding lives. The only
API-visible free-text today is the import-time `details` JSON, which is
scanner data, not conversation, and requires a full re-import to touch.

**Proposed**:

```
POST /v1/findings/<finding-id>/comments
{ "comment": "string", "author": "string (optional; defaults to credential)" }
→ 201 { "id": "uuid", "comment": "...", "author": "...", "createdDateTime": "..." }

GET /v1/findings/<finding-id>/comments      → 200 [ ...comments... ]
```

**Today**: platform UI, or abusing `details` on re-import.

## 3. POST /v1/assets — Direct asset creation (P1)

**Why.** Assets exist only as a side effect of `POST /v1/import/assets`:
the call is asynchronous, may return an empty body, does not return the
created asset ID, and offers no get-or-create contract — clients must
re-search by attributes and hope matching succeeded. CMDB-style automation
(register an asset, then act on its ID) needs a synchronous primitive.

**Proposed**:

```
POST /v1/assets
```
```json
{
  "type": "INFRA" | "CLOUD" | "WEB" | "CONTAINER" | "REPOSITORY" | "BUILD" | "CODE",
  "attributes": { "...per-type attributes as in the import spec..." },
  "tags": [ { "key": "env", "value": "prod" } ],
  "installedSoftware": [ { "vendor": "...", "name": "...", "version": "..." } ],
  "onConflict": "return" | "update" | "error"   // get-or-create contract
}
```

- **Responses**: `201` full Asset object (with `id`) · `200` existing asset
  when `onConflict=return` matched · `409` when `onConflict=error` and the
  attributes match an existing asset.

**Today**: `phx assets create` wraps the import endpoint (merge, empty
findings array); the ID must be re-discovered via `POST /v1/assets` search.

## 4. PATCH /v1/assets/&lt;asset-id&gt; — Edit an asset (P1)

**Why.** Import merge can only ADD or UPDATE attribute values supplied in a
report. It cannot remove an attribute, correct an identity field (IP,
hostname, repository) without creating a second asset, set criticality, or
change locality. Asset hygiene is therefore manual.

**Proposed** (all optional):

```
PATCH /v1/assets/<asset-id>
```
```json
{
  "attributes": { "os": "Ubuntu 24.04", "netbios": null },
  "locality": "INTERNAL" | "EXTERNAL" | "DMZ",
  "criticality": 8
}
```

- `null` attribute value = remove the attribute.
- Identity-field changes re-key the asset while preserving its finding
  history and ID.
- **Responses**: `200` updated Asset · `400` invalid attribute for the
  asset's type · `404`.

**Today**: additive-only `phx assets update` / `phoenix_update_asset`
(import merge); removals and identity fixes are UI-only.

## 5. DELETE /v1/assets/&lt;asset-id&gt; — Remove an asset (P1)

**Why.** Decommissioned hosts, deleted repos and retired images linger via
API. No delete/decommission exists, so inventory accuracy depends on manual
UI cleanup — untenable at the 250K-asset scale the platform targets.

**Proposed**:

```
DELETE /v1/assets/<asset-id>            → 204
DELETE /v1/assets                       → 204   (bulk)
{ "assetIds": ["uuid", ...], "mode": "decommission" | "purge" }
```

- `decommission` (default): close the asset's OPEN findings, mark the asset
  inactive/historical (auditable, reversible).
- `purge`: full removal (admin-only).
- **Responses**: `204` · `404` · `409` if referenced by active association
  rules and `force` is not set.

**Today**: not possible via API — UI only. (`phx assets delete` is an
explicit flagged stub.)

## 6. PATCH /v1/assets/&lt;asset-id&gt;/tags — Remove asset tags (P2)

**Why (parity).** Applications and components support tag removal
(`PATCH .../tags` with `action: "delete"`); assets support only tag
addition (`PUT`). Mis-tagged assets cannot be corrected programmatically —
which also breaks automation that keys team auto-linking and asset
association rules off tags.

**Proposed** — mirror the existing app/component convention exactly:

```
PATCH /v1/assets/<asset-id>/tags
{ "action": "delete", "tags": [ { "id": "uuid" } | { "key": "env", "value": "staging" } ] }
→ 204 · 404 if no tag matched

PATCH /v1/assets/tags        (bulk: adds "assetIds": ["uuid"])
```

**Today**: UI only. (`phx assets remove-tags` is a flagged stub.)

## 7. DELETE /v1/applications/&lt;application-id&gt; — Delete app/env (P2)

**Why (parity).** Components/services are deletable by ID or selector;
Applications and Environments are not. IaC-style workflows (PYRUS-like
config sync) can create but never garbage-collect, so renamed/retired
apps accumulate.

**Proposed** — mirror the component convention:

```
DELETE /v1/applications/<application-id>     → 204
DELETE /v1/applications                      → 204
{ "applicationSelector": { "name": "...", "caseSensitive": false } }
```

- Must not target the Default Application (same protection as existing
  default-entity rules); `409` if it is the Default.
- Cascade semantics documented: components/services and deployment links
  are removed; assets are unassigned, not deleted.

**Today**: UI only. (`phx apps delete` is a flagged stub.)

## 8. GET /v1/scanners — Scanner type enumeration (P3)

**Why.** `POST /v1/findings` accepts a `scannerTypes` filter, but the valid
codes are not queryable — the official docs say to "request the list from
Phoenix". Clients hardcode or reverse-engineer codes from existing
findings' `scannerType` values.

**Proposed**:

```
GET /v1/scanners?pageNumber=0&pageSize=100
→ 200 paged envelope of
  { "code": "string", "name": "string", "type": "SAST|SCA|DAST|CONTAINER|CLOUD|INFRA|...", "native": boolean }
```

**Today**: maintain a local list, or derive codes from findings.

## 9. GET /v1/import/requests/&lt;request-id&gt; + webhooks — Import tracking (P2)

**Why.** `POST /v1/import/assets` is asynchronous and may return an empty
`200` body. The polling endpoint used by official Phoenix tooling
(`GET /v1/import/assets/file/translate/request/<request-id>`) is
undocumented and translate-specific. CI gates that import scans and then
gate on posture have no reliable "import finished" signal and resort to
sleeps.

**Proposed**:

```
POST /v1/import/assets → 202 { "requestId": "uuid" }   (always return an ID)

GET /v1/import/requests/<request-id>
→ 200 {
  "requestId": "uuid",
  "status": "QUEUED" | "PROCESSING" | "COMPLETED" | "FAILED",
  "assessment": { "name": "...", "assetType": "..." },
  "stats": { "assetsCreated": 0, "assetsUpdated": 0,
             "findingsCreated": 0, "findingsClosed": 0 },
  "errors": [ { "index": 3, "message": "missing required attribute ip" } ]
}
```

Plus organisation-level webhook subscriptions
(`POST /v1/webhooks` with events `import.completed`, `finding.created`,
`finding.closed`, `sla.breached`) so integrations don't have to poll at all.

**Today**: `phx import status` calls the undocumented translate endpoint;
empty-200 bodies are special-cased as success.

---

## Cross-cutting requests

1. **Distinguish 404-not-found from 403-no-permission** — today both cases
   return `404`, which makes automation debugging guesswork.
2. **Document rate limits** and return `429` + `Retry-After` consistently
   (clients already honour it).
3. **One severity scale** — searches use 0–1000 while imports use string
   `"1.0"`–`"10.0"`; accept both (or document the mapping) on any new write
   endpoint.

## Change management

When any endpoint above ships:
1. Remove/adjust its entry in `phoenix_cli/gaps.py` (`GAPS` and
   `REQUIRED_ENDPOINTS`) — this updates `phx gaps`, the MCP
   `phoenix_api_gaps` tool and the stub commands automatically.
2. Replace the workaround implementation (e.g. rewire
   `phx findings close` to `PATCH /v1/findings/<id>`), keeping the CLI
   surface stable.
3. Update `docs/GAP_ANALYSIS.md`, `docs/API_REFERENCE.md` and the OpenAPI
   spec (`openapi/phoenix-security-api-v1.27.yaml` → new version).
