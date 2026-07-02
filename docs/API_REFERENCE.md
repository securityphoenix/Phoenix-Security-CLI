# Phoenix Security API — Enterprise v1.27 — Reference

> Human-readable reference for the Phoenix Security REST API (Enterprise edition, specification v1.27, 15 April 2026).
> Machine-readable spec: [`openapi/phoenix-security-api-v1.27.yaml`](../openapi/phoenix-security-api-v1.27.yaml).

## Table of Contents

- [Base URLs & Environments](#base-urls--environments)
- [Authentication](#authentication)
- [Global HTTP Response Codes](#global-http-response-codes)
- [Global Conventions](#global-conventions)
  - [Pagination](#pagination)
  - [Selectors (identify by name)](#selectors-identify-by-name)
  - [Tags](#tags)
  - [Risk & Severity Scales](#risk--severity-scales)
  - [Ticketing & Messaging Blocks](#ticketing--messaging-blocks)
- [Auth Endpoints](#auth-endpoints)
- [Asset Endpoints](#asset-endpoints)
- [Findings Endpoints](#findings-endpoints)
- [Import Endpoints](#import-endpoints)
- [Application / Environment Endpoints](#application--environment-endpoints)
- [Component / Service Endpoints](#component--service-endpoints)
- [Asset Association Rules Endpoints](#asset-association-rules-endpoints)
- [Team Endpoints](#team-endpoints)
- [User Endpoints](#user-endpoints)
- [Known Limitations of API v1.27](#known-limitations-of-api-v127)

---

## Base URLs & Environments

| Environment | Base URL |
|---|---|
| SaaS production | `https://api.securityphoenix.cloud` |
| Non-production / demo | `https://api.demo.appsecphx.io` |
| Enterprise PoC | `https://api.poc1.appsecphx.io` |
| Dedicated Enterprise (`https://mycompany.securityphoenix.cloud`) | `https://api.mycompany.securityphoenix.cloud` |
| Any other environment | Check with Phoenix Support |

All paths below are relative to the base URL.

## Authentication

API credentials (Client ID + Client Secret) are created in the platform UI under **Organisation > API Access**. The Client Secret is shown **only once**, at creation time (stored hashed server-side, cannot be recovered). Multiple credential sets can be created and deactivated/removed independently.

**Step 1 — get a token** (HTTP Basic auth, Client ID as username, Client Secret as password; note this is a `GET`):

```bash
curl -s -u "$CLIENT_ID:$CLIENT_SECRET" \
  "https://api.securityphoenix.cloud/v1/auth/access_token"
```

Response (`200 OK`; wrong credentials return `401`):

```json
{
  "token": "eyJvcGFxdWUiOiJ0b2tlbiJ9...",
  "expiry": 1782645600
}
```

**Step 2 — call the API** with the Bearer token:

```bash
TOKEN=$(curl -s -u "$CLIENT_ID:$CLIENT_SECRET" \
  "https://api.securityphoenix.cloud/v1/auth/access_token" | jq -r .token)

curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.securityphoenix.cloud/v1/applications?pageNumber=0&pageSize=20"
```

Notes:

- `token` is an **opaque** Bearer token; include it on every request except the token endpoint itself.
- `expiry` is a Unix timestamp, but **no fixed token lifetime is documented** and server clocks may drift — do not rely on `expiry` alone. On any `401`, obtain a new token and retry.

## Global HTTP Response Codes

| Status | Verbs | Meaning | Suggested action |
|---|---|---|---|
| 200 OK | GET (and others) | Success; body contains the JSON result | Use the result |
| 201 Created | POST, PUT(?) | New item created | — |
| 204 No Content | DELETE (and tag removals) | Item deleted/removed; no body | — |
| 400 Bad Request | Some POST/PUT | Invalid input (e.g. invalid user email, empty ids+emails) | Fix the request |
| 401 Unauthorized | All | Token wrong or expired | Re-authenticate, retry |
| 404 Not Found | GET and others | Item doesn't exist, or credentials lack access | If the ID came from another endpoint, contact support |
| 409 Conflict | Some POST/PUT | Duplicate name / all items already present | — |
| 500 Internal Error | All | Problem executing the request (rare) | Do not retry indefinitely |
| 503 Service Unavailable | All | API temporarily unreachable | Retry a limited number of times |

## Global Conventions

### Pagination

List endpoints take `?pageNumber=<0-based>&pageSize=<n>`. Defaults are `pageNumber=0&pageSize=20` (assets, findings, applications, components) and `pageNumber=0&pageSize=100` (teams, users). Paged responses use a standard envelope:

```json
{
  "content": [ ],
  "first": true,
  "last": false,
  "pageNumber": 0,
  "pageNumberOfElements": 20,
  "pageSize": 20,
  "totalElements": 137,
  "totalPages": 7
}
```

Exception: `GET /v1/teams/{teamId}/users` returns a **bare JSON array**, not the envelope.

### Selectors (identify by name)

Many endpoints that take an ID path segment have an alternative "selector" form: **same URL without the `<id>` segment, plus a selector object in the request body**.

| Selector | Shape | Identifies |
|---|---|---|
| `applicationSelector` | `{ "id": "...", "name": "...", "caseSensitive": true }` | Application/Environment by ID or name |
| `componentSelector` | `{ "name": "...", "caseSensitive": true }` | Component/Service by name within the selected application |
| `teamSelector` | `{ "name": "...", "caseSensitive": true }` | Team by name |
| `serviceSelector` (singular, **legacy**) | `{ "id", "name", "caseSensitive", "tags", "matchAssetTags" }` | ONE service (first match) for deployment links |
| `serviceSelectors` (plural, **preferred**) | `{ "ids", "names", "caseSensitive", "tags", "matchAssetTags" }` | ALL matching services for deployment links |

`caseSensitive` is optional and defaults to `true`. For service selectors, at least one of id(s)/name(s)/tags must be provided; when several are given, only the first in the order **id(s) → name(s) → tags** is used.

### Tags

- Written tags: `{ "key": "string", "value": "string" }` — **`value` required, `key` optional**, everywhere.
- Tag-removal / auto-link tags may also carry `"id": "uuid"`; when `id` is present, key/value are ignored.
- Finding tags in responses carry a `category`: one of `TECH_STACK`, `ALERT`, `COMPLIANCE`, `BUSINESS_UNIT`, `GENERAL`.

### Risk & Severity Scales

| Field | Range |
|---|---|
| `criticality` (apps, components) | 1–10 |
| `threshold` (app/env) | 0–1000 (inherited from Organization threshold if omitted) |
| `value` (business value) | 1000–10000000 |
| Findings search `severityScoreFrom/To` | 0–1000 |
| Import finding `severity` | string `"1.0"`–`"10.0"` |
| `epssScore` | 0.0–1.0 |
| Risk buckets (posture/stats) | `critical`, `high`, `medium`, `low`, `none` |

### Ticketing & Messaging Blocks

Create/update endpoints for apps/envs and components/services accept optional `ticketing` and `messaging` blocks:

```json
"ticketing": {
  "integrationId": "uuid (optional)",
  "integrationName": "string (optional)",
  "projectId": "string (optional)",
  "projectName": "SEC",
  "integrationType": "JIRA"
},
"messaging": {
  "integrationId": "uuid (optional)",
  "integrationName": "string (optional)",
  "channelId": "string (optional)",
  "channelName": "#appsec-alerts",
  "integrationType": "SLACK"
}
```

- `integrationType` — ticketing: `JIRA`, `JIRA_DC`, `ADO`, `GITHUB`, `SERVICE_NOW`; messaging: `SLACK`.
- `projectName` / `channelName` is the **only required** field in each block.
- Integration selection order: `integrationId` → `integrationName` → any available (restricted to `integrationType` if given). Project/channel selection: by ID if provided, otherwise by name.

---

## Auth Endpoints

### GET /v1/auth/access_token — Obtain access token

- **Auth**: HTTP Basic (`base64(client_id:client_secret)`).
- **Response `200`**: `{ "token": "string", "expiry": 1234567890 }`
- **Errors**: `401` incorrect credentials.

See the [Authentication](#authentication) walkthrough above.

---

## Asset Endpoints

### POST /v1/assets — List/search assets

POST-as-search: filters in the body (this does **not** create assets — use `POST /v1/import/assets` for that).

| Parameter | In | Description |
|---|---|---|
| `pageNumber` | query | 0-based page, default 0 |
| `pageSize` | query | default 20 |
| `requests[].types` | body | **Required.** Asset types to return |
| `requests[].type` | body | Deprecated; if present, added to `types` |
| `requests[].applicationEnvironmentId` | body | App/Env UUID scope |
| `requests[].componentServiceId` | body | Component/Service UUID scope; if present, `applicationEnvironmentId` is ignored |
| `requests[].onlyUnassigned` | body | `true` = only assets not assigned to any Environment; default `false` |
| `requests[].filters[]` | body | Per-domain filters (CLOUD: `resourceType`, `providerAccountId`, `vpc`, `subnet`, `region`; INFRA: `cidr`, `hostnames`, `osNames`, `netbios`, `macAddress`; WEB/API: `cidr`, `fqdn`; SAST/SCA/Container: `repository`, `build`, `dockerfile`, `scannerSource`; plus `key`, `locality`, `tagKeys`, `tagValues`) |

Request example:

```json
{
  "requests": [
    {
      "types": ["CLOUD"],
      "applicationEnvironmentId": "8f14e45f-ea3c-4b7e-9c3d-2f5a6b7c8d90",
      "onlyUnassigned": false,
      "filters": [
        { "providerAccountId": ["123456789012"], "region": ["eu-west-1"], "tagValues": ["prod"] }
      ]
    }
  ]
}
```

Response `200` (paged envelope):

```json
{
  "content": [
    {
      "id": "3c9d2a4e-1f5b-4a6c-8d7e-9b0a1c2d3e4f",
      "key": "arn:aws:ec2:eu-west-1:123456789012:instance/i-0abc123",
      "type": "CLOUD",
      "resourceType": "EC2_INSTANCE",
      "locality": "INTERNAL",
      "data": [ { "source": "prowler", "attributes": { "region": "eu-west-1" } } ],
      "tags": [ { "key": "env", "value": "prod" } ]
    }
  ],
  "first": true, "last": true, "pageNumber": 0,
  "pageNumberOfElements": 1, "pageSize": 20, "totalElements": 1, "totalPages": 1
}
```

**Errors**: `401`.

### GET /v1/assets/{assetId} — Get asset

Returns the single-asset document. Note: this response uses `resource_type` (snake_case) while the list uses `resourceType` — an inconsistency in the source spec; handle both in clients.

**Errors**: `401`, `404`.

### PUT /v1/assets/{assetId}/tags — Add tags to one asset

```json
{ "tags": [ { "key": "owner", "value": "team-payments" } ] }
```

`assetIds` in the body is ignored in this variant. **Errors**: `401`, `404`.

### PUT /v1/assets/tags — Add tags to multiple assets

```json
{
  "tags": [ { "key": "owner", "value": "team-payments" } ],
  "assetIds": ["3c9d2a4e-1f5b-4a6c-8d7e-9b0a1c2d3e4f", "5e8f0a1b-2c3d-4e5f-6a7b-8c9d0e1f2a3b"]
}
```

`assetIds` is **required** here. **Errors**: `401`, `404`.

---

## Findings Endpoints

`/v1/findings` and `/v1/vulnerabilities` are **aliases** — every findings path exists under both prefixes.

### POST /v1/findings — Search findings

| Filter (body, all optional) | Values |
|---|---|
| `applicationEnvironmentId`, `componentServiceId`, `assetId` | UUIDs |
| `teamIds` | array of team UUIDs |
| `assetAssignedStatus` | `ASSIGNED` \| `UNASSIGNED` |
| `assetLocalities` | array of `INTERNAL`, `EXTERNAL`, `DMZ` |
| `type` | `WEB`, `CLOUD`, `FOSS`, `SAST`, `CONTAINER`, `INFRA` |
| `scannerTypes` | scanner codes (request the list from Phoenix — no list endpoint) |
| `status` | array of `OPEN`, `CLOSED` |
| `suggestedToFix`, `zeroDayAlert` | boolean |
| `dateFrom`, `dateTo` | `yyyy-MM-dd` |
| `severityScoreFrom/To` | 0–1000 |
| `cves` | array; each must start with `CVE-` |
| `epssScoreFrom/To` | 0.0–1.0 |
| `workflowTicketStatuses` | array of strings |
| `slaBreach`, `workflowTicketSlaBreach` | `"true"` \| `"false"` |
| `tagKeys`, `tagValues`, `tagCategories` | strings; categories narrow the tag search (`TECH_STACK`, `ALERT`, `COMPLIANCE`, `BUSINESS_UNIT`, `GENERAL`) |

Request example:

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://api.securityphoenix.cloud/v1/findings?pageNumber=0&pageSize=50" \
  -d '{
    "status": ["OPEN"],
    "type": "CONTAINER",
    "severityScoreFrom": "700",
    "cves": ["CVE-2025-1234"],
    "assetLocalities": ["EXTERNAL"]
  }'
```

Response `200`: paged envelope of Finding objects (see next section).

### GET /v1/findings/{findingId} — Get finding

Response `200` (abbreviated example):

```json
{
  "id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
  "organizationId": "0f1e2d3c-4b5a-4697-8877-665544332211",
  "status": "OPEN",
  "data": [
    {
      "spid": "SPID-000123",
      "name": "OpenSSL heap overflow",
      "description": "Heap buffer overflow in ...",
      "remedy": "Upgrade openssl to 3.0.15",
      "cve": "CVE-2025-1234",
      "type": "CONTAINER"
    }
  ],
  "assetId": "3c9d2a4e-1f5b-4a6c-8d7e-9b0a1c2d3e4f",
  "parents": [
    {
      "applicationId": "8f14e45f-ea3c-4b7e-9c3d-2f5a6b7c8d90",
      "applicationName": "Payments",
      "componentId": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
      "componentName": "payments-api"
    }
  ],
  "severityScore": 870,
  "exposed": true,
  "location": "docker.io/payments/api:1.4.2",
  "suggestedToFix": true,
  "epssScore": 0.42,
  "daysOpen": 12,
  "duplicate": false,
  "scannerName": "Trivy",
  "scannerType": "TRIVY",
  "assetLocality": "EXTERNAL",
  "slaPolicy": {
    "vulnerability":  { "targetDays": 30, "targetDate": "2026-07-20", "breach": false },
    "workflowTicket": { "targetDays": 14, "targetDate": "2026-07-04", "breach": true }
  },
  "workflowTickets": [
    {
      "workflowType": "JIRA",
      "externalLink": true,
      "externalName": "SEC-4211",
      "externalUrl": "https://mycompany.atlassian.net/browse/SEC-4211",
      "createdDateTime": "2026-06-20T10:15:00Z"
    }
  ],
  "tags": [ { "key": "env", "value": "prod", "category": "GENERAL" } ]
}
```

**Errors**: `401`, `404`.

---

## Import Endpoints

### POST /v1/import/assets — Import assets and vulnerabilities

Developer-friendly JSON equivalent of the platform UI's Assessment Import. **This is the only way to create assets via the API.**

> **importType semantics — read before using**
>
> - `delta` — the report contains information about vulnerabilities/assets present right now but may NOT include everything in scope. The platform adds/updates what is in the report and removes/alters nothing else.
> - `new` / `merge` — the report is assumed to include ALL vulnerabilities currently present in all assets in the assessment scope. Anything present in a previous report for this assessment but absent from the new one is assumed addressed and **will be closed**. `new` removes existing vulnerabilities from the assets before importing; `merge` updates as required.
> - **Importing a delta report as `new`/`merge` will close vulnerabilities you may not have intended to close.**

Request example:

```json
{
  "importType": "merge",
  "assessment": { "assetType": "CONTAINER", "name": "nightly-trivy-scan" },
  "assets": [
    {
      "id": "7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d",
      "attributes": {
        "dockerfile": "payments/api/Dockerfile",
        "origin": "github"
      },
      "tags": [ { "key": "team", "value": "payments" } ],
      "installedSoftware": [
        { "vendor": "openssl", "name": "openssl", "version": "3.0.12", "cpe": "cpe:2.3:a:openssl:openssl:3.0.12" }
      ],
      "findings": [
        {
          "name": "CVE-2025-1234 openssl heap overflow",
          "description": "Heap buffer overflow in ...",
          "remedy": "Upgrade openssl to 3.0.15",
          "severity": "8.7",
          "location": "docker.io/payments/api:1.4.2",
          "referenceIds": ["CVE-2025-1234"],
          "cwes": ["CWE-787"],
          "publishedDateTime": "2026:05:01 09:00:00",
          "details": { "layer": "sha256:abc..." }
        }
      ]
    }
  ]
}
```

**Asset attributes by asset type**:

| Asset Type | Required | Optional |
|---|---|---|
| `INFRA` | `ip`, `hostname` | `network`, `fqdn`, `os`, `netbios`, `macAddress` |
| `WEB` | one of `ip` / `fqdn` | the other one |
| `CLOUD` | `providerType` (`AWS`/`AZURE`/`GCP`), `providerAccountId`; `region` (Azure only) | `vpc`, `subnet`, `region` (AWS/GCP), `providerAccountName`, `providerResourceId`, `resourceGroup` |
| `CONTAINER` / `REPOSITORY` / `CODE` / `BUILD` | `dockerfile` (Container), `repository` (Repo), `scannerSource` (Code), `buildFile` (Build) | `origin` (e.g. `"github"`) |

**Finding fields**: required `name`, `description`, `remedy`, `severity` (string `"1.0"`–`"10.0"`); `location` required for CODE. Optional: `referenceIds` (CVE/GHSA/…), `cwes` (`"CWE-xxxx"`), `publishedDateTime` (`"YYYY:MM:DD HH:MM:SS"`, defaults to now), `details` (free JSON, captured and displayed).

**InstalledSoftware**: required `vendor`, `name`, `version` (SemVer); optional `cpe`.

**Errors**: `401`.

---

## Application / Environment Endpoints

`/v1/applications` covers **both** Applications and Environments (distinguished by `type`: `APPLICATION` | `ENVIRONMENT`; Environments also carry `subType`: `CLOUD` | `INFRA`).

Default-entity protection: tag, responsible-user, repository, deploy, and update operations **must not target the Default Application**.

Name-selector variants: every ID-based endpoint below also exists at the same URL **without** the ID segment, with an `applicationSelector` (`{ "name", "caseSensitive" }`) in the body.

### GET /v1/applications — List apps/envs

| Parameter | In | Description |
|---|---|---|
| `pageNumber`, `pageSize` | query | paging |
| `type` | query | optional; `APPLICATION` or `ENVIRONMENT` only |

Response `200`: paged envelope of Application objects:

```json
{
  "id": "8f14e45f-ea3c-4b7e-9c3d-2f5a6b7c8d90",
  "organizationId": "0f1e2d3c-4b5a-4697-8877-665544332211",
  "name": "Payments",
  "owner": { "id": "11111111-2222-3333-4444-555555555555", "email": "owner@mycompany.com" },
  "criticality": 8,
  "value": 500000,
  "risk": 640,
  "threshold": 500,
  "aboveThreshold": true,
  "type": "APPLICATION",
  "subType": null,
  "responsibleUsers": [ { "id": "1111...", "email": "dev@mycompany.com" } ],
  "tags": [ { "key": "bu", "value": "retail" } ],
  "stats": {
    "findings": { "open": 42, "closed": 310, "openByRisk": { "critical": 2, "high": 9, "medium": 18, "low": 11, "none": 2 } },
    "assets": { "total": 57 }
  },
  "default": false
}
```

### GET /v1/applications/{applicationId} — Get app/env

Single Application object. **Errors**: `401`, `404`.

### GET /v1/applications/{applicationId}/posture — Posture (by ID)

| Parameter | In | Description |
|---|---|---|
| `excludeRiskAccepted` | query | exclude "risk accepted" findings from counts; default `false` |

Response `200`: posture object (`id`, `name`, `criticality`, `value`, `risk`, `riskMagnitude`, `threshold`, `aboveThreshold`, `type`, `default`, and `posture.findings` / `posture.assets` counts). **Errors**: `401`, `404`.

### POST /v1/applications/posture — Posture (by selector)

```json
{
  "applicationSelector": { "name": "Payments", "caseSensitive": false },
  "excludeRiskAccepted": true
}
```

Same response as the ID-based variant. **Errors**: `401`, `404`.

### POST /v1/applications — Create app/env

| Field | Required | Notes |
|---|---|---|
| `name` | yes | 3–255 chars |
| `type` | yes | `APPLICATION` \| `ENVIRONMENT` |
| `subType` | for ENVIRONMENT | `CLOUD` \| `INFRA` |
| `criticality` | yes | 1–10 |
| `owner` | yes | `{id}` or `{email}` of an existing user |
| `threshold` | no | 0–1000; inherited from Organization if omitted |
| `value` | no | 1000–10000000 |
| `responsibleUsers[]` | no | each needs `id` or `email` |
| `tags[]` | no | `value` required, `key` optional |
| `ticketing`, `messaging` | no | see [common blocks](#ticketing--messaging-blocks) |

```json
{
  "name": "Payments",
  "type": "APPLICATION",
  "criticality": 8,
  "value": 500000,
  "owner": { "email": "owner@mycompany.com" },
  "responsibleUsers": [ { "email": "dev@mycompany.com" } ],
  "tags": [ { "key": "bu", "value": "retail" } ],
  "ticketing": { "projectName": "SEC", "integrationType": "JIRA" }
}
```

Response: created Application object. **Errors**: `401`.

### PATCH /v1/applications — Update app/env

Documented at the collection path; identify the entity with `applicationSelector` in the body (the spec is not fully explicit here — see limitations). All fields optional; only supplied fields change.

```json
{
  "applicationSelector": { "name": "Payments" },
  "criticality": 9,
  "owner": { "email": "new-owner@mycompany.com" }
}
```

Response: updated Application object. **Errors**: `401`, `404`.

### PUT /v1/applications/{applicationId}/tags — Add tags

```json
{ "tags": [ { "key": "bu", "value": "retail" } ] }
```

Response: updated Application object. Selector variant: `PUT /v1/applications/tags` + `applicationSelector`. **Errors**: `401`, `404`.

### PATCH /v1/applications/{applicationId}/tags — Remove tags

```json
{
  "action": "delete",
  "tags": [ { "id": "9a8b7c6d-5e4f-4a3b-2c1d-0e9f8a7b6c5d" }, { "key": "bu", "value": "retail" } ]
}
```

`action` must be `"delete"`; when a tag has `id`, key/value are ignored. Response: `204 No Content`. **Errors**: `401`, `404` (no tags matched). Selector variant: `PATCH /v1/applications/tags`.

### PUT /v1/applications/{applicationId}/responsible-users — Add responsible users

```json
{ "responsibleUsers": [ { "email": "dev2@mycompany.com" } ] }
```

Users are **added** to the existing list if not already present; they must already exist in the organisation. Response: updated Application object. Selector variant: `PUT /v1/applications/responsible-users`. **Errors**: `401`, `404`.

### PATCH /v1/applications/{applicationId}/deploy — Add/replace deployment links

The ID **must be an Application's** (not an Environment's). Prefer plural `serviceSelectors` (selects ALL matches) over legacy singular `serviceSelector` (first match only).

```json
{
  "serviceSelectors": {
    "names": ["payments-prod-cluster"],
    "caseSensitive": false,
    "matchAssetTags": true
  },
  "replaceExisting": false
}
```

`replaceExisting` defaults to `true` (replace instead of add). Response: updated Application object. **Errors**: `401`, `404` (no service found). Selector variant: `PATCH /v1/applications/deploy`.

### POST /v1/applications/{applicationId}/repository — Link repository

Adds a "repository rule" (associates any asset whose `repository` attribute matches). Creates a new component named after the repository when `component` is omitted.

| Field | Required | Notes |
|---|---|---|
| `repository` | yes | repository name for the rule |
| `search` | no | substring matched on asset IDs to select a subset within the repository |
| `component.id` / `component.name` | one of, when `component` present | `id` must not be the Default Component; `name` must be unique in the application |
| `component.criticality` | no | 1–10, overrides the application's |
| `component.tags` | no | added to the new/existing component |

```json
{
  "repository": "github.com/mycompany/payments-api",
  "component": { "name": "payments-api", "criticality": 8, "tags": [ { "key": "lang", "value": "java" } ] }
}
```

Constraint: the repository must not already exist inside the target component (or, when creating a component, anywhere inside the application). Response: updated Application object. Selector variant: `POST /v1/applications/repository`. **Errors**: `401`, `404`.

---

## Component / Service Endpoints

`/v1/components` covers Components (inside Applications) and Services (inside Environments). Default Component/Service is protected (no tag removal, deploy, delete).

### GET /v1/components — List components/services

| Parameter | In | Description |
|---|---|---|
| `pageNumber`, `pageSize` | query | paging |
| `parentId` | query | App/Env UUID to limit scope |
| `type` | query | `COMPONENT` \| `SERVICE` |

Response `200`: paged envelope of Component objects:

```json
{
  "id": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
  "organizationId": "0f1e2d3c-4b5a-4697-8877-665544332211",
  "applicationId": "8f14e45f-ea3c-4b7e-9c3d-2f5a6b7c8d90",
  "name": "payments-api",
  "criticality": 8,
  "tags": [ { "key": "lang", "value": "java" } ],
  "default": false
}
```

### GET /v1/components/{componentId} — Get component/service

Single Component object. **Errors**: `401`, `404`.

### GET /v1/components/{componentId}/posture — Posture (by ID)

Query param `excludeRiskAccepted` (default `false`). Response includes `risk`, `riskMagnitude`, and `posture.findings`/`posture.assets` counts. **Errors**: `401`, `404`.

### POST /v1/components/posture — Posture (by selector)

```json
{
  "selector": {
    "applicationSelector": { "name": "Payments" },
    "componentSelector": { "name": "payments-api", "caseSensitive": false }
  },
  "excludeRiskAccepted": true
}
```

**Errors**: `401`, `404`.

### POST /v1/components — Create component/service

| Field | Required | Notes |
|---|---|---|
| `applicationSelector` | yes | app/env by `id` or `name` |
| `name` | yes | 3–255 chars, unique within the application |
| `criticality` | no | 1–10 |
| `tags[]` | no | |
| `ticketing`, `messaging` | no | |

```json
{
  "applicationSelector": { "name": "Payments" },
  "name": "payments-worker",
  "criticality": 6,
  "tags": [ { "key": "lang", "value": "kotlin" } ]
}
```

Response: `201` Created with the Component object. **Errors**: `401`, `409` (name already exists in that application).

### PATCH /v1/components/{componentId} — Update component/service

All fields optional. Tags are **added** unless the same key/value pair already exists.

```json
{ "name": "payments-worker-v2", "criticality": 7, "tags": [ { "key": "tier", "value": "backend" } ] }
```

Response: updated Component object. **Errors**: `401`, `404`.

### DELETE /v1/components/{componentId} — Delete (by ID)

Must not be the Default Component/Service. Prefer the selector variant for more precise identification. Response: `204 No Content`. **Errors**: `401`, `404`.

### DELETE /v1/components — Delete (by selector)

Body sent with the DELETE request:

```json
{
  "applicationSelector": { "name": "Payments" },
  "componentSelector": { "name": "payments-worker", "caseSensitive": false }
}
```

Response: `204 No Content`. **Errors**: `401`, `404`.

### PATCH /v1/components/{componentId}/tags — Remove tags

Same shape as application tag removal (`action: "delete"`, tags by `id` or key/value). Response `204`; `404` if no tags matched. Must not target the Default Component/Service.

### PATCH /v1/components/{componentId}/deploy — Add deployment links

The ID **must be a Component's** (not a Service's).

| Field | Default | Notes |
|---|---|---|
| `inheritFromApp` | `false` | `true` = inherit deployment config from the Application; other params ignored |
| `serviceSelectors` | — | `ids` / `names` / `tags` (+ `caseSensitive`, `matchAssetTags`); ALL matching services selected; precedence ids → names → tags |
| `replaceExisting` | `true` | replace vs add |

```json
{
  "serviceSelectors": { "tags": [ { "key": "cluster", "value": "prod-eu" } ], "matchAssetTags": true },
  "replaceExisting": true
}
```

Response: `200 OK`. **Errors**: `401`, `404` (no service found).

---

## Asset Association Rules Endpoints

### POST /v1/components/{componentId}/rules — Add/replace rules (by ID)
### POST /v1/components/rules — Add/replace rules (by selector)

When the component ID is in the path, the body `selector` is ignored; without it, `selector.applicationSelector` + `selector.componentSelector` are required.

| Field | Required | Notes |
|---|---|---|
| `rules[]` | yes | each rule has `name` + `filter` |
| `rules[].filter.ids` | no | asset UUIDs — if provided, these and only these are selected |
| `rules[].filter.keyLike` | no | case-sensitive substring on asset key, wrap in `*`, e.g. `"*prod*"` |
| `rules[].filter.tags` | no | tag objects (`value` required) |
| `rules[].filter.negateFilter` | no | same structure; matched assets are EXCLUDED; **cannot be nested** |
| `resetRules` | no | default `false`; `true` replaces all existing rules |

Filter fields by parent kind:

- **Cloud environments**: `providerAccountId`, `providerAccountName`, `resourceGroup`
- **Infra environments**: `assetType` (`INFRA` | `CONTAINER`), `cidrs`, `ipRanges` (`{from, to}`), `hostnames`, `osNames`, `netbios`
- **Applications (APPSEC)**: `assetType` (`REPOSITORY` | `SOURCE_CODE` | `BUILD` | `WEBSITE_API`), `cidr(s)`, `fqdn`, `repository` (all asset types except `WEBSITE_API`)

If `assetType` is missing, all types are included.

```json
{
  "selector": {
    "applicationSelector": { "name": "Payments" },
    "componentSelector": { "name": "payments-api" }
  },
  "rules": [
    {
      "name": "prod repos",
      "filter": {
        "assetType": "REPOSITORY",
        "repository": ["github.com/mycompany/payments-api"],
        "keyLike": "*prod*",
        "negateFilter": { "tags": [ { "key": "env", "value": "sandbox" } ] }
      }
    }
  ],
  "resetRules": false
}
```

Rules are deduplicated **by their definition (filters), not their name**. Response: `201 Created` — body indicates the number of rules added. **Errors**: `401`, `404`, `409` (all provided rules already present).

---

## Team Endpoints

Name-selector variants: every ID-based endpoint below also exists at the same URL **without** the `{teamId}` segment, with a `teamSelector` (`{ "name", "caseSensitive" }`) in the body.

### GET /v1/teams — List teams

Paging defaults: `pageNumber=0`, `pageSize=100`. Response: paged envelope of `{ "id", "name", "type", "usersCount" }`.

### GET /v1/teams/{teamId} — Get team

Single Team object. **Errors**: `401`, `404`.

### GET /v1/teams/{teamId}/users — Get team members

Response `200` is a **bare JSON array** (not paged):

```json
[ { "id": "11111111-2222-3333-4444-555555555555", "email": "dev@mycompany.com" } ]
```

### DELETE /v1/teams/{teamId}/users/{userEmail} — Remove a member

Response: `204`. **Errors**: `401`, `404`.

### POST /v1/teams — Create team

```json
{ "name": "AppSec Champions", "type": "SECURITY" }
```

`name` must be unique in the organisation; `type` is `GENERAL` | `SECURITY`. Response: Team object. **Errors**: `401`, `409`.

### PUT /v1/teams/{teamId}/users — Add users to team

```json
{
  "users": [ { "email": "dev@mycompany.com" }, { "id": "11111111-2222-3333-4444-555555555555" } ],
  "autoCreateUsers": true
}
```

- `autoCreateUsers` (default `false`): when `true`, unknown emails are auto-created with the **Org User** role (first name = email username part, last name = `"User"`). When `false`, unknown emails return `400 "Invalid user email"`.

Response: `200` no body. **Errors**: `400` (unknown user without auto-create), `401`, `409` (all users already members — no changes made).

### POST /v1/teams/{teamId}/applications/auto-link/tags — Configure app/env auto-link tags

```json
{
  "match": "ANY",
  "tags": [ { "key": "team", "value": "payments" } ]
}
```

- `match`: `ANY` | `ALL`, optional. If omitted: `ANY` is used when the team has no existing rule; otherwise the existing rule's expression is kept.

Response: `200` no body. **Errors**: `401`, `409` (match mode not provided/unchanged and all tags already configured).

### PATCH /v1/teams/{teamId}/applications/auto-link/tags — Remove specific auto-link tags

```json
{ "action": "delete", "tags": [ { "key": "team", "value": "payments" } ] }
```

Each tag needs `id` or key/value (`id` takes precedence). Response: `204`. **Errors**: `401`, `404` (none of the tags exist in the team configuration).

### DELETE /v1/teams/{teamId}/applications/auto-link/tags — Remove ALL auto-link tags

Response: `200` no body.

### POST /v1/teams/{teamId}/applications/auto-link/users — Enable auto-link by team members

Links the team to apps/envs where team members are responsible users ("Auto-link based on Team Members"). No request body. Response: `200` no body.

### DELETE /v1/teams/{teamId}/applications/auto-link/users — Disable auto-link by team members

Response: `200` no body.

### POST /v1/teams/{teamId}/components/auto-link/tags — Configure component auto-link tags

Same body and rules as the app/env variant. Response: `200` no body; `409` as above.

### PATCH /v1/teams/{teamId}/components/auto-link/tags — Remove specific component auto-link tags

Same body as the app/env variant. Response: `204`; `404` if none exist.

### DELETE /v1/teams/{teamId}/components/auto-link/tags — Remove ALL component auto-link tags

Response: `200` no body.

---

## User Endpoints

### GET /v1/users — List users

Paging defaults: `pageNumber=0`, `pageSize=100`. Response: paged envelope of:

```json
{
  "id": "11111111-2222-3333-4444-555555555555",
  "email": "dev@mycompany.com",
  "firstName": "Dev",
  "lastName": "Eloper",
  "active": true,
  "role": "ORG_USER"
}
```

### POST /v1/users — Create user

Sends welcome + one-time-password emails to the address (equivalent to UI creation).

```json
{
  "email": "new.user@mycompany.com",
  "firstName": "New",
  "lastName": "User",
  "role": "ORG_USER"
}
```

All four fields required; email unique in the organisation. Roles: `ORG_ADMIN`, `ORG_APP_ADMIN`, `ORG_USER`, `ORG_ADMIN_LITE`, `ORG_SEC_ADMIN`, `ORG_SEC_DEV`. Response: `200` with the User object. **Errors**: `401`, `409` (email already exists).

### POST /v1/users/deactivate — Deactivate users

```json
{ "ids": ["11111111-2222-3333-4444-555555555555"], "emails": ["leaver@mycompany.com"] }
```

At least one of `ids`/`emails` must be non-empty; duplicates across the lists are deduplicated; deactivating an already-inactive user is a no-op. Deactivated users lose access immediately. Response: `200` no body. **Errors**: `400` (both lists missing/empty), `401`, `404` (a user doesn't belong to the token's organisation).

### POST /v1/users/activate — Activate users

Same body shape and rules as deactivate; restores platform access; activating an already-active user is a no-op. Response: `200` no body. **Errors**: `400`, `401`, `404`.

---

## Known Limitations of API v1.27

Summarized from the source specification's ambiguities and gaps:

1. **No finding update endpoint** — findings can be searched and read, but not updated/closed directly via `/v1/findings` (state changes happen through imports).
2. **No delete for applications/environments, teams, or users** — only components/services can be deleted; users can only be deactivated.
3. **No rate limits documented** — the v1.27 spec contains no rate-limit information.
4. **No scanner-code list endpoint** — the valid `scannerTypes` values must be requested from Phoenix support.
5. **No webhook/event endpoints** are documented.
6. **Token lifetime is unspecified** — only an `expiry` Unix timestamp is returned; clients must handle 401 re-auth (server clock drift is possible). The overview also once refers to the token path as `/v1/access_token`; the canonical path is `/v1/auth/access_token`, and it uses GET + Basic auth rather than an OAuth form POST.
7. **POST-as-search** — `POST /v1/assets` and `POST /v1/findings` are search endpoints, not create; assets are created only via `POST /v1/import/assets`.
8. **`PATCH /v1/applications` identification is under-specified** — the PDF documents the update at the collection path without an explicit selector in its body example; the `applicationSelector` convention is the identification mechanism.
9. **Field-name inconsistencies in the source doc** — `resourceType` (asset list) vs `resource_type` (single asset); one tag example capitalizes `"Value"` (assume `value`); prose misspellings ("findgins", "outCreateUsers" — the real payload key is `autoCreateUsers`).
10. **Severity scales differ** — findings search uses 0–1000 (`severityScoreFrom/To`), imports use string `"1.0"`–`"10.0"`.
11. **`serviceSelector` vs `serviceSelectors`** — the singular form (Application deploy) is legacy and picks only the FIRST matching service; prefer the plural form, which selects ALL matches.
12. **Team members list is a bare array** — not the paged envelope used everywhere else.
13. **Default entities are protected** — Default Application and Default Component/Service must not be targeted by tag, responsible-user, repository, deploy, or delete operations.
