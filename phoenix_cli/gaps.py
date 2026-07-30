"""Registry of Phoenix Security REST API v1.27 capability gaps.

Single source of truth for `phx gaps`, for the PhoenixNotSupportedError
stubs, and for docs/GAP_ANALYSIS.md. Each entry is an operation that a
security engineer would reasonably expect from the API/CLI but that the
platform does not (yet) expose via REST.
"""

GAPS = [
    {
        "operation": "findings update / close / reopen",
        "area": "Findings",
        "severity": "high",
        "gap": "No endpoint to update a single finding: status changes, "
               "risk acceptance, false-positive marking and comments are "
               "UI-only.",
        "workaround": "phx findings close automates closure (merge re-import "
                      "of the asset omitting the finding, assessment-scoped); "
                      "phx findings add adds new findings (delta); phx "
                      "findings enrich updates severity/description/remedy/"
                      "tags. Risk-accept/false-positive remain UI-only.",
        "cli": "phx findings add / close / enrich (workarounds); "
               "phx findings update-status (stub, explains the gap)",
    },
    {
        "operation": "findings set-severity (override)",
        "area": "Findings",
        "severity": "high",
        "gap": "No per-finding severity/risk override endpoint.",
        "workaround": "phx findings enrich re-imports the finding with a new "
                      "severity (changes scanner-reported severity, not a "
                      "platform override).",
        "cli": "phx findings set-severity (stub)",
    },
    {
        "operation": "assets create (direct)",
        "area": "Assets",
        "severity": "medium",
        "gap": "No direct asset CRUD create; assets exist only as a side "
               "effect of POST /v1/import/assets. Asset matching is "
               "attribute-based and implicit (no get-or-create contract).",
        "workaround": "phx assets create wraps the import endpoint with an "
                      "empty findings array (merge import).",
        "cli": "phx assets create (implemented via import)",
    },
    {
        "operation": "assets update attributes / delete",
        "area": "Assets",
        "severity": "medium",
        "gap": "No endpoint to update asset attributes directly, and no "
               "asset delete/decommission endpoint.",
        "workaround": "Additive attribute edits via import merge (phx assets "
                      "update / enrich) — cannot remove attributes or change "
                      "identity fields; deletion is UI-only.",
        "cli": "phx assets update / enrich (partial) / phx assets delete "
               "(stub)",
    },
    {
        "operation": "apps delete",
        "area": "Applications/Environments",
        "severity": "medium",
        "gap": "Components/services can be deleted via API, but Applications "
               "and Environments cannot.",
        "workaround": "Delete in the platform UI.",
        "cli": "phx apps delete (stub)",
    },
    {
        "operation": "teams delete / rename",
        "area": "Teams",
        "severity": "low",
        "gap": "Teams can be created and configured but not deleted or "
               "renamed via API.",
        "workaround": "Manage in the platform UI.",
        "cli": "phx teams delete (stub)",
    },
    {
        "operation": "users delete / change role",
        "area": "Users",
        "severity": "low",
        "gap": "Users can be created, activated and deactivated, but not "
               "deleted; roles cannot be changed via the documented API.",
        "workaround": "phx users deactivate; role changes in the UI.",
        "cli": "phx users delete (stub)",
    },
    {
        "operation": "list scanner types",
        "area": "Platform metadata",
        "severity": "medium",
        "gap": "The findings filter accepts scannerTypes but there is no "
               "endpoint to enumerate valid scanner codes ('request the list "
               "from Phoenix', per the official docs).",
        "workaround": "Keep a local list, or derive codes from existing "
                      "findings (scannerType field).",
        "cli": "—",
    },
    {
        "operation": "import status / async tracking",
        "area": "Import",
        "severity": "medium",
        "gap": "POST /v1/import/assets is asynchronous with an opaque "
               "(sometimes empty) success body; the polling endpoint used by "
               "official tooling (/v1/import/assets/file/translate/request/"
               "<id>) is not in the v1.27 documentation. No webhooks exist.",
        "workaround": "phx import status <request-id> calls the undocumented "
                      "polling endpoint.",
        "cli": "phx import status (undocumented endpoint)",
    },
    {
        "operation": "ticketing / workflow actions",
        "area": "Workflow",
        "severity": "medium",
        "gap": "Findings expose workflowTickets read-only; tickets cannot be "
               "created or transitioned via the API. SLA policies are "
               "read-only on findings.",
        "workaround": "Configure ticketing blocks on apps/components "
                      "(create/update) and let platform automation raise "
                      "tickets; manage tickets in the external tracker.",
        "cli": "—",
    },
    {
        "operation": "rate limits / API introspection",
        "area": "Platform metadata",
        "severity": "low",
        "gap": "No documented rate limits, no health endpoint, no endpoint "
               "listing organisation settings or API credential metadata.",
        "workaround": "The CLI honours Retry-After on 429/503 and retries "
                      "with backoff.",
        "cli": "—",
    },
]


# Endpoints the Phoenix API should add — the formal wishlist behind the
# gaps above. Surfaced via `phx gaps --required` and the MCP
# phoenix_api_gaps tool.
REQUIRED_ENDPOINTS = [
    {
        "method": "PATCH",
        "path": "/v1/findings/<finding-id>",
        "purpose": "Update a single finding: status (open/close/reopen), "
                   "severity override, risk acceptance, false-positive flag.",
        "today": "Close only via merge re-import omitting the finding "
                 "(phx findings close); other updates UI-only.",
    },
    {
        "method": "POST",
        "path": "/v1/findings/<finding-id>/comments",
        "purpose": "Attach triage comments/notes to a finding.",
        "today": "Abuse of 'details' JSON on re-import, or UI.",
    },
    {
        "method": "POST",
        "path": "/v1/assets",
        "purpose": "Direct synchronous asset creation returning the asset ID "
                   "(get-or-create contract).",
        "today": "Side effect of POST /v1/import/assets; ID must be "
                 "re-discovered by searching.",
    },
    {
        "method": "PATCH",
        "path": "/v1/assets/<asset-id>",
        "purpose": "Edit asset attributes (incl. removing attributes and "
                   "changing identity fields), criticality, locality.",
        "today": "Additive-only via import merge (phx assets update).",
    },
    {
        "method": "DELETE",
        "path": "/v1/assets/<asset-id>",
        "purpose": "Remove/decommission an asset.",
        "today": "Not possible via API — UI only.",
    },
    {
        "method": "DELETE",
        "path": "/v1/applications/<application-id>",
        "purpose": "Delete an application/environment (parity with "
                   "components).",
        "today": "UI only.",
    },
    {
        "method": "GET",
        "path": "/v1/scanners",
        "purpose": "Enumerate valid scannerType codes for findings filters.",
        "today": "Undocumented; values must be reverse-engineered.",
    },
    {
        "method": "GET",
        "path": "/v1/import/requests/<request-id>",
        "purpose": "Documented, stable import job status polling (plus "
                   "webhooks for completion).",
        "today": "Undocumented translate-request endpoint; empty 200 bodies.",
    },
]


def as_rows():
    return [
        {
            "area": g["area"],
            "operation": g["operation"],
            "severity": g["severity"],
            "gap": g["gap"],
            "workaround": g["workaround"],
        }
        for g in GAPS
    ]


def required_endpoint_rows():
    return [
        {
            "method": e["method"],
            "path": e["path"],
            "purpose": e["purpose"],
            "workaround today": e["today"],
        }
        for e in REQUIRED_ENDPOINTS
    ]
