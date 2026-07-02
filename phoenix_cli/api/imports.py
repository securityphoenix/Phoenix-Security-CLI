"""Import API — POST /v1/import/assets (assets + findings, one call).

This endpoint is the platform's ONLY write path for assets and findings.
importType semantics (v1.27):
  - delta: adds/updates only what is in the payload; never closes anything.
  - merge: updates matching assets/findings; findings absent from the payload
           (within the assessment scope) are CLOSED.
  - new:   removes existing vulnerabilities from the assets before importing;
           absent findings are CLOSED.
WARNING: importing a delta-style payload as new/merge closes findings the
user may not have intended to close.
"""

import json

from phoenix_cli.api.common import drop_none, parse_tags
from phoenix_cli.errors import PhoenixConfigError

IMPORT_TYPES = ("new", "merge", "delta")
ASSESSMENT_ASSET_TYPES = ("INFRA", "CLOUD", "WEB", "CONTAINER",
                          "REPOSITORY", "BUILD", "CODE")


class ImportsAPI:

    def import_assets(self, import_type, assessment_name, asset_type,
                      assets):
        """Import assets (and optionally their findings).

        `assets` is a list of dicts with keys: attributes (required),
        tags, installedSoftware, findings. Asset IDs are intentionally not
        sent — Phoenix matches/creates assets by attributes.
        """
        if import_type not in IMPORT_TYPES:
            raise PhoenixConfigError(
                f"importType must be one of {IMPORT_TYPES}, got '{import_type}'.")
        normalized = []
        for asset in assets:
            asset = dict(asset)
            asset.pop("id", None)  # attribute-based matching is the contract
            if asset.get("tags"):
                asset["tags"] = parse_tags(asset["tags"])
            if "findings" not in asset or asset["findings"] is None:
                asset["findings"] = []
            normalized.append(drop_none(asset))
        payload = {
            "importType": import_type,
            "assessment": drop_none({
                "assetType": asset_type,
                "name": assessment_name,
            }),
            "assets": normalized,
        }
        return self.transport.request("POST", "/v1/import/assets",
                                      json_body=payload) or {"status": "accepted"}

    def import_file(self, path, import_type=None, assessment_name=None):
        """Import a ready-made /v1/import/assets JSON payload from disk.

        Optional overrides: import_type, assessment_name.
        """
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        if not isinstance(payload, dict) or "assets" not in payload:
            raise PhoenixConfigError(
                f"{path} does not look like an import payload "
                "(expected top-level 'assets').")
        if import_type:
            payload["importType"] = import_type
        if assessment_name:
            payload.setdefault("assessment", {})["name"] = assessment_name
        if payload.get("importType") not in IMPORT_TYPES:
            raise PhoenixConfigError(
                f"Payload importType must be one of {IMPORT_TYPES}.")
        return self.transport.request("POST", "/v1/import/assets",
                                      json_body=payload) or {"status": "accepted"}

    def get_import_status(self, request_id):
        """Poll an asynchronous import/translate request.

        NOTE: this endpoint is used by official Phoenix tooling but is NOT
        documented in the v1.27 API PDF (flagged in docs/GAP_ANALYSIS.md).
        """
        return self.transport.request(
            "GET", f"/v1/import/assets/file/translate/request/{request_id}")
