"""Assets API — search, retrieve, tag, create and enrich assets.

Direct REST coverage: POST /v1/assets (search), GET /v1/assets/<id>,
PUT /v1/assets/<id>/tags, PUT /v1/assets/tags.

Asset CREATION and attribute ENRICHMENT have no direct CRUD endpoint in
API v1.27 — they are implemented on top of POST /v1/import/assets (merge),
which is the platform's only asset write path. See docs/GAP_ANALYSIS.md.
"""

from phoenix_cli.api.common import drop_none, parse_tags
from phoenix_cli.errors import PhoenixConfigError, PhoenixNotSupportedError

ASSET_TYPES = ("INFRA", "CLOUD", "WEB", "CONTAINER", "REPOSITORY", "BUILD", "CODE")


class AssetsAPI:

    def search_assets(self, types=None, application_environment_id=None,
                      component_service_id=None, only_unassigned=None,
                      filters=None, page_size=100, max_items=None):
        """Search the asset registry (paged POST-as-search)."""
        request = drop_none({
            "types": list(types) if types else None,
            "applicationEnvironmentId": application_environment_id,
            "componentServiceId": component_service_id,
            "onlyUnassigned": only_unassigned,
            "filters": filters,
        })
        body = {"requests": [request]}
        return list(self.transport.paginate(
            "POST", "/v1/assets", json_body=body,
            page_size=page_size, max_items=max_items,
        ))

    def get_asset(self, asset_id):
        """Get one asset by its Phoenix ID."""
        return self.transport.request("GET", f"/v1/assets/{asset_id}")

    def add_asset_tags(self, tags, asset_id=None, asset_ids=None):
        """Add tags to one asset (asset_id) or many (asset_ids)."""
        parsed = parse_tags(tags)
        if asset_id:
            return self.transport.request(
                "PUT", f"/v1/assets/{asset_id}/tags", json_body={"tags": parsed})
        if not asset_ids:
            raise PhoenixConfigError("Provide asset_id or a list of asset_ids.")
        return self.transport.request(
            "PUT", "/v1/assets/tags",
            json_body={"tags": parsed, "assetIds": list(asset_ids)})

    # -- creation & enrichment (via the import pipeline) ---------------------

    def create_asset(self, asset_type, attributes, tags=None,
                     installed_software=None, assessment_name=None,
                     import_type="merge"):
        """Create (or upsert) a single asset without findings.

        API v1.27 has no direct asset-create endpoint; this builds a minimal
        POST /v1/import/assets payload. Phoenix matches assets server-side by
        their attributes (ip/hostname, repository, providerAccountId, ...), so
        re-running is an upsert, not a duplicate.
        """
        return self.import_assets(
            import_type=import_type,
            assessment_name=assessment_name or "CLI Asset Creation",
            asset_type=asset_type,
            assets=[drop_none({
                "attributes": attributes,
                "tags": parse_tags(tags) if tags else None,
                "installedSoftware": installed_software,
                "findings": [],
            })],
        )

    def enrich_asset(self, asset_type, attributes, tags=None,
                     installed_software=None, assessment_name=None):
        """Enrich an existing asset's attributes/tags/installed software.

        Uses import merge — the asset is matched by attributes and updated.
        For tag-only enrichment of an asset you already know the ID of,
        prefer add_asset_tags (direct endpoint, synchronous).
        """
        return self.create_asset(
            asset_type=asset_type, attributes=attributes, tags=tags,
            installed_software=installed_software,
            assessment_name=assessment_name or "CLI Asset Enrichment",
            import_type="merge",
        )

    def delete_asset(self, asset_id=None):
        """NOT SUPPORTED — flagged gap."""
        raise PhoenixNotSupportedError(
            "assets delete",
            "API v1.27 exposes no asset delete/decommission endpoint.",
            "Remove the asset's source assessment data in the platform UI, or "
            "let new/merge imports close out its findings.",
        )

    def remove_asset_tags(self, asset_id=None, tags=None):
        """NOT SUPPORTED — flagged gap."""
        raise PhoenixNotSupportedError(
            "assets remove-tags",
            "API v1.27 can ADD asset tags (PUT) but exposes no tag-removal "
            "endpoint for assets (unlike applications/components).",
            "Remove asset tags in the platform UI.",
        )
