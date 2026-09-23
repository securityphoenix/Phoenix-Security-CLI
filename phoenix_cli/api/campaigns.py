"""Campaigns API — /v1/campaigns.

Read-only access to aggregated campaign statistics. The stats are a daily
snapshot computed server-side (risk, finding/asset/SLA counts, ticket
summary); `stats` may be null if no snapshot has been generated yet.
"""


class CampaignsAPI:

    def get_campaign_stats(self, campaign_id):
        """Aggregated statistics for a campaign by its ID (UUID)."""
        return self.transport.request(
            "GET", f"/v1/campaigns/{campaign_id}/stats")
