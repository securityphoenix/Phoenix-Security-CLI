"""Copilot patch plans, /v1/copilot/**.

Routes R-9 to R-11 of the autopatcher API contract. Copilot builds a plan
for an asset as a background job; the client starts it, polls the job and
reads the plan.
"""

from __future__ import annotations

import time
import uuid

from phoenix_cli.errors import PhoenixError


class CopilotAPI:

    def start_patch_plan(self, asset_id: str, idempotency_key: str,
                         stale_copies: list[dict] | None = None) -> str:
        """R-9: start a Copilot patch plan job; returns the job ID."""
        reply = self.transport.request(
            "POST", "/v1/copilot/patch-plans",
            json_body={"assetId": asset_id,
                       "staleCopies": list(stale_copies or [])},
            headers={"Idempotency-Key": idempotency_key})
        return reply["jobId"]

    def get_job(self, job_id: str) -> dict:
        """R-10: state of a Copilot job."""
        return self.transport.request("GET", f"/v1/copilot/jobs/{job_id}")

    def get_copilot_patch_plan(self, plan_id: str) -> dict:
        """R-11: a plan written by Copilot."""
        return self.transport.request(
            "GET", f"/v1/copilot/patch-plans/{plan_id}")

    def wait_for_patch_plan(self, asset_id: str, *,
                            stale_copies: list[dict] | None = None,
                            timeout_s: int = 900, poll_s: int = 5,
                            sleep=time.sleep) -> dict:
        """Start a job, wait for it, and return the plan (R-11).

        Raises ``PhoenixError`` when the job fails and ``TimeoutError`` after
        ``timeout_s`` seconds of waiting.
        """
        job_id = self.start_patch_plan(asset_id, str(uuid.uuid4()), stale_copies)
        waited = 0
        while True:
            job = self.get_job(job_id)
            state = job.get("state")
            if state == "DONE":
                return self.get_copilot_patch_plan(job["planId"])
            if state == "FAILED":
                raise PhoenixError(
                    f"Copilot could not build a plan: {job.get('error') or 'unknown error'}")
            if waited >= timeout_s:
                raise TimeoutError(
                    f"Copilot job {job_id} did not finish within {timeout_s} seconds")
            sleep(poll_s)
            waited += poll_s
