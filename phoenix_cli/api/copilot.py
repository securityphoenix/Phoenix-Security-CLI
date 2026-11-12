"""Copilot patch plans, /v1/copilot/**.

Copilot patch plan routes. Copilot builds a plan
for an asset as a background job; the client starts it, polls the job and
reads the plan.
"""

from __future__ import annotations

import time
import uuid

from phoenix_cli.errors import PhoenixError, expect_mapping


class CopilotAPI:

    def start_patch_plan(self, asset_id: str, idempotency_key: str,
                         stale_copies: list[dict] | None = None) -> str:
        """Start a Copilot patch plan job; returns the job ID."""
        reply = self.transport.request(
            "POST", "/v1/copilot/patch-plans",
            json_body={"assetId": asset_id,
                       "staleCopies": list(stale_copies or [])},
            headers={"Idempotency-Key": idempotency_key})
        job_id = expect_mapping(reply, "the new job").get("jobId")
        if not job_id:
            raise PhoenixError("Unexpected response from Phoenix: no job ID")
        return job_id

    def get_job(self, job_id: str) -> dict:
        """State of a Copilot job."""
        return self.transport.request("GET", f"/v1/copilot/jobs/{job_id}")

    def get_copilot_patch_plan(self, plan_id: str) -> dict:
        """A plan written by Copilot."""
        return self.transport.request(
            "GET", f"/v1/copilot/patch-plans/{plan_id}")

    def wait_for_patch_plan(self, asset_id: str, *,
                            stale_copies: list[dict] | None = None,
                            timeout_s: int = 900, poll_s: int = 5,
                            sleep=time.sleep, clock=time.monotonic) -> dict:
        """Start a job, wait for it, and return the plan.

        Raises ``PhoenixError`` when the job fails and ``TimeoutError`` after
        ``timeout_s`` seconds, counted from the start with a monotonic clock so
        the time spent in requests and retries counts too.
        """
        job_id = self.start_patch_plan(asset_id, str(uuid.uuid4()), stale_copies)
        deadline = clock() + timeout_s
        while True:
            job = expect_mapping(self.get_job(job_id), "the job")
            state = job.get("state")
            if state == "DONE":
                if not job.get("planId"):
                    raise PhoenixError(
                        "Unexpected response from Phoenix: job is done but has no plan ID")
                return self.get_copilot_patch_plan(job["planId"])
            if state == "FAILED":
                raise PhoenixError(
                    f"Copilot could not build a plan: {job.get('error') or 'unknown error'}")
            remaining = deadline - clock()
            if remaining <= 0:
                raise TimeoutError(
                    f"Copilot job {job_id} did not finish within {timeout_s} seconds")
            sleep(min(poll_s, remaining))
            if clock() >= deadline:
                raise TimeoutError(
                    f"Copilot job {job_id} did not finish within {timeout_s} seconds")
