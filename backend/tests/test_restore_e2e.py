"""Gated restore-only check: SQL outbox recovers work without the old Redis queue."""

import os
import time

import httpx
import pytest


@pytest.mark.skipif(
    not os.getenv("ZG_E2E_URL") or os.getenv("ZG_RESTORE_E2E") != "true",
    reason="Requires the disposable restored Compose drill",
)
def test_restored_job_outbox_recovers_without_old_broker():
    base = os.environ["ZG_E2E_URL"].rstrip("/")
    with httpx.Client(base_url=base, timeout=15, headers={"Origin": base}) as client:
        assert client.post("/api/auth/demo").status_code == 200
        for _attempt in range(90):
            response = client.get("/api/zg/ingestions/restore-queued-proof")
            assert response.status_code == 200, response.text
            job = response.json()
            if job["status"] == "completed":
                break
            assert job["status"] != "failed", job
            time.sleep(1)
        else:
            pytest.fail(f"Restored durable job did not complete: {job['status']}")
        assert len(client.get("/api/zg/graph").json()["nodes"]) >= 12
        assert len(client.get("/api/zg/remediations").json()) >= 1
        assert client.post("/api/auth/logout").status_code == 200
