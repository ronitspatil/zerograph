"""Optional full-stack test through the built frontend, real queue, SQL and graph services."""

import os
import time
from datetime import UTC, datetime, timedelta

import httpx
import pytest


@pytest.mark.skipif(not os.getenv("ZG_E2E_URL"), reason="No running full stack configured")
def test_session_ingestion_simulation_and_remediation():
    base = os.environ["ZG_E2E_URL"].rstrip("/")
    with httpx.Client(base_url=base, timeout=15, headers={"Origin": base}) as client:
        assert client.get("/login").status_code == 200
        assert client.get("/api/zg/me").status_code == 401
        assert (
            client.post("/api/auth/demo", headers={"Origin": "https://attacker.example"}).status_code == 403
        )
        login = client.post("/api/auth/demo")
        assert login.status_code == 200
        assert "HttpOnly" in login.headers["set-cookie"]
        assert client.get("/api/zg/me").json()["tenant_id"] == "demo"
        response = client.post("/api/zg/ingestions", json={"source": "demo"})
        assert response.status_code == 202, response.text
        job_id = response.json()["id"]
        for _attempt in range(30):
            job = client.get(f"/api/zg/ingestions/{job_id}").json()
            if job["status"] == "completed":
                break
            assert job["status"] != "failed", job
            time.sleep(0.5)
        else:
            pytest.fail(f"Ingestion did not complete: {job}")
        graph = client.get("/api/zg/graph").json()
        assert len(graph["nodes"]) >= 12
        assert any(edge["type"] == "STORES_PII" for edge in graph["edges"])
        result = client.post("/api/zg/simulate", json={"node_id": "agent:support", "max_hops": 5})
        assert result.status_code == 200, result.text
        assert len(result.json()["affected_assets"]) == 3
        assert len(client.get("/api/zg/findings").json()) == 3
        assert client.get("/").status_code == 200
        now = datetime.now(UTC)
        preview = client.post(
            "/api/zg/remediations/preview",
            json={
                "identity_id": "role:admin",
                "policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:DeleteObject"], "Resource": "*"}
                    ],
                },
                "usage": {
                    "window_start": (now - timedelta(days=100)).isoformat(),
                    "window_end": (now - timedelta(days=1)).isoformat(),
                    "used_actions": ["s3:GetObject"],
                    "covered_services": ["s3"],
                    "complete": True,
                    "source": "synthetic-stack-test",
                },
            },
        )
        assert preview.status_code == 200, preview.text
        assert preview.json()["optimization"]["removed_actions"] == ["s3:DeleteObject"]
        rid = preview.json()["id"]
        assert "jsonencode" in client.get(f"/api/zg/remediations/{rid}/terraform").text
        assert client.post(f"/api/zg/remediations/{rid}/pr").status_code == 502
        assert any(e["action"] == "remediation.previewed" for e in client.get("/api/zg/audit").json())
        assert client.post("/api/auth/logout").status_code == 200
        assert client.get("/api/zg/me").status_code == 401


@pytest.mark.skipif(
    not os.getenv("ZG_E2E_URL") or os.getenv("ZG_E2E_VERIFY_PERSISTENCE") != "true",
    reason="Requires an already ingested disposable stack after database restart",
)
def test_snapshot_and_remediation_survive_database_restart():
    base = os.environ["ZG_E2E_URL"].rstrip("/")
    with httpx.Client(base_url=base, timeout=15, headers={"Origin": base}) as client:
        assert client.post("/api/auth/demo").status_code == 200
        graph = client.get("/api/zg/graph")
        assert graph.status_code == 200, graph.text
        assert len(graph.json()["nodes"]) >= 12
        assert len(client.get("/api/zg/findings").json()) == 3
        remediations = client.get("/api/zg/remediations")
        assert remediations.status_code == 200, remediations.text
        assert len(remediations.json()) >= 1
        assert any(e["action"] == "remediation.previewed" for e in client.get("/api/zg/audit").json())
        assert client.post("/api/auth/logout").status_code == 200
