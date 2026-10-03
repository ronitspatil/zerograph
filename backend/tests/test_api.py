from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.collectors.tasks import process_job
from app.core.auth import Actor, current_actor
from app.db.models import AuditEvent, IngestionJob, TenantState
from app.graph.demo import demo_snapshot
from app.main import create_app


def test_auth_required(environment):
    with TestClient(create_app()) as client:
        assert client.get("/api/v1/graph").status_code == 401
        assert client.get("/health/live").status_code == 200


def test_graph_and_overview(client):
    response = client.get("/api/v1/graph")
    assert response.status_code == 200
    assert len(response.json()["nodes"]) == 12
    assert all("id" in e for e in response.json()["edges"])
    assert client.get("/api/v1/overview").json()["ai_agents"] == 2
    assert len(client.get("/api/v1/findings").json()) == 3
    assert response.headers["cache-control"] == "no-store"


def test_cross_tenant_cannot_read_snapshot(environment):
    app = create_app()
    app.dependency_overrides[current_actor] = lambda: Actor("bob", "tenant-b", frozenset({"viewer"}))
    with TestClient(app) as client:
        assert client.get("/api/v1/graph").json()["nodes"] == []
        assert client.get("/api/v1/ingestions").json() == []
        assert client.get("/api/v1/remediations").json() == []


def test_viewer_cannot_simulate_or_ingest(environment):
    app = create_app()
    app.dependency_overrides[current_actor] = lambda: Actor("bob", "tenant-a", frozenset({"viewer"}))
    with TestClient(app) as client:
        assert client.post("/api/v1/simulate", json={"node_id": "agent:support"}).status_code == 403
        assert (
            client.post("/api/v1/ingestions", json={"source": "snapshot", "payload": {}}).status_code == 403
        )
        assert client.get("/api/v1/audit").status_code == 403


def test_simulation_is_audited_and_hop_limit_validated(client, environment):
    response = client.post("/api/v1/simulate", json={"node_id": "agent:support", "max_hops": 5})
    assert response.status_code == 200
    assert len(response.json()["affected_assets"]) == 3
    assert client.post("/api/v1/simulate", json={"node_id": "missing"}).status_code == 404
    assert (
        client.post("/api/v1/simulate", json={"node_id": "agent:support", "max_hops": 6}).status_code == 422
    )
    factory, _ = environment
    with factory() as db:
        assert db.scalar(select(AuditEvent)).action == "simulation.run"


def test_snapshot_ingestion_publishes_atomically_and_is_idempotent(client, environment):
    factory, graph = environment
    with patch("app.api.routes.ingest.delay"):
        response = client.post(
            "/api/v1/ingestions",
            json={"source": "snapshot", "payload": demo_snapshot().model_dump(mode="json")},
        )
    assert response.status_code == 202
    job_id = response.json()["id"]
    process_job(job_id)
    process_job(job_id)
    assert client.get(f"/api/v1/ingestions/{job_id}").json()["status"] == "completed"
    with factory() as db:
        state = db.get(TenantState, "tenant-a")
        assert state.revision != "revision-a"
        assert len(graph.snapshot("tenant-a", state.revision).nodes) >= 12


def test_graph_failure_does_not_advance_revision(client, environment):
    factory, graph = environment
    with patch("app.api.routes.ingest.delay"):
        job = client.post(
            "/api/v1/ingestions",
            json={"source": "snapshot", "payload": demo_snapshot().model_dump(mode="json")},
        ).json()
    with patch.object(graph, "publish", side_effect=RuntimeError("database unavailable")):
        try:
            process_job(job["id"])
        except RuntimeError:
            pass
    with factory() as db:
        assert db.get(TenantState, "tenant-a").revision == "revision-a"


def test_mcp_secret_redaction_and_outbox_survives_broker_failure(client, environment):
    with patch("app.api.routes.ingest.delay", side_effect=ConnectionError):
        response = client.post(
            "/api/v1/ingestions",
            json={
                "source": "mcp",
                "payload": {
                    "mcpServers": {
                        "crm": {"env": {"API_TOKEN": "SECRET"}, "url": "https://secret@example.test"}
                    }
                },
            },
        )
    assert response.status_code == 202
    factory, _ = environment
    with factory() as db:
        job = db.get(IngestionJob, response.json()["id"])
        assert "SECRET" not in str(job.payload)
        assert "secret@example" not in str(job.payload)


def test_bad_ingestion_and_unconfigured_aws_rejected(client):
    assert (
        client.post(
            "/api/v1/ingestions",
            json={
                "source": "snapshot",
                "payload": {"edges": [{"source": "a", "target": "b", "type": "CAN_READ"}]},
            },
        ).status_code
        == 422
    )
    assert client.post("/api/v1/ingestions", json={"source": "aws"}).status_code == 409
    assert client.post("/api/v1/ingestions", json={"source": "demo"}).status_code == 403


def preview_payload():
    now = datetime.now(UTC)
    return {
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
            "source": "cloudtrail",
        },
    }


def test_preview_and_terraform_export(client):
    response = client.post("/api/v1/remediations/preview", json=preview_payload())
    assert response.status_code == 200
    assert response.json()["optimization"]["removed_actions"] == ["s3:DeleteObject"]
    rid = response.json()["id"]
    assert "jsonencode" in client.get(f"/api/v1/remediations/{rid}/terraform").text
    assert client.post(f"/api/v1/remediations/{rid}/pr").status_code == 502


def test_cross_tenant_job_and_remediation_are_not_found(client, environment):
    response = client.post("/api/v1/remediations/preview", json=preview_payload())
    rid = response.json()["id"]
    with patch("app.api.routes.ingest.delay"):
        jid = client.post(
            "/api/v1/ingestions",
            json={"source": "snapshot", "payload": demo_snapshot().model_dump(mode="json")},
        ).json()["id"]
    app = create_app()
    app.dependency_overrides[current_actor] = lambda: Actor("bob", "tenant-b", frozenset({"admin"}))
    with TestClient(app) as other:
        assert other.get(f"/api/v1/remediations/{rid}/terraform").status_code == 404
        assert other.post(f"/api/v1/remediations/{rid}/pr").status_code == 404
        assert other.get(f"/api/v1/ingestions/{jid}").status_code == 404
        assert other.get("/api/v1/ingestions").json() == []
        assert other.get("/api/v1/remediations").json() == []
        assert other.get("/api/v1/audit").json() == []
        assert other.post("/api/v1/simulate", json={"node_id": "agent:support"}).status_code == 404


def test_stale_graph_blocks_pr(client, environment):
    rid = client.post("/api/v1/remediations/preview", json=preview_payload()).json()["id"]
    factory, _ = environment
    with factory() as db:
        db.get(TenantState, "tenant-a").revision = "new"
        db.commit()
    assert client.post(f"/api/v1/remediations/{rid}/pr").status_code == 409


def test_gitops_destination_cannot_be_used_by_another_tenant(client, monkeypatch):
    from app.core.config import get_settings

    rid = client.post("/api/v1/remediations/preview", json=preview_payload()).json()["id"]
    monkeypatch.setenv("ZG_GIT_REPOSITORY", "another-company/policies")
    monkeypatch.setenv("ZG_GIT_TENANT_ID", "another-company")
    get_settings.cache_clear()
    assert client.post(f"/api/v1/remediations/{rid}/pr").status_code == 403
    get_settings.cache_clear()


def gitops_test_destination(monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setenv("ZG_GIT_REPOSITORY", "acme/policies")
    monkeypatch.setenv("ZG_GIT_TENANT_ID", "tenant-a")
    monkeypatch.setenv("ZG_GIT_TOKEN", "dedicated-test-token")
    get_settings.cache_clear()


def test_gitops_intent_persists_after_provider_timeout_and_scope_change_refused(
    client, environment, monkeypatch
):
    import hashlib

    import httpx
    from test_gitops import Provider

    from app.api import routes
    from app.core.config import get_settings
    from app.db.models import Remediation
    from app.remediation.gitops_sync import GitOpsClient

    gitops_test_destination(monkeypatch)
    rid = client.post("/api/v1/remediations/preview", json=preview_payload()).json()["id"]
    remote = Provider("github", rid, hashlib.sha256(b"tenant-a").hexdigest()[:16])
    remote.fail_after = "file"
    factory, _ = environment

    def constructor(config):
        def transport(request):
            with factory() as db:
                record = db.get(Remediation, rid)
                assert record.evidence["gitops_scope"]["repository"] == "acme/policies"
            return remote(request)

        return GitOpsClient(config, httpx.MockTransport(transport))

    monkeypatch.setattr(routes, "GitOpsClient", constructor)
    response = client.post(f"/api/v1/remediations/{rid}/pr")
    assert response.status_code == 502
    writes = len(remote.writes)
    with factory() as db:
        record = db.get(Remediation, rid)
        scope = record.evidence["gitops_scope"]
        assert record.pr_url is None
        assert "dedicated-test-token" not in str(scope)
        assert "s3:GetObject" not in str(scope)
    monkeypatch.setenv("ZG_GIT_BASE_BRANCH", "new-base")
    get_settings.cache_clear()
    assert client.post(f"/api/v1/remediations/{rid}/pr").status_code == 409
    assert len(remote.writes) == writes
    monkeypatch.setenv("ZG_GIT_BASE_BRANCH", "main")
    get_settings.cache_clear()
    assert client.post(f"/api/v1/remediations/{rid}/pr").status_code == 200
    assert len(remote.writes) == 3


def test_remote_success_sql_result_failure_retry_has_zero_remote_mutations(client, environment, monkeypatch):
    import hashlib

    import httpx
    from sqlalchemy.exc import SQLAlchemyError
    from sqlalchemy.orm import Session
    from test_gitops import Provider

    from app.api import routes
    from app.db.models import Remediation
    from app.remediation.gitops_sync import GitOpsClient

    gitops_test_destination(monkeypatch)
    rid = client.post("/api/v1/remediations/preview", json=preview_payload()).json()["id"]
    remote = Provider("gitlab", rid, hashlib.sha256(b"tenant-a").hexdigest()[:16])
    monkeypatch.setenv("ZG_GIT_PROVIDER", "gitlab")
    from app.core.config import get_settings

    get_settings.cache_clear()
    monkeypatch.setattr(
        routes, "GitOpsClient", lambda config: GitOpsClient(config, httpx.MockTransport(remote))
    )
    original_commit = Session.commit
    fail_once = True

    def commit(db):
        nonlocal fail_once
        if fail_once and any(isinstance(item, Remediation) and item.pr_url for item in db.dirty):
            fail_once = False
            raise SQLAlchemyError("SECRET database error")
        return original_commit(db)

    monkeypatch.setattr(Session, "commit", commit)
    with TestClient(client.app, raise_server_exceptions=False) as request_client:
        first = request_client.post(f"/api/v1/remediations/{rid}/pr")
        assert first.status_code == 500
        assert "SECRET" not in first.text
        writes = len(remote.writes)
        assert writes == 3 and remote.review is not None
        factory, _ = environment
        with factory() as db:
            record = db.get(Remediation, rid)
            assert record.pr_url is None
            assert record.evidence["gitops_scope"]["provider"] == "gitlab"
        second = request_client.post(f"/api/v1/remediations/{rid}/pr")
        assert second.status_code == 200
        assert len(remote.writes) == writes
        assert request_client.post(f"/api/v1/remediations/{rid}/pr").json() == second.json()
        assert len(remote.writes) == writes
