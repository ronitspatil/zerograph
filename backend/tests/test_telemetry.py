import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from prometheus_client.parser import text_string_to_metric_families
from pydantic import ValidationError

from app.core.config import Settings, get_settings
from app.core.telemetry import Telemetry
from app.db.models import IngestionJob
from app.main import BodyLimitMiddleware, create_app

TOKEN = "m" * 64


@pytest.fixture
def metrics_client(environment, monkeypatch):
    monkeypatch.setenv("ZG_METRICS_TOKEN", TOKEN)
    get_settings.cache_clear()
    app = create_app()
    with TestClient(app) as client:
        yield client, app
    get_settings.cache_clear()


def samples(body):
    return [sample for family in text_string_to_metric_families(body) for sample in family.samples]


def scrape(client):
    return client.get("/metrics", headers={"Authorization": f"Bearer {TOKEN}"})


def test_scraping_fails_closed_without_separate_secret(environment):
    with TestClient(create_app()) as client:
        assert client.get("/metrics").status_code == 503
        assert client.get("/metrics", headers={"Authorization": "Bearer " + "a" * 64}).status_code == 503


def test_scrape_auth_not_application_auth_and_not_public(metrics_client):
    client, _ = metrics_client
    for authorization in ["", "Basic " + TOKEN, "Bearer " + "a" * 64, "Bearer invalid"]:
        assert client.get("/metrics", headers={"Authorization": authorization}).status_code == 401
    response = scrape(client)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert "text/plain" in response.headers["content-type"]


@pytest.mark.parametrize("secret", ["short", "\u2603" * 64, "a" * 4097, "a" * 64])
def test_scrape_secret_validation(secret):
    with pytest.raises(ValidationError):
        Settings(metrics_token=secret)


def test_http_metrics_finite_labels_no_request_identifiers(metrics_client):
    client, app = metrics_client
    client.get("/api/v1/graph?tenant_id=secret-tenant", headers={"Authorization": "Bearer " + "a" * 64})
    for index in range(30):
        client.get(f"/unknown/secret-{index}?token=secret-query")
    app.state.telemetry.observe_http("attacker-operation", "attacker-method", 700, 0.1)
    body = scrape(client).text
    assert all(
        value not in body
        for value in [
            "secret-tenant",
            "secret-query",
            "secret-0",
            TOKEN,
            "attacker-operation",
            "attacker-method",
            "/api/",
        ]
    )
    values = samples(body)
    requests = [sample for sample in values if sample.name == "zg_http_requests_total"]
    assert len(requests) == 3
    assert {sample.labels["operation"] for sample in requests} == {"graph_view", "unmatched"}
    assert {sample.labels["method"] for sample in requests} == {"GET", "OTHER"}
    assert {sample.labels["status_class"] for sample in requests} == {"2xx", "4xx", "other"}
    assert not any(sample.labels.get("operation") == "metrics" for sample in values)


def test_ingestion_aggregates_all_tenants_without_labels(metrics_client, environment):
    client, _ = metrics_client
    factory, _ = environment
    with factory() as db:
        for index, status in enumerate(
            ["queued", "queued", "retrying", "completed", "failed", "unknown-secret-status"]
        ):
            db.add(
                IngestionJob(
                    id=f"private-job-{index}",
                    tenant_id=f"private-tenant-{index}",
                    actor="private-identity",
                    source="private-source",
                    status=status,
                    payload={},
                    created_at=datetime.now(UTC) - timedelta(seconds=120),
                )
            )
        db.commit()
    response = scrape(client)
    assert "private-" not in response.text and "unknown-secret-status" not in response.text
    values = samples(response.text)
    counts = {
        sample.labels["status"]: sample.value for sample in values if sample.name == "zg_ingestion_jobs"
    }
    assert counts == {"queued": 2, "retrying": 1, "running": 0, "completed": 1, "failed": 1, "other": 1}
    age = next(sample.value for sample in values if sample.name == "zg_ingestion_oldest_pending_seconds")
    assert 120 <= age < 130


def test_database_failure_omits_stale_gauges_and_reports_failure(metrics_client):
    client, app = metrics_client
    collector = next(
        collector
        for collector in app.state.telemetry.registry._collector_to_names
        if collector.__class__.__name__ == "IngestionCollector"
    )
    assert scrape(client).status_code == 200
    collector.refreshed_at = float("-inf")
    with patch("app.core.telemetry.session_factory", side_effect=RuntimeError("password-and-private-db-url")):
        response = scrape(client)
    assert response.status_code == 200
    assert "password-and-private-db-url" not in response.text
    assert "zg_ingestion_collection_success 0.0" in response.text
    assert "zg_ingestion_jobs{" not in response.text


def test_health_checks_have_only_known_dependencies(metrics_client):
    client, app = metrics_client
    with patch("app.main.Redis.from_url", side_effect=ConnectionError("private-redis-url")):
        assert client.get("/health/ready").status_code == 503
    body = scrape(client).text
    assert 'zg_dependency_health{dependency="redis"} 0.0' in body
    assert 'zg_dependency_health{dependency="postgres"} 1.0' in body
    assert "private-redis-url" not in body
    with pytest.raises(ValueError):
        app.state.telemetry.observe_health("private-host", False)


def test_separate_apps_do_not_share_metric_registries():
    first, second = Telemetry({"live"}), Telemetry({"live"})
    first.observe_http("live", "GET", 200, 0.1)
    assert "zg_http_requests_total{" not in second.render().decode()


def test_backend_body_limit_handles_many_chunks_and_timeout():
    async def exercise():
        messages = [
            {"type": "http.request", "body": b"x", "more_body": index < 1999} for index in range(2000)
        ]
        sent, replayed = [], []

        async def receive():
            return messages.pop(0)

        async def send(message):
            sent.append(message)

        async def app(scope, receive, send):
            replayed.append(await receive())

        scope = {"type": "http", "method": "POST", "path": "/", "headers": []}
        await BodyLimitMiddleware(app, 4096, 1)(scope, receive, send)
        assert replayed == [{"type": "http.request", "body": b"x" * 2000, "more_body": False}]

        async def stalled():
            await asyncio.sleep(60)

        await BodyLimitMiddleware(app, 4096, 0.01)(scope, stalled, send)
        assert sent[0]["status"] == 408

    asyncio.run(exercise())


def test_configuration_errors_do_not_include_secrets():
    secret = "private-token-too-short"
    with pytest.raises(ValidationError) as exc:
        Settings(metrics_token=secret)
    assert secret not in str(exc.value)
    shared = "private-credential-" * 4
    with pytest.raises(ValidationError) as exc:
        Settings(metrics_token=shared, git_token=shared)
    assert shared not in str(exc.value)


def test_postgres_metrics_connections_are_separate_and_bounded(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    from sqlalchemy.pool import NullPool

    from app.core.telemetry import IngestionCollector

    monkeypatch.setenv("ZG_DATABASE_URL", "postgresql+psycopg://unused@invalid.example/unused")
    get_settings.cache_clear()
    engine = MagicMock()
    db = MagicMock()
    db.get_bind.return_value = SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))
    db.execute.return_value.all.return_value = [("queued", 2)]
    db.scalar.return_value = None
    with (
        patch("app.core.telemetry.create_engine", return_value=engine) as create,
        patch("app.core.telemetry.Session") as session,
    ):
        session.return_value.__enter__.return_value = db
        metrics = list(IngestionCollector().collect())
        assert metrics[0].samples[0].value == 1
        assert create.call_args.kwargs == {"poolclass": NullPool, "connect_args": {"connect_timeout": 2}}
        assert str(db.execute.call_args_list[0].args[0]) == "SET LOCAL statement_timeout = '2000ms'"
        engine.dispose.assert_called_once()
    get_settings.cache_clear()


def test_real_postgres_ingestion_metrics(monkeypatch):
    import os
    from uuid import uuid4

    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url
    from sqlalchemy.orm import Session

    from app.db.models import Base

    url = os.environ.get("ZG_INGESTION_POSTGRES_URL")
    if not url:
        pytest.skip("Dedicated PostgreSQL integration URL is not configured")
    schema = f"telemetry_{uuid4().hex}"
    admin = create_engine(url)
    scoped_url = make_url(url).update_query_dict({"options": f"-csearch_path={schema}"})
    engine = create_engine(scoped_url)
    try:
        with admin.begin() as db:
            db.execute(text(f'CREATE SCHEMA "{schema}"'))
        Base.metadata.create_all(engine)
        with Session(engine) as db:
            db.add(
                IngestionJob(
                    id="private-job",
                    actor="private-user",
                    tenant_id="private-tenant",
                    source="snapshot",
                    status="queued",
                    payload={},
                )
            )
            db.commit()
        monkeypatch.setenv("ZG_DATABASE_URL", scoped_url.render_as_string(hide_password=False))
        monkeypatch.setenv("ZG_METRICS_TOKEN", TOKEN)
        get_settings.cache_clear()
        with TestClient(create_app()) as client:
            response = scrape(client)
            assert response.status_code == 200
            assert 'zg_ingestion_jobs{status="queued"} 1.0' in response.text
            assert "zg_ingestion_collection_success 1.0" in response.text
            assert "private-" not in response.text
    finally:
        get_settings.cache_clear()
        engine.dispose()
        with admin.begin() as db:
            db.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        admin.dispose()
