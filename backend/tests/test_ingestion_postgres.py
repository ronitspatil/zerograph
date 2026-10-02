"""Actual row-lock/CAS races; opt in with a dedicated PostgreSQL test URL.

Every test owns a random schema. No existing tables are modified or removed.
"""

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier, Event
from unittest.mock import patch
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

from app.collectors import tasks
from app.db.models import AuditEvent, Base, IngestionJob, SourceSnapshot, TenantState, now
from app.graph.repository import MemoryGraphStore
from app.graph.schema import GraphSnapshot, Node, NodeType

pytestmark = pytest.mark.skipif(
    not os.getenv("ZG_INGESTION_POSTGRES_URL"), reason="No dedicated ingestion PostgreSQL test URL configured"
)


@pytest.fixture
def postgres_environment(monkeypatch):
    url = os.environ["ZG_INGESTION_POSTGRES_URL"]
    admin = create_engine(url)
    schema = "zg_ingestion_" + uuid4().hex
    with admin.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_engine(url, connect_args={"options": f"-csearch_path={schema}"})
    factory = sessionmaker(engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    graph = MemoryGraphStore()
    monkeypatch.setattr(tasks, "session_factory", lambda: factory)
    monkeypatch.setattr(tasks, "get_graph_store", lambda: graph)
    with factory() as db:
        db.add(TenantState(tenant_id="tenant", revision="initial"))
        db.commit()
    try:
        yield factory, graph
    finally:
        engine.dispose()
        with admin.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


def enqueue(factory, source="snapshot"):
    job_id = str(uuid4())
    snapshot = GraphSnapshot(nodes=[Node(id=source, name=source, type=NodeType.BUCKET)])
    with factory() as db:
        db.add(
            IngestionJob(
                id=job_id,
                tenant_id="tenant",
                actor="actor",
                source=source,
                payload=snapshot.model_dump(mode="json"),
            )
        )
        db.commit()
    return job_id


def run_parallel(callables):
    barrier = Barrier(len(callables))

    def run(function):
        barrier.wait(timeout=10)
        return function()

    with ThreadPoolExecutor(max_workers=len(callables)) as pool:
        return list(pool.map(run, callables))


def test_duplicate_workers_claim_exactly_once(postgres_environment):
    factory, _ = postgres_environment
    job_id = enqueue(factory)
    original = tasks.collect
    with patch.object(tasks, "collect", wraps=original) as collect:
        run_parallel([lambda: tasks.process_job(job_id)] * 4)
    assert collect.call_count == 1
    with factory() as db:
        assert db.get(IngestionJob, job_id).attempt_count == 1
        assert db.get(IngestionJob, job_id).status == "completed"
        assert len(list(db.scalars(select(AuditEvent)))) == 1


def test_concurrent_publishers_preserve_both_sources(postgres_environment):
    factory, graph = postgres_environment
    ids = [enqueue(factory, source) for source in ("one", "two")]
    barrier = Barrier(2)

    def collect(source, payload, tenant):
        barrier.wait(timeout=10)
        return GraphSnapshot.model_validate(payload)

    with patch.object(tasks, "collect", side_effect=collect):
        run_parallel([lambda job_id=job_id: tasks.process_job(job_id) for job_id in ids])
    with factory() as db:
        revision = db.get(TenantState, "tenant").revision
        assert {row.source for row in db.scalars(select(SourceSnapshot))} == {"one", "two"}
    assert {n.id for n in graph.snapshot("tenant", revision).nodes} == {"one", "two"}


def test_stale_worker_fenced_after_real_concurrent_reassignment(postgres_environment):
    factory, graph = postgres_environment
    job_id = enqueue(factory)
    started, release = Event(), Event()

    def old_collect(*args):
        started.set()
        assert release.wait(timeout=10)
        return GraphSnapshot(nodes=[Node(id="stale", name="stale", type=NodeType.BUCKET)])

    with ThreadPoolExecutor(max_workers=1) as pool:
        with patch.object(tasks, "collect", side_effect=old_collect):
            future = pool.submit(tasks.process_job, job_id)
            assert started.wait(timeout=10)
            with factory() as db:
                db.get(IngestionJob, job_id).lease_expires_at = now() - timedelta(seconds=1)
                db.commit()
            tasks._recover_expired(now())
            token, _, payload, tenant = tasks._claim_job(job_id)
            tasks._publish_job(job_id, token, tenant, GraphSnapshot.model_validate(payload))
            release.set()
            future.result(timeout=10)
    with factory() as db:
        revision = db.get(TenantState, "tenant").revision
        assert db.get(IngestionJob, job_id).attempt_count == 2
        assert db.get(IngestionJob, job_id).status == "completed"
    assert {n.id for n in graph.snapshot("tenant", revision).nodes} == {"snapshot"}
    assert len(graph.snapshots) == 1


def test_concurrent_dispatchers_publish_each_reservation_once(postgres_environment):
    factory, _ = postgres_environment
    ids = [enqueue(factory) for _ in range(10)]
    with patch.object(tasks.ingest, "delay") as delay:
        counts = run_parallel([tasks.dispatch_pending.run] * 4)
    assert sum(counts) == len(ids)
    assert sorted(call.args[0] for call in delay.call_args_list) == sorted(ids)


def test_broker_failure_does_not_revoke_claimed_worker(postgres_environment):
    factory, _ = postgres_environment
    job_id = enqueue(factory)
    claimed_token = None

    def published_then_broker_failed(delivered_id):
        nonlocal claimed_token
        claimed_token, _, _, _ = tasks._claim_job(delivered_id)
        raise ConnectionError("lost broker acknowledgement")

    with patch.object(tasks.ingest, "delay", side_effect=published_then_broker_failed):
        assert tasks.dispatch_pending.run() == 0
    with factory() as db:
        job = db.get(IngestionJob, job_id)
        assert job.status == "running"
        assert job.lease_token == claimed_token
        assert job.attempt_count == 1


def test_postgres_upgrade_preserves_legacy_outbox(postgres_environment, monkeypatch):
    from pathlib import Path

    from alembic import command
    from alembic.config import Config
    from sqlalchemy import inspect

    import app.db.migrations
    from app.core.config import get_settings

    factory, _ = postgres_environment
    engine = factory.kw["bind"]
    Base.metadata.drop_all(engine)  # Only this test's random schema.
    with engine.connect() as connection:
        schema_name = connection.execute(text("SHOW search_path")).scalar_one()
    url = engine.url.update_query_dict({"options": f"-csearch_path={schema_name}"})
    monkeypatch.setenv("ZG_DATABASE_URL", url.render_as_string(hide_password=False))
    get_settings.cache_clear()
    config = Config()
    config.set_main_option("script_location", str(Path(app.db.migrations.__file__).parent))
    try:
        command.upgrade(config, "0001")
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO ingestion_jobs "
                    "(id,tenant_id,actor,status,source,payload,node_count,created_at,updated_at) "
                    "VALUES ('legacy','tenant','actor','running','snapshot','{}',0,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"
                )
            )
        command.upgrade(config, "head")
        command.upgrade(config, "head")
        with engine.connect() as connection:
            job = connection.execute(text("SELECT * FROM ingestion_jobs WHERE id='legacy'")).mappings().one()
            assert job["attempt_count"] == 0
            assert job["available_at"] == job["updated_at"]
        assert "ix_ingestion_jobs_dispatch" in {
            i["name"] for i in inspect(engine).get_indexes("ingestion_jobs")
        }
        tasks._recover_expired(now())
        assert tasks._claim_job("legacy")
    finally:
        get_settings.cache_clear()


def test_retention_protects_publication_pointer_with_real_tenant_lock(postgres_environment, monkeypatch):
    from datetime import UTC, datetime

    from app.graph import retention

    factory, graph = postgres_environment
    # Old revisions and pointer are synthetic and scoped to this disposable schema.
    for index in range(8):
        graph.publish("tenant", f"old-{index}", GraphSnapshot())
        graph.created_at["tenant", f"old-{index}"] = index + 1
    with factory() as db:
        db.get(TenantState, "tenant").revision = "old-0"
        db.commit()
    monkeypatch.setattr(retention, "session_factory", lambda: factory)
    monkeypatch.setattr(retention, "get_graph_store", lambda: graph)
    deleting, release, published = Event(), Event(), Event()
    original_delete = graph.delete_revision
    original_publish = graph.publish

    def paused_delete(*args):
        deleting.set()
        assert release.wait(timeout=10)
        return original_delete(*args)

    def observed_publish(*args):
        published.set()
        return original_publish(*args)

    job_id = enqueue(factory)
    with (
        patch.object(graph, "delete_revision", side_effect=paused_delete),
        patch.object(graph, "publish", side_effect=observed_publish),
    ):
        with ThreadPoolExecutor(max_workers=2) as pool:
            cleanup = pool.submit(
                retention.prune_revisions,
                "tenant",
                retention.RetentionPolicy(1, 2, 1),
                apply=True,
                timestamp=datetime.now(UTC),
            )
            assert deleting.wait(timeout=10)
            ingestion = pool.submit(tasks.process_job, job_id)
            # Worker can claim/collect, but cannot publish while retention owns
            # the tenant row lock. This bounded wait tests exclusion, not speed.
            assert not published.wait(timeout=0.2)
            release.set()
            result = cleanup.result(timeout=10)
            ingestion.result(timeout=10)
    assert result.deleted == ["old-5"]
    assert ("tenant", "old-0") in graph.snapshots
    with factory() as db:
        state = db.get(TenantState, "tenant")
        assert state.revision not in {"old-5", "old-0"}
        assert graph.snapshot("tenant", state.revision).nodes
        assert db.scalar(select(AuditEvent).where(AuditEvent.action == "graph.revision_deleted"))


def test_retention_missing_or_recent_revisions_are_not_deleted(postgres_environment, monkeypatch):
    from app.graph import retention

    factory, graph = postgres_environment
    monkeypatch.setattr(retention, "session_factory", lambda: factory)
    monkeypatch.setattr(retention, "get_graph_store", lambda: graph)
    for index in range(5):
        graph.publish("tenant", f"new-{index}", GraphSnapshot())
    result = retention.prune_revisions("tenant", retention.RetentionPolicy(1, 2, 2), apply=True)
    assert result.deleted == []
    assert len(graph.snapshots) == 5
    with pytest.raises(ValueError, match="authoritative SQL state"):
        retention.prune_revisions("unknown", apply=True)


def test_retention_intent_survives_graph_commit_and_completion_commit_failure(
    postgres_environment, monkeypatch
):
    from sqlalchemy.orm import Session

    from app.graph import retention

    factory, graph = postgres_environment
    monkeypatch.setattr(retention, "session_factory", lambda: factory)
    monkeypatch.setattr(retention, "get_graph_store", lambda: graph)
    for index in range(5):
        graph.publish("tenant", f"old-{index}", GraphSnapshot())
        graph.created_at["tenant", f"old-{index}"] = index + 1
    original_commit = Session.commit

    def fail_completion(db):
        if any(
            isinstance(event, AuditEvent) and event.action == "graph.revision_deleted" for event in db.new
        ):
            raise RuntimeError("injected completion commit failure")
        return original_commit(db)

    with patch.object(Session, "commit", fail_completion):
        with pytest.raises(RuntimeError, match="completion commit"):
            retention.prune_revisions("tenant", retention.RetentionPolicy(1, 2, 1), apply=True)
    assert ("tenant", "old-2") not in graph.snapshots
    with factory() as db:
        intent = db.scalar(select(AuditEvent).where(AuditEvent.action == "graph.revision_delete_requested"))
        assert intent.detail["revision"] == "old-2"
        assert intent.detail["operation_id"]
        assert db.scalar(select(AuditEvent).where(AuditEvent.action == "graph.revision_deleted")) is None
        assert db.get(TenantState, "tenant").revision == "initial"


def test_retention_refuses_deletion_when_durable_intent_commit_fails(postgres_environment, monkeypatch):
    from sqlalchemy.orm import Session

    from app.graph import retention

    factory, graph = postgres_environment
    monkeypatch.setattr(retention, "session_factory", lambda: factory)
    monkeypatch.setattr(retention, "get_graph_store", lambda: graph)
    for index in range(5):
        graph.publish("tenant", f"old-{index}", GraphSnapshot())
        graph.created_at["tenant", f"old-{index}"] = index + 1
    with (
        patch.object(Session, "commit", side_effect=RuntimeError("intent storage unavailable")),
        patch.object(graph, "delete_revision") as delete,
    ):
        with pytest.raises(RuntimeError, match="intent storage"):
            retention.prune_revisions("tenant", retention.RetentionPolicy(1, 2, 1), apply=True)
    delete.assert_not_called()
    assert len(graph.snapshots) == 5
    with factory() as db:
        assert db.scalar(select(AuditEvent)) is None


def test_api_reader_pin_blocks_publication_and_cleanup_through_paths(postgres_environment, monkeypatch):
    from app.api.routes import load_snapshot
    from app.graph import retention

    factory, graph = postgres_environment
    monkeypatch.setattr(retention, "session_factory", lambda: factory)
    monkeypatch.setattr(retention, "get_graph_store", lambda: graph)
    for index in range(5):
        graph.publish(
            "tenant",
            f"old-{index}",
            GraphSnapshot(nodes=[Node(id="asset", name="asset", type=NodeType.BUCKET)]),
        )
        graph.created_at["tenant", f"old-{index}"] = index + 1
    with factory() as db:
        db.get(TenantState, "tenant").revision = "old-0"
        db.commit()
    snapshot_started, paths_started, release_snapshot, release_paths = Event(), Event(), Event(), Event()
    original_snapshot, original_paths = graph.snapshot, graph.shortest_paths

    def paused_snapshot(tenant, revision):
        if revision == "old-0":
            snapshot_started.set()
            assert release_snapshot.wait(timeout=10)
        return original_snapshot(tenant, revision)

    def paused_paths(*args):
        paths_started.set()
        assert release_paths.wait(timeout=10)
        return original_paths(*args)

    def reader():
        with factory() as db:
            snapshot, revision = load_snapshot(db, graph, "tenant")
            assert revision == "old-0"
            assert len(snapshot.nodes) == 1
            graph.shortest_paths("tenant", revision, "asset", 1, False)
        return revision

    collected = Event()
    original_collect = tasks.collect

    def observed_collect(*args):
        snapshot = original_collect(*args)
        collected.set()
        return snapshot

    job_id = enqueue(factory)
    with (
        patch.object(graph, "snapshot", side_effect=paused_snapshot),
        patch.object(graph, "shortest_paths", side_effect=paused_paths),
        patch.object(tasks, "collect", side_effect=observed_collect),
    ):
        with ThreadPoolExecutor(max_workers=3) as pool:
            read = pool.submit(reader)
            assert snapshot_started.wait(timeout=10)
            publish = pool.submit(tasks.process_job, job_id)
            cleanup = pool.submit(
                retention.prune_revisions, "tenant", retention.RetentionPolicy(1, 2, 3), apply=True
            )
            assert collected.wait(timeout=10)
            assert not publish.done()
            assert not cleanup.done()
            release_snapshot.set()
            assert paths_started.wait(timeout=10)
            with pytest.raises(TimeoutError):
                publish.result(timeout=0.1)
            with pytest.raises(TimeoutError):
                cleanup.result(timeout=0.1)
            assert ("tenant", "old-0") in graph.snapshots
            release_paths.set()
            assert read.result(timeout=10) == "old-0"
            publish.result(timeout=10)
            cleanup.result(timeout=10)
    with factory() as db:
        snapshot, revision = load_snapshot(db, graph, "tenant")
        assert revision != "old-0"
        assert len(snapshot.nodes) == 1


def test_api_pointer_pin_refreshes_stale_identity_map(postgres_environment):
    from app.api.routes import load_snapshot

    factory, graph = postgres_environment
    graph.publish("tenant", "new", GraphSnapshot(nodes=[Node(id="new", name="new", type=NodeType.BUCKET)]))
    with factory() as reader:
        stale = reader.get(TenantState, "tenant")
        assert stale.revision == "initial"
        with factory() as publisher:
            publisher.get(TenantState, "tenant").revision = "new"
            publisher.commit()
        snapshot, revision = load_snapshot(reader, graph, "tenant")
        assert revision == "new"
        assert stale.revision == "new"
        assert snapshot.nodes[0].id == "new"


def test_api_pointer_pin_timeout_returns_sanitized_retry_response(postgres_environment, monkeypatch):
    from fastapi.testclient import TestClient

    from app.api import routes
    from app.core.auth import Actor, current_actor
    from app.db.session import get_db
    from app.graph.repository import get_graph_store
    from app.main import create_app

    factory, graph = postgres_environment
    monkeypatch.setattr(routes, "SNAPSHOT_LOCK_TIMEOUT_MS", 20)

    def reader_db():
        with factory() as db:
            yield db

    app = create_app()
    app.dependency_overrides[get_db] = reader_db
    app.dependency_overrides[get_graph_store] = lambda: graph
    app.dependency_overrides[current_actor] = lambda: Actor("reader", "tenant", frozenset({"viewer"}))
    with factory() as publisher:
        publisher.execute(
            select(TenantState).where(TenantState.tenant_id == "tenant").with_for_update()
        ).scalar_one()
        with TestClient(app) as client:
            response = client.get("/api/v1/graph")
        assert response.status_code == 503
        assert response.headers["retry-after"] == "5"
        assert response.json() == {"detail": "Graph publication or maintenance is busy; retry shortly"}
        assert "SQL" not in response.text
        assert "55P03" not in response.text
    with TestClient(app) as client:
        assert client.get("/api/v1/graph").status_code == 200
