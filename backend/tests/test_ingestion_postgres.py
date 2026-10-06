"""Actual row-lock/CAS races; opt in with a dedicated PostgreSQL test URL.

Every test owns a random schema. No existing tables are modified or removed.
"""

import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier, Event
from unittest.mock import patch
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

from app.collectors import tasks
from app.db.models import (
    AuditEvent,
    Base,
    IngestionJob,
    RevisionAnalysis,
    RevisionCluster,
    RevisionClusterLink,
    RevisionClusterMember,
    RevisionClusterSummary,
    RevisionFinding,
    SourceSnapshot,
    TenantState,
    now,
)
from app.graph.analysis import compute_analysis, store_analysis
from app.graph.clusters import compute_clusters, store_clusters, stored_summary
from app.graph.compact import CompactGraph
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


def exposed():
    """One exposed agent reaching restricted data, so analysis stores findings rows."""
    return GraphSnapshot.model_validate(
        {
            "nodes": [
                {
                    "id": "agent",
                    "name": "agent",
                    "type": "AIAgent",
                    "internet_exposed": True,
                    "authenticated": False,
                },
                {"id": "data", "name": "data", "type": "Database", "sensitivity": "restricted"},
            ],
            "edges": [{"source": "agent", "target": "data", "type": "CAN_READ"}],
        }
    )


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
        # Each serialized publication committed its own analysis with its pointer swap.
        rows = {row.revision: row for row in db.scalars(select(RevisionAnalysis))}
        assert set(rows) == {r for (_, r) in graph.snapshots} and len(rows) == 2
        assert rows[revision].overview["data_assets"] == 2
        assert rows[revision].total_nodes == 2
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
        assert {"revision_analysis", "revision_findings"} <= set(inspect(engine).get_table_names())
        assert "ux_revision_findings_finding" in {
            i["name"] for i in inspect(engine).get_indexes("revision_findings")
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
        graph.publish("tenant", f"old-{index}", exposed())
        graph.created_at["tenant", f"old-{index}"] = index + 1
    with factory() as db:
        for index in range(8):
            store_analysis(db, "tenant", f"old-{index}", compute_analysis(exposed()))
            clustered = compute_clusters(CompactGraph.from_snapshot(exposed()), f"old-{index}")
            store_clusters(db, "tenant", f"old-{index}", clustered)
        store_analysis(db, "other", "old-5", compute_analysis(exposed()))
        store_clusters(db, "other", "old-5", compute_clusters(CompactGraph.from_snapshot(exposed()), "old-5"))
        db.get(TenantState, "tenant").revision = "old-0"
        db.commit()
    monkeypatch.setattr(retention, "session_factory", lambda: factory)
    monkeypatch.setattr(retention, "get_graph_store", lambda: graph)
    deleting, release, published = Event(), Event(), Event()
    original_delete = graph.delete_revision
    original_begin = graph.begin_revision

    def paused_delete(*args):
        deleting.set()
        assert release.wait(timeout=10)
        return original_delete(*args)

    def observed_publish(*args):
        published.set()
        return original_begin(*args)

    job_id = enqueue(factory)
    with (
        patch.object(graph, "delete_revision", side_effect=paused_delete),
        patch.object(graph, "begin_revision", side_effect=observed_publish),
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
            # Worker can claim/collect, but cannot start building while retention
            # owns the tenant publication lock. This bounded wait tests exclusion.
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
        # Analysis rows left with the deleted revision only; the other tenant's
        # same-named revision, retained revisions and the new publication remain.
        analyzed = {(row.tenant_id, row.revision) for row in db.scalars(select(RevisionAnalysis))}
        assert ("tenant", "old-5") not in analyzed
        assert {("other", "old-5"), ("tenant", "old-0"), ("tenant", state.revision)} <= analyzed
        finding_scopes = {(row.tenant_id, row.revision) for row in db.scalars(select(RevisionFinding))}
        assert ("tenant", "old-5") not in finding_scopes and ("other", "old-5") in finding_scopes
        # Cluster rows follow the same lifecycle, in the same locked transaction.
        for model in (RevisionClusterSummary, RevisionCluster, RevisionClusterLink, RevisionClusterMember):
            scopes = {(row.tenant_id, row.revision) for row in db.scalars(select(model))}
            assert ("tenant", "old-5") not in scopes
            if model is not RevisionClusterLink:  # One-cluster revisions have no links.
                assert {("other", "old-5"), ("tenant", "old-0"), ("tenant", state.revision)} <= scopes


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
    with factory() as db:
        store_analysis(db, "tenant", "old-2", compute_analysis(exposed()))
        db.commit()
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
        # The analysis delete rolled back with the completion record. The rows
        # are unreachable (no pointer can name a deleted revision) and a retry
        # of the same revision is skipped, so they are inert, not visible data.
        assert db.get(RevisionAnalysis, ("tenant", "old-2")) is not None


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


def test_api_reader_pin_blocks_only_the_pointer_swap_and_never_its_revision(
    postgres_environment, monkeypatch
):
    """Short-lock contract: a reader's shared pin delays only a publisher's pointer
    swap. The new revision is built while the reader runs, and retention proceeds
    without waiting, but never deletes the pinned (current) revision."""
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
    original_snapshot, original_paths = graph.snapshot, graph.reach
    original_finish = graph.finish_revision
    built = Event()

    def paused_snapshot(tenant, revision):
        if revision == "old-0":
            snapshot_started.set()
            assert release_snapshot.wait(timeout=10)
        return original_snapshot(tenant, revision)

    def paused_paths(*args):
        paths_started.set()
        assert release_paths.wait(timeout=10)
        return original_paths(*args)

    def observed_finish(*args):
        original_finish(*args)
        built.set()

    def reader():
        with factory() as db:
            snapshot, revision = load_snapshot(db, graph, "tenant")
            assert revision == "old-0"
            assert len(snapshot.nodes) == 1
            assert graph.reach("tenant", revision, "asset", 1, False) is not None
        return revision

    job_id = enqueue(factory)
    with (
        patch.object(graph, "snapshot", side_effect=paused_snapshot),
        patch.object(graph, "reach", side_effect=paused_paths),
        patch.object(graph, "finish_revision", side_effect=observed_finish),
    ):
        with ThreadPoolExecutor(max_workers=3) as pool:
            read = pool.submit(reader)
            assert snapshot_started.wait(timeout=10)
            # Retention does not wait for the reader and spares its revision.
            cleanup = pool.submit(
                retention.prune_revisions, "tenant", retention.RetentionPolicy(1, 2, 3), apply=True
            ).result(timeout=10)
            assert "old-0" not in cleanup.deleted and cleanup.deleted
            assert ("tenant", "old-0") in graph.snapshots
            publish = pool.submit(tasks.process_job, job_id)
            # The whole revision is built while the reader holds its pin ...
            assert built.wait(timeout=10)
            release_snapshot.set()
            assert paths_started.wait(timeout=10)
            # ... but the pointer swap waits for the reader's shared lock.
            with pytest.raises(TimeoutError):
                publish.result(timeout=0.2)
            with factory() as db:
                assert db.get(TenantState, "tenant").revision == "old-0"
            release_paths.set()
            assert read.result(timeout=10) == "old-0"
            publish.result(timeout=10)
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
            for path in ("overview", "findings"):
                busy = client.get(f"/api/v1/{path}")
                assert busy.status_code == 503 and busy.headers["retry-after"] == "5"
            response = client.get("/api/v1/graph")
        assert response.status_code == 503
        assert response.headers["retry-after"] == "5"
        assert response.json() == {"detail": "Graph publication or maintenance is busy; retry shortly"}
        assert "SQL" not in response.text
        assert "55P03" not in response.text
    with TestClient(app) as client:
        assert client.get("/api/v1/graph").status_code == 200


def test_stored_analysis_read_under_pointer_pin_blocks_publication(postgres_environment):
    from app.api.routes import pin_revision
    from app.graph.analysis import stored_analysis, stored_findings_page

    factory, graph = postgres_environment
    graph.publish("tenant", "pinned", exposed())
    with factory() as db:
        store_analysis(db, "tenant", "pinned", compute_analysis(exposed()))
        db.get(TenantState, "tenant").revision = "pinned"
        db.commit()
    job_id = enqueue(factory)
    with factory() as reader:
        revision = pin_revision(reader, "tenant")
        row = stored_analysis(reader, "tenant", revision)
        assert revision == "pinned" and row.total_findings == 1
        with ThreadPoolExecutor(max_workers=1) as pool:
            publish = pool.submit(tasks.process_job, job_id)
            # The publisher's pointer swap and analysis insert wait for the reader's share lock.
            with pytest.raises(TimeoutError):
                publish.result(timeout=0.3)
            page, more = stored_findings_page(reader, "tenant", revision, None, 10)
            assert [finding["target"] for finding in page] == ["data"] and not more
            reader.commit()
            publish.result(timeout=10)
    with factory() as db:
        current = db.get(TenantState, "tenant").revision
        assert current != "pinned"
        assert stored_analysis(db, "tenant", current).overview["data_assets"] == 1
        assert stored_analysis(db, "tenant", "pinned").total_findings == 1


def api_client(factory, graph, tenant="tenant", roles=frozenset({"viewer", "analyst", "admin"})):
    from fastapi.testclient import TestClient

    from app.core.auth import Actor, current_actor
    from app.db.session import get_db
    from app.graph.repository import get_graph_store
    from app.main import create_app

    def reader_db():
        with factory() as db:
            yield db

    app = create_app()
    app.dependency_overrides[get_db] = reader_db
    app.dependency_overrides[get_graph_store] = lambda: graph
    app.dependency_overrides[current_actor] = lambda: Actor("actor", tenant, roles)
    return TestClient(app)


def test_readers_and_retention_during_a_long_build(postgres_environment, monkeypatch):
    """Zero read outage while a revision builds; retention fails fast on the lock."""
    from app.api import routes
    from app.graph import retention

    factory, graph = postgres_environment
    graph.publish("tenant", "pinned", exposed())
    with factory() as db:
        store_analysis(db, "tenant", "pinned", compute_analysis(exposed()))
        db.get(TenantState, "tenant").revision = "pinned"
        db.commit()
    monkeypatch.setattr(routes, "SNAPSHOT_LOCK_TIMEOUT_MS", 50)
    monkeypatch.setattr(retention, "session_factory", lambda: factory)
    monkeypatch.setattr(retention, "get_graph_store", lambda: graph)
    monkeypatch.setattr(retention, "LOCK_TIMEOUT", "100ms")
    building, release = Event(), Event()
    original = graph.write_nodes

    def paused(*args, **kwargs):
        building.set()
        assert release.wait(timeout=10)
        return original(*args, **kwargs)

    job_id = enqueue(factory)
    with patch.object(graph, "write_nodes", side_effect=paused), ThreadPoolExecutor(max_workers=1) as pool:
        publish = pool.submit(tasks.process_job, job_id)
        assert building.wait(timeout=10)
        with api_client(factory, graph) as client:
            for path in ("graph/explore", "overview", "findings", "graph/roles", "graph/search?q=a"):
                response = client.get(f"/api/v1/{path}")
                assert response.status_code == 200, (path, response.text)
            assert client.get("/api/v1/graph/explore").json()["revision"] == "pinned"
        with pytest.raises(ValueError, match="in progress"):
            retention.prune_revisions("tenant", retention.RetentionPolicy(1, 2, 1), apply=True)
        release.set()
        publish.result(timeout=10)
    with factory() as db:
        assert db.get(TenantState, "tenant").revision != "pinned"


def test_chunked_upload_and_sql_conflict_detection_on_postgres(postgres_environment):
    import json

    factory, graph = postgres_environment
    snapshot = exposed()
    lines = [json.dumps({"node": n.model_dump(mode="json")}) for n in snapshot.nodes]
    lines += [json.dumps({"edge": e.model_dump(mode="json")}) for e in snapshot.edges]
    with api_client(factory, graph) as client, patch("app.api.routes.ingest.delay"):
        upload_id = client.post("/api/v1/ingestions/uploads", json={}).json()["id"]
        assert (
            client.put(f"/api/v1/ingestions/uploads/{upload_id}/chunks/0", content=lines[0]).status_code
            == 200
        )
        duplicate = client.put(f"/api/v1/ingestions/uploads/{upload_id}/chunks/1", content=lines[0])
        assert duplicate.status_code == 422
        body = "\n".join(lines[1:]).encode()
        assert client.put(f"/api/v1/ingestions/uploads/{upload_id}/chunks/1", content=body).status_code == 200
        job = client.post(f"/api/v1/ingestions/uploads/{upload_id}/commit").json()
    tasks.process_job(job["id"])
    with factory() as db:
        revision = db.get(TenantState, "tenant").revision
        assert db.get(RevisionAnalysis, ("tenant", revision)).total_findings == 1
    assert {n.id for n in graph.snapshot("tenant", revision).nodes} == {"agent", "data"}
    conflicting = GraphSnapshot(nodes=[Node(id="data", name="other", type=NodeType.DATABASE)])
    job_id = str(uuid4())
    with factory() as db:
        db.add(
            IngestionJob(
                id=job_id,
                tenant_id="tenant",
                actor="a",
                source="other",
                payload=conflicting.model_dump(mode="json"),
            )
        )
        db.commit()
    with (
        patch.object(tasks, "collect", return_value=conflicting),
        pytest.raises(ValueError, match="Conflicting"),
    ):
        tasks.process_job(job_id)
    with factory() as db:
        assert db.get(TenantState, "tenant").revision == revision


def test_abandoned_build_is_invisible_and_cleaned_once_stale(postgres_environment, monkeypatch):
    from datetime import UTC, datetime

    from app.graph import retention

    factory, graph = postgres_environment
    monkeypatch.setattr(retention, "session_factory", lambda: factory)
    monkeypatch.setattr(retention, "get_graph_store", lambda: graph)
    job_id = enqueue(factory)
    with patch.object(graph, "write_edges", side_effect=RuntimeError("worker died")):
        with patch.object(graph, "finish_revision", side_effect=RuntimeError("worker died")):
            with pytest.raises(RuntimeError):
                tasks.process_job(job_id)
    (abandoned,) = list(graph.building)
    with factory() as db:
        assert db.get(TenantState, "tenant").revision == "initial"
    timestamp = datetime.now(UTC)
    young = retention.prune_revisions(
        "tenant", retention.RetentionPolicy(1, 2, 5), apply=True, timestamp=timestamp
    )
    assert young.deleted == [] and abandoned in graph.building
    later = timestamp + retention.STALE_BUILDING_AGE + timedelta(minutes=1)
    stale = retention.prune_revisions(
        "tenant", retention.RetentionPolicy(1, 2, 5), apply=True, timestamp=later
    )
    assert stale.deleted == [abandoned[1]] and not graph.building


def test_new_readers_queue_behind_a_waiting_pointer_swap(postgres_environment, monkeypatch):
    """Overlapping shared pins cannot starve publication: once the swap waits, a new
    reader waits behind it and then reads the new revision."""
    from app.api import routes
    from app.api.routes import pin_revision

    factory, graph = postgres_environment
    monkeypatch.setattr(routes, "SNAPSHOT_LOCK_TIMEOUT_MS", 10_000)
    built = Event()
    original_finish = graph.finish_revision

    def observed_finish(*args):
        original_finish(*args)
        built.set()

    job_id = enqueue(factory)
    with factory() as first, patch.object(graph, "finish_revision", side_effect=observed_finish):
        assert pin_revision(first, "tenant") == "initial"
        with ThreadPoolExecutor(max_workers=2) as pool:
            publish = pool.submit(tasks.process_job, job_id)
            try:
                assert built.wait(timeout=10)
                # Wait until the swap is actually queued on the gate.
                with factory() as probe:
                    for _ in range(200):
                        waiting = probe.scalar(
                            text("SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted")
                        )
                        if waiting:
                            break
                        time.sleep(0.01)
                assert waiting

                def second_reader():
                    with factory() as db:
                        return pin_revision(db, "tenant")

                second = pool.submit(second_reader)
                with pytest.raises(TimeoutError):
                    second.result(timeout=0.3)  # Queued behind the swap, not joining the old pin.
            finally:
                first.commit()  # Never leave the publisher blocked if an assertion failed.
            publish.result(timeout=10)
            new = second.result(timeout=10)
    with factory() as db:
        assert new == db.get(TenantState, "tenant").revision != "initial"


def test_publication_copies_cluster_rows_and_warm_starts_from_the_previous_revision(postgres_environment):
    factory, graph = postgres_environment
    nodes = [Node(id=f"svc:{i}", name=f"svc {i}", type=NodeType.SERVICE) for i in range(30)]
    nodes += [Node(id=f"role:{i}", name=f"role {i}", type=NodeType.ROLE) for i in range(3)]
    edges = [{"source": f"svc:{i}", "target": f"role:{i % 3}", "type": "ASSUMES_ROLE"} for i in range(30)]
    payload = {"nodes": [n.model_dump(mode="json") for n in nodes], "edges": edges}
    revisions = []
    for _ in range(2):
        job_id = str(uuid4())
        with factory() as db:
            db.add(IngestionJob(id=job_id, tenant_id="tenant", actor="a", source="snapshot", payload=payload))
            db.commit()
        tasks.process_job(job_id)
        with factory() as db:
            revisions.append(db.get(TenantState, "tenant").revision)
    with factory() as db:
        first, second = (stored_summary(db, "tenant", revision) for revision in revisions)
        assert first.previous_revision == "initial" or first.previous_revision is None
        assert second.previous_revision == revisions[0] and second.reused_ids == second.total_clusters
        members = db.scalars(
            select(RevisionClusterMember).where(RevisionClusterMember.revision == revisions[1])
        ).all()
        assert len(members) == 33
        hubs = sorted(m.entity_id for m in members if m.ordinal == 0)
        assert hubs == ["role:0", "role:1", "role:2"]
        clusters = db.scalars(select(RevisionCluster).where(RevisionCluster.revision == revisions[1])).all()
        assert all(isinstance(row.types, dict) for row in clusters)
        assert {row.label for row in clusters} == {"role 0", "role 1", "role 2"}
        ids = [
            {
                row.cluster_id
                for row in db.scalars(select(RevisionCluster).where(RevisionCluster.revision == r))
            }
            for r in revisions
        ]
        assert ids[0] == ids[1]


def test_worker_cluster_backfill_skips_a_publishing_tenant_then_fills_it(postgres_environment, monkeypatch):
    factory, graph = postgres_environment
    from app.db.locks import acquire_publication_lock
    from app.graph import clusters

    graph.publish("tenant", "initial", exposed())
    monkeypatch.setattr(clusters, "session_factory", lambda: factory)
    monkeypatch.setattr(clusters, "get_graph_store", lambda: graph)
    monkeypatch.setattr(clusters, "_failed", {})
    with factory() as publisher:
        acquire_publication_lock(publisher, "tenant")  # A publication in progress.
        started = time.perf_counter()
        assert clusters.backfill_missing() == [{"tenant": "tenant", "backfilled": False, "busy": True}]
        assert time.perf_counter() - started < 2  # Skipped, not queued behind the publisher.
        publisher.rollback()
    with factory() as db:
        assert stored_summary(db, "tenant", "initial") is None
    assert [r["backfilled"] for r in clusters.backfill_missing()] == [True]
    with factory() as db:
        assert stored_summary(db, "tenant", "initial").total_nodes == len(exposed().nodes)


def test_worker_sample_refresh_skips_a_publishing_tenant_then_refreshes_it(postgres_environment, monkeypatch):
    factory, graph = postgres_environment
    from app.db.locks import acquire_publication_lock
    from app.graph import analysis
    from app.graph.sample import SAMPLE_VERSION

    snapshot = exposed()
    graph.publish("tenant", "initial", snapshot)
    expected = compute_analysis(snapshot)
    with factory() as db:
        store_analysis(db, "tenant", "initial", expected)
        db.flush()
        row = db.get(RevisionAnalysis, ("tenant", "initial"))
        row.sample_ids, row.sample_version = sorted(row.sample_ids)[:2], None
        db.commit()
    monkeypatch.setattr(analysis, "session_factory", lambda: factory)
    monkeypatch.setattr(analysis, "get_graph_store", lambda: graph)
    monkeypatch.setattr(analysis, "_failed", {})
    with factory() as db:
        assert analysis.stale_samples(db, 10) == [("tenant", "initial")]
    with factory() as publisher:
        acquire_publication_lock(publisher, "tenant")  # A publication in progress.
        started = time.perf_counter()
        assert analysis.backfill_stale_samples() == [{"tenant": "tenant", "backfilled": False, "busy": True}]
        assert time.perf_counter() - started < 2  # Skipped, not queued behind the publisher.
        publisher.rollback()
    with factory() as db:
        assert db.get(RevisionAnalysis, ("tenant", "initial")).sample_version is None
    assert [r["backfilled"] for r in analysis.backfill_stale_samples()] == [True]
    with factory() as db:
        row = db.get(RevisionAnalysis, ("tenant", "initial"))
        assert (row.sample_ids, row.sample_version) == (expected.sample_ids, SAMPLE_VERSION)
        assert analysis.stale_samples(db, 10) == []
    assert analysis.backfill_stale_samples() == []
