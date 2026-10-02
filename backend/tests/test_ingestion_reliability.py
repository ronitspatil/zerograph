from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.collectors import tasks
from app.db.models import AuditEvent, IngestionJob, SourceSnapshot, TenantState, now
from app.graph.schema import GraphSnapshot, Node, NodeType


def enqueue(factory, *, source="snapshot", snapshot=None, created_at=None, tenant="tenant-a"):
    job_id = str(uuid4())
    with factory() as db:
        db.add(
            IngestionJob(
                id=job_id,
                tenant_id=tenant,
                actor="alice",
                source=source,
                payload=(snapshot or GraphSnapshot()).model_dump(mode="json"),
                created_at=created_at or now(),
            )
        )
        db.commit()
    return job_id


def asset(name):
    return GraphSnapshot(nodes=[Node(id=name, name=name, type=NodeType.BUCKET)])


def test_duplicate_delivery_claims_only_once(environment):
    factory, _ = environment
    job_id = enqueue(factory)
    with patch.object(tasks, "collect", return_value=GraphSnapshot()) as collect:
        tasks.process_job(job_id)
        tasks.process_job(job_id)
    assert collect.call_count == 1
    with factory() as db:
        assert db.get(IngestionJob, job_id).attempt_count == 1
        assert len(list(db.scalars(select(AuditEvent)))) == 1


def test_stale_worker_cannot_publish_or_change_new_owner(environment):
    factory, graph = environment
    job_id = enqueue(factory)
    old_token, _, _, tenant = tasks._claim_job(job_id)
    with factory() as db:
        db.get(IngestionJob, job_id).lease_expires_at = now() - timedelta(seconds=1)
        db.commit()
    tasks._recover_expired(now())
    new_token, _, _, _ = tasks._claim_job(job_id)
    tasks._publish_job(job_id, old_token, tenant, asset("stale"))
    tasks._record_failure(job_id, old_token)
    with factory() as db:
        job = db.get(IngestionJob, job_id)
        assert job.lease_token == new_token
        assert job.status == "running"
        assert db.get(TenantState, tenant).revision == "revision-a"
        assert db.get(SourceSnapshot, (tenant, "snapshot")) is None
    assert len(graph.snapshots) == 1
    tasks._publish_job(job_id, new_token, tenant, asset("new"))
    with factory() as db:
        assert db.get(IngestionJob, job_id).status == "completed"


def test_expired_lease_cannot_publish_even_before_recovery(environment):
    factory, graph = environment
    job_id = enqueue(factory)
    token, _, _, tenant = tasks._claim_job(job_id)
    with factory() as db:
        db.get(IngestionJob, job_id).lease_expires_at = now() - timedelta(seconds=1)
        db.commit()
    tasks._publish_job(job_id, token, tenant, asset("stale"))
    assert len(graph.snapshots) == 1


def test_database_retry_budget_survives_fresh_deliveries(environment):
    factory, _ = environment
    job_id = enqueue(factory)
    with patch.object(tasks, "collect", side_effect=RuntimeError("SECRET")) as collect:
        for attempt in range(tasks.MAX_ATTEMPTS):
            tasks.ingest.run(job_id)
            with factory() as db:
                job = db.get(IngestionJob, job_id)
                assert job.attempt_count == attempt + 1
                assert job.status == ("failed" if attempt == tasks.MAX_ATTEMPTS - 1 else "retrying")
                assert "SECRET" not in job.error
                assert job.lease_token is None
                job.available_at = now() - timedelta(seconds=1)
                db.commit()
        tasks.ingest.run(job_id)
    assert collect.call_count == tasks.MAX_ATTEMPTS


def test_retry_is_not_claimed_or_dispatched_before_due(environment):
    factory, _ = environment
    job_id = enqueue(factory)
    with factory() as db:
        job = db.get(IngestionJob, job_id)
        job.status = "retrying"
        job.available_at = now() + timedelta(hours=1)
        db.commit()
    assert tasks._claim_job(job_id) is None
    with patch.object(tasks.ingest, "delay") as publish:
        assert tasks.dispatch_pending.run() == 0
    publish.assert_not_called()


def test_killed_workers_eventually_exhaust_budget(environment):
    factory, _ = environment
    job_id = enqueue(factory)
    for _ in range(tasks.MAX_ATTEMPTS):
        assert tasks._claim_job(job_id)
        with factory() as db:
            db.get(IngestionJob, job_id).lease_expires_at = now() - timedelta(seconds=1)
            db.commit()
        tasks._recover_expired(now())
    assert tasks._claim_job(job_id) is None
    with factory() as db:
        assert db.get(IngestionJob, job_id).status == "failed"


def test_outbox_reservation_prevents_repeated_publication_and_recovers_crash(environment):
    factory, _ = environment
    job_id = enqueue(factory)
    with patch.object(tasks.ingest, "delay") as publish:
        assert tasks.dispatch_pending.run() == 1
        assert tasks.dispatch_pending.run() == 0
        with factory() as db:
            db.get(IngestionJob, job_id).dispatched_at = now() - tasks.DISPATCH_RESERVATION
            db.commit()
        assert tasks.dispatch_pending.run() == 1
    assert publish.call_count == 2


def test_one_broker_failure_does_not_starve_remaining_jobs(environment):
    factory, _ = environment
    ids = [enqueue(factory), enqueue(factory)]
    with patch.object(tasks.ingest, "delay", side_effect=[ConnectionError("secret"), None]) as publish:
        assert tasks.dispatch_pending.run() == 1
    failed_id = publish.call_args_list[0].args[0]
    with factory() as db:
        assert db.get(IngestionJob, failed_id).dispatched_at is None
        assert db.get(IngestionJob, ids[0]).attempt_count == 0
    with patch.object(tasks.ingest, "delay") as publish:
        assert tasks.dispatch_pending.run() == 1
    publish.assert_called_once_with(failed_id)


def test_dispatch_sweep_is_bounded(environment):
    factory, _ = environment
    for _ in range(105):
        enqueue(factory)
    with patch.object(tasks.ingest, "delay") as publish:
        assert tasks.dispatch_pending.run() == 100
        assert tasks.dispatch_pending.run() == 5
    assert publish.call_count == 105


def test_older_source_collection_cannot_overwrite_newer_snapshot(environment):
    factory, graph = environment
    old_id = enqueue(factory, snapshot=asset("old"), created_at=now() - timedelta(hours=1))
    new_id = enqueue(factory, snapshot=asset("new"))
    tasks.process_job(new_id)
    with factory() as db:
        revision = db.get(TenantState, "tenant-a").revision
    tasks.process_job(old_id)
    with factory() as db:
        assert db.get(TenantState, "tenant-a").revision == revision
        assert db.get(IngestionJob, old_id).status == "completed"
        assert db.get(SourceSnapshot, ("tenant-a", "snapshot")).job_id == new_id
        assert db.scalar(select(AuditEvent).where(AuditEvent.action == "ingestion.superseded"))
    assert [n.id for n in graph.snapshot("tenant-a", revision).nodes] == ["new"]


def test_graph_failure_rolls_back_sources_but_records_retry(environment):
    factory, graph = environment
    job_id = enqueue(factory, snapshot=asset("new"))
    with patch.object(graph, "publish", side_effect=RuntimeError("unavailable")):
        with pytest.raises(RuntimeError):
            tasks.process_job(job_id)
    with factory() as db:
        assert db.get(TenantState, "tenant-a").revision == "revision-a"
        assert db.get(SourceSnapshot, ("tenant-a", "snapshot")) is None
        assert db.get(IngestionJob, job_id).status == "retrying"


def test_legacy_running_job_without_lease_is_recovered(environment):
    factory, _ = environment
    job_id = enqueue(factory)
    with factory() as db:
        db.get(IngestionJob, job_id).status = "running"
        db.commit()
    tasks._recover_expired(now())
    assert tasks._claim_job(job_id)


def test_graph_commit_then_sql_failure_keeps_old_pointer(environment):
    from sqlalchemy.orm import Session

    factory, graph = environment
    job_id = enqueue(factory, snapshot=asset("new"))
    original_commit = Session.commit
    failed = False

    def fail_publication_commit(db):
        nonlocal failed
        completing = any(isinstance(row, IngestionJob) and row.status == "completed" for row in db.dirty)
        if completing and not failed:
            failed = True
            raise RuntimeError("SQL unavailable after graph commit")
        return original_commit(db)

    with patch.object(Session, "commit", fail_publication_commit):
        with pytest.raises(RuntimeError):
            tasks.process_job(job_id)
    with factory() as db:
        assert db.get(TenantState, "tenant-a").revision == "revision-a"
        assert db.get(SourceSnapshot, ("tenant-a", "snapshot")) is None
        job = db.get(IngestionJob, job_id)
        assert job.status == "retrying"
        job.available_at = now() - timedelta(seconds=1)
        db.commit()
    assert len(graph.snapshots) == 2  # Unreferenced graph revision is retained.
    tasks.process_job(job_id)
    with factory() as db:
        assert db.get(IngestionJob, job_id).status == "completed"
        revision = db.get(TenantState, "tenant-a").revision
    assert [n.id for n in graph.snapshot("tenant-a", revision).nodes] == ["new"]
    assert len(graph.snapshots) == 3


def test_conflicting_edges_do_not_silently_replace_other_source(environment):
    from app.graph.schema import Edge, EdgeType

    factory, graph = environment
    snapshot = GraphSnapshot(
        nodes=asset("one").nodes + asset("two").nodes,
        edges=[Edge(source="one", target="two", type=EdgeType.READ, evidence=["source-one"])],
    )
    first_id = enqueue(factory)
    with patch.object(tasks, "collect", return_value=snapshot):
        tasks.process_job(first_id)
    snapshot.edges[0] = snapshot.edges[0].model_copy(update={"evidence": ["source-two"]})
    second_id = enqueue(factory, source="mcp")
    with patch.object(tasks, "collect", return_value=snapshot):
        with pytest.raises(ValueError, match="Conflicting edge"):
            tasks.process_job(second_id)
    with factory() as db:
        revision = db.get(TenantState, "tenant-a").revision
        assert db.get(SourceSnapshot, ("tenant-a", "mcp")) is None
        assert db.get(IngestionJob, second_id).status == "retrying"
    assert graph.snapshot("tenant-a", revision).edges[0].type == EdgeType.READ
