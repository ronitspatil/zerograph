"""Chunked upload sessions, SQL staging and row-based multi-source publication."""

import json
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

import pytest
from sqlalchemy import func, select

from app.collectors import tasks
from app.collectors.data_classifier import classification_edges
from app.core.auth import Actor, current_actor
from app.core.config import get_settings
from app.db.models import (
    AuditEvent,
    IngestionJob,
    RevisionAnalysis,
    SourceSnapshot,
    StagedEntity,
    TenantState,
    UploadSession,
    now,
)
from app.graph.analysis import compute_analysis, stored_analysis
from app.graph.demo import demo_snapshot
from app.graph.schema import Edge, EdgeType, GraphSnapshot, Node, NodeType

DELAY = "app.api.routes.ingest.delay"


def ndjson(snapshot: GraphSnapshot, nodes=True, edges=True, warnings=True) -> bytes:
    lines = []
    if nodes:
        lines += [json.dumps({"node": n.model_dump(mode="json")}) for n in snapshot.nodes]
    if edges:
        lines += [json.dumps({"edge": e.model_dump(mode="json")}) for e in snapshot.edges]
    if warnings:
        lines += [json.dumps({"warning": w}) for w in snapshot.warnings]
    return ("\n".join(lines) + "\n").encode()


def start(client) -> str:
    response = client.post("/api/v1/ingestions/uploads", json={"source": "snapshot"})
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "open" and body["max_nodes"] == get_settings().max_nodes
    return body["id"]


def put(client, upload_id, chunk, body):
    return client.put(f"/api/v1/ingestions/uploads/{upload_id}/chunks/{chunk}", content=body)


def upload(client, snapshot: GraphSnapshot) -> dict:
    upload_id = start(client)
    assert put(client, upload_id, 0, ndjson(snapshot, edges=False, warnings=False)).status_code == 200
    staged = put(client, upload_id, 1, ndjson(snapshot, nodes=False))
    assert staged.status_code == 200, staged.text
    assert (staged.json()["node_count"], staged.json()["edge_count"]) == (
        len(snapshot.nodes),
        len(snapshot.edges),
    )
    with patch(DELAY):
        committed = client.post(f"/api/v1/ingestions/uploads/{upload_id}/commit")
    assert committed.status_code == 202, committed.text
    return {"upload_id": upload_id, **committed.json()}


def canonical(snapshot: GraphSnapshot) -> tuple:
    return (
        sorted(json.dumps(n.model_dump(mode="json"), sort_keys=True) for n in snapshot.nodes),
        sorted(json.dumps({**e.model_dump(mode="json"), "id": e.id}, sort_keys=True) for e in snapshot.edges),
        list(snapshot.warnings),
    )


def current(factory) -> str:
    with factory() as db:
        return db.get(TenantState, "tenant-a").revision


def test_chunked_upload_publishes_the_same_revision_and_analysis_as_inline(client, environment):
    factory, graph = environment
    snapshot = demo_snapshot()
    job = upload(client, snapshot)
    assert job["source"] == "snapshot" and job["status"] == "queued"
    tasks.process_job(job["id"])
    revision = current(factory)
    published = graph.snapshot("tenant-a", revision)
    # Same merge + classification semantics as the former in-memory publication.
    expected = GraphSnapshot.model_validate(classification_edges(snapshot).model_dump())
    assert canonical(published) == canonical(expected)
    with factory() as db:
        stored = stored_analysis(db, "tenant-a", revision)
        reference = compute_analysis(expected)
        assert stored.overview == reference.overview
        assert stored.total_findings == len(reference.findings)
        assert stored.high_blast_ids == reference.high_blast_ids
        upload_row = db.get(UploadSession, job["upload_id"])
        assert upload_row.status == "active"
        assert db.get(SourceSnapshot, ("tenant-a", "snapshot")).payload == {"entity_set": job["upload_id"]}
        assert db.get(IngestionJob, job["id"]).node_count == len(expected.nodes)
    # Republishing an inline snapshot of the same source replaces (and deletes) the staged set.
    with patch(DELAY):
        inline = client.post(
            "/api/v1/ingestions", json={"source": "snapshot", "payload": snapshot.model_dump(mode="json")}
        ).json()
    tasks.process_job(inline["id"])
    assert canonical(graph.snapshot("tenant-a", current(factory))) == canonical(expected)
    with factory() as db:
        assert db.get(UploadSession, job["upload_id"]) is None
        sets = set(db.scalars(select(StagedEntity.session_id).distinct()))
        assert sets == {db.get(SourceSnapshot, ("tenant-a", "snapshot")).payload["entity_set"]}


def test_chunk_retry_replaces_the_chunk(client, environment):
    snapshot = demo_snapshot()
    upload_id = start(client)
    for _ in range(2):
        response = put(client, upload_id, 3, ndjson(snapshot, edges=False))
        assert response.status_code == 200
        assert response.json()["node_count"] == len(snapshot.nodes)
    smaller = GraphSnapshot(nodes=snapshot.nodes[:2])
    assert put(client, upload_id, 3, ndjson(smaller)).json()["node_count"] == 2


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (b"not json\n", "Line 1: invalid JSON"),
        (b'{"node": {"id": "a"}}\n', "Line 1: invalid node"),
        (b'{"vertex": {}}\n', "Line 1: expected exactly one of node, edge, policy, reference or warning"),
        (b'{"node": {}, "edge": {}}\n', "Line 1: expected exactly one"),
        (b'\n{"warning": 5}\n', "Line 2: invalid warning"),
        (
            b'{"node": {"id": "a", "name": "a", "type": "S3Bucket"}}\n'
            b'{"node": {"id": "a", "name": "b", "type": "S3Bucket"}}\n',
            "Line 2: Node IDs must be unique within a snapshot",
        ),
        (
            b'{"edge": {"source": "a", "target": "b", "type": "CAN_READ"}}\n'
            b'{"edge": {"source": "a", "target": "b", "type": "CAN_READ"}}\n',
            "Line 2: Duplicate graph edges",
        ),
        (b"\xff\n", "Chunk must be UTF-8 NDJSON"),
    ],
)
def test_invalid_chunks_are_refused_without_staging(client, environment, body, message):
    factory, _ = environment
    upload_id = start(client)
    response = put(client, upload_id, 0, body)
    assert response.status_code == 422
    assert response.json()["detail"].startswith(message)
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(StagedEntity)) == 0


def test_cross_chunk_duplicates_and_dangling_edges_are_refused(client, environment):
    factory, _ = environment
    snapshot = demo_snapshot()
    upload_id = start(client)
    assert put(client, upload_id, 0, ndjson(snapshot, edges=False)).status_code == 200
    duplicate = put(client, upload_id, 1, ndjson(GraphSnapshot(nodes=snapshot.nodes[:1])))
    assert duplicate.status_code == 422
    assert "already staged" in duplicate.json()["detail"]
    dangling = Edge(source=snapshot.nodes[0].id, target="missing", type=EdgeType.READ)
    assert (
        put(
            client,
            upload_id,
            1,
            ndjson(GraphSnapshot.model_construct(nodes=[], edges=[dangling], warnings=[])),
        ).status_code
        == 200
    )
    with patch(DELAY) as delay:
        refused = client.post(f"/api/v1/ingestions/uploads/{upload_id}/commit")
    assert refused.status_code == 422
    assert refused.json()["detail"] == (
        "Every edge endpoint must be a node or reference, and every policy principal a node, of this snapshot"
    )
    delay.assert_not_called()
    # The session stays open: the client can replace the bad chunk and commit.
    assert put(client, upload_id, 1, ndjson(snapshot, nodes=False)).status_code == 200
    with patch(DELAY):
        assert client.post(f"/api/v1/ingestions/uploads/{upload_id}/commit").status_code == 202
    assert put(client, upload_id, 2, b"").status_code == 409
    with patch(DELAY):
        assert client.post(f"/api/v1/ingestions/uploads/{upload_id}/commit").status_code == 409
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(IngestionJob)) == 1
        assert db.scalar(select(AuditEvent).where(AuditEvent.action == "ingestion.upload_started"))


def test_caps_come_from_settings(client, environment, monkeypatch):
    monkeypatch.setenv("ZG_MAX_NODES", "3")
    monkeypatch.setenv("ZG_MAX_EDGES", "2")
    get_settings.cache_clear()
    snapshot = demo_snapshot()
    upload_id = start(client)
    assert put(client, upload_id, 0, ndjson(GraphSnapshot(nodes=snapshot.nodes[:3]))).status_code == 200
    over = put(client, upload_id, 1, ndjson(GraphSnapshot(nodes=snapshot.nodes[3:4])))
    assert over.status_code == 413
    inline = client.post(
        "/api/v1/ingestions", json={"source": "snapshot", "payload": snapshot.model_dump(mode="json")}
    )
    assert inline.status_code == 413
    # Pydantic no longer caps list sizes; Settings do.
    big = [Node(id=f"n{i}", name="n", type=NodeType.BUCKET) for i in range(6000)]
    assert len(GraphSnapshot(nodes=big).nodes) == 6000


def test_merged_revision_over_cap_fails_before_any_graph_write(environment, monkeypatch):
    factory, graph = environment
    monkeypatch.setenv("ZG_MAX_NODES", "3")
    get_settings.cache_clear()
    job_id = enqueue(factory, "one", GraphSnapshot(nodes=demo_snapshot().nodes[:2]))
    other = enqueue(factory, "two", GraphSnapshot(nodes=demo_snapshot().nodes[2:4]))
    run(job_id, GraphSnapshot(nodes=demo_snapshot().nodes[:2]))
    with patch.object(graph, "begin_revision") as begin, pytest.raises(ValueError, match="node limit"):
        run(other, GraphSnapshot(nodes=demo_snapshot().nodes[2:4]))
    begin.assert_not_called()


def test_upload_sessions_are_tenant_scoped_bounded_and_expire(client, environment, monkeypatch):
    factory, _ = environment
    upload_id = start(client)
    client.app.dependency_overrides[current_actor] = lambda: Actor(
        "mallory", "tenant-b", frozenset({"admin", "analyst", "viewer"})
    )
    assert put(client, upload_id, 0, b"").status_code == 404
    assert client.post(f"/api/v1/ingestions/uploads/{upload_id}/commit").status_code == 404
    client.app.dependency_overrides[current_actor] = lambda: Actor(
        "alice", "tenant-a", frozenset({"admin", "analyst", "viewer"})
    )
    for _ in range(get_settings().max_open_uploads - 1):
        start(client)
    busy = client.post("/api/v1/ingestions/uploads", json={})
    assert busy.status_code == 429
    with factory() as db:
        for row in db.scalars(select(UploadSession)):
            row.expires_at = now() - timedelta(seconds=1)
        db.commit()
    assert put(client, upload_id, 0, b"").status_code == 410
    # Expired sessions are purged when the next upload starts.
    start(client)
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(UploadSession)) == 1
    client.app.dependency_overrides[current_actor] = lambda: Actor(
        "viewer", "tenant-a", frozenset({"viewer"})
    )
    assert client.post("/api/v1/ingestions/uploads", json={}).status_code == 403


def enqueue(factory, source, snapshot, created_at=None, tenant="tenant-a"):
    job_id = str(uuid4())
    with factory() as db:
        db.add(
            IngestionJob(
                id=job_id,
                tenant_id=tenant,
                actor="alice",
                source=source,
                payload=snapshot.model_dump(mode="json"),
                created_at=created_at or now(),
            )
        )
        db.commit()
    return job_id


def run(job_id, snapshot):
    with patch.object(tasks, "collect", return_value=snapshot):
        tasks.process_job(job_id)


def publish(factory, source, snapshot):
    job_id = enqueue(factory, source, snapshot)
    run(job_id, snapshot)
    return job_id


def test_identical_duplicates_merge_and_conflicts_fail_in_sql(environment):
    factory, graph = environment
    shared = Node(id="shared", name="Shared", type=NodeType.DATABASE, metadata={"a": 1, "b": 2})
    one = GraphSnapshot(nodes=[shared, Node(id="x", name="x", type=NodeType.ROLE)], warnings=["one"])
    # Same node with differently ordered metadata keys is the same definition.
    reordered = Node.model_validate({**shared.model_dump(mode="json"), "metadata": {"b": 2, "a": 1}})
    two = GraphSnapshot(
        nodes=[Node(id="y", name="y", type=NodeType.SERVICE), reordered],
        edges=[Edge(source="y", target="shared", type=EdgeType.READ)],
        warnings=["two"],
    )
    publish(factory, "one", one)
    publish(factory, "two", two)
    merged = graph.snapshot("tenant-a", current(factory))
    assert [n.id for n in merged.nodes] == ["shared", "x", "y"]
    assert merged.warnings == ["one", "two"] and merged.source == "combined"
    before = current(factory)
    conflicting = GraphSnapshot(nodes=[Node(id="shared", name="Renamed", type=NodeType.DATABASE)])
    job_id = enqueue(factory, "three", conflicting)
    with pytest.raises(ValueError, match="Conflicting node definitions"):
        run(job_id, conflicting)
    with factory() as db:
        assert db.get(TenantState, "tenant-a").revision == before
        assert db.get(SourceSnapshot, ("tenant-a", "three")) is None
        assert db.get(IngestionJob, job_id).status == "retrying"
    edge_conflict = GraphSnapshot(
        nodes=[reordered, Node(id="y", name="y", type=NodeType.SERVICE)],
        edges=[Edge(source="y", target="shared", type=EdgeType.READ, evidence=["different"])],
    )
    with pytest.raises(ValueError, match="Conflicting edge definitions"):
        run(enqueue(factory, "four", edge_conflict), edge_conflict)


def test_classification_matches_the_former_merge_including_overrides(environment):
    factory, graph = environment
    first = GraphSnapshot(
        nodes=[
            Node(id="db:1", name="db1", type=NodeType.DATABASE, tags=["PII", "PCI"], sensitivity="internal"),
            Node(id="classification:PII", name="custom", type=NodeType.CATEGORY),
            Node(id="classification:Other", name="kept", type=NodeType.CATEGORY),
            Node(id="svc", name="svc", type=NodeType.SERVICE),
        ],
        edges=[
            Edge(source="svc", target="db:1", type=EdgeType.READ),
            # Same ID as a generated annotation: replaced in place.
            Edge(source="db:1", target="classification:PII", type=EdgeType.PII, certainty="declared"),
        ],
    )
    second = GraphSnapshot(
        nodes=[Node(id="db:2", name="db2", type=NodeType.BUCKET, tags=["PII"], sensitivity="restricted")],
    )
    publish(factory, "a", first)
    publish(factory, "b", second)
    published = graph.snapshot("tenant-a", current(factory))
    combined = GraphSnapshot(
        nodes=first.nodes + second.nodes, edges=first.edges + second.edges, source="combined"
    )
    expected = GraphSnapshot.model_validate(classification_edges(combined).model_dump())
    assert canonical(published) == canonical(expected)
    category = next(n for n in published.nodes if n.id == "classification:PII")
    assert category.sensitivity == "restricted" and category.provider == "classification"
    with factory() as db:
        stored = db.get(RevisionAnalysis, ("tenant-a", current(factory)))
        assert stored.overview == compute_analysis(expected).overview


def test_legacy_source_documents_are_staged_on_next_publication(environment):
    factory, graph = environment
    legacy = GraphSnapshot(nodes=[Node(id="legacy", name="legacy", type=NodeType.BUCKET)])
    with factory() as db:
        db.add(
            SourceSnapshot(tenant_id="tenant-a", source="aaa-legacy", payload=legacy.model_dump(mode="json"))
        )
        db.commit()
    publish(factory, "new", GraphSnapshot(nodes=[Node(id="fresh", name="fresh", type=NodeType.BUCKET)]))
    assert [n.id for n in graph.snapshot("tenant-a", current(factory)).nodes] == ["legacy", "fresh"]
    with factory() as db:
        set_id = db.get(SourceSnapshot, ("tenant-a", "aaa-legacy")).payload["entity_set"]
        assert db.get(UploadSession, set_id).status == "active"


def test_superseded_upload_discards_its_staged_rows(client, environment):
    factory, _ = environment
    job = upload(client, demo_snapshot())
    newer = enqueue(factory, "snapshot", GraphSnapshot(nodes=[Node(id="n", name="n", type=NodeType.BUCKET)]))
    with factory() as db:
        db.get(IngestionJob, newer).created_at = now() + timedelta(seconds=5)
        db.commit()
    tasks.process_job(newer)
    tasks.process_job(job["id"])
    with factory() as db:
        assert db.get(IngestionJob, job["id"]).status == "completed"
        assert db.get(UploadSession, job["upload_id"]) is None
        assert db.scalar(select(AuditEvent).where(AuditEvent.action == "ingestion.superseded"))


def test_worker_refuses_an_upload_not_committed_for_its_job(client, environment):
    factory, _ = environment
    upload_id = start(client)
    job_id = enqueue(factory, "snapshot", GraphSnapshot())
    with factory() as db:
        db.get(IngestionJob, job_id).payload = {"upload_session": upload_id}
        db.commit()
    with pytest.raises(ValueError, match="not committed"):
        tasks.process_job(job_id)


ROLE = "arn:aws:iam::123456789012:role/support-runtime"


def aws_source(metadata: dict) -> GraphSnapshot:
    return GraphSnapshot(
        nodes=[
            Node(id=ROLE, name="support-runtime", type=NodeType.ROLE, account_id="123456789012",
                 provider="aws", metadata=metadata),
            Node(id="arn:aws:s3:::hr", name="hr", type=NodeType.BUCKET, sensitivity="restricted"),
        ],
        edges=[Edge(source=ROLE, target="arn:aws:s3:::hr", type=EdgeType.READ, actions=["s3:GetObject"])],
    )  # fmt: skip


AGENT = Node(id="agent:bot", name="bot", type=NodeType.AGENT, internet_exposed=True, authenticated=False)
ASSUMES = Edge(source="agent:bot", target=ROLE, type=EdgeType.ASSUMES, certainty="declared")


def test_references_link_to_another_sources_node_across_metadata_changes(environment):
    """An agent inventory links to the AWS role by reference: when a later collection changes
    the role's metadata, publication still succeeds (restating the role would conflict)."""
    factory, graph = environment
    publish(factory, "aws", aws_source({"role_last_used": "2026-09-01"}))
    agents = GraphSnapshot(nodes=[AGENT], edges=[ASSUMES], references=[ROLE], source="agents")
    publish(factory, "agents", agents)
    publish(factory, "aws", aws_source({"role_last_used": "2026-10-01"}))
    published = graph.snapshot("tenant-a", current(factory))
    role = next(n for n in published.nodes if n.id == ROLE)
    assert role.metadata == {"role_last_used": "2026-10-01"}  # The defining source's metadata.
    assert [n.id for n in published.nodes].count(ROLE) == 1
    assert any(e.source == "agent:bot" and e.target == ROLE for e in published.edges)
    with factory() as db:
        assert db.get(RevisionAnalysis, ("tenant-a", current(factory))).total_findings >= 1  # bot -> hr
    # Restating the role instead is a genuine duplicate definition: it conflicts once AWS changes it.
    stale = aws_source({"role_last_used": "2026-09-01"}).nodes[0]
    restated = GraphSnapshot(nodes=[AGENT, stale], edges=[ASSUMES], source="agents")
    with pytest.raises(ValueError, match="Conflicting node definitions"):
        run(enqueue(factory, "agents", restated), restated)


def test_unresolved_references_fail_publication_clearly(environment):
    factory, graph = environment
    before = current(factory)
    agents = GraphSnapshot(nodes=[AGENT], edges=[ASSUMES], references=[ROLE], source="agents")
    job_id = enqueue(factory, "agents", agents)
    with pytest.raises(ValueError, match="1 referenced node\\(s\\) are not defined by any source"):
        run(job_id, agents)
    with factory() as db:
        assert db.get(TenantState, "tenant-a").revision == before
        assert db.get(SourceSnapshot, ("tenant-a", "agents")) is None
        job = db.get(IngestionJob, job_id)
        assert job.status == "retrying" and "not defined by any source" in job.error
    # Once the defining source is published, the reference resolves.
    publish(factory, "aws", aws_source({}))
    publish(factory, "agents", agents)
    # A later collection that drops the role fails clearly instead of leaving a dangling edge.
    dropped = GraphSnapshot(nodes=aws_source({}).nodes[1:])
    with pytest.raises(ValueError, match="not defined by any source"):
        run(enqueue(factory, "aws", dropped), dropped)
    assert any(n.id == ROLE for n in graph.snapshot("tenant-a", current(factory)).nodes)


def test_references_resolve_only_within_the_tenant(environment):
    factory, _ = environment
    with factory() as db:
        db.add(TenantState(tenant_id="tenant-b", revision=None))
        db.commit()
    defining = aws_source({})
    run(enqueue(factory, "aws", defining, tenant="tenant-b"), defining)
    agents = GraphSnapshot(nodes=[AGENT], edges=[ASSUMES], references=[ROLE], source="agents")
    with pytest.raises(ValueError, match="not defined by any source"):
        run(enqueue(factory, "agents", agents), agents)
    run(enqueue(factory, "agents", agents, tenant="tenant-b"), agents)
    with factory() as db:
        assert db.get(SourceSnapshot, ("tenant-b", "agents")) is not None
        assert db.get(SourceSnapshot, ("tenant-a", "agents")) is None


def test_snapshot_reference_validation():
    with pytest.raises(ValueError, match="must be a node or a reference"):
        GraphSnapshot(nodes=[AGENT], edges=[ASSUMES])
    with pytest.raises(ValueError, match="Duplicate node references"):
        GraphSnapshot(nodes=[AGENT], edges=[ASSUMES], references=[ROLE, ROLE])
    with pytest.raises(ValueError):
        GraphSnapshot(references=[""])
    # A reference to a node the snapshot defines itself resolves to that node.
    GraphSnapshot(nodes=[AGENT, *aws_source({}).nodes], edges=[ASSUMES], references=[ROLE])


def test_ndjson_reference_lines(client, environment):
    factory, graph = environment
    defining = aws_source({})
    run(enqueue(factory, "aws", defining), defining)
    lines = [{"node": AGENT.model_dump(mode="json")}, {"edge": ASSUMES.model_dump(mode="json")}]
    upload_id = start(client)
    body = ("\n".join(json.dumps(line) for line in lines) + "\n").encode()
    assert put(client, upload_id, 0, body).status_code == 200
    with patch(DELAY):
        assert client.post(f"/api/v1/ingestions/uploads/{upload_id}/commit").status_code == 422
    duplicate = body + ((json.dumps({"reference": ROLE}) + "\n") * 2).encode()
    assert put(client, upload_id, 0, duplicate).status_code == 422
    assert put(client, upload_id, 1, (json.dumps({"reference": ROLE}) + "\n").encode()).status_code == 200
    with patch(DELAY):
        committed = client.post(f"/api/v1/ingestions/uploads/{upload_id}/commit")
    assert committed.status_code == 202, committed.text
    tasks.process_job(committed.json()["id"])
    published = graph.snapshot("tenant-a", current(factory))
    assert any(e.source == "agent:bot" and e.target == ROLE for e in published.edges)
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(StagedEntity).where(StagedEntity.kind == "ref")) == 1


def test_mcp_inventory_references_roles_and_tool_targets():
    from app.collectors.mcp_agent_collector import MCPInventory, collect_mcp

    inventory = MCPInventory.model_validate(
        {
            "mcpServers": {"files": {"command": "x"}},
            "bindings": {"files": [{"name": "read", "target_id": "arn:aws:s3:::hr"}]},
            "agents": [{"id": "bot", "name": "bot", "servers": ["files"], "roles": [ROLE]}],
        }
    )
    snapshot = collect_mcp(inventory)
    assert snapshot.references == sorted([ROLE, "arn:aws:s3:::hr"])
    assert {(e.source, e.target, e.type) for e in snapshot.edges} >= {
        ("agent:bot", ROLE, EdgeType.ASSUMES),
        ("mcp:files", "arn:aws:s3:::hr", EdgeType.READ),
    }
    with pytest.raises(ValueError, match="exactly one of target or target_id"):
        MCPInventory.model_validate({"bindings": {"files": [{"name": "read"}]}})
