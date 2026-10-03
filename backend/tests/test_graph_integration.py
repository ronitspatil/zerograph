"""Run against a real graph database in CI, or set ZG_INTEGRATION_GRAPH locally."""

import os
import time
from uuid import uuid4

import pytest

from app.core.config import get_settings
from app.graph.demo import demo_snapshot
from app.graph.repository import CypherGraphStore


@pytest.mark.skipif(not os.getenv("ZG_INTEGRATION_GRAPH"), reason="No real graph database configured")
def test_real_graph_roundtrip_and_tenant_isolation(monkeypatch):
    monkeypatch.setenv("ZG_GRAPH_VENDOR", os.environ["ZG_INTEGRATION_GRAPH"])
    get_settings.cache_clear()
    store = CypherGraphStore()
    for attempt in range(45):
        try:
            store.driver.verify_connectivity()
            break
        except Exception:
            if attempt == 44:
                raise
            time.sleep(1)
    store.migrate()
    store.migrate()
    tenant = "integration-" + str(uuid4())
    revision = str(uuid4())
    try:
        store.publish(tenant, revision, demo_snapshot())
        snapshot = store.snapshot(tenant, revision)
        assert len(snapshot.nodes) == 12
        assert len(store.snapshot("other-tenant", revision).nodes) == 0
        paths = store.shortest_paths(tenant, revision, "agent:support", 5, False)
        assert paths["db:customers"] == ["agent:support", "mcp:crm", "role:admin", "db:customers"]
    finally:
        with store.driver.session() as session:
            session.run("MATCH (n {tenant_id:$tenant}) DETACH DELETE n", tenant=tenant).consume()
        store.close()
        get_settings.cache_clear()


@pytest.mark.skipif(not os.getenv("ZG_INTEGRATION_GRAPH"), reason="No real graph database configured")
def test_real_graph_retention_age_scope_bounds_and_atomic_rollback(environment, monkeypatch):
    from datetime import UTC, datetime, timedelta

    from app.db.models import TenantState
    from app.graph import repository, retention

    monkeypatch.setenv("ZG_GRAPH_VENDOR", os.environ["ZG_INTEGRATION_GRAPH"])
    get_settings.cache_clear()
    store = CypherGraphStore()
    for attempt in range(45):
        try:
            store.driver.verify_connectivity()
            break
        except Exception:
            if attempt == 44:
                raise
            time.sleep(1)
    store.migrate()
    store.migrate()
    tenant, other = "retention-" + str(uuid4()), "retention-other-" + str(uuid4())
    timestamp = datetime.now(UTC)
    factory, _ = environment
    try:
        with factory() as db:
            db.add(TenantState(tenant_id=tenant, revision="revision-0"))
            db.commit()
        for index in range(8):
            revision = f"revision-{index}"
            store.publish(tenant, revision, demo_snapshot())
            created = int((timestamp - timedelta(days=40 - index)).timestamp() * 1000)
            with store.driver.session() as session:
                session.run(
                    "MATCH (s:Snapshot {tenant_id:$tenant, revision:$revision}) SET s.created_at_ms=$created",
                    tenant=tenant,
                    revision=revision,
                    created=created,
                ).consume()
        store.publish(other, "revision-5", demo_snapshot())
        with store.driver.session() as session:
            session.run(
                "MATCH (s:Snapshot {tenant_id:$tenant, revision:'revision-3'}) REMOVE s.created_at_ms",
                tenant=tenant,
            ).consume()
        monkeypatch.setattr(retention, "get_graph_store", lambda: store)
        plan = retention.prune_revisions(tenant, retention.RetentionPolicy(30, 2, 4), timestamp=timestamp)
        assert plan.dry_run
        assert [item.revision for item in plan.candidates] == [
            "revision-5",
            "revision-4",
            "revision-2",
            "revision-1",
        ]
        candidate = plan.candidates[0]
        assert not store.delete_revision(
            tenant, candidate.revision, candidate.created_at_ms + 1, plan.cutoff_ms
        )
        assert not store.delete_revision(
            tenant, candidate.revision, candidate.created_at_ms, candidate.created_at_ms
        )

        # Inject a failure after Entity deletion but before Snapshot deletion.
        # Both supported graph engines must roll back the entire transaction.
        original = repository.unit_of_work

        class FailureTransaction:
            def __init__(self, tx):
                self.tx = tx

            def run(self, query, **kwargs):
                if query == "MATCH (s:Snapshot {key:$key}) DELETE s":
                    raise RuntimeError("injected deletion failure")
                return self.tx.run(query, **kwargs)

        def failing_unit_of_work(**kwargs):
            def decorate(function):
                return original(**kwargs)(lambda tx: function(FailureTransaction(tx)))

            return decorate

        with monkeypatch.context() as injected:
            injected.setattr(repository, "unit_of_work", failing_unit_of_work)
            with pytest.raises(RuntimeError, match="injected deletion"):
                store.delete_revision(tenant, candidate.revision, candidate.created_at_ms, plan.cutoff_ms)
        assert len(store.snapshot(tenant, candidate.revision).nodes) == 12
        assert store.delete_revision(tenant, candidate.revision, candidate.created_at_ms, plan.cutoff_ms)
        assert store.snapshot(tenant, candidate.revision).nodes == []
        assert not store.delete_revision(tenant, candidate.revision, candidate.created_at_ms, plan.cutoff_ms)
        assert len(store.snapshot(other, candidate.revision).nodes) == 12
        for protected in ("revision-0", "revision-3", "revision-6", "revision-7"):
            assert len(store.snapshot(tenant, protected).nodes) == 12
        # Timestamp is first-publication metadata, not last-write age.
        before = plan.candidates[1].created_at_ms
        store.publish(tenant, "revision-4", demo_snapshot())
        after = store.retention_candidates(tenant, "revision-0", plan.cutoff_ms, 2, 10)
        assert next(item.created_at_ms for item in after if item.revision == "revision-4") == before
    finally:
        with store.driver.session() as session:
            session.run(
                "MATCH (n) WHERE n.tenant_id IN $tenants DETACH DELETE n", tenants=[tenant, other]
            ).consume()
        store.close()
        get_settings.cache_clear()


@pytest.mark.skipif(not os.getenv("ZG_INTEGRATION_GRAPH"), reason="No real graph database configured")
def test_real_bounded_exploration_search_scopes_and_dense_neighbors(monkeypatch):
    from unittest.mock import patch

    from app.graph.exploration import RevisionUnavailable, RootNotFound
    from app.graph.repository import MemoryGraphStore
    from app.graph.schema import Edge, EdgeType, GraphSnapshot, Node, NodeType

    monkeypatch.setenv("ZG_GRAPH_VENDOR", os.environ["ZG_INTEGRATION_GRAPH"])
    get_settings.cache_clear()
    store = CypherGraphStore()
    for attempt in range(45):
        try:
            store.driver.verify_connectivity()
            break
        except Exception:
            if attempt == 44:
                raise
            time.sleep(1)
    store.migrate()
    tenant, other, revision = "explore-" + str(uuid4()), "explore-other-" + str(uuid4()), str(uuid4())
    root = Node(id="root", name="Root", type=NodeType.AGENT)
    nodes = [root] + [
        Node(id=f"neighbor:{index:03}", name=f"Customer {index}", type=NodeType.DATABASE)
        for index in range(60)
    ]
    nodes.append(Node(id="category", name="PII", type=NodeType.CATEGORY))
    edges = [Edge(source=root.id, target=node.id, type=EdgeType.READ) for node in nodes[1:-1]]
    edges += [Edge(source=node.id, target=root.id, type=EdgeType.INVOKES) for node in nodes[1:-1]]
    edges.append(Edge(source=root.id, target="category", type=EdgeType.PII))
    snapshot = GraphSnapshot(nodes=nodes, edges=edges)
    memory = MemoryGraphStore()
    memory.publish(tenant, revision, snapshot)
    try:
        store.publish(tenant, revision, snapshot)
        store.publish(other, revision, snapshot)
        store.publish(tenant, "old", snapshot)
        # Deliberately malformed links must not enter scoped counts/neighborhoods.
        with store.driver.session() as session:
            session.run(
                "MATCH (a:Entity {tenant_id:$tenant, revision:$revision, id:'root'}), "
                "(b:Entity {tenant_id:$other, revision:$revision, id:'neighbor:059'}) "
                "CREATE (a)-[:CAN_READ {tenant_id:$tenant, revision:$revision, id:'cross-tenant'}]->(b)",
                tenant=tenant,
                other=other,
                revision=revision,
            ).consume()
            session.run(
                "MATCH (a:Entity {tenant_id:$tenant, revision:$revision, id:'root'}), "
                "(b:Entity {tenant_id:$tenant, revision:'old', id:'neighbor:059'}) "
                "CREATE (a)-[:CAN_READ {tenant_id:$tenant, revision:$revision, id:'cross-revision'}]->(b)",
                tenant=tenant,
                revision=revision,
            ).consume()
            session.run(
                "MATCH (a:Entity {tenant_id:$tenant, revision:$revision, id:'root'}), "
                "(b:Entity {tenant_id:$tenant, revision:$revision, id:'neighbor:059'}) "
                "CREATE (a)-[:CAN_WRITE {tenant_id:$other, revision:$revision, id:'wrong-owner'}]->(b) "
                "CREATE (a)-[:CAN_WRITE {tenant_id:$tenant, revision:'old', id:'wrong-revision'}]->(b) "
                "CREATE (a)-[:UNRECOGNIZED {tenant_id:$tenant, revision:$revision, id:'unknown-type'}]->(b)",
                tenant=tenant,
                other=other,
                revision=revision,
            ).consume()
        with patch.object(store, "snapshot", side_effect=AssertionError("Full snapshot forbidden")):
            for source, node_limit, edge_limit in (
                (None, 3, 4),
                ("root", 25, 7),
                ("root", 1, 1),
                ("root", 100, 200),
                ("category", 5, 5),
            ):
                actual = store.explore(tenant, revision, source, node_limit, edge_limit)
                expected = memory.explore(tenant, revision, source, node_limit, edge_limit)
                assert actual == expected
                ids = {node.id for node in actual.nodes}
                assert all(edge.source in ids and edge.target in ids for edge in actual.edges)
            for q, limit in (
                (" CUSTOMER ", 5),
                ("neighbor:059", 1),
                ("missing", 3),
                ("x' MATCH (secret)", 3),
            ):
                assert store.search(tenant, revision, q, limit) == memory.search(tenant, revision, q, limit)
            with pytest.raises(RootNotFound):
                store.explore(tenant, revision, "missing", 20, 20)
            with pytest.raises(RevisionUnavailable):
                store.explore(tenant, "missing", None, 20, 20)
            with pytest.raises(RevisionUnavailable):
                store.search(tenant, "missing", "customer", 20)
    finally:
        with store.driver.session() as session:
            session.run(
                "MATCH (n) WHERE n.tenant_id IN $tenants DETACH DELETE n", tenants=[tenant, other]
            ).consume()
        store.close()
        get_settings.cache_clear()
