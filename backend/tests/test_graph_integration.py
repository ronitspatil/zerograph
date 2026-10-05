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

        # Inject a failure after the batched Entity deletion but before the Snapshot
        # node is removed. The revision stays discoverable ("deleting") and the next
        # run resumes it; the pointer never references a non-current revision.
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
        assert store.snapshot(tenant, candidate.revision).nodes == []
        resumed = store.retention_candidates(tenant, "revision-0", plan.cutoff_ms, 2, 10)
        assert (candidate.revision, "deleting") in {(item.revision, item.state) for item in resumed}
        assert store.delete_revision(
            tenant, candidate.revision, candidate.created_at_ms, plan.cutoff_ms, "deleting"
        )
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


@pytest.mark.skipif(not os.getenv("ZG_INTEGRATION_GRAPH"), reason="No real graph database configured")
def test_real_role_map_label_counts_keyset_pages_and_scoped_structural_summaries(monkeypatch):
    from unittest.mock import patch

    from app.graph.exploration import RevisionUnavailable
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
    tenant, other, revision = "roles-" + str(uuid4()), "roles-other-" + str(uuid4()), str(uuid4())
    roles = [Node(id=f"role:{index:02}", name=f"Role {index}", type=NodeType.ROLE) for index in range(8)]
    neighbors = [
        Node(id="neighbor:" + kind.value, name=kind.value, type=kind)
        for kind in NodeType
        if kind != NodeType.ROLE
    ]
    edges = [
        Edge(source="role:00", target="role:01", type=EdgeType.INHERITS),
        Edge(source="role:00", target="role:01", type=EdgeType.INHERITS, certainty="conditional"),
        Edge(source="role:02", target="role:00", type=EdgeType.ASSUMES),
        Edge(source="role:03", target="role:04", type=EdgeType.INHERITS),
    ]
    edges += [Edge(source="role:00", target=node.id, type=EdgeType.READ) for node in neighbors]
    edges += [
        Edge(source=node.id, target="role:00", type=EdgeType.INVOKES, certainty="declared")
        for node in neighbors
    ]
    edges.append(Edge(source="role:00", target="neighbor:DataCategory", type=EdgeType.PII))
    edges.append(Edge(source="role:00", target="role:05", type=EdgeType.PII))
    edges.extend(
        [
            Edge(source="role:00", target="role:00", type=EdgeType.INHERITS),
            Edge(source="role:07", target="role:07", type=EdgeType.ASSUMES),
        ]
    )
    snapshot = GraphSnapshot(nodes=list(reversed(roles + neighbors)), edges=list(reversed(edges)))
    memory = MemoryGraphStore()
    memory.publish(tenant, revision, snapshot)
    try:
        store.publish(tenant, revision, snapshot)
        store.publish(other, revision, snapshot)
        store.publish(tenant, "old", snapshot)
        with store.driver.session() as session:
            session.run(
                "MATCH (a:Entity:CloudRole {tenant_id:$tenant, revision:$revision, id:'role:00'}), "
                "(b:Entity:CloudRole {tenant_id:$other, revision:$revision, id:'role:06'}) "
                "CREATE (a)-[:INHERITS_PERMISSIONS {tenant_id:$tenant, revision:$revision, id:'cross-tenant'}]->(b)",
                tenant=tenant,
                other=other,
                revision=revision,
            ).consume()
            session.run(
                "MATCH (a:Entity:CloudRole {tenant_id:$tenant, revision:$revision, id:'role:00'}), "
                "(b:Entity:CloudRole {tenant_id:$tenant, revision:'old', id:'role:06'}) "
                "CREATE (a)-[:INHERITS_PERMISSIONS {tenant_id:$tenant, revision:$revision, id:'cross-revision'}]->(b)",
                tenant=tenant,
                revision=revision,
            ).consume()
            session.run(
                "MATCH (a:Entity:CloudRole {tenant_id:$tenant, revision:$revision, id:'role:00'}), "
                "(b:Entity:CloudRole {tenant_id:$tenant, revision:$revision, id:'role:06'}) "
                "CREATE (a)-[:ASSUMES_ROLE {tenant_id:$other, revision:$revision, id:'wrong-owner'}]->(b) "
                "CREATE (a)-[:ASSUMES_ROLE {tenant_id:$tenant, revision:'old', id:'wrong-revision'}]->(b) "
                "CREATE (a)-[:ASSUMES_ROLE {id:'missing-scope'}]->(b) "
                "CREATE (a)-[:UNRECOGNIZED {tenant_id:$tenant, revision:$revision, id:'unknown-type'}]->(b)",
                tenant=tenant,
                other=other,
                revision=revision,
            ).consume()
        with patch.object(store, "snapshot", side_effect=AssertionError("Full snapshot forbidden")):
            for role_limit, edge_limit, cursor in (
                (2, 10, None),
                (2, 10, "role:01"),
                (100, 1, None),
                (100, 100, None),
                (100, 100, "role:03a"),
                (1, 10, "role:06"),
                (2, 10, "z"),
            ):
                actual = store.roles(tenant, revision, role_limit, edge_limit, cursor)
                assert actual == memory.roles(tenant, revision, role_limit, edge_limit, cursor)
                ids = {node.id for node in actual.nodes}
                assert all(node.type == NodeType.ROLE for node in actual.nodes)
                assert all(edge.source in ids and edge.target in ids for edge in actual.edges)
            summary = store.roles(tenant, revision, 1, 10, None).role_summaries[0]
            assert (summary.direct_neighbors, summary.linked_identities, summary.linked_data_assets) == (
                10,
                6,
                3,
            )
            assert store.roles(other, revision, 2, 10, None) == memory.roles(tenant, revision, 2, 10, None)
            with pytest.raises(RevisionUnavailable):
                store.roles(tenant, "missing", 2, 10, None)
            # Totals stored at publication equal the scoped aggregates they replace,
            # despite the deliberately malformed cross-scope relationships above.
            from app.graph.analysis import compute_analysis

            totals = compute_analysis(snapshot).totals
            for role_limit, edge_limit, cursor in ((2, 10, None), (100, 100, "role:03a")):
                assert store.roles(tenant, revision, role_limit, edge_limit, cursor, totals=totals) == (
                    store.roles(tenant, revision, role_limit, edge_limit, cursor)
                )
            for root in (None, "role:00"):
                assert store.explore(tenant, revision, root, 5, 10, totals=totals) == store.explore(
                    tenant, revision, root, 5, 10
                )
            # Single keyed node lookup is tenant- and revision-scoped.
            assert store.node(tenant, revision, "role:03") == memory.node(tenant, revision, "role:03")
            assert store.node(tenant, revision, "neighbor:AIAgent").type == NodeType.AGENT
            assert store.node(tenant, revision, "missing") is None
            assert store.node(tenant, "missing", "role:03") is None
            assert store.node("roles-absent-" + str(uuid4()), revision, "role:03") is None
    finally:
        with store.driver.session() as session:
            session.run(
                "MATCH (n) WHERE n.tenant_id IN $tenants DETACH DELETE n", tenants=[tenant, other]
            ).consume()
        store.close()
        get_settings.cache_clear()


@pytest.mark.skipif(not os.getenv("ZG_INTEGRATION_GRAPH"), reason="No real graph database configured")
def test_real_batched_publication_building_state_and_batched_delete(monkeypatch):
    import sys
    from pathlib import Path

    from app.graph.repository import MemoryGraphStore, edge_row, node_row

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    from qualify_scale import generate

    monkeypatch.setenv("ZG_GRAPH_VENDOR", os.environ["ZG_INTEGRATION_GRAPH"])
    monkeypatch.setenv("ZG_GRAPH_BATCH_SIZE", "100")
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
    tenant = "batched-" + str(uuid4())
    snapshot = generate(600)
    try:
        # Whole-snapshot publish goes through multiple bounded transactions.
        store.publish(tenant, "whole", snapshot)
        memory = MemoryGraphStore()
        memory.publish(tenant, "whole", snapshot)
        loaded = store.snapshot(tenant, "whole")
        assert sorted(n.id for n in loaded.nodes) == sorted(n.id for n in snapshot.nodes)
        assert sorted(e.id for e in loaded.edges) == sorted(e.id for e in snapshot.edges)
        # Idempotent republish of the same revision MERGEs instead of duplicating.
        store.publish(tenant, "whole", snapshot)
        assert len(store.snapshot(tenant, "whole").edges) == len(snapshot.edges)

        # A build in progress is "building": never a retention candidate while young,
        # and does not count toward the kept newest revisions.
        assert store.begin_revision(tenant, "partial", "combined", [])
        store.write_nodes(tenant, "partial", [node_row(n) for n in snapshot.nodes[:150]])
        with pytest.raises(ValueError, match="endpoint"):
            store.write_edges(
                tenant,
                "partial",
                [edge_row(e) for e in snapshot.edges if e.source not in {n.id for n in snapshot.nodes[:150]}][:5],
            )
        future = 2**62
        found = {c.revision: c.state for c in store.retention_candidates(tenant, "", future, 2, 50, None)}
        assert "partial" not in found
        stale = {c.revision: c.state for c in store.retention_candidates(tenant, "", future, 2, 50, future)}
        assert stale == {"partial": "building"}
        created = next(
            c.created_at_ms for c in store.retention_candidates(tenant, "", future, 2, 50, future)
        )
        # A ready-state delete request cannot remove a building revision, and vice versa.
        assert not store.delete_revision(tenant, "partial", created, future, "ready")
        assert store.delete_revision(tenant, "partial", created, future, "building")
        with store.driver.session() as session:
            remaining = session.run(
                "MATCH (n {tenant_id:$tenant, revision:'partial'}) RETURN count(n) AS count", tenant=tenant
            ).single()["count"]
        assert remaining == 0
        # Batched delete of a multi-batch ready revision (several 50-node transactions).
        with store.driver.session() as session:
            created = session.run(
                "MATCH (s:Snapshot {tenant_id:$tenant, revision:'whole'}) RETURN s.created_at_ms AS c",
                tenant=tenant,
            ).single()["c"]
        assert store.delete_revision(tenant, "whole", created, future)
        with store.driver.session() as session:
            remaining = session.run(
                "MATCH (n {tenant_id:$tenant}) RETURN count(n) AS count", tenant=tenant
            ).single()["count"]
        assert remaining == 0
    finally:
        with store.driver.session() as session:
            session.run("MATCH (n {tenant_id:$tenant}) DETACH DELETE n", tenant=tenant).consume()
        store.close()
        get_settings.cache_clear()
