"""The initial explore sample: connected, representative, deterministic and bounded."""

import random
import sys
from collections import Counter
from pathlib import Path

from app.db.models import RevisionAnalysis, TenantState
from app.graph.analysis import backfill, compute_analysis, store_analysis, stored_totals
from app.graph.compact import CompactGraph
from app.graph.demo import demo_snapshot
from app.graph.sample import SAMPLE_SIZE, SAMPLE_VERSION, select_sample, snapshot_sample
from app.graph.schema import Edge, EdgeType, GraphSnapshot, Node, NodeType

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from qualify_scale import generate  # noqa: E402


def components(snapshot: GraphSnapshot, ids: list[str]) -> int:
    chosen = set(ids)
    adjacent = {node_id: set() for node_id in ids}
    for edge in snapshot.edges:
        if edge.source in chosen and edge.target in chosen:
            adjacent[edge.source].add(edge.target)
            adjacent[edge.target].add(edge.source)
    seen, count = set(), 0
    for start in ids:
        if start in seen:
            continue
        count += 1
        pending = [start]
        seen.add(start)
        while pending:
            for neighbor in adjacent[pending.pop()]:
                if neighbor not in seen:
                    seen.add(neighbor)
                    pending.append(neighbor)
    return count


def internal_edges(snapshot: GraphSnapshot, ids: list[str]) -> int:
    chosen = set(ids)
    return sum(edge.source in chosen and edge.target in chosen for edge in snapshot.edges)


def test_enterprise_sample_is_connected_mixed_and_linked_at_every_prefix():
    snapshot = generate(6000, exposed_rate=0.02)
    analysis = compute_analysis(snapshot)
    sample = analysis.sample_ids
    types = {node.id: node.type for node in snapshot.nodes}
    assert len(sample) == len(set(sample)) == SAMPLE_SIZE
    # The ID-sorted sample this replaces: one type, no relationships at all.
    legacy = sorted(types)[:250]
    assert len({types[i] for i in legacy}) == 1 and internal_edges(snapshot, legacy) == 0
    for limit in (2, 10, 50, 250, 500):
        prefix = sample[:limit]
        assert components(snapshot, prefix) == 1
        assert internal_edges(snapshot, prefix) >= limit - 1
    view = sample[:250]
    mix = Counter(types[i] for i in view)
    assert len(mix) >= 6 and max(mix.values()) <= 250 // 3
    assert {NodeType.ROLE, NodeType.AGENT} <= set(mix) and set(mix) & {NodeType.DATABASE, NodeType.BUCKET}
    assert internal_edges(snapshot, view) >= 250
    # Seeded from the first finding (an exposed entry point to sensitive data).
    first = analysis.findings[0].path
    assert sample[: len(first)] == first


def test_selection_is_deterministic_whatever_the_input_order():
    snapshot = generate(3000, seed=11)
    expected = compute_analysis(snapshot).sample_ids
    rng = random.Random(3)
    nodes, edges = list(snapshot.nodes), list(snapshot.edges)
    rng.shuffle(nodes)
    rng.shuffle(edges)
    shuffled = GraphSnapshot.model_construct(nodes=nodes, edges=edges, warnings=[], source="snapshot")
    assert compute_analysis(shuffled).sample_ids == expected
    assert CompactGraph.from_snapshot(shuffled).analyze().sample_ids == expected
    # A smaller limit is exactly a prefix: stored samples serve any node_limit.
    findings = compute_analysis(snapshot).findings
    for limit in (1, 7, 120):
        assert snapshot_sample(snapshot, findings, (), limit) == expected[:limit]


def test_small_graphs_are_included_whole_with_isolated_entities_last():
    demo = demo_snapshot()
    sample = compute_analysis(demo).sample_ids
    assert sorted(sample) == sorted(node.id for node in demo.nodes)
    nodes = [Node(id=f"n:{i}", name=f"n{i}", type=NodeType.ROLE) for i in range(4)]
    nodes += [Node(id="lonely", name="Lonely", type=NodeType.AGENT)]
    edges = [Edge(source="n:0", target="n:1", type=EdgeType.INHERITS)]
    edges += [Edge(source="n:2", target="n:3", type=EdgeType.INHERITS)]
    edges += [Edge(source="n:3", target="n:3", type=EdgeType.INHERITS)]  # Self-loop.
    snapshot = GraphSnapshot(nodes=nodes, edges=edges)
    # Component by component (highest degree first), then the isolated entity.
    assert snapshot_sample(snapshot) == ["n:3", "n:2", "n:0", "n:1", "lonely"]
    assert snapshot_sample(snapshot, limit=0) == []
    assert snapshot_sample(GraphSnapshot()) == []
    assert compute_analysis(GraphSnapshot()).sample_ids == []


def test_important_entities_lead_and_types_balance_within_the_frontier():
    # A hub reaching many buckets and few roles: buckets cannot crowd the roles out.
    ids = ["hub"] + [f"bucket:{i:03}" for i in range(50)] + [f"role:{i}" for i in range(3)] + ["vip"]
    types = ["CloudRole"] + ["S3Bucket"] * 50 + ["CloudRole"] * 3 + ["AIAgent"]
    index = {node_id: i for i, node_id in enumerate(ids)}
    pairs = [("hub", f"bucket:{i:03}") for i in range(50)] + [(f"role:{i}", "hub") for i in range(3)]
    pairs.append(("vip", "role:2"))
    sources = [index[a] for a, _ in pairs]
    targets = [index[b] for _, b in pairs]
    # Least represented type first; ties by relationships into the sample, degree, ID.
    plain = select_sample(ids, types, sources, targets, limit=6)
    assert plain == ["hub", "bucket:000", "role:2", "vip", "bucket:001", "bucket:002"]
    flagged = select_sample(ids, types, sources, targets, important_ids=["vip"], limit=3)
    assert flagged == ["vip", "role:2", "hub"]
    path = select_sample(ids, types, sources, targets, finding_paths=[["vip", "role:2", "hub"]], limit=4)
    assert path[:3] == ["vip", "role:2", "hub"]


def test_sample_rows_are_scoped_versioned_and_refreshed_by_backfill(environment):
    factory, graph = environment
    other = GraphSnapshot(nodes=[Node(id="private", name="Private", type=NodeType.HUMAN)])
    graph.publish("tenant-b", "revision-b", other)
    with factory() as db:
        db.add(TenantState(tenant_id="tenant-b", revision="revision-b"))
        store_analysis(db, "tenant-a", "revision-a", compute_analysis(demo_snapshot()))
        store_analysis(db, "tenant-b", "revision-b", compute_analysis(other))
        db.commit()
        row = db.get(RevisionAnalysis, ("tenant-a", "revision-a"))
        assert row.sample_version == SAMPLE_VERSION
        assert stored_totals(db, "tenant-b", "revision-b").sample_ids == ("private",)
        assert stored_totals(db, "tenant-b", "revision-a") is None
        # An older (ascending-ID) sample keeps serving until the backfill refreshes it.
        row.sample_ids, row.sample_version = sorted(row.sample_ids)[:3], None
        db.commit()
        assert stored_totals(db, "tenant-a", "revision-a").sample_ids == tuple(sorted(row.sample_ids))
    assert backfill("tenant-a")["backfilled"] is True
    assert backfill("tenant-a")["backfilled"] is False
    with factory() as db:
        row = db.get(RevisionAnalysis, ("tenant-a", "revision-a"))
        assert row.sample_version == SAMPLE_VERSION
        assert row.sample_ids == compute_analysis(demo_snapshot()).sample_ids
    assert backfill("tenant-b")["backfilled"] is False


def test_api_default_view_serves_the_stored_sample_with_its_relationships(client, environment):
    factory, graph = environment
    snapshot = generate(3000)
    graph.publish("tenant-a", "revision-big", snapshot)
    analysis = compute_analysis(snapshot)
    with factory() as db:
        store_analysis(db, "tenant-a", "revision-big", analysis)
        db.get(TenantState, "tenant-a").revision = "revision-big"
        db.commit()
    body = client.get("/api/v1/graph/explore").json()
    ids = [node["id"] for node in body["nodes"]]
    assert ids == sorted(analysis.sample_ids[:250])
    assert len({node["type"] for node in body["nodes"]}) >= 3
    assert len(body["edges"]) >= len(ids)
    assert all(edge["source"] in ids and edge["target"] in ids for edge in body["edges"])
    assert body["view"]["truncated"] is True and body["view"]["total_nodes"] == len(snapshot.nodes)
    small = client.get("/api/v1/graph/explore", params={"node_limit": 5, "edge_limit": 1}).json()
    assert [node["id"] for node in small["nodes"]] == sorted(analysis.sample_ids[:5])
    assert len(small["edges"]) == 1
