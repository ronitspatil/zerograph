"""Graph-free /simulate must equal the reference engine (``calculate``) exactly."""

import random
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from app.collectors.data_classifier import classification_edges
from app.core.config import get_settings
from app.db.models import TenantState
from app.engine.analysis_index import AnalysisIndex
from app.engine.blast_radius import calculate, simulate, snapshot_reach
from app.graph.analysis import compute_analysis, store_analysis
from app.graph.demo import demo_snapshot
from app.graph.schema import Edge, EdgeType, GraphSnapshot, Node, NodeType

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from qualify_scale import generate  # noqa: E402
from test_compact_analysis import random_graph  # noqa: E402


def canonical(result) -> tuple:
    # Paths keep BFS discovery order, so compare items, not just the mapping.
    return result.model_dump(), list(result.paths.items())


def scale(snapshot: GraphSnapshot) -> tuple[int, int]:
    return len(snapshot.nodes), AnalysisIndex.build(snapshot).total_asset_weight


def assert_parity(snapshot: GraphSnapshot, sources, hops_options=(1, 3, 5)) -> None:
    nodes, weight = scale(snapshot)
    indexes = {flag: AnalysisIndex.build(snapshot, flag) for flag in (False, True)}
    for source in sources:
        for hops in hops_options:
            for uncertain in (False, True):
                expected = calculate(snapshot, source, hops, uncertain, index=indexes[uncertain])
                actual = simulate(snapshot_reach(snapshot, source, hops, uncertain), nodes, weight)
                assert canonical(actual) == canonical(expected), (source, hops, uncertain)


def enterprise(size: int, exposed: float = 0.01) -> GraphSnapshot:
    generated = generate(size, exposed_rate=exposed)
    return classification_edges(
        GraphSnapshot.model_construct(nodes=generated.nodes, edges=generated.edges, warnings=[], source="s")
    )


def sources(snapshot: GraphSnapshot, count: int, seed: int = 3) -> list[str]:
    """Hubs (highest out-degree), entry points and a seeded sample of the rest."""
    degree: dict[str, int] = {}
    for edge in snapshot.edges:
        degree[edge.source] = degree.get(edge.source, 0) + 1
    hubs = sorted(degree, key=lambda node: (-degree[node], node))[:5]
    entries = [n.id for n in snapshot.nodes if n.internet_exposed and not n.authenticated][:5]
    rest = random.Random(seed).sample([n.id for n in snapshot.nodes], count)
    return list(dict.fromkeys(hubs + entries + rest))


def test_demo_parity_every_node():
    snapshot = demo_snapshot()
    assert_parity(snapshot, [n.id for n in snapshot.nodes], hops_options=(1, 2, 3, 4, 5))


@pytest.mark.parametrize("seed", range(8))
def test_random_dense_graph_parity(seed):
    # Self-loops, parallel edges of mixed certainty, annotations and cycles.
    snapshot = random_graph(seed, 30 + seed * 5)
    assert_parity(snapshot, [n.id for n in snapshot.nodes])


@pytest.mark.parametrize(("size", "count"), [(1000, 60), (5000, 40)])
def test_enterprise_fixture_parity(size, count):
    snapshot = enterprise(size)
    assert_parity(snapshot, sources(snapshot, count), hops_options=(2, 5))


def test_reach_holds_only_the_bounded_neighborhood():
    snapshot = demo_snapshot()
    reach = snapshot_reach(snapshot, "agent:support", 1, False)
    assert set(reach.edges) == {"agent:support"}
    assert set(reach.kinds) == {"agent:support", *(t for t, _ in reach.edges["agent:support"])}
    assert snapshot_reach(snapshot, "missing", 5, False) is None
    with pytest.raises(ValueError):
        snapshot_reach(snapshot, "agent:support", 6, False)


def test_uncertain_shortcut_and_annotations_follow_the_reference():
    snapshot = demo_snapshot()
    snapshot.edges.append(
        Edge(source="agent:support", target="db:customers", type=EdgeType.READ, certainty="conditional")
    )
    snapshot.edges.append(Edge(source="agent:support", target="s3:exports", type=EdgeType.PII))
    assert_parity(snapshot, ["agent:support", "mcp:crm"], hops_options=(1, 5))
    nodes, weight = scale(snapshot)
    confirmed = simulate(snapshot_reach(snapshot, "agent:support", 5, False), nodes, weight)
    assert len(confirmed.paths["db:customers"]) == 4
    shortcut = simulate(snapshot_reach(snapshot, "agent:support", 5, True), nodes, weight)
    assert shortcut.paths["db:customers"] == ["agent:support", "db:customers"]


def test_singleton_and_self_loop_degree_semantics():
    snapshot = GraphSnapshot(
        nodes=[Node(id="one", name="One", type=NodeType.ROLE)],
        edges=[Edge(source="one", target="one", type=EdgeType.ASSUMES)],
    )
    result = simulate(snapshot_reach(snapshot, "one", 5, False), 1, 0)
    assert canonical(result) == canonical(calculate(snapshot, "one"))
    assert result.centrality == 1 and result.risk_score == 0


def test_api_matches_reference_with_stored_analysis_and_never_loads_the_snapshot(client, environment):
    factory, graph = environment
    snapshot = graph.snapshots[("tenant-a", "revision-a")]
    with factory() as db:
        store_analysis(db, "tenant-a", "revision-a", compute_analysis(snapshot))
        db.commit()
    with patch.object(graph, "snapshot", side_effect=AssertionError("whole snapshot loaded")):
        for node in snapshot.nodes:
            for uncertain in (False, True):
                response = client.post(
                    "/api/v1/simulate",
                    json={"node_id": node.id, "max_hops": 5, "include_uncertain": uncertain},
                )
                assert response.status_code == 200
                assert response.headers["x-graph-revision"] == "revision-a"
                expected = calculate(snapshot, node.id, 5, uncertain).model_dump(mode="json")
                assert response.json() == expected
                assert list(response.json()["paths"]) == list(expected["paths"])


def test_api_legacy_revision_without_stored_analysis_matches_reference(client, environment):
    _, graph = environment
    snapshot = graph.snapshots[("tenant-a", "revision-a")]
    response = client.post("/api/v1/simulate", json={"node_id": "agent:support", "max_hops": 4})
    assert response.status_code == 200
    assert response.json() == calculate(snapshot, "agent:support", 4).model_dump(mode="json")


def test_api_revision_pin_conflict_and_missing_source(client, environment):
    ok = client.post("/api/v1/simulate", json={"node_id": "agent:support", "revision": "revision-a"})
    assert ok.status_code == 200
    stale = client.post("/api/v1/simulate", json={"node_id": "agent:support", "revision": "old"})
    assert stale.status_code == 409
    assert client.post("/api/v1/simulate", json={"node_id": "nope"}).status_code == 404
    assert client.post("/api/v1/simulate", json={"node_id": "x", "extra": 1}).status_code == 422
    factory, _ = environment
    with factory() as db:
        db.get(TenantState, "tenant-a").revision = ""
        db.commit()
    assert client.post("/api/v1/simulate", json={"node_id": "agent:support"}).status_code == 404


def test_legacy_graph_view_is_deprecated_and_refuses_large_revisions(client, environment, monkeypatch):
    factory, graph = environment
    response = client.get("/api/v1/graph")
    assert response.status_code == 200 and response.headers["deprecation"] == "true"
    with factory() as db:
        store_analysis(
            db, "tenant-a", "revision-a", compute_analysis(graph.snapshots[("tenant-a", "revision-a")])
        )
        db.commit()
    assert client.get("/api/v1/graph").status_code == 200
    monkeypatch.setenv("ZG_LEGACY_GRAPH_MAX_NODES", "11")
    get_settings.cache_clear()
    with patch.object(graph, "snapshot", side_effect=AssertionError("whole snapshot loaded")):
        refused = client.get("/api/v1/graph")
    assert refused.status_code == 413
    assert "/graph/explore" in refused.json()["detail"]
    monkeypatch.setenv("ZG_LEGACY_GRAPH_MAX_NODES", "5000")
    monkeypatch.setenv("ZG_LEGACY_GRAPH_MAX_EDGES", "3")
    get_settings.cache_clear()
    assert client.get("/api/v1/graph").status_code == 413
