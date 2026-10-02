"""Independent NetworkX oracle for request-local optimization correctness."""

import random

import networkx as nx
import pytest

from app.engine.analysis_index import AnalysisIndex
from app.engine.blast_radius import calculate
from app.engine.toxic_combos import detect
from app.graph.schema import DATA_TYPES, Edge, EdgeType, GraphSnapshot, Node, NodeType, Sensitivity


def fixture():
    rng = random.Random(773)
    nodes = [
        Node(
            id=f"node:{i:02}",
            name=str(i),
            type=NodeType.ROLE if i < 12 else NodeType.BUCKET,
            sensitivity=list(Sensitivity)[i % 4],
        )
        for i in range(24)
    ]
    edges = [
        Edge(
            source=a,
            target=b,
            type=EdgeType.READ,
            certainty=rng.choice(["confirmed", "conditional", "declared"]),
        )
        for a, b in sorted({(rng.choice(nodes).id, rng.choice(nodes).id) for _ in range(100)})
    ]
    edges += [Edge(source="node:00", target="node:23", type=EdgeType.PII)]
    return GraphSnapshot(nodes=nodes, edges=edges)


@pytest.mark.parametrize("include_uncertain", [False, True])
@pytest.mark.parametrize("hops", [1, 3, 5])
def test_index_matches_independent_paths_centrality_and_weighted_score(include_uncertain, hops):
    snapshot = fixture()
    oracle = nx.DiGraph()
    oracle.add_nodes_from(node.id for node in snapshot.nodes)
    oracle.add_edges_from(
        sorted(
            {
                (edge.source, edge.target)
                for edge in snapshot.edges
                if edge.type != EdgeType.PII and (include_uncertain or edge.certainty == "confirmed")
            }
        )
    )
    weights = dict(zip(list(Sensitivity), [1, 2, 5, 10], strict=True))
    nodes = {node.id: node for node in snapshot.nodes}
    total = sum(weights[node.sensitivity] for node in snapshot.nodes if node.type in DATA_TYPES)
    index = AnalysisIndex.build(snapshot, include_uncertain)
    for source in ["node:00", "node:05", "node:23"]:
        paths = nx.single_source_shortest_path(oracle, source, cutoff=hops)
        paths.pop(source)
        assets = sorted(node for node in paths if nodes[node].type in DATA_TYPES)
        exposure = sum(weights[nodes[node].sensitivity] for node in assets) / total
        centrality = nx.out_degree_centrality(oracle)[source]
        result = calculate(snapshot, source, hops, include_uncertain, index=index)
        assert result.paths == paths
        assert result.affected_assets == assets
        assert result.centrality == round(centrality, 4)
        assert result.sensitivity_exposure == round(exposure, 4)
        assert result.risk_score == (
            min(100, round(100 * (0.85 * exposure + 0.15 * centrality))) if assets else 0
        )


def test_index_cannot_cross_snapshots_or_certainty_modes():
    snapshot = fixture()
    index = AnalysisIndex.build(snapshot)
    with pytest.raises(ValueError):
        calculate(snapshot.model_copy(deep=True), "node:00", index=index)
    with pytest.raises(ValueError):
        calculate(snapshot, "node:00", include_uncertain=True, index=index)


def test_parallel_evidence_prefers_confirmed_access_and_excludes_annotations():
    snapshot = GraphSnapshot(
        nodes=[
            Node(
                id="agent",
                name="Agent",
                type=NodeType.AGENT,
                internet_exposed=True,
                authenticated=False,
                privileged=True,
            ),
            Node(id="data", name="Data", type=NodeType.BUCKET, sensitivity=Sensitivity.RESTRICTED),
        ],
        edges=[
            Edge(
                source="agent",
                target="data",
                type=EdgeType.READ,
                certainty="conditional",
                evidence=["uncertain"],
            ),
            Edge(
                source="agent",
                target="data",
                type=EdgeType.READ,
                certainty="confirmed",
                evidence=["confirmed"],
            ),
            Edge(source="agent", target="data", type=EdgeType.PII, evidence=["annotation"]),
        ],
    )
    result = detect(snapshot, AnalysisIndex.build(snapshot, True))
    assert len(result) == 1
    assert result[0].path == ["agent", "data"]
    assert result[0].severity == "critical" and not result[0].conditional
    assert result[0].evidence == ["Public endpoint is declared unauthenticated", "confirmed"]


def test_singleton_and_self_loop_degree_semantics():
    snapshot = GraphSnapshot(
        nodes=[Node(id="one", name="One", type=NodeType.ROLE)],
        edges=[Edge(source="one", target="one", type=EdgeType.ASSUMES)],
    )
    result = calculate(snapshot, "one")
    assert result.centrality == 1
    assert result.affected_nodes == [] and result.risk_score == 0
