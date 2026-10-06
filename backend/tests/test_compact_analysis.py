"""The worker's compact analysis must equal the reference compute_analysis exactly."""

import random
import sys
from pathlib import Path

import pytest

from app.collectors.data_classifier import classification_edges
from app.graph.analysis import compute_analysis
from app.graph.compact import CompactGraph
from app.graph.demo import demo_snapshot
from app.graph.schema import Edge, EdgeType, GraphSnapshot, Node, NodeType, Sensitivity

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from qualify_scale import generate  # noqa: E402


def assert_parity(snapshot: GraphSnapshot) -> None:
    reference = compute_analysis(snapshot)
    compact = CompactGraph.from_snapshot(snapshot).analyze()
    assert compact.overview == reference.overview
    assert [f.model_dump() for f in compact.findings] == [f.model_dump() for f in reference.findings]
    assert compact.totals == reference.totals
    assert compact.total_asset_weight == reference.total_asset_weight
    assert compact.high_blast_ids == reference.high_blast_ids
    assert compact.sample_ids == reference.sample_ids


def random_graph(seed: int, size: int) -> GraphSnapshot:
    """Dense small graphs: self-loops, parallel edges of mixed certainty, cycles,
    privileged/unencrypted nodes, several entry points and high-blast identities."""
    rng = random.Random(seed)
    kinds = list(NodeType)
    nodes = [
        Node(
            id=f"n{rng.randrange(10**6):06d}-{i}",
            name=f"n{i}",
            type=rng.choice(kinds),
            account_id=rng.choice(["", "a", "b"]),
            sensitivity=rng.choice(list(Sensitivity)),
            internet_exposed=rng.random() < 0.15,
            authenticated=rng.random() < 0.5,
            encrypted=rng.random() < 0.7,
            privileged=rng.random() < 0.2,
            tags=rng.choice([[], ["PII"], ["PCI", "PII"]]),
        )
        for i in range(size)
    ]
    edges = {}
    for _ in range(size * 4):
        a, b = rng.choice(nodes), rng.choice(nodes)
        edge = Edge(
            source=a.id,
            target=b.id,
            type=rng.choice(list(EdgeType)),
            actions=rng.choice([[], ["x"], ["y", "x"]]),
            certainty=rng.choice(["confirmed", "conditional", "declared"]),
            evidence=[f"e{rng.randrange(5)}" for _ in range(rng.randrange(3))],
        )
        edges.setdefault(edge.id, edge)
    snapshot = GraphSnapshot(nodes=nodes, edges=list(edges.values()))
    return GraphSnapshot.model_validate(classification_edges(snapshot).model_dump())


def test_demo_parity():
    assert_parity(GraphSnapshot.model_validate(classification_edges(demo_snapshot()).model_dump()))
    assert compute_analysis(demo_snapshot()).high_blast_ids  # The fixture exercises high blast.


@pytest.mark.parametrize("seed", range(12))
def test_random_dense_graph_parity(seed):
    snapshot = random_graph(seed, 40 + seed * 5)
    reference = compute_analysis(snapshot)
    assert_parity(snapshot)
    if seed == 0:
        assert reference.findings and reference.high_blast_ids


@pytest.mark.parametrize(("size", "exposed"), [(1000, 0.05), (5000, 0.01)])
def test_enterprise_fixture_parity(size, exposed):
    generated = generate(size, exposed_rate=exposed)
    snapshot = classification_edges(
        GraphSnapshot.model_construct(nodes=generated.nodes, edges=generated.edges, warnings=[], source="s")
    )
    assert_parity(snapshot)


def test_empty_and_single_node_graphs():
    assert_parity(GraphSnapshot())
    assert_parity(GraphSnapshot(nodes=[Node(id="r", name="r", type=NodeType.ROLE)]))


def test_dangling_or_duplicate_rows_are_rejected():
    graph = CompactGraph()
    graph.add_node({"id": "a", "type": "S3Bucket"})
    with pytest.raises(ValueError):
        graph.add_node({"id": "a", "type": "S3Bucket"})
    with pytest.raises(ValueError):
        graph.add_edge({"source": "a", "target": "b", "type": "CAN_READ"})


def csr_row(graph: CompactGraph, csr, node: str) -> list[str]:
    start, end = csr.offsets[graph.index[node]], csr.offsets[graph.index[node] + 1]
    return [graph.ids[target] for target in csr.targets[start:end]]


def test_csr_is_built_once_sorted_distinct_and_traversal_only():
    graph = CompactGraph()
    for node_id in ("c", "a", "b"):
        graph.add_node({"id": node_id, "type": "CloudRole"})
    for source, target, kind in [
        ("c", "b", "ASSUMES_ROLE"),
        ("c", "a", "CAN_READ"),
        ("c", "b", "CAN_WRITE"),
        ("c", "c", "ASSUMES_ROLE"),
        ("a", "b", "STORES_PII"),
    ]:
        graph.add_edge({"source": source, "target": target, "type": kind})
    csr = graph.csr()
    assert graph.csr() is csr
    assert [csr_row(graph, csr, node) for node in "cab"] == [["a", "b", "c"], [], []]
    assert list(csr.expands) == [1, 0, 0]
    graph.add_edge({"source": "a", "target": "c", "type": "ASSUMES_ROLE"})
    fresh = graph.csr()
    assert fresh is not csr and csr_row(graph, fresh, "a") == ["c"]
