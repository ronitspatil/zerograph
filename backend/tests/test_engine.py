import pytest
from pydantic import ValidationError

from app.engine.blast_radius import calculate, shortest_paths
from app.engine.toxic_combos import detect
from app.graph.demo import demo_snapshot
from app.graph.schema import Edge, EdgeType, GraphSnapshot, Node, NodeType


def test_directed_transitive_blast_radius():
    graph = demo_snapshot()
    result = calculate(graph, "agent:support", 5)
    assert result.affected_assets == ["db:billing", "db:customers", "s3:exports"]
    assert result.paths["db:customers"] == ["agent:support", "mcp:crm", "role:admin", "db:customers"]
    assert "human:operator" not in result.affected_nodes
    assert 70 <= result.risk_score <= 100
    assert calculate(graph, "db:customers").affected_nodes == []


def test_hop_bounds_and_missing_source():
    graph = demo_snapshot()
    assert calculate(graph, "agent:support", 2).affected_assets == []
    with pytest.raises(ValueError):
        shortest_paths(graph, "agent:support", 6)
    with pytest.raises(KeyError):
        calculate(graph, "missing")


def test_cycles_terminate_and_shortest_path_is_stable():
    graph = GraphSnapshot(
        nodes=[Node(id=n, name=n, type=NodeType.SERVICE) for n in "abcd"],
        edges=[
            Edge(source=a, target=b, type=EdgeType.ASSUMES)
            for a, b in [("a", "b"), ("b", "a"), ("a", "c"), ("c", "d"), ("b", "d")]
        ],
    )
    paths = shortest_paths(graph, "a")
    assert paths["d"] == ["a", "b", "d"]
    assert "a" not in paths


def test_uncertain_shortcut_does_not_hide_confirmed_path():
    graph = demo_snapshot()
    graph.edges.append(
        Edge(source="agent:support", target="db:customers", type=EdgeType.READ, certainty="conditional")
    )
    assert len(shortest_paths(graph, "agent:support")["db:customers"]) == 4
    assert len(shortest_paths(graph, "agent:support", include_uncertain=True)["db:customers"]) == 2


def test_annotation_edges_are_not_access():
    graph = demo_snapshot()
    graph.edges = [Edge(source="agent:support", target="db:customers", type=EdgeType.PII)]
    assert calculate(graph, "agent:support").affected_assets == []


def test_toxic_findings_include_path_and_evidence():
    findings = detect(demo_snapshot())
    assert len(findings) == 3
    assert all(f.severity == "critical" for f in findings)
    assert all(f.evidence and f.path for f in findings)
    graph = demo_snapshot()
    graph.nodes[0].authenticated = True
    assert detect(graph) == []


def test_uncertain_path_is_labeled():
    graph = demo_snapshot()
    graph.edges[0].certainty = "declared"
    assert not calculate(graph, "agent:support").affected_assets
    assert len(calculate(graph, "agent:support", include_uncertain=True).affected_assets) == 3
    assert all(f.conditional for f in detect(graph))


def test_graph_rejects_dangling_and_duplicate_ids():
    with pytest.raises(ValidationError):
        GraphSnapshot(nodes=[], edges=[Edge(source="missing", target="other", type=EdgeType.READ)])
    with pytest.raises(ValidationError):
        GraphSnapshot(nodes=[Node(id="a", name="a", type=NodeType.AGENT)] * 2)
