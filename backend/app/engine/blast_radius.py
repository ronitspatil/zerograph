from collections import defaultdict, deque

import networkx as nx
from pydantic import BaseModel

from app.graph.schema import DATA_TYPES, TRAVERSAL_TYPES, GraphSnapshot, Sensitivity

WEIGHTS = {
    Sensitivity.PUBLIC: 1,
    Sensitivity.INTERNAL: 2,
    Sensitivity.CONFIDENTIAL: 5,
    Sensitivity.RESTRICTED: 10,
}


class BlastRadius(BaseModel):
    source: str
    max_hops: int
    risk_score: int
    affected_nodes: list[str]
    affected_assets: list[str]
    paths: dict[str, list[str]]
    highlighted_edges: list[str]
    sensitivity_exposure: float
    centrality: float
    includes_uncertain: bool
    explanation: str


def shortest_paths(
    snapshot: GraphSnapshot, source: str, max_hops: int = 5, include_uncertain: bool = False
) -> dict[str, list[str]]:
    if not 1 <= max_hops <= 5:
        raise ValueError("Hop count must be between 1 and 5")
    if source not in {n.id for n in snapshot.nodes}:
        raise KeyError(source)
    adjacency: dict[str, set[str]] = defaultdict(set)
    for edge in snapshot.edges:
        if edge.type in TRAVERSAL_TYPES and (include_uncertain or edge.certainty == "confirmed"):
            adjacency[edge.source].add(edge.target)
    paths = {source: [source]}
    queue = deque([source])
    while queue:
        current = queue.popleft()
        if len(paths[current]) - 1 >= max_hops:
            continue
        for target in sorted(adjacency[current]):
            if target not in paths:
                paths[target] = [*paths[current], target]
                queue.append(target)
    return {node: path for node, path in paths.items() if node != source}


def calculate(
    snapshot: GraphSnapshot,
    source: str,
    max_hops: int = 5,
    include_uncertain: bool = False,
    paths: dict[str, list[str]] | None = None,
) -> BlastRadius:
    nodes = {n.id: n for n in snapshot.nodes}
    if source not in nodes:
        raise KeyError(source)
    paths = shortest_paths(snapshot, source, max_hops, include_uncertain) if paths is None else paths
    assets = [node_id for node_id in paths if nodes[node_id].type in DATA_TYPES]
    total_weight = sum(WEIGHTS[n.sensitivity] for n in snapshot.nodes if n.type in DATA_TYPES)
    affected_weight = sum(WEIGHTS[nodes[node_id].sensitivity] for node_id in assets)
    exposure = affected_weight / total_weight if total_weight else 0
    graph = nx.DiGraph()
    graph.add_nodes_from(nodes)
    graph.add_edges_from(
        (e.source, e.target)
        for e in snapshot.edges
        if e.type in TRAVERSAL_TYPES and (include_uncertain or e.certainty == "confirmed")
    )
    centrality = nx.out_degree_centrality(graph).get(source, 0)
    risk_score = round(100 * (0.85 * exposure + 0.15 * centrality)) if assets else 0
    pairs = {(a, b) for path in paths.values() for a, b in zip(path, path[1:], strict=False)}
    highlighted = [
        e.id
        for e in snapshot.edges
        if (e.source, e.target) in pairs
        and e.type in TRAVERSAL_TYPES
        and (include_uncertain or e.certainty == "confirmed")
    ]
    return BlastRadius(
        source=source,
        max_hops=max_hops,
        risk_score=min(100, risk_score),
        affected_nodes=sorted(paths),
        affected_assets=sorted(assets),
        paths=paths,
        highlighted_edges=highlighted,
        sensitivity_exposure=round(exposure, 4),
        centrality=round(centrality, 4),
        includes_uncertain=include_uncertain,
        explanation="Heuristic score: 85% sensitivity-weighted asset exposure + 15% normalized outgoing degree. Not a breach probability.",
    )
