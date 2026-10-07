"""Blast-radius simulation.

``calculate`` is the in-process reference over a whole snapshot. ``simulate`` is the
request path: it runs the same BFS over a ``Reach`` (only the source's bounded
neighborhood, fetched from the graph store) and takes the revision-wide quantities
(node count, total asset weight) from the stored revision analysis, so a request
never loads the whole revision. Both produce identical results on every adapter:
paths follow the BFS discovery order of ``AnalysisIndex.paths`` (targets visited in
ascending ID order), and ``highlighted_edges`` lists edge IDs in ascending order.
"""

from collections import deque
from dataclasses import dataclass, field

from pydantic import BaseModel

from app.engine.analysis_index import WEIGHTS, AnalysisIndex
from app.graph.schema import DATA_TYPES, TRAVERSAL_TYPES, GraphSnapshot, Sensitivity

DATA = frozenset(kind.value for kind in DATA_TYPES)
WEIGHT = {level.value: weight for level, weight in WEIGHTS.items()}
EXPLANATION = (
    "Heuristic score: 85% sensitivity-weighted asset exposure + 15% normalized outgoing degree. "
    "Not a breach probability."
)


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


@dataclass
class Reach:
    """A source's bounded out-neighborhood within one revision and certainty mode.

    ``edges`` maps every expanded node (the source and each node first reached at
    fewer than ``hops`` hops) to its traversal relationships that pass the certainty
    filter, as ``(target ID, edge ID)``. ``kinds`` holds the node type of every
    reached node and ``sensitivity`` the sensitivity of every reached data asset.
    """

    source: str
    hops: int
    include_uncertain: bool
    edges: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    kinds: dict[str, str] = field(default_factory=dict)
    sensitivity: dict[str, str] = field(default_factory=dict)


def validate_hops(hops: int) -> None:
    if not 1 <= hops <= 5:
        raise ValueError("Hop count must be between 1 and 5")


def expand(adjacency, source: str, hops: int):
    """Hop-bounded BFS over ``adjacency(node) -> ascending distinct targets``.

    Yields ``(node, depth)`` for every node whose out-edges are needed (depth < hops)
    and returns paths in the discovery order of ``AnalysisIndex.paths``. Frontier
    fetching is left to ``adjacency`` so a graph store can batch it per level.
    """
    paths = {source: [source]}
    queue = deque([source])
    while queue:
        current = queue.popleft()
        if len(paths[current]) - 1 >= hops:
            continue
        for target in adjacency(current):
            if target not in paths:
                paths[target] = [*paths[current], target]
                queue.append(target)
    del paths[source]
    return paths


def simulate(reach: Reach, total_nodes: int, total_asset_weight: int) -> BlastRadius:
    """Blast radius from a fetched neighborhood and the revision's stored totals."""
    validate_hops(reach.hops)
    targets = {
        node: sorted({target for target, _ in relationships}) for node, relationships in reach.edges.items()
    }
    paths = expand(lambda node: targets.get(node, ()), reach.source, reach.hops)
    assets = [node for node in paths if reach.kinds[node] in DATA]
    affected = sum(WEIGHT[reach.sensitivity[node]] for node in assets)
    exposure = affected / total_asset_weight if total_asset_weight else 0
    centrality = len(targets.get(reach.source, ())) / (total_nodes - 1) if total_nodes > 1 else 1
    risk = min(100, round(100 * (0.85 * exposure + 0.15 * centrality))) if assets else 0
    pairs = {(a, b) for path in paths.values() for a, b in zip(path, path[1:], strict=False)}
    highlighted = sorted(
        {edge for node, edges in reach.edges.items() for target, edge in edges if (node, target) in pairs}
    )
    return BlastRadius(
        source=reach.source,
        max_hops=reach.hops,
        risk_score=risk,
        affected_nodes=sorted(paths),
        affected_assets=sorted(assets),
        paths=paths,
        highlighted_edges=highlighted,
        sensitivity_exposure=round(exposure, 4),
        centrality=round(centrality, 4),
        includes_uncertain=reach.include_uncertain,
        explanation=EXPLANATION,
    )


def snapshot_reach(snapshot: GraphSnapshot, source: str, hops: int, include_uncertain: bool) -> Reach | None:
    """``Reach`` from an in-memory snapshot (memory adapter, legacy fallback); None if absent."""
    validate_hops(hops)
    nodes = {node.id: node for node in snapshot.nodes}
    if source not in nodes:
        return None
    out: dict[str, list[tuple[str, str]]] = {}
    for edge in snapshot.edges:
        if edge.type in TRAVERSAL_TYPES and (include_uncertain or edge.certainty == "confirmed"):
            out.setdefault(edge.source, []).append((edge.target, edge.id))
    reach = Reach(source, hops, include_uncertain)
    adjacency = {node: sorted({target for target, _ in edges}) for node, edges in out.items()}

    def visit(node: str):
        reach.edges[node] = out.get(node, [])
        return adjacency.get(node, ())

    paths = expand(visit, source, hops)
    for node in [source, *paths]:
        kind = nodes[node].type
        reach.kinds[node] = kind.value
        if kind in DATA_TYPES:
            reach.sensitivity[node] = Sensitivity(nodes[node].sensitivity).value
    return reach


def shortest_paths(
    snapshot: GraphSnapshot,
    source: str,
    max_hops: int = 5,
    include_uncertain: bool = False,
    index: AnalysisIndex | None = None,
) -> dict[str, list[str]]:
    prepared = index or AnalysisIndex.build(snapshot, include_uncertain)
    prepared.validate_for(snapshot, include_uncertain)
    return prepared.paths(source, max_hops)


def calculate(
    snapshot: GraphSnapshot,
    source: str,
    max_hops: int = 5,
    include_uncertain: bool = False,
    paths: dict[str, list[str]] | None = None,
    index: AnalysisIndex | None = None,
) -> BlastRadius:
    """Reference blast radius over a whole snapshot (one index build per call)."""
    prepared = index or AnalysisIndex.build(snapshot, include_uncertain)
    prepared.validate_for(snapshot, include_uncertain)
    nodes = prepared.nodes
    if source not in nodes:
        raise KeyError(source)
    paths = prepared.paths(source, max_hops) if paths is None else paths
    assets = [node_id for node_id in paths if nodes[node_id].type in DATA_TYPES]
    risk_score, exposure, centrality = prepared.score(source, paths)
    pairs = {(a, b) for path in paths.values() for a, b in zip(path, path[1:], strict=False)}
    highlighted = sorted({e.id for pair in pairs for e in prepared.edge_pairs.get(pair, ())})
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
        explanation=EXPLANATION,
    )


def apply_overlay(
    reach: Reach,
    removed: set[tuple[str, str]] = frozenset(),
    edge_ids: set[str] = frozenset(),
    disabled: set[str] = frozenset(),
) -> Reach:
    """The neighborhood with edges removed (by ``(source, target)`` pair or edge ID) and nodes
    disabled (no edges into or out of them).

    Exact for what-if simulation: removal only shrinks reach, and every node the reduced
    graph reaches within the hop bound was reached at the same or a smaller depth before,
    so its out-edges are already in ``reach.edges``.
    """
    edges: dict[str, list[tuple[str, str]]] = {}
    for node, relationships in reach.edges.items():
        if node in disabled:
            edges[node] = []
            continue
        edges[node] = [
            (target, edge)
            for target, edge in relationships
            if target not in disabled and (node, target) not in removed and edge not in edge_ids
        ]
    return Reach(reach.source, reach.hops, reach.include_uncertain, edges, reach.kinds, reach.sensitivity)
