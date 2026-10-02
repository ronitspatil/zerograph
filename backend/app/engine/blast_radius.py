from pydantic import BaseModel

from app.engine.analysis_index import AnalysisIndex
from app.graph.schema import DATA_TYPES, TRAVERSAL_TYPES, GraphSnapshot


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
    prepared = index or AnalysisIndex.build(snapshot, include_uncertain)
    prepared.validate_for(snapshot, include_uncertain)
    nodes = prepared.nodes
    if source not in nodes:
        raise KeyError(source)
    paths = prepared.paths(source, max_hops) if paths is None else paths
    assets = [node_id for node_id in paths if nodes[node_id].type in DATA_TYPES]
    risk_score, exposure, centrality = prepared.score(source, paths)
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
