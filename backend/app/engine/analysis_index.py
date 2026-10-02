"""Request-local graph preparation, with no cross-tenant or revision cache."""

from collections import defaultdict, deque
from dataclasses import dataclass

from app.graph.schema import DATA_TYPES, TRAVERSAL_TYPES, Edge, GraphSnapshot, Node, Sensitivity

WEIGHTS = {
    Sensitivity.PUBLIC: 1,
    Sensitivity.INTERNAL: 2,
    Sensitivity.CONFIDENTIAL: 5,
    Sensitivity.RESTRICTED: 10,
}


@dataclass(frozen=True)
class AnalysisIndex:
    snapshot: GraphSnapshot
    includes_uncertain: bool
    nodes: dict[str, Node]
    adjacency: dict[str, tuple[str, ...]]
    edge_pairs: dict[tuple[str, str], list[Edge]]
    total_asset_weight: int

    @classmethod
    def build(cls, snapshot: GraphSnapshot, include_uncertain: bool = False) -> "AnalysisIndex":
        nodes = {node.id: node for node in snapshot.nodes}
        adjacency: dict[str, set[str]] = defaultdict(set)
        pairs: dict[tuple[str, str], list[Edge]] = defaultdict(list)
        for edge in snapshot.edges:
            if edge.type not in TRAVERSAL_TYPES:
                continue
            if not include_uncertain and edge.certainty != "confirmed":
                continue
            adjacency[edge.source].add(edge.target)
            pairs[(edge.source, edge.target)].append(edge)
        return cls(
            snapshot,
            include_uncertain,
            nodes,
            {node: tuple(sorted(targets)) for node, targets in adjacency.items()},
            dict(pairs),
            sum(WEIGHTS[node.sensitivity] for node in snapshot.nodes if node.type in DATA_TYPES),
        )

    def validate_for(self, snapshot: GraphSnapshot, include_uncertain: bool) -> None:
        if self.snapshot is not snapshot or self.includes_uncertain != include_uncertain:
            raise ValueError("Analysis index must match the exact snapshot and certainty mode")

    def paths(self, source: str, max_hops: int = 5) -> dict[str, list[str]]:
        if not 1 <= max_hops <= 5:
            raise ValueError("Hop count must be between 1 and 5")
        if source not in self.nodes:
            raise KeyError(source)
        paths = {source: [source]}
        queue = deque([source])
        while queue:
            current = queue.popleft()
            if len(paths[current]) - 1 >= max_hops:
                continue
            for target in self.adjacency.get(current, ()):
                if target not in paths:
                    paths[target] = [*paths[current], target]
                    queue.append(target)
        return {node: path for node, path in paths.items() if node != source}

    def score(self, source: str, paths: dict[str, list[str]]) -> tuple[int, float, float]:
        if source not in self.nodes:
            raise KeyError(source)
        assets = [node for node in paths if self.nodes[node].type in DATA_TYPES]
        affected_weight = sum(WEIGHTS[self.nodes[node].sensitivity] for node in assets)
        exposure = affected_weight / self.total_asset_weight if self.total_asset_weight else 0
        # NetworkX normalized outgoing degree semantics, including singleton/self-loop cases.
        centrality = len(self.adjacency.get(source, ())) / (len(self.nodes) - 1) if len(self.nodes) > 1 else 1
        risk = round(100 * (0.85 * exposure + 0.15 * centrality)) if assets else 0
        return min(100, risk), exposure, centrality
