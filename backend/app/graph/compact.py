"""Compact whole-revision analysis for publication, built from staged rows.

``CompactGraph`` holds only what the publish-time analysis needs (integer node
indices, a few per-node attributes, edge endpoints/certainty/evidence), so the
worker never materializes a Pydantic ``GraphSnapshot`` of a large revision. Its
``analyze`` reproduces ``app.graph.analysis.compute_analysis`` exactly (same
overview, findings in API order, totals, asset weight and high-blast IDs); parity
is asserted by tests on generated and edge-case graphs. A full CSR rewrite and
graph-free ``/simulate`` are Phase 3.
"""

import hashlib
from array import array

from app.engine.analysis_index import WEIGHTS
from app.engine.toxic_combos import Finding
from app.graph.exploration import RevisionTotals
from app.graph.schema import DATA_TYPES, IDENTITY_TYPES, TRAVERSAL_TYPES, GraphSnapshot, NodeType

DATA = frozenset(kind.value for kind in DATA_TYPES)
IDENTITY = frozenset(kind.value for kind in IDENTITY_TYPES)
TRAVERSAL = frozenset(kind.value for kind in TRAVERSAL_TYPES)
WEIGHT = {level.value: weight for level, weight in WEIGHTS.items()}
SENSITIVE = frozenset({"confidential", "restricted"})
MAX_HOPS = 5
HIGH_BLAST_THRESHOLD = 70
SENSITIVITY_LEVELS = ["public", "internal", "confidential", "restricted"]
RECOMMENDATION = (
    "Authenticate the entry point, restrict role trust and tool scope, and review data access permissions."
)


class CompactGraph:
    """Append nodes, then edges (endpoints must already exist), in revision order."""

    def __init__(self):
        self.ids: list[str] = []
        self.index: dict[str, int] = {}
        self.types: list[str] = []
        self.sensitivity: list[str] = []
        self.entry = bytearray()  # internet_exposed and not authenticated
        self.privileged = bytearray()
        self.encrypted = bytearray()
        self.accounts: set[str] = set()
        # Per-node display name and account (interned) for publish-time clustering.
        self.names: list[str] = []
        self.account: list[str] = []
        self._interned: dict[str, str] = {}
        self.edge_source = array("l")
        self.edge_target = array("l")
        self.edge_traversal = bytearray()
        self.edge_confirmed = bytearray()
        self.edge_evidence: list[tuple[str, ...]] = []

    @classmethod
    def from_snapshot(cls, snapshot: GraphSnapshot) -> "CompactGraph":
        graph = cls()
        for node in snapshot.nodes:
            graph.add_node(node.model_dump(mode="json"))
        for edge in snapshot.edges:
            graph.add_edge(edge.model_dump(mode="json"))
        return graph

    def add_node(self, node: dict) -> None:
        node_id = node["id"]
        if node_id in self.index:
            raise ValueError("Node IDs must be unique within a snapshot")
        self.index[node_id] = len(self.ids)
        self.ids.append(node_id)
        self.types.append(node["type"])
        self.sensitivity.append(node.get("sensitivity", "internal"))
        self.entry.append(bool(node.get("internet_exposed", False)) and not node.get("authenticated", True))
        self.privileged.append(bool(node.get("privileged", False)))
        self.encrypted.append(bool(node.get("encrypted", True)))
        account = node.get("account_id") or ""
        if account:
            self.accounts.add(account)
        self.account.append(self._interned.setdefault(account, account))
        self.names.append(node.get("name") or node_id)

    def add_edge(self, edge: dict) -> None:
        try:
            source, target = self.index[edge["source"]], self.index[edge["target"]]
        except KeyError:
            raise ValueError("Every edge endpoint must exist in this snapshot") from None
        traversal = edge["type"] in TRAVERSAL
        self.edge_source.append(source)
        self.edge_target.append(target)
        self.edge_traversal.append(traversal)
        self.edge_confirmed.append(edge.get("certainty", "confirmed") == "confirmed")
        # Evidence is only ever quoted from traversal edges on finding paths.
        self.edge_evidence.append(tuple(edge.get("evidence", ())) if traversal else ())

    @property
    def node_count(self) -> int:
        return len(self.ids)

    @property
    def edge_count(self) -> int:
        return len(self.edge_source)

    def _adjacency(self) -> list[tuple[int, ...]]:
        # Same order as AnalysisIndex: distinct traversal targets sorted by node ID.
        rank = array("l", bytes(8 * len(self.ids)))
        for position, node in enumerate(sorted(range(len(self.ids)), key=self.ids.__getitem__)):
            rank[node] = position
        targets: dict[int, set[int]] = {}
        for edge in range(len(self.edge_source)):
            if self.edge_traversal[edge]:
                targets.setdefault(self.edge_source[edge], set()).add(self.edge_target[edge])
        adjacency: list[tuple[int, ...]] = [()] * len(self.ids)
        for source, reached in targets.items():
            adjacency[source] = tuple(sorted(reached, key=rank.__getitem__))
        return adjacency

    def _paths(self, adjacency, source: int) -> dict[int, int]:
        """BFS parents within MAX_HOPS, discovery order identical to AnalysisIndex.paths."""
        parent = {source: -1}
        frontier = [source]
        for _ in range(MAX_HOPS):
            following = []
            for current in frontier:
                for target in adjacency[current]:
                    if target not in parent:
                        parent[target] = current
                        following.append(target)
            if not following:
                break
            frontier = following
        return parent

    def analyze(self):
        from app.graph.analysis import ComputedAnalysis

        count = len(self.ids)
        adjacency = self._adjacency()
        is_data = bytearray(kind in DATA for kind in self.types)
        weight = array("l", (WEIGHT[level] if is_data[i] else 0 for i, level in enumerate(self.sensitivity)))
        total_weight = sum(weight)

        # High blast radius: 5-hop reach per identity, scored like AnalysisIndex.score.
        high_blast = []
        stamp = array("l", [-1]) * count
        for node in range(count):
            if self.types[node] not in IDENTITY:
                continue
            stamp[node] = node
            frontier, affected, assets = [node], 0, False
            for _ in range(MAX_HOPS):
                following = []
                for current in frontier:
                    for target in adjacency[current]:
                        if stamp[target] != node:
                            stamp[target] = node
                            following.append(target)
                            if is_data[target]:
                                assets = True
                                affected += weight[target]
                if not following:
                    break
                frontier = following
            if not assets:
                continue
            exposure = affected / total_weight if total_weight else 0
            centrality = len(adjacency[node]) / (count - 1) if count > 1 else 1
            if min(100, round(100 * (0.85 * exposure + 0.15 * centrality))) >= HIGH_BLAST_THRESHOLD:
                high_blast.append(self.ids[node])
        high_blast.sort()

        # Toxic combinations from every exposed, unauthenticated entry point.
        candidates = []
        for source in range(count):
            if not self.entry[source]:
                continue
            parent = self._paths(adjacency, source)
            for target in parent:
                if target == source or not is_data[target]:
                    continue
                if not (self.sensitivity[target] in SENSITIVE or not self.encrypted[target]):
                    continue
                path = [target]
                while parent[path[-1]] != -1:
                    path.append(parent[path[-1]])
                path.reverse()
                candidates.append((source, target, path))
        needed = {(a, b) for _, _, path in candidates for a, b in zip(path, path[1:], strict=False)}
        pairs: dict[tuple[int, int], list[int]] = {}
        if needed:
            for edge in range(len(self.edge_source)):
                if self.edge_traversal[edge]:
                    pair = self.edge_source[edge], self.edge_target[edge]
                    if pair in needed:
                        pairs.setdefault(pair, []).append(edge)
        findings = []
        for source, target, path in candidates:
            privileged = any(self.privileged[node] for node in path)
            matched, uncertain = [], False
            for a, b in zip(path, path[1:], strict=False):
                options = pairs.get((a, b), [])
                confirmed = [edge for edge in options if self.edge_confirmed[edge]]
                uncertain |= not bool(confirmed)
                for edge in confirmed or options:
                    matched.extend(self.edge_evidence[edge])
            source_id, target_id = self.ids[source], self.ids[target]
            findings.append(
                Finding(
                    id=hashlib.sha256((source_id + "\0" + target_id).encode()).hexdigest()[:20],
                    title="Privileged agent access to sensitive data"
                    if privileged
                    else "Exposed agent access to sensitive data",
                    severity="critical" if privileged and not uncertain else "high",
                    source=source_id,
                    target=target_id,
                    path=[self.ids[node] for node in path],
                    evidence=["Public endpoint is declared unauthenticated", *matched[:20]],
                    conditional=uncertain,
                    recommendation=RECOMMENDATION,
                )
            )
        findings.sort(key=lambda finding: (finding.severity != "critical", finding.id))

        roles = bytearray(kind == NodeType.ROLE.value for kind in self.types)
        confirmed_edges = sum(self.edge_confirmed)
        data_levels = [self.sensitivity[i] for i in range(count) if is_data[i]]
        overview = {
            "total_nhis": sum(kind in IDENTITY for kind in self.types),
            "ai_agents": sum(kind == NodeType.AGENT.value for kind in self.types),
            "toxic_combinations": len(findings),
            "high_blast_radius": len(high_blast),
            "data_assets": len(data_levels),
            "confirmed_edges": confirmed_edges,
            "uncertain_edges": len(self.edge_source) - confirmed_edges,
            "accounts": sorted(self.accounts),
            "sensitivity": {level: data_levels.count(level) for level in SENSITIVITY_LEVELS},
        }
        totals = RevisionTotals(
            nodes=count,
            edges=len(self.edge_source),
            roles=sum(roles),
            role_edges=sum(
                1
                for edge in range(len(self.edge_source))
                if self.edge_traversal[edge]
                and roles[self.edge_source[edge]]
                and roles[self.edge_target[edge]]
            ),
        )
        from app.graph.analysis import sample_ids

        return ComputedAnalysis(overview, findings, totals, total_weight, high_blast, sample_ids(self.ids))
