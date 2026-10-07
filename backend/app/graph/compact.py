"""Compact whole-revision analysis for publication, built from staged rows.

``CompactGraph`` holds only what the publish-time analysis needs (integer node
indices, a few per-node attributes, edge endpoints/certainty/evidence), so the
worker never materializes a Pydantic ``GraphSnapshot`` of a large revision. Its
``analyze`` reproduces ``app.graph.analysis.compute_analysis`` exactly (same
overview, findings in API order, totals, asset weight and high-blast IDs); parity
is asserted by tests on generated and edge-case graphs. Traversal adjacency is one
CSR (``csr()``), built once and shared by every BFS of the analysis; publish-time
clustering reads the same edge arrays. Publish-time topic analysis
(``app.graph.topics``) also reads each node's raw tags, provider and topic hints
from metadata, and each edge's type and actions; repeated tuples are interned so
a 100k revision adds only a few MB.
"""

import hashlib
import re
from array import array

from app.engine.analysis_index import WEIGHTS
from app.engine.toxic_combos import Finding
from app.graph.exploration import RevisionTotals
from app.graph.sample import select_sample
from app.graph.schema import DATA_TYPES, NHI_TYPES, TRAVERSAL_TYPES, EdgeType, GraphSnapshot, NodeType

DATA = frozenset(kind.value for kind in DATA_TYPES)
IDENTITY = frozenset(kind.value for kind in NHI_TYPES)
TRAVERSAL = frozenset(kind.value for kind in TRAVERSAL_TYPES)
WEIGHT = {level.value: weight for level, weight in WEIGHTS.items()}
SENSITIVE = frozenset({"confidential", "restricted"})
MAX_HOPS = 5
HIGH_BLAST_THRESHOLD = 70
SENSITIVITY_LEVELS = ["public", "internal", "confidential", "restricted"]
# Edge types by code (``CompactGraph.edge_kind``); new types append.
EDGE_KINDS = [kind.value for kind in EdgeType]
EDGE_CODE = {kind: code for code, kind in enumerate(EDGE_KINDS)}
# Metadata keys kept as topic hints (string values only), in priority order.
HINT_KEYS = ("topic", "app", "application", "project", "workload", "team", "service", "data_category")
NO_STRINGS: tuple[str, ...] = ()
# Edge certainty codes (``CompactGraph.edge_certainty``): recomputing an edge ID needs the value.
CERTAINTIES = ("confirmed", "conditional", "declared")
CERTAINTY_CODE = {value: code for code, value in enumerate(CERTAINTIES)}
# Optimizer safety flags per node (``CompactGraph.safety``, sparse bitmask): identities and
# resources whose access changes are never recommended automatically (``app.graph.proposals``).
SERVICE_LINKED, BREAK_GLASS, EXEMPT, KMS = 1, 2, 4, 8
_BREAK_GLASS = re.compile(
    r"break[-_ ]?glass|emergency|disaster[-_ ]?recovery|(?:^|[^a-z0-9])dr(?:[^a-z0-9]|$)", re.IGNORECASE
)
# Scheduled or seasonal identities need a longer window than the attested one, or an exemption.
_EXEMPT = re.compile(
    r"^(?:zg[-_]?optimizer[=:]\s*(?:exempt|skip|manual)|(?:schedule|cadence)[=:]\s*"
    r"(?:seasonal|scheduled|quarterly|annual|yearly|monthly)|seasonal(?:[=:]\s*true)?|scheduled(?:[=:]\s*true)?)$",
    re.IGNORECASE,
)
SERVICE_LINKED_TAG = re.compile(r"^(?:aws[-_:])?service[-_]linked(?:[=:]\s*true)?$", re.IGNORECASE)


def safety_flags(node: dict) -> int:
    """Never-auto categories of a node from its ID, name, tags and metadata (deterministic)."""
    node_id, name = node["id"], node.get("name") or ""
    tags = node.get("tags") or ()
    metadata = node.get("metadata") or {}
    flags = 0
    if (
        ":role/aws-service-role/" in node_id
        or metadata.get("scp_exempt_service_linked_role") is True
        or any(SERVICE_LINKED_TAG.match(tag.strip()) for tag in tags)
    ):
        flags |= SERVICE_LINKED
    if any(_BREAK_GLASS.search(value) for value in (node_id, name, *tags)):
        flags |= BREAK_GLASS
    if metadata.get("optimizer_exempt") is True or any(_EXEMPT.match(tag.strip()) for tag in tags):
        flags |= EXEMPT
    service = metadata.get("service")
    if ":kms:" in node_id or (isinstance(service, str) and service.strip().lower() == "kms"):
        flags |= KMS
    return flags


RECOMMENDATION = (
    "Authenticate the entry point, restrict role trust and tool scope, and review data access permissions."
)


class Csr:
    """Distinct traversal targets per node, sorted by node ID, as two flat arrays."""

    __slots__ = ("offsets", "targets", "expands")

    def __init__(self, offsets: array, targets: array):
        self.offsets, self.targets = offsets, targets
        # 1 where a node has traversal targets: BFS frontiers skip sinks (most data assets).
        self.expands = bytearray(offsets[node + 1] > offsets[node] for node in range(len(offsets) - 1))

    @classmethod
    def build(cls, graph: "CompactGraph") -> "Csr":
        count = len(graph.ids)
        rank = array("l", bytes(8 * count))
        for position, node in enumerate(sorted(range(count), key=graph.ids.__getitem__)):
            rank[node] = position
        # Counting sort of traversal edges by source, then by target rank within a row.
        degree = array("l", bytes(8 * (count + 1)))
        traversal, sources, targets = graph.edge_traversal, graph.edge_source, graph.edge_target
        for edge in range(len(sources)):
            if traversal[edge]:
                degree[sources[edge] + 1] += 1
        for node in range(count):
            degree[node + 1] += degree[node]
        slots = array("l", degree)
        flat = array("l", bytes(8 * degree[count]))
        for edge in range(len(sources)):
            if traversal[edge]:
                source = sources[edge]
                flat[slots[source]] = targets[edge]
                slots[source] += 1
        offsets = array("l", bytes(8 * (count + 1)))
        distinct = array("l")
        for node in range(count):
            start, end = degree[node], degree[node + 1]
            if end - start == 1:
                distinct.append(flat[start])
            elif end > start:
                distinct.extend(sorted(set(flat[start:end]), key=rank.__getitem__))
            offsets[node + 1] = len(distinct)
        return cls(offsets, distinct)


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
        # Topic analysis inputs: raw tags (``key=value`` strings kept verbatim), provider,
        # and string metadata hints under HINT_KEYS as ``key=value`` (sparse).
        self.tags: list[tuple[str, ...]] = []
        self.provider: list[str] = []
        self.hints: dict[int, tuple[str, ...]] = {}
        # Last-used hints (sparse): ``RoleLastUsed`` ISO date from metadata. Hints only.
        self.last_used: dict[int, str] = {}
        self._tuples: dict[tuple[str, ...], tuple[str, ...]] = {}
        # Optimizer safety flags (sparse bitmask, see ``safety_flags``).
        self.safety: dict[int, int] = {}
        self.edge_source = array("l")
        self.edge_target = array("l")
        self.edge_traversal = bytearray()
        self.edge_confirmed = bytearray()
        self.edge_evidence: list[tuple[str, ...]] = []
        self.edge_kind = bytearray()  # EDGE_CODE of the edge type
        self.edge_actions: list[tuple[str, ...]] = []
        self.edge_certainty = bytearray()  # CERTAINTY_CODE
        self._csr: Csr | None = None
        self._csr_edges = -1

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
        self.tags.append(self._tuple(node.get("tags") or ()))
        flags = safety_flags(node)
        if flags:
            self.safety[len(self.ids) - 1] = flags
        provider = node.get("provider") or ""
        self.provider.append(self._interned.setdefault(provider, provider))
        metadata = node.get("metadata") or {}
        if metadata:
            hints = tuple(
                f"{key}={metadata[key]}"
                for key in HINT_KEYS
                if isinstance(metadata.get(key), str) and metadata[key].strip()
            )
            if hints:
                self.hints[len(self.ids) - 1] = self._tuple(hints)
            last_used = metadata.get("role_last_used")
            if isinstance(last_used, str) and last_used:
                self.last_used[len(self.ids) - 1] = last_used[:64]

    def _tuple(self, values) -> tuple[str, ...]:
        """One shared tuple per distinct value list (tags and actions repeat heavily)."""
        if not values:
            return NO_STRINGS
        key = tuple(values)
        return self._tuples.setdefault(key, key)

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
        self.edge_kind.append(EDGE_CODE.get(edge["type"], 255))
        self.edge_actions.append(self._tuple(edge.get("actions") or ()))
        self.edge_certainty.append(CERTAINTY_CODE.get(edge.get("certainty", "confirmed"), 0))

    def edge_id(self, edge: int) -> str:
        """The edge's stable ID, as ``app.graph.schema.Edge.id`` computes it."""
        content = (
            f"{self.ids[self.edge_source[edge]]}\0{EDGE_KINDS[self.edge_kind[edge]]}\0"
            f"{self.ids[self.edge_target[edge]]}\0{','.join(sorted(self.edge_actions[edge]))}\0"
            f"{CERTAINTIES[self.edge_certainty[edge]]}"
        )
        return hashlib.sha256(content.encode()).hexdigest()[:24]

    @property
    def node_count(self) -> int:
        return len(self.ids)

    @property
    def edge_count(self) -> int:
        return len(self.edge_source)

    def csr(self) -> "Csr":
        """Traversal adjacency in compressed sparse row form, built once per graph.

        ``targets[offsets[n]:offsets[n + 1]]`` are the distinct traversal targets of
        node ``n`` in ascending node-ID order (the visiting order of
        ``AnalysisIndex.paths``). Two flat integer arrays instead of a tuple per node:
        a few MB at 100k nodes, and reads never touch per-element reference counts.
        """
        if self._csr is None or self._csr_edges != len(self.edge_source):
            self._csr = Csr.build(self)
            self._csr_edges = len(self.edge_source)
        return self._csr

    def _paths(self, csr: "Csr", source: int) -> dict[int, int]:
        """BFS parents within MAX_HOPS, discovery order identical to AnalysisIndex.paths."""
        offsets, targets, expands = csr.offsets, csr.targets, csr.expands
        parent = {source: -1}
        frontier = [source]
        for _ in range(MAX_HOPS):
            following = []
            for current in frontier:
                for target in targets[offsets[current] : offsets[current + 1]]:
                    if target not in parent:
                        parent[target] = current
                        if expands[target]:  # Sinks are discovered but never expanded.
                            following.append(target)
            if not following:
                break
            frontier = following
        return parent

    def analyze(self):
        from app.graph.analysis import ComputedAnalysis

        count = len(self.ids)
        csr = self.csr()
        offsets, targets, expands = csr.offsets, csr.targets, csr.expands
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
                    for target in targets[offsets[current] : offsets[current + 1]]:
                        if stamp[target] != node:
                            stamp[target] = node
                            if expands[target]:
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
            centrality = (offsets[node + 1] - offsets[node]) / (count - 1) if count > 1 else 1
            if min(100, round(100 * (0.85 * exposure + 0.15 * centrality))) >= HIGH_BLAST_THRESHOLD:
                high_blast.append(self.ids[node])
        high_blast.sort()

        # Toxic combinations from every exposed, unauthenticated entry point.
        candidates = []
        for source in range(count):
            if not self.entry[source]:
                continue
            parent = self._paths(csr, source)
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
        sample = select_sample(
            self.ids,
            self.types,
            self.edge_source,
            self.edge_target,
            (finding.path for finding in findings),
            high_blast,
        )
        return ComputedAnalysis(overview, findings, totals, total_weight, high_blast, sample)
