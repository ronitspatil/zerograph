"""Publish-time hierarchical clusters for the global map (structure, not permissions).

At publication the worker partitions the revision's undirected topology (edge
multiplicity as weight) with seeded Louvain, from the ``CompactGraph`` it already
holds; no Pydantic snapshot is materialized. The result is a bounded hierarchy:

* the top level holds at most ``MAX_TOP`` clusters: Louvain communities, plus one
  bucket per node type for entities with no relationships at all, and (only when
  needed to stay within the bound) "small groups" bins that pack the smallest
  communities of one dominant type together;
* a cluster with more than ``MAX_MEMBERS`` entities is split again (Louvain on its
  induced subgraph; ordered parts when it cannot be split), into at most
  ``MAX_CHILDREN`` children, so every expansion is bounded;
* every leaf holds at most ``MAX_MEMBERS`` entities.

Cluster IDs are carried over from the previous revision by best-Jaccard matching
at each depth, so the same structure keeps its ID across republications. Rows are
stored in PostgreSQL keyed by (tenant, revision), written in the publication
transaction, deleted by retention with the revision and included in the database
backup. Clusters group entities by graph structure only; they are not permission
or trust boundaries, and membership implies no access.
"""

import argparse
import hashlib
import json
import random
import time
from array import array
from collections import Counter, deque
from dataclasses import dataclass, field

from pydantic import BaseModel
from sqlalchemy import delete, insert, select, text
from sqlalchemy.orm import Session

from app.db.locks import acquire_publication_lock
from app.db.models import RevisionCluster, RevisionClusterLink, RevisionClusterMember, RevisionClusterSummary
from app.db.session import session_factory
from app.graph.compact import CompactGraph
from app.graph.repository import get_graph_store
from app.graph.schema import Node

# Bump when the partition or stored fields change: other versions read as missing.
CLUSTER_VERSION = 1
ALGORITHM = "louvain"
SEED = 7
MAX_TOP = 300
MAX_CHILDREN = 300
MAX_MEMBERS = 500
MAX_DEPTH = 6
MIN_JACCARD = 0.3
INERTIA = 1.0  # Warm-start move margin, in edge-weight units (one relationship).
WARM_MIN_KNOWN = 0.5  # Warm-start only when most members existed in the previous revision.
MAX_PASSES = 50  # Local-move sweeps per level; guards against float-tie cycling.
ACCOUNT_FACETS = 12
NO_ACCOUNT = "(none)"
OTHER_ACCOUNTS = "(other)"
STRUCTURAL_NOTICE = (
    "Clusters group entities by graph structure only. They are not permission or trust boundaries; "
    "membership in a cluster implies no access."
)


@dataclass
class Hierarchy:
    """Clusters by index (parents before children); leaves list their members by node index."""

    parent: list[int] = field(default_factory=list)
    depth: list[int] = field(default_factory=list)
    kind: list[str] = field(default_factory=list)
    children: list[list[int]] = field(default_factory=list)
    members: list[list[int]] = field(default_factory=list)
    leaf_of: array = field(default_factory=lambda: array("l"))
    # Filled by summarize():
    size: list[int] = field(default_factory=list)
    label: list[str] = field(default_factory=list)
    representative: list[int] = field(default_factory=list)
    internal: list[int] = field(default_factory=list)
    boundary: list[int] = field(default_factory=list)
    types: list[dict] = field(default_factory=list)
    accounts: list[dict] = field(default_factory=list)
    links: dict = field(default_factory=dict)  # (parent or -1, a, b) -> weight, a < b
    degree: array = field(default_factory=lambda: array("l"))
    inner_degree: array = field(default_factory=lambda: array("l"))
    # Filled by assign_ids():
    ids: list[str] = field(default_factory=list)
    reused: int = 0
    isolated: int = 0

    @property
    def top(self) -> list[int]:
        return [c for c, parent in enumerate(self.parent) if parent < 0]

    def path(self, cluster: int) -> tuple[int, ...]:
        chain = []
        while cluster >= 0:
            chain.append(cluster)
            cluster = self.parent[cluster]
        return tuple(reversed(chain))


def _dominant(histogram: Counter) -> str:
    return min(histogram.items(), key=lambda item: (-item[1], item[0]))[0] if histogram else ""


Adjacency = list[dict[int, int]]


def louvain(
    adjacency: Adjacency, nodes: list[int], initial: list | None = None, seed: int = SEED
) -> list[list[list[int]]]:
    """Seeded multilevel Louvain (modularity, resolution 1) over the subgraph induced by ``nodes``.

    Returns the partition after each level, finest first, as lists of ascending node
    lists. ``initial`` (one hashable label per node, aligned with ``nodes``) warm-starts
    the first level from a previous partition: local moves then only change what the
    new topology actually favors, which keeps clusters stable across revisions.
    Deterministic for the same inputs: nodes are visited in a seeded shuffled order and
    ties keep the current community.
    """
    position = {node: index for index, node in enumerate(nodes)}
    neighbors: list[dict[int, float]] = []
    for node in nodes:
        row = {}
        for other, weight in adjacency[node].items():
            index = position.get(other)
            if index is not None:
                row[index] = float(weight)
        neighbors.append(row)
    degree = [sum(row.values()) for row in neighbors]
    total = sum(degree)
    members: list[list[int]] = [[node] for node in nodes]
    if initial is None:
        community = list(range(len(nodes)))
    else:
        labels: dict = {}
        community = [labels.setdefault(label, len(labels)) for label in initial]
    rng = random.Random(seed)
    levels: list[list[list[int]]] = []
    first = True
    while True:
        count = len(neighbors)
        margin = INERTIA if first and initial is not None else 0.0
        moved = _local_moves(neighbors, degree, community, total, rng, margin) if total else False
        relabel: dict[int, int] = {}
        for index in range(count):
            relabel.setdefault(community[index], len(relabel))
        if not moved and not (first and len(relabel) < count):
            if not levels:
                levels.append(sorted(sorted(group) for group in members))
            break
        grouped: list[list[int]] = [[] for _ in relabel]
        aggregated: list[dict[int, float]] = [{} for _ in relabel]
        weights = [0.0] * len(relabel)
        for index in range(count):
            target = relabel[community[index]]
            grouped[target].extend(members[index])
            weights[target] += degree[index]
            row = aggregated[target]
            for other, weight in neighbors[index].items():
                other_target = relabel[community[other]]
                if other_target != target:
                    row[other_target] = row.get(other_target, 0.0) + weight
        members, neighbors, degree = grouped, aggregated, weights
        levels.append(sorted(sorted(group) for group in members))
        community = list(range(len(members)))
        first = False
    return levels


def _local_moves(neighbors, degree, community, total: float, rng: random.Random, margin: float) -> bool:
    """Phase one: move nodes to the neighboring community with the best modularity gain.

    A move must beat staying by ``margin`` (in edge-weight units); warm starts use it
    so near-tied boundary nodes keep their previous community.
    """
    size = len(neighbors)
    totals = [0.0] * size
    for index in range(size):
        totals[community[index]] += degree[index]
    order = list(range(size))
    rng.shuffle(order)
    moved_any, moved, passes = False, True, 0
    while moved and passes < MAX_PASSES:
        moved, passes = False, passes + 1
        for node in order:
            current, weight = community[node], degree[node]
            links: dict[int, float] = {}
            for other, edge in neighbors[node].items():
                key = community[other]
                links[key] = links.get(key, 0.0) + edge
            totals[current] -= weight
            scale = weight / total
            best, best_gain = current, links.get(current, 0.0) - totals[current] * scale + margin
            for candidate, edge in links.items():
                gain = edge - totals[candidate] * scale
                if gain > best_gain:
                    best, best_gain = candidate, gain
            totals[best] += weight
            if best != current:
                community[node] = best
                moved = moved_any = True
    return moved_any


# A group to place: (kind, ascending member indices, dendrogram level or -1). Without a
# previous revision, a community of the whole-revision run is split along the run's own
# finer levels; otherwise (or below level 0) by a Louvain run on its induced subgraph,
# warm-started from the previous revision's children.
Group = tuple[str, list[int], int]


class _Builder:
    def __init__(
        self,
        graph: CompactGraph,
        adjacency: Adjacency,
        levels: list[list[list[int]]],
        previous: list[tuple[str, ...] | None],
    ):
        self.graph, self.adjacency, self.previous = graph, adjacency, previous
        self.levels: list[array] = []
        for partition in levels:
            owner = array("l", [-1]) * graph.node_count
            for index, community in enumerate(partition):
                for node in community:
                    owner[node] = index
            self.levels.append(owner)
        self.h = Hierarchy(leaf_of=array("l", [-1]) * graph.node_count)

    def new(self, parent: int, depth: int, kind: str) -> int:
        h = self.h
        h.parent.append(parent)
        h.depth.append(depth)
        h.kind.append(kind)
        h.children.append([])
        h.members.append([])
        if parent >= 0:
            h.children[parent].append(len(h.parent) - 1)
        return len(h.parent) - 1

    def dominant_type(self, members: list[int]) -> str:
        return _dominant(Counter(self.graph.types[m] for m in members))

    def arrange(self, groups: list[Group], capacity: int) -> list[Group]:
        """Largest groups first; pack the smallest into per-type bins until ``capacity`` fits."""
        groups = sorted(groups, key=lambda group: (-len(group[1]), group[1][0]))
        if len(groups) <= capacity:
            return groups
        bins: list[list[int]] = []
        open_bin: dict[str, int] = {}
        while groups and len(groups) + len(bins) > capacity and len(groups[-1][1]) <= MAX_MEMBERS:
            members = groups.pop()[1]
            key = self.dominant_type(members)
            slot = open_bin.get(key)
            if slot is None or len(bins[slot]) + len(members) > MAX_MEMBERS:
                bins.append([])
                slot = open_bin[key] = len(bins) - 1
            bins[slot].extend(members)
        packed = [("group", sorted(members), -1) for members in bins]
        return groups + sorted(packed, key=lambda group: (-len(group[1]), group[1][0]))

    def attach(self, groups: list[Group], parent: int, depth: int) -> None:
        capacity = MAX_TOP if parent < 0 else MAX_CHILDREN
        groups = self.arrange(groups, capacity)
        if len(groups) > capacity:
            # Only reachable beyond the supported revision size: an intermediate level of ranges.
            step = -(-len(groups) // capacity)
            for start in range(0, len(groups), step):
                holder = self.new(parent, depth, "range")
                self.attach(groups[start : start + step], holder, depth + 1)
            return
        for group in groups:
            self.build(group, parent, depth)

    def build(self, group: Group, parent: int, depth: int) -> None:
        kind, members, _ = group
        cluster = self.new(parent, depth, kind)
        if len(members) <= MAX_MEMBERS:
            self.h.members[cluster] = members
            for member in members:
                self.h.leaf_of[member] = cluster
            return
        self.attach(self.split(group, depth), cluster, depth + 1)

    def split(self, group: Group, depth: int) -> list[Group]:
        kind, members, level = group
        if kind == "community" and depth + 1 < MAX_DEPTH:
            initial = self.initial(members, depth + 1)
            communities = louvain(self.adjacency, members, initial)[-1]
            if len(communities) > 1:
                return [("community", part, -1) for part in communities]
        ordered = self.ordered(kind, members)
        return [
            ("part", sorted(ordered[i : i + MAX_MEMBERS]), -1) for i in range(0, len(ordered), MAX_MEMBERS)
        ]

    def initial(self, members: list[int], depth: int) -> list | None:
        """Previous-revision cluster at ``depth`` per member (new entities start alone), if any."""
        labels, known = [], 0
        for member in members:
            path = self.previous[member]
            if path is not None and len(path) > depth:
                labels.append(path[depth])
                known += 1
            else:
                labels.append(("new", member))
        return labels if members and known >= WARM_MIN_KNOWN * len(members) else None

    def ordered(self, kind: str, members: list[int]) -> list[int]:
        """Deterministic order for splitting into parts: BFS from hubs keeps neighbors together."""
        ids, accounts = self.graph.ids, self.graph.account
        if kind == "isolated":
            return sorted(members, key=lambda m: (accounts[m], ids[m]))
        inside = set(members)
        seen: set[int] = set()
        order: list[int] = []
        adjacency = self.adjacency
        for start in sorted(members, key=lambda m: (-len(adjacency[m]), m)):
            if start in seen:
                continue
            seen.add(start)
            queue = deque([start])
            while queue:
                current = queue.popleft()
                order.append(current)
                for neighbor in sorted(adjacency[current]):
                    if neighbor in inside and neighbor not in seen:
                        seen.add(neighbor)
                        queue.append(neighbor)
        return order


def topology(graph: CompactGraph) -> Adjacency:
    """Undirected simple adjacency over node indices; parallel and reverse edges add weight."""
    adjacency: Adjacency = [{} for _ in range(graph.node_count)]
    for source, target in zip(graph.edge_source, graph.edge_target, strict=True):
        if source != target:
            row = adjacency[source]
            row[target] = row.get(target, 0) + 1
            row = adjacency[target]
            row[source] = row.get(source, 0) + 1
    return adjacency


def build_hierarchy(graph: CompactGraph, previous: "PreviousClusters | None" = None) -> Hierarchy:
    adjacency = topology(graph)
    paths: list[tuple[str, ...] | None] = [None] * graph.node_count
    if previous is not None:
        cache: dict[str, tuple[str, ...]] = {}
        for node, entity in enumerate(graph.ids):
            leaf = previous.leaf.get(entity)
            if leaf is not None:
                paths[node] = cache.get(leaf) or cache.setdefault(leaf, previous.path(leaf))
    isolated: dict[str, list[int]] = {}
    connected: list[int] = []
    for node in range(graph.node_count):
        if adjacency[node]:
            connected.append(node)
        else:
            isolated.setdefault(graph.types[node], []).append(node)
    builder = _Builder(graph, adjacency, [], paths)
    initial = builder.initial(connected, 0) if previous is not None else None
    levels = louvain(adjacency, connected, initial) if connected else [[]]
    builder = _Builder(graph, adjacency, levels, paths)
    groups: list[Group] = [("community", part, len(levels) - 1) for part in levels[-1]]
    groups += [("isolated", members, -1) for _, members in sorted(isolated.items())]
    builder.attach(groups, -1, 0)
    h = builder.h
    h.isolated = sum(len(members) for members in isolated.values())
    summarize(h, graph)
    return h


def summarize(h: Hierarchy, graph: CompactGraph) -> None:
    count = len(h.parent)
    n = graph.node_count
    degree, inner = array("l", [0]) * n, array("l", [0]) * n
    pairs: Counter = Counter()
    leaf_of = h.leaf_of
    for source, target in zip(graph.edge_source, graph.edge_target, strict=True):
        degree[source] += 1
        if source != target:
            degree[target] += 1
        a, b = leaf_of[source], leaf_of[target]
        if a == b:
            inner[source] += 1
            if source != target:
                inner[target] += 1
        pairs[(a, b) if a <= b else (b, a)] += 1
    paths = [h.path(c) for c in range(count)]
    internal, boundary = [0] * count, [0] * count
    links: Counter = Counter()
    for (a, b), weight in pairs.items():
        pa, pb = paths[a], paths[b]
        shared = 0
        while shared < len(pa) and shared < len(pb) and pa[shared] == pb[shared]:
            shared += 1
        for cluster in pa[:shared]:
            internal[cluster] += weight
        if a == b:
            continue
        for cluster in pa[shared:] + pb[shared:]:
            boundary[cluster] += weight
        x, y = pa[shared], pb[shared]
        links[(pa[shared - 1] if shared else -1, min(x, y), max(x, y))] += weight

    size = [0] * count
    representative = [-1] * count
    types: list[Counter] = [Counter() for _ in range(count)]
    accounts: list[Counter] = [Counter() for _ in range(count)]
    best = lambda m: (degree[m], -m)  # noqa: E731 - highest degree, then earliest node
    for cluster in range(count - 1, -1, -1):  # Children (higher index) before parents.
        for member in h.members[cluster]:
            size[cluster] += 1
            types[cluster][graph.types[member]] += 1
            accounts[cluster][graph.account[member] or NO_ACCOUNT] += 1
            if representative[cluster] < 0 or best(member) > best(representative[cluster]):
                representative[cluster] = member
        for child in h.children[cluster]:
            size[cluster] += size[child]
            types[cluster].update(types[child])
            accounts[cluster].update(accounts[child])
            rep = representative[child]
            if rep >= 0 and (representative[cluster] < 0 or best(rep) > best(representative[cluster])):
                representative[cluster] = rep

    labels = [""] * count
    for cluster in range(count):
        kind, rep = h.kind[cluster], representative[cluster]
        if kind == "isolated":
            labels[cluster] = f"Unconnected {_dominant(types[cluster])}"
        elif kind == "group":
            labels[cluster] = f"Small groups: {_dominant(types[cluster])}"
        elif kind == "part":
            siblings = h.children[h.parent[cluster]] if h.parent[cluster] >= 0 else h.top
            position = siblings.index(cluster) + 1
            labels[cluster] = f"{graph.names[rep]} (part {position} of {len(siblings)})"
        elif kind == "range":
            labels[cluster] = f"{graph.names[rep]} and others"
        else:
            labels[cluster] = graph.names[rep]

    h.size, h.label, h.representative = size, labels, representative
    h.internal, h.boundary, h.links = internal, boundary, dict(links)
    h.types = [dict(sorted(t.items())) for t in types]
    h.accounts = [_facets(a) for a in accounts]
    h.degree, h.inner_degree = degree, inner


def _facets(accounts: Counter) -> dict[str, int]:
    """The largest account facets; the remainder is folded into one "(other)" bucket."""
    ranked = sorted(accounts.items(), key=lambda item: (-item[1], item[0]))
    facets = dict(ranked[:ACCOUNT_FACETS])
    rest = sum(count for _, count in ranked[ACCOUNT_FACETS:])
    if rest:
        facets[OTHER_ACCOUNTS] = facets.get(OTHER_ACCOUNTS, 0) + rest
    return facets


@dataclass
class PreviousClusters:
    """The prior revision's leaf membership and cluster tree, for ID matching."""

    revision: str
    leaf: dict[str, str]
    parent: dict[str, str]
    size: dict[str, int]

    def path(self, cluster: str) -> tuple[str, ...]:
        chain = []
        while cluster:
            chain.append(cluster)
            cluster = self.parent.get(cluster, "")
        return tuple(reversed(chain))


def load_previous(db: Session, tenant: str, revision: str) -> PreviousClusters | None:
    if not revision or stored_summary(db, tenant, revision) is None:
        return None
    scope = (RevisionCluster.tenant_id == tenant, RevisionCluster.revision == revision)
    parent, size = {}, {}
    for cluster_id, parent_id, cluster_size in db.execute(
        select(RevisionCluster.cluster_id, RevisionCluster.parent_id, RevisionCluster.size).where(*scope)
    ):
        parent[cluster_id], size[cluster_id] = parent_id, cluster_size
    leaf = {
        entity: cluster
        for entity, cluster in db.execute(
            select(RevisionClusterMember.entity_id, RevisionClusterMember.cluster_id)
            .where(RevisionClusterMember.tenant_id == tenant, RevisionClusterMember.revision == revision)
            .execution_options(yield_per=10000)
        )
    }
    return PreviousClusters(revision, leaf, parent, size)


def assign_ids(h: Hierarchy, graph: CompactGraph, revision: str, previous: PreviousClusters | None) -> None:
    """Reuse a previous cluster ID for the best Jaccard match at the same depth (greedy, one-to-one)."""
    count = len(h.parent)
    ids: list[str | None] = [None] * count
    if previous is not None and previous.leaf:
        prior_paths: dict[str, tuple[str, ...]] = {}
        pairs: Counter = Counter()
        for node in range(graph.node_count):
            prior = previous.leaf.get(graph.ids[node])
            if prior is not None:
                pairs[(h.leaf_of[node], prior)] += 1
        overlap: Counter = Counter()
        new_paths = {}
        for (leaf, prior), shared in pairs.items():
            new_path = new_paths.get(leaf) or new_paths.setdefault(leaf, h.path(leaf))
            old_path = prior_paths.get(prior) or prior_paths.setdefault(prior, previous.path(prior))
            for new, old in zip(new_path, old_path, strict=False):
                overlap[(new, old)] += shared
        scored = []
        for (new, old), shared in overlap.items():
            union = h.size[new] + previous.size.get(old, 0) - shared
            score = shared / union if union else 0.0
            if score >= MIN_JACCARD:
                scored.append((-score, new, old))
        taken: set[str] = set()
        for _, new, old in sorted(scored):
            if ids[new] is None and old not in taken:
                ids[new] = old
                taken.add(old)
    reused = sum(cluster is not None for cluster in ids)
    used = {cluster for cluster in ids if cluster is not None}
    for cluster in range(count):
        if ids[cluster] is None:
            salt = 0
            while True:
                candidate = "c" + hashlib.sha256(f"{revision}:{cluster}:{salt}".encode()).hexdigest()[:15]
                if candidate not in used:
                    break
                salt += 1
            ids[cluster] = candidate
            used.add(candidate)
    h.ids, h.reused = ids, reused


@dataclass
class ComputedClusters:
    hierarchy: Hierarchy
    graph: CompactGraph
    previous_revision: str | None
    compute_ms: int


def compute_clusters(
    graph: CompactGraph, revision: str, previous: PreviousClusters | None = None
) -> ComputedClusters:
    started = time.perf_counter()
    hierarchy = build_hierarchy(graph, previous)
    assign_ids(hierarchy, graph, revision, previous)
    return ComputedClusters(
        hierarchy,
        graph,
        previous.revision if previous else None,
        round((time.perf_counter() - started) * 1000),
    )


def _bulk_insert(db: Session, model, columns: list[str], rows) -> None:
    """COPY on PostgreSQL (one round trip per table); batched executemany elsewhere."""
    if db.get_bind().dialect.name == "postgresql":
        raw = db.connection().connection.driver_connection
        with raw.cursor() as cursor:
            with cursor.copy(f"COPY {model.__tablename__} ({', '.join(columns)}) FROM STDIN") as copy:
                for row in rows:
                    copy.write_row([json.dumps(v) if isinstance(v, dict) else v for v in row])
        return
    batch = []
    for row in rows:
        batch.append(dict(zip(columns, row, strict=True)))
        if len(batch) >= 5000:
            db.execute(insert(model), batch)
            batch.clear()
    if batch:
        db.execute(insert(model), batch)


def store_clusters(db: Session, tenant: str, revision: str, computed: ComputedClusters) -> None:
    """Stage rows in the caller's transaction, which also advances the revision pointer."""
    h, graph = computed.hierarchy, computed.graph
    ids = h.ids
    db.add(
        RevisionClusterSummary(
            tenant_id=tenant,
            revision=revision,
            cluster_version=CLUSTER_VERSION,
            algorithm=ALGORITHM,
            seed=SEED,
            total_nodes=graph.node_count,
            total_edges=graph.edge_count,
            total_clusters=len(h.parent),
            top_level=len(h.top),
            max_depth=max(h.depth, default=-1) + 1,
            isolated_nodes=h.isolated,
            top_links=sum(1 for parent, _, _ in h.links if parent < 0),
            previous_revision=computed.previous_revision,
            reused_ids=h.reused,
            compute_ms=computed.compute_ms,
        )
    )
    db.flush()
    position = {}
    for siblings in [h.top, *h.children]:
        for ordinal, cluster in enumerate(siblings):
            position[cluster] = ordinal
    _bulk_insert(
        db,
        RevisionCluster,
        [
            "tenant_id",
            "revision",
            "cluster_id",
            "parent_id",
            "depth",
            "ordinal",
            "kind",
            "label",
            "representative_id",
            "size",
            "child_count",
            "member_count",
            "internal_edges",
            "boundary_edges",
            "types",
            "accounts",
        ],
        (
            (
                tenant,
                revision,
                ids[c],
                ids[h.parent[c]] if h.parent[c] >= 0 else "",
                h.depth[c],
                position[c],
                h.kind[c],
                h.label[c][:256],
                graph.ids[h.representative[c]],
                h.size[c],
                len(h.children[c]),
                len(h.members[c]),
                h.internal[c],
                h.boundary[c],
                h.types[c],
                h.accounts[c],
            )
            for c in range(len(h.parent))
        ),
    )
    _bulk_insert(
        db,
        RevisionClusterLink,
        ["tenant_id", "revision", "parent_id", "source_id", "target_id", "weight"],
        (
            (tenant, revision, ids[parent] if parent >= 0 else "", *sorted((ids[a], ids[b])), weight)
            for (parent, a, b), weight in h.links.items()
        ),
    )

    def members():
        degree, inner, node_ids = h.degree, h.inner_degree, graph.ids
        for cluster, listed in enumerate(h.members):
            if not listed:
                continue
            top = ids[h.path(cluster)[0]]
            ranked = sorted(listed, key=lambda m: (-degree[m], node_ids[m]))
            for ordinal, member in enumerate(ranked):
                yield (
                    tenant,
                    revision,
                    node_ids[member],
                    ids[cluster],
                    top,
                    ordinal,
                    degree[member],
                    inner[member],
                )

    _bulk_insert(
        db,
        RevisionClusterMember,
        [
            "tenant_id",
            "revision",
            "entity_id",
            "cluster_id",
            "top_id",
            "ordinal",
            "degree",
            "internal_degree",
        ],
        members(),
    )


def delete_clusters(db: Session, tenant: str, revision: str) -> None:
    """Remove a revision's cluster rows; call in the transaction holding the publication lock."""
    for model in (RevisionClusterMember, RevisionClusterLink, RevisionCluster, RevisionClusterSummary):
        db.execute(delete(model).where(model.tenant_id == tenant, model.revision == revision))


def stored_summary(db: Session, tenant: str, revision: str) -> RevisionClusterSummary | None:
    if not revision:
        return None
    row = db.get(RevisionClusterSummary, (tenant, revision))
    return row if isinstance(row, RevisionClusterSummary) and row.cluster_version == CLUSTER_VERSION else None


# ---------------------------------------------------------------------------
# Read API


class ClusterSummary(BaseModel):
    id: str
    parent_id: str | None
    depth: int
    kind: str
    label: str
    representative_id: str
    size: int
    child_count: int
    member_count: int
    internal_edges: int
    boundary_edges: int
    dominant_type: str
    types: dict[str, int]
    accounts: dict[str, int]


class ClusterLink(BaseModel):
    source: str
    target: str
    weight: int


class ClusterCrumb(BaseModel):
    id: str
    label: str
    size: int


class ClusterMapView(BaseModel):
    level: int
    total_nodes: int
    total_edges: int
    total_clusters: int
    clusters: int
    shown_clusters: int
    links: int
    shown_links: int
    edge_limit: int
    isolated_nodes: int
    truncated: bool
    notice: str = STRUCTURAL_NOTICE


class ClusterMapResponse(BaseModel):
    revision: str
    clusters: list[ClusterSummary]
    edges: list[ClusterLink]
    warnings: list[str]
    view: ClusterMapView


class ClusterDetailView(BaseModel):
    mode: str  # "clusters" (child clusters) or "members" (entities of a leaf)
    total_children: int
    shown_children: int
    total_links: int
    shown_links: int
    total_members: int
    shown_members: int
    member_limit: int
    total_member_edges: int
    shown_member_edges: int
    edge_limit: int
    truncated: bool
    notice: str = STRUCTURAL_NOTICE


class ClusterDetailResponse(BaseModel):
    revision: str
    cluster: ClusterSummary
    path: list[ClusterCrumb]
    children: list[ClusterSummary]
    edges: list[ClusterLink]
    nodes: list[Node]
    node_edges: list[dict]
    boundary_edges: dict[str, int]
    warnings: list[str]
    view: ClusterDetailView


class ClusterNotFound(LookupError):
    pass


def _summary(row: RevisionCluster) -> ClusterSummary:
    types = row.types if isinstance(row.types, dict) else json.loads(row.types)
    accounts = row.accounts if isinstance(row.accounts, dict) else json.loads(row.accounts)
    return ClusterSummary(
        id=row.cluster_id,
        parent_id=row.parent_id or None,
        depth=row.depth,
        kind=row.kind,
        label=row.label,
        representative_id=row.representative_id,
        size=row.size,
        child_count=row.child_count,
        member_count=row.member_count,
        internal_edges=row.internal_edges,
        boundary_edges=row.boundary_edges,
        dominant_type=_dominant(Counter(types)),
        types=types,
        accounts=accounts,
    )


def _children(db: Session, tenant: str, revision: str, parent: str, limit: int):
    rows = db.scalars(
        select(RevisionCluster)
        .where(
            RevisionCluster.tenant_id == tenant,
            RevisionCluster.revision == revision,
            RevisionCluster.parent_id == parent,
        )
        .order_by(RevisionCluster.ordinal)
        .limit(limit)
    )
    return [_summary(row) for row in rows]


def _links(db: Session, tenant: str, revision: str, parent: str, limit: int) -> list[ClusterLink]:
    rows = db.execute(
        select(RevisionClusterLink.source_id, RevisionClusterLink.target_id, RevisionClusterLink.weight)
        .where(
            RevisionClusterLink.tenant_id == tenant,
            RevisionClusterLink.revision == revision,
            RevisionClusterLink.parent_id == parent,
        )
        .order_by(
            RevisionClusterLink.weight.desc(), RevisionClusterLink.source_id, RevisionClusterLink.target_id
        )
        .limit(limit)
    )
    return [ClusterLink(source=a, target=b, weight=w) for a, b, w in rows]


def _link_count(db: Session, tenant: str, revision: str, parent: str) -> int:
    from sqlalchemy import func

    return db.scalar(
        select(func.count())
        .select_from(RevisionClusterLink)
        .where(
            RevisionClusterLink.tenant_id == tenant,
            RevisionClusterLink.revision == revision,
            RevisionClusterLink.parent_id == parent,
        )
    )


def validate_cluster_bounds(member_limit: int, edge_limit: int) -> None:
    if not 1 <= member_limit <= 500 or not 1 <= edge_limit <= 2000:
        raise ValueError("Cluster limits outside supported bounds")


def cluster_map(
    db: Session, summary: RevisionClusterSummary, warnings: list[str], edge_limit: int
) -> ClusterMapResponse:
    tenant, revision = summary.tenant_id, summary.revision
    clusters = _children(db, tenant, revision, "", MAX_TOP)
    links = _links(db, tenant, revision, "", edge_limit)
    return ClusterMapResponse(
        revision=revision,
        clusters=clusters,
        edges=links,
        warnings=warnings,
        view=ClusterMapView(
            level=0,
            total_nodes=summary.total_nodes,
            total_edges=summary.total_edges,
            total_clusters=summary.total_clusters,
            clusters=summary.top_level,
            shown_clusters=len(clusters),
            links=summary.top_links,
            shown_links=len(links),
            edge_limit=edge_limit,
            isolated_nodes=summary.isolated_nodes,
            truncated=len(clusters) < summary.top_level or len(links) < summary.top_links,
        ),
    )


def cluster_row(db: Session, tenant: str, revision: str, cluster_id: str) -> RevisionCluster:
    row = db.get(RevisionCluster, (tenant, revision, cluster_id))
    if not isinstance(row, RevisionCluster):
        raise ClusterNotFound(cluster_id)
    return row


def cluster_path(db: Session, tenant: str, revision: str, row: RevisionCluster) -> list[ClusterCrumb]:
    chain = [row]
    while chain[-1].parent_id and len(chain) <= MAX_DEPTH + 1:
        chain.append(cluster_row(db, tenant, revision, chain[-1].parent_id))
    return [ClusterCrumb(id=item.cluster_id, label=item.label, size=item.size) for item in reversed(chain)]


def member_page(
    db: Session, tenant: str, revision: str, cluster_id: str, limit: int
) -> list[tuple[str, int, int]]:
    """(entity ID, degree, internal degree) of a leaf, highest degree first."""
    return [
        tuple(row)
        for row in db.execute(
            select(
                RevisionClusterMember.entity_id,
                RevisionClusterMember.degree,
                RevisionClusterMember.internal_degree,
            )
            .where(
                RevisionClusterMember.tenant_id == tenant,
                RevisionClusterMember.revision == revision,
                RevisionClusterMember.cluster_id == cluster_id,
            )
            .order_by(RevisionClusterMember.ordinal)
            .limit(limit)
        )
    ]


def cluster_detail(
    db: Session,
    graph,
    tenant: str,
    revision: str,
    cluster_id: str,
    member_limit: int,
    edge_limit: int,
) -> ClusterDetailResponse:
    """Child clusters with their sibling links, or a leaf's members and internal relationships."""
    validate_cluster_bounds(member_limit, edge_limit)
    row = cluster_row(db, tenant, revision, cluster_id)
    path = cluster_path(db, tenant, revision, row)
    children: list[ClusterSummary] = []
    links: list[ClusterLink] = []
    total_links = 0
    members: list[tuple[str, int, int]] = []
    if row.child_count:
        children = _children(db, tenant, revision, cluster_id, MAX_CHILDREN)
        links = _links(db, tenant, revision, cluster_id, edge_limit)
        total_links = _link_count(db, tenant, revision, cluster_id)
        sliced = graph.cluster_members(tenant, revision, [], edge_limit)
    else:
        members = member_page(db, tenant, revision, cluster_id, member_limit)
        sliced = graph.cluster_members(tenant, revision, [m[0] for m in members], edge_limit)
    shown_edges = len(sliced.edges)
    return ClusterDetailResponse(
        revision=revision,
        cluster=_summary(row),
        path=path,
        children=children,
        edges=links,
        nodes=sliced.nodes,
        node_edges=[{**edge.model_dump(mode="json"), "id": edge.id} for edge in sliced.edges],
        boundary_edges={entity: degree - inner for entity, degree, inner in members},
        warnings=sliced.warnings,
        view=ClusterDetailView(
            mode="clusters" if row.child_count else "members",
            total_children=row.child_count,
            shown_children=len(children),
            total_links=total_links,
            shown_links=len(links),
            total_members=row.member_count,
            shown_members=len(sliced.nodes),
            member_limit=member_limit,
            total_member_edges=0 if row.child_count else row.internal_edges,
            shown_member_edges=shown_edges,
            edge_limit=edge_limit,
            truncated=len(children) < row.child_count
            or len(links) < total_links
            or (
                not row.child_count
                and (len(sliced.nodes) < row.member_count or shown_edges < row.internal_edges)
            ),
        ),
    )


# ---------------------------------------------------------------------------
# Operator backfill


def backfill(tenant: str) -> dict:
    """Compute and store clusters for a tenant's current revision under the publication lock."""
    from app.db.models import TenantState

    with session_factory()() as db:
        if db.get_bind().dialect.name == "postgresql":
            db.execute(text("SET LOCAL lock_timeout = '5s'"))
        acquire_publication_lock(db, tenant)
        state = db.execute(
            select(TenantState).where(TenantState.tenant_id == tenant).with_for_update(read=True)
        ).scalar_one_or_none()
        if state is None or not state.revision:
            raise ValueError("Tenant has no published revision")
        revision = state.revision
        if stored_summary(db, tenant, revision) is not None:
            return {"tenant": tenant, "revision": revision, "backfilled": False}
        delete_clusters(db, tenant, revision)
        graph = CompactGraph.from_snapshot(get_graph_store().snapshot(tenant, revision))
        computed = compute_clusters(graph, revision)
        store_clusters(db, tenant, revision, computed)
        db.commit()
        return {
            "tenant": tenant,
            "revision": revision,
            "backfilled": True,
            "clusters": len(computed.hierarchy.parent),
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Store global-map clusters for a tenant's current revision")
    parser.add_argument("--tenant", required=True)
    args = parser.parse_args()
    try:
        result = backfill(args.tenant)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
