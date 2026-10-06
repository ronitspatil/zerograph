"""The initial explore sample: a connected, representative slice of a revision.

Computed once at publication (stored as ``revision_analysis.sample_ids``) so the
default graph view is a bounded key lookup. The sample is an *ordered* list: every
prefix is itself a good sample, so ``/graph/explore?node_limit=N`` takes the first N.

Selection, deterministic for a given revision whatever the node or edge order:

1. Seed with the path of the first finding in API order (an exposed entry point to
   sensitive data), else with the most important entity (on a finding path or of
   high blast radius), else the highest-degree entity; ties break by ascending ID.
2. Grow along relationships (either direction, any type), so each added entity is
   linked to one already chosen. The next entity comes from the frontier, by:
   important entities first while they are at most half the sample; otherwise the
   least represented entity type so far (identities, roles and data assets mix);
   within a type, most relationships into the sample, then highest degree, then ID.
3. When the reachable frontier is exhausted, start again from the best unchosen
   entity in the same global order, so a graph that fits is included whole.
"""

import heapq
from array import array
from collections.abc import Iterable, Sequence

from app.graph.schema import NodeType

SAMPLE_SIZE = 500
# Bump when the selection changes: older stored samples are refreshed by the analysis backfill.
SAMPLE_VERSION = 2
# Finding paths that mark their entities as important (bounded work at any scale).
IMPORTANT_FINDINGS = 64
TYPE_ORDER = {kind.value: position for position, kind in enumerate(NodeType)}


def select_sample(
    ids: Sequence[str],
    types: Sequence[str],
    sources: Sequence[int],
    targets: Sequence[int],
    finding_paths: Iterable[Sequence[str]] = (),
    important_ids: Iterable[str] = (),
    limit: int = SAMPLE_SIZE,
) -> list[str]:
    """Up to ``limit`` node IDs in selection order (see the module docstring).

    ``ids``/``types`` are per node index; ``sources``/``targets`` are edge endpoint
    indices. ``finding_paths`` are in API order; ``important_ids`` adds entities such
    as high-blast-radius identities.
    """
    count = len(ids)
    limit = min(limit, count)
    if limit <= 0:
        return []
    index = {node_id: position for position, node_id in enumerate(ids)}

    # Undirected adjacency (one entry per relationship end) in CSR form.
    degree = array("l", bytes(8 * (count + 1)))
    for source, target in zip(sources, targets, strict=True):
        degree[source + 1] += 1
        degree[target + 1] += 1
    for node in range(count):
        degree[node + 1] += degree[node]
    offsets = array("l", degree)
    slots = array("l", degree)
    neighbors = array("l", bytes(8 * offsets[count]))
    for source, target in zip(sources, targets, strict=True):
        neighbors[slots[source]] = target
        slots[source] += 1
        neighbors[slots[target]] = source
        slots[target] += 1

    def links(node: int) -> int:
        return offsets[node + 1] - offsets[node]

    important = bytearray(count)
    seed_path: list[int] = []
    for ordinal, path in enumerate(finding_paths):
        if ordinal >= IMPORTANT_FINDINGS:
            break
        resolved = [index[node_id] for node_id in path if node_id in index]
        if not seed_path:
            seed_path = resolved
        for node in resolved:
            important[node] = 1
    for node_id in important_ids:
        if node_id in index:
            important[index[node_id]] = 1

    chosen = bytearray(count)
    into = array("l", bytes(8 * count))  # Relationships from each node into the sample.
    kind_rank = [TYPE_ORDER.get(kind, len(TYPE_ORDER)) for kind in types]
    per_type: dict[int, int] = {}
    # Frontier heaps: important entities, and one per entity type.
    priority: list[tuple] = []
    by_type: dict[int, list[tuple]] = {}
    selected: list[str] = []
    important_selected = 0

    def entry(node: int) -> tuple:
        return (-into[node], -links(node), ids[node], node)

    def choose(node: int) -> None:
        nonlocal important_selected
        chosen[node] = 1
        selected.append(ids[node])
        per_type[kind_rank[node]] = per_type.get(kind_rank[node], 0) + 1
        important_selected += important[node]
        for neighbor in neighbors[offsets[node] : offsets[node + 1]]:
            if chosen[neighbor]:
                continue
            into[neighbor] += 1
            item = entry(neighbor)
            if important[neighbor]:
                heapq.heappush(priority, item)
            heapq.heappush(by_type.setdefault(kind_rank[neighbor], []), item)

    def fresh(heap: list[tuple]) -> tuple | None:
        """Drop chosen or outdated entries (a node's newest entry ranks first)."""
        while heap:
            item = heap[0]
            node = item[3]
            if chosen[node] or -item[0] != into[node]:
                heapq.heappop(heap)
                continue
            return item
        return None

    def next_from_frontier() -> int | None:
        if 2 * important_selected <= len(selected):
            item = fresh(priority)
            if item is not None:
                return item[3]
        best = None
        for rank, heap in by_type.items():
            item = fresh(heap)
            if item is None:
                continue
            key = (per_type.get(rank, 0), item, rank)
            if best is None or key < best:
                best = key
        return None if best is None else best[1][3]

    restart: list[int] | None = None
    restart_at = 0

    def next_restart() -> int:
        nonlocal restart, restart_at
        if restart is None:
            restart = sorted(range(count), key=lambda node: (-important[node], -links(node), ids[node]))
        while chosen[restart[restart_at]]:
            restart_at += 1
        return restart[restart_at]

    for node in seed_path:
        if len(selected) >= limit:
            break
        if not chosen[node]:
            choose(node)
    while len(selected) < limit:
        node = next_from_frontier()
        choose(next_restart() if node is None else node)
    return selected


def snapshot_sample(snapshot, findings=(), important_ids=(), limit: int = SAMPLE_SIZE) -> list[str]:
    """``select_sample`` over a ``GraphSnapshot`` (findings as ``Finding`` models)."""
    ids = [node.id for node in snapshot.nodes]
    index = {node_id: position for position, node_id in enumerate(ids)}
    return select_sample(
        ids,
        [str(node.type) for node in snapshot.nodes],
        [index[edge.source] for edge in snapshot.edges],
        [index[edge.target] for edge in snapshot.edges],
        (finding.path for finding in findings),
        important_ids,
        limit,
    )
