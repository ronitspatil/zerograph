"""Blast radius: everything reachable from a node if it is compromised.

Breadth-first over edges. Following a transitive edge inherits the target's own
access; a non-transitive edge (network reachability, an unmounted token) marks the
target reachable but stops there.

Score = sum of the severity of every reachable node (capabilities, permissions and
secrets carry weight; agents, tools and identities carry none). Rating comes from
the single worst item: critical >= 9, high >= 7, medium >= 4, otherwise low.
"""

from __future__ import annotations

from .model import Edge, Graph


def rating(max_severity: int) -> str:
    if max_severity >= 9:
        return "critical"
    if max_severity >= 7:
        return "high"
    if max_severity >= 4:
        return "medium"
    return "low"


def blast_radius(g: Graph, start: str, out: dict[str, list[Edge]] | None = None) -> dict:
    out = out if out is not None else g.out_edges()
    via: dict[str, Edge] = {}
    queue, seen = [start], {start}
    while queue:
        current = queue.pop(0)
        for edge in out.get(current, []):
            if edge.dst in seen:
                continue
            seen.add(edge.dst)
            via[edge.dst] = edge
            if edge.transitive:
                queue.append(edge.dst)
    reached = [g.nodes[n] for n in via]
    weighted = sorted((n for n in reached if n.severity > 0), key=lambda n: (-n.severity, n.label))
    max_sev = max((n.severity for n in weighted), default=0)
    return {
        "id": start,
        "label": g.nodes[start].label,
        "score": sum(n.severity for n in weighted),
        "max_severity": max_sev,
        "rating": rating(max_sev),
        "reachable": [n.id for n in reached],
        "edges": [[e.src, e.dst, e.rel] for e in via.values()],
        "findings": [{"id": n.id, "label": n.label, "kind": n.kind, "severity": n.severity,
                      "path": _path(g, via, n.id)} for n in weighted],
    }


def _path(g: Graph, via: dict[str, Edge], node: str) -> list[dict]:
    """The chain of edges that reached a node, each with its evidence."""
    steps = []
    while node in via:
        edge = via[node]
        steps.append({"from": g.nodes[edge.src].label, "to": g.nodes[edge.dst].label, "rel": edge.rel,
                      "evidence": f"{edge.file}:{edge.line}" if edge.file and edge.line else edge.file})
        node = edge.src
    return steps[::-1]


def rank_agents(g: Graph) -> list[dict]:
    out = g.out_edges()
    results = [blast_radius(g, n.id, out) for n in g.nodes.values() if n.kind == "agent"]
    return sorted(results, key=lambda r: (-r["score"], -r["max_severity"], r["label"]))


def all_radii(g: Graph) -> dict[str, dict]:
    out = g.out_edges()
    return {n: blast_radius(g, n, out) for n in g.nodes}
