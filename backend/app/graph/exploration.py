"""Bounded visualization queries, independent of full-snapshot permission analysis."""

import json
from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel

from app.graph.schema import Edge, EdgeType, GraphSnapshot, Node


class RevisionUnavailable(ValueError):
    pass


class RootNotFound(ValueError):
    pass


@dataclass(frozen=True)
class RevisionTotals:
    """Whole-revision counts stored at publication; same semantics as the scoped aggregates."""

    nodes: int
    edges: int
    roles: int
    role_edges: int
    # Ascending first node IDs of the revision (explore sample); None when not stored.
    sample_ids: tuple[str, ...] | None = None


@dataclass
class GraphSlice:
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    total_nodes: int = 0
    total_edges: int = 0

    @property
    def truncated(self) -> bool:
        return len(self.nodes) < self.total_nodes or len(self.edges) < self.total_edges


class ExplorationView(BaseModel):
    mode: Literal["sample", "neighborhood"]
    root_id: str | None
    node_limit: int
    edge_limit: int
    truncated: bool
    total_nodes: int
    total_edges: int


class ExplorationResponse(BaseModel):
    revision: str
    nodes: list[Node]
    edges: list[dict]
    warnings: list[str]
    view: ExplorationView


class SearchResponse(BaseModel):
    revision: str
    nodes: list[Node]
    has_more: bool


def validate_bounds(node_limit: int, edge_limit: int, root: str | None):
    if not 1 <= node_limit <= 500 or not 1 <= edge_limit <= 2000:
        raise ValueError("Exploration limits outside supported bounds")
    if root is not None and not 1 <= len(root) <= 512:
        raise ValueError("Invalid root ID")


def search_text(q: str, limit: int) -> str:
    q = q.strip()
    if not 1 <= len(q) <= 128 or not 1 <= limit <= 50:
        raise ValueError("Search query or limit outside supported bounds")
    return q.lower()


def memory_explore(
    snapshot: GraphSnapshot,
    root: str | None,
    node_limit: int,
    edge_limit: int,
    totals: RevisionTotals | None = None,
) -> GraphSlice:
    validate_bounds(node_limit, edge_limit, root)
    if root is None:
        selected = sorted(snapshot.nodes, key=lambda node: node.id)[:node_limit]
    else:
        by_id = {node.id: node for node in snapshot.nodes}
        if root not in by_id:
            raise RootNotFound("Graph root not found")
        neighbors = {edge.target for edge in snapshot.edges if edge.source == root}
        neighbors.update(edge.source for edge in snapshot.edges if edge.target == root)
        neighbors.discard(root)
        selected = [by_id[root]] + [by_id[node_id] for node_id in sorted(neighbors)[: node_limit - 1]]
    selected.sort(key=lambda node: node.id)
    ids = {node.id for node in selected}
    edges = sorted(
        (edge for edge in snapshot.edges if edge.source in ids and edge.target in ids),
        key=lambda edge: edge.id,
    )[:edge_limit]
    return GraphSlice(
        nodes=[node.model_copy(deep=True) for node in selected],
        edges=[edge.model_copy(deep=True) for edge in edges],
        warnings=list(snapshot.warnings),
        total_nodes=totals.nodes if totals else len(snapshot.nodes),
        total_edges=totals.edges if totals else len(snapshot.edges),
    )


def memory_search(snapshot: GraphSnapshot, q: str, limit: int) -> tuple[list[Node], bool]:
    q = search_text(q, limit)
    matched = sorted(
        (node for node in snapshot.nodes if q in node.id.lower() or q in node.name.lower()),
        key=lambda node: node.id,
    )[: limit + 1]
    return [node.model_copy(deep=True) for node in matched[:limit]], len(matched) > limit


EDGE_TYPES = "|".join(kind.value for kind in EdgeType)
NODE_SCOPE = "(n:Entity {tenant_id:$tenant, revision:$revision})"
EDGE_SCOPE = (
    "(a:Entity {tenant_id:$tenant, revision:$revision})"
    f"-[r:{EDGE_TYPES} {{tenant_id:$tenant, revision:$revision}}]->"
    "(b:Entity {tenant_id:$tenant, revision:$revision})"
)


def revision_warnings(tx, params):
    meta = tx.run(
        "MATCH (s:Snapshot {tenant_id:$tenant, revision:$revision}) RETURN s.warnings AS warnings LIMIT 1",
        **params,
    ).single()
    if meta is None:
        raise RevisionUnavailable("Published graph revision unavailable")
    return meta["warnings"] or []


def scoped_totals(tx, params) -> tuple[int, int]:
    total_nodes = tx.run("MATCH " + NODE_SCOPE + " RETURN count(n) AS count", **params).single()["count"]
    total_edges = tx.run("MATCH " + EDGE_SCOPE + " RETURN count(r) AS count", **params).single()["count"]
    return total_nodes, total_edges


def entity_key(tenant: str, revision: str, node_id: str) -> str:
    return json.dumps([tenant, revision, node_id])


def cypher_nodes(tx, tenant: str, revision: str, ids: list[str]) -> list[Node]:
    """Nodes by unique entity key (one index seek each), ascending by ID."""
    if not ids:
        return []
    rows = tx.run(
        "UNWIND $keys AS key MATCH (n:Entity {key:key}) "
        "WHERE n.tenant_id=$tenant AND n.revision=$revision "
        "RETURN n.payload AS payload ORDER BY n.id",
        keys=[entity_key(tenant, revision, node_id) for node_id in ids],
        tenant=tenant,
        revision=revision,
    )
    return [Node.model_validate_json(row["payload"]) for row in rows]


def cypher_internal_edges(tx, tenant: str, revision: str, ids: list[str], limit: int) -> list[Edge]:
    """Relationships with both endpoints in ``ids``, ascending by ID, at most ``limit``.

    Anchored on the endpoints' unique keys and expanded from there: the cost is the
    selected nodes' degree, never a scan of the revision.
    """
    if not ids or limit < 1:
        return []
    keys = [entity_key(tenant, revision, node_id) for node_id in ids]
    rows = tx.run(
        f"UNWIND $keys AS key MATCH (a:Entity {{key:key}})-[r:{EDGE_TYPES}]->(b:Entity) "
        "WITH r, a, b WHERE b.key IN $keys AND a.tenant_id=$tenant AND a.revision=$revision "
        "AND r.tenant_id=$tenant AND r.revision=$revision "
        "RETURN r.payload AS payload ORDER BY r.id LIMIT $limit",
        keys=keys,
        tenant=tenant,
        revision=revision,
        limit=limit,
    )
    return [Edge.model_validate_json(row["payload"]) for row in rows]


def cypher_explore(
    tx,
    tenant: str,
    revision: str,
    root: str | None,
    node_limit: int,
    edge_limit: int,
    totals: RevisionTotals | None = None,
) -> GraphSlice:
    validate_bounds(node_limit, edge_limit, root)
    params = {"tenant": tenant, "revision": revision}
    warnings = revision_warnings(tx, params)
    # Stored publication totals avoid two whole-revision count scans per request.
    # Legacy revisions without stored analysis keep the scoped aggregates.
    total_nodes, total_edges = (totals.nodes, totals.edges) if totals else scoped_totals(tx, params)
    if root is None and totals is not None and totals.sample_ids is not None:
        # The stored ascending ID sample replaces a sorted scan of the whole revision.
        nodes = cypher_nodes(tx, tenant, revision, list(totals.sample_ids[:node_limit]))
    elif root is None:
        rows = tx.run(
            "MATCH " + NODE_SCOPE + " RETURN n.payload AS payload ORDER BY n.id LIMIT $limit",
            **params,
            limit=node_limit,
        )
        nodes = [Node.model_validate_json(row["payload"]) for row in rows]
    else:
        key = entity_key(tenant, revision, root)
        row = tx.run(
            "MATCH (n:Entity {key:$key}) WHERE n.tenant_id=$tenant AND n.revision=$revision AND n.id=$root "
            "RETURN n.payload AS payload LIMIT 1",
            **params,
            root=root,
            key=key,
        ).single()
        if row is None:
            raise RootNotFound("Graph root not found")
        nodes = [Node.model_validate_json(row["payload"])]
        if node_limit > 1:
            # Anchored on the root's unique key: cost is the root's degree.
            rows = tx.run(
                f"MATCH (s:Entity {{key:$key}})-[r:{EDGE_TYPES}]-(n:Entity) "
                "WHERE n.id <> $root AND n.tenant_id=$tenant AND n.revision=$revision "
                "AND r.tenant_id=$tenant AND r.revision=$revision WITH DISTINCT n "
                "RETURN n.payload AS payload ORDER BY n.id LIMIT $limit",
                **params,
                root=root,
                key=key,
                limit=node_limit - 1,
            )
            nodes.extend(Node.model_validate_json(row["payload"]) for row in rows)
    nodes.sort(key=lambda node: node.id)
    edges = cypher_internal_edges(tx, tenant, revision, [node.id for node in nodes], edge_limit)
    return GraphSlice(
        nodes=nodes,
        edges=edges,
        warnings=warnings,
        total_nodes=total_nodes,
        total_edges=total_edges,
    )


def cypher_cluster_members(tx, tenant: str, revision: str, ids: list[str], edge_limit: int) -> GraphSlice:
    """A global-map leaf: its member nodes and the relationships among them."""
    warnings = revision_warnings(tx, {"tenant": tenant, "revision": revision})
    nodes = cypher_nodes(tx, tenant, revision, ids)
    edges = cypher_internal_edges(tx, tenant, revision, [node.id for node in nodes], edge_limit)
    return GraphSlice(nodes=nodes, edges=edges, warnings=warnings)


def memory_cluster_members(snapshot: GraphSnapshot, ids: list[str], edge_limit: int) -> GraphSlice:
    wanted = set(ids)
    nodes = sorted((node for node in snapshot.nodes if node.id in wanted), key=lambda node: node.id)
    edges = sorted(
        (edge for edge in snapshot.edges if edge.source in wanted and edge.target in wanted),
        key=lambda edge: edge.id,
    )[:edge_limit]
    return GraphSlice(
        nodes=[node.model_copy(deep=True) for node in nodes],
        edges=[edge.model_copy(deep=True) for edge in edges],
        warnings=list(snapshot.warnings),
    )


def cypher_search(tx, tenant: str, revision: str, q: str, limit: int) -> tuple[list[Node], bool]:
    q = search_text(q, limit)
    revision_warnings(tx, {"tenant": tenant, "revision": revision})
    rows = tx.run(
        "MATCH " + NODE_SCOPE + " WHERE toLower(n.id) CONTAINS $q OR toLower(n.name) CONTAINS $q "
        "RETURN n.payload AS payload ORDER BY n.id LIMIT $limit",
        tenant=tenant,
        revision=revision,
        q=q,
        limit=limit + 1,
    )
    nodes = [Node.model_validate_json(row["payload"]) for row in rows]
    return nodes[:limit], len(nodes) > limit
