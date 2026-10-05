"""Paged structural role map, not effective permissions or transitive analysis."""

import json
from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel

from app.graph.exploration import (
    GraphSlice,
    RevisionTotals,
    revision_warnings,
    scoped_totals,
)
from app.graph.schema import (
    DATA_TYPES,
    IDENTITY_TYPES,
    TRAVERSAL_TYPES,
    Edge,
    EdgeType,
    GraphSnapshot,
    Node,
    NodeType,
)


class RoleSummary(BaseModel):
    role_id: str
    direct_neighbors: int
    linked_identities: int
    linked_data_assets: int


@dataclass
class RoleMapSlice(GraphSlice):
    role_summaries: list[RoleSummary] = field(default_factory=list)
    total_roles: int = 0
    total_role_edges: int = 0
    has_more: bool = False
    next_cursor: str | None = None

    @property
    def role_map_truncated(self) -> bool:
        return len(self.nodes) < self.total_roles or len(self.edges) < self.total_role_edges


class RoleMapView(BaseModel):
    mode: Literal["roles"] = "roles"
    root_id: None = None
    node_limit: int
    edge_limit: int
    truncated: bool
    total_nodes: int
    total_edges: int
    total_roles: int
    total_role_edges: int
    role_map_truncated: bool
    has_more: bool
    next_cursor: str | None


class RoleMapResponse(BaseModel):
    revision: str
    nodes: list[Node]
    edges: list[dict]
    warnings: list[str]
    role_summaries: list[RoleSummary]
    view: RoleMapView


def validate_role_bounds(role_limit: int, edge_limit: int, cursor: str | None):
    if not 1 <= role_limit <= 100 or not 1 <= edge_limit <= 2000:
        raise ValueError("Role map limits outside supported bounds")
    if cursor is not None and not 1 <= len(cursor) <= 512:
        raise ValueError("Invalid role cursor")


def memory_roles(
    snapshot: GraphSnapshot,
    role_limit: int,
    edge_limit: int,
    cursor: str | None,
    totals: RevisionTotals | None = None,
) -> RoleMapSlice:
    validate_role_bounds(role_limit, edge_limit, cursor)
    roles = sorted((node for node in snapshot.nodes if node.type == NodeType.ROLE), key=lambda node: node.id)
    page = [role for role in roles if cursor is None or role.id > cursor][: role_limit + 1]
    has_more = len(page) > role_limit
    selected = page[:role_limit]
    ids = {node.id for node in selected}
    role_ids = {node.id for node in roles}
    role_edges = [
        edge
        for edge in snapshot.edges
        if edge.type in TRAVERSAL_TYPES and edge.source in role_ids and edge.target in role_ids
    ]
    visible_edges = sorted(
        (edge for edge in role_edges if edge.source in ids and edge.target in ids), key=lambda edge: edge.id
    )[:edge_limit]
    neighbors = {role_id: set() for role_id in ids}
    for edge in snapshot.edges:
        if edge.type not in TRAVERSAL_TYPES:
            continue
        if edge.source in ids:
            neighbors[edge.source].add(edge.target)
        if edge.target in ids:
            neighbors[edge.target].add(edge.source)
    for role_id, adjacent in neighbors.items():
        adjacent.discard(role_id)
    by_id = {node.id: node for node in snapshot.nodes}
    summaries = [
        RoleSummary(
            role_id=node.id,
            direct_neighbors=len(neighbors[node.id]),
            linked_identities=sum(
                by_id[neighbor].type in IDENTITY_TYPES | {NodeType.HUMAN} for neighbor in neighbors[node.id]
            ),
            linked_data_assets=sum(by_id[neighbor].type in DATA_TYPES for neighbor in neighbors[node.id]),
        )
        for node in selected
    ]
    return RoleMapSlice(
        nodes=[node.model_copy(deep=True) for node in selected],
        edges=[edge.model_copy(deep=True) for edge in visible_edges],
        warnings=list(snapshot.warnings),
        total_nodes=totals.nodes if totals else len(snapshot.nodes),
        total_edges=totals.edges if totals else len(snapshot.edges),
        role_summaries=summaries,
        total_roles=totals.roles if totals else len(roles),
        total_role_edges=totals.role_edges if totals else len(role_edges),
        has_more=has_more,
        next_cursor=selected[-1].id if has_more else None,
    )


TRAVERSAL_LABELS = "|".join(kind.value for kind in EdgeType if kind in TRAVERSAL_TYPES)
ROLE_NODE_SCOPE = "(n:Entity:CloudRole {tenant_id:$tenant, revision:$revision})"
ROLE_EDGE_SCOPE = (
    "(a:Entity:CloudRole {tenant_id:$tenant, revision:$revision})"
    f"-[r:{TRAVERSAL_LABELS} {{tenant_id:$tenant, revision:$revision}}]->"
    "(b:Entity:CloudRole {tenant_id:$tenant, revision:$revision})"
)


def cypher_roles(
    tx,
    tenant: str,
    revision: str,
    role_limit: int,
    edge_limit: int,
    cursor: str | None,
    totals: RevisionTotals | None = None,
) -> RoleMapSlice:
    validate_role_bounds(role_limit, edge_limit, cursor)
    params = {"tenant": tenant, "revision": revision}
    warnings = revision_warnings(tx, params)
    if totals:
        # Stored at publication; avoids four whole-revision count scans per page.
        total_nodes, total_edges = totals.nodes, totals.edges
        total_roles, total_role_edges = totals.roles, totals.role_edges
    else:
        total_nodes, total_edges = scoped_totals(tx, params)
        total_roles = tx.run("MATCH " + ROLE_NODE_SCOPE + " RETURN count(n) AS count", **params).single()[
            "count"
        ]
        total_role_edges = tx.run(
            "MATCH " + ROLE_EDGE_SCOPE + " RETURN count(r) AS count", **params
        ).single()["count"]
    rows = tx.run(
        "MATCH " + ROLE_NODE_SCOPE + " WHERE $cursor IS NULL OR n.id > $cursor "
        "RETURN n.payload AS payload ORDER BY n.id LIMIT $limit",
        **params,
        cursor=cursor,
        limit=role_limit + 1,
    )
    page = [Node.model_validate_json(row["payload"]) for row in rows]
    has_more = len(page) > role_limit
    nodes = page[:role_limit]
    ids = [node.id for node in nodes]
    edges, summaries = [], []
    if ids:
        rows = tx.run(
            "MATCH " + ROLE_EDGE_SCOPE + " WHERE a.id IN $ids AND b.id IN $ids "
            "RETURN r.payload AS payload ORDER BY r.id LIMIT $limit",
            **params,
            ids=ids,
            limit=edge_limit,
        )
        edges = [Edge.model_validate_json(row["payload"]) for row in rows]
        rows = tx.run(
            "UNWIND $roles AS selected "
            "MATCH (role:Entity:CloudRole {key:selected.key, tenant_id:$tenant, revision:$revision}) "
            "OPTIONAL MATCH (role)"
            f"-[r:{TRAVERSAL_LABELS} {{tenant_id:$tenant, revision:$revision}}]-"
            "(neighbor:Entity {tenant_id:$tenant, revision:$revision}) "
            "WHERE neighbor.id <> role.id "
            "RETURN role.id AS role_id, count(DISTINCT neighbor.id) AS direct_neighbors, "
            "count(DISTINCT CASE WHEN neighbor:HumanUser OR neighbor:ServiceAccount OR neighbor:AIAgent "
            "OR neighbor:MCPServer OR neighbor:CloudRole THEN neighbor.id ELSE null END) AS linked_identities, "
            "count(DISTINCT CASE WHEN neighbor:Database OR neighbor:S3Bucket OR neighbor:VectorStore "
            "THEN neighbor.id ELSE null END) AS linked_data_assets "
            "ORDER BY role_id LIMIT $limit",
            **params,
            roles=[{"key": json.dumps([tenant, revision, node_id])} for node_id in ids],
            limit=len(ids),
        )
        summaries = [RoleSummary(**dict(row)) for row in rows]
    return RoleMapSlice(
        nodes=nodes,
        edges=edges,
        warnings=warnings,
        role_summaries=summaries,
        total_nodes=total_nodes,
        total_edges=total_edges,
        total_roles=total_roles,
        total_role_edges=total_role_edges,
        has_more=has_more,
        next_cursor=nodes[-1].id if has_more else None,
    )
