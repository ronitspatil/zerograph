"""Merge a tenant's active source sets in SQL and stream them into a new revision.

Semantics match the former in-memory merge (sources in name order, entities in
submission order, first position wins, identical duplicates collapse, differing
duplicates are a conflict) followed by ``classification_edges``. Nothing here
materializes a whole-graph Pydantic snapshot: rows are streamed from SQL, written
to the graph in bounded batches, and folded into a ``CompactGraph`` for analysis.
"""

import json
from collections.abc import Iterator
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.collectors.data_classifier import RULES
from app.collectors.staging import canonical_json
from app.core.config import get_settings
from app.db.models import StagedEntity
from app.graph.compact import DATA, CompactGraph
from app.graph.policies import PolicyBudgetExceeded, store_policies
from app.graph.repository import EdgeRow, GraphStore, NodeRow
from app.graph.schema import Edge, EdgeType, Node, NodeType

MAX_COMBINED_WARNINGS = 1000
CLASSIFICATION_PREFIX = "classification:"
STREAM_BATCH = 5000


class PublicationConflict(ValueError):
    pass


class RevisionTooLarge(ValueError):
    pass


def derived_bounds(max_nodes: int, max_edges: int) -> tuple[int, int]:
    """Largest possible published revision for the given submitted-entity caps."""
    return max_nodes + len(RULES), max_edges + len(RULES) * max_nodes


@dataclass
class PublishedRevision:
    nodes: int
    edges: int
    analysis: object  # app.graph.analysis.ComputedAnalysis
    graph: CompactGraph  # For publish-time clustering; dropped by the caller after use.
    policies: int = 0  # Policy attachments stored for the revision.


def check_conflicts(db: Session, set_ids: list[str]) -> None:
    """Differing definitions of one node/edge ID across sources fail publication."""
    if len(set_ids) < 2:
        return  # A set's primary key already makes IDs unique within it.
    conflict = db.execute(
        select(StagedEntity.kind)
        .where(StagedEntity.session_id.in_(set_ids), StagedEntity.kind.in_(["node", "edge"]))
        .group_by(StagedEntity.kind, StagedEntity.entity_id)
        .having(func.count(func.distinct(StagedEntity.digest)) > 1)
        .limit(1)
    ).scalar_one_or_none()
    if conflict is not None:
        raise PublicationConflict(
            f"Conflicting {conflict} definitions across sources; reconcile IDs before publishing"
        )


def check_caps(db: Session, set_ids: list[str], max_nodes: int, max_edges: int) -> None:
    """Refuse before any graph write when the merged submitted entities exceed the caps.

    Classification annotations are derived on top: at most one category node per
    rule and one annotation edge per (tagged data asset, rule), see derived_bounds.
    """
    for kind, cap in (("node", max_nodes), ("edge", max_edges)):
        scope = (StagedEntity.session_id.in_(set_ids), StagedEntity.kind == kind)
        total = db.scalar(select(func.count()).select_from(StagedEntity).where(*scope))
        if total > cap and len(set_ids) > 1:
            total = db.scalar(select(func.count(func.distinct(StagedEntity.entity_id))).where(*scope))
        if total > cap:
            raise RevisionTooLarge(f"Revision exceeds the configured {kind} limit")


def _stream(db: Session, set_ids: list[str], kind: str) -> Iterator[tuple]:
    for set_id in set_ids:
        rows = db.execute(
            select(
                StagedEntity.entity_id,
                StagedEntity.entity_type,
                StagedEntity.source_id,
                StagedEntity.target_id,
                StagedEntity.payload,
            )
            .where(StagedEntity.session_id == set_id, StagedEntity.kind == kind)
            .order_by(StagedEntity.chunk, StagedEntity.ordinal)
            .execution_options(yield_per=STREAM_BATCH)
        )
        yield from rows


def combined_warnings(db: Session, set_ids: list[str]) -> list[str]:
    warnings: list[str] = []
    for set_id in set_ids:
        rows = db.scalars(
            select(StagedEntity.payload)
            .where(StagedEntity.session_id == set_id, StagedEntity.kind == "warning")
            .order_by(StagedEntity.chunk, StagedEntity.ordinal)
            .limit(MAX_COMBINED_WARNINGS - len(warnings))
        )
        warnings.extend(json.loads(payload) for payload in rows)
        if len(warnings) >= MAX_COMBINED_WARNINGS:
            break
    return warnings[:MAX_COMBINED_WARNINGS]


def publish_sets(
    db: Session, graph: GraphStore, tenant: str, revision: str, set_ids: list[str]
) -> PublishedRevision:
    """Build ``revision`` from the active sets (in source order); the caller swaps the pointer."""
    settings = get_settings()
    check_conflicts(db, set_ids)
    check_caps(db, set_ids, settings.max_nodes, settings.max_edges)
    size = settings.graph_batch_size
    compact = CompactGraph()
    graph.begin_revision(tenant, revision, "combined", combined_warnings(db, set_ids))

    # Nodes: first appearance wins; IDs in the classification namespace are written
    # last because classification may redefine them (as classification_edges does).
    seen: set[str] = set()
    deferred: dict[str, dict] = {}
    categories: dict[str, str] = {}  # category ID -> sensitivity (last data node wins)
    annotations: list[tuple[str, str]] = []  # (data node ID, category ID) in order
    batch: list[NodeRow] = []

    def emit_node(node: dict, payload: str) -> None:
        compact.add_node(node)
        batch.append(NodeRow(node["id"], node["type"], node["name"], payload))
        if len(batch) >= size:
            graph.write_nodes(tenant, revision, batch)
            batch.clear()

    for entity_id, entity_type, _, _, payload in _stream(db, set_ids, "node"):
        if entity_id in seen:
            continue
        seen.add(entity_id)
        node = json.loads(payload)
        if entity_type in DATA:
            for tag in node["tags"]:
                if tag in RULES:
                    category = CLASSIFICATION_PREFIX + tag
                    categories[category] = node["sensitivity"]
                    annotations.append((entity_id, category))
        if entity_id.startswith(CLASSIFICATION_PREFIX):
            deferred[entity_id] = node
            continue
        emit_node(node, payload)
    for category, sensitivity in categories.items():
        deferred[category] = Node(
            id=category,
            name=category.removeprefix(CLASSIFICATION_PREFIX),
            type=NodeType.CATEGORY,
            provider="classification",
            sensitivity=sensitivity,
        ).model_dump(mode="json")
    for node in deferred.values():
        emit_node(node, canonical_json(node))
    if batch:
        graph.write_nodes(tenant, revision, batch)
        batch.clear()
    seen.clear()

    # Edges: classification annotations replace an identical-ID edge in place and
    # are otherwise appended after all source edges.
    generated: dict[str, dict] = {}
    for source, category in annotations:
        edge = Edge(
            source=source,
            target=category,
            type=EdgeType.PII,
            certainty="declared",
            evidence=["Metadata classification; validate against data contents"],
        )
        generated[edge.id] = edge.model_dump(mode="json")
    edges: list[EdgeRow] = []

    def emit_edge(edge_id: str, edge: dict, payload: str) -> None:
        compact.add_edge(edge)
        edges.append(
            EdgeRow(edge_id, edge["source"], edge["target"], edge["type"], edge["certainty"], payload)
        )
        if len(edges) >= size:
            graph.write_edges(tenant, revision, edges)
            edges.clear()

    seen_edges: set[str] = set()
    for entity_id, _, _, _, payload in _stream(db, set_ids, "edge"):
        if entity_id in seen_edges:
            continue
        seen_edges.add(entity_id)
        if entity_id in generated:
            edge = generated.pop(entity_id)
            emit_edge(entity_id, edge, canonical_json(edge))
        else:
            emit_edge(entity_id, json.loads(payload), payload)
    for edge_id, edge in generated.items():
        emit_edge(edge_id, edge, canonical_json(edge))
    if edges:
        graph.write_edges(tenant, revision, edges)
    seen_edges.clear()
    analysis = compact.analyze()
    nodes, edge_count = compact.node_count, compact.edge_count
    # Policy documents (SQL only, never node JSON): first attachment ID wins across sources.
    try:
        policies = store_policies(
            db,
            tenant,
            revision,
            ((entity_id, payload) for entity_id, _, _, _, payload in _stream(db, set_ids, "policy")),
        )
    except PolicyBudgetExceeded as exc:
        raise RevisionTooLarge(str(exc)) from None
    graph.finish_revision(tenant, revision)
    return PublishedRevision(nodes, edge_count, analysis, compact, policies)
