import hashlib
import json
import re
from datetime import datetime, timedelta
from typing import Annotated, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from app.collectors import cloudtrail, staging
from app.collectors.execution_audit import SERVICES, AuditNormalization, normalize_cloudtrail
from app.collectors.mcp_agent_collector import MCPInventory
from app.collectors.tasks import ingest
from app.core.auth import Actor, require_role
from app.core.config import get_settings
from app.db.locks import acquire_rollout_lock, pin_pointer_gate
from app.db.models import (
    AuditEvent,
    IngestionJob,
    Remediation,
    RevisionAnalysis,
    RevisionProposal,
    RevisionTopic,
    RolloutChange,
    StagedEntity,
    TenantState,
    UploadSession,
    UsageStaged,
    UsageUpload,
    UsageUploadChunk,
    now,
)
from app.db.session import audit, get_db
from app.engine.analysis_index import WEIGHTS
from app.engine.blast_radius import BlastRadius, apply_overlay
from app.engine.blast_radius import simulate as simulate_reach
from app.engine.toxic_combos import Finding
from app.graph import optimized, usage
from app.graph import proposals as optimizer
from app.graph.analysis import (
    UnknownCursor,
    compute_analysis,
    computed_findings_page,
    stored_analysis,
    stored_findings_page,
    stored_totals,
)
from app.graph.clusters import (
    MAX_EXPANDED,
    ClusterDetailResponse,
    ClusterMapResponse,
    ClusterMembersResponse,
    ClusterNotFound,
    ExpansionTooLarge,
    cluster_detail,
    cluster_expansion,
    cluster_map,
    stored_summary,
)
from app.graph.exploration import (
    ExplorationResponse,
    ExplorationView,
    RevisionUnavailable,
    RootNotFound,
    SearchResponse,
)
from app.graph.policies import PrincipalPoliciesResponse, principal_policies
from app.graph.repository import MAX_VISIBLE_EDGES, MAX_VISIBLE_MEMBERS, GraphStore, get_graph_store
from app.graph.role_map import RoleMapResponse, RoleMapView
from app.graph.schema import DATA_TYPES, IDENTITY_TYPES, GraphSnapshot, Node, NodeType
from app.graph.topics import (
    MAX_PAGE,
    TopicDetailResponse,
    TopicMapResponse,
    TopicNotFound,
    stored_privilege,
    stored_topic_summary,
    topic_detail,
    topic_map,
)
from app.remediation import rollout
from app.remediation.gitops_sync import GitOpsClient, GitOpsConflict, GitOpsError
from app.remediation.policy_optimizer import Optimization, UsageEvidence, optimize, terraform_policy

SNAPSHOT_LOCK_TIMEOUT_MS = 5000

router = APIRouter(prefix="/api/v1")
DB = Annotated[Session, Depends(get_db)]
Graph = Annotated[GraphStore, Depends(get_graph_store)]
Viewer = Annotated[Actor, Depends(require_role("viewer"))]
Analyst = Annotated[Actor, Depends(require_role("analyst"))]
Admin = Annotated[Actor, Depends(require_role("admin"))]


def tenant_state(db: Session, tenant: str) -> TenantState | None:
    return db.get(TenantState, tenant)


def pin_revision(db: Session, tenant: str) -> str:
    # Pin the authoritative pointer for this request transaction. Publishers lock
    # the row FOR UPDATE only for the final pointer swap (they build the new
    # revision without blocking readers), and retention never deletes the pointer's
    # revision, so the graph cannot disappear or advance while snapshot and
    # subsequent shortest-path queries materialize. Refresh any identity-map entry
    # loaded before the lock was acquired.
    if db.get_bind().dialect.name == "postgresql":
        db.execute(
            text("SELECT set_config('lock_timeout', :timeout, true)"),
            {"timeout": f"{SNAPSHOT_LOCK_TIMEOUT_MS}ms"},
        )
    try:
        pin_pointer_gate(db, tenant)
        state = db.execute(
            select(TenantState)
            .where(TenantState.tenant_id == tenant)
            .with_for_update(read=True)
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
    except DBAPIError as exc:
        if getattr(exc.orig, "sqlstate", None) != "55P03":
            raise
        db.rollback()
        raise HTTPException(
            503, "Graph publication or maintenance is busy; retry shortly", headers={"Retry-After": "5"}
        ) from None
    return state.revision if state else ""


def load_snapshot(db: Session, graph: GraphStore, tenant: str) -> tuple[GraphSnapshot, str]:
    revision = pin_revision(db, tenant)
    return graph.snapshot(tenant, revision), revision


class GraphResponse(BaseModel):
    revision: str
    nodes: list[Node]
    edges: list[dict]
    warnings: list[str]


@router.get("/me")
def me(actor: Viewer):
    return {"subject": actor.subject, "tenant_id": actor.tenant_id, "roles": sorted(actor.roles)}


@router.get("/graph", response_model=GraphResponse)
def graph_view(
    response: Response,
    db: DB,
    graph: Graph,
    actor: Viewer,
    account: str | None = None,
    identity_type: NodeType | None = None,
):
    """Deprecated whole-revision view, kept for small revisions only.

    Revisions above ``legacy_graph_max_nodes``/``legacy_graph_max_edges`` get 413
    before anything is loaded; bounded views are ``/graph/explore``, ``/graph/roles``
    and ``/graph/clusters``. Revisions without stored totals predate publish-time
    analysis and therefore the scale work (published under the former 5k/20k caps).
    """
    settings = get_settings()
    revision = pin_revision(db, actor.tenant_id)
    response.headers["Deprecation"] = "true"
    response.headers["Link"] = '</api/v1/graph/explore>; rel="successor-version"'
    sized = db.get(RevisionAnalysis, (actor.tenant_id, revision)) if revision else None
    if isinstance(sized, RevisionAnalysis) and (
        sized.total_nodes > settings.legacy_graph_max_nodes
        or sized.total_edges > settings.legacy_graph_max_edges
    ):
        raise HTTPException(
            413,
            f"Revision has {sized.total_nodes} entities and {sized.total_edges} relationships, above the "
            "deprecated whole-graph view limit; use /graph/explore, /graph/roles or /graph/clusters",
            headers={"Deprecation": "true"},
        )
    snapshot = graph.snapshot(actor.tenant_id, revision)
    nodes = [
        n
        for n in snapshot.nodes
        if (not account or n.account_id == account)
        and (not identity_type or n.type == identity_type or n.type not in IDENTITY_TYPES)
    ]
    ids = {n.id for n in nodes}
    return GraphResponse(
        revision=revision,
        nodes=nodes,
        edges=[
            {**e.model_dump(mode="json"), "id": e.id}
            for e in snapshot.edges
            if e.source in ids and e.target in ids
        ],
        warnings=snapshot.warnings,
    )


def expected_revision(db: Session, tenant: str, expected: str | None) -> str:
    revision = pin_revision(db, tenant)
    if expected is not None and expected != revision:
        raise HTTPException(409, "Graph revision changed; refresh the current view")
    return revision


@router.get("/graph/explore", response_model=ExplorationResponse)
def explore_graph(
    db: DB,
    graph: Graph,
    actor: Viewer,
    root_id: Annotated[str | None, Query(min_length=1, max_length=512)] = None,
    node_limit: Annotated[int, Query(ge=1, le=500)] = 250,
    edge_limit: Annotated[int, Query(ge=1, le=2000)] = 1000,
    revision: str | None = None,
):
    current = expected_revision(db, actor.tenant_id, revision)
    totals = stored_totals(db, actor.tenant_id, current)
    try:
        result = graph.explore(actor.tenant_id, current, root_id, node_limit, edge_limit, totals=totals)
    except RootNotFound:
        raise HTTPException(404, "Graph root not found") from None
    except RevisionUnavailable:
        raise HTTPException(
            503, "Published graph revision unavailable; retry shortly", headers={"Retry-After": "5"}
        ) from None
    return ExplorationResponse(
        revision=current,
        nodes=result.nodes,
        edges=[{**edge.model_dump(mode="json"), "id": edge.id} for edge in result.edges],
        warnings=result.warnings,
        view=ExplorationView(
            mode="neighborhood" if root_id is not None else "sample",
            root_id=root_id,
            node_limit=node_limit,
            edge_limit=edge_limit,
            truncated=result.truncated,
            total_nodes=result.total_nodes,
            total_edges=result.total_edges,
        ),
    )


CLUSTER_ID = r"^c[0-9a-f]{15}$|^[A-Za-z0-9_-]{1,32}$"
CLUSTERS_UNAVAILABLE = (
    "The global map is not computed for this revision yet; the worker builds it within a few minutes"
)
# The worker's backfill sweep runs every 60 s; the console retries on this hint.
CLUSTERS_RETRY_AFTER = "60"


def _clusters_missing() -> HTTPException:
    return HTTPException(404, CLUSTERS_UNAVAILABLE, headers={"Retry-After": CLUSTERS_RETRY_AFTER})


def _cluster_summary(db: Session, tenant: str, revision: str):
    summary = stored_summary(db, tenant, revision)
    if summary is None:
        raise _clusters_missing()
    return summary


def _unavailable() -> HTTPException:
    return HTTPException(
        503, "Published graph revision unavailable; retry shortly", headers={"Retry-After": "5"}
    )


@router.get("/graph/clusters", response_model=ClusterMapResponse)
def graph_clusters(
    db: DB,
    graph: Graph,
    actor: Viewer,
    level: Annotated[int, Query(ge=0, le=0)] = 0,
    edge_limit: Annotated[int, Query(ge=1, le=2000)] = 1000,
    revision: str | None = None,
):
    """Top-level structural clusters of the pinned revision (at most 300) and their link weights.

    Clusters group entities by graph structure only; they are not permission boundaries.
    """
    current = expected_revision(db, actor.tenant_id, revision)
    if not current:
        raise _clusters_missing()
    summary = _cluster_summary(db, actor.tenant_id, current)
    try:
        # Confirms the revision's graph metadata, as explore does, and carries its warnings.
        warnings = graph.cluster_members(actor.tenant_id, current, [], 1).warnings
    except RevisionUnavailable:
        raise _unavailable() from None
    return cluster_map(db, summary, warnings, edge_limit)


@router.get("/graph/clusters/{cluster_id}", response_model=ClusterDetailResponse)
def graph_cluster(
    db: DB,
    graph: Graph,
    actor: Viewer,
    cluster_id: Annotated[str, Path(pattern=CLUSTER_ID)],
    member_limit: Annotated[int, Query(ge=1, le=500)] = 500,
    edge_limit: Annotated[int, Query(ge=1, le=2000)] = 2000,
    revision: str | None = None,
):
    """Child clusters of one cluster, or a leaf's members (at most 500) and their relationships.

    Clusters group entities by graph structure only; they are not permission boundaries.
    """
    current = expected_revision(db, actor.tenant_id, revision)
    if not current:
        raise _clusters_missing()
    _cluster_summary(db, actor.tenant_id, current)
    try:
        return cluster_detail(db, graph, actor.tenant_id, current, cluster_id, member_limit, edge_limit)
    except ClusterNotFound:
        raise HTTPException(404, "Cluster not found in this revision") from None
    except RevisionUnavailable:
        raise _unavailable() from None


@router.get("/graph/clusters/{cluster_id}/members", response_model=ClusterMembersResponse)
def graph_cluster_members(
    db: DB,
    graph: Graph,
    actor: Viewer,
    cluster_id: Annotated[str, Path(pattern=CLUSTER_ID)],
    expanded: Annotated[list[str], Query(max_length=MAX_EXPANDED)] = [],  # noqa: B006
    member_limit: Annotated[int, Query(ge=1, le=MAX_VISIBLE_MEMBERS)] = MAX_VISIBLE_MEMBERS,
    edge_limit: Annotated[int, Query(ge=1, le=MAX_VISIBLE_EDGES)] = MAX_VISIBLE_EDGES,
    revision: str | None = None,
):
    """Every member of one cluster, shown in place on the map, with its relationships among
    them and to the members of the ``expanded`` clusters already on screen.

    At most 5,000 entities may be shown at once (422 above). Clusters group entities by
    graph structure only; they are not permission boundaries.
    """
    if any(not re.fullmatch(CLUSTER_ID, item) for item in expanded):
        raise HTTPException(422, "Invalid expanded cluster ID")
    current = expected_revision(db, actor.tenant_id, revision)
    if not current:
        raise _clusters_missing()
    _cluster_summary(db, actor.tenant_id, current)
    try:
        return cluster_expansion(
            db, graph, actor.tenant_id, current, cluster_id, expanded, member_limit, edge_limit
        )
    except ClusterNotFound:
        raise HTTPException(404, "Cluster not found in this revision") from None
    except ExpansionTooLarge as error:
        raise HTTPException(422, str(error)) from None
    except RevisionUnavailable:
        raise _unavailable() from None


TOPIC_ID = r"^t[0-9a-f]{15}$"
TOPICS_UNAVAILABLE = (
    "Topics are not computed for this revision yet; the worker builds them within a few minutes"
)


def _topics_missing() -> HTTPException:
    return HTTPException(404, TOPICS_UNAVAILABLE, headers={"Retry-After": CLUSTERS_RETRY_AFTER})


def _topic_summary(db: Session, tenant: str, revision: str):
    if not revision:
        raise _topics_missing()
    summary = stored_topic_summary(db, tenant, revision)
    if summary is None:
        raise _topics_missing()
    return summary


@router.get("/graph/topics", response_model=TopicMapResponse)
def graph_topics(
    db: DB,
    graph: Graph,
    actor: Viewer,
    edge_limit: Annotated[int, Query(ge=1, le=2000)] = 1000,
    revision: str | None = None,
):
    """Relationship topics of the pinned revision (at most 300) and their cross-topic grant counts.

    Topics are derived from resource tags, names and access; they are not policy boundaries.
    Counts describe granted (structural) access, not needed access.
    """
    current = expected_revision(db, actor.tenant_id, revision)
    summary = _topic_summary(db, actor.tenant_id, current)
    try:
        warnings = graph.cluster_members(actor.tenant_id, current, [], 1).warnings
    except RevisionUnavailable:
        raise _unavailable() from None
    return topic_map(db, summary, warnings, edge_limit)


@router.get("/graph/topics/{topic_id}", response_model=TopicDetailResponse)
def graph_topic(
    db: DB,
    graph: Graph,
    actor: Viewer,
    topic_id: Annotated[str, Path(pattern=TOPIC_ID)],
    kind: Literal["resource", "role", "identity"] = "resource",
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 50,
    revision: str | None = None,
):
    """One topic with a page of its data assets, roles or identities (profiles and flags) and
    its most over-privileged roles. Granted (structural) access, not needed access."""
    current = expected_revision(db, actor.tenant_id, revision)
    _topic_summary(db, actor.tenant_id, current)
    try:
        graph.cluster_members(actor.tenant_id, current, [], 1)
    except RevisionUnavailable:
        raise _unavailable() from None
    try:
        return topic_detail(db, actor.tenant_id, current, topic_id, kind, offset, limit)
    except TopicNotFound:
        raise HTTPException(404, "Topic not found in this revision") from None


class TopicSubgraphView(BaseModel):
    # Entities shown per group and the topic's totals: its roles, identities and data
    # assets, and the outside assets its shown roles have removal proposals on.
    shown: dict[str, int]
    totals: dict[str, int]
    edge_limit: int
    truncated: bool


class TopicSubgraphResponse(BaseModel):
    revision: str
    topic_id: str
    nodes: list[Node]
    edges: list[dict]
    # Entity ID -> "role", "identity", "resource" or "outside" (an asset of another topic).
    groups: dict[str, str]
    warnings: list[str]
    view: TopicSubgraphView


@router.get("/graph/topics/{topic_id}/subgraph", response_model=TopicSubgraphResponse)
def graph_topic_subgraph(
    db: DB,
    graph: Graph,
    actor: Viewer,
    topic_id: Annotated[str, Path(pattern=TOPIC_ID)],
    roles: Annotated[int, Query(ge=0, le=optimized.SLICE_LIMITS["role"])] = 40,
    identities: Annotated[int, Query(ge=0, le=optimized.SLICE_LIMITS["identity"])] = 40,
    resources: Annotated[int, Query(ge=0, le=optimized.SLICE_LIMITS["resource"])] = 80,
    outside: Annotated[int, Query(ge=0, le=optimized.SLICE_LIMITS["outside"])] = 120,
    edge_limit: Annotated[int, Query(ge=1, le=2000)] = 2000,
    revision: str | None = None,
):
    """A topic's bounded subgraph for the explorer canvas: its first roles, identities and data
    assets (by their topic rank), the assets of other topics its shown roles have removal
    proposals on, and the relationships among them (at most 500 entities). Overlay a proposal
    set with POST /proposals/overlay. Granted (structural) access, not needed access."""
    current = expected_revision(db, actor.tenant_id, revision)
    _topic_summary(db, actor.tenant_id, current)
    row = db.get(RevisionTopic, (actor.tenant_id, current, topic_id))
    if not isinstance(row, RevisionTopic):
        raise HTTPException(404, "Topic not found in this revision")
    groups = optimized.topic_slice(
        db,
        actor.tenant_id,
        current,
        topic_id,
        {"role": roles, "identity": identities, "resource": resources, "outside": outside},
    )
    kind_of: dict[str, str] = {}
    for kind in ("role", "identity", "resource", "outside"):
        for entity in groups[kind]:
            kind_of.setdefault(entity, kind)
    try:
        found = graph.cluster_members(actor.tenant_id, current, list(kind_of), edge_limit)
    except RevisionUnavailable:
        raise _unavailable() from None
    edges = found.edges[:edge_limit]
    present = {node.id for node in found.nodes}
    return TopicSubgraphResponse(
        revision=current,
        topic_id=topic_id,
        nodes=found.nodes,
        edges=[{**edge.model_dump(mode="json"), "id": edge.id} for edge in edges],
        groups={entity: kind for entity, kind in kind_of.items() if entity in present},
        warnings=found.warnings,
        view=TopicSubgraphView(
            shown={kind: sum(1 for e in groups[kind] if kind_of[e] == kind and e in present) for kind in groups},
            totals={"role": row.roles, "identity": row.identities, "resource": row.resources},
            edge_limit=edge_limit,
            truncated=len(found.edges) > edge_limit
            or len(groups["role"]) < row.roles
            or len(groups["identity"]) < row.identities
            or len(groups["resource"]) < row.resources,
        ),
    )


@router.get("/graph/policies", response_model=PrincipalPoliciesResponse)
def graph_policies(
    db: DB,
    actor: Analyst,
    principal: Annotated[str, Query(min_length=1, max_length=512)],
    revision: str | None = None,
):
    """Policy documents attached to one principal of the pinned revision (inline, managed,
    boundary, trust and group-inherited), each with its content hash."""
    current = expected_revision(db, actor.tenant_id, revision)
    return principal_policies(db, actor.tenant_id, current, principal)


@router.get("/graph/search", response_model=SearchResponse)
def search_graph(
    q: str,
    db: DB,
    graph: Graph,
    actor: Viewer,
    limit: Annotated[int, Query(ge=1, le=50)] = 25,
    revision: str | None = None,
):
    q = q.strip()
    if not 1 <= len(q) <= 128:
        raise HTTPException(422, "Search query must contain 1 to 128 characters")
    current = expected_revision(db, actor.tenant_id, revision)
    try:
        nodes, has_more = graph.search(actor.tenant_id, current, q, limit)
    except RevisionUnavailable:
        raise HTTPException(
            503, "Published graph revision unavailable; retry shortly", headers={"Retry-After": "5"}
        ) from None
    return SearchResponse(revision=current, nodes=nodes, has_more=has_more)


@router.get("/graph/roles", response_model=RoleMapResponse)
def role_map(
    db: DB,
    graph: Graph,
    actor: Viewer,
    role_limit: Annotated[int, Query(ge=1, le=100)] = 50,
    edge_limit: Annotated[int, Query(ge=1, le=2000)] = 1000,
    cursor: Annotated[str | None, Query(min_length=1, max_length=512)] = None,
    revision: str | None = None,
):
    current = expected_revision(db, actor.tenant_id, revision)
    totals = stored_totals(db, actor.tenant_id, current)
    try:
        result = graph.roles(actor.tenant_id, current, role_limit, edge_limit, cursor, totals=totals)
    except RevisionUnavailable:
        raise HTTPException(
            503, "Published graph revision unavailable; retry shortly", headers={"Retry-After": "5"}
        ) from None
    return RoleMapResponse(
        revision=current,
        nodes=result.nodes,
        edges=[{**edge.model_dump(mode="json"), "id": edge.id} for edge in result.edges],
        warnings=result.warnings,
        role_summaries=result.role_summaries,
        view=RoleMapView(
            node_limit=role_limit,
            edge_limit=edge_limit,
            truncated=result.truncated,
            total_nodes=result.total_nodes,
            total_edges=result.total_edges,
            total_roles=result.total_roles,
            total_role_edges=result.total_role_edges,
            role_map_truncated=result.role_map_truncated,
            has_more=result.has_more,
            next_cursor=result.next_cursor,
        ),
    )


def excess_privilege_tile(privilege: dict | None) -> dict | None:
    """Graph-wide excess privilege for the overview, always decomposed with/without hubs."""
    if not privilege:
        return None
    evidence = privilege.get("evidence", {})
    return {
        "status": evidence.get("status", "none"),
        "window_start": evidence.get("window_start"),
        "window_end": evidence.get("window_end"),
        "sufficient_services": evidence.get("sufficient_services", []),
        "identities": privilege["identities"],
        "roles": privilege["roles"],
        "unused_grants": privilege["unused_grants"],
        "unused_restricted_grants": privilege["unused_restricted_grants"],
        "dormant_identities": privilege["dormant_identities"],
        "dormant_roles": privilege["dormant_roles"],
    }


@router.get("/overview")
def overview(db: DB, graph: Graph, actor: Viewer):
    revision = pin_revision(db, actor.tenant_id)
    stored = stored_analysis(db, actor.tenant_id, revision)
    if stored is not None:
        privilege = stored_privilege(db, actor.tenant_id, revision) if revision else None
        return {"revision": revision, **stored.overview, "excess_privilege": excess_privilege_tile(privilege)}
    # Legacy revision (published before stored analysis) or empty tenant.
    snapshot = graph.snapshot(actor.tenant_id, revision) if revision else GraphSnapshot()
    return {"revision": revision, **compute_analysis(snapshot).overview}


@router.get("/findings", response_model=list[Finding])
def findings(
    db: DB,
    graph: Graph,
    actor: Viewer,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    cursor: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    revision: str | None = None,
):
    current = expected_revision(db, actor.tenant_id, revision)
    stored = stored_analysis(db, actor.tenant_id, current)
    try:
        if stored is not None:
            page, has_more = stored_findings_page(db, actor.tenant_id, current, cursor, limit)
            total = stored.total_findings
        else:
            snapshot = graph.snapshot(actor.tenant_id, current) if current else GraphSnapshot()
            computed = compute_analysis(snapshot).findings
            page, has_more = computed_findings_page(computed, cursor, limit)
            total = len(computed)
    except UnknownCursor:
        raise HTTPException(422, "Unknown findings cursor for this revision") from None
    headers = {"X-Graph-Revision": current, "X-Total-Count": str(total)}
    if has_more and page:
        headers["X-Next-Cursor"] = page[-1]["id"]
    return JSONResponse(page, headers=headers)


PROPOSAL_ID = r"^p[0-9a-f]{19}$"
ProposalId = Annotated[str, Field(pattern=PROPOSAL_ID)]
EntityId = Annotated[str, Field(min_length=1, max_length=512)]


class OverlayEdge(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: EntityId
    target: EntityId


class SimulationOverlay(BaseModel):
    """What-if changes: proposals of the pinned revision and/or explicit edges and nodes."""

    model_config = ConfigDict(extra="forbid")
    proposal_ids: list[ProposalId] = Field(default_factory=list, max_length=200)
    edges: list[OverlayEdge] = Field(default_factory=list, max_length=2000)
    edge_ids: list[Annotated[str, Field(min_length=1, max_length=64)]] = Field(
        default_factory=list, max_length=2000
    )
    disabled_nodes: list[EntityId] = Field(default_factory=list, max_length=500)


class SimulationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    node_id: str = Field(min_length=1, max_length=512)
    max_hops: int = Field(default=5, ge=1, le=5)
    include_uncertain: bool = False
    # Optional revision the caller is viewing: a different current revision is 409.
    revision: str | None = Field(default=None, max_length=128)
    # Optional what-if overlay: the response adds the blast radius with it applied.
    overlay: SimulationOverlay | None = None


class WhatIf(BaseModel):
    after: BlastRadius
    risk_delta: int
    exposure_delta: float
    assets_removed: list[str]
    assets_removed_count: int
    nodes_removed_count: int
    # Applied proposals by type, skipped ones (merge/split restructure roles; not simulated),
    # removed edge pairs and disabled nodes.
    overlay: dict
    notice: str = optimizer.NOTICE


class SimulationResult(BlastRadius):
    """The current blast radius; with an overlay, ``whatif`` holds the result with it applied."""

    whatif: WhatIf | None = None


def revision_scale(db: Session, graph: GraphStore, tenant: str, revision: str) -> tuple[int, int]:
    """(node count, total asset weight) of a revision, from its stored analysis.

    Only a legacy revision without stored analysis (published before it existed,
    under the former 5k-node cap) is measured from its snapshot.
    """
    row = db.get(RevisionAnalysis, (tenant, revision))
    if isinstance(row, RevisionAnalysis):
        return row.total_nodes, row.total_asset_weight
    snapshot = graph.snapshot(tenant, revision)
    weight = sum(WEIGHTS[node.sensitivity] for node in snapshot.nodes if node.type in DATA_TYPES)
    return len(snapshot.nodes), weight


def _overlay(db: Session, tenant: str, revision: str, request: SimulationOverlay) -> optimizer.Overlay:
    """Resolve proposals (in the pinned revision) and explicit changes into one overlay."""
    overlay = optimizer.Overlay()
    if request.proposal_ids:
        model = optimizer.load_model(db, tenant, revision)
        if model is None:
            raise _proposals_missing()
        try:
            ordinals = optimizer.selected_ordinals(
                db, tenant, revision, request.proposal_ids, None, None, model
            )
        except optimizer.ProposalNotFound as exc:
            raise HTTPException(404, f"Proposal not found in this revision: {exc}") from None
        overlay = optimizer.overlay_from(model, ordinals)
    overlay.removed.update((edge.source, edge.target) for edge in request.edges)
    overlay.edge_ids.update(request.edge_ids)
    overlay.disabled.update(request.disabled_nodes)
    return overlay


def _whatif(reach, overlay: optimizer.Overlay, before: BlastRadius, total_nodes: int, weight: int) -> WhatIf:
    after = simulate_reach(
        apply_overlay(reach, overlay.removed, overlay.edge_ids, overlay.disabled), total_nodes, weight
    )
    removed_assets = sorted(set(before.affected_assets) - set(after.affected_assets))
    return WhatIf(
        after=after,
        risk_delta=after.risk_score - before.risk_score,
        exposure_delta=round(after.sensitivity_exposure - before.sensitivity_exposure, 4),
        assets_removed=removed_assets[:500],
        assets_removed_count=len(removed_assets),
        nodes_removed_count=len(set(before.affected_nodes) - set(after.affected_nodes)),
        overlay={
            "applied": dict(sorted(overlay.applied.items())),
            "skipped": dict(sorted(overlay.skipped.items())),
            "removed_edges": len(overlay.removed) + len(overlay.edge_ids),
            "disabled_nodes": len(overlay.disabled),
        },
    )


def run_simulation(
    db: Session,
    graph: GraphStore,
    actor: Actor,
    revision: str,
    node_id: str,
    max_hops: int,
    include_uncertain: bool,
    overlay: SimulationOverlay | None,
) -> SimulationResult:
    resolved = _overlay(db, actor.tenant_id, revision, overlay) if overlay is not None else None
    try:
        reach = graph.reach(actor.tenant_id, revision, node_id, max_hops, include_uncertain)
    except RevisionUnavailable:
        raise _unavailable() from None
    if reach is None:
        raise HTTPException(404, "Identity not found")
    total_nodes, total_asset_weight = revision_scale(db, graph, actor.tenant_id, revision)
    result = SimulationResult(**simulate_reach(reach, total_nodes, total_asset_weight).model_dump())
    detail = {
        "node_id": node_id,
        "max_hops": max_hops,
        "include_uncertain": include_uncertain,
        "risk_score": result.risk_score,
    }
    if resolved is not None:
        result.whatif = _whatif(reach, resolved, result, total_nodes, total_asset_weight)
        detail["whatif"] = {
            "proposals": len(overlay.proposal_ids),
            "risk_after": result.whatif.after.risk_score,
            **result.whatif.overlay,
        }
    audit(db, actor, "simulation.run", detail)
    db.commit()
    return result


@router.post("/simulate", response_model=SimulationResult, response_model_exclude_none=True)
def simulate(request: SimulationRequest, response: Response, db: DB, graph: Graph, actor: Analyst):
    """Blast radius from the source's bounded neighborhood; never loads the whole revision.

    With ``overlay`` (proposal IDs of the pinned revision and/or explicit edges and disabled
    nodes), ``whatif`` holds the blast radius with those changes applied and the risk delta.
    """
    revision = expected_revision(db, actor.tenant_id, request.revision)
    result = run_simulation(
        db,
        graph,
        actor,
        revision,
        request.node_id,
        request.max_hops,
        request.include_uncertain,
        request.overlay,
    )
    response.headers["X-Graph-Revision"] = revision
    return result


# ---------------------------------------------------------------------------
# Optimizer proposals (proposed, never applied)

PROPOSALS_UNAVAILABLE = (
    "Proposals are not computed for this revision yet; the worker builds them within a few minutes"
)


def _proposals_missing() -> HTTPException:
    return HTTPException(404, PROPOSALS_UNAVAILABLE, headers={"Retry-After": CLUSTERS_RETRY_AFTER})


def _proposal_summary(db: Session, tenant: str, revision: str):
    summary = optimizer.stored_proposal_summary(db, tenant, revision)
    if summary is None:
        raise _proposals_missing()
    return summary


@router.get("/proposals", response_model=optimizer.ProposalListResponse)
def list_proposals(
    db: DB,
    actor: Viewer,
    response: Response,
    tier: Literal[optimizer.TIERS] | None = None,
    type: Literal[optimizer.TYPES] | None = None,
    topic: Annotated[str | None, Query(pattern=TOPIC_ID)] = None,
    subject: Annotated[str | None, Query(min_length=1, max_length=512)] = None,
    state: Literal["pending", "accepted", "rejected"] | None = None,
    cursor: Annotated[int | None, Query(ge=-1, le=10_000_000)] = None,
    limit: Annotated[int, Query(ge=1, le=optimizer.MAX_PAGE)] = 50,
    revision: str | None = None,
):
    """Least-privilege proposals of the pinned revision in their deterministic order (tier, type,
    weight, ID), filtered by tier, type, topic, role (subject or target) or decision state.
    Proposed, not applied."""
    current = expected_revision(db, actor.tenant_id, revision)
    summary = _proposal_summary(db, actor.tenant_id, current)
    response.headers["X-Graph-Revision"] = current
    return optimizer.proposal_page(
        db,
        summary,
        tier=tier,
        kind=type,
        topic=topic,
        subject=subject,
        state=state,
        cursor=cursor,
        limit=limit,
    )


@router.get("/proposals/summary")
def proposals_summary(db: DB, actor: Viewer, revision: str | None = None):
    """Counts by tier, type and topic, high-tier excess privilege after, and decision counts."""
    current = expected_revision(db, actor.tenant_id, revision)
    summary = _proposal_summary(db, actor.tenant_id, current)
    totals = summary.totals if isinstance(summary.totals, dict) else json.loads(summary.totals)
    return {
        "revision": current,
        **totals,
        "decisions": optimizer.decision_counts(db, actor.tenant_id, current),
    }


class MetricsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    proposal_ids: list[ProposalId] = Field(default_factory=list, max_length=optimizer.MAX_SELECTED)
    tier: Literal[optimizer.TIERS] | None = None
    # "accepted": every proposal of the revision the tenant accepted (carried forward by ID).
    decision: Literal["accepted", "rejected"] | None = None
    revision: str | None = Field(default=None, max_length=128)


@router.post("/proposals/metrics")
def proposal_metrics(request: MetricsRequest, db: DB, actor: Viewer, response: Response):
    """Excess privilege (graph, per topic, roles and identities, with and without hubs) and
    counts before and after applying a set of proposals: explicit IDs, a whole tier and/or the
    accepted ones. Evaluated on the revision's stored what-if model, never its snapshot."""
    current = expected_revision(db, actor.tenant_id, request.revision)
    _proposal_summary(db, actor.tenant_id, current)
    model = optimizer.load_model(db, actor.tenant_id, current)
    if model is None:
        raise _proposals_missing()
    try:
        ordinals = optimizer.selected_ordinals(
            db, actor.tenant_id, current, request.proposal_ids, request.tier, request.decision, model
        )
    except optimizer.ProposalNotFound as exc:
        raise HTTPException(404, f"Proposal not found in this revision: {exc}") from None
    response.headers["X-Graph-Revision"] = current
    return {
        "revision": current,
        "selected": len(ordinals),
        **model.evaluate(model.selection(ordinals)),
        "notice": optimizer.NOTICE,
    }


def _selected(db: Session, tenant: str, revision: str, request: "MetricsRequest"):
    """(model, selection key, selection) of a proposal set of the pinned revision."""
    model = optimizer.load_model(db, tenant, revision)
    if model is None:
        raise _proposals_missing()
    try:
        ordinals = optimizer.selected_ordinals(
            db, tenant, revision, request.proposal_ids, request.tier, request.decision, model
        )
    except optimizer.ProposalNotFound as exc:
        raise HTTPException(404, f"Proposal not found in this revision: {exc}") from None
    key = optimized.selection_key(tenant, revision, ordinals)
    return model, key, ordinals, optimized.selection_of(model, key, ordinals)


class OverlayRequest(MetricsRequest):
    # The visible slice: entity IDs on screen (explorer view, neighborhood or topic subgraph).
    node_ids: list[Annotated[str, Field(min_length=1, max_length=512)]] = Field(
        min_length=1, max_length=optimized.MAX_SLICE
    )


@router.post("/proposals/overlay")
def proposal_overlay(request: OverlayRequest, db: DB, actor: Viewer, response: Response):
    """The optimized view of a visible slice: the grants a proposal set (explicit IDs, a tier
    and/or the accepted ones) would remove, the role or tool hops it would cut and the nodes
    it would disable, restricted to edges and nodes inside the slice, with the set's
    graph-wide counts (as /proposals/metrics reports them). Simulated, never applied."""
    current = expected_revision(db, actor.tenant_id, request.revision)
    _proposal_summary(db, actor.tenant_id, current)
    model, _, ordinals, chosen = _selected(db, actor.tenant_id, current, request)
    found = optimized.slice_overlay(model, chosen, request.node_ids)
    response.headers["X-Graph-Revision"] = current
    return {
        "revision": current,
        "selected": len(ordinals),
        "removed_edges": [{"source": a, "target": b, "kind": "grant"} for a, b in found.removed]
        + [{"source": a, "target": b, "kind": "hop"} for a, b in found.cut],
        "disabled_nodes": found.disabled,
        "slice": {
            "nodes": len(set(request.node_ids)),
            "outside_model": found.unknown,
            "grants_removed": len(found.removed),
            "hops_cut": len(found.cut),
            "disabled_nodes": len(found.disabled),
        },
        "totals": optimized.selection_totals(model, chosen),
        "applied": dict(sorted(chosen.applied.items())),
        "applied_tiers": dict(sorted(chosen.tiers.items())),
        "skipped": dict(sorted(chosen.skipped.items())),
        "notice": optimizer.NOTICE,
    }


@router.post("/proposals/links")
def proposal_links(request: MetricsRequest, db: DB, actor: Viewer, response: Response):
    """The optimized topics map: cross-topic grants a proposal set would remove per topic link
    (counted like the map's links) and each topic's excess privilege before and after."""
    current = expected_revision(db, actor.tenant_id, request.revision)
    _topic_summary(db, actor.tenant_id, current)
    _proposal_summary(db, actor.tenant_id, current)
    model, key, ordinals, chosen = _selected(db, actor.tenant_id, current, request)
    assets = optimized.resource_topics(db, actor.tenant_id, current, model)
    evaluated = optimized.evaluation_of(model, key, chosen)
    response.headers["X-Graph-Revision"] = current
    return {
        "revision": current,
        "selected": len(ordinals),
        "links": optimized.link_removals(model, assets, chosen),
        "topics": evaluated["topics"],
        "graph": evaluated["graph"],
        "counts": evaluated["counts"],
        "skipped": evaluated["skipped"],
        "notice": optimizer.NOTICE,
    }


@router.get("/proposals/overview")
def proposals_overview(db: DB, actor: Viewer, response: Response, revision: str | None = None):
    """Overview tiles: graph-wide excess privilege now, after the accepted proposals and after
    the high tier (with and without hubs), dormant identities, unused grants on restricted
    data, decisions, and rollout changes by state (pull requests open, canaries watching,
    verified, rolled back). What-if only: nothing is applied."""
    current = expected_revision(db, actor.tenant_id, revision)
    summary = _proposal_summary(db, actor.tenant_id, current)
    totals = summary.totals if isinstance(summary.totals, dict) else json.loads(summary.totals)
    model, key, ordinals, chosen = _selected(
        db, actor.tenant_id, current, MetricsRequest(decision="accepted", revision=current)
    )
    accepted = optimized.evaluation_of(model, key, chosen)
    if rollout.refresh(db, actor.tenant_id):
        db.commit()
    states = dict(
        db.execute(
            select(RolloutChange.state, func.count())
            .where(RolloutChange.tenant_id == actor.tenant_id)
            .group_by(RolloutChange.state)
        ).all()
    )
    watching = db.scalar(
        select(func.count())
        .select_from(RolloutChange)
        .where(
            RolloutChange.tenant_id == actor.tenant_id,
            RolloutChange.state == "merged",
            RolloutChange.canary.is_(True),
        )
    )
    privilege = stored_privilege(db, actor.tenant_id, current) or {}
    response.headers["X-Graph-Revision"] = current
    return {
        "revision": current,
        "evidence": totals.get("evidence", {"status": "none"}),
        "now": {kind: accepted["graph"][kind]["before"] for kind in ("roles", "identities")},
        "after_accepted": {kind: accepted["graph"][kind]["after"] for kind in ("roles", "identities")},
        "after_high": {kind: totals["high_tier"]["graph"][kind]["after"] for kind in ("roles", "identities")},
        "accepted": {"selected": len(ordinals), "counts": accepted["counts"]},
        "high": {"selected": totals["by_tier"].get("high", 0), "counts": totals["high_tier"]["counts"]},
        "decisions": optimizer.decision_counts(db, actor.tenant_id, current),
        "dormant_identities": privilege.get("dormant_identities", 0),
        "dormant_roles": privilege.get("dormant_roles", 0),
        "unused_grants": privilege.get("unused_grants", 0),
        "unused_restricted_grants": privilege.get("unused_restricted_grants", 0),
        "rollout": {
            **{state: states.get(state, 0) for state in rollout.STATES},
            "canary_watching": watching or 0,
        },
        "notice": optimizer.NOTICE,
    }


BULK_MAX = 500


class BulkDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    proposal_ids: list[ProposalId] = Field(min_length=1, max_length=BULK_MAX)
    state: Literal["accepted", "rejected", "pending"]
    # Bulk decisions stay within one tier and one topic (safety model): every proposal must match.
    tier: Literal[optimizer.TIERS]
    topic_id: Annotated[str, Field(pattern=TOPIC_ID)]
    note: str = Field(default="", max_length=500)
    revision: str | None = Field(default=None, max_length=128)


@router.post("/proposals/decisions")
def decide_proposals(request: BulkDecisionRequest, db: DB, actor: Admin):
    """Accept, reject or clear up to 500 proposals at once, all of one tier and one topic
    (manual-tier proposals are decided one at a time). Each decision is audited like a single
    one; nothing is applied."""
    if request.tier == "manual" and request.state == "accepted":
        raise HTTPException(422, "Manual-tier proposals are accepted one at a time")
    current = expected_revision(db, actor.tenant_id, request.revision)
    _proposal_summary(db, actor.tenant_id, current)
    ids = sorted(set(request.proposal_ids))
    rows = list(
        db.scalars(
            select(RevisionProposal).where(
                RevisionProposal.tenant_id == actor.tenant_id,
                RevisionProposal.revision == current,
                RevisionProposal.proposal_id.in_(ids),
            )
        )
    )
    missing = sorted(set(ids) - {row.proposal_id for row in rows})
    if missing:
        raise HTTPException(404, f"Proposal not found in this revision: {','.join(missing[:5])}")
    if any(row.tier != request.tier or row.topic_id != request.topic_id for row in rows):
        raise HTTPException(422, "Bulk decisions are limited to proposals of one tier and one topic")
    action = {"accepted": "proposal.accepted", "rejected": "proposal.rejected"}.get(
        request.state, "proposal.cleared"
    )
    for row in sorted(rows, key=lambda r: r.ordinal):
        optimizer.decide(
            db, actor.tenant_id, current, row.proposal_id, request.state, actor.subject, request.note
        )
        audit(
            db,
            actor,
            action,
            {
                "proposal_id": row.proposal_id,
                "revision": current,
                "type": row.type,
                "tier": row.tier,
                "subject": row.subject_id,
                "target": row.target_id,
                "digest": row.digest,
                "note": request.note,
                "bulk": {"tier": request.tier, "topic_id": request.topic_id, "count": len(rows)},
            },
        )
    db.commit()
    return {
        "revision": current,
        "state": request.state,
        "decided": len(rows),
        "tier": request.tier,
        "topic_id": request.topic_id,
        "decisions": optimizer.decision_counts(db, actor.tenant_id, current),
        "notice": optimizer.NOTICE,
    }


class ProposalSimulationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    proposal_ids: list[ProposalId] = Field(min_length=1, max_length=200)
    # Source of the blast radius; default: the first proposal's subject.
    node_id: str | None = Field(default=None, min_length=1, max_length=512)
    max_hops: int = Field(default=5, ge=1, le=5)
    # Granted access includes conditional edges (AWS edges are conditional).
    include_uncertain: bool = True
    revision: str | None = Field(default=None, max_length=128)


@router.post("/proposals/simulate", response_model=SimulationResult, response_model_exclude_none=True)
def simulate_proposals(
    request: ProposalSimulationRequest, response: Response, db: DB, graph: Graph, actor: Viewer
):
    """Blast radius before and after one or more proposals of the pinned revision (simulated only)."""
    current = expected_revision(db, actor.tenant_id, request.revision)
    _proposal_summary(db, actor.tenant_id, current)
    node_id = request.node_id
    if node_id is None:
        try:
            node_id = optimizer.proposal_row(db, actor.tenant_id, current, request.proposal_ids[0]).subject_id
        except optimizer.ProposalNotFound:
            raise HTTPException(404, "Proposal not found in this revision") from None
    result = run_simulation(
        db,
        graph,
        actor,
        current,
        node_id,
        request.max_hops,
        request.include_uncertain,
        SimulationOverlay(proposal_ids=request.proposal_ids),
    )
    response.headers["X-Graph-Revision"] = current
    return result


@router.get("/proposals/{proposal_id}", response_model=optimizer.ProposalDetailResponse)
def get_proposal(
    db: DB,
    actor: Viewer,
    response: Response,
    proposal_id: Annotated[str, Path(pattern=PROPOSAL_ID)],
    revision: str | None = None,
):
    """One proposal with its evidence (window, sources, coverage, peers, last-used hint), topic
    and label reason, affected identities, exact edges changed and the graph-wide EPI delta."""
    current = expected_revision(db, actor.tenant_id, revision)
    summary = _proposal_summary(db, actor.tenant_id, current)
    response.headers["X-Graph-Revision"] = current
    try:
        return optimizer.proposal_detail(db, summary, proposal_id)
    except optimizer.ProposalNotFound:
        raise HTTPException(404, "Proposal not found in this revision") from None


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # "pending" clears an earlier decision.
    state: Literal["accepted", "rejected", "pending"]
    note: str = Field(default="", max_length=500)
    revision: str | None = Field(default=None, max_length=128)


@router.post("/proposals/{proposal_id}/decision")
def decide_proposal(
    request: DecisionRequest,
    db: DB,
    actor: Admin,
    proposal_id: Annotated[str, Path(pattern=PROPOSAL_ID)],
):
    """Accept or reject a proposal (nothing is applied; see /rollout for pull requests). The
    decision is stored per tenant by the proposal's stable ID and carries forward."""
    current = expected_revision(db, actor.tenant_id, request.revision)
    _proposal_summary(db, actor.tenant_id, current)
    try:
        row = optimizer.proposal_row(db, actor.tenant_id, current, proposal_id)
        optimizer.decide(
            db, actor.tenant_id, current, proposal_id, request.state, actor.subject, request.note
        )
    except optimizer.ProposalNotFound:
        raise HTTPException(404, "Proposal not found in this revision") from None
    action = {"accepted": "proposal.accepted", "rejected": "proposal.rejected"}.get(
        request.state, "proposal.cleared"
    )
    audit(
        db,
        actor,
        action,
        {
            "proposal_id": proposal_id,
            "revision": current,
            "type": row.type,
            "tier": row.tier,
            "subject": row.subject_id,
            "target": row.target_id,
            "digest": row.digest,
            "note": request.note,
        },
    )
    db.commit()
    decision = db.get(optimizer.ProposalDecision, (actor.tenant_id, proposal_id))
    return {
        "revision": current,
        "proposal_id": proposal_id,
        "state": request.state,
        "decision": optimizer._decision(decision, row.digest) if decision is not None else None,
        "notice": optimizer.NOTICE,
    }


# ---------------------------------------------------------------------------
# Optimizer rollout: accepted proposals -> draft pull requests, canary, rollback.
# Nothing is applied by ZeroGraph; merging happens in the customer's repository.

TOPIC_KEY = r"^[A-Za-z0-9_.:-]{1,32}$"
ChangeId = Annotated[str, Path(pattern=r"^[0-9a-f-]{36}$")]


class RolloutSelection(BaseModel):
    """One principal (a pull request per role) or one topic (a bundle of its principals)."""

    model_config = ConfigDict(extra="forbid")
    subject_id: str | None = Field(default=None, min_length=1, max_length=512)
    topic_id: str | None = Field(default=None, pattern=TOPIC_KEY)
    revision: str | None = Field(default=None, max_length=128)


class RevertRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(default="", max_length=500)


def tenant_key(tenant: str) -> str:
    return hashlib.sha256(tenant.encode()).hexdigest()[:16]


def _rollout_busy(exc: DBAPIError, db: Session) -> HTTPException:
    if getattr(exc.orig, "sqlstate", None) != "55P03":
        raise exc
    db.rollback()
    return HTTPException(
        503, "Rollout or graph publication is busy; retry shortly", headers={"Retry-After": "5"}
    )


def _bounded_lock(db: Session) -> None:
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SELECT set_config('lock_timeout', :timeout, true)"), {"timeout": "5000ms"})


def _plan(db: Session, tenant: str, revision: str, selection: RolloutSelection, **extra) -> rollout.Plan:
    if (selection.subject_id is None) == (selection.topic_id is None):
        raise HTTPException(422, "Choose one principal (subject_id) or one topic (topic_id)")
    _proposal_summary(db, tenant, revision)
    model = optimizer.load_model(db, tenant, revision)
    if model is None:
        raise _proposals_missing()
    try:
        return rollout.plan_change(
            db, tenant, revision, model, subject=selection.subject_id, topic=selection.topic_id, **extra
        )
    except rollout.RolloutError as exc:
        raise HTTPException(409, str(exc)) from None


def _change_simulation(db, graph, actor, revision, plan: rollout.Plan) -> dict | None:
    """Blast radius of a single principal before/after the change (None for bundles)."""
    if plan.scope != "role" or not plan.included:
        return None
    try:
        result = run_simulation(
            db,
            graph,
            actor,
            revision,
            plan.subject_id,
            5,
            True,
            SimulationOverlay(proposal_ids=plan.proposal_ids[:200]),
        )
    except HTTPException:
        return None
    after = result.whatif.after if result.whatif else result
    return {
        "risk_before": result.risk_score,
        "risk_after": after.risk_score,
        "assets_before": len(result.affected_assets),
        "assets_after": len(after.affected_assets),
        "assets_removed": result.whatif.assets_removed_count if result.whatif else 0,
    }


def _usage_evidence(db: Session, tenant: str, revision: str) -> dict:
    summary = optimizer.stored_proposal_summary(db, tenant, revision)
    totals = summary.totals if summary is not None else {}
    totals = totals if isinstance(totals, dict) else json.loads(totals)
    return totals.get("evidence", {})


def _gitops_settings(actor: Actor):
    settings = get_settings()
    if not settings.git_repository or not settings.git_token.get_secret_value():
        raise HTTPException(409, "GitOps destination is not configured")
    if settings.git_tenant_id != actor.tenant_id:
        raise HTTPException(403, "GitOps destination is not configured for this tenant")
    return settings


@router.get("/rollout")
def rollout_changes(db: DB, actor: Viewer, limit: int = Query(default=100, ge=1, le=500)):
    """Rollout changes of the tenant (newest first) with state, canary gating, PR links and the
    canary watch countdown. Merged changes whose watch passed without a flag become verified."""
    verified = rollout.refresh(db, actor.tenant_id)
    if verified:
        db.commit()
    changes = list(
        db.scalars(
            select(RolloutChange)
            .where(RolloutChange.tenant_id == actor.tenant_id)
            .order_by(RolloutChange.created_at.desc(), RolloutChange.id)
            .limit(limit)
        )
    )
    canaries: dict[str, dict] = {}
    views = []
    for change in changes:
        decision = rollout.gate(db, change) if change.state == "draft" else None
        views.append(rollout.view(change, decision))
        if change.topic_id not in canaries:
            current = rollout.canary_of(db, actor.tenant_id, change.topic_id)
            canaries[change.topic_id] = (
                {"change_id": current.id, "subject_name": current.subject_name, "state": current.state}
                if current
                else None
            )
    settings = get_settings()
    return {
        "changes": views,
        "canaries": canaries,
        "watch_days": settings.rollout_watch_days,
        "denied_threshold": settings.rollout_denied_threshold,
        "gitops_configured": bool(settings.git_repository) and settings.git_tenant_id == actor.tenant_id,
        "notice": rollout.NOTICE,
    }


@router.post("/rollout/plan")
def plan_rollout(request: RolloutSelection, db: DB, actor: Analyst):
    """Preview the change for a principal or topic bundle: eligible accepted proposals, file
    diffs, draft-only proposals with reasons. Nothing is stored or sent. Analyst: the diffs
    show policy documents (like ``GET /graph/policies``)."""
    current = expected_revision(db, actor.tenant_id, request.revision)
    plan = _plan(db, actor.tenant_id, current, request)
    note = ""
    if plan.files:
        probe = RolloutChange(
            id="", tenant_id=actor.tenant_id, scope=plan.scope, topic_id=plan.topic_id, subject_name=""
        )
        decision = rollout.gate(db, probe)
        note = (
            "Becomes the topic's canary"
            if decision.canary
            else ("Widens the rollout (canary verified)" if decision.allowed else decision.reason)
        )
    return rollout.plan_view(plan, note)


@router.post("/rollout/changes", status_code=201)
def create_rollout_change(request: RolloutSelection, db: DB, graph: Graph, actor: Admin):
    """Store a draft change (one principal, or a topic bundle) from accepted proposals. Its pull
    request opens separately, subject to canary gating."""
    try:
        current = expected_revision(db, actor.tenant_id, request.revision)
        plan = _plan(db, actor.tenant_id, current, request)
        if not plan.files:
            raise HTTPException(409, "No accepted proposal of this selection can become a pull request")
        evidence = _usage_evidence(db, actor.tenant_id, current)
        simulation = _change_simulation(db, graph, actor, current, plan)
        _bounded_lock(db)
        acquire_rollout_lock(db, actor.tenant_id)
        # Re-plan under the rollout lock: another change may have taken these proposals.
        plan = _plan(db, actor.tenant_id, current, request)
        model = optimizer.load_model(db, actor.tenant_id, current)
        change = rollout.create_change(
            db,
            actor.tenant_id,
            actor.subject,
            plan,
            model,
            evidence,
            simulation,
            get_settings().rollout_watch_days,
        )
    except rollout.RolloutError as exc:
        raise HTTPException(409, str(exc)) from None
    except DBAPIError as exc:
        raise _rollout_busy(exc, db) from None
    audit(
        db,
        actor,
        "rollout.created",
        {
            "change_id": change.id,
            "scope": change.scope,
            "subject": change.subject_id,
            "topic": change.topic_id,
            "revision": current,
            "proposals": len(change.proposal_ids),
            "files": [item["path"] for item in change.files][:50],
        },
    )
    db.commit()
    return rollout.detail(change, rollout.gate(db, change))


@router.get("/rollout/changes/{change_id}")
def get_rollout_change(change_id: ChangeId, db: DB, actor: Analyst):
    """One change with its file diffs, proposals and draft-only proposals (analyst: the diffs
    show policy documents)."""
    try:
        change = rollout.get_change(db, actor.tenant_id, change_id)
    except rollout.ChangeNotFound:
        raise HTTPException(404, "Rollout change not found") from None
    return rollout.detail(change, rollout.gate(db, change) if change.state == "draft" else None)


@router.delete("/rollout/changes/{change_id}", status_code=204)
def discard_rollout_change(change_id: ChangeId, db: DB, actor: Admin):
    """Discard a draft whose pull request was never requested (its proposals become free)."""
    try:
        change = rollout.get_change(db, actor.tenant_id, change_id, lock=True)
    except rollout.ChangeNotFound:
        raise HTTPException(404, "Rollout change not found") from None
    if change.state != "draft" or change.gitops_scope is not None:
        raise HTTPException(409, "Only a draft whose pull request was never requested can be discarded")
    for remediation_id in change.remediation_ids:
        record = db.get(Remediation, remediation_id)
        if record is not None and record.tenant_id == actor.tenant_id:
            db.delete(record)
    audit(db, actor, "rollout.discarded", {"change_id": change.id, "subject": change.subject_id})
    db.delete(change)
    db.commit()
    return Response(status_code=204)


@router.post("/rollout/changes/{change_id}/pr")
def open_rollout_pr(change_id: ChangeId, db: DB, graph: Graph, actor: Admin):
    """Open the change's draft pull request through GitOps, subject to canary gating. A draft
    generated on an older revision is regenerated first (same proposals by ID)."""
    client = None

    def refresh():
        _bounded_lock(db)
        acquire_rollout_lock(db, actor.tenant_id)
        return rollout.get_change(db, actor.tenant_id, change_id, lock=True)

    try:
        change = refresh()
        if change.pr_url:
            return {"url": change.pr_url, "state": change.state}
        if change.state != "draft":
            raise HTTPException(409, f"A {change.state} change has no pull request to open")
        decision = rollout.gate(db, change)
        if not decision.allowed:
            raise HTTPException(409, decision.reason)
        settings = _gitops_settings(actor)
        key = tenant_key(actor.tenant_id)
        if change.gitops_scope is None:
            current = pin_revision(db, actor.tenant_id)
            if change.revision != current:
                selection = (
                    RolloutSelection(subject_id=change.subject_id)
                    if change.scope == "role"
                    else RolloutSelection(topic_id=change.topic_id)
                )
                plan = _plan(
                    db,
                    actor.tenant_id,
                    current,
                    selection,
                    exclude_change=change.id,
                    only=change.proposal_ids,
                )
                model = optimizer.load_model(db, actor.tenant_id, current)
                rollout.regenerate(
                    db,
                    change,
                    plan,
                    model,
                    _usage_evidence(db, actor.tenant_id, current),
                    None,
                    actor.subject,
                )
                audit(db, actor, "rollout.regenerated", {"change_id": change.id, "revision": current})
            client = GitOpsClient(settings)
            files = rollout.change_files(db, change)
            scope = client.change_scope(change.id, key, files)
            change.gitops_scope = {**scope, "canary": decision.canary}
            change.canary = decision.canary
            change.summary = {**change.summary, "canary_note": rollout.canary_note(change, decision)}
            change.updated_at = now()
            audit(
                db,
                actor,
                "rollout.pr_requested",
                {"change_id": change.id, "canary": decision.canary, "scope": scope},
            )
            db.commit()  # Durable intent (and the canary claim) precede provider side effects.
            change = refresh()
            if change.pr_url:
                return {"url": change.pr_url, "state": change.state}
            client.close()
        settings = _gitops_settings(actor)
        client = GitOpsClient(settings)
        files = rollout.change_files(db, change)
        scope = client.change_scope(change.id, key, files)
        if {k: v for k, v in change.gitops_scope.items() if k != "canary"} != scope:
            raise HTTPException(409, "Change destination or content changed; discard and recreate the change")
        db.commit()  # Release the rollout lock before calling the provider.
        pr = client.open_change(
            change.id,
            key,
            files,
            rollout.pr_title(change),
            rollout.pr_body(change, change.summary.get("canary_note", ""), key, settings.git_policy_prefix),
        )
        change = rollout.get_change(db, actor.tenant_id, change_id, lock=True)
        if not change.pr_url:
            change.pr_url, change.state, change.updated_at = pr.url, "pr_open", now()
            for remediation_id in change.remediation_ids:
                record = db.get(Remediation, remediation_id)
                if record is not None:
                    record.pr_url, record.status = pr.url, "pr_opened"
            audit(
                db,
                actor,
                "rollout.pr_opened",
                {"change_id": change.id, "url": pr.url, "canary": change.canary},
            )
        db.commit()
        return {"url": change.pr_url, "state": change.state}
    except rollout.ChangeNotFound:
        raise HTTPException(404, "Rollout change not found") from None
    except rollout.RolloutError as exc:
        raise HTTPException(409, str(exc)) from None
    except GitOpsConflict as exc:
        raise HTTPException(409, str(exc)) from None
    except GitOpsError as exc:
        raise HTTPException(502, str(exc)) from None
    except DBAPIError as exc:
        raise _rollout_busy(exc, db) from None
    finally:
        if client is not None:
            client.close()


@router.post("/rollout/changes/{change_id}/merged")
def mark_rollout_merged(change_id: ChangeId, db: DB, actor: Admin):
    """Record that the pull request was merged in the customer's repository; the canary watch starts."""
    return _transition(db, actor, change_id, "merged")


@router.post("/rollout/changes/{change_id}/reverted")
def mark_rollout_reverted(change_id: ChangeId, db: DB, actor: Admin):
    """Record that the revert pull request was merged; the change is rolled back."""
    return _transition(db, actor, change_id, "rolled_back")


def _transition(db: Session, actor: Actor, change_id: str, target: str) -> dict:
    try:
        _bounded_lock(db)
        acquire_rollout_lock(db, actor.tenant_id)
        change = rollout.get_change(db, actor.tenant_id, change_id, lock=True)
        rollout.transition(change, target)
    except rollout.ChangeNotFound:
        raise HTTPException(404, "Rollout change not found") from None
    except rollout.RolloutError as exc:
        raise HTTPException(409, str(exc)) from None
    except DBAPIError as exc:
        raise _rollout_busy(exc, db) from None
    audit(
        db,
        actor,
        f"rollout.{target}",
        {"change_id": change.id, "canary": change.canary, "watch_days": change.watch_days},
    )
    db.commit()
    return rollout.view(change)


def open_revert(db: Session, actor: Actor, change_id: str, reason: str, automatic: bool = False) -> dict:
    """Open (or find) the change's revert pull request: restores every original byte for byte.
    Never merges. Audited; used by the API and by the AccessDenied watch."""
    client = None
    try:
        _bounded_lock(db)
        change = rollout.get_change(db, actor.tenant_id, change_id, lock=True)
        if change.revert_pr_url:
            return {"url": change.revert_pr_url, "state": change.state}
        rollout.can_revert(change)
        settings = _gitops_settings(actor)
        key = tenant_key(actor.tenant_id)
        client = GitOpsClient(settings)
        files = rollout.revert_files(db, change)
        scope = client.change_scope(change.id, key, files, "revert")
        if change.revert_scope is None:
            change.revert_scope = scope
            change.state, change.updated_at = "revert_open", now()
            audit(
                db,
                actor,
                "rollout.revert_requested",
                {"change_id": change.id, "automatic": automatic, "reason": reason[:500], "scope": scope},
            )
            db.commit()
            change = rollout.get_change(db, actor.tenant_id, change_id, lock=True)
            if change.revert_pr_url:
                return {"url": change.revert_pr_url, "state": change.state}
        elif change.revert_scope != scope:
            raise HTTPException(409, "Revert destination or content changed; revert manually")
        db.commit()
        pr = client.open_change(
            change.id,
            key,
            files,
            f"ZeroGraph: revert least-privilege change for {change.subject_name}",
            rollout.revert_body(change, reason or "Requested by an administrator"),
            purpose="revert",
        )
        change = rollout.get_change(db, actor.tenant_id, change_id, lock=True)
        if not change.revert_pr_url:
            change.revert_pr_url, change.revert_error, change.updated_at = pr.url, None, now()
            audit(
                db,
                actor,
                "rollout.revert_opened",
                {"change_id": change.id, "url": pr.url, "automatic": automatic},
            )
        db.commit()
        return {"url": change.revert_pr_url, "state": change.state}
    except (GitOpsConflict, GitOpsError) as exc:
        db.rollback()
        try:
            change = rollout.get_change(db, actor.tenant_id, change_id, lock=True)
            change.revert_error = str(exc)[:256]
            audit(db, actor, "rollout.revert_failed", {"change_id": change_id, "error": str(exc)[:256]})
            db.commit()
        except rollout.ChangeNotFound:
            db.rollback()
        raise HTTPException(409 if isinstance(exc, GitOpsConflict) else 502, str(exc)) from None
    finally:
        if client is not None:
            client.close()


@router.post("/rollout/changes/{change_id}/revert")
def revert_rollout_change(change_id: ChangeId, request: RevertRequest, db: DB, actor: Admin):
    """One-click revert: a draft pull request restoring the original policies (never merged)."""
    try:
        return open_revert(db, actor, change_id, request.reason or "Requested by an administrator")
    except rollout.ChangeNotFound:
        raise HTTPException(404, "Rollout change not found") from None
    except rollout.RolloutError as exc:
        raise HTTPException(409, str(exc)) from None
    except DBAPIError as exc:
        raise _rollout_busy(exc, db) from None


MAX_AUTOMATIC_REVERTS = 10


def access_denied_watch(db: Session, actor: Actor, upload_id: str) -> dict | None:
    """After a usage upload: flag merged changes with AccessDenied on what they touched inside
    their watch window and open (never merge) a revert pull request for each. Best effort: a
    failure is recorded on the change and audited, never fails the upload."""
    settings = get_settings()
    try:
        _bounded_lock(db)
        acquire_rollout_lock(db, actor.tenant_id)
        flagged = rollout.access_denied(db, actor.tenant_id, settings.rollout_denied_threshold)
        for change in flagged:
            audit(
                db,
                Actor(rollout.HOOK_ACTOR, actor.tenant_id, frozenset()),
                "rollout.flagged",
                {
                    "change_id": change.id,
                    "upload_id": upload_id,
                    "events": change.flag["events"],
                    "by": actor.subject,
                },
            )
        db.commit()
    except DBAPIError:
        db.rollback()
        return {
            "flagged": [],
            "reverts": [],
            "error": "Rollout watch busy; it runs again with the next upload",
        }
    if not flagged:
        return {"flagged": [], "reverts": []}
    reverts = []
    hook = Actor(rollout.HOOK_ACTOR, actor.tenant_id, frozenset({"admin"}))
    for change in flagged[:MAX_AUTOMATIC_REVERTS]:
        try:
            found = open_revert(
                db, hook, change.id, f"AccessDenied events after merge (upload {upload_id})", True
            )
            reverts.append({"change_id": change.id, "url": found["url"]})
        except (HTTPException, rollout.RolloutError) as exc:
            detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
            reverts.append({"change_id": change.id, "error": str(detail)[:256]})
    return {"flagged": [change.id for change in flagged], "reverts": reverts}


@router.get("/proposals/{proposal_id}/draft")
def proposal_draft(
    db: DB,
    actor: Viewer,
    proposal_id: Annotated[str, Path(pattern=PROPOSAL_ID)],
    revision: str | None = None,
):
    """A reviewed description of the change a proposal makes, and whether it can become a pull
    request (merges, splits, wildcard scoping and manual-tier proposals are draft only)."""
    current = expected_revision(db, actor.tenant_id, revision)
    _proposal_summary(db, actor.tenant_id, current)
    try:
        row = optimizer.proposal_row(db, actor.tenant_id, current, proposal_id)
    except optimizer.ProposalNotFound:
        raise HTTPException(404, "Proposal not found in this revision") from None
    reason = rollout.draft_reason(row)
    held = rollout.active_proposals(db, actor.tenant_id).get(proposal_id)
    return {
        "revision": current,
        "proposal_id": proposal_id,
        "pr_eligible": reason is None,
        "reason": reason,
        "text": rollout.draft_text(row, reason),
        "change_id": held,
        "notice": rollout.NOTICE,
    }


class IngestionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: Literal["snapshot", "mcp", "aws", "demo"]
    payload: dict = Field(default_factory=dict)


class JobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    status: str
    source: str
    error: str | None
    node_count: int
    created_at: datetime
    updated_at: datetime


def ensure_tenant_state(db: Session, tenant: str) -> None:
    if tenant_state(db, tenant) is None:
        db.add(TenantState(tenant_id=tenant))
        try:
            db.commit()
        except IntegrityError:
            db.rollback()


def enqueue_job(db: Session, actor: Actor, source: str, payload: dict, detail: dict) -> IngestionJob:
    job = IngestionJob(
        id=str(uuid4()),
        tenant_id=actor.tenant_id,
        actor=actor.subject,
        source=source,
        payload=payload,
    )
    db.add(job)
    audit(db, actor, "ingestion.requested", {"job_id": job.id, "source": source, **detail})
    db.commit()
    try:
        ingest.delay(job.id)
    except Exception:
        # Beat recovers the committed outbox row after broker availability returns.
        pass
    return job


@router.post("/ingestions", response_model=JobResponse, status_code=202)
def start_ingestion(request: IngestionRequest, db: DB, actor: Admin):
    settings = get_settings()
    payload = request.payload
    try:
        if request.source == "snapshot":
            snapshot = GraphSnapshot.model_validate(payload)
            if len(snapshot.nodes) > settings.max_nodes or len(snapshot.edges) > settings.max_edges:
                raise HTTPException(413, "Snapshot exceeds the configured node or edge limit")
            payload = snapshot.model_dump(mode="json")
        elif request.source == "mcp":
            payload = MCPInventory.model_validate(payload).model_dump(mode="json")
            # MCP definitions may contain credentials. Persist transport only; the collector never executes them.
            payload["mcpServers"] = {
                name: ({"url": "redacted"} if "url" in value else {"transport": "stdio"})
                for name, value in payload["mcpServers"].items()
            }
        elif payload:
            raise ValueError("AWS and demo ingestion do not accept a payload")
    except ValueError as exc:
        raise HTTPException(422, "Invalid ingestion schema") from exc
    if request.source == "demo" and not (settings.demo_mode and actor.tenant_id == "demo"):
        raise HTTPException(403, "Demo fixtures are disabled")
    if request.source == "aws" and (not settings.aws_role_arn or settings.aws_tenant_id != actor.tenant_id):
        raise HTTPException(409, "AWS connector is not configured for this tenant")
    ensure_tenant_state(db, actor.tenant_id)
    return enqueue_job(db, actor, request.source, payload, {})


class UploadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: Literal["snapshot"] = "snapshot"


class UploadResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    status: str
    source: str
    node_count: int
    edge_count: int
    warning_count: int
    expires_at: datetime
    max_chunk_bytes: int
    max_nodes: int
    max_edges: int


def upload_response(upload: UploadSession) -> UploadResponse:
    settings = get_settings()
    return UploadResponse(
        id=upload.id,
        status=upload.status,
        source=upload.source,
        node_count=upload.node_count,
        edge_count=upload.edge_count,
        warning_count=upload.warning_count,
        expires_at=upload.expires_at,
        max_chunk_bytes=settings.max_body_bytes,
        max_nodes=settings.max_nodes,
        max_edges=settings.max_edges,
    )


async def raw_body(request: Request) -> bytes:
    return await request.body()


UploadId = Annotated[str, Path(min_length=1, max_length=64)]
ChunkBody = Annotated[bytes, Depends(raw_body)]


def _utc_aware(timestamp: datetime) -> datetime:
    return timestamp if timestamp.tzinfo else timestamp.replace(tzinfo=now().tzinfo)


def open_upload(db: Session, actor: Actor, upload_id: str) -> UploadSession:
    """Lock the caller's open upload session; chunk writes and commit are serialized."""
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SELECT set_config('lock_timeout', '5000ms', true)"))
    try:
        upload = db.execute(
            select(UploadSession)
            .where(
                UploadSession.id == upload_id,
                UploadSession.tenant_id == actor.tenant_id,
                UploadSession.origin == "upload",
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
    except DBAPIError as exc:
        if getattr(exc.orig, "sqlstate", None) != "55P03":
            raise
        db.rollback()
        raise HTTPException(
            409, "Upload session is busy; retry the chunk", headers={"Retry-After": "1"}
        ) from None
    if upload is None:
        raise HTTPException(404, "Upload session not found")
    if upload.status != "open":
        raise HTTPException(409, "Upload session is no longer open")
    if _utc_aware(upload.expires_at) < now():
        raise HTTPException(410, "Upload session expired; start a new upload")
    return upload


@router.post("/ingestions/uploads", response_model=UploadResponse, status_code=201)
def create_upload(request: UploadRequest, db: DB, actor: Admin):
    """Start a chunked snapshot upload for graphs above the single-body limit."""
    settings = get_settings()
    timestamp = now()
    staging.purge_expired(db, actor.tenant_id, timestamp)
    active = db.scalar(
        select(func.count())
        .select_from(UploadSession)
        .where(
            UploadSession.tenant_id == actor.tenant_id,
            UploadSession.origin == "upload",
            UploadSession.status == "open",
            UploadSession.expires_at >= timestamp,
        )
    )
    if active >= settings.max_open_uploads:
        db.rollback()
        raise HTTPException(
            429, "Too many open uploads; commit one or let it expire", headers={"Retry-After": "60"}
        )

    upload = staging.new_session(
        db,
        actor.tenant_id,
        actor.subject,
        request.source,
        "upload",
        timedelta(seconds=settings.upload_session_ttl_seconds),
    )
    audit(db, actor, "ingestion.upload_started", {"upload_id": upload.id, "source": request.source})
    db.commit()
    return upload_response(upload)


@router.put("/ingestions/uploads/{upload_id}/chunks/{chunk}", response_model=UploadResponse)
def upload_chunk(
    upload_id: UploadId,
    chunk: Annotated[int, Path(ge=0, lt=staging.MAX_CHUNKS)],
    body: ChunkBody,
    db: DB,
    actor: Admin,
):
    """Stage one NDJSON chunk (``{"node":…}``/``{"edge":…}``/``{"policy":…}``/``{"warning":…}`` lines).

    Re-sending a chunk number replaces that chunk, so a client may retry safely.
    """
    settings = get_settings()
    upload = open_upload(db, actor, upload_id)
    try:
        rows = staging.parse_chunk(body, chunk)
    except staging.ChunkError as exc:
        db.rollback()
        raise HTTPException(422, str(exc)) from None
    db.execute(delete(StagedEntity).where(StagedEntity.session_id == upload.id, StagedEntity.chunk == chunk))
    try:
        staging.insert_rows(db, upload.id, rows)
    except IntegrityError:
        db.rollback()
        raise HTTPException(422, "Node or edge ID already staged by another chunk of this upload") from None
    totals = staging.counts(db, upload.id)
    if (
        totals["node"] > settings.max_nodes
        or totals["edge"] > settings.max_edges
        or totals["warning"] > staging.MAX_WARNINGS
        or totals["policy"] > staging.MAX_POLICIES
    ):
        db.rollback()
        raise HTTPException(413, "Upload exceeds the configured node, edge, policy or warning limit")
    upload.node_count, upload.edge_count, upload.warning_count = (
        totals["node"],
        totals["edge"],
        totals["warning"],
    )
    upload.updated_at = now()
    db.commit()
    return upload_response(upload)


@router.post("/ingestions/uploads/{upload_id}/commit", response_model=JobResponse, status_code=202)
def commit_upload(upload_id: UploadId, db: DB, actor: Admin):
    """Validate the staged graph as a whole (endpoints) and queue its publication."""
    ensure_tenant_state(db, actor.tenant_id)
    upload = open_upload(db, actor, upload_id)
    if staging.missing_endpoints(db, upload.id):
        db.rollback()
        raise HTTPException(422, "Every edge endpoint and policy principal must exist in this snapshot")
    upload.status = "committed"
    upload.updated_at = now()
    job_id = str(uuid4())
    upload.job_id = job_id
    job = IngestionJob(
        id=job_id,
        tenant_id=actor.tenant_id,
        actor=actor.subject,
        source=upload.source,
        payload={"upload_session": upload.id},
        node_count=upload.node_count,
    )
    db.add(job)
    audit(
        db,
        actor,
        "ingestion.requested",
        {"job_id": job.id, "source": upload.source, "upload_id": upload.id, "nodes": upload.node_count},
    )
    db.commit()
    try:
        ingest.delay(job.id)
    except Exception:
        pass  # Beat recovers the committed outbox row.
    return job


@router.get("/ingestions", response_model=list[JobResponse])
def list_jobs(db: DB, actor: Viewer):
    return list(
        db.scalars(
            select(IngestionJob)
            .where(IngestionJob.tenant_id == actor.tenant_id)
            .order_by(IngestionJob.created_at.desc())
            .limit(30)
        )
    )


@router.get("/ingestions/{job_id}", response_model=JobResponse)
def get_job(job_id: str, db: DB, actor: Viewer):
    job = db.get(IngestionJob, job_id)
    if job is None or job.tenant_id != actor.tenant_id:
        raise HTTPException(404, "Ingestion not found")
    return job


class PreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    identity_id: str = Field(min_length=1, max_length=512)
    policy: dict
    usage: UsageEvidence


class PreviewResponse(BaseModel):
    id: str
    identity_id: str
    optimization: Optimization


BREAK_GLASS = re.compile(r"break[-_ ]?glass|emergency", re.IGNORECASE)


def manual_only(identity: Node) -> bool:
    """Human identities marked break-glass or emergency (by name or tag) are never trimmed
    automatically: their access is reserved for rare events a usage window cannot show."""
    return identity.type == NodeType.HUMAN and any(
        BREAK_GLASS.search(value) for value in (identity.name, identity.id, *identity.tags)
    )


@router.post("/remediations/preview", response_model=PreviewResponse)
def preview(request: PreviewRequest, db: DB, graph: Graph, actor: Analyst):
    revision = pin_revision(db, actor.tenant_id)
    identity = graph.node(actor.tenant_id, revision, request.identity_id)
    if identity is None or identity.type not in IDENTITY_TYPES:
        raise HTTPException(404, "Identity not found")
    if manual_only(identity):
        raise HTTPException(409, "Break-glass or emergency human identities require manual review")
    try:
        result = optimize(request.policy, request.usage)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    record = Remediation(
        id=str(uuid4()),
        tenant_id=actor.tenant_id,
        actor=actor.subject,
        identity_id=request.identity_id,
        original=result.original,
        optimized=result.optimized,
        evidence={
            "usage": request.usage.model_dump(mode="json"),
            "revision": revision,
            "removed_actions": result.removed_actions,
            "retained_reasons": result.retained_reasons,
        },
    )
    db.add(record)
    audit(
        db,
        actor,
        "remediation.previewed",
        {"remediation_id": record.id, "removed_actions": result.removed_actions},
    )
    db.commit()
    return PreviewResponse(id=record.id, identity_id=record.identity_id, optimization=result)


@router.get("/remediations")
def list_remediations(db: DB, actor: Viewer):
    rows = db.scalars(
        select(Remediation)
        .where(Remediation.tenant_id == actor.tenant_id)
        .order_by(Remediation.created_at.desc())
        .limit(50)
    )
    return [
        {
            "id": r.id,
            "identity_id": r.identity_id,
            "status": r.status,
            "pr_url": r.pr_url,
            "created_at": r.created_at,
            "removed_actions": r.evidence.get("removed_actions", []),
        }
        for r in rows
    ]


@router.get("/remediations/{remediation_id}/terraform")
def export_terraform(remediation_id: str, db: DB, actor: Viewer):
    record = db.get(Remediation, remediation_id)
    if record is None or record.tenant_id != actor.tenant_id:
        raise HTTPException(404, "Remediation not found")
    return Response(terraform_policy(record.optimized), media_type="text/plain")


@router.post("/remediations/{remediation_id}/pr")
def create_pr(remediation_id: str, db: DB, actor: Admin):
    statement = (
        select(Remediation)
        .where(Remediation.id == remediation_id, Remediation.tenant_id == actor.tenant_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )

    def refresh():
        if db.get_bind().dialect.name == "postgresql":
            db.execute(text("SELECT set_config('lock_timeout', :timeout, true)"), {"timeout": "5000ms"})
        record = db.execute(statement).scalar_one_or_none()
        if record is None:
            raise HTTPException(404, "Remediation not found")
        return record

    def validate(record, settings):
        if record.evidence.get("rollout_id"):
            raise HTTPException(
                409, "This remediation belongs to an optimizer rollout change; use the rollout"
            )
        if record.original == record.optimized:
            raise HTTPException(409, "No policy reduction to propose")
        state = db.execute(
            select(TenantState)
            .where(TenantState.tenant_id == actor.tenant_id)
            .with_for_update(read=True)
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
        if not state or state.revision != record.evidence.get("revision"):
            raise HTTPException(409, "Graph changed since preview; generate a fresh proposal")
        if settings.git_repository and settings.git_tenant_id != actor.tenant_id:
            raise HTTPException(403, "GitOps destination is not configured for this tenant")

    client = None
    try:
        record = refresh()
        if record.evidence.get("rollout_id"):
            raise HTTPException(
                409, "This remediation belongs to an optimizer rollout change; use the rollout"
            )
        if record.pr_url:
            return {"url": record.pr_url, "status": record.status}
        settings = get_settings()
        validate(record, settings)
        client = GitOpsClient(settings)
        tenant_key = hashlib.sha256(actor.tenant_id.encode()).hexdigest()[:16]
        content = json.dumps(record.optimized, indent=2, sort_keys=True) + "\n"
        scope = client.scope(record.id, tenant_key, content)
        previous = record.evidence.get("gitops_scope")
        if previous is not None and previous != scope:
            raise HTTPException(409, "Proposal destination or content changed; generate a fresh preview")
        if previous is None:
            record.evidence = {**record.evidence, "gitops_scope": scope}
            audit(db, actor, "remediation.pr_requested", {"remediation_id": record.id, "scope": scope})
            db.commit()  # Durable intent precedes any provider side effects; releases the row lock.
            record = refresh()  # Refresh after reacquiring: another request may have completed.
            if record.pr_url:
                return {"url": record.pr_url, "status": record.status}
            settings = get_settings()
            validate(record, settings)
            client.close()
            client = GitOpsClient(settings)
            content = json.dumps(record.optimized, indent=2, sort_keys=True) + "\n"
            scope = client.scope(record.id, tenant_key, content)
            if record.evidence.get("gitops_scope") != scope:
                raise HTTPException(409, "Proposal destination or content changed; generate a fresh preview")
        pr = client.create_pr(record.id, tenant_key, content)
        record.pr_url, record.status = pr.url, "pr_opened"
        audit(db, actor, "remediation.pr_opened", {"remediation_id": record.id, "url": pr.url})
        db.commit()
        return {"url": pr.url, "status": record.status}
    except GitOpsConflict as exc:
        raise HTTPException(409, str(exc)) from None
    except GitOpsError as exc:
        raise HTTPException(502, str(exc)) from None
    except DBAPIError as exc:
        if getattr(exc.orig, "sqlstate", None) != "55P03":
            raise
        db.rollback()
        raise HTTPException(
            503, "Proposal or graph publication is busy; retry shortly", headers={"Retry-After": "5"}
        ) from None
    finally:
        if client is not None:
            client.close()


@router.get("/audit")
def audit_log(db: DB, actor: Admin, limit: int = Query(default=50, ge=1, le=200)):
    events = db.scalars(
        select(AuditEvent)
        .where(AuditEvent.tenant_id == actor.tenant_id)
        .order_by(AuditEvent.created_at.desc())
        .limit(limit)
    )
    return [
        {"id": e.id, "actor": e.actor, "action": e.action, "detail": e.detail, "created_at": e.created_at}
        for e in events
    ]


# ---------------------------------------------------------------------------
# Usage evidence: CloudTrail export uploads (observed-access store)


def usage_response(db: Session, upload: UsageUpload) -> usage.UsageUploadResponse:
    return usage.UsageUploadResponse(
        id=upload.id,
        status=upload.status,
        source=upload.source,
        revision=upload.revision,
        window_start=usage.utc(upload.window_start),
        window_end=usage.utc(upload.window_end),
        attested_services=upload.attested_services,
        progress=usage.progress(db, upload.id) if upload.status == "open" else upload.stats,
        expires_at=usage.utc(upload.expires_at),
        max_chunk_bytes=get_settings().max_body_bytes,
        max_decompressed_bytes=cloudtrail.MAX_DECOMPRESSED_BYTES,
    )


def open_usage_upload(db: Session, actor: Actor, upload_id: str) -> UsageUpload:
    """Lock the caller's open usage upload; file writes and commit are serialized."""
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SELECT set_config('lock_timeout', '5000ms', true)"))
    try:
        upload = db.execute(
            select(UsageUpload)
            .where(UsageUpload.id == upload_id, UsageUpload.tenant_id == actor.tenant_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
    except DBAPIError as exc:
        if getattr(exc.orig, "sqlstate", None) != "55P03":
            raise
        db.rollback()
        raise HTTPException(
            409, "Usage upload is busy; retry the file", headers={"Retry-After": "1"}
        ) from None
    if upload is None:
        raise HTTPException(404, "Usage upload not found")
    if upload.status != "open":
        raise HTTPException(409, "Usage upload is no longer open")
    if _utc_aware(upload.expires_at) < now():
        raise HTTPException(410, "Usage upload expired; start a new upload")
    return upload


@router.post("/usage/uploads", response_model=usage.UsageUploadResponse, status_code=201)
def create_usage_upload(request: usage.UsageUploadRequest, db: DB, actor: Admin):
    """Start an upload of CloudTrail export files covering one declared window.

    ``attested_services`` are the services (``s3``, ``sts``, ``glue``...) whose events the
    customer attests are completely captured in the files for the whole window.
    """
    settings = get_settings()
    timestamp = now()
    if request.source != usage.SOURCE:
        raise HTTPException(422, "Unsupported usage evidence source")
    try:
        usage.validate_window(request.window_start, request.window_end, timestamp)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    services = sorted(set(request.attested_services))
    if len(services) > len(SERVICES) or any(service not in SERVICES for service in services):
        raise HTTPException(422, "Attested services must be supported CloudTrail services")
    usage.purge_expired(db, actor.tenant_id, timestamp)
    active = db.scalar(
        select(func.count())
        .select_from(UsageUpload)
        .where(
            UsageUpload.tenant_id == actor.tenant_id,
            UsageUpload.status == "open",
            UsageUpload.expires_at >= timestamp,
        )
    )
    if active >= settings.max_open_uploads:
        db.rollback()
        raise HTTPException(
            429, "Too many open usage uploads; commit one or let it expire", headers={"Retry-After": "60"}
        )
    revision = db.scalar(select(TenantState.revision).where(TenantState.tenant_id == actor.tenant_id)) or ""
    upload = UsageUpload(
        id=str(uuid4()),
        tenant_id=actor.tenant_id,
        actor=actor.subject,
        source=usage.SOURCE,
        status="open",
        revision=revision,
        window_start=request.window_start,
        window_end=request.window_end,
        attested_services=services,
        stats={},
        created_at=timestamp,
        updated_at=timestamp,
        expires_at=timestamp + timedelta(seconds=settings.upload_session_ttl_seconds),
    )
    db.add(upload)
    db.flush()
    audit(db, actor, "usage.upload_started", {"upload_id": upload.id, "attested_services": services})
    db.commit()
    return usage_response(db, upload)


@router.put("/usage/uploads/{upload_id}/files/{chunk}", response_model=usage.UsageUploadResponse)
def upload_usage_file(
    upload_id: UploadId,
    chunk: Annotated[int, Path(ge=0, lt=usage.MAX_CHUNKS)],
    body: ChunkBody,
    db: DB,
    actor: Admin,
):
    """Normalize and stage one CloudTrail export file (JSON or gzip). Re-sending a file
    number replaces it, so a client may retry safely."""
    upload = open_usage_upload(db, actor, upload_id)
    try:
        records = cloudtrail.decode_export(body)
    except cloudtrail.ExportError as exc:
        db.rollback()
        raise HTTPException(422, str(exc)) from None
    normalized = cloudtrail.normalize_export(
        records, usage.utc(upload.window_start), usage.utc(upload.window_end)
    )
    del records
    usage.stage_chunk(db, upload, chunk, len(body), normalized)
    staged = db.scalar(
        select(func.count()).select_from(UsageStaged).where(UsageStaged.upload_id == upload.id)
    )
    if staged > usage.MAX_UPLOAD_PAIRS:
        db.rollback()
        raise HTTPException(413, "Usage upload exceeds the observed-access limit")
    upload.updated_at = now()
    db.commit()
    return usage_response(db, upload)


@router.post("/usage/uploads/{upload_id}/commit", response_model=usage.UsageCommitResponse)
def commit_usage_upload(upload_id: UploadId, db: DB, actor: Admin):
    """Store the upload's observed access and coverage. The worker then recomputes topics and
    excess privilege for the current revision (usage carries forward to later revisions)."""
    upload = open_usage_upload(db, actor, upload_id)
    if not db.scalar(
        select(func.count()).select_from(UsageUploadChunk).where(UsageUploadChunk.upload_id == upload.id)
    ):
        db.rollback()
        raise HTTPException(422, "Upload at least one CloudTrail export file before committing")
    stats = usage.commit(db, upload, now())
    audit(
        db,
        actor,
        "usage.upload_committed",
        {
            "upload_id": upload.id,
            "pairs": stats["pairs"],
            "records": stats["records"],
            "unmapped": stats["unmapped"],
        },
    )
    db.commit()
    evidence = usage.evidence(db, actor.tenant_id).as_dict()
    watch = access_denied_watch(db, actor, upload.id)
    return usage.UsageCommitResponse(
        id=upload.id,
        status=upload.status,
        revision=upload.revision,
        stats=stats,
        evidence=evidence,
        notice=usage.NOTICE,
        rollout=watch,
    )


@router.get("/usage", response_model=usage.UsageStatusResponse)
def usage_status(db: DB, actor: Viewer):
    """Usage evidence of the tenant: coverage per service, window, freshness and recent uploads."""
    uploads = db.scalars(
        select(UsageUpload)
        .where(UsageUpload.tenant_id == actor.tenant_id)
        .order_by(UsageUpload.created_at.desc())
        .limit(20)
    )
    return usage.UsageStatusResponse(
        evidence=usage.evidence(db, actor.tenant_id).as_dict(),
        uploads=[usage.upload_summary(upload) for upload in uploads],
        notice=usage.NOTICE,
    )


@router.delete("/usage/uploads/{upload_id}", status_code=204)
def delete_usage_upload(upload_id: UploadId, db: DB, actor: Admin):
    """Remove an upload and its observed access and coverage."""
    if not usage.delete_upload(db, actor.tenant_id, upload_id):
        raise HTTPException(404, "Usage upload not found")
    audit(db, actor, "usage.upload_deleted", {"upload_id": upload_id})
    db.commit()
    return Response(status_code=204)


class CloudTrailRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    identity_id: str
    events: list[dict] = Field(max_length=10000)
    window_start: datetime
    window_end: datetime
    covered_services: list[str] = Field(max_length=500)
    coverage_attested: bool = False


@router.post("/audit/normalize", response_model=AuditNormalization)
def normalize_audit(request: CloudTrailRequest, db: DB, graph: Graph, actor: Analyst):
    revision = pin_revision(db, actor.tenant_id)
    identity = graph.node(actor.tenant_id, revision, request.identity_id)
    if identity is None or identity.type not in IDENTITY_TYPES:
        raise HTTPException(404, "Identity not found")
    try:
        result = normalize_cloudtrail(
            request.events,
            request.identity_id,
            request.window_start,
            request.window_end,
            request.covered_services,
            request.coverage_attested,
        )
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, "Invalid CloudTrail export or observation window") from exc
    audit(
        db,
        actor,
        "audit.normalized",
        {
            "identity_id": request.identity_id,
            "matched_events": result.matched_events,
            "unresolved_events": result.unresolved_events,
        },
    )
    db.commit()
    return result
