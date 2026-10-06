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
from app.db.locks import pin_pointer_gate
from app.db.models import (
    AuditEvent,
    IngestionJob,
    Remediation,
    RevisionAnalysis,
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
from app.engine.blast_radius import BlastRadius
from app.engine.blast_radius import simulate as simulate_reach
from app.engine.toxic_combos import Finding
from app.graph import usage
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


class SimulationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    node_id: str = Field(min_length=1, max_length=512)
    max_hops: int = Field(default=5, ge=1, le=5)
    include_uncertain: bool = False
    # Optional revision the caller is viewing: a different current revision is 409.
    revision: str | None = Field(default=None, max_length=128)


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


@router.post("/simulate", response_model=BlastRadius)
def simulate(request: SimulationRequest, response: Response, db: DB, graph: Graph, actor: Analyst):
    """Blast radius from the source's bounded neighborhood; never loads the whole revision."""
    revision = expected_revision(db, actor.tenant_id, request.revision)
    try:
        reach = graph.reach(
            actor.tenant_id, revision, request.node_id, request.max_hops, request.include_uncertain
        )
    except RevisionUnavailable:
        raise _unavailable() from None
    if reach is None:
        raise HTTPException(404, "Identity not found")
    total_nodes, total_asset_weight = revision_scale(db, graph, actor.tenant_id, revision)
    result = simulate_reach(reach, total_nodes, total_asset_weight)
    audit(
        db,
        actor,
        "simulation.run",
        {
            "node_id": request.node_id,
            "max_hops": request.max_hops,
            "include_uncertain": request.include_uncertain,
            "risk_score": result.risk_score,
        },
    )
    db.commit()
    response.headers["X-Graph-Revision"] = revision
    return result


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
    return usage.UsageCommitResponse(
        id=upload.id,
        status=upload.status,
        revision=upload.revision,
        stats=stats,
        evidence=usage.evidence(db, actor.tenant_id).as_dict(),
        notice=usage.NOTICE,
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
