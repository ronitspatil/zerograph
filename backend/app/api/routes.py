import hashlib
import json
from datetime import datetime
from typing import Annotated, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.collectors.execution_audit import AuditNormalization, normalize_cloudtrail
from app.collectors.mcp_agent_collector import MCPInventory
from app.collectors.tasks import ingest
from app.core.auth import Actor, require_role
from app.core.config import get_settings
from app.db.models import AuditEvent, IngestionJob, Remediation, TenantState
from app.db.session import audit, get_db
from app.engine.blast_radius import BlastRadius, calculate
from app.engine.toxic_combos import Finding, detect
from app.graph.repository import GraphStore, get_graph_store
from app.graph.schema import IDENTITY_TYPES, GraphSnapshot, Node, NodeType
from app.remediation.gitops_sync import GitOpsClient, GitOpsError
from app.remediation.policy_optimizer import Optimization, UsageEvidence, optimize, terraform_policy

router = APIRouter(prefix="/api/v1")
DB = Annotated[Session, Depends(get_db)]
Graph = Annotated[GraphStore, Depends(get_graph_store)]
Viewer = Annotated[Actor, Depends(require_role("viewer"))]
Analyst = Annotated[Actor, Depends(require_role("analyst"))]
Admin = Annotated[Actor, Depends(require_role("admin"))]


def tenant_state(db: Session, tenant: str) -> TenantState | None:
    return db.get(TenantState, tenant)


def load_snapshot(db: Session, graph: GraphStore, tenant: str) -> tuple[GraphSnapshot, str]:
    state = tenant_state(db, tenant)
    revision = state.revision if state else ""
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
    db: DB, graph: Graph, actor: Viewer, account: str | None = None, identity_type: NodeType | None = None
):
    snapshot, revision = load_snapshot(db, graph, actor.tenant_id)
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


@router.get("/overview")
def overview(db: DB, graph: Graph, actor: Viewer):
    snapshot, revision = load_snapshot(db, graph, actor.tenant_id)
    findings = detect(snapshot)
    identities = [n for n in snapshot.nodes if n.type in IDENTITY_TYPES]
    # Count identities with sensitive reachable assets. Full scores are computed on demand.
    high_blast = sum(calculate(snapshot, n.id, include_uncertain=True).risk_score >= 70 for n in identities)
    return {
        "revision": revision,
        "total_nhis": len(identities),
        "ai_agents": sum(n.type == NodeType.AGENT for n in snapshot.nodes),
        "toxic_combinations": len(findings),
        "high_blast_radius": high_blast,
        "data_assets": sum(
            n.type in {NodeType.BUCKET, NodeType.DATABASE, NodeType.VECTOR} for n in snapshot.nodes
        ),
        "confirmed_edges": sum(e.certainty == "confirmed" for e in snapshot.edges),
        "uncertain_edges": sum(e.certainty != "confirmed" for e in snapshot.edges),
        "accounts": sorted({n.account_id for n in snapshot.nodes if n.account_id}),
        "sensitivity": {
            level: sum(
                n.sensitivity.value == level
                for n in snapshot.nodes
                if n.type in {NodeType.BUCKET, NodeType.DATABASE, NodeType.VECTOR}
            )
            for level in ["public", "internal", "confidential", "restricted"]
        },
    }


@router.get("/findings", response_model=list[Finding])
def findings(db: DB, graph: Graph, actor: Viewer):
    snapshot, _ = load_snapshot(db, graph, actor.tenant_id)
    return detect(snapshot)


class SimulationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    node_id: str = Field(min_length=1, max_length=512)
    max_hops: int = Field(default=5, ge=1, le=5)
    include_uncertain: bool = False


@router.post("/simulate", response_model=BlastRadius)
def simulate(request: SimulationRequest, db: DB, graph: Graph, actor: Analyst):
    snapshot, revision = load_snapshot(db, graph, actor.tenant_id)
    if request.node_id not in {n.id for n in snapshot.nodes}:
        raise HTTPException(404, "Identity not found")
    paths = graph.shortest_paths(
        actor.tenant_id, revision, request.node_id, request.max_hops, request.include_uncertain
    )
    result = calculate(snapshot, request.node_id, request.max_hops, request.include_uncertain, paths)
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


@router.post("/ingestions", response_model=JobResponse, status_code=202)
def start_ingestion(request: IngestionRequest, db: DB, actor: Admin):
    settings = get_settings()
    payload = request.payload
    try:
        if request.source == "snapshot":
            payload = GraphSnapshot.model_validate(payload).model_dump(mode="json")
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
    if tenant_state(db, actor.tenant_id) is None:
        db.add(TenantState(tenant_id=actor.tenant_id))
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
    job = IngestionJob(
        id=str(uuid4()),
        tenant_id=actor.tenant_id,
        actor=actor.subject,
        source=request.source,
        payload=payload,
    )
    db.add(job)
    audit(db, actor, "ingestion.requested", {"job_id": job.id, "source": request.source})
    db.commit()
    try:
        ingest.delay(job.id)
    except Exception:
        # Beat recovers the committed outbox row after broker availability returns.
        pass
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


@router.post("/remediations/preview", response_model=PreviewResponse)
def preview(request: PreviewRequest, db: DB, graph: Graph, actor: Analyst):
    snapshot, revision = load_snapshot(db, graph, actor.tenant_id)
    if not any(n.id == request.identity_id and n.type in IDENTITY_TYPES for n in snapshot.nodes):
        raise HTTPException(404, "Identity not found")
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
    record = db.execute(
        select(Remediation)
        .where(Remediation.id == remediation_id, Remediation.tenant_id == actor.tenant_id)
        .with_for_update()
    ).scalar_one_or_none()
    if record is None:
        raise HTTPException(404, "Remediation not found")
    if record.pr_url:
        return {"url": record.pr_url, "status": record.status}
    if record.original == record.optimized:
        raise HTTPException(409, "No policy reduction to propose")
    state = tenant_state(db, actor.tenant_id)
    if not state or state.revision != record.evidence.get("revision"):
        raise HTTPException(409, "Graph changed since preview; generate a fresh proposal")
    settings = get_settings()
    if settings.git_repository and settings.git_tenant_id != actor.tenant_id:
        raise HTTPException(403, "GitOps destination is not configured for this tenant")
    try:
        pr = GitOpsClient(settings).create_pr(
            record.id,
            hashlib.sha256(actor.tenant_id.encode()).hexdigest()[:16],
            json.dumps(record.optimized, indent=2) + "\n",
        )
    except GitOpsError as exc:
        raise HTTPException(502, str(exc)) from exc
    record.pr_url = pr.url
    record.status = "pr_opened"
    audit(db, actor, "remediation.pr_opened", {"remediation_id": record.id, "url": pr.url})
    db.commit()
    return {"url": pr.url, "status": record.status}


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
    snapshot, _ = load_snapshot(db, graph, actor.tenant_id)
    if request.identity_id not in {n.id for n in snapshot.nodes if n.type in IDENTITY_TYPES}:
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
