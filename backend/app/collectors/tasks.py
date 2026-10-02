from datetime import timedelta
from uuid import uuid4

import boto3
from celery import Celery
from loguru import logger
from sqlalchemy import select

from app.collectors.aws_collector import AWSCollector
from app.collectors.data_classifier import classification_edges
from app.collectors.mcp_agent_collector import MCPInventory, collect_mcp
from app.core.auth import Actor
from app.core.config import get_settings
from app.db.models import IngestionJob, SourceSnapshot, TenantState, now
from app.db.session import audit, session_factory
from app.graph.demo import demo_snapshot
from app.graph.repository import get_graph_store
from app.graph.schema import GraphSnapshot

settings = get_settings()
celery_app = Celery("zerograph", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_time_limit=900,
    task_soft_time_limit=840,
    result_expires=86400,
    broker_connection_retry_on_startup=True,
    task_ignore_result=True,
    task_publish_retry=False,
    broker_transport_options={"socket_timeout": 3, "socket_connect_timeout": 3, "visibility_timeout": 1200},
)


def collect(source: str, payload: dict, tenant: str) -> GraphSnapshot:
    if source == "snapshot":
        return GraphSnapshot.model_validate(payload)
    if source == "mcp":
        return collect_mcp(MCPInventory.model_validate(payload))
    if source == "demo" and settings.demo_mode and tenant == "demo":
        return demo_snapshot()
    if source == "aws":
        if not settings.aws_role_arn or settings.aws_tenant_id != tenant:
            raise ValueError("No AWS collector is configured for this tenant")
        session = boto3.Session(region_name=settings.aws_region)
        kwargs = {"RoleArn": settings.aws_role_arn, "RoleSessionName": "ZeroGraphReadOnly"}
        if settings.aws_external_id.get_secret_value():
            kwargs["ExternalId"] = settings.aws_external_id.get_secret_value()
        credentials = session.client("sts").assume_role(**kwargs)["Credentials"]
        session = boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=settings.aws_region,
        )
        return AWSCollector(session).collect()
    raise ValueError("Unsupported ingestion source")


def process_job(job_id: str) -> None:
    with session_factory()() as db:
        job = db.execute(
            select(IngestionJob).where(IngestionJob.id == job_id).with_for_update()
        ).scalar_one_or_none()
        if job is None or job.status in {"completed", "running", "failed"}:
            return
        job.status = "running"
        job.updated_at = now()
        db.commit()
        tenant = job.tenant_id
        snapshot = collect(job.source, job.payload, tenant)
        # Persist each source separately, then publish a combined immutable revision.
        # Serialize publishers for a tenant with a row lock (PostgreSQL).
        state = db.execute(
            select(TenantState).where(TenantState.tenant_id == tenant).with_for_update()
        ).scalar_one()
        source_row = db.get(SourceSnapshot, (tenant, job.source))
        if source_row is None:
            source_row = SourceSnapshot(
                tenant_id=tenant, source=job.source, payload=snapshot.model_dump(mode="json")
            )
            db.add(source_row)
        else:
            source_row.payload = snapshot.model_dump(mode="json")
        db.flush()
        nodes, edges, warnings = {}, {}, []
        for row in db.scalars(
            select(SourceSnapshot).where(SourceSnapshot.tenant_id == tenant).order_by(SourceSnapshot.source)
        ):
            part = GraphSnapshot.model_validate(row.payload)
            for node in part.nodes:
                if node.id in nodes and nodes[node.id] != node:
                    raise ValueError(
                        "Conflicting node definitions across sources; reconcile IDs before publishing"
                    )
                nodes[node.id] = node
            for edge in part.edges:
                edges[edge.id] = edge
            warnings.extend(part.warnings)
        combined = GraphSnapshot(
            nodes=list(nodes.values()),
            edges=list(edges.values()),
            warnings=warnings[:1000],
            source="combined",
        )
        combined = GraphSnapshot.model_validate(classification_edges(combined).model_dump())
        revision = str(uuid4())
        get_graph_store().publish(tenant, revision, combined)
        state.revision = revision
        state.updated_at = now()
        job.status = "completed"
        job.error = None
        job.node_count = len(combined.nodes)
        job.payload = {}  # Retain normalized metadata in source_snapshots, not raw uploaded configuration.
        job.updated_at = now()
        audit(
            db,
            Actor(job.actor, tenant, frozenset()),
            "ingestion.completed",
            {"job_id": job_id, "revision": revision, "nodes": job.node_count},
        )
        db.commit()
        logger.info("Ingestion completed job={} nodes={}", job_id, job.node_count)


@celery_app.task(bind=True, max_retries=3)
def ingest(self, job_id: str) -> None:
    try:
        process_job(job_id)
    except Exception as exc:
        # No raw policy payloads or cloud exception strings in logs/user-visible errors.
        logger.warning("Ingestion failed job={} exception_type={}", job_id, type(exc).__name__)
        with session_factory()() as db:
            job = db.get(IngestionJob, job_id)
            if job is not None:
                job.status = "failed" if self.request.retries >= self.max_retries else "retrying"
                job.error = "Collection or graph publication failed. Check connector permissions and schema; reference job ID."
                job.updated_at = now()
                db.commit()
        raise self.retry(
            exc=RuntimeError("Ingestion failed"), countdown=2**self.request.retries * 10
        ) from None


@celery_app.task
def dispatch_pending() -> int:
    # Transactional outbox recovery: rows survive Redis outages or publisher crashes.
    with session_factory()() as db:
        stale = list(
            db.scalars(
                select(IngestionJob).where(
                    IngestionJob.status == "running", IngestionJob.updated_at < now() - timedelta(minutes=20)
                )
            )
        )
        for job in stale:
            job.status = "queued"
            job.updated_at = now()
        db.commit()
        ids = list(db.scalars(select(IngestionJob.id).where(IngestionJob.status.in_(["queued", "retrying"]))))
    for job_id in ids:
        ingest.delay(job_id)
    return len(ids)


celery_app.conf.beat_schedule = {
    "recover-queued-jobs": {"task": "app.collectors.tasks.dispatch_pending", "schedule": 30.0}
}
