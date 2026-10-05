from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import boto3
from celery import Celery
from loguru import logger
from sqlalchemy import or_, select, update

from app.collectors import staging
from app.collectors.aws_collector import AWSCollector
from app.collectors.mcp_agent_collector import MCPInventory, collect_mcp
from app.collectors.publication import publish_sets
from app.core.auth import Actor
from app.core.config import get_settings
from app.db.locks import acquire_pointer_gate, acquire_publication_lock
from app.db.models import IngestionJob, SourceSnapshot, TenantState, UploadSession, now
from app.db.session import audit, session_factory
from app.graph.analysis import store_analysis
from app.graph.clusters import backfill_missing, compute_clusters, load_previous, store_clusters
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


@dataclass(frozen=True)
class StagedUpload:
    """A committed upload session; its rows are already validated and staged in SQL."""

    session_id: str


def collect(source: str, payload: dict, tenant: str) -> GraphSnapshot | StagedUpload:
    if source == "snapshot":
        if set(payload) == {"upload_session"}:
            return StagedUpload(str(payload["upload_session"]))
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


# A lease exceeds the hard task limit and Redis visibility timeout. A killed
# worker consumes an attempt; neither redelivery nor dispatcher restart resets it.
MAX_ATTEMPTS = 4
LEASE_DURATION = timedelta(minutes=21)
DISPATCH_RESERVATION = timedelta(seconds=60)
FAILURE_MESSAGE = (
    "Collection or graph publication failed. Check connector permissions and schema; reference job ID."
)


def _utc(timestamp: datetime) -> datetime:
    return timestamp.replace(tzinfo=UTC) if timestamp.tzinfo is None else timestamp.astimezone(UTC)


def _claim_job(job_id: str) -> tuple[str, str, dict, str] | None:
    token, timestamp = str(uuid4()), now()
    with session_factory()() as db:
        claimed = db.execute(
            update(IngestionJob)
            .where(
                IngestionJob.id == job_id,
                IngestionJob.status.in_(["queued", "retrying"]),
                IngestionJob.available_at <= timestamp,
                IngestionJob.attempt_count < MAX_ATTEMPTS,
            )
            .values(
                status="running",
                lease_token=token,
                lease_expires_at=timestamp + LEASE_DURATION,
                attempt_count=IngestionJob.attempt_count + 1,
                updated_at=timestamp,
            )
        )
        if not claimed.rowcount:
            db.rollback()
            return None
        job = db.get(IngestionJob, job_id)
        result = token, job.source, job.payload, job.tenant_id
        db.commit()
        return result


def _record_failure(job_id: str, token: str) -> None:
    with session_factory()() as db:
        job = db.execute(
            select(IngestionJob)
            .where(
                IngestionJob.id == job_id,
                IngestionJob.status == "running",
                IngestionJob.lease_token == token,
            )
            .with_for_update()
        ).scalar_one_or_none()
        if job is None:
            return  # A stale worker must not change the new owner's state.
        job.status = "failed" if job.attempt_count >= MAX_ATTEMPTS else "retrying"
        job.error = FAILURE_MESSAGE
        job.available_at = now() + timedelta(seconds=10 * 2 ** (job.attempt_count - 1))
        job.lease_token = None
        job.lease_expires_at = None
        job.dispatched_at = None
        job.updated_at = now()
        db.commit()


def process_job(job_id: str) -> None:
    claim = _claim_job(job_id)
    if claim is None:
        return
    token, source, payload, tenant = claim
    try:
        snapshot = collect(source, payload, tenant)
        _publish_job(job_id, token, tenant, snapshot)
    except Exception:
        _record_failure(job_id, token)
        raise


def _complete(db, job: IngestionJob) -> None:
    job.status = "completed"
    job.payload = {}
    job.error = None
    job.lease_token = None
    job.lease_expires_at = None
    job.updated_at = now()


def _entity_set(db, job: IngestionJob, tenant: str, collected: GraphSnapshot | StagedUpload) -> str:
    """This job's validated rows as an entity set (staged now, or by an upload session)."""
    if isinstance(collected, GraphSnapshot):
        return staging.stage_snapshot(db, tenant, job.actor, job.source, collected).id
    upload = db.get(UploadSession, collected.session_id)
    if (
        upload is None
        or upload.tenant_id != tenant
        or upload.status != "committed"
        or upload.job_id != job.id
    ):
        raise ValueError("Upload session is not committed for this job")
    return upload.id


def _source_sets(db, tenant: str) -> list[tuple[SourceSnapshot, str]]:
    """Active entity set per source, in source-name order; legacy JSON blobs are staged."""
    result = []
    for row in db.scalars(
        select(SourceSnapshot).where(SourceSnapshot.tenant_id == tenant).order_by(SourceSnapshot.source)
    ):
        set_id = (row.payload or {}).get("entity_set")
        if not set_id:
            # Release upgrade: a pre-staging source still holds one snapshot document.
            legacy = GraphSnapshot.model_validate(row.payload)
            set_id = staging.stage_snapshot(db, tenant, "migration:source-snapshot", row.source, legacy).id
            db.get(UploadSession, set_id).status = "active"
            row.payload = {"entity_set": set_id}
        result.append((row, set_id))
    return result


def _publish_job(job_id: str, token: str, tenant: str, collected: GraphSnapshot | StagedUpload) -> None:
    with session_factory()() as db:
        # Fence old owners before any source or graph writes. Hold this row lock
        # through publication: recovery cannot revoke ownership mid-commit.
        job = db.execute(
            select(IngestionJob)
            .where(
                IngestionJob.id == job_id,
                IngestionJob.tenant_id == tenant,
                IngestionJob.status == "running",
                IngestionJob.lease_token == token,
                IngestionJob.lease_expires_at > now(),
            )
            .with_for_update()
        ).scalar_one_or_none()
        if job is None:
            return
        # Serialize publishers (and retention/backfill) for a tenant for the whole
        # build. Readers are not blocked: TenantState is locked only for the swap.
        acquire_publication_lock(db, tenant)
        source_row = db.get(SourceSnapshot, (tenant, job.source))
        # Collection can finish out of order. Never overwrite a newer submitted
        # snapshot of the same source. UUID breaks equal timestamp ties stably.
        if (
            source_row
            and source_row.job_created_at
            and (_utc(source_row.job_created_at), source_row.job_id or "") > (_utc(job.created_at), job.id)
        ):
            if isinstance(collected, StagedUpload):
                staging.delete_set(db, collected.session_id)
            _complete(db, job)
            audit(db, Actor(job.actor, tenant, frozenset()), "ingestion.superseded", {"job_id": job_id})
            db.commit()
            return
        set_id = _entity_set(db, job, tenant, collected)
        db.get(UploadSession, set_id).status = "active"
        previous = None
        if source_row is None:
            source_row = SourceSnapshot(tenant_id=tenant, source=job.source)
            db.add(source_row)
        else:
            # A legacy (pre-staging) document of this source is simply replaced.
            previous = (source_row.payload or {}).get("entity_set")
        source_row.payload = {"entity_set": set_id}
        source_row.job_created_at = job.created_at
        source_row.job_id = job.id
        db.flush()
        set_ids = [set_id_ for _, set_id_ in _source_sets(db, tenant)]
        # The publication lock keeps the pointer fixed: this is the revision being replaced.
        current = db.scalar(select(TenantState.revision).where(TenantState.tenant_id == tenant)) or ""
        revision = str(uuid4())
        # Graph rows go into an invisible revision in bounded transactions; its
        # Snapshot node is "building" until finished. If anything below fails, the
        # SQL transaction rolls back (sources unchanged) and the abandoned revision
        # is never referenced; retention removes it once stale. A retry publishes
        # a new revision.
        published = publish_sets(db, get_graph_store(), tenant, revision, set_ids)
        # Analysis rows reference only the new, not yet visible revision.
        store_analysis(db, tenant, revision, published.analysis)
        # Global-map clusters, warm-started from and ID-matched to the current revision.
        clusters = compute_clusters(published.graph, revision, load_previous(db, tenant, current))
        published.graph = None
        store_clusters(db, tenant, revision, clusters)
        del clusters
        if previous and previous != set_id:
            staging.delete_set(db, previous)
        # Short pointer lock: waits only for readers' shared pins, then commits.
        # The gate makes new readers queue behind this swap instead of starving it.
        acquire_pointer_gate(db, tenant)
        state = db.execute(
            select(TenantState).where(TenantState.tenant_id == tenant).with_for_update()
        ).scalar_one()
        state.revision = revision
        state.updated_at = now()
        _complete(db, job)
        job.node_count = published.nodes
        audit(
            db,
            Actor(job.actor, tenant, frozenset()),
            "ingestion.completed",
            {"job_id": job_id, "revision": revision, "nodes": job.node_count},
        )
        db.commit()
        logger.info("Ingestion completed job={} nodes={}", job_id, job.node_count)


@celery_app.task
def ingest(job_id: str) -> None:
    try:
        process_job(job_id)
    except Exception as exc:
        # SQL state, not delivery metadata, governs retries and backoff. Beat
        # redispatches due jobs even if the broker dies after a failed attempt.
        logger.warning("Ingestion failed job={} exception_type={}", job_id, type(exc).__name__)


def _recover_expired(timestamp: datetime) -> None:
    with session_factory()() as db:
        expired = (
            IngestionJob.status == "running",
            or_(IngestionJob.lease_expires_at <= timestamp, IngestionJob.lease_expires_at.is_(None)),
        )
        ids = list(
            db.scalars(
                select(IngestionJob.id)
                .where(*expired)
                .order_by(IngestionJob.created_at, IngestionJob.id)
                .limit(100)
            )
        )
        if not ids:
            return
        for terminal in (True, False):
            budget = (
                IngestionJob.attempt_count >= MAX_ATTEMPTS
                if terminal
                else IngestionJob.attempt_count < MAX_ATTEMPTS
            )
            db.execute(
                update(IngestionJob)
                .where(IngestionJob.id.in_(ids), *expired, budget)
                .values(
                    status="failed" if terminal else "retrying",
                    error=FAILURE_MESSAGE,
                    lease_token=None,
                    lease_expires_at=None,
                    dispatched_at=None,
                    available_at=timestamp,
                    updated_at=timestamp,
                )
            )
        db.commit()


@celery_app.task
def dispatch_pending() -> int:
    timestamp = now()
    _recover_expired(timestamp)
    eligible = (
        IngestionJob.status.in_(["queued", "retrying"]),
        IngestionJob.available_at <= timestamp,
        IngestionJob.attempt_count < MAX_ATTEMPTS,
        or_(
            IngestionJob.dispatched_at.is_(None),
            IngestionJob.dispatched_at <= timestamp - DISPATCH_RESERVATION,
        ),
    )
    # Bound each sweep. Conditional UPDATE makes the reservation safe across
    # multiple dispatchers, without holding SQL transactions across broker I/O.
    with session_factory()() as db:
        ids = list(
            db.scalars(
                select(IngestionJob.id)
                .where(*eligible)
                .order_by(IngestionJob.available_at, IngestionJob.id)
                .limit(100)
            )
        )
    dispatched = 0
    for job_id in ids:
        with session_factory()() as db:
            reserved = db.execute(
                update(IngestionJob)
                .where(IngestionJob.id == job_id, *eligible)
                .values(dispatched_at=timestamp)
            )
            db.commit()
            if not reserved.rowcount:
                continue
        try:
            ingest.delay(job_id)
            dispatched += 1
        except Exception as exc:
            logger.warning("Ingestion dispatch failed job={} exception_type={}", job_id, type(exc).__name__)
            with session_factory()() as db:
                db.execute(
                    update(IngestionJob)
                    .where(
                        IngestionJob.id == job_id,
                        IngestionJob.dispatched_at == timestamp,
                        IngestionJob.status.in_(["queued", "retrying"]),
                    )
                    .values(dispatched_at=None)
                )
                db.commit()
    return dispatched


@celery_app.task
def backfill_clusters() -> int:
    """Global-map clusters for current revisions that lack them (pre-0005 or an older version)."""
    return sum(1 for result in backfill_missing() if result.get("backfilled"))


celery_app.conf.beat_schedule = {
    "recover-queued-jobs": {"task": "app.collectors.tasks.dispatch_pending", "schedule": 30.0},
    "backfill-global-map": {"task": "app.collectors.tasks.backfill_clusters", "schedule": 60.0},
}
