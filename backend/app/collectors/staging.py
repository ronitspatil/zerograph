"""Row staging for chunked uploads and row-based source sets.

An *entity set* (``UploadSession`` + ``StagedEntity`` rows) holds one source's
validated nodes, edges and warnings in submission order. API upload sessions
stage NDJSON chunks; workers stage inline snapshots and collector output the same
way. ``SourceSnapshot.payload["entity_set"]`` names a source's active set, and
publication streams the active sets of all of a tenant's sources from SQL.

NDJSON chunk lines are single-key objects: ``{"node": {...}}``, ``{"edge": {...}}``,
``{"policy": {...}}`` (a policy document attached to a principal) or
``{"warning": "..."}``. Each line is validated with the same Pydantic models as the
single-body ingestion endpoint.
"""

import hashlib
import json
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta
from uuid import uuid4

from pydantic import ValidationError
from sqlalchemy import and_, delete, func, insert, or_, select
from sqlalchemy.orm import Session, aliased

from app.db.models import IngestionJob, StagedEntity, UploadSession, now
from app.graph.schema import MAX_SNAPSHOT_POLICIES, Edge, GraphSnapshot, Node, PolicyAttachment

LINE_KINDS = ("node", "edge", "warning", "policy")
MAX_POLICIES = MAX_SNAPSHOT_POLICIES
MAX_WARNINGS = 1000
MAX_WARNING_CHARACTERS = 2000
MAX_CHUNKS = 100_000
INSERT_BATCH = 5000


class ChunkError(ValueError):
    """A client-correctable problem with a chunk; the message never echoes payload values."""


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _row(kind: str, entity_id: str, chunk: int, ordinal: int, payload: str, **extra) -> dict:
    return {
        "kind": kind,
        "entity_id": entity_id,
        "chunk": chunk,
        "ordinal": ordinal,
        "entity_type": extra.get("entity_type", ""),
        "source_id": extra.get("source_id"),
        "target_id": extra.get("target_id"),
        "digest": hashlib.sha256(payload.encode()).hexdigest(),
        "payload": payload,
    }


def node_staged(node: Node, chunk: int, ordinal: int) -> dict:
    payload = canonical_json(node.model_dump(mode="json"))
    return _row("node", node.id, chunk, ordinal, payload, entity_type=node.type.value)


def edge_staged(edge: Edge, chunk: int, ordinal: int) -> dict:
    if len(edge.source) > 512 or len(edge.target) > 512:
        raise ValueError("Every edge endpoint must exist in this snapshot")
    payload = canonical_json(edge.model_dump(mode="json"))
    return _row(
        "edge",
        edge.id,
        chunk,
        ordinal,
        payload,
        entity_type=edge.type.value,
        source_id=edge.source,
        target_id=edge.target,
    )


def policy_staged(policy: PolicyAttachment, chunk: int, ordinal: int) -> dict:
    """A policy attachment; ``source_id`` is its principal, ``target_id`` its document digest."""
    payload = canonical_json(policy.model_dump(mode="json"))
    return _row(
        "policy",
        policy.id,
        chunk,
        ordinal,
        payload,
        entity_type=policy.kind,
        source_id=policy.principal,
        target_id=policy.digest,
    )


def warning_staged(warning: str, chunk: int, ordinal: int) -> dict:
    return _row("warning", f"{chunk}:{ordinal}", chunk, ordinal, json.dumps(warning, ensure_ascii=False))


def parse_chunk(body: bytes, chunk: int) -> list[dict]:
    """Validate one NDJSON chunk; duplicates inside the chunk are refused here."""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        raise ChunkError("Chunk must be UTF-8 NDJSON") from None
    rows, seen = [], set()
    for number, line in enumerate(text.split("\n"), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except ValueError:
            raise ChunkError(f"Line {number}: invalid JSON") from None
        if not isinstance(item, dict) or len(item) != 1 or next(iter(item)) not in LINE_KINDS:
            raise ChunkError(f"Line {number}: expected exactly one of node, edge, policy or warning")
        kind, value = next(iter(item.items()))
        try:
            if kind == "node":
                row = node_staged(Node.model_validate(value), chunk, len(rows))
            elif kind == "edge":
                row = edge_staged(Edge.model_validate(value), chunk, len(rows))
            elif kind == "policy":
                row = policy_staged(PolicyAttachment.model_validate(value), chunk, len(rows))
            else:
                if not isinstance(value, str) or len(value) > MAX_WARNING_CHARACTERS:
                    raise ValueError("invalid warning")
                row = warning_staged(value, chunk, len(rows))
        except (ValidationError, ValueError):
            raise ChunkError(f"Line {number}: invalid {kind}") from None
        key = row["kind"], row["entity_id"]
        if key in seen:
            raise ChunkError(
                f"Line {number}: "
                + {
                    "node": "Node IDs must be unique within a snapshot",
                    "edge": "Duplicate graph edges",
                    "policy": "Duplicate policy attachments",
                }[kind]
            )
        seen.add(key)
        rows.append(row)
    return rows


def snapshot_rows(snapshot: GraphSnapshot) -> Iterator[dict]:
    """One validated snapshot as staged rows (chunk 0), preserving its order."""
    ordinal = 0
    for node in snapshot.nodes:
        yield node_staged(node, 0, ordinal)
        ordinal += 1
    for edge in snapshot.edges:
        yield edge_staged(edge, 0, ordinal)
        ordinal += 1
    for warning in snapshot.warnings:
        yield warning_staged(warning, 0, ordinal)
        ordinal += 1
    for policy in snapshot.policies:
        yield policy_staged(policy, 0, ordinal)
        ordinal += 1


def insert_rows(db: Session, session_id: str, rows: Iterable[dict]) -> None:
    batch = []
    for row in rows:
        batch.append({**row, "session_id": session_id})
        if len(batch) >= INSERT_BATCH:
            db.execute(insert(StagedEntity), batch)
            batch = []
    if batch:
        db.execute(insert(StagedEntity), batch)


def counts(db: Session, session_id: str) -> dict[str, int]:
    found = dict(
        db.execute(
            select(StagedEntity.kind, func.count())
            .where(StagedEntity.session_id == session_id)
            .group_by(StagedEntity.kind)
        ).all()
    )
    return {kind: found.get(kind, 0) for kind in LINE_KINDS}


def missing_endpoints(db: Session, session_id: str) -> int:
    """Edges (and policy attachments) of the set whose endpoint (principal) is not staged in the same set."""
    edge, node = aliased(StagedEntity), aliased(StagedEntity)

    def absent(column):
        return ~(
            select(node.entity_id)
            .where(node.session_id == session_id, node.kind == "node", node.entity_id == column)
            .exists()
        )

    return db.scalar(
        select(func.count())
        .select_from(edge)
        .where(
            edge.session_id == session_id,
            or_(
                and_(edge.kind == "edge", or_(absent(edge.source_id), absent(edge.target_id))),
                and_(edge.kind == "policy", absent(edge.source_id)),
            ),
        )
    )


def new_session(
    db: Session, tenant: str, actor: str, source: str, origin: str, ttl: timedelta, status: str = "open"
) -> UploadSession:
    timestamp = now()
    session = UploadSession(
        id=str(uuid4()),
        tenant_id=tenant,
        actor=actor,
        source=source,
        origin=origin,
        status=status,
        node_count=0,
        edge_count=0,
        warning_count=0,
        created_at=timestamp,
        updated_at=timestamp,
        expires_at=timestamp + ttl,
    )
    db.add(session)
    db.flush()
    return session


def stage_snapshot(
    db: Session, tenant: str, actor: str, source: str, snapshot: GraphSnapshot
) -> UploadSession:
    """Stage a validated snapshot (inline body or collector output) as an entity set."""
    session = new_session(db, tenant, actor, source, "job", timedelta(0), status="committed")
    insert_rows(db, session.id, snapshot_rows(snapshot))
    session.node_count, session.edge_count = len(snapshot.nodes), len(snapshot.edges)
    session.warning_count = len(snapshot.warnings)
    return session


def delete_set(db: Session, session_id: str) -> None:
    db.execute(delete(StagedEntity).where(StagedEntity.session_id == session_id))
    db.execute(delete(UploadSession).where(UploadSession.id == session_id))


def purge_expired(db: Session, tenant: str, timestamp: datetime, limit: int = 20) -> int:
    """Delete abandoned sets of a tenant: expired open uploads, and committed uploads
    whose job failed terminally or no longer exists. Active sets are never touched."""
    job = aliased(IngestionJob)
    ids = list(
        db.scalars(
            select(UploadSession.id)
            .outerjoin(job, job.id == UploadSession.job_id)
            .where(
                UploadSession.tenant_id == tenant,
                UploadSession.expires_at < timestamp,
                or_(
                    UploadSession.status == "open",
                    and_(
                        UploadSession.status == "committed",
                        or_(job.id.is_(None), job.status == "failed"),
                    ),
                ),
            )
            .limit(limit)
        )
    )
    for session_id in ids:
        delete_set(db, session_id)
    return len(ids)
