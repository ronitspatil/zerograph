from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class TenantState(Base):
    __tablename__ = "tenant_states"
    tenant_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    revision: Mapped[str] = mapped_column(String(64), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class IngestionJob(Base):
    __tablename__ = "ingestion_jobs"
    __table_args__ = (Index("ix_ingestion_jobs_dispatch", "status", "available_at", "dispatched_at"),)
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    actor: Mapped[str] = mapped_column(String(256))
    status: Mapped[str] = mapped_column(String(32), default="queued")
    source: Mapped[str] = mapped_column(String(128))
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    lease_token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    node_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    actor: Mapped[str] = mapped_column(String(256))
    action: Mapped[str] = mapped_column(String(128))
    detail: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Remediation(Base):
    __tablename__ = "remediations"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    actor: Mapped[str] = mapped_column(String(256))
    status: Mapped[str] = mapped_column(String(32), default="preview")
    identity_id: Mapped[str] = mapped_column(String(512))
    original: Mapped[dict[str, Any]] = mapped_column(JSON)
    optimized: Mapped[dict[str, Any]] = mapped_column(JSON)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON)
    pr_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class SourceSnapshot(Base):
    __tablename__ = "source_snapshots"
    tenant_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    source: Mapped[str] = mapped_column(String(128), primary_key=True)
    job_created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    job_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class RevisionAnalysis(Base):
    """Whole-revision analysis computed once, before the publication pointer swap."""

    __tablename__ = "revision_analysis"
    tenant_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    revision: Mapped[str] = mapped_column(String(64), primary_key=True)
    analysis_version: Mapped[int] = mapped_column(Integer)
    overview: Mapped[dict[str, Any]] = mapped_column(JSON)
    total_nodes: Mapped[int] = mapped_column(Integer)
    total_edges: Mapped[int] = mapped_column(Integer)
    total_roles: Mapped[int] = mapped_column(Integer)
    total_role_edges: Mapped[int] = mapped_column(Integer)
    total_findings: Mapped[int] = mapped_column(Integer)
    total_asset_weight: Mapped[int] = mapped_column(Integer)
    high_blast_ids: Mapped[list[str]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class RevisionFinding(Base):
    """One toxic-combination finding of a revision, in the API's stable order (ordinal)."""

    __tablename__ = "revision_findings"
    __table_args__ = (
        Index("ux_revision_findings_finding", "tenant_id", "revision", "finding_id", unique=True),
    )
    tenant_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    revision: Mapped[str] = mapped_column(String(64), primary_key=True)
    ordinal: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class UploadSession(Base):
    """A set of staged entity rows: an API upload session or a collector's output.

    ``origin`` is "upload" (chunked API session) or "job" (rows a worker staged from
    an inline snapshot or collector). ``status``: open -> committed -> active
    (referenced by ``SourceSnapshot.payload["entity_set"]``) -> deleted when replaced.
    """

    __tablename__ = "upload_sessions"
    __table_args__ = (Index("ix_upload_sessions_tenant_status", "tenant_id", "status", "expires_at"),)
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128))
    actor: Mapped[str] = mapped_column(String(256))
    source: Mapped[str] = mapped_column(String(128))
    origin: Mapped[str] = mapped_column(String(16), default="upload")
    status: Mapped[str] = mapped_column(String(32), default="open")
    node_count: Mapped[int] = mapped_column(Integer, default=0)
    edge_count: Mapped[int] = mapped_column(Integer, default=0)
    warning_count: Mapped[int] = mapped_column(Integer, default=0)
    job_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class StagedEntity(Base):
    """One validated node, edge or warning of an entity set, in submission order.

    ``payload`` is canonical JSON (sorted keys) and ``digest`` its SHA-256, so
    cross-source conflicts are detected in SQL by comparing digests.
    """

    __tablename__ = "staged_entities"
    __table_args__ = (Index("ix_staged_entities_order", "session_id", "chunk", "ordinal"),)
    session_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(8), primary_key=True)
    entity_id: Mapped[str] = mapped_column(String(512), primary_key=True)
    chunk: Mapped[int] = mapped_column(Integer)
    ordinal: Mapped[int] = mapped_column(Integer)
    entity_type: Mapped[str] = mapped_column(String(32), default="")
    source_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    digest: Mapped[str] = mapped_column(String(64))
    payload: Mapped[str] = mapped_column(Text)
