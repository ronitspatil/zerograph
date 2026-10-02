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
