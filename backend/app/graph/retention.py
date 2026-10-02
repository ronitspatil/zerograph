"""Explicit, tenant-scoped immutable graph revision maintenance.

Deletion is opt-in and requires PostgreSQL's publication row lock. This module is
not scheduled automatically and never treats legacy undated revisions as old.
"""

import argparse
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import select, text

from app.core.auth import Actor
from app.db.models import TenantState
from app.db.session import audit, session_factory
from app.graph.repository import RevisionMetadata, _validate_retention_bounds, get_graph_store


@dataclass(frozen=True)
class RetentionPolicy:
    older_than_days: int = 30
    keep_revisions: int = 5
    batch_size: int = 10

    def __post_init__(self) -> None:
        if not 1 <= self.older_than_days <= 3650:
            raise ValueError("Retention age must be 1..3650 days")
        _validate_retention_bounds(self.keep_revisions, self.batch_size)


@dataclass
class RetentionResult:
    tenant: str
    dry_run: bool
    protected_revision: str
    cutoff_ms: int
    candidates: list[RevisionMetadata]
    deleted: list[str]


def prune_revisions(
    tenant: str,
    policy: RetentionPolicy = RetentionPolicy(),
    *,
    apply: bool = False,
    actor: str = "operator:graph-retention",
    timestamp: datetime | None = None,
) -> RetentionResult:
    if not tenant or len(tenant) > 128 or not actor or len(actor) > 256:
        raise ValueError("Explicit valid tenant and operator are required")
    timestamp = timestamp or datetime.now(UTC)
    if timestamp.tzinfo is None:
        raise ValueError("Retention timestamp must include a timezone")
    cutoff = int((timestamp - timedelta(days=policy.older_than_days)).timestamp() * 1000)
    graph = get_graph_store()
    with session_factory()() as db:
        if apply and db.get_bind().dialect.name != "postgresql":
            raise ValueError("Applied retention requires PostgreSQL publication locks")
        if db.get_bind().dialect.name == "postgresql":
            db.execute(text("SET LOCAL lock_timeout = '5s'"))
        # Ingestion takes this same lock before graph publication and pointer
        # advancement. Missing SQL state must never imply an orphan tenant.
        state = db.execute(
            select(TenantState).where(TenantState.tenant_id == tenant).with_for_update()
        ).scalar_one_or_none()
        if state is None:
            raise ValueError("Tenant has no authoritative SQL state; cleanup refused")
        result = RetentionResult(
            tenant,
            not apply,
            state.revision,
            cutoff,
            graph.retention_candidates(
                tenant, state.revision, cutoff, policy.keep_revisions, policy.batch_size
            ),
            [],
        )
        if not apply:
            return result
        for revision in result.candidates:
            if revision.revision == state.revision:
                continue  # Defense in depth if an adapter violates its contract.
            detail = {
                "operation_id": str(uuid4()),
                "revision": revision.revision,
                "created_at_ms": revision.created_at_ms,
                "cutoff_ms": cutoff,
                "protected_revision": state.revision,
            }
            # The separate session commits durable intent before irreversible
            # graph I/O. AuditEvent has no tenant-state FK, so this does not
            # release or contend with the outer publication row lock.
            with session_factory()() as intent_db:
                audit(intent_db, Actor(actor, tenant, frozenset()), "graph.revision_delete_requested", detail)
                intent_db.commit()
            if graph.delete_revision(tenant, revision.revision, revision.created_at_ms, cutoff):
                result.deleted.append(revision.revision)
                audit(db, Actor(actor, tenant, frozenset()), "graph.revision_deleted", detail)
            else:
                audit(db, Actor(actor, tenant, frozenset()), "graph.revision_delete_skipped", detail)
        db.commit()
        return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Plan or apply bounded tenant graph revision retention")
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--older-than-days", type=int, default=30)
    parser.add_argument("--keep-revisions", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument("--actor", default="operator:graph-retention")
    parser.add_argument("--apply", action="store_true", help="Delete candidates; omitted means dry run")
    args = parser.parse_args()
    try:
        result = prune_revisions(
            args.tenant,
            RetentionPolicy(args.older_than_days, args.keep_revisions, args.batch_size),
            apply=args.apply,
            actor=args.actor,
        )
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(asdict(result), sort_keys=True))


if __name__ == "__main__":
    main()
