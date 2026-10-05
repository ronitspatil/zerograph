"""Explicit, tenant-scoped immutable graph revision maintenance.

Deletion is opt-in and requires PostgreSQL's tenant publication lock (advisory, the
same one publishers hold while building). Readers are not blocked: they only ever
pin the current pointer, which is protected and cannot move while the lock is held.
This module is not scheduled automatically and never treats legacy undated
revisions as old. Abandoned "building" revisions (a publisher died) become
candidates once older than ``STALE_BUILDING_AGE``; a young one is never selected.
"""

import argparse
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.core.auth import Actor
from app.db.locks import acquire_publication_lock
from app.db.models import TenantState
from app.db.session import audit, session_factory
from app.graph.analysis import delete_analysis
from app.graph.repository import RevisionMetadata, _validate_retention_bounds, get_graph_store

# Longer than the ingestion lease (21 minutes) and hard task limit: an older
# "building" revision has no live publisher (and the publication lock proves it).
STALE_BUILDING_AGE = timedelta(hours=1)


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
    stale_cutoff = int((timestamp - STALE_BUILDING_AGE).timestamp() * 1000)
    now_ms = int(timestamp.timestamp() * 1000)
    graph = get_graph_store()
    with session_factory()() as db:
        if apply and db.get_bind().dialect.name != "postgresql":
            raise ValueError("Applied retention requires PostgreSQL publication locks")
        if db.get_bind().dialect.name == "postgresql":
            db.execute(text("SET LOCAL lock_timeout = '5s'"))
        # Publishers hold this lock for a whole build, so no revision is under
        # construction and the pointer cannot advance until this transaction ends.
        # The shared row lock also excludes any writer that predates the advisory
        # lock. Missing SQL state must never imply an orphan tenant.
        try:
            acquire_publication_lock(db, tenant)
        except DBAPIError as exc:
            if getattr(exc.orig, "sqlstate", None) != "55P03":
                raise
            raise ValueError("Tenant publication or maintenance is in progress; retry later") from None
        state = db.execute(
            select(TenantState)
            .where(TenantState.tenant_id == tenant)
            .with_for_update(read=True)
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
        if state is None:
            raise ValueError("Tenant has no authoritative SQL state; cleanup refused")
        result = RetentionResult(
            tenant,
            not apply,
            state.revision,
            cutoff,
            graph.retention_candidates(
                tenant, state.revision, cutoff, policy.keep_revisions, policy.batch_size, stale_cutoff
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
                "state": revision.state,
                "protected_revision": state.revision,
            }
            # Each state is re-checked against its own age bound by the adapter.
            bound = {"ready": cutoff, "building": stale_cutoff}.get(revision.state, now_ms)
            # The separate session commits durable intent before irreversible
            # graph I/O. AuditEvent has no tenant-state FK, so this does not
            # release or contend with the outer publication row lock.
            with session_factory()() as intent_db:
                audit(intent_db, Actor(actor, tenant, frozenset()), "graph.revision_delete_requested", detail)
                intent_db.commit()
            if graph.delete_revision(
                tenant, revision.revision, revision.created_at_ms, bound, revision.state
            ):
                result.deleted.append(revision.revision)
                # Stored analysis goes in the same transaction that still holds
                # the tenant publication lock and records the deletion. A
                # building revision never had analysis rows; the delete is a no-op.
                delete_analysis(db, tenant, revision.revision)
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
