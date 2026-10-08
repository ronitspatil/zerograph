"""Tenant publication lock: serializes publishers, retention and analysis backfill.

PostgreSQL holds a transaction-scoped advisory lock keyed by tenant for the whole
build of a revision. Readers never take it: they pin ``TenantState`` FOR SHARE, and
publishers lock that row FOR UPDATE only for the final pointer swap. SQLite (tests,
local development) serializes writers itself, so the call is a no-op there.
"""

from sqlalchemy import text
from sqlalchemy.orm import Session

# Arbitrary fixed namespace ("ZG") for the two-key advisory lock form.
PUBLICATION_LOCK_NAMESPACE = 0x5A47


def acquire_publication_lock(db: Session, tenant: str) -> None:
    if db.get_bind().dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(:namespace, hashtext(:tenant))"),
            {"namespace": PUBLICATION_LOCK_NAMESPACE, "tenant": tenant},
        )


def try_publication_lock(db: Session, tenant: str) -> bool:
    """Take the publication lock only if it is free (background sweeps never queue behind a publisher)."""
    if db.get_bind().dialect.name != "postgresql":
        return True
    return bool(
        db.scalar(
            text("SELECT pg_try_advisory_xact_lock(:namespace, hashtext(:tenant))"),
            {"namespace": PUBLICATION_LOCK_NAMESPACE, "tenant": tenant},
        )
    )


# Pointer gate: readers hold it shared for their request transaction (with their
# FOR SHARE pin) and a publisher takes it exclusively just before the swap. Unlike
# row share locks, which new readers can keep joining while an exclusive locker
# waits, heavyweight lock requests queue fairly: once a swap is waiting, new
# readers wait behind it (bounded by their lock timeout), so continuous
# overlapping reads cannot starve publication.
POINTER_GATE_NAMESPACE = 0x5A48


def pin_pointer_gate(db: Session, tenant: str) -> None:
    if db.get_bind().dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock_shared(:namespace, hashtext(:tenant))"),
            {"namespace": POINTER_GATE_NAMESPACE, "tenant": tenant},
        )


def acquire_pointer_gate(db: Session, tenant: str) -> None:
    if db.get_bind().dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(:namespace, hashtext(:tenant))"),
            {"namespace": POINTER_GATE_NAMESPACE, "tenant": tenant},
        )


# Optimizer rollout: serializes canary gating and change creation per tenant (short,
# never held across Git provider calls).
ROLLOUT_LOCK_NAMESPACE = 0x5A49


def acquire_rollout_lock(db: Session, tenant: str) -> None:
    if db.get_bind().dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(:namespace, hashtext(:tenant))"),
            {"namespace": ROLLOUT_LOCK_NAMESPACE, "tenant": tenant},
        )
