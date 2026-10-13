"""Observed-access store: usage evidence uploads, coverage attestation and evidence status.

Usage evidence is provider-neutral: ``observed_access`` rows hold (principal,
resource, action class, service) with first/last seen, a count and the source,
keyed by stable entity IDs (ARNs for AWS) and by the upload they came from. An
upload is made against the tenant's current revision and carries forward to later
revisions because IDs are stable; principals or resources absent from a revision
are simply not matched there.

Each committed upload attests coverage per service over its declared window
(``usage_coverage``). A service's evidence is **sufficient** when complete coverage
(attested, no unmapped events, no malformed records) spans at least
``WINDOW_DAYS`` contiguous days ending within ``FRESH_DAYS`` of evaluation; only
then can observed use stand for needed access. Otherwise the privilege analysis
falls back to an inferred peer baseline. IAM Access Advisor and ``RoleLastUsed``
stay hints in node metadata: they are never sufficient on their own.

**Attribution.** Role-level rows credit a role's use to the role. At commit, each
role-session access is also attributed to the principal that assumed the role
(``attribute``): the session's key is matched to the upload's in-window ``AssumeRole*``
issuance and the chain is followed through role chaining (at most ``MAX_CHAIN``
sessions) to its root principal. An ``onBehalfOf`` user (IAM Identity Center) takes
precedence; a ``sourceIdentity`` that only one root principal set in the upload is a
fallback for a session whose key is unknown, and a session ARN that only one root
principal used is one for an event without a key.
Sessions that cannot be attributed (``AssumeRole`` outside the window or upload, a
broken or too deep chain) are stored as ``unattributed`` and keep role-level credit.
Attribution is per upload: a session issued in one upload and used in another is
unattributed.
"""

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel
from sqlalchemy import delete, func, insert, literal, select
from sqlalchemy.orm import Session

from app.collectors.cloudtrail import Normalized
from app.collectors.execution_audit import SERVICES
from app.db.models import (
    AccessDenial,
    AttributedAccess,
    ObservedAccess,
    UsageCoverage,
    UsageSessionIssued,
    UsageSessionStaged,
    UsageStaged,
    UsageUpload,
    UsageUploadChunk,
)

SOURCE = "cloudtrail-export"
WINDOW_DAYS = 90
FRESH_DAYS = 7
MAX_WINDOW_DAYS = 400
MAX_CHUNKS = 10_000
MAX_UPLOAD_PAIRS = 5_000_000
CONTIGUOUS_GAP = timedelta(days=1)
INSERT_BATCH = 5000
MAX_CHAIN = 5  # Role sessions followed per assumption chain (= the graph hop bound).
ATTRIBUTION_BASES = ("session", "on-behalf-of", "session-arn", "source-identity", "unattributed")
UNATTRIBUTED = "unattributed"
STAGING = (UsageStaged, UsageUploadChunk, AccessDenial, UsageSessionIssued, UsageSessionStaged)
COUNT_KEYS = (
    "records",
    "matched",
    "outside_window",
    "denied",
    "malformed",
    "unresolved_principal",
    "unresolved_resource",
    "unmapped",
)


def utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


# ---------------------------------------------------------------------------
# Upload staging and commit


def stage_chunk(db: Session, upload: UsageUpload, chunk: int, size: int, normalized: Normalized) -> None:
    """Replace one file's staged aggregates, role sessions, denied attempts and counts."""
    for model in STAGING:
        db.execute(delete(model).where(model.upload_id == upload.id, model.chunk == chunk))
    denials = [
        {
            "upload_id": upload.id,
            "chunk": chunk,
            "tenant_id": upload.tenant_id,
            "principal_id": principal,
            "resource_id": resource,
            "service": service,
            "error_code": code,
            "first_seen": first,
            "last_seen": last,
            "count": count,
        }
        for (principal, resource, service, code), (first, last, count) in normalized.denied_access.items()
    ]
    for start in range(0, len(denials), INSERT_BATCH):
        db.execute(insert(AccessDenial), denials[start : start + INSERT_BATCH])
    batch = []
    for (principal, resource, action_class, service), (first, last, count) in normalized.access.items():
        batch.append(
            {
                "upload_id": upload.id,
                "chunk": chunk,
                "principal_id": principal,
                "resource_id": resource,
                "action_class": action_class,
                "service": service,
                "first_seen": first,
                "last_seen": last,
                "count": count,
            }
        )
        if len(batch) >= INSERT_BATCH:
            db.execute(insert(UsageStaged), batch)
            batch = []
    if batch:
        db.execute(insert(UsageStaged), batch)
    issued = [
        {
            "upload_id": upload.id,
            "chunk": chunk,
            "ordinal": ordinal,
            "access_key": key,
            "session_arn": arn,
            "role_id": role,
            "principal_id": principal,
            "parent_key": parent,
            "parent_role": parent_role,
            "source_identity": source,
            "issued_at": issued_at,
        }
        for ordinal, (key, (arn, role, principal, parent, parent_role, source, issued_at)) in enumerate(
            sorted(normalized.issued.items())
        )
    ]
    for start in range(0, len(issued), INSERT_BATCH):
        db.execute(insert(UsageSessionIssued), issued[start : start + INSERT_BATCH])
    batch = []
    for ordinal, (key, (first, last, count)) in enumerate(normalized.sessions.items()):
        role, access_key, arn, source, behalf, resource, action_class, service = key
        batch.append(
            {
                "upload_id": upload.id,
                "chunk": chunk,
                "ordinal": ordinal,
                "role_id": role,
                "access_key": access_key,
                "session_arn": arn,
                "source_identity": source,
                "on_behalf_of": behalf,
                "resource_id": resource,
                "action_class": action_class,
                "service": service,
                "first_seen": first,
                "last_seen": last,
                "count": count,
            }
        )
        if len(batch) >= INSERT_BATCH:
            db.execute(insert(UsageSessionStaged), batch)
            batch = []
    if batch:
        db.execute(insert(UsageSessionStaged), batch)
    db.add(UsageUploadChunk(upload_id=upload.id, chunk=chunk, size_bytes=size, stats=normalized.stats()))
    db.flush()


def progress(db: Session, upload_id: str) -> dict:
    """Totals over the upload's files so far (counts, per-service events and unmapped)."""
    totals = dict.fromkeys(COUNT_KEYS, 0)
    service_events: dict[str, int] = {}
    service_unmapped: dict[str, int] = {}
    files = size = 0
    for stats, chunk_size in db.execute(
        select(UsageUploadChunk.stats, UsageUploadChunk.size_bytes).where(
            UsageUploadChunk.upload_id == upload_id
        )
    ):
        stats = stats if isinstance(stats, dict) else json.loads(stats)
        files += 1
        size += chunk_size
        for key in COUNT_KEYS:
            totals[key] += stats.get(key, 0)
        for service, count in stats.get("service_events", {}).items():
            service_events[service] = service_events.get(service, 0) + count
        for service, count in stats.get("service_unmapped", {}).items():
            service_unmapped[service] = service_unmapped.get(service, 0) + count
    pairs = db.scalar(select(func.count()).select_from(UsageStaged).where(UsageStaged.upload_id == upload_id))
    return {
        **totals,
        "files": files,
        "bytes": size,
        "staged_pairs": pairs or 0,
        "service_events": dict(sorted(service_events.items())),
        "service_unmapped": dict(sorted(service_unmapped.items())),
    }


def coverage_rows(upload: UsageUpload, stats: dict) -> list[dict]:
    """One coverage row per attested or observed service of a committed upload."""
    services = sorted(set(upload.attested_services) | set(stats["service_events"]))
    rows = []
    for service in services:
        unmapped = stats["service_unmapped"].get(service, 0)
        attested = service in upload.attested_services
        rows.append(
            {
                "tenant_id": upload.tenant_id,
                "upload_id": upload.id,
                "service": service,
                "window_start": upload.window_start,
                "window_end": upload.window_end,
                "attested": attested,
                "events": stats["service_events"].get(service, 0),
                "unmapped": unmapped,
                # Unmapped or malformed records mean coverage cannot be claimed complete.
                "complete": attested and unmapped == 0 and stats["malformed"] == 0,
            }
        )
    return rows


@dataclass(frozen=True)
class Issuance:
    session_arn: str
    role: str
    principal: str
    parent_key: str
    parent_role: str
    source_identity: str


def resolve_sessions(issued: dict[str, Issuance]) -> dict[str, tuple[str, int]]:
    """Root principal and chain depth (1 = assumed directly) of every resolvable session key.

    A session assumed from another role session resolves through its parent (whose role
    must be the parent role the call was made with); a missing parent, a cycle or a chain
    longer than ``MAX_CHAIN`` leaves it (and its descendants) unresolved.
    """
    resolved: dict[str, tuple[str, int] | None] = {}
    for start in issued:
        chain: list[str] = []
        current, outcome = start, None
        while True:
            if current in resolved:
                outcome = resolved[current]
                break
            entry = issued.get(current)
            if entry is None or current in chain or len(chain) >= MAX_CHAIN:
                break
            chain.append(current)
            if entry.principal:
                outcome = (entry.principal, 0)
                break
            parent = issued.get(entry.parent_key)
            if parent is None or parent.role != entry.parent_role:
                break
            current = entry.parent_key
        # ``outcome`` is the root and depth of the element after the chain (0 for a principal).
        for key in reversed(chain):
            if outcome is None:
                resolved[key] = None
                continue
            depth = outcome[1] + 1
            outcome = (outcome[0], depth) if depth <= MAX_CHAIN else None
            resolved[key] = outcome
    return {key: value for key, value in resolved.items() if value is not None}


def attribute(db: Session, upload: UsageUpload) -> dict:
    """Attribute the upload's staged role-session use to assuming principals; returns stats."""
    issued: dict[str, Issuance] = {}
    for row in db.execute(
        select(
            UsageSessionIssued.access_key,
            UsageSessionIssued.session_arn,
            UsageSessionIssued.role_id,
            UsageSessionIssued.principal_id,
            UsageSessionIssued.parent_key,
            UsageSessionIssued.parent_role,
            UsageSessionIssued.source_identity,
        )
        .where(UsageSessionIssued.upload_id == upload.id)
        .order_by(UsageSessionIssued.issued_at, UsageSessionIssued.chunk, UsageSessionIssued.ordinal)
    ):
        issued.setdefault(row[0], Issuance(*row[1:]))
    roots = resolve_sessions(issued)
    # Fallbacks: a session ARN or sourceIdentity that only one root principal used.
    by_arn: dict[str, set[str]] = {}
    by_source: dict[str, set[str]] = {}
    for key, (root, _) in roots.items():
        entry = issued[key]
        if entry.session_arn:
            by_arn.setdefault(entry.session_arn, set()).add(root)
        if entry.source_identity:
            by_source.setdefault(entry.source_identity, set()).add(root)
    depth_of_arn = {}
    for key, (_, depth) in roots.items():
        arn = issued[key].session_arn
        if arn and len(by_arn.get(arn, ())) == 1:
            depth_of_arn[arn] = max(depth_of_arn.get(arn, 0), depth)
    aggregated: dict[tuple, list] = {}
    events: Counter = Counter()
    for (
        role, key, arn, source, behalf, resource, action_class, service, first, last, count
    ) in db.execute(
        select(
            UsageSessionStaged.role_id,
            UsageSessionStaged.access_key,
            UsageSessionStaged.session_arn,
            UsageSessionStaged.source_identity,
            UsageSessionStaged.on_behalf_of,
            UsageSessionStaged.resource_id,
            UsageSessionStaged.action_class,
            UsageSessionStaged.service,
            UsageSessionStaged.first_seen,
            UsageSessionStaged.last_seen,
            UsageSessionStaged.count,
        )
        .where(UsageSessionStaged.upload_id == upload.id)
        .execution_options(yield_per=INSERT_BATCH)
    ):  # fmt: skip
        found = roots.get(key) if key else None
        if behalf:
            identity, depth, basis = behalf, (found[1] if found else 1), "on-behalf-of"
        elif found is not None and issued[key].role == role:
            identity, depth, basis = found[0], found[1], "session"
        elif not key and arn and len(by_arn.get(arn, ())) == 1:
            identity, depth, basis = next(iter(by_arn[arn])), depth_of_arn[arn], "session-arn"
        elif source and len(by_source.get(source, ())) == 1:
            identity, depth, basis = next(iter(by_source[source])), 0, "source-identity"
        else:
            identity, depth, basis = "", 0, UNATTRIBUTED
        events[basis] += count
        group = (identity, role, resource, action_class, service, basis)
        row = aggregated.get(group)
        if row is None:
            aggregated[group] = [first, last, count, depth]
        else:
            row[0], row[1] = min(row[0], first), max(row[1], last)
            row[2] += count
            row[3] = max(row[3], depth)
    batch = []
    for ordinal, (group, (first, last, count, depth)) in enumerate(sorted(aggregated.items())):
        identity, role, resource, action_class, service, basis = group
        batch.append(
            {
                "tenant_id": upload.tenant_id,
                "upload_id": upload.id,
                "ordinal": ordinal,
                "identity_id": identity,
                "role_id": role,
                "resource_id": resource,
                "action_class": action_class,
                "service": service,
                "basis": basis,
                "depth": depth,
                "first_seen": first,
                "last_seen": last,
                "count": count,
            }
        )
        if len(batch) >= INSERT_BATCH:
            db.execute(insert(AttributedAccess), batch)
            batch = []
    if batch:
        db.execute(insert(AttributedAccess), batch)
    total = sum(events.values())
    return {
        "sessions_issued": len(issued),
        "sessions_resolved": len(roots),
        "session_events": total,
        "attributed_events": total - events[UNATTRIBUTED],
        "unattributed_events": events[UNATTRIBUTED],
        "by_basis": {basis: events.get(basis, 0) for basis in ATTRIBUTION_BASES},
        "rows": len(aggregated),
    }


def commit(db: Session, upload: UsageUpload, timestamp: datetime) -> dict:
    """Aggregate the staged files into observed access and record coverage; returns stats."""
    stats = progress(db, upload.id)
    grouped = (
        select(
            literal(upload.tenant_id),
            literal(upload.id),
            UsageStaged.principal_id,
            UsageStaged.resource_id,
            UsageStaged.action_class,
            UsageStaged.service,
            func.min(UsageStaged.first_seen),
            func.max(UsageStaged.last_seen),
            func.sum(UsageStaged.count),
            literal(upload.source),
        )
        .where(UsageStaged.upload_id == upload.id)
        .group_by(
            UsageStaged.principal_id, UsageStaged.resource_id, UsageStaged.action_class, UsageStaged.service
        )
    )
    columns = [
        "tenant_id", "upload_id", "principal_id", "resource_id", "action_class", "service", "first_seen",
        "last_seen", "count", "source",
    ]  # fmt: skip
    db.execute(insert(ObservedAccess).from_select(columns, grouped))
    pairs = db.scalar(
        select(func.count())
        .select_from(ObservedAccess)
        .where(ObservedAccess.tenant_id == upload.tenant_id, ObservedAccess.upload_id == upload.id)
    )
    rows = coverage_rows(upload, stats)
    if rows:
        db.execute(insert(UsageCoverage), rows)
    stats["attribution"] = attribute(db, upload)
    for model in (UsageStaged, UsageSessionIssued, UsageSessionStaged):
        db.execute(delete(model).where(model.upload_id == upload.id))
    upload.attributed = True
    stats["pairs"] = pairs
    stats["coverage"] = [
        {key: row[key] for key in ("service", "attested", "events", "unmapped", "complete")} for row in rows
    ]
    upload.stats = stats
    upload.status = "committed"
    upload.committed_at = upload.updated_at = timestamp
    return stats


def delete_upload(db: Session, tenant: str, upload_id: str) -> bool:
    upload = db.get(UsageUpload, upload_id)
    if upload is None or upload.tenant_id != tenant:
        return False
    for model in STAGING:
        db.execute(delete(model).where(model.upload_id == upload_id))
    for model in (ObservedAccess, UsageCoverage, AttributedAccess):
        db.execute(delete(model).where(model.tenant_id == tenant, model.upload_id == upload_id))
    db.delete(upload)
    return True


def purge_expired(db: Session, tenant: str, timestamp: datetime, limit: int = 20) -> int:
    ids = list(
        db.scalars(
            select(UsageUpload.id)
            .where(
                UsageUpload.tenant_id == tenant,
                UsageUpload.status == "open",
                UsageUpload.expires_at < timestamp,
            )
            .limit(limit)
        )
    )
    for upload_id in ids:
        delete_upload(db, tenant, upload_id)
    return len(ids)


# ---------------------------------------------------------------------------
# Evidence status


@dataclass
class ServiceEvidence:
    service: str
    window_start: datetime | None  # contiguous complete coverage ending at the latest end
    window_end: datetime | None
    days: float
    fresh: bool
    attested_uploads: int
    complete_uploads: int
    events: int
    unmapped: int
    sufficient: bool

    def as_dict(self) -> dict:
        return {
            "service": self.service,
            "window_start": self.window_start.isoformat() if self.window_start else None,
            "window_end": self.window_end.isoformat() if self.window_end else None,
            "days": round(self.days, 2),
            "fresh": self.fresh,
            "attested_uploads": self.attested_uploads,
            "complete_uploads": self.complete_uploads,
            "events": self.events,
            "unmapped": self.unmapped,
            "sufficient": self.sufficient,
        }


@dataclass
class Evidence:
    """Usage evidence of a tenant as evaluated at ``evaluated_at``."""

    evaluated_at: datetime
    uploads: list[str]
    services: dict[str, ServiceEvidence]
    observed_pairs: int
    window_start: datetime | None
    window_end: datetime | None

    @property
    def present(self) -> bool:
        return bool(self.uploads)

    @property
    def sufficient_services(self) -> frozenset[str]:
        return frozenset(name for name, service in self.services.items() if service.sufficient)

    @property
    def status(self) -> str:
        """``none`` (no uploads), ``attested`` (some service sufficient) or ``partial``."""
        if not self.uploads:
            return "none"
        return "attested" if self.sufficient_services else "partial"

    @property
    def fingerprint(self) -> str:
        """Changes when uploads change or a service's sufficiency flips (e.g. goes stale)."""
        if not self.uploads:
            return ""
        content = json.dumps(
            {"uploads": self.uploads, "sufficient": sorted(self.sufficient_services)}, sort_keys=True
        )
        return hashlib.sha256(content.encode()).hexdigest()[:32]

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "evaluated_at": self.evaluated_at.isoformat(),
            "window_start": self.window_start.isoformat() if self.window_start else None,
            "window_end": self.window_end.isoformat() if self.window_end else None,
            "window_days_required": WINDOW_DAYS,
            "freshness_days": FRESH_DAYS,
            "uploads": len(self.uploads),
            "observed_pairs": self.observed_pairs,
            "services": {name: service.as_dict() for name, service in sorted(self.services.items())},
            "sufficient_services": sorted(self.sufficient_services),
            "sources": [SOURCE] if self.uploads else [],
            "hints": ["role_last_used", "access_advisor"],
            "fingerprint": self.fingerprint,
        }


def _span(windows: list[tuple[datetime, datetime]]) -> tuple[datetime, datetime] | None:
    """Contiguous union (gaps up to CONTIGUOUS_GAP) of windows that ends at the latest end."""
    if not windows:
        return None
    ordered = sorted(windows)
    spans: list[list[datetime]] = []
    for start, end in ordered:
        if spans and start <= spans[-1][1] + CONTIGUOUS_GAP:
            spans[-1][1] = max(spans[-1][1], end)
        else:
            spans.append([start, end])
    latest = max(spans, key=lambda span: span[1])
    return latest[0], latest[1]


def evidence(db: Session, tenant: str, at: datetime | None = None) -> Evidence:
    at = utc(at or datetime.now(UTC))
    uploads = list(
        db.scalars(
            select(UsageUpload.id)
            .where(UsageUpload.tenant_id == tenant, UsageUpload.status == "committed")
            .order_by(UsageUpload.id)
        )
    )
    per_service: dict[str, list] = {}
    for row in db.scalars(select(UsageCoverage).where(UsageCoverage.tenant_id == tenant)):
        per_service.setdefault(row.service, []).append(row)
    services = {}
    starts, ends = [], []
    for service, rows in per_service.items():
        complete = [(utc(r.window_start), utc(r.window_end)) for r in rows if r.complete]
        span = _span(complete)
        days = (span[1] - span[0]).total_seconds() / 86400 if span else 0.0
        fresh = bool(span) and at - span[1] <= timedelta(days=FRESH_DAYS)
        services[service] = ServiceEvidence(
            service=service,
            window_start=span[0] if span else None,
            window_end=span[1] if span else None,
            days=days,
            fresh=fresh,
            attested_uploads=sum(r.attested for r in rows),
            complete_uploads=len(complete),
            events=sum(r.events for r in rows),
            unmapped=sum(r.unmapped for r in rows),
            sufficient=fresh and days >= WINDOW_DAYS,
        )
        for r in rows:
            starts.append(utc(r.window_start))
            ends.append(utc(r.window_end))
    pairs = db.scalar(
        select(func.count()).select_from(ObservedAccess).where(ObservedAccess.tenant_id == tenant)
    )
    return Evidence(at, uploads, services, pairs or 0, min(starts, default=None), max(ends, default=None))


def observed(db: Session, tenant: str):
    """Observed access of every committed upload, aggregated by (principal, resource, class).

    Yields ``(principal, resource, action class, service, last seen, count)``.
    """
    yield from db.execute(
        select(
            ObservedAccess.principal_id,
            ObservedAccess.resource_id,
            ObservedAccess.action_class,
            ObservedAccess.service,
            func.max(ObservedAccess.last_seen),
            func.sum(ObservedAccess.count),
        )
        .where(ObservedAccess.tenant_id == tenant)
        .group_by(
            ObservedAccess.principal_id,
            ObservedAccess.resource_id,
            ObservedAccess.action_class,
            ObservedAccess.service,
        )
        .execution_options(yield_per=INSERT_BATCH)
    )


def observed_triples(db: Session, tenant: str):
    """``(principal, resource, action class)`` of every committed upload, one row per distinct
    (principal, resource, class, service) as ``observed`` aggregates them (Core rows, no ORM)."""
    return db.connection().execute(
        select(ObservedAccess.principal_id, ObservedAccess.resource_id, ObservedAccess.action_class)
        .where(ObservedAccess.tenant_id == tenant)
        .group_by(
            ObservedAccess.principal_id,
            ObservedAccess.resource_id,
            ObservedAccess.action_class,
            ObservedAccess.service,
        )
    )


def attribution_counts(db: Session, tenant: str):
    """``(role, attributed events, session events)`` per role over committed uploads."""
    return db.connection().execute(
        select(
            AttributedAccess.role_id,
            func.sum(AttributedAccess.count).filter(AttributedAccess.identity_id != ""),
            func.sum(AttributedAccess.count),
        )
        .where(AttributedAccess.tenant_id == tenant)
        .group_by(AttributedAccess.role_id)
    )


def attributed_pairs(db: Session, tenant: str):
    """``(identity, role, resource, action class)`` of attributed use (unaggregated: a pair
    may repeat across uploads and bases; Core rows, no ORM)."""
    return db.connection().execute(
        select(
            AttributedAccess.identity_id,
            AttributedAccess.role_id,
            AttributedAccess.resource_id,
            AttributedAccess.action_class,
        ).where(AttributedAccess.tenant_id == tenant, AttributedAccess.identity_id != "")
    )


def attribution_ready(db: Session, tenant: str) -> bool:
    """Every committed upload of the tenant was attributed (none predates attribution)."""
    counts = db.execute(
        select(func.count(), func.count().filter(UsageUpload.attributed.is_(True))).where(
            UsageUpload.tenant_id == tenant, UsageUpload.status == "committed"
        )
    ).one()
    return bool(counts[0]) and counts[0] == counts[1]


def attributed(db: Session, tenant: str):
    """Attributed role-session use of every committed upload.

    Yields ``(identity, role, resource, action class, count)`` aggregated over uploads
    and attribution bases; ``identity`` ``""`` is unattributed use.
    """
    yield from db.execute(
        select(
            AttributedAccess.identity_id,
            AttributedAccess.role_id,
            AttributedAccess.resource_id,
            AttributedAccess.action_class,
            func.sum(AttributedAccess.count),
        )
        .where(AttributedAccess.tenant_id == tenant)
        .group_by(
            AttributedAccess.identity_id,
            AttributedAccess.role_id,
            AttributedAccess.resource_id,
            AttributedAccess.action_class,
        )
        .execution_options(yield_per=INSERT_BATCH)
    )


# ---------------------------------------------------------------------------
# API models


class UsageUploadRequest(BaseModel):
    window_start: datetime
    window_end: datetime
    attested_services: list[str] = []
    source: str = SOURCE


class UsageUploadResponse(BaseModel):
    id: str
    status: str
    source: str
    revision: str
    window_start: datetime
    window_end: datetime
    attested_services: list[str]
    progress: dict
    expires_at: datetime
    max_chunk_bytes: int
    max_decompressed_bytes: int
    services: list[str] = list(SERVICES)


class UsageCommitResponse(BaseModel):
    id: str
    status: str
    revision: str
    stats: dict
    evidence: dict
    notice: str
    # Optimizer rollout AccessDenied watch: changes flagged by this upload and revert PRs opened.
    rollout: dict | None = None


class UsageStatusResponse(BaseModel):
    evidence: dict
    uploads: list[dict]
    services: list[str] = list(SERVICES)
    notice: str


NOTICE = (
    "Observed use is evidence of need only where coverage is attested, complete and spans "
    f"{WINDOW_DAYS} days ending within {FRESH_DAYS} days; otherwise needed access is inferred from "
    "peers. RoleLastUsed and Access Advisor are hints and never sufficient on their own."
)


def validate_window(start: datetime, end: datetime, at: datetime) -> None:
    if start.tzinfo is None or end.tzinfo is None:
        raise ValueError("Usage window requires timezone-aware timestamps")
    if not start < end:
        raise ValueError("Usage window must start before it ends")
    if end - start > timedelta(days=MAX_WINDOW_DAYS):
        raise ValueError(f"Usage window is longer than {MAX_WINDOW_DAYS} days")
    if end > at + timedelta(days=1):
        raise ValueError("Usage window ends in the future")


def upload_summary(upload: UsageUpload) -> dict:
    stats = upload.stats if isinstance(upload.stats, dict) else json.loads(upload.stats or "{}")
    return {
        "id": upload.id,
        "status": upload.status,
        "source": upload.source,
        "revision": upload.revision,
        "window_start": utc(upload.window_start).isoformat(),
        "window_end": utc(upload.window_end).isoformat(),
        "attested_services": upload.attested_services,
        "created_at": utc(upload.created_at).isoformat(),
        "committed_at": utc(upload.committed_at).isoformat() if upload.committed_at else None,
        "stats": {key: value for key, value in stats.items() if key != "coverage"},
        "coverage": stats.get("coverage", []),
    }
