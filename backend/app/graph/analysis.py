"""Per-revision analysis, computed once before the publication pointer swap.

Overview counts, every toxic-combination finding (in API order), high-blast flags,
whole-revision totals and the total asset weight are stored in SQL, keyed by
(tenant, revision) and stamped with ``ANALYSIS_VERSION``. Readers use the rows
when present and current; a revision published before this table existed (or by
an older analysis version) is computed on read from its snapshot instead, exactly
as before, so legacy revisions keep working without a migration-time backfill.
``python -m app.graph.analysis --tenant T`` backfills a tenant's current revision.
An explore sample older than ``SAMPLE_VERSION`` in an otherwise current analysis is
refreshed by the worker sweep (``backfill_stale_samples``, every 60 s) or by that
command, recomputing only the sample; until then the older sample is still served
(it is bounded and valid, just less representative).
"""

import argparse
import json
from dataclasses import dataclass

from sqlalchemy import delete, insert, or_, select, text
from sqlalchemy.orm import Session

from app.db.locks import acquire_publication_lock, try_publication_lock
from app.db.models import RevisionAnalysis, RevisionFinding, TenantState
from app.db.session import session_factory
from app.engine.analysis_index import AnalysisIndex
from app.engine.toxic_combos import Finding, detect
from app.graph.exploration import RevisionTotals
from app.graph.repository import get_graph_store
from app.graph.sample import IMPORTANT_FINDINGS, SAMPLE_VERSION, select_sample, snapshot_sample
from app.graph.schema import DATA_TYPES, IDENTITY_TYPES, TRAVERSAL_TYPES, GraphSnapshot, NodeType
from app.graph.sweep import SWEEP_TENANTS, run_sweep

# Bump when the overview, finding or totals logic changes: rows with another
# version are ignored (computed on read) until the revision is republished or backfilled.
ANALYSIS_VERSION = 1
HIGH_BLAST_THRESHOLD = 70
SENSITIVITY_LEVELS = ["public", "internal", "confidential", "restricted"]


@dataclass
class ComputedAnalysis:
    overview: dict
    findings: list[Finding]
    totals: RevisionTotals
    total_asset_weight: int
    high_blast_ids: list[str]
    # The initial explore sample in selection order (app.graph.sample): a key lookup, no scan.
    sample_ids: list[str] | None = None


def compute_analysis(snapshot: GraphSnapshot) -> ComputedAnalysis:
    """Whole-revision analysis with the exact semantics of the former request-time overview."""
    prepared = AnalysisIndex.build(snapshot, include_uncertain=True)
    findings = detect(snapshot, index=prepared)
    identities = [n for n in snapshot.nodes if n.type in IDENTITY_TYPES]
    # Identities whose 5-hop reach (uncertain edges included) scores as high blast radius.
    high_blast = sorted(
        n.id for n in identities if prepared.score(n.id, prepared.paths(n.id))[0] >= HIGH_BLAST_THRESHOLD
    )
    data_assets = [n for n in snapshot.nodes if n.type in DATA_TYPES]
    role_ids = {n.id for n in snapshot.nodes if n.type == NodeType.ROLE}
    overview = {
        "total_nhis": len(identities),
        "ai_agents": sum(n.type == NodeType.AGENT for n in snapshot.nodes),
        "toxic_combinations": len(findings),
        "high_blast_radius": len(high_blast),
        "data_assets": len(data_assets),
        "confirmed_edges": sum(e.certainty == "confirmed" for e in snapshot.edges),
        "uncertain_edges": sum(e.certainty != "confirmed" for e in snapshot.edges),
        "accounts": sorted({n.account_id for n in snapshot.nodes if n.account_id}),
        "sensitivity": {
            level: sum(n.sensitivity.value == level for n in data_assets) for level in SENSITIVITY_LEVELS
        },
    }
    totals = RevisionTotals(
        nodes=len(snapshot.nodes),
        edges=len(snapshot.edges),
        roles=len(role_ids),
        role_edges=sum(
            e.type in TRAVERSAL_TYPES and e.source in role_ids and e.target in role_ids
            for e in snapshot.edges
        ),
    )
    return ComputedAnalysis(
        overview,
        findings,
        totals,
        prepared.total_asset_weight,
        high_blast,
        snapshot_sample(snapshot, findings, high_blast),
    )


def store_analysis(db: Session, tenant: str, revision: str, analysis: ComputedAnalysis) -> None:
    """Stage rows in the caller's transaction, which also advances the revision pointer."""
    db.add(
        RevisionAnalysis(
            tenant_id=tenant,
            revision=revision,
            analysis_version=ANALYSIS_VERSION,
            overview=analysis.overview,
            total_nodes=analysis.totals.nodes,
            total_edges=analysis.totals.edges,
            total_roles=analysis.totals.roles,
            total_role_edges=analysis.totals.role_edges,
            total_findings=len(analysis.findings),
            total_asset_weight=analysis.total_asset_weight,
            high_blast_ids=analysis.high_blast_ids,
            sample_ids=analysis.sample_ids,
            sample_version=SAMPLE_VERSION if analysis.sample_ids is not None else None,
        )
    )
    if analysis.findings:
        db.execute(
            insert(RevisionFinding),
            [
                {
                    "tenant_id": tenant,
                    "revision": revision,
                    "ordinal": ordinal,
                    "finding_id": finding.id,
                    "payload": finding.model_dump(mode="json"),
                }
                for ordinal, finding in enumerate(analysis.findings)
            ],
        )


def delete_analysis(db: Session, tenant: str, revision: str) -> None:
    """Remove a revision's rows; call in the transaction holding the tenant publication lock."""
    for model in (RevisionFinding, RevisionAnalysis):
        db.execute(delete(model).where(model.tenant_id == tenant, model.revision == revision))


def stored_analysis(db: Session, tenant: str, revision: str) -> RevisionAnalysis | None:
    """Current-version analysis for a pinned revision, or None (legacy/stale: compute on read)."""
    if not revision:
        return None
    row = db.get(RevisionAnalysis, (tenant, revision))
    return row if isinstance(row, RevisionAnalysis) and row.analysis_version == ANALYSIS_VERSION else None


def stored_totals(db: Session, tenant: str, revision: str) -> RevisionTotals | None:
    row = stored_analysis(db, tenant, revision)
    if row is None:
        return None
    return RevisionTotals(
        row.total_nodes,
        row.total_edges,
        row.total_roles,
        row.total_role_edges,
        tuple(row.sample_ids) if row.sample_ids is not None else None,
    )


class UnknownCursor(ValueError):
    pass


def stored_findings_page(
    db: Session, tenant: str, revision: str, cursor: str | None, limit: int
) -> tuple[list[dict], bool]:
    """Findings after ``cursor`` (a finding ID of this revision), in API order, plus has-more."""
    scope = (RevisionFinding.tenant_id == tenant, RevisionFinding.revision == revision)
    after = -1
    if cursor is not None:
        position = db.scalar(
            select(RevisionFinding.ordinal).where(*scope, RevisionFinding.finding_id == cursor)
        )
        if position is None:
            raise UnknownCursor(cursor)
        after = position
    rows = list(
        db.scalars(
            select(RevisionFinding.payload)
            .where(*scope, RevisionFinding.ordinal > after)
            .order_by(RevisionFinding.ordinal)
            .limit(limit + 1)
        )
    )
    return rows[:limit], len(rows) > limit


def computed_findings_page(
    findings: list[Finding], cursor: str | None, limit: int
) -> tuple[list[dict], bool]:
    start = 0
    if cursor is not None:
        position = next((i for i, finding in enumerate(findings) if finding.id == cursor), None)
        if position is None:
            raise UnknownCursor(cursor)
        start = position + 1
    page = findings[start : start + limit]
    return [finding.model_dump(mode="json") for finding in page], start + limit < len(findings)


def sample_is_stale(row: RevisionAnalysis) -> bool:
    return row.sample_version is None or row.sample_version < SAMPLE_VERSION


def refresh_sample(db: Session, tenant: str, revision: str, row: RevisionAnalysis) -> list[str]:
    """Recompute only the explore sample of a stored analysis, in the caller's locked transaction.

    Reads the revision's topology (IDs, types, edge endpoints; no payloads, no
    snapshot) and the stored finding paths and high-blast IDs, which is exactly the
    input of the publish-time selection. The row is updated in place: readers keep
    the older sample until this transaction commits.
    """
    topology = get_graph_store().topology(tenant, revision)
    if len(topology.ids) != row.total_nodes or len(topology.sources) != row.total_edges:
        raise ValueError("Graph revision does not match its stored analysis")
    paths = db.scalars(
        select(RevisionFinding.payload)
        .where(RevisionFinding.tenant_id == tenant, RevisionFinding.revision == revision)
        .order_by(RevisionFinding.ordinal)
        .limit(IMPORTANT_FINDINGS)
    )
    sample = select_sample(
        topology.ids,
        topology.types,
        topology.sources,
        topology.targets,
        [payload["path"] for payload in paths],
        row.high_blast_ids,
    )
    row.sample_ids, row.sample_version = sample, SAMPLE_VERSION
    return sample


def backfill(tenant: str) -> dict:
    """Compute and store analysis for a tenant's current revision under the publication lock.

    The advisory publication lock keeps the pointer fixed; readers are not blocked
    (the shared pin) and see the rows atomically once this transaction commits. A
    current analysis whose explore sample is older than ``SAMPLE_VERSION`` only has
    its sample recomputed.
    """
    with session_factory()() as db:
        if db.get_bind().dialect.name == "postgresql":
            db.execute(text("SET LOCAL lock_timeout = '5s'"))
        acquire_publication_lock(db, tenant)
        state = db.execute(
            select(TenantState).where(TenantState.tenant_id == tenant).with_for_update(read=True)
        ).scalar_one_or_none()
        if state is None or not state.revision:
            raise ValueError("Tenant has no published revision")
        revision = state.revision
        current = stored_analysis(db, tenant, revision)
        if current is not None and not sample_is_stale(current):
            return {"tenant": tenant, "revision": revision, "backfilled": False}
        if current is not None:
            refresh_sample(db, tenant, revision, current)
            db.commit()
            return {
                "tenant": tenant,
                "revision": revision,
                "backfilled": True,
                "findings": current.total_findings,
            }
        # Replace rows of an older analysis version, if any.
        delete_analysis(db, tenant, revision)
        analysis = compute_analysis(get_graph_store().snapshot(tenant, revision))
        store_analysis(db, tenant, revision, analysis)
        db.commit()
        return {
            "tenant": tenant,
            "revision": revision,
            "backfilled": True,
            "findings": len(analysis.findings),
        }


# Worker sweep: current revisions whose stored analysis is current but whose
# explore sample predates SAMPLE_VERSION (stored before migration 0006, or before
# a version bump) get a fresh sample without a republication. Revisions with no
# current analysis are left to publication or the operator backfill: their
# overview and findings are computed on read, and recomputing them needs a snapshot.
_failed: dict[tuple[str, str], float] = {}


def stale_samples(db: Session, limit: int) -> list[tuple[str, str]]:
    """(tenant, revision) pairs whose current revision has a current analysis with an older sample."""
    rows = db.execute(
        select(TenantState.tenant_id, TenantState.revision)
        .join(
            RevisionAnalysis,
            (RevisionAnalysis.tenant_id == TenantState.tenant_id)
            & (RevisionAnalysis.revision == TenantState.revision),
        )
        .where(
            TenantState.revision.is_not(None),
            TenantState.revision != "",
            RevisionAnalysis.analysis_version == ANALYSIS_VERSION,
            or_(RevisionAnalysis.sample_version.is_(None), RevisionAnalysis.sample_version < SAMPLE_VERSION),
        )
        .order_by(TenantState.tenant_id)
        .limit(limit)
    )
    return [(tenant, revision) for tenant, revision in rows]


def backfill_sample(tenant: str) -> dict:
    """The sweep's per-tenant step: never waits for the publication lock (a busy tenant is skipped)."""
    with session_factory()() as db:
        if db.get_bind().dialect.name == "postgresql":
            db.execute(text("SET LOCAL lock_timeout = '5s'"))
        if not try_publication_lock(db, tenant):
            return {"tenant": tenant, "backfilled": False, "busy": True}
        state = db.execute(
            select(TenantState).where(TenantState.tenant_id == tenant).with_for_update(read=True)
        ).scalar_one_or_none()
        if state is None or not state.revision:
            return {"tenant": tenant, "backfilled": False}
        revision = state.revision
        row = stored_analysis(db, tenant, revision)
        if row is None or not sample_is_stale(row):
            # Republished meanwhile (publication stores a current sample), or already refreshed.
            return {"tenant": tenant, "revision": revision, "backfilled": False}
        sample = refresh_sample(db, tenant, revision, row)
        db.commit()
        return {"tenant": tenant, "revision": revision, "backfilled": True, "sample": len(sample)}


def backfill_stale_samples(limit: int = SWEEP_TENANTS) -> list[dict]:
    """Refresh up to ``limit`` tenants' stale explore samples; never raises for one tenant's failure."""

    def pending(count: int) -> list[tuple[str, str]]:
        with session_factory()() as db:
            return stale_samples(db, count)

    return run_sweep(
        "Explore sample",
        pending,
        backfill_sample,
        _failed,
        lambda result: f"sample={result['sample']}",
        limit,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Store analysis for a tenant's current graph revision")
    parser.add_argument("--tenant", required=True)
    args = parser.parse_args()
    try:
        result = backfill(args.tenant)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
