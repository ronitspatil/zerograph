"""Per-revision analysis, computed once before the publication pointer swap.

Overview counts, every toxic-combination finding (in API order), high-blast flags,
whole-revision totals and the total asset weight are stored in SQL, keyed by
(tenant, revision) and stamped with ``ANALYSIS_VERSION``. Readers use the rows
when present and current; a revision published before this table existed (or by
an older analysis version) is computed on read from its snapshot instead, exactly
as before, so legacy revisions keep working without a migration-time backfill.
``python -m app.graph.analysis --tenant T`` backfills a tenant's current revision.
"""

import argparse
import json
from dataclasses import dataclass

from sqlalchemy import delete, insert, select, text
from sqlalchemy.orm import Session

from app.db.locks import acquire_publication_lock
from app.db.models import RevisionAnalysis, RevisionFinding, TenantState
from app.db.session import session_factory
from app.engine.analysis_index import AnalysisIndex
from app.engine.toxic_combos import Finding, detect
from app.graph.exploration import RevisionTotals
from app.graph.repository import get_graph_store
from app.graph.schema import DATA_TYPES, IDENTITY_TYPES, TRAVERSAL_TYPES, GraphSnapshot, NodeType

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
    return ComputedAnalysis(overview, findings, totals, prepared.total_asset_weight, high_blast)


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
    return RevisionTotals(row.total_nodes, row.total_edges, row.total_roles, row.total_role_edges)


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


def backfill(tenant: str) -> dict:
    """Compute and store analysis for a tenant's current revision under the publication lock.

    The advisory publication lock keeps the pointer fixed; readers are not blocked
    (the shared pin) and see the rows atomically once this transaction commits.
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
        if stored_analysis(db, tenant, revision) is not None:
            return {"tenant": tenant, "revision": revision, "backfilled": False}
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
