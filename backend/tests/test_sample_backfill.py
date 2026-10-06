"""Worker refresh of explore samples stored with an older SAMPLE_VERSION."""

import sys
from pathlib import Path
from unittest.mock import patch

from app.collectors.tasks import backfill_samples
from app.db.models import RevisionAnalysis, RevisionFinding, TenantState
from app.graph import analysis
from app.graph.analysis import (
    ANALYSIS_VERSION,
    backfill_stale_samples,
    compute_analysis,
    stale_samples,
    store_analysis,
)
from app.graph.demo import demo_snapshot
from app.graph.sample import SAMPLE_VERSION
from app.graph.schema import Edge, EdgeType, GraphSnapshot, Node, NodeType
from app.graph.sweep import FAILED_BACKOFF_SECONDS

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from qualify_scale import generate  # noqa: E402


def publish(factory, graph, tenant, revision, snapshot, current=True):
    """Publish with a stored analysis; returns the publish-time sample."""
    graph.publish(tenant, revision, snapshot)
    computed = compute_analysis(snapshot)
    with factory() as db:
        store_analysis(db, tenant, revision, computed)
        if current:
            state = db.get(TenantState, tenant) or TenantState(tenant_id=tenant)
            state.revision = revision
            db.add(state)
        db.commit()
    return computed.sample_ids


def make_stale(factory, tenant, revision, version=None, analysis_version=ANALYSIS_VERSION):
    """Rewrite a row as a pre-0006 one: an ascending-ID sample of an older version."""
    with factory() as db:
        row = db.get(RevisionAnalysis, (tenant, revision))
        row.sample_ids = sorted(row.sample_ids)[:250]
        row.sample_version = version
        row.analysis_version = analysis_version
        db.commit()
        return list(row.sample_ids)


def sample_of(factory, tenant, revision):
    with factory() as db:
        row = db.get(RevisionAnalysis, (tenant, revision))
        return list(row.sample_ids), row.sample_version


def small(prefix: str) -> GraphSnapshot:
    nodes = [Node(id=f"{prefix}:{i}", name=f"{prefix} {i}", type=NodeType.ROLE) for i in range(4)]
    edges = [
        Edge(source=f"{prefix}:{i}", target=f"{prefix}:{i + 1}", type=EdgeType.INHERITS) for i in range(3)
    ]
    return GraphSnapshot(nodes=nodes, edges=edges)


def test_sweep_refreshes_only_current_stale_samples_per_tenant_without_a_snapshot(
    client, environment, monkeypatch
):
    factory, graph = environment
    monkeypatch.setattr(analysis, "_failed", {})
    big = generate(3000, seed=5, exposed_rate=0.02)
    expected_a = publish(factory, graph, "tenant-a", "a-1", big)
    old_a = make_stale(factory, "tenant-a", "a-1")
    assert old_a != expected_a
    # tenant-b: a current sample on its current revision; an older revision stays stale.
    publish(factory, graph, "tenant-b", "b-old", small("b"))
    old_b = make_stale(factory, "tenant-b", "b-old")
    expected_b = publish(factory, graph, "tenant-b", "b-new", small("b"))
    # tenant-c: the whole analysis is of an older version (computed on read): not this sweep's.
    publish(factory, graph, "tenant-c", "c-1", small("c"))
    old_c = make_stale(factory, "tenant-c", "c-1", analysis_version=ANALYSIS_VERSION - 1)
    # tenant-d: an older numbered sample version; tenant-e: a newer one (rolling deploy).
    expected_d = publish(factory, graph, "tenant-d", "d-1", small("d"))
    make_stale(factory, "tenant-d", "d-1", version=SAMPLE_VERSION - 1)
    publish(factory, graph, "tenant-e", "e-1", small("e"))
    old_e = make_stale(factory, "tenant-e", "e-1", version=SAMPLE_VERSION + 1)
    with factory() as db:
        assert stale_samples(db, 10) == [("tenant-a", "a-1"), ("tenant-d", "d-1")]
        assert stale_samples(db, 1) == [("tenant-a", "a-1")]

    # The older sample keeps serving until the new one lands: never a 404 or empty view.
    body = client.get("/api/v1/graph/explore").json()
    assert [node["id"] for node in body["nodes"]] == sorted(old_a)

    with patch.object(graph, "snapshot", side_effect=AssertionError("sweep loaded a snapshot")):
        first = backfill_stale_samples(limit=1)
        assert first == [{"tenant": "tenant-a", "revision": "a-1", "backfilled": True, "sample": 500}]
        assert backfill_stale_samples() == [
            {"tenant": "tenant-d", "revision": "d-1", "backfilled": True, "sample": 4}
        ]
        assert backfill_stale_samples() == []  # Idempotent: nothing left.
        assert backfill_samples() == 0

    # Same selection as publication, from each tenant's own graph only.
    assert sample_of(factory, "tenant-a", "a-1") == (expected_a, SAMPLE_VERSION)
    assert sample_of(factory, "tenant-d", "d-1") == (expected_d, SAMPLE_VERSION)
    assert sample_of(factory, "tenant-b", "b-new") == (expected_b, SAMPLE_VERSION)
    assert sample_of(factory, "tenant-b", "b-old") == (old_b, None)
    assert sample_of(factory, "tenant-c", "c-1") == (old_c, None)
    assert sample_of(factory, "tenant-e", "e-1") == (old_e, SAMPLE_VERSION + 1)
    with factory() as db:
        assert stale_samples(db, 10) == []
        # Only the sample changed: overview, totals and findings are untouched.
        row = db.get(RevisionAnalysis, ("tenant-a", "a-1"))
        computed = compute_analysis(big)
        assert row.overview == computed.overview and row.high_blast_ids == computed.high_blast_ids
        assert db.query(RevisionFinding).filter_by(tenant_id="tenant-a").count() == len(computed.findings)
    body = client.get("/api/v1/graph/explore").json()
    assert [node["id"] for node in body["nodes"]] == sorted(expected_a[:250])


def test_sweep_skips_busy_tenants_backs_off_failures_and_keeps_the_old_sample(environment, monkeypatch):
    factory, graph = environment
    expected = publish(factory, graph, "tenant-a", "revision-a", demo_snapshot())
    old = make_stale(factory, "tenant-a", "revision-a")
    monkeypatch.setattr(analysis, "_failed", {})
    monkeypatch.setattr(analysis, "try_publication_lock", lambda db, tenant: False)
    assert backfill_stale_samples() == [{"tenant": "tenant-a", "backfilled": False, "busy": True}]
    monkeypatch.undo()
    monkeypatch.setattr(analysis, "_failed", {})
    with patch.object(analysis, "select_sample", side_effect=RuntimeError("sample bug")):
        assert backfill_stale_samples()[0]["failed"] is True
        # Not retried by this process within the backoff window.
        assert backfill_stale_samples() == []
    assert sample_of(factory, "tenant-a", "revision-a") == (old, None)
    monkeypatch.setattr(
        analysis,
        "_failed",
        {key: value - FAILED_BACKOFF_SECONDS for key, value in analysis._failed.items()},
    )
    assert backfill_samples() == 1
    assert sample_of(factory, "tenant-a", "revision-a") == (expected, SAMPLE_VERSION)
    assert analysis._failed == {}


def test_sweep_refuses_a_graph_revision_that_does_not_match_its_analysis(environment, monkeypatch):
    factory, graph = environment
    publish(factory, graph, "tenant-a", "revision-a", demo_snapshot())
    old = make_stale(factory, "tenant-a", "revision-a")
    monkeypatch.setattr(analysis, "_failed", {})
    graph.snapshots.pop(("tenant-a", "revision-a"))  # Revision missing from the graph store.
    assert backfill_stale_samples()[0]["failed"] is True
    # Never replaced by an empty sample.
    assert sample_of(factory, "tenant-a", "revision-a") == (old, None)


def test_memory_topology_matches_the_snapshot(environment):
    _, graph = environment
    snapshot = demo_snapshot()
    topology = graph.topology("tenant-a", "revision-a")
    assert topology.ids == [node.id for node in snapshot.nodes]
    assert topology.types == [node.type.value for node in snapshot.nodes]
    assert [
        (topology.ids[s], topology.ids[t]) for s, t in zip(topology.sources, topology.targets, strict=True)
    ] == [(edge.source, edge.target) for edge in snapshot.edges]
    assert graph.topology("tenant-b", "revision-a").ids == []
