"""Publish-time hierarchical clusters: bounds, determinism, ID stability, API, isolation, lifecycle."""

import json
import random
import sys
from collections import Counter
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.collectors.tasks import process_job
from app.core.auth import Actor, current_actor
from app.db.models import (
    IngestionJob,
    RevisionCluster,
    RevisionClusterLink,
    RevisionClusterMember,
    RevisionClusterSummary,
    TenantState,
)
from app.graph import clusters
from app.graph.clusters import (
    MAX_CHILDREN,
    MAX_MEMBERS,
    MAX_TOP,
    STRUCTURAL_NOTICE,
    PreviousClusters,
    assign_ids,
    backfill,
    backfill_missing,
    build_hierarchy,
    compute_clusters,
    delete_clusters,
    load_previous,
    louvain,
    missing_clusters,
    store_clusters,
    stored_summary,
    topology,
)
from app.graph.compact import CompactGraph
from app.graph.demo import demo_snapshot
from app.graph.schema import Edge, EdgeType, GraphSnapshot, Node, NodeType
from app.main import create_app

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from qualify_scale import generate  # noqa: E402


def client_for(tenant="tenant-a", roles=("viewer",)):
    app = create_app()
    app.dependency_overrides[current_actor] = lambda: Actor("reader", tenant, frozenset(roles))
    return TestClient(app)


def check_invariants(
    h, graph: CompactGraph, max_top=MAX_TOP, max_children=MAX_CHILDREN, max_members=MAX_MEMBERS
):
    assert 0 < len(h.top) <= max_top
    leaves = Counter()
    for cluster in range(len(h.parent)):
        assert len(h.children[cluster]) <= max_children
        assert len(h.members[cluster]) <= max_members
        assert bool(h.children[cluster]) != bool(h.members[cluster])  # Exactly one of the two.
        assert h.size[cluster] == len(h.members[cluster]) + sum(h.size[c] for c in h.children[cluster])
        for member in h.members[cluster]:
            leaves[member] += 1
            assert h.leaf_of[member] == cluster
    # Every entity sits in exactly one leaf.
    assert leaves == Counter(range(graph.node_count))
    assert sum(h.size[c] for c in h.top) == graph.node_count


def brute_force_edges(h, graph: CompactGraph):
    """Internal/boundary counts and sibling links recomputed edge by edge."""
    internal, boundary, links = Counter(), Counter(), Counter()
    for source, target in zip(graph.edge_source, graph.edge_target, strict=True):
        a, b = h.path(h.leaf_of[source]), h.path(h.leaf_of[target])
        for cluster in set(a) & set(b):
            internal[cluster] += 1
        for cluster in set(a) ^ set(b):
            boundary[cluster] += 1
        shared = len([1 for x, y in zip(a, b, strict=False) if x == y])
        if a != b:
            x, y = a[shared], b[shared]
            links[(a[shared - 1] if shared else -1, min(x, y), max(x, y))] += 1
    return internal, boundary, links


def test_hierarchy_bounds_counts_and_links_on_an_enterprise_shaped_graph():
    graph = CompactGraph.from_snapshot(generate(5000))
    h = build_hierarchy(graph)
    check_invariants(h, graph)
    assert max(h.size[c] for c in h.top) > MAX_MEMBERS  # Large communities really were split.
    assert {"community", "isolated"} <= set(h.kind)
    internal, boundary, links = brute_force_edges(h, graph)
    assert [h.internal[c] for c in range(len(h.parent))] == [internal[c] for c in range(len(h.parent))]
    assert [h.boundary[c] for c in range(len(h.parent))] == [boundary[c] for c in range(len(h.parent))]
    assert h.links == dict(links)
    # Degrees count relationships; isolated buckets hold exactly the nodes without any.
    assert sum(h.degree) == 2 * graph.edge_count - sum(
        1 for s, t in zip(graph.edge_source, graph.edge_target, strict=True) if s == t
    )
    isolated = {m for c in range(len(h.parent)) if h.kind[c] == "isolated" for m in h.members[c]}
    isolated |= {
        m
        for c in range(len(h.parent))
        if h.kind[c] == "part" and h.kind[h.parent[c]] == "isolated"
        for m in h.members[c]
    }
    assert isolated == {n for n in range(graph.node_count) if h.degree[n] == 0}
    for cluster in range(len(h.parent)):
        rep = h.representative[cluster]
        assert h.leaf_of[rep] in {cluster, *[d for d in range(len(h.parent)) if cluster in h.path(d)]}
        assert sum(h.types[cluster].values()) == h.size[cluster]
        assert sum(h.accounts[cluster].values()) == h.size[cluster]
        assert len(h.accounts[cluster]) <= clusters.ACCOUNT_FACETS + 1


def many_components(pairs=60, singles=25, star=40) -> GraphSnapshot:
    nodes, edges = [], []
    for index in range(pairs):
        a, b = f"svc:{index:03d}", f"role:{index:03d}"
        nodes += [Node(id=a, name=a, type=NodeType.SERVICE), Node(id=b, name=b, type=NodeType.ROLE)]
        edges.append(Edge(source=a, target=b, type=EdgeType.ASSUMES))
    nodes += [
        Node(id=f"db:{i:03d}", name=f"db {i}", type=NodeType.DATABASE, account_id=f"a{i % 3}")
        for i in range(singles)
    ]
    nodes.append(Node(id="hub", name="hub", type=NodeType.ROLE))
    for index in range(star):
        leaf = f"bucket:{index:03d}"
        nodes.append(Node(id=leaf, name=leaf, type=NodeType.BUCKET))
        edges.append(Edge(source="hub", target=leaf, type=EdgeType.READ))
    return GraphSnapshot(nodes=nodes, edges=edges)


def test_small_limits_pack_groups_split_parts_and_stay_bounded(monkeypatch):
    monkeypatch.setattr(clusters, "MAX_TOP", 16)
    monkeypatch.setattr(clusters, "MAX_CHILDREN", 4)
    monkeypatch.setattr(clusters, "MAX_MEMBERS", 10)
    graph = CompactGraph.from_snapshot(many_components())
    h = build_hierarchy(graph)
    check_invariants(h, graph, 16, 4, 10)
    kinds = set(h.kind)
    # Sixty two-node communities cannot all be top-level: they are packed per type.
    assert "group" in kinds
    # The 41-node star cannot be split by Louvain into more than one community: ordered parts.
    assert "part" in kinds
    assert any(h.label[c].startswith("Unconnected Database") for c in h.top)
    assert all(h.label[c] for c in range(len(h.parent)))


def test_more_groups_than_capacity_get_an_intermediate_range_level(monkeypatch):
    monkeypatch.setattr(clusters, "MAX_TOP", 3)
    monkeypatch.setattr(clusters, "MAX_CHILDREN", 3)
    monkeypatch.setattr(clusters, "MAX_MEMBERS", 4)
    graph = CompactGraph.from_snapshot(many_components(pairs=30, singles=0, star=3))
    h = build_hierarchy(graph)
    check_invariants(h, graph, 3, 3, 4)
    assert "range" in h.kind


def test_labels_never_repeat_an_ancestor_or_a_sibling():
    graph = CompactGraph.from_snapshot(generate(5000))
    h = build_hierarchy(graph)
    count = len(h.parent)
    # The graph really has children holding their parent's hub (the old label repeated the parent).
    hub_children = [
        c for c in range(count) if h.parent[c] >= 0 and h.representative[c] == h.representative[h.parent[c]]
    ]
    assert hub_children
    for cluster in range(count):
        ancestors = h.path(cluster)[:-1]
        assert h.label[cluster] not in {h.label[a] for a in ancestors}, h.label[cluster]
    for siblings in [h.top, *h.children]:
        labels = [h.label[c] for c in siblings]
        assert len(labels) == len(set(labels))
    for cluster in hub_children:
        if h.kind[cluster] == "community":
            # Named after its best member that the parent's label does not already use.
            assert h.label[cluster] != graph.names[h.representative[cluster]]
            assert h.label[cluster] in {graph.names[m] for m in range(graph.node_count)}


def test_duplicate_names_and_packed_bins_get_numbered_sibling_labels(monkeypatch):
    monkeypatch.setattr(clusters, "MAX_TOP", 6)
    monkeypatch.setattr(clusters, "MAX_MEMBERS", 10)
    nodes, edges = [], []
    for index in range(12):  # Twelve pairs, every role named "admin".
        a, b = f"svc:{index}", f"role:{index}"
        nodes += [
            Node(id=a, name=f"svc {index}", type=NodeType.SERVICE),
            Node(id=b, name="admin", type=NodeType.ROLE),
        ]
        edges += [
            Edge(source=a, target=b, type=EdgeType.ASSUMES),
            Edge(source=b, target=a, type=EdgeType.ASSUMES),
        ]
    graph = CompactGraph.from_snapshot(GraphSnapshot(nodes=nodes, edges=edges))
    h = build_hierarchy(graph)
    labels = [h.label[c] for c in h.top]
    assert len(labels) == len(set(labels)), labels
    assert any(" · group 1 of " in label for label in labels), labels
    again = build_hierarchy(CompactGraph.from_snapshot(GraphSnapshot(nodes=nodes, edges=edges)))
    assert again.label == h.label


def test_clustering_is_deterministic():
    snapshot = generate(3000)
    first, second = (CompactGraph.from_snapshot(snapshot) for _ in range(2))
    a, b = build_hierarchy(first), build_hierarchy(second)
    assign_ids(a, first, "rev", None)
    assign_ids(b, second, "rev", None)
    assert a.ids == b.ids and a.label == b.label and list(a.leaf_of) == list(b.leaf_of)
    assert a.links == b.links and a.size == b.size


def test_louvain_finds_two_cliques_and_warm_start_keeps_a_valid_previous_partition():
    nodes = list(range(10))
    adjacency = [dict() for _ in nodes]
    for group in (range(5), range(5, 10)):
        for a in group:
            for b in group:
                if a != b:
                    adjacency[a][b] = 1
    adjacency[4][5] = adjacency[5][4] = 1
    final = louvain(adjacency, nodes)[-1]
    assert final == [[0, 1, 2, 3, 4], [5, 6, 7, 8, 9]]
    # A near-tie (node 4 bridging) does not flip a warm-started partition.
    adjacency[4][6] = adjacency[6][4] = 1
    warm = louvain(adjacency, nodes, ["a"] * 5 + ["b"] * 5)[-1]
    assert warm == [[0, 1, 2, 3, 4], [5, 6, 7, 8, 9]]
    assert louvain([{}], [0]) == [[[0]]]


def previous_of(h, graph, revision="r1") -> PreviousClusters:
    return PreviousClusters(
        revision,
        {graph.ids[m]: h.ids[h.leaf_of[m]] for m in range(graph.node_count)},
        {h.ids[c]: h.ids[h.parent[c]] if h.parent[c] >= 0 else "" for c in range(len(h.parent))},
        {h.ids[c]: h.size[c] for c in range(len(h.parent))},
    )


def perturbed(snapshot: GraphSnapshot, fraction: float, seed: int = 99) -> GraphSnapshot:
    """Replace ``fraction`` of the edges: half removed, as many random new ones added."""
    rng = random.Random(seed)
    edges = list(snapshot.edges)
    drop = set(rng.sample(range(len(edges)), int(len(edges) * fraction / 2)))
    kept = [edge for index, edge in enumerate(edges) if index not in drop]
    ids, seen = [node.id for node in snapshot.nodes], {edge.id for edge in kept}
    while len(kept) < len(edges):
        edge = Edge(source=rng.choice(ids), target=rng.choice(ids), type=EdgeType.READ)
        if edge.id not in seen:
            seen.add(edge.id)
            kept.append(edge)
    return snapshot.model_copy(update={"edges": kept})


def test_cluster_ids_are_stable_across_a_one_percent_edge_change():
    snapshot = generate(5000)
    first = CompactGraph.from_snapshot(snapshot)
    before = compute_clusters(first, "r1").hierarchy
    second = CompactGraph.from_snapshot(perturbed(snapshot, 0.01))
    after = compute_clusters(second, "r2", previous_of(before, first)).hierarchy
    check_invariants(after, second)
    kept = set(before.ids) & set(after.ids)
    assert len(kept) / len(before.ids) >= 0.9
    same_leaf = sum(
        before.ids[before.leaf_of[m]] == after.ids[after.leaf_of[m]] for m in range(first.node_count)
    )
    assert same_leaf / first.node_count >= 0.85
    assert after.reused == len(kept)
    # Unchanged input warm-started from its own clusters keeps (nearly) every ID.
    again = compute_clusters(CompactGraph.from_snapshot(snapshot), "r3", previous_of(before, first)).hierarchy
    assert len(set(again.ids) & set(before.ids)) / len(before.ids) >= 0.95


def test_new_ids_do_not_collide_with_reused_ones():
    graph = CompactGraph.from_snapshot(many_components())
    h = build_hierarchy(graph)
    assign_ids(h, graph, "r1", None)
    assert len(set(h.ids)) == len(h.ids)
    assert all(cluster.startswith("c") and len(cluster) == 16 for cluster in h.ids)


def publish(client, snapshot: GraphSnapshot) -> str:
    with patch("app.api.routes.ingest.delay"):
        job = client.post(
            "/api/v1/ingestions", json={"source": "snapshot", "payload": snapshot.model_dump(mode="json")}
        ).json()
    process_job(job["id"])
    return job["id"]


def current(factory, tenant="tenant-a") -> str:
    with factory() as db:
        return db.get(TenantState, tenant).revision


def test_publish_stores_clusters_and_endpoints_walk_the_hierarchy(client, environment, monkeypatch):
    factory, graph = environment
    monkeypatch.setattr(clusters, "MAX_MEMBERS", 10)
    monkeypatch.setattr(clusters, "MAX_CHILDREN", 4)
    publish(client, many_components())
    revision = current(factory)
    with factory() as db:
        summary = stored_summary(db, "tenant-a", revision)
        assert summary is not None and summary.previous_revision is None and summary.reused_ids == 0
        assert summary.total_nodes == 186 and summary.total_edges == 100
        members = db.scalar(
            select(func.count()).where(
                RevisionClusterMember.tenant_id == "tenant-a", RevisionClusterMember.revision == revision
            )
        )
        assert members == summary.total_nodes
    with patch.object(graph, "snapshot", side_effect=AssertionError("full snapshot load")):
        body = client.get("/api/v1/graph/clusters").json()
        assert body["revision"] == revision and body["view"]["notice"] == STRUCTURAL_NOTICE
        assert body["view"]["clusters"] == len(body["clusters"]) == summary.top_level <= MAX_TOP
        assert body["view"]["total_nodes"] == 186 and not body["view"]["truncated"]
        assert sum(c["size"] for c in body["clusters"]) == 186
        assert {c["parent_id"] for c in body["clusters"]} == {None}
        top_ids = {c["id"] for c in body["clusters"]}
        assert all({e["source"], e["target"]} <= top_ids and e["source"] < e["target"] for e in body["edges"])
        # Expand everything: children are bounded, leaves list members with internal edges.
        pending, leaves, member_ids = [c["id"] for c in body["clusters"]], 0, set()
        while pending:
            detail = client.get(
                f"/api/v1/graph/clusters/{pending.pop()}", params={"revision": revision}
            ).json()
            assert detail["path"][-1]["id"] == detail["cluster"]["id"]
            assert detail["view"]["notice"] == STRUCTURAL_NOTICE
            if detail["view"]["mode"] == "clusters":
                assert 0 < len(detail["children"]) <= 4 and detail["nodes"] == []
                assert {c["parent_id"] for c in detail["children"]} == {detail["cluster"]["id"]}
                pending += [c["id"] for c in detail["children"]]
            else:
                leaves += 1
                ids = {n["id"] for n in detail["nodes"]}
                assert 0 < len(ids) <= 10
                assert len(ids) == detail["cluster"]["member_count"] and not (ids & member_ids)
                member_ids |= ids
                assert set(detail["boundary_edges"]) == ids
                assert all(e["source"] in ids and e["target"] in ids for e in detail["node_edges"])
                assert detail["view"]["shown_member_edges"] == detail["cluster"]["internal_edges"]
        assert len(member_ids) == 186 and leaves >= 3
    # Explicit truncation: a smaller member/edge limit is reported, never silent.
    star = next(
        c
        for c in client.get("/api/v1/graph/clusters").json()["clusters"]
        if c["kind"] == "community" and c["size"] > 10
    )
    leaf = client.get(f"/api/v1/graph/clusters/{star['id']}").json()
    while leaf["view"]["mode"] == "clusters":
        leaf = client.get(f"/api/v1/graph/clusters/{leaf['children'][0]['id']}").json()
    first_part = leaf["cluster"]
    assert first_part["member_count"] > 2
    page = client.get(
        f"/api/v1/graph/clusters/{first_part['id']}", params={"member_limit": 2, "edge_limit": 1}
    ).json()
    assert page["view"]["truncated"], page["view"]
    assert page["view"]["shown_members"] == 2
    assert page["view"]["total_members"] == first_part["member_count"]


def test_hub_member_boundary_counts(client, environment):
    factory, _ = environment
    publish(client, many_components(pairs=2, singles=0, star=5))
    top = client.get("/api/v1/graph/clusters").json()["clusters"]
    star = next(c for c in top if c["representative_id"] == "hub")
    assert star["label"] == "hub" and star["size"] == 6 and star["dominant_type"] == "S3Bucket"
    detail = client.get(f"/api/v1/graph/clusters/{star['id']}").json()
    assert detail["view"]["mode"] == "members" and detail["nodes"][0]["id"] == "bucket:000"
    assert detail["boundary_edges"] == {**{f"bucket:{i:03d}": 0 for i in range(5)}, "hub": 0}
    assert len(detail["node_edges"]) == 5


def test_cluster_api_semantics_revision_409_missing_404_unavailable_503_and_bounds(client, environment):
    factory, graph = environment
    # Legacy revision (published before clustering) and empty tenant: explicit 404.
    response = client.get("/api/v1/graph/clusters")
    assert response.status_code == 404 and "not computed" in response.json()["detail"]
    publish(client, demo_snapshot())
    revision = current(factory)
    assert client.get("/api/v1/graph/clusters", params={"revision": "stale"}).status_code == 409
    top = client.get("/api/v1/graph/clusters", params={"revision": revision}).json()["clusters"]
    cluster_id = top[0]["id"]
    assert client.get(f"/api/v1/graph/clusters/{cluster_id}", params={"revision": "stale"}).status_code == 409
    assert client.get("/api/v1/graph/clusters/cffffffffffffff").status_code == 404
    for bad in ("x" * 33, "a b", "c;DROP"):
        assert client.get(f"/api/v1/graph/clusters/{bad}").status_code in {404, 422}
    for params in ({"level": 1}, {"edge_limit": 0}, {"edge_limit": 2001}):
        assert client.get("/api/v1/graph/clusters", params=params).status_code == 422
    for params in ({"member_limit": 0}, {"member_limit": 501}, {"edge_limit": 2001}):
        assert client.get(f"/api/v1/graph/clusters/{cluster_id}", params=params).status_code == 422
    # Graph metadata gone (e.g. a partial restore): 503 with Retry-After, like explore.
    published = graph.snapshots.pop(("tenant-a", revision))
    for path in ("/api/v1/graph/clusters", f"/api/v1/graph/clusters/{cluster_id}"):
        response = client.get(path)
        assert response.status_code == 503 and response.headers["retry-after"] == "5"
    graph.snapshots[("tenant-a", revision)] = published
    with TestClient(create_app()) as anonymous:
        assert anonymous.get("/api/v1/graph/clusters").status_code == 401
        assert anonymous.get(f"/api/v1/graph/clusters/{cluster_id}").status_code == 401


def test_cluster_rows_are_tenant_and_revision_isolated(client, environment):
    factory, graph = environment
    publish(client, demo_snapshot())
    first = current(factory)
    first_ids = {c["id"] for c in client.get("/api/v1/graph/clusters").json()["clusters"]}
    publish(client, many_components(pairs=5, singles=3, star=4))
    second = current(factory)
    assert second != first
    with factory() as db:
        assert stored_summary(db, "tenant-a", second).previous_revision == first
    # Tenant B (no revision) never sees tenant A's clusters, by list or by ID.
    with client_for("tenant-b") as other:
        assert other.get("/api/v1/graph/clusters").status_code == 404
        for cluster_id in first_ids:
            assert other.get(f"/api/v1/graph/clusters/{cluster_id}").status_code == 404
    # Rows of a same-named revision of another tenant are invisible too.
    with factory() as db:
        db.add(TenantState(tenant_id="tenant-b", revision=second))
        db.commit()
    graph.snapshots[("tenant-b", second)] = GraphSnapshot()
    with client_for("tenant-b") as other:
        assert other.get("/api/v1/graph/clusters").status_code == 404
    # An ID that only exists in the older revision is not served for the current one.
    current_ids = {c["id"] for c in client.get("/api/v1/graph/clusters").json()["clusters"]}
    for cluster_id in first_ids - current_ids:
        assert client.get(f"/api/v1/graph/clusters/{cluster_id}").status_code == 404
    with factory() as db:
        delete_clusters(db, "tenant-a", first)
        db.commit()
        for model in (RevisionClusterSummary, RevisionCluster, RevisionClusterLink, RevisionClusterMember):
            scopes = {(r.tenant_id, r.revision) for r in db.scalars(select(model))}
            assert ("tenant-a", first) not in scopes
            assert ("tenant-a", second) in scopes or model is RevisionClusterLink


def test_failed_clustering_publishes_nothing(client, environment):
    factory, graph = environment
    with patch("app.api.routes.ingest.delay"):
        job = client.post(
            "/api/v1/ingestions",
            json={"source": "snapshot", "payload": demo_snapshot().model_dump(mode="json")},
        ).json()
    with patch("app.collectors.tasks.compute_clusters", side_effect=RuntimeError("cluster bug")):
        with pytest.raises(RuntimeError):
            process_job(job["id"])
    with factory() as db:
        assert db.get(TenantState, "tenant-a").revision == "revision-a"
        assert db.get(IngestionJob, job["id"]).status == "retrying"
        assert db.scalar(select(func.count()).select_from(RevisionClusterSummary)) == 0
        assert db.scalar(select(func.count()).select_from(RevisionClusterMember)) == 0


def test_backfill_recomputes_clusters_for_a_revision_without_rows(environment, capsys):
    factory, graph = environment
    assert backfill("tenant-a")["backfilled"] is True
    assert backfill("tenant-a")["backfilled"] is False
    with factory() as db:
        summary = stored_summary(db, "tenant-a", "revision-a")
        assert summary.total_nodes == len(demo_snapshot().nodes)
    with client_for() as client:
        assert client.get("/api/v1/graph/clusters").status_code == 200
    with patch.object(sys, "argv", ["clusters", "--tenant", "tenant-a"]):
        clusters.main()
    assert json.loads(capsys.readouterr().out)["backfilled"] is False
    with pytest.raises(ValueError):
        backfill("tenant-missing")


def test_older_cluster_version_reads_as_missing(environment):
    factory, _ = environment
    backfill("tenant-a")
    with factory() as db:
        before = {row.cluster_id: row.label for row in db.scalars(select(RevisionCluster))}
        db.get(RevisionClusterSummary, ("tenant-a", "revision-a")).cluster_version = (
            clusters.CLUSTER_VERSION - 1
        )
        db.commit()
        assert stored_summary(db, "tenant-a", "revision-a") is None
        assert load_previous(db, "tenant-a", "revision-a") is None
        assert load_previous(db, "tenant-a", "revision-a", any_version=True) is not None
    assert backfill("tenant-a")["backfilled"] is True
    with factory() as db:
        # Recomputing the same revision keeps its cluster IDs (seeded from the older rows).
        assert {row.cluster_id: row.label for row in db.scalars(select(RevisionCluster))} == before
        assert db.scalar(select(func.count()).select_from(RevisionClusterSummary)) == 1


def test_worker_sweep_backfills_current_revisions_only_per_tenant(environment):
    factory, graph = environment
    # tenant-a: current revision-a has no clusters (published before migration 0005).
    # tenant-b: current revision is clustered; its older revision is not and stays so.
    # tenant-c: clusters of an older CLUSTER_VERSION. tenant-d: nothing published.
    for tenant, revision, snapshot in (
        ("tenant-b", "b-old", demo_snapshot()),
        ("tenant-b", "b-new", many_components(pairs=3, singles=2, star=3)),
        ("tenant-c", "c-1", many_components(pairs=2, singles=1, star=2)),
    ):
        graph.publish(tenant, revision, snapshot)
    with factory() as db:
        db.add_all(
            [
                TenantState(tenant_id="tenant-b", revision="b-new"),
                TenantState(tenant_id="tenant-c", revision="c-1"),
                TenantState(tenant_id="tenant-d", revision=""),
            ]
        )
        for tenant, revision in (("tenant-b", "b-new"), ("tenant-c", "c-1")):
            store_clusters(
                db,
                tenant,
                revision,
                compute_clusters(CompactGraph.from_snapshot(graph.snapshot(tenant, revision)), revision),
            )
        db.flush()
        db.get(RevisionClusterSummary, ("tenant-c", "c-1")).cluster_version = clusters.CLUSTER_VERSION - 1
        db.commit()
        assert missing_clusters(db, 10) == [("tenant-a", "revision-a"), ("tenant-c", "c-1")]
        b_rows = sorted(
            (r.cluster_id, r.label)
            for r in db.scalars(select(RevisionCluster).where(RevisionCluster.tenant_id == "tenant-b"))
        )
    with (
        client_for("tenant-a") as reader,
        patch.object(graph, "snapshot", side_effect=AssertionError("API loaded a snapshot")),
    ):
        response = reader.get("/api/v1/graph/clusters")
        assert response.status_code == 404 and response.headers["retry-after"] == "60"
    results = backfill_missing(limit=1)
    assert [(r["tenant"], r["backfilled"]) for r in results] == [("tenant-a", True)]
    assert backfill_missing() == [
        {
            "tenant": "tenant-c",
            "revision": "c-1",
            "backfilled": True,
            "clusters": results_count(factory, "tenant-c", "c-1"),
        }
    ]
    assert backfill_missing() == []
    with factory() as db:
        assert missing_clusters(db, 10) == []
        # Revision pin: only current revisions are computed; tenant-b's older revision stays without rows.
        assert stored_summary(db, "tenant-b", "b-old") is None
        assert (
            sorted(
                (r.cluster_id, r.label)
                for r in db.scalars(select(RevisionCluster).where(RevisionCluster.tenant_id == "tenant-b"))
            )
            == b_rows
        )
        summary = stored_summary(db, "tenant-a", "revision-a")
        assert summary.total_nodes == len(demo_snapshot().nodes)
        assert {
            r.tenant_id
            for r in db.scalars(
                select(RevisionClusterMember).where(RevisionClusterMember.revision == "revision-a")
            )
        } == {"tenant-a"}
    with (
        client_for("tenant-a") as reader,
        patch.object(graph, "snapshot", side_effect=AssertionError("API loaded a snapshot")),
    ):
        assert reader.get("/api/v1/graph/clusters").status_code == 200
    with client_for("tenant-d") as reader:
        assert reader.get("/api/v1/graph/clusters").status_code == 404


def results_count(factory, tenant: str, revision: str) -> int:
    with factory() as db:
        return db.scalar(
            select(func.count()).where(
                RevisionCluster.tenant_id == tenant, RevisionCluster.revision == revision
            )
        )


def test_worker_sweep_skips_busy_tenants_and_backs_off_failures(environment, monkeypatch):
    factory, graph = environment
    monkeypatch.setattr(clusters, "_failed", {})
    monkeypatch.setattr(clusters, "try_publication_lock", lambda db, tenant: False)
    assert backfill_missing() == [{"tenant": "tenant-a", "backfilled": False, "busy": True}]
    monkeypatch.undo()
    monkeypatch.setattr(clusters, "_failed", {})
    with patch.object(clusters, "compute_clusters", side_effect=RuntimeError("cluster bug")):
        assert backfill_missing()[0]["failed"] is True
        # Not retried by this process within the backoff window.
        assert backfill_missing() == []
    with factory() as db:
        assert stored_summary(db, "tenant-a", "revision-a") is None
    monkeypatch.setattr(
        clusters,
        "_failed",
        {key: value - clusters.FAILED_BACKOFF_SECONDS for key, value in clusters._failed.items()},
    )
    from app.collectors.tasks import backfill_clusters

    assert backfill_clusters() == 1
    with factory() as db:
        assert stored_summary(db, "tenant-a", "revision-a") is not None


def test_store_clusters_round_trips_through_sql(environment):
    factory, _ = environment
    graph = CompactGraph.from_snapshot(many_components())
    computed = compute_clusters(graph, "rev-x")
    with factory() as db:
        store_clusters(db, "tenant-z", "rev-x", computed)
        db.commit()
        h = computed.hierarchy
        rows = {row.cluster_id: row for row in db.scalars(select(RevisionCluster))}
        assert set(rows) == set(h.ids)
        for index, cluster_id in enumerate(h.ids):
            row = rows[cluster_id]
            assert row.size == h.size[index] and row.types == h.types[index]
            assert row.parent_id == (h.ids[h.parent[index]] if h.parent[index] >= 0 else "")
        links = db.scalars(select(RevisionClusterLink)).all()
        assert sum(link.weight for link in links) == sum(h.links.values())
        assert all(link.source_id < link.target_id for link in links)
        hub = db.get(RevisionClusterMember, ("tenant-z", "rev-x", "hub"))
        assert hub.ordinal == 0 and hub.degree == 40 and hub.internal_degree == 40
    assert topology(graph)[graph.index["hub"]] == {graph.index[f"bucket:{i:03d}"]: 1 for i in range(40)}


def brute_internal(snapshot: GraphSnapshot, ids: set[str]) -> set[str]:
    return {edge.id for edge in snapshot.edges if edge.source in ids and edge.target in ids}


def test_in_place_expansion_shows_whole_subtrees_and_links_them_to_expanded_clusters(
    client, environment, monkeypatch
):
    factory, graph = environment
    monkeypatch.setattr(clusters, "MAX_MEMBERS", 40)
    monkeypatch.setattr(clusters, "MAX_CHILDREN", 4)
    snapshot = generate(1500)
    publish(client, snapshot)
    revision = current(factory)
    top = client.get("/api/v1/graph/clusters").json()["clusters"]
    # A cluster with sub-groups expands to every member below it, in one response.
    nested = sorted((c for c in top if c["child_count"]), key=lambda c: -c["size"])
    assert nested, "fixture must produce a multi-level cluster"
    shown: set[str] = set()
    expanded: list[str] = []
    seen_edges: set[str] = set()
    with patch.object(graph, "snapshot", side_effect=AssertionError("full snapshot load")):
        for cluster in [nested[0], *sorted(top, key=lambda c: c["size"])[:6]]:
            if cluster["id"] in expanded or len(shown) + cluster["size"] > 5000:
                continue
            body = client.get(
                f"/api/v1/graph/clusters/{cluster['id']}/members",
                params={"revision": revision, "expanded": expanded},
            )
            assert body.status_code == 200, body.text
            body = body.json()
            ids = {n["id"] for n in body["nodes"]}
            assert len(ids) == cluster["size"] == body["view"]["total_members"]
            assert not ids & shown and set(body["degrees"]) == ids
            degrees = [body["degrees"][n] for n in ids]
            assert all(d >= 0 for d in degrees)
            assert body["view"]["visible_members"] == len(shown) + len(ids)
            assert body["view"]["notice"] == STRUCTURAL_NOTICE and not body["view"]["truncated"]
            for edge in body["edges"]:
                assert edge["source"] in ids or edge["target"] in ids
                assert {edge["source"], edge["target"]} <= ids | shown
            seen_edges |= {edge["id"] for edge in body["edges"]}
            shown |= ids
            expanded.append(cluster["id"])
    # Every relationship among the shown members arrived exactly once across the expansions.
    assert len(expanded) >= 3
    assert seen_edges == brute_internal(snapshot, shown)
    # Truncation is explicit; a hub cluster's members come highest degree first.
    page = client.get(
        f"/api/v1/graph/clusters/{nested[0]['id']}/members", params={"member_limit": 5, "edge_limit": 1}
    ).json()
    assert page["view"]["truncated"] and len(page["nodes"]) == 5 and len(page["edges"]) <= 1
    full = client.get(f"/api/v1/graph/clusters/{nested[0]['id']}/members").json()
    top_five = sorted(full["degrees"].items(), key=lambda item: (-item[1], item[0]))[:5]
    assert set(page["degrees"]) == {entity for entity, _ in top_five}


def test_in_place_expansion_budget_bounds_and_isolation(client, environment, monkeypatch):
    factory, graph = environment
    publish(client, many_components())
    revision = current(factory)
    top = sorted(client.get("/api/v1/graph/clusters").json()["clusters"], key=lambda c: -c["size"])
    big, small = top[0], top[1]
    path = f"/api/v1/graph/clusters/{big['id']}/members"
    assert client.get(path, params={"expanded": [small["id"]]}).status_code == 200
    # More than the visible budget on screen at once: 422 with an explanation.
    monkeypatch.setattr(clusters, "MAX_VISIBLE_MEMBERS", big["size"] + small["size"] - 1)
    response = client.get(path, params={"expanded": [small["id"]]})
    assert response.status_code == 422 and "at most" in response.json()["detail"]
    assert client.get(path).status_code == 200
    monkeypatch.undo()
    for params in (
        {"member_limit": 0},
        {"member_limit": 5001},
        {"edge_limit": 0},
        {"edge_limit": 20001},
        {"expanded": ["a b"]},
        {"expanded": [f"x{i}" for i in range(65)]},
    ):
        assert client.get(path, params=params).status_code == 422, params
    assert client.get(path, params={"revision": "stale"}).status_code == 409
    assert client.get("/api/v1/graph/clusters/cffffffffffffff/members").status_code == 404
    assert client.get(path, params={"expanded": ["cffffffffffffff"]}).status_code == 404
    with client_for("tenant-b") as other:
        assert other.get(path).status_code == 404
    published = graph.snapshots.pop(("tenant-a", revision))
    response = client.get(path)
    assert response.status_code == 503 and response.headers["retry-after"] == "5"
    graph.snapshots[("tenant-a", revision)] = published
    with TestClient(create_app()) as anonymous:
        assert anonymous.get(path).status_code == 401
    with pytest.raises(ValueError):
        graph.cluster_expansion("tenant-a", revision, [f"n{i}" for i in range(5001)], [], 10)
    with pytest.raises(ValueError):
        graph.cluster_expansion("tenant-a", revision, ["a"], [], 20001)
