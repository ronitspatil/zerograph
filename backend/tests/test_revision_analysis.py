"""Publication-time revision analysis: storage, read paths, legacy fallback and isolation."""

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.collectors.tasks import process_job
from app.core.auth import Actor, current_actor
from app.db.models import IngestionJob, RevisionAnalysis, RevisionFinding, TenantState
from app.engine.analysis_index import AnalysisIndex
from app.engine.toxic_combos import detect
from app.graph import analysis
from app.graph.analysis import (
    ANALYSIS_VERSION,
    backfill,
    compute_analysis,
    delete_analysis,
    store_analysis,
    stored_analysis,
)
from app.graph.demo import demo_snapshot
from app.graph.exploration import RevisionTotals
from app.graph.repository import CypherGraphStore
from app.graph.schema import IDENTITY_TYPES, Edge, EdgeType, GraphSnapshot, Node, NodeType, Sensitivity
from app.main import create_app


def reference_overview(snapshot: GraphSnapshot) -> dict:
    """The request-time overview implementation this change replaced, kept as a golden reference."""
    prepared = AnalysisIndex.build(snapshot, include_uncertain=True)
    findings = detect(snapshot, index=prepared)
    identities = [n for n in snapshot.nodes if n.type in IDENTITY_TYPES]
    high_blast = sum(prepared.score(n.id, prepared.paths(n.id))[0] >= 70 for n in identities)
    return {
        "total_nhis": len(identities),
        "ai_agents": sum(n.type == NodeType.AGENT for n in snapshot.nodes),
        "toxic_combinations": len(findings),
        "high_blast_radius": high_blast,
        "data_assets": sum(
            n.type in {NodeType.BUCKET, NodeType.DATABASE, NodeType.VECTOR} for n in snapshot.nodes
        ),
        "confirmed_edges": sum(e.certainty == "confirmed" for e in snapshot.edges),
        "uncertain_edges": sum(e.certainty != "confirmed" for e in snapshot.edges),
        "accounts": sorted({n.account_id for n in snapshot.nodes if n.account_id}),
        "sensitivity": {
            level: sum(
                n.sensitivity.value == level
                for n in snapshot.nodes
                if n.type in {NodeType.BUCKET, NodeType.DATABASE, NodeType.VECTOR}
            )
            for level in ["public", "internal", "confidential", "restricted"]
        },
    }


def exposed_snapshot(agents=7, assets=4) -> GraphSnapshot:
    """Several exposed agents through a shared role and an uncertain hop, for multi-page findings."""
    nodes = [
        Node(
            id=f"agent:{index}",
            name=f"Agent {index}",
            type=NodeType.AGENT,
            account_id=f"acct-{index % 2}",
            internet_exposed=True,
            authenticated=False,
        )
        for index in range(agents)
    ]
    nodes += [
        Node(id="role:hub", name="Hub", type=NodeType.ROLE, privileged=True),
        Node(id="role:side", name="Side", type=NodeType.ROLE),
        Node(id="mcp:tools", name="Tools", type=NodeType.MCP),
    ]
    nodes += [
        Node(
            id=f"data:{index}",
            name=f"Data {index}",
            type=[NodeType.DATABASE, NodeType.BUCKET, NodeType.VECTOR][index % 3],
            sensitivity=[Sensitivity.RESTRICTED, Sensitivity.CONFIDENTIAL, Sensitivity.PUBLIC][index % 3],
            encrypted=index % 3 != 2,
        )
        for index in range(assets)
    ]
    edges = [
        Edge(source=f"agent:{index}", target="role:hub", type=EdgeType.ASSUMES) for index in range(agents)
    ]
    edges += [
        Edge(source="agent:0", target="mcp:tools", type=EdgeType.INVOKES, certainty="declared"),
        Edge(source="mcp:tools", target="role:side", type=EdgeType.ASSUMES, certainty="conditional"),
        Edge(source="role:side", target="role:hub", type=EdgeType.INHERITS),
        Edge(source="role:hub", target="role:side", type=EdgeType.INHERITS),
    ]
    edges += [Edge(source="role:hub", target=f"data:{index}", type=EdgeType.READ) for index in range(assets)]
    return GraphSnapshot(nodes=nodes, edges=edges, warnings=["fixture"])


def publish_with_analysis(factory, graph, tenant, revision, snapshot):
    graph.publish(tenant, revision, snapshot)
    with factory() as db:
        store_analysis(db, tenant, revision, compute_analysis(snapshot))
        state = db.get(TenantState, tenant)
        if state is None:
            db.add(TenantState(tenant_id=tenant, revision=revision))
        else:
            state.revision = revision
        db.commit()


def client_for(tenant="tenant-a", roles=("admin", "analyst", "viewer")):
    app = create_app()
    app.dependency_overrides[current_actor] = lambda: Actor("alice", tenant, frozenset(roles))
    return TestClient(app)


@pytest.mark.parametrize("snapshot", [demo_snapshot(), exposed_snapshot(), GraphSnapshot()])
def test_computed_analysis_matches_former_request_time_overview(snapshot):
    result = compute_analysis(snapshot)
    assert result.overview == reference_overview(snapshot)
    assert [f.id for f in result.findings] == [f.id for f in detect(snapshot)]
    assert result.total_asset_weight == AnalysisIndex.build(snapshot).total_asset_weight
    assert len(result.high_blast_ids) == result.overview["high_blast_radius"]
    assert result.totals.nodes == len(snapshot.nodes) and result.totals.edges == len(snapshot.edges)


def test_publish_stores_analysis_before_pointer_swap_and_reads_never_load_snapshot(client, environment):
    factory, graph = environment
    snapshot = exposed_snapshot()
    with patch("app.api.routes.ingest.delay"):
        job = client.post(
            "/api/v1/ingestions", json={"source": "snapshot", "payload": snapshot.model_dump(mode="json")}
        ).json()
    process_job(job["id"])
    with factory() as db:
        revision = db.get(TenantState, "tenant-a").revision
        row = stored_analysis(db, "tenant-a", revision)
        assert row is not None and row.analysis_version == ANALYSIS_VERSION
        published = graph.snapshot("tenant-a", revision)
        assert row.overview == reference_overview(published)
        assert row.total_findings == len(detect(published)) > 1
        assert row.total_asset_weight == AnalysisIndex.build(published).total_asset_weight
        assert db.scalar(select(func.count()).select_from(RevisionFinding)) == row.total_findings
    with patch.object(graph, "snapshot", side_effect=AssertionError("full snapshot load")):
        body = client.get("/api/v1/overview").json()
        assert body == {"revision": revision, **reference_overview(published)}
        response = client.get("/api/v1/findings")
        assert response.status_code == 200
        assert response.json() == [f.model_dump(mode="json") for f in detect(published)]
        assert response.headers["x-graph-revision"] == revision
        assert response.headers["x-total-count"] == str(len(response.json()))
        assert "x-next-cursor" not in response.headers
        view = client.get("/api/v1/graph/explore").json()["view"]
        assert (view["total_nodes"], view["total_edges"]) == (len(published.nodes), len(published.edges))
        roles = client.get("/api/v1/graph/roles").json()["view"]
        assert (roles["total_roles"], roles["total_role_edges"]) == (2, 2)


def test_failed_analysis_publishes_nothing(client, environment):
    factory, graph = environment
    with patch("app.api.routes.ingest.delay"):
        job = client.post(
            "/api/v1/ingestions",
            json={"source": "snapshot", "payload": demo_snapshot().model_dump(mode="json")},
        ).json()
    with patch("app.graph.compact.CompactGraph.analyze", side_effect=RuntimeError("analysis bug")):
        with pytest.raises(RuntimeError):
            process_job(job["id"])
    with factory() as db:
        assert db.get(TenantState, "tenant-a").revision == "revision-a"
        assert db.get(IngestionJob, job["id"]).status == "retrying"
        assert db.scalar(select(func.count()).select_from(RevisionAnalysis)) == 0
    assert list(graph.snapshots) == [("tenant-a", "revision-a")]


@pytest.mark.parametrize("stored", [True, False])
def test_findings_pages_follow_cursor_with_identical_results_stored_or_computed(client, environment, stored):
    factory, graph = environment
    snapshot = exposed_snapshot()
    if stored:
        publish_with_analysis(factory, graph, "tenant-a", "paged", snapshot)
    else:
        graph.publish("tenant-a", "paged", snapshot)
        with factory() as db:
            db.get(TenantState, "tenant-a").revision = "paged"
            db.commit()
    expected = [f.model_dump(mode="json") for f in detect(snapshot)]
    assert len(expected) > 5
    collected, cursor = [], None
    while True:
        params = {"limit": 3, "revision": "paged"}
        if cursor:
            params["cursor"] = cursor
        response = client.get("/api/v1/findings", params=params)
        assert response.status_code == 200
        page = response.json()
        assert len(page) <= 3 and response.headers["x-total-count"] == str(len(expected))
        collected += page
        cursor = response.headers.get("x-next-cursor")
        if cursor is None:
            break
        assert cursor == page[-1]["id"]
    assert collected == expected
    assert len(client.get("/api/v1/findings").json()) == len(expected)  # Default limit is 200.
    assert client.get("/api/v1/findings", params={"cursor": "missing"}).status_code == 422
    assert client.get("/api/v1/findings", params={"revision": "stale"}).status_code == 409
    for params in ({"limit": 0}, {"limit": 1001}, {"cursor": ""}, {"cursor": "x" * 65}):
        assert client.get("/api/v1/findings", params=params).status_code == 422


def test_overview_and_findings_default_limit_and_empty_tenant(environment):
    factory, graph = environment
    with client_for("empty-tenant", ("viewer",)) as other:
        overview = other.get("/api/v1/overview").json()
        assert overview == {"revision": "", **reference_overview(GraphSnapshot())}
        response = other.get("/api/v1/findings")
        assert response.json() == [] and response.headers["x-total-count"] == "0"
    many = exposed_snapshot(agents=60, assets=4)
    publish_with_analysis(factory, graph, "tenant-a", "many", many)
    with client_for() as client:
        response = client.get("/api/v1/findings")
        assert len(response.json()) == 200
        assert response.headers["x-total-count"] == str(len(detect(many)))
        assert response.headers["x-next-cursor"] == response.json()[-1]["id"]


def test_stored_rows_are_tenant_and_revision_isolated(environment):
    factory, graph = environment
    publish_with_analysis(factory, graph, "tenant-b", "shared-name", exposed_snapshot())
    # Same revision string for another tenant, and a stale revision of tenant-a, both with rows.
    publish_with_analysis(factory, graph, "tenant-a", "shared-name", demo_snapshot())
    publish_with_analysis(factory, graph, "tenant-a", "older", exposed_snapshot(agents=2))
    with factory() as db:
        db.get(TenantState, "tenant-a").revision = "shared-name"
        db.commit()
    demo_ids = [f.id for f in detect(demo_snapshot())]
    with client_for() as client:
        assert client.get("/api/v1/overview").json()["ai_agents"] == 2
        assert [f["id"] for f in client.get("/api/v1/findings").json()] == demo_ids
        other_cursor = detect(exposed_snapshot())[0].id
        assert client.get("/api/v1/findings", params={"cursor": other_cursor}).status_code == 422
        assert client.get("/api/v1/graph/explore").json()["view"]["total_nodes"] == 12
    with client_for("tenant-b", ("viewer",)) as client:
        assert client.get("/api/v1/overview").json()["ai_agents"] == 7
        assert client.get("/api/v1/graph/explore").json()["view"]["total_nodes"] == 14
    with factory() as db:
        delete_analysis(db, "tenant-a", "shared-name")
        db.commit()
        assert stored_analysis(db, "tenant-b", "shared-name") is not None
        assert stored_analysis(db, "tenant-a", "older") is not None
        assert stored_analysis(db, "tenant-a", "shared-name") is None
        assert (
            db.scalar(
                select(func.count()).where(
                    RevisionFinding.tenant_id == "tenant-a", RevisionFinding.revision == "shared-name"
                )
            )
            == 0
        )


def test_explore_and_roles_take_totals_from_stored_rows(environment):
    factory, graph = environment
    with factory() as db:
        # Distinct sentinel totals prove the route used the stored row, not a recount.
        store_analysis(db, "tenant-a", "revision-a", compute_analysis(demo_snapshot()))
        db.flush()
        row = db.get(RevisionAnalysis, ("tenant-a", "revision-a"))
        row.total_nodes, row.total_edges, row.total_roles, row.total_role_edges = 9001, 9002, 9003, 9004
        db.commit()
    with client_for() as client:
        view = client.get("/api/v1/graph/explore").json()["view"]
        assert (view["total_nodes"], view["total_edges"], view["truncated"]) == (9001, 9002, True)
        roles = client.get("/api/v1/graph/roles").json()["view"]
        assert (roles["total_nodes"], roles["total_roles"], roles["total_role_edges"]) == (9001, 9003, 9004)


def test_older_analysis_version_is_ignored_and_backfill_replaces_it(environment, capsys):
    factory, graph = environment
    with factory() as db:
        store_analysis(db, "tenant-a", "revision-a", compute_analysis(GraphSnapshot()))
        db.flush()
        db.get(RevisionAnalysis, ("tenant-a", "revision-a")).analysis_version = ANALYSIS_VERSION - 1
        db.commit()
    with client_for() as client:
        assert client.get("/api/v1/overview").json()["ai_agents"] == 2  # Computed on read.
    assert backfill("tenant-a") == {
        "tenant": "tenant-a",
        "revision": "revision-a",
        "backfilled": True,
        "findings": 3,
    }
    assert backfill("tenant-a")["backfilled"] is False
    with factory() as db:
        assert stored_analysis(db, "tenant-a", "revision-a").overview == reference_overview(demo_snapshot())
    with patch.object(graph, "snapshot", side_effect=AssertionError("full snapshot load")):
        with client_for() as client:
            assert client.get("/api/v1/overview").json()["ai_agents"] == 2
            assert len(client.get("/api/v1/findings").json()) == 3
    with pytest.raises(ValueError, match="no published revision"):
        backfill("missing")
    with patch("sys.argv", ["analysis", "--tenant", "tenant-a"]):
        analysis.main()
    assert json.loads(capsys.readouterr().out)["backfilled"] is False
    with patch("sys.argv", ["analysis", "--tenant", "missing"]), pytest.raises(SystemExit):
        analysis.main()


def test_preview_and_audit_normalize_use_single_node_lookup(client, environment):
    _, graph = environment
    now = datetime.now(UTC)
    usage = {
        "window_start": (now - timedelta(days=100)).isoformat(),
        "window_end": (now - timedelta(days=1)).isoformat(),
        "used_actions": ["s3:GetObject"],
        "covered_services": ["s3"],
        "complete": True,
        "source": "cloudtrail",
    }
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}],
    }
    trail = {
        "events": [],
        "window_start": usage["window_start"],
        "window_end": usage["window_end"],
        "covered_services": ["s3"],
    }
    with patch.object(graph, "snapshot", side_effect=AssertionError("full snapshot load")):
        for identity, status in (("role:admin", 200), ("db:customers", 404), ("missing", 404)):
            preview = client.post(
                "/api/v1/remediations/preview",
                json={"identity_id": identity, "policy": policy, "usage": usage},
            )
            assert preview.status_code == status
            normalized = client.post("/api/v1/audit/normalize", json={"identity_id": identity, **trail})
            assert normalized.status_code == status
    with client_for("tenant-b") as other:
        response = other.post(
            "/api/v1/remediations/preview",
            json={"identity_id": "role:admin", "policy": policy, "usage": usage},
        )
        assert response.status_code == 404


def test_memory_node_lookup_is_scoped_and_isolated(environment):
    _, graph = environment
    node = graph.node("tenant-a", "revision-a", "role:admin")
    assert node is not None and node.type == NodeType.ROLE
    node.name = "mutated"
    assert graph.node("tenant-a", "revision-a", "role:admin").name != "mutated"
    assert graph.node("tenant-b", "revision-a", "role:admin") is None
    assert graph.node("tenant-a", "other", "role:admin") is None
    assert graph.node("tenant-a", "", "role:admin") is None


def test_cypher_node_lookup_is_one_keyed_bounded_query():
    store = CypherGraphStore.__new__(CypherGraphStore)
    store.timeout = 15
    calls = []
    payload = Node(id="role:a", name="A", type=NodeType.ROLE).model_dump_json()

    class Tx:
        def run(self, query, **params):
            calls.append((query, params))
            result = MagicMock()
            result.single.return_value = {"payload": payload} if params["id"] == "role:a" else None
            return result

    session = MagicMock()
    session.__enter__.return_value = session

    def read(function):
        assert function.timeout == 15
        return function(Tx())

    session.execute_read.side_effect = read
    store.driver = MagicMock()
    store.driver.session.return_value = session
    assert store.node("tenant", "revision", "role:a").id == "role:a"
    assert store.node("tenant", "revision", "missing") is None
    query, params = calls[0]
    assert "key:$key" in query and "tenant_id:$tenant" in query and "revision:$revision" in query
    assert "LIMIT 1" in query and "role:a" not in query
    assert params["key"] == json.dumps(["tenant", "revision", "role:a"])
    assert store.node("tenant", "", "role:a") is None
    assert store.node("tenant", "revision", "x" * 513) is None
    assert len(calls) == 2


class CountingTx:
    def __init__(self):
        self.queries = []

    def run(self, query, **params):
        self.queries.append(query)
        result = MagicMock()
        if "Snapshot" in query:
            result.single.return_value = {"warnings": []}
        elif "count(" in query and "DISTINCT" not in query:
            result.single.return_value = {"count": 1}
        else:
            result.__iter__.return_value = iter([])
        return result


def test_cypher_explore_and_roles_skip_count_scans_with_stored_totals():
    from app.graph.exploration import cypher_explore
    from app.graph.role_map import cypher_roles

    totals = RevisionTotals(10, 20, 3, 4)
    tx = CountingTx()
    sliced = cypher_explore(tx, "tenant", "revision", None, 5, 5, totals)
    assert (sliced.total_nodes, sliced.total_edges) == (10, 20)
    assert not any("count(" in query for query in tx.queries)
    tx = CountingTx()
    roles = cypher_roles(tx, "tenant", "revision", 5, 5, None, totals)
    assert (roles.total_nodes, roles.total_edges, roles.total_roles, roles.total_role_edges) == (10, 20, 3, 4)
    assert not any("count(" in query for query in tx.queries)
    tx = CountingTx()
    cypher_roles(tx, "tenant", "revision", 5, 5, None)
    assert sum("count(" in query for query in tx.queries) == 4
