"""Relationship topics and structural privilege analysis: seeding, propagation, profiles,
flags, determinism, planted accuracy, storage, API semantics, isolation and backfill."""

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.collectors.tasks import process_job
from app.core.auth import Actor, current_actor
from app.db.models import (
    IngestionJob,
    RevisionTopic,
    RevisionTopicLink,
    RevisionTopicMember,
    RevisionTopicSummary,
    TenantState,
)
from app.graph import topics
from app.graph.compact import CompactGraph
from app.graph.demo import demo_snapshot
from app.graph.schema import Edge, EdgeType, GraphSnapshot, Node, NodeType
from app.graph.topics import (
    NOTICE,
    TOPIC_VERSION,
    backfill,
    backfill_missing,
    compute_topics,
    delete_topics,
    member_rows,
    missing_topics,
    normalize,
    store_topics,
    stored_topic_summary,
    tag_topic,
    topic_id,
)
from app.main import create_app

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from qualify_scale import generate, generate_topics  # noqa: E402


def client_for(tenant="tenant-a", roles=("viewer",)):
    app = create_app()
    app.dependency_overrides[current_actor] = lambda: Actor("reader", tenant, frozenset(roles))
    return TestClient(app)


def node(node_id, kind, name=None, **extra):
    return Node(id=node_id, type=kind, name=name or node_id, **extra)


def grant(source, target, kind=EdgeType.READ, actions=("s3:GetObject",)):
    return Edge(source=source, target=target, type=kind, actions=list(actions))


def assume(source, target):
    return Edge(source=source, target=target, type=EdgeType.ASSUMES, actions=["sts:AssumeRole"])


def small_graph() -> GraphSnapshot:
    """Two tagged topics (lake, payments), name-token and co-access members, a hub, a fallback."""
    nodes, edges = [], []
    for i in range(6):  # Tagged lake buckets: the name token "lake" becomes specific to data-lake.
        nodes.append(
            node(f"lake:{i}", NodeType.BUCKET, f"lake-raw-{i}", tags=["topic=Data Lake", "env=prod"])
        )
    for i in range(6):
        nodes.append(
            node(
                f"pay:{i}",
                NodeType.DATABASE,
                f"payments-ledger-{i}",
                tags=["app:payments-db"],
                sensitivity="restricted",
            )
        )
    nodes.append(node("lake:named", NodeType.BUCKET, "lake-curated-x"))  # by name token
    nodes.append(node("pay:meta", NodeType.DATABASE, "db-77", metadata={"team": "payments-db"}))
    nodes.append(node("orphan:shared", NodeType.BUCKET, "bucket-3f9a"))  # by co-access
    nodes.append(node("orphan:none", NodeType.VECTOR, "index-1", tags=["PII"]))  # fallback
    nodes.append(node("classification:PII", NodeType.CATEGORY, "PII", provider="classification"))
    edges.append(
        Edge(source="orphan:none", target="classification:PII", type=EdgeType.PII, certainty="declared")
    )
    nodes += [
        node("role:lake", NodeType.ROLE, "lake-reader"),
        node("role:pay", NodeType.ROLE, "payments-writer"),
        node("role:admin", NodeType.ROLE, "admin", privileged=True),
        node("role:wild", NodeType.ROLE, "wild"),
        node("role:empty", NodeType.ROLE, "no-grants"),
        node("svc:lake", NodeType.SERVICE),
        node("svc:both", NodeType.SERVICE),
        node("svc:admin", NodeType.SERVICE),
        node("agent:wild", NodeType.AGENT),
    ]
    for i in range(6):
        edges.append(grant("role:lake", f"lake:{i}"))
        edges.append(grant("role:pay", f"pay:{i}", EdgeType.WRITE, ("rds-data:BatchExecuteStatement",)))
    edges += [
        grant("role:lake", "orphan:shared"),
        grant("role:lake", "pay:0"),  # cross-topic, to restricted data
        grant("role:admin", "lake:0"),
        grant("role:wild", "lake:1", EdgeType.WRITE, ("s3:*",)),
        assume("svc:lake", "role:lake"),
        assume("svc:both", "role:lake"),
        assume("svc:both", "role:pay"),
        assume("svc:admin", "role:admin"),
        assume("agent:wild", "role:wild"),
    ]
    return GraphSnapshot(nodes=nodes, edges=edges)


def by_id(computed, entity):
    return computed.graph.index[entity]


def topic_name(computed, row):
    return computed.topics[row["topic"]].name if row["topic"] >= 0 else None


def test_tag_parsing_priority_and_normalization():
    assert normalize("  Data Lake / Raw ") == "data-lake-raw"
    assert normalize("___") == ""
    assert tag_topic(("env=prod", "team=Platform", "app=Checkout API")) == (
        "checkout-api",
        "app=Checkout API",
    )
    assert tag_topic(("Topic:Payments",)) == ("payments", "topic=Payments")
    assert tag_topic(("project=x", "workload=y")) == ("x", "project=x")
    assert tag_topic(("PII", "owner=alice", "topic=")) is None
    assert topic_id("anchored", "crm") == topic_id("anchored", "crm") != topic_id("fallback", "crm")
    assert topic_id("anchored", "crm").startswith("t") and len(topic_id("anchored", "crm")) == 16


def test_compact_graph_carries_tags_hints_edge_types_and_interned_actions():
    graph = CompactGraph.from_snapshot(small_graph())
    lake = graph.index["lake:0"]
    assert graph.tags[lake] == ("topic=Data Lake", "env=prod")
    assert graph.tags[graph.index["lake:1"]] is graph.tags[lake]  # Interned.
    assert graph.hints[graph.index["pay:meta"]] == ("team=payments-db",)
    assert graph.provider[lake] == "custom"
    kinds = {graph.edge_kind[e] for e in range(graph.edge_count)}
    assert {0, 3, 4} <= kinds  # ASSUMES_ROLE, CAN_READ, CAN_WRITE codes.
    reads = [
        graph.edge_actions[e] for e in range(graph.edge_count) if graph.edge_actions[e] == ("s3:GetObject",)
    ]
    assert len(reads) > 2 and all(a is reads[0] for a in reads)


def test_seeding_name_tokens_coaccess_fallback_and_reasons():
    computed = compute_topics(CompactGraph.from_snapshot(small_graph()))
    names = {t.name: t for t in computed.topics}
    assert {"data-lake", "payments-db"} <= set(names)
    seeds = {computed.graph.ids[item]: seed for item, seed in computed.resource_seed.items()}
    resource = {
        entity: computed.topics[computed.resource_topic[by_id(computed, entity)]].name
        for entity in computed.graph.ids
        if computed.resource_topic[by_id(computed, entity)] >= 0
    }
    assert resource["lake:0"] == "data-lake" and seeds["lake:0"] == ("tag", "tag topic=Data Lake")
    assert resource["pay:0"] == "payments-db" and seeds["pay:0"][1] == "tag app=payments-db"
    assert resource["pay:meta"] == "payments-db" and seeds["pay:meta"] == (
        "metadata",
        "metadata team=payments-db",
    )
    assert resource["lake:named"] == "data-lake" and seeds["lake:named"][0] == "name"
    assert '"lake"' in seeds["lake:named"][1]
    assert resource["orphan:shared"] == "data-lake" and seeds["orphan:shared"][0] == "coaccess"
    assert "1 of 1 granted roles" in seeds["orphan:shared"][1]
    fallback = computed.topics[computed.resource_topic[by_id(computed, "orphan:none")]]
    assert fallback.kind == "fallback" and fallback.label == "Unassigned vector stores (PII)"
    assert seeds["orphan:none"][0] == "fallback" and "category PII" in seeds["orphan:none"][1]
    # Category nodes are never topic members.
    assert computed.resource_topic[by_id(computed, "classification:PII")] == -1


def test_profiles_primary_topics_and_flags():
    computed = compute_topics(CompactGraph.from_snapshot(small_graph()))
    roles = {computed.graph.ids[i]: row for i, row in computed.roles.items()}
    identities = {computed.graph.ids[i]: row for i, row in computed.identities.items()}
    lake = roles["role:lake"]
    assert topic_name(computed, lake) == "data-lake" and lake["direct"] == 8
    # One cross-topic grant, onto restricted payments data.
    assert lake["cross"] == 1 and lake["cross_weight"] == 10 and lake["restricted_outside"] == 1
    assert lake["flags"] == topics.CROSS_TOPIC | topics.RESTRICTED_OUTSIDE
    shares = {computed.topics[t].name: w for t, w, _, _ in lake["profile"]}
    assert shares["payments-db"] == 10 and sum(shares.values()) == lake["reach_weight"]
    assert topic_name(computed, roles["role:pay"]) == "payments-db" and roles["role:pay"]["flags"] == 0
    assert roles["role:admin"]["flags"] & topics.PRIVILEGED  # Marked privileged.
    assert roles["role:wild"]["flags"] & topics.PRIVILEGED  # Wildcard action s3:*.
    assert roles["role:empty"]["topic"] == -1 and roles["role:empty"]["reach"] == 0
    both = identities["svc:both"]
    # Reach is the union of its roles' grants; two roles with different primary topics.
    assert both["reach"] == len({*range(6), "x"}) + 1 + 6 - 1  # lake 0-5, orphan:shared, pay 0-5
    assert both["flags"] & topics.CROSS_TOPIC and both["roles"] == 2
    assert not identities["svc:lake"]["flags"] & topics.CROSS_TOPIC
    assert identities["svc:admin"]["flags"] & topics.PRIVILEGED
    assert identities["agent:wild"]["flags"] & topics.PRIVILEGED


def test_hub_roles_are_flagged_excluded_from_propagation_and_decomposed(monkeypatch):
    monkeypatch.setattr(topics, "HUB_MIN_RESOURCES", 10)
    monkeypatch.setattr(topics, "HUB_SHARE", 0.0)
    snapshot = small_graph()
    hub = node("role:hub", NodeType.ROLE, "org-admin")
    edges = [
        grant("role:hub", n.id, EdgeType.WRITE, ("*",)) for n in snapshot.nodes if n.type != NodeType.ROLE
    ]
    edges = [e for e in edges if e.target.startswith(("lake:", "pay:", "orphan:"))]
    snapshot = GraphSnapshot(
        nodes=[*snapshot.nodes, hub, node("svc:hubbed", NodeType.SERVICE)],
        edges=[*snapshot.edges, *edges, assume("svc:hubbed", "role:hub"), assume("svc:hubbed", "role:pay")],
    )
    computed = compute_topics(CompactGraph.from_snapshot(snapshot))
    roles = {computed.graph.ids[i]: row for i, row in computed.roles.items()}
    identities = {computed.graph.ids[i]: row for i, row in computed.identities.items()}
    assert roles["role:hub"]["flags"] & topics.HUB and roles["role:hub"]["flags"] & topics.PRIVILEGED
    hubbed = identities["svc:hubbed"]
    assert hubbed["flags"] & topics.VIA_HUB
    assert hubbed["reach_weight"] > hubbed["reach_weight_excl_hubs"] == 6 * 10
    assert topic_name(computed, hubbed) == "payments-db"
    assert computed.summary["hub_roles"] >= 1 and computed.summary["via_hub_identities"] >= 1
    hub_topic = roles["role:hub"]["topic"]
    assert computed.topic_stats[hub_topic]["hub_roles"] >= 1
    assert sum(s["hub_grants_in"] for s in computed.topic_stats) >= len(edges)


def test_topics_are_deterministic_and_row_identical():
    snapshot, _, _ = generate_topics(4000, seed=3)
    first = compute_topics(CompactGraph.from_snapshot(snapshot))
    second = compute_topics(CompactGraph.from_snapshot(snapshot))
    assert list(member_rows(first, "t", "r")) == list(member_rows(second, "t", "r"))
    assert first.links == second.links and first.topic_stats == second.topic_stats
    assert {k: v for k, v in first.summary.items()} == second.summary


def test_planted_fixture_recovers_topics():
    """Smaller planted graph: the 100k acceptance numbers are measured by qualify_topics.py."""
    snapshot, truth, usage = generate_topics(20000, seed=11)
    assert usage["window_days"] == 90 and truth["over_grants"]  # Sidecars exist, never read here.
    computed = compute_topics(CompactGraph.from_snapshot(snapshot))
    index = computed.graph.index
    resources = truth["resource_topic"]
    groups: dict[str, dict[str, int]] = {}
    for entity, planted in resources.items():
        predicted = computed.topics[computed.resource_topic[index[entity]]].name
        groups.setdefault(predicted, {}).setdefault(planted, 0)
        groups[predicted][planted] += 1
    purity = sum(max(g.values()) for g in groups.values()) / len(resources)
    roles = truth["role_topic"]
    correct = sum(topic_name(computed, computed.roles[index[r]]) == t for r, t in roles.items())
    assert purity >= 0.9 and correct / len(roles) >= 0.94
    assert computed.summary["hub_roles"] == 3
    assert computed.summary["anchored_topics"] == 12


def test_existing_fixture_without_tags_falls_back_to_type_groups():
    computed = compute_topics(CompactGraph.from_snapshot(generate(2000)))
    assert {t.kind for t in computed.topics} == {"fallback"}
    assert computed.summary["seeded_resources"]["fallback"] == computed.summary["resources"]


# ---------------------------------------------------------------------------
# Publication, storage and API


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


def test_publish_stores_topics_and_endpoints_page_members(client, environment):
    factory, graph = environment
    publish(client, small_graph())
    revision = current(factory)
    with factory() as db:
        summary = stored_topic_summary(db, "tenant-a", revision)
        assert summary is not None and summary.totals["basis"] == "granted (structural)"
        members = db.scalar(
            select(func.count()).where(
                RevisionTopicMember.tenant_id == "tenant-a", RevisionTopicMember.revision == revision
            )
        )
        # Every data asset, role and principal (category nodes excluded).
        assert members == len(small_graph().nodes) - 1
    with patch.object(graph, "snapshot", side_effect=AssertionError("full snapshot load")):
        body = client.get("/api/v1/graph/topics").json()
    assert body["revision"] == revision and body["view"]["notice"] == NOTICE
    assert body["view"]["basis"] == "granted (structural)" and not body["view"]["truncated"]
    listed = {t["name"]: t for t in body["topics"]}
    assert list(listed)[:2] == ["payments-db", "data-lake"]  # Anchored first, by resource weight.
    lake = listed["data-lake"]
    # role:lake, plus the privileged and wildcard roles granted on lake buckets.
    assert lake["resources"] == 8 and lake["roles"] == 3 and lake["cross_grants_out"] == 1
    assert (
        lake["reason"].startswith("Tagged topic=Data Lake on 6 assets") and "1 more by name" in lake["reason"]
    )
    assert lake["seeds"]["coaccess"] == 1 and lake["overprivileged_share"] > 0
    assert listed["payments-db"]["cross_grants_in"] == 1
    assert body["edges"] == [
        {
            "source": min(lake["id"], listed["payments-db"]["id"]),
            "target": max(lake["id"], listed["payments-db"]["id"]),
            "weight": 1,
        }
    ]
    detail = client.get(f"/api/v1/graph/topics/{lake['id']}", params={"kind": "role"}).json()
    assert [m["id"] for m in detail["members"]] == ["role:lake", "role:admin", "role:wild"]
    member = detail["members"][0]
    assert member["flags"] == ["cross_topic", "restricted_outside"] and member["cross_topic_grants"] == 1
    assert {p["topic_id"] for p in member["profile"]} == {lake["id"], listed["payments-db"]["id"]}
    assert [m["id"] for m in detail["top_roles"]] == ["role:lake", "role:admin", "role:wild"]
    assert detail["view"]["notice"] == NOTICE
    # Resources: highest sensitivity first; paging is explicit.
    first = client.get(f"/api/v1/graph/topics/{lake['id']}", params={"limit": 3}).json()
    assert first["view"] == {
        "kind": "resource",
        "total": 8,
        "offset": 0,
        "limit": 3,
        "shown": 3,
        "next_offset": 3,
        "truncated": True,
        "basis": "granted (structural)",
        "notice": NOTICE,
    }
    pages, offset = [], 0
    while offset is not None:
        page = client.get(f"/api/v1/graph/topics/{lake['id']}", params={"limit": 3, "offset": offset}).json()
        pages += page["members"]
        offset = page["view"]["next_offset"]
    assert len({m["id"] for m in pages}) == 8 and all(m["kind"] == "resource" for m in pages)
    identities = client.get(f"/api/v1/graph/topics/{lake['id']}", params={"kind": "identity"}).json()
    assert {m["id"] for m in identities["members"]} >= {"svc:lake"}


def test_topic_api_semantics_409_404_503_422_and_auth(client, environment):
    factory, graph = environment
    response = client.get("/api/v1/graph/topics")  # Published before topics existed.
    assert response.status_code == 404 and response.headers["retry-after"] == "60"
    publish(client, small_graph())
    revision = current(factory)
    body = client.get("/api/v1/graph/topics", params={"revision": revision}).json()
    some = body["topics"][0]["id"]
    assert client.get("/api/v1/graph/topics", params={"revision": "stale"}).status_code == 409
    assert client.get(f"/api/v1/graph/topics/{some}", params={"revision": "stale"}).status_code == 409
    assert client.get("/api/v1/graph/topics/t" + "f" * 15).status_code == 404
    for bad in ("x" * 33, "c0123456789abcde", "t;DROP"):
        assert client.get(f"/api/v1/graph/topics/{bad}").status_code in {404, 422}
    for params in ({"edge_limit": 0}, {"edge_limit": 2001}):
        assert client.get("/api/v1/graph/topics", params=params).status_code == 422
    for params in ({"limit": 0}, {"limit": 501}, {"offset": -1}, {"kind": "other"}):
        assert client.get(f"/api/v1/graph/topics/{some}", params=params).status_code == 422
    published = graph.snapshots.pop(("tenant-a", revision))
    for path in ("/api/v1/graph/topics", f"/api/v1/graph/topics/{some}"):
        response = client.get(path)
        assert response.status_code == 503 and response.headers["retry-after"] == "5"
    graph.snapshots[("tenant-a", revision)] = published
    with TestClient(create_app()) as anonymous:
        assert anonymous.get("/api/v1/graph/topics").status_code == 401
        assert anonymous.get(f"/api/v1/graph/topics/{some}").status_code == 401


def test_topic_rows_are_tenant_and_revision_isolated(client, environment):
    factory, graph = environment
    publish(client, small_graph())
    first = current(factory)
    first_ids = {t["id"] for t in client.get("/api/v1/graph/topics").json()["topics"]}
    publish(client, demo_snapshot())
    second = current(factory)
    with client_for("tenant-b") as other:
        assert other.get("/api/v1/graph/topics").status_code == 404
        for topic in first_ids:
            assert other.get(f"/api/v1/graph/topics/{topic}").status_code == 404
    with factory() as db:
        db.add(TenantState(tenant_id="tenant-b", revision=second))
        db.commit()
    graph.snapshots[("tenant-b", second)] = GraphSnapshot()
    with client_for("tenant-b") as other:
        assert other.get("/api/v1/graph/topics").status_code == 404
    current_ids = {t["id"] for t in client.get("/api/v1/graph/topics").json()["topics"]}
    for topic in first_ids - current_ids:
        assert client.get(f"/api/v1/graph/topics/{topic}").status_code == 404
    with factory() as db:
        delete_topics(db, "tenant-a", first)
        db.commit()
        for model in (RevisionTopicSummary, RevisionTopic, RevisionTopicLink, RevisionTopicMember):
            scopes = {(r.tenant_id, r.revision) for r in db.scalars(select(model))}
            assert ("tenant-a", first) not in scopes
            assert ("tenant-a", second) in scopes or model is RevisionTopicLink


def test_failed_topic_analysis_publishes_nothing(client, environment):
    factory, _ = environment
    with patch("app.api.routes.ingest.delay"):
        job = client.post(
            "/api/v1/ingestions",
            json={"source": "snapshot", "payload": demo_snapshot().model_dump(mode="json")},
        ).json()
    with patch("app.collectors.tasks.compute_topics", side_effect=RuntimeError("topic bug")):
        with pytest.raises(RuntimeError):
            process_job(job["id"])
    with factory() as db:
        assert db.get(TenantState, "tenant-a").revision == "revision-a"
        assert db.get(IngestionJob, job["id"]).status == "retrying"
        assert db.scalar(select(func.count()).select_from(RevisionTopicSummary)) == 0


def test_backfill_cli_and_older_version_reads_as_missing(environment, capsys):
    factory, _ = environment
    assert backfill("tenant-a")["backfilled"] is True
    assert backfill("tenant-a")["backfilled"] is False
    with client_for() as reader:
        assert reader.get("/api/v1/graph/topics").status_code == 200
    with factory() as db:
        db.get(RevisionTopicSummary, ("tenant-a", "revision-a")).topic_version = TOPIC_VERSION - 1
        db.commit()
        assert stored_topic_summary(db, "tenant-a", "revision-a") is None
    with client_for() as reader:
        assert reader.get("/api/v1/graph/topics").status_code == 404
    with patch.object(sys, "argv", ["topics", "--tenant", "tenant-a"]):
        topics.main()
    assert json.loads(capsys.readouterr().out)["backfilled"] is True
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(RevisionTopicSummary)) == 1
    with pytest.raises(ValueError):
        backfill("tenant-missing")


def test_worker_sweep_backfills_current_revisions_skips_busy_and_backs_off(environment, monkeypatch):
    factory, graph = environment
    graph.publish("tenant-b", "b-old", demo_snapshot())
    graph.publish("tenant-b", "b-new", small_graph())
    with factory() as db:
        db.add_all([TenantState(tenant_id="tenant-b", revision="b-new"), TenantState(tenant_id="tenant-c")])
        db.commit()
        assert missing_topics(db, 10) == [("tenant-a", "revision-a"), ("tenant-b", "b-new")]
    monkeypatch.setattr(topics, "_failed", {})
    monkeypatch.setattr(topics, "try_publication_lock", lambda db, tenant: False)
    assert backfill_missing(limit=1) == [{"tenant": "tenant-a", "backfilled": False, "busy": True}]
    monkeypatch.undo()
    monkeypatch.setattr(topics, "_failed", {})
    with patch.object(topics, "compute_topics", side_effect=RuntimeError("topic bug")):
        assert all(result["failed"] for result in backfill_missing())
        assert backfill_missing() == []  # Backed off.
    monkeypatch.setattr(topics, "_failed", {})
    from app.collectors.tasks import backfill_topics

    assert backfill_topics() == 2
    with factory() as db:
        assert missing_topics(db, 10) == []
        assert stored_topic_summary(db, "tenant-b", "b-old") is None  # Only current revisions.
        assert stored_topic_summary(db, "tenant-b", "b-new").total_topics >= 3


def test_store_topics_round_trips_through_sql(environment):
    factory, _ = environment
    computed = compute_topics(CompactGraph.from_snapshot(small_graph()))
    with factory() as db:
        store_topics(db, "tenant-z", "rev-x", computed)
        db.commit()
        rows = db.scalars(select(RevisionTopicMember).where(RevisionTopicMember.kind == "role")).all()
        assert all(isinstance(row.profile, list) for row in rows)
        stored = [
            tuple(getattr(row, c) for c in topics.MEMBER_COLUMNS)
            for row in db.scalars(select(RevisionTopicMember).order_by(RevisionTopicMember.entity_id))
        ]
        expected = sorted(member_rows(computed, "tenant-z", "rev-x"), key=lambda row: row[2])
        assert stored == [tuple(row) for row in expected]
        topic_rows = db.scalars(select(RevisionTopic).order_by(RevisionTopic.ordinal)).all()
        assert [row.ordinal for row in topic_rows] == list(range(len(computed.topics)))
        assert all(isinstance(row.stats, dict) for row in topic_rows)
