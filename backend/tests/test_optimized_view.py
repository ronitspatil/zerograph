"""Current vs optimized views: the slice overlay against the proposals' own changes and the
what-if model, totals against /proposals/metrics, topic link removals against a brute-force
count, the topic subgraph's bounds, the overview tiles, bulk decisions and their guards."""

import random
import sys
from collections import Counter
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import func, select

from app.collectors.tasks import process_job
from app.core.auth import Actor, current_actor
from app.db.models import AuditEvent, RevisionTopicLink, RevisionTopicMember, RolloutChange, TenantState
from app.graph import optimized
from app.graph import proposals as P

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from proposal_reference import changes_of, structure  # noqa: E402
from qualify_scale import generate_topics  # noqa: E402


def publish(client, snapshot):
    with patch("app.api.routes.ingest.delay"):
        job = client.post(
            "/api/v1/ingestions", json={"source": "snapshot", "payload": snapshot.model_dump(mode="json")}
        ).json()
    process_job(job["id"])


def every(client, **params) -> list[dict]:
    rows, cursor = [], None
    while True:
        query = {**params, "limit": 200, **({"cursor": cursor} if cursor is not None else {})}
        page = client.get("/api/v1/proposals", params=query).json()
        rows += page["proposals"]
        cursor = page["view"]["next_cursor"]
        if cursor is None:
            return rows


@pytest.fixture
def optimized_tenant(client, environment):
    from test_privilege import upload_usage

    from app.graph.topics import backfill_missing

    factory, _ = environment
    snapshot, _, usage = generate_topics(2000, seed=11)
    publish(client, snapshot)
    upload_usage(client, snapshot, usage)
    backfill_missing()
    with factory() as db:
        revision = db.get(TenantState, "tenant-a").revision
    return snapshot, revision


def test_overlay_matches_the_proposals_changes_and_metrics(client, environment, optimized_tenant):
    snapshot, revision = optimized_tenant
    factory, _ = environment
    _, direct, hops = structure(snapshot)
    high = every(client, tier="high")
    assert high
    removed, cut, disabled = changes_of(high)
    ids = sorted(node.id for node in snapshot.nodes)
    rng = random.Random(5)
    # Slices: the endpoints of some removals (dense) and a random sample of entities.
    dense = sorted({entity for pair in sorted(removed)[:200] for entity in pair})[:500]
    for shown in (dense, rng.sample(ids, 500)):
        body = client.post(
            "/api/v1/proposals/overlay", json={"tier": "high", "node_ids": shown, "revision": revision}
        ).json()
        inside = set(shown)
        expected_grants = {pair for pair in removed if set(pair) <= inside}
        got_grants = {(e["source"], e["target"]) for e in body["removed_edges"] if e["kind"] == "grant"}
        got_hops = {(e["source"], e["target"]) for e in body["removed_edges"] if e["kind"] == "hop"}
        assert got_grants == expected_grants
        assert got_hops == {pair for pair in cut if set(pair) <= inside}
        assert set(body["disabled_nodes"]) == disabled & inside
        # Every removed grant is a real grant edge of the revision; hops are real hops.
        assert all(target in direct[source] for source, target in got_grants)
        assert all(target in hops[source] for source, target in got_hops)
        assert body["slice"]["grants_removed"] == len(got_grants)
        assert body["selected"] == len(high)
    assert dense and got_grants is not None
    metrics = client.post("/api/v1/proposals/metrics", json={"tier": "high"}).json()
    for key in ("grants_removed", "restricted_grants_removed", "hops_cut", "disabled_nodes"):
        assert body["totals"][key] == metrics["counts"][key]
    # Against the model directly: the slice is exactly the selection's pairs inside it.
    with factory() as db:
        model = P.load_model(db, "tenant-a", revision)
        ordinals = P.selected_ordinals(db, "tenant-a", revision, None, "high", None, model)
    chosen = model.selection(ordinals)
    pairs = {
        (model.ids[h], model.ids[i])
        for h, items in chosen.removed.items()
        for i in items & model.direct.get(h, frozenset())
    }
    assert pairs == removed
    found = optimized.slice_overlay(model, chosen, dense)
    assert set(found.removed) == {pair for pair in pairs if set(pair) <= set(dense)}

    # Explicit IDs and the accepted set use the same selection rules as the metrics.
    some = [p["id"] for p in high[:7]]
    explicit = client.post("/api/v1/proposals/overlay", json={"proposal_ids": some, "node_ids": dense}).json()
    assert explicit["selected"] == 7
    assert {(e["source"], e["target"]) for e in explicit["removed_edges"]} <= {
        (e["source"], e["target"]) for e in client.post(
            "/api/v1/proposals/overlay", json={"tier": "high", "node_ids": dense}
        ).json()["removed_edges"]
    }  # fmt: skip
    none = client.post("/api/v1/proposals/overlay", json={"decision": "accepted", "node_ids": dense}).json()
    assert none["selected"] == 0 and none["removed_edges"] == [] and none["totals"]["grants_removed"] == 0

    # Bounds, unknown proposals, revision pinning, viewers.
    assert client.post("/api/v1/proposals/overlay", json={"tier": "high", "node_ids": []}).status_code == 422
    too_many = [f"x{i}" for i in range(501)]
    assert (
        client.post("/api/v1/proposals/overlay", json={"tier": "high", "node_ids": too_many}).status_code
        == 422
    )
    unknown = client.post(
        "/api/v1/proposals/overlay", json={"proposal_ids": ["p" + "3" * 19], "node_ids": ["a"]}
    )
    assert unknown.status_code == 404
    stale = client.post(
        "/api/v1/proposals/overlay", json={"tier": "high", "node_ids": ["a"], "revision": "old"}
    )
    assert stale.status_code == 409
    client.app.dependency_overrides[current_actor] = lambda: Actor("v", "tenant-a", frozenset({"viewer"}))
    assert (
        client.post("/api/v1/proposals/overlay", json={"tier": "high", "node_ids": dense}).status_code == 200
    )


def test_topic_links_match_the_map_and_a_brute_force_count(client, environment, optimized_tenant):
    snapshot, revision = optimized_tenant
    factory, _ = environment
    with factory() as db:
        model = P.load_model(db, "tenant-a", revision)
        assets = optimized.resource_topics(db, "tenant-a", revision, model)
        stored = {
            (row.source_id, row.target_id): row.weight
            for row in db.scalars(select(RevisionTopicLink).where(RevisionTopicLink.revision == revision))
        }
        topic_of = dict(
            db.execute(
                select(RevisionTopicMember.entity_id, RevisionTopicMember.topic_id).where(
                    RevisionTopicMember.revision == revision
                )
            ).all()
        )
    topics = model.topics
    before = {
        tuple(sorted((topics[a][0], topics[b][0]))): value
        for (a, b), value in optimized.topic_links(model, assets).items()
    }
    assert before == stored and stored

    body = client.post("/api/v1/proposals/links", json={"tier": "high", "revision": revision}).json()
    high = every(client, tier="high")
    removed, _, disabled = changes_of(high)
    _, direct, _ = structure(snapshot)
    hubs = {model.ids[h] for h in model.hubs}
    expected: Counter = Counter()

    def count(holder, items):
        own = topic_of.get(holder, "")
        if holder in hubs or not own:
            return
        for item in items:
            if topic_of.get(item, "") and topic_of[item] != own:
                expected[tuple(sorted((own, topic_of[item])))] += 1

    for holder in disabled:
        count(holder, direct.get(holder, ()))
    for holder, item in removed:
        if holder not in disabled:
            count(holder, [item])
    assert {(link["source"], link["target"]): link["removed"] for link in body["links"]} == dict(expected)
    assert all(link["removed"] <= stored.get((link["source"], link["target"]), 0) for link in body["links"])
    metrics = client.post("/api/v1/proposals/metrics", json={"tier": "high"}).json()
    assert body["topics"] == metrics["topics"] and body["graph"] == metrics["graph"]
    assert body["counts"] == metrics["counts"]


def test_topic_subgraph_is_bounded_and_grouped(client, environment, optimized_tenant):
    _, revision = optimized_tenant
    summary = client.get("/api/v1/proposals/summary").json()
    topic = max(summary["topics"], key=lambda t: summary["topics"][t]["by_tier"]["high"])
    body = client.get(f"/api/v1/graph/topics/{topic}/subgraph", params={"revision": revision}).json()
    assert body["topic_id"] == topic and len(body["nodes"]) <= 500 and len(body["edges"]) <= 2000
    ids = {node["id"] for node in body["nodes"]}
    assert set(body["groups"]) == ids
    assert all(e["source"] in ids and e["target"] in ids for e in body["edges"])
    shown = Counter(body["groups"].values())
    assert (
        shown["role"] <= 40 and shown["identity"] <= 40 and shown["resource"] + shown["outside"] <= 80 + 120
    )
    assert body["view"]["shown"] == {
        kind: shown.get(kind, 0) for kind in ("role", "identity", "resource", "outside")
    }
    detail = client.get(f"/api/v1/graph/topics/{topic}", params={"kind": "resource", "limit": 500}).json()
    own = {m["id"] for m in detail["members"]}
    outside = [entity for entity, kind in body["groups"].items() if kind == "outside"]
    assert outside and not own & set(outside)
    # The topic's high-tier removals on its shown roles appear in the optimized slice.
    overlay = client.post(
        "/api/v1/proposals/overlay", json={"tier": "high", "node_ids": sorted(ids), "revision": revision}
    ).json()
    assert overlay["slice"]["grants_removed"] > 0
    edges = {(e["source"], e["target"]) for e in body["edges"]}
    assert all((e["source"], e["target"]) in edges for e in overlay["removed_edges"])
    small = client.get(
        f"/api/v1/graph/topics/{topic}/subgraph",
        params={"roles": 2, "identities": 0, "resources": 3, "outside": 0},
    ).json()
    assert (
        Counter(small["groups"].values()) <= Counter({"role": 2, "resource": 3})
        and small["view"]["truncated"]
    )
    assert client.get(f"/api/v1/graph/topics/{topic}/subgraph", params={"roles": 61}).status_code == 422
    assert client.get("/api/v1/graph/topics/t000000000000000/subgraph").status_code == 404
    assert client.get(f"/api/v1/graph/topics/{topic}/subgraph", params={"revision": "old"}).status_code == 409


def test_overview_tiles_and_bulk_decisions(client, environment, optimized_tenant):
    _, revision = optimized_tenant
    factory, _ = environment
    tiles = client.get("/api/v1/proposals/overview").json()
    summary = client.get("/api/v1/proposals/summary").json()
    assert tiles["after_high"]["identities"] == summary["high_tier"]["graph"]["identities"]["after"]
    assert tiles["now"] == {k: summary["high_tier"]["graph"][k]["before"] for k in ("roles", "identities")}
    assert tiles["after_accepted"] == tiles["now"] and tiles["accepted"]["selected"] == 0
    assert tiles["rollout"]["pr_open"] == 0 and tiles["rollout"]["canary_watching"] == 0
    privilege = client.get("/api/v1/overview").json()["excess_privilege"]
    assert tiles["dormant_identities"] == privilege["dormant_identities"]
    assert tiles["unused_restricted_grants"] == privilege["unused_restricted_grants"]

    high = every(client, tier="high")
    topic = Counter(p["topic_id"] for p in high).most_common(1)[0][0]
    group = [p["id"] for p in high if p["topic_id"] == topic]
    other = next(p for p in high if p["topic_id"] != topic)
    medium = next(p for p in every(client, tier="medium") if p["topic_id"] == topic)
    request = {
        "proposal_ids": group,
        "state": "accepted",
        "tier": "high",
        "topic_id": topic,
        "revision": revision,
    }
    # Guards: one tier and one topic; manual proposals one at a time; admins only.
    for ids in (group + [other["id"]], group + [medium["id"]]):
        assert (
            client.post("/api/v1/proposals/decisions", json={**request, "proposal_ids": ids}).status_code
            == 422
        )
    manual = client.post("/api/v1/proposals/decisions", json={**request, "tier": "manual"})
    assert manual.status_code == 422
    assert client.post("/api/v1/proposals/decisions", json={**request, "revision": "old"}).status_code == 409
    missing = client.post("/api/v1/proposals/decisions", json={**request, "proposal_ids": ["p" + "4" * 19]})
    assert missing.status_code == 404
    with factory() as db:
        assert (
            db.scalar(
                select(func.count()).select_from(AuditEvent).where(AuditEvent.action.like("proposal.%"))
            )
            == 0
        )
    done = client.post("/api/v1/proposals/decisions", json=request).json()
    assert done["decided"] == len(group) and done["decisions"]["accepted"] == len(group)
    with factory() as db:
        events = db.scalars(select(AuditEvent).where(AuditEvent.action == "proposal.accepted")).all()
        assert len(events) == len(group) and all(e.detail["bulk"]["topic_id"] == topic for e in events)
    tiles = client.get("/api/v1/proposals/overview").json()
    metrics = client.post("/api/v1/proposals/metrics", json={"decision": "accepted"}).json()
    assert tiles["accepted"]["selected"] == len(group)
    assert tiles["after_accepted"]["identities"] == metrics["graph"]["identities"]["after"]
    assert tiles["accepted"]["counts"] == metrics["counts"]
    assert tiles["decisions"]["accepted"] == len(group)
    # The accepted overlay is the accepted proposals' changes.
    removed, _, _ = changes_of([p for p in high if p["topic_id"] == topic])
    shown = sorted({entity for pair in sorted(removed)[:150] for entity in pair})[:500]
    overlay = client.post(
        "/api/v1/proposals/overlay", json={"decision": "accepted", "node_ids": shown}
    ).json()
    assert {(e["source"], e["target"]) for e in overlay["removed_edges"]} == {
        pair for pair in removed if set(pair) <= set(shown)
    }
    cleared = client.post("/api/v1/proposals/decisions", json={**request, "state": "pending"}).json()
    assert cleared["decisions"]["accepted"] == 0
    with factory() as db:
        db.add(
            RolloutChange(
                id="c1", tenant_id="tenant-a", scope="role", topic_id=topic, subject_id="s", subject_name="s",
                proposal_ids=[], state="pr_open", canary=True, revision=revision, remediation_ids=[], files=[],
                summary={}, watch_days=7, actor="alice",
            )
        )  # fmt: skip
        db.commit()
    assert client.get("/api/v1/proposals/overview").json()["rollout"]["pr_open"] == 1
    client.app.dependency_overrides[current_actor] = lambda: Actor("v", "tenant-a", frozenset({"viewer"}))
    assert client.get("/api/v1/proposals/overview").status_code == 200
    assert client.post("/api/v1/proposals/links", json={"tier": "high"}).status_code == 200
    assert client.post("/api/v1/proposals/decisions", json=request).status_code == 403
