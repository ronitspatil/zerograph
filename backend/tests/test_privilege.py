"""Excess-privilege index and usage refinement: hand-checked values, parity with the
brute-force reference in the used and inferred modes, refinement accuracy, dormant
detection, and recomputation when usage evidence changes (publish, upload, sweep)."""

import gzip
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import select

from app.collectors.tasks import process_job
from app.db.models import RevisionTopicMember, RevisionTopicSummary, TenantState
from app.graph import topics
from app.graph.compact import CompactGraph
from app.graph.privilege import PEER_SHARE, match_usage
from app.graph.schema import Edge, EdgeType, GraphSnapshot, Node, NodeType
from app.graph.topics import DORMANT, backfill_missing, compute_topics, missing_topics, stored_topic_summary
from app.graph.usage import Evidence, ServiceEvidence

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from qualify_scale import cloudtrail_files, cloudtrail_records, generate_topics  # noqa: E402
from qualify_topics import nmi  # noqa: E402
from qualify_usage import compare, reference_privilege  # noqa: E402

NOW = datetime.now(UTC).replace(microsecond=0)


def evidence(sufficient=("s3", "sts", "rds-data", "aoss"), uploads=("u1",)) -> Evidence:
    services = {
        name: ServiceEvidence(
            name, NOW - timedelta(days=95), NOW, 95.0, True, 1, 1, 10, 0, name in sufficient
        )
        for name in ("s3", "sts", "rds-data", "aoss")
    }
    return Evidence(NOW, list(uploads), services, 0, NOW - timedelta(days=95), NOW)


def node(node_id, kind, **extra):
    return Node(id=node_id, type=kind, name=extra.pop("name", node_id), **extra)


def grant(source, target):
    return Edge(source=source, target=target, type=EdgeType.READ, actions=["s3:GetObject"])


def assume(source, target):
    return Edge(source=source, target=target, type=EdgeType.ASSUMES, actions=["sts:AssumeRole"])


def small() -> GraphSnapshot:
    """Two lake roles and a payments role; one identity per role; a hub granted on most data."""
    nodes = [node(f"lake:{i}", NodeType.BUCKET, tags=["topic=lake"]) for i in range(4)]
    nodes += [
        node(f"pay:{i}", NodeType.BUCKET, tags=["topic=payments"], sensitivity="restricted") for i in range(2)
    ]
    nodes += [
        node("role:a", NodeType.ROLE),
        node("role:b", NodeType.ROLE),
        node("role:p", NodeType.ROLE),
        node("svc:a", NodeType.SERVICE),
        node("svc:b", NodeType.SERVICE),
        node("svc:idle", NodeType.SERVICE),
    ]
    edges = [grant("role:a", f"lake:{i}") for i in range(4)] + [grant("role:a", "pay:0")]
    edges += [grant("role:b", f"lake:{i}") for i in range(2)]
    edges += [grant("role:p", f"pay:{i}") for i in range(2)]
    edges += [assume("svc:a", "role:a"), assume("svc:b", "role:b"), assume("svc:idle", "role:p")]
    return GraphSnapshot(nodes=nodes, edges=edges)


OBSERVED = [
    ("role:a", "lake:0", "read"),
    ("role:a", "lake:1", "read"),
    ("role:b", "lake:0", "read"),
    ("role:p", "pay:0", "write"),
    ("svc:a", "role:a", "assume"),
    ("svc:b", "role:b", "assume"),
    ("unknown", "lake:0", "read"),
    ("svc:a", "missing-resource", "read"),
]


def computed(snapshot, observed=OBSERVED, sufficient=("s3", "sts")):
    graph = CompactGraph.from_snapshot(snapshot)
    usage = match_usage(graph, evidence(sufficient), observed)
    return graph, usage, compute_topics(graph, usage)


def row(result, graph, entity):
    index = graph.index[entity]
    return result.roles.get(index) or result.identities[index]


def test_used_mode_needed_weights_unused_and_dormant_by_hand():
    graph, usage, result = computed(small())
    assert usage.matched == 6 and usage.unmatched == 2
    a = row(result, graph, "role:a")
    # Granted: 4 internal lake (2 each) + 1 restricted (10) = 18; used lake:0, lake:1 = 4.
    assert (a["basis"], a["reach_weight"], a["needed_weight"], a["used_resources"]) == ("used", 18, 4, 2)
    assert (a["unused_grants"], a["unused_restricted"]) == (3, 1)
    identity = row(result, graph, "svc:a")
    assert (identity["needed_weight"], identity["reach_weight"]) == (4, 18)  # Uses what its role used.
    idle = row(result, graph, "svc:idle")
    assert idle["dormant"] and idle["flags"] & DORMANT and idle["needed_weight"] == 0
    assert not identity["dormant"] and not row(result, graph, "role:p")["dormant"]
    privilege = result.summary["privilege"]
    assert privilege["identities"]["granted_weight"] == 18 + 4 + 20
    assert privilege["identities"]["needed_weight"] == 4 + 2 + 0
    assert privilege["identities"]["epi"] == pytest.approx(1 - 6 / 42)
    assert privilege["dormant_identities"] == 1 and privilege["evidence"]["status"] == "attested"
    assert privilege["unused_restricted_grants"] == 2  # role:a pay:0 and role:p pay:1


def test_inferred_mode_uses_peer_baseline():
    # No sufficient service: role:a's lake:0 is peer-needed (both lake roles granted it, both used
    # it); lake:1 is used by 1 of 2 holders (50% >= k); lake:2/3 by 0 of 1.
    graph, _, result = computed(small(), sufficient=())
    a = row(result, graph, "role:a")
    assert a["basis"] == "inferred"
    assert a["needed_weight"] == 4 and a["unused_grants"] == 3
    # Identities infer from same-topic peers that can assume the same role.
    assert row(result, graph, "svc:a")["basis"] == "inferred"
    assert not row(result, graph, "svc:idle")["dormant"]  # Never dormant without sufficient evidence.


def test_no_usage_evidence_reports_no_epi():
    graph = CompactGraph.from_snapshot(small())
    result = compute_topics(graph)
    assert all(r["basis"] == "none" for r in result.roles.values())
    assert result.summary["privilege"]["identities"]["epi"] is None
    assert result.summary["privilege"]["evidence"] == {"status": "none"}
    empty = compute_topics(graph, match_usage(graph, evidence(uploads=()), []))
    assert empty.summary["privilege"]["roles"]["basis"]["none"] == 3


def test_hub_roles_are_decomposed():
    snapshot = small()
    nodes = [*snapshot.nodes, node("role:hub", NodeType.ROLE)]
    nodes += [node(f"extra:{i}", NodeType.BUCKET) for i in range(60)]
    edges = [*snapshot.edges, assume("svc:a", "role:hub")]
    edges += [grant("role:hub", f"extra:{i}") for i in range(60)]
    graph, _, result = computed(GraphSnapshot(nodes=nodes, edges=edges))
    identity = row(result, graph, "svc:a")
    assert row(result, graph, "role:hub")["flags"] & topics.HUB
    assert identity["reach_weight"] == 18 + 120 and identity["reach_weight_excl_hubs"] == 18
    assert identity["needed_weight"] == identity["needed_weight_excl_hubs"] == 4


@pytest.mark.parametrize("sufficient", [("s3", "sts", "rds-data", "aoss"), ()])
def test_planted_epi_matches_brute_force_reference(sufficient):
    snapshot, _, planted = generate_topics(3000, seed=11)
    observed = [(r, d, "read") for r, items in planted["role_data_used"].items() for d in items]
    observed += [(i, r, "assume") for i, roles in planted["identity_role_used"].items() for r in roles]
    graph = CompactGraph.from_snapshot(snapshot)
    result = compute_topics(graph, match_usage(graph, evidence(sufficient), observed))
    rows, kinds, topic_of = {}, {}, {}
    for rows_, kind in ((result.roles, "roles"), (result.identities, "identities")):
        for index, value in rows_.items():
            entity = graph.ids[index]
            rows[entity], kinds[entity] = value, kind
            topic_of[entity] = result.topics[value["topic"]].id if value["topic"] >= 0 else None
    hubs = {graph.ids[i] for i, value in result.roles.items() if value["flags"] & topics.HUB}
    reference = reference_privilege(snapshot, observed, frozenset(sufficient), topic_of, hubs, PEER_SHARE)
    by_topic = {
        result.topics[position].id: (
            stats["privilege"],
            [e for e, t in topic_of.items() if t == result.topics[position].id],
        )
        for position, stats in enumerate(result.topic_stats)
    }
    outcome = compare(reference, rows, result.summary["privilege"], by_topic, kinds)
    assert outcome["match"], outcome
    assert outcome["members_compared"] == len(result.roles) + len(result.identities)
    for entity, value in rows.items():
        assert value["dormant"] == reference[entity]["dormant"], entity
    if sufficient:
        assert result.summary["privilege"]["identities"]["basis"]["used"] == len(result.identities)
    else:
        assert result.summary["privilege"]["identities"]["basis"]["inferred"] == len(result.identities)


def test_usage_refinement_improves_planted_topic_accuracy():
    snapshot, truth, planted = generate_topics(6000, seed=11)
    observed = [(r, d, "read") for r, items in planted["role_data_used"].items() for d in items]
    graph = CompactGraph.from_snapshot(snapshot)
    before = compute_topics(graph)
    after = compute_topics(graph, match_usage(graph, evidence(), observed))
    resources = truth["resource_topic"]

    def score(result):
        names = [result.topics[result.resource_topic[graph.index[e]]].name for e in resources]
        return nmi(names, list(resources.values()))

    assert after.summary["seeded_resources"]["usage"] > 0
    assert after.summary["privilege"]["refinement"]["relabeled"] == after.summary["seeded_resources"]["usage"]
    assert score(after) > score(before) + 0.01
    usage_seeded = [e for e in resources if after.resource_seed[graph.index[e]][0] == "usage"]
    correct = sum(
        after.topics[after.resource_topic[graph.index[e]]].name == resources[e] for e in usage_seeded
    )
    assert correct / len(usage_seeded) > 0.9
    reason = after.resource_seed[graph.index[usage_seeded[0]]][1]
    assert reason.startswith("usage co-access: used together with")
    # Strong labels never change.
    for entity in resources:
        index = graph.index[entity]
        if before.resource_seed[index][0] in ("tag", "metadata", "name"):
            assert after.resource_seed[index] == before.resource_seed[index]


# Publication, upload and sweep.


def publish(client, snapshot):
    with patch("app.api.routes.ingest.delay"):
        job = client.post(
            "/api/v1/ingestions", json={"source": "snapshot", "payload": snapshot.model_dump(mode="json")}
        ).json()
    process_job(job["id"])


def upload_usage(client, snapshot, planted, services=("aoss", "rds-data", "s3", "sts")):
    end = NOW - timedelta(days=1)
    start = end - timedelta(days=91)
    created = client.post(
        "/api/v1/usage/uploads",
        json={
            "window_start": start.isoformat(),
            "window_end": end.isoformat(),
            "attested_services": list(services),
        },
    ).json()
    for number, body in enumerate(cloudtrail_files(cloudtrail_records(snapshot, planted, start, end), 3000)):
        assert (
            client.put(f"/api/v1/usage/uploads/{created['id']}/files/{number}", content=body).status_code
            == 200
        )
    return client.post(f"/api/v1/usage/uploads/{created['id']}/commit").json()


def test_usage_upload_triggers_recompute_and_serves_epi(client, environment):
    factory, _ = environment
    snapshot, truth, planted = generate_topics(2000, seed=11)
    publish(client, snapshot)
    with factory() as db:
        revision = db.get(TenantState, "tenant-a").revision
        assert stored_topic_summary(db, "tenant-a", revision).usage_fingerprint == ""
        assert missing_topics(db, 3) == []
    tile = client.get("/api/v1/overview").json()["excess_privilege"]
    assert tile["status"] == "none" and tile["identities"]["epi"] is None
    committed = upload_usage(client, snapshot, planted)
    assert committed["evidence"]["status"] == "attested"
    with factory() as db:
        assert missing_topics(db, 3) == [("tenant-a", revision)]
    results = backfill_missing()
    assert results[0]["backfilled"] and results[0]["usage"]
    with factory() as db:
        summary = stored_topic_summary(db, "tenant-a", revision)
        assert summary.usage_fingerprint == committed["evidence"]["fingerprint"]
        assert missing_topics(db, 3) == []
        dormant = set(
            db.scalars(
                select(RevisionTopicMember.entity_id).where(
                    RevisionTopicMember.revision == revision, RevisionTopicMember.flags.op("&")(DORMANT) != 0
                )
            )
        )
    assert set(truth["dormant_identities"]) <= dormant
    tile = client.get("/api/v1/overview").json()["excess_privilege"]
    assert tile["status"] == "attested" and 0 < tile["identities"]["epi"] < 1
    assert tile["identities"]["epi_excl_hubs"] is not None and tile["dormant_identities"] >= len(
        truth["dormant_identities"]
    )
    body = client.get("/api/v1/graph/topics").json()
    assert body["summary"]["privilege"]["evidence"]["status"] == "attested"
    topic = next(t for t in body["topics"] if t["kind"] == "anchored")
    assert topic["privilege"]["roles"]["epi"] is not None and "usage" in topic["seeds"]
    detail = client.get(f"/api/v1/graph/topics/{topic['id']}", params={"kind": "role"}).json()
    member = detail["members"][0]
    assert member["basis"] == "used" and member["epi"] == pytest.approx(
        1 - member["needed_weight"] / member["reach_weight"], abs=1e-6
    )
    # A later revision recomputes with the same evidence at publish (usage carries forward).
    publish(client, snapshot)
    with factory() as db:
        later = db.get(TenantState, "tenant-a").revision
        assert later != revision
        assert stored_topic_summary(db, "tenant-a", later).usage_fingerprint == summary.usage_fingerprint
    # Deleting the upload makes the current revision's rows stale again.
    uploads = client.get("/api/v1/usage").json()["uploads"]
    assert client.delete(f"/api/v1/usage/uploads/{uploads[0]['id']}").status_code == 204
    with factory() as db:
        assert missing_topics(db, 3) == [("tenant-a", later)]
    backfill_missing()
    with factory() as db:
        assert db.get(RevisionTopicSummary, ("tenant-a", later)).usage_fingerprint == ""
    assert client.get("/api/v1/overview").json()["excess_privilege"]["status"] == "none"


def test_stale_evidence_flips_to_inferred_via_fingerprint(client, environment):
    factory, _ = environment
    snapshot, _, planted = generate_topics(2000, seed=11)
    publish(client, snapshot)
    upload_usage(client, snapshot, planted, services=("s3",))  # sts not attested
    backfill_missing()
    body = client.get("/api/v1/graph/topics").json()
    basis = body["summary"]["privilege"]["identities"]["basis"]
    assert basis["inferred"] > 0  # Identities assume roles: sts is not sufficient.
    roles = body["summary"]["privilege"]["roles"]["basis"]
    assert roles["used"] + roles["inferred"] == body["summary"]["roles"]


def test_gzip_and_json_files_are_equivalent_for_the_generator():
    snapshot, _, planted = generate_topics(1000, seed=11)
    begin, end = NOW - timedelta(days=91), NOW
    files = list(cloudtrail_files(cloudtrail_records(snapshot, planted, begin, end), 10_000))
    records = json.loads(gzip.decompress(files[0]))["Records"]
    assert records[0]["eventCategory"] == "Data" and records[0]["userIdentity"]["type"] == "AssumedRole"


def test_unused_grants_do_not_vote_in_co_access_when_evidence_suffices():
    snapshot = small()
    nodes = [*snapshot.nodes, node("orphan:used", NodeType.BUCKET), node("orphan:unused", NodeType.BUCKET)]
    edges = [*snapshot.edges, grant("role:a", "orphan:used"), grant("role:a", "orphan:unused")]
    graph_snapshot = GraphSnapshot(nodes=nodes, edges=edges)
    observed = [*OBSERVED, ("role:a", "orphan:used", "read")]
    graph, _, result = computed(graph_snapshot, observed)
    used, unused = graph.index["orphan:used"], graph.index["orphan:unused"]
    assert result.resource_seed[used] == ("coaccess", "co-access: 1 of 1 roles observed using it are lake")
    assert result.resource_seed[unused][0] == "fallback"
    assert "granted but never used" in result.resource_seed[unused][1]
    # Without sufficient evidence every grant still votes (Phase 1 behaviour).
    graph, _, partial = computed(graph_snapshot, observed, sufficient=())
    assert partial.resource_seed[graph.index["orphan:unused"]] == (
        "coaccess",
        "co-access: 1 of 1 granted roles are lake",
    )
