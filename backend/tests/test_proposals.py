"""Optimizer proposals: tiers by hand, the observed-access invariant, the never-auto list,
merges/splits/wildcards/toxic paths, determinism, the what-if model against a brute-force
reference, the simulate overlay, and the API (list, detail, metrics, decisions)."""

import random
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import func, select

from app.collectors.tasks import process_job
from app.core.auth import Actor, current_actor
from app.db.models import AuditEvent, ProposalDecision, RevisionProposal, RevisionProposalSummary, TenantState
from app.engine.blast_radius import apply_overlay, simulate, snapshot_reach
from app.graph import proposals as P
from app.graph.compact import CompactGraph
from app.graph.policies import policy_index
from app.graph.privilege import match_usage
from app.graph.schema import Edge, EdgeType, GraphSnapshot, Node, NodeType, PolicyAttachment
from app.graph.topics import compute_topics
from app.graph.usage import Evidence, ServiceEvidence
from app.graph.whatif import WhatIfModel

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from proposal_reference import (  # noqa: E402
    changes_of,
    never_auto_violations,
    observed_access_kept,
    reference_metrics,
)
from qualify_scale import generate_topics, plant_safety_cases  # noqa: E402

NOW = datetime.now(UTC).replace(microsecond=0)
SERVICES = ("s3", "sts", "rds-data", "aoss")


def evidence(sufficient=SERVICES, partial=()) -> Evidence:
    services = {}
    for name in SERVICES:
        if name in sufficient:
            services[name] = ServiceEvidence(
                name, NOW - timedelta(days=95), NOW, 95.0, True, 1, 1, 10, 0, True
            )
        elif name in partial:
            services[name] = ServiceEvidence(
                name, NOW - timedelta(days=30), NOW, 30.0, True, 1, 1, 10, 0, False
            )
    return Evidence(NOW, ["u1"], services, 0, NOW - timedelta(days=95), NOW)


def node(node_id, kind, **extra):
    return Node(id=node_id, type=kind, name=extra.pop("name", node_id), **extra)


def grant(source, target, actions=("s3:GetObject",)):
    return Edge(source=source, target=target, type=EdgeType.READ, actions=list(actions))


def assume(source, target):
    return Edge(source=source, target=target, type=EdgeType.ASSUMES, actions=["sts:AssumeRole"])


def small(extra_nodes=(), extra_edges=()) -> GraphSnapshot:
    nodes = [node(f"lake:{i}", NodeType.BUCKET, tags=["topic=lake"]) for i in range(4)]
    nodes += [
        node(f"pay:{i}", NodeType.BUCKET, tags=["topic=payments"], sensitivity="restricted") for i in range(2)
    ]
    nodes += [node(f"role:{r}", NodeType.ROLE) for r in "abp"]
    nodes += [node(f"svc:{s}", NodeType.SERVICE) for s in ("a", "b", "idle")]
    edges = [grant("role:a", f"lake:{i}") for i in range(4)] + [grant("role:a", "pay:0")]
    edges += [grant("role:b", f"lake:{i}") for i in range(2)]
    edges += [grant("role:p", f"pay:{i}") for i in range(2)]
    edges += [assume("svc:a", "role:a"), assume("svc:b", "role:b"), assume("svc:idle", "role:p")]
    return GraphSnapshot(nodes=nodes + list(extra_nodes), edges=edges + list(extra_edges))


OBSERVED = [
    ("role:a", "lake:0", "read"),
    ("role:a", "lake:1", "read"),
    ("role:b", "lake:0", "read"),
    ("role:p", "pay:0", "write"),
    ("svc:a", "role:a", "assume"),
    ("svc:b", "role:b", "assume"),
]


def run(snapshot, observed=OBSERVED, found=None, findings=(), policies=None):
    graph = CompactGraph.from_snapshot(snapshot)
    usage = match_usage(graph, found or evidence(), observed)
    computed = compute_topics(graph, usage)
    result = P.compute_proposals(computed, findings, policies)
    return computed, result


def by_pair(result, computed, kind=P.REMOVE):
    ids = computed.graph.ids
    return {
        (ids[p.subject], ids[p.target] if p.target >= 0 else ""): p
        for p in result.proposals
        if p.kind == kind
    }


def test_remove_grant_tiers_by_hand():
    computed, result = run(small())
    removals = by_pair(result, computed)
    tier = {pair: P.TIERS[p.tier] for pair, p in removals.items()}
    assert tier[("role:a", "pay:0")] == "high"  # Unused, outside role:a's topic (lake).
    assert tier[("role:a", "lake:2")] == "medium"  # Unused, in topic, no peer uses it.
    assert tier[("role:b", "lake:1")] == "low"  # Unused by role:b, but role:a (1 of 2 holders) uses it.
    assert tier[("role:p", "pay:1")] == "medium"
    # Used grants are never proposed.
    assert not {("role:a", "lake:0"), ("role:a", "lake:1"), ("role:b", "lake:0"), ("role:p", "pay:0")} & set(
        tier
    )
    high = removals[("role:a", "pay:0")]
    assert high.reasons == () and high.detail["coverage"] == "sufficient" and high.weight == 10
    assert high.epi[0] == pytest.approx(1 - 4 / 18) and high.epi[1] == pytest.approx(1 - 4 / 8)
    dormant = by_pair(result, computed, P.DISABLE_IDENTITY)
    assert set(dormant) == {("svc:idle", "")} and P.TIERS[dormant[("svc:idle", "")].tier] == "high"
    assert not any(
        c["delete"] for p in result.proposals for c in P._changes(p, computed, result.edges) if "delete" in c
    )


def test_coverage_decides_inferred_and_manual():
    # s3 complete but only 30 days: inferred (peer baseline agrees it is unneeded).
    computed, result = run(small(), found=evidence(sufficient=("sts",), partial=("s3",)))
    tiers = {pair: P.TIERS[p.tier] for pair, p in by_pair(result, computed).items()}
    assert tiers[("role:a", "pay:0")] == "inferred" and ("role:b", "lake:1") not in tiers  # peer-needed
    # s3 never covered: manual, reason "coverage".
    computed, result = run(small(), found=evidence(sufficient=("sts",)))
    for p in by_pair(result, computed).values():
        assert P.TIERS[p.tier] == "manual" and "coverage" in p.reasons
    # No usage evidence at all: no removal is proposed.
    graph = CompactGraph.from_snapshot(small())
    computed = compute_topics(graph, None)
    assert not [p for p in P.compute_proposals(computed).proposals if p.kind == P.REMOVE]


def test_observed_use_through_another_principal_is_protected():
    # svc:a used lake:3 itself (through role:a's grant): role:a's lake:3 grant must stay.
    computed, result = run(small(), observed=[*OBSERVED, ("svc:a", "lake:3", "read")])
    assert ("role:a", "lake:3") not in by_pair(result, computed)
    assert result.summary["guards"]["skipped_observed"] >= 1
    # Observed use no graph grant explains freezes the asset.
    computed, result = run(small(), observed=[*OBSERVED, ("role:p", "lake:2", "read")])
    assert ("role:a", "lake:2") not in by_pair(result, computed)
    assert P.check_invariant(computed, result.proposals) == []


def test_invariant_detects_a_violation():
    computed, result = run(small())
    graph = computed.graph
    bad = P.Proposal(P.REMOVE, P.HIGH, P.HIGH, graph.index["role:a"], graph.index["lake:0"], 0, 2, 1, (),
                     removals=(graph.index["role:a"], graph.index["lake:0"]), id="pbad")  # fmt: skip
    assert P.check_invariant(computed, [*result.proposals, bad]) == ["pbad"]


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"tags": ["purpose=break-glass"]}, "break_glass"),
        ({"tags": ["schedule=seasonal"]}, "seasonal"),
        ({"metadata": {"scp_exempt_service_linked_role": True}}, "service_linked"),
        ({"name": "dr-failover"}, "break_glass"),
    ],
)
def test_never_auto_identities_are_manual(change, reason):
    snapshot = small()
    role = next(n for n in snapshot.nodes if n.id == "role:a")
    for key, value in change.items():
        setattr(role, key, value)
    computed, result = run(snapshot)
    for pair, p in by_pair(result, computed).items():
        if pair[0] == "role:a":
            assert P.TIERS[p.tier] == "manual" and reason in p.reasons and P.TIERS[p.base_tier] != "manual"


def test_kms_condition_deny_and_resource_policy_are_manual(environment):
    snapshot = small(extra_nodes=[node("arn:aws:kms:us-east-1:1:key/k", NodeType.DATABASE, tags=["topic=lake"])],
                     extra_edges=[grant("role:a", "arn:aws:kms:us-east-1:1:key/k", ["kms:Decrypt"])])  # fmt: skip
    statement = {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["lake:0", "lake:1", "pay:0"]}
    snapshot.policies = [
        PolicyAttachment(principal="role:a", kind="inline", name="base", document={"Statement": [statement]}),
        PolicyAttachment(principal="role:a", kind="managed", name="cond", document={"Statement": [
            {"Effect": "Allow", "Action": "s3:Get*", "Resource": "lake:2", "Condition": {"Bool": {"x": "y"}}},
            {"Effect": "Deny", "Action": "s3:*", "Resource": "pay:*"},
        ]}),
    ]  # fmt: skip
    factory, _ = environment
    from app.graph.policies import store_policies

    with factory() as db:
        store_policies(db, "tenant-a", "r1", ((p.id, p.model_dump_json()) for p in snapshot.policies))
        db.commit()
        policies = policy_index(db, "tenant-a", "r1")
    computed, result = run(snapshot, policies=policies)
    removals = by_pair(result, computed)
    assert "condition" in removals[("role:a", "lake:2")].reasons
    assert "deny" in removals[("role:a", "pay:0")].reasons
    assert "resource_policy" in removals[("role:a", "lake:3")].reasons  # No identity policy grants it.
    kms = removals[("role:a", "arn:aws:kms:us-east-1:1:key/k")]
    assert "kms" in kms.reasons and P.TIERS[kms.tier] == "manual"
    for pair in (("role:a", "lake:2"), ("role:a", "pay:0"), ("role:a", "lake:3")):
        assert P.TIERS[removals[pair].tier] == "manual"


def test_merge_split_wildcard_and_toxic():
    lake = [node(f"lake:{i}", NodeType.BUCKET, tags=["topic=lake"]) for i in range(6)]
    pay = [
        node(f"pay:{i}", NodeType.BUCKET, tags=["topic=payments"], sensitivity="restricted") for i in range(4)
    ]
    roles = [node(r, NodeType.ROLE) for r in ("role:m1", "role:m2", "role:split", "role:hub", "role:p")]
    agent = node("agent:x", NodeType.AGENT, internet_exposed=True, authenticated=False)
    edges = [grant(r, f"lake:{i}") for r in ("role:m1", "role:m2") for i in range(5)]
    edges += [grant("role:split", f"lake:{i}") for i in range(3)] + [
        grant("role:split", f"pay:{i}") for i in range(3)
    ]
    edges += [grant("role:hub", item.id, ["s3:*"]) for item in lake + pay]
    edges += [grant("role:p", "pay:0"), grant("role:p", "pay:3"), assume("agent:x", "role:p")]
    observed = [("role:split", f"lake:{i}", "read") for i in range(3)]
    observed += [("role:split", f"pay:{i}", "read") for i in range(3)]
    observed += [("role:m1", "lake:0", "read"), ("role:hub", "lake:5", "read"), ("role:p", "pay:0", "read")]
    snapshot = GraphSnapshot(nodes=[*lake, *pay, *roles, agent], edges=edges)
    graph = CompactGraph.from_snapshot(snapshot)
    findings = P.findings_from(graph.analyze().findings)
    assert findings
    computed, result = run(snapshot, observed=observed, findings=findings)
    merges = by_pair(result, computed, P.MERGE)
    assert len(merges) == 1
    merge = next(iter(merges.values()))
    assert P.TIERS[merge.tier] == "manual" and "trust" in merge.reasons and merge.detail["jaccard"] == 1.0
    split = by_pair(result, computed, P.SPLIT)[("role:split", "")]
    assert {g["topic"] for g in split.detail["groups"]} == {"lake", "payments"} and P.TIERS[
        split.tier
    ] == "manual"
    wildcard = by_pair(result, computed, P.WILDCARD)[("role:hub", "")]
    assert "wildcard" in wildcard.reasons and wildcard.detail["keep_used"] == 1
    assert not [p for p in result.proposals if p.kind == P.REMOVE and graph.ids[p.subject] == "role:hub"]
    toxic = by_pair(result, computed, P.TOXIC)
    # The used pay:0 grant is kept; the unused pay:3 grant is the edge to cut.
    assert ("role:p", "pay:3") in toxic and ("role:p", "pay:0") not in toxic
    assert P.check_invariant(computed, result.proposals) == []


def test_ids_and_order_are_deterministic_and_independent_of_revision_order():
    snapshot, _, usage = generate_topics(2000, seed=5)
    observed = [(r, i, "read") for r, items in usage["role_data_used"].items() for i in items]
    observed += [(i, r, "assume") for i, roles in usage["identity_role_used"].items() for r in roles]
    _, first = run(snapshot, observed)
    _, again = run(snapshot, observed)
    shuffled = snapshot.model_copy()
    rng = random.Random(3)
    nodes, edges = list(snapshot.nodes), list(snapshot.edges)
    rng.shuffle(nodes)
    rng.shuffle(edges)
    shuffled = GraphSnapshot.model_construct(
        nodes=nodes, edges=edges, warnings=[], source="snapshot", policies=[]
    )
    _, reordered = run(shuffled, observed)

    def key(result):
        return [(p.id, p.tier, p.kind, p.weight) for p in result.proposals]

    assert key(first) == key(again) == key(reordered)
    assert len({p.id for p in first.proposals}) == len(first.proposals)


@pytest.fixture(scope="module")
def planted():
    snapshot, truth, usage = generate_topics(3000, seed=11)
    cases = plant_safety_cases(snapshot, truth, usage, per_case=3)
    observed = [(r, i, "read") for r, items in usage["role_data_used"].items() for i in items]
    observed += [(i, r, "assume") for i, roles in usage["identity_role_used"].items() for r in roles]
    graph = CompactGraph.from_snapshot(snapshot)
    found = P.findings_from(graph.analyze().findings)
    index = P.PolicyIndex()
    from app.graph.policies import statements

    for attachment in snapshot.policies:
        index.statements.setdefault(attachment.principal, []).extend(statements(attachment.document))
    computed, result = run(snapshot, observed, findings=found, policies=index)
    views = [
        {
            "id": row[2],
            "type": row[4],
            "tier": row[5],
            "subject_id": row[8],
            "target_id": row[11],
            "reasons": row[17],
            "changes": row[19],
        }
        for row in P.proposal_rows(result, computed, "t", "r")
    ]
    return snapshot, truth, cases, observed, computed, result, views


def test_planted_never_auto_cases_are_manual(planted):
    _, _, cases, _, _, result, views = planted
    assert never_auto_violations(views, cases) == []
    by_reason = {reason for p in result.proposals for reason in p.reasons}
    assert {
        "break_glass",
        "service_linked",
        "seasonal",
        "condition",
        "deny",
        "kms",
        "wildcard",
        "trust",
    } <= by_reason
    assert any(p.kind == P.TOXIC for p in result.proposals)
    # Every planted pair that is proposed is manual, and planted subjects are proposed manually.
    pairs = {tuple(p) for values in cases["pairs"].values() for p in values}
    proposed = {(v["subject_id"], v["target_id"]): v for v in views if v["type"] == "remove_grant"}
    assert pairs & set(proposed)
    assert all(proposed[pair]["tier"] == "manual" for pair in pairs & set(proposed))


def test_planted_invariant_over_every_proposal(planted):
    snapshot, _, _, observed, computed, result, _ = planted
    assert P.check_invariant(computed, result.proposals) == []
    overlay = P.overlay_from(result.model, range(len(result.proposals)))
    lost = observed_access_kept(snapshot, observed, overlay.removed, set(), overlay.disabled)
    assert lost == []


def test_whatif_model_matches_brute_force(planted):
    snapshot, truth, _, _, computed, result, views = planted
    model = WhatIfModel.loads(result.model.dumps())
    rows = {
        computed.graph.ids[n]: row
        for rows_ in (computed.roles, computed.identities)
        for n, row in rows_.items()
    }
    hubs = {computed.graph.ids[h] for h in computed.context.hubs}
    rng = random.Random(1)
    selections = [
        [i for i, p in enumerate(result.proposals) if p.tier == P.HIGH],
        rng.sample(range(len(result.proposals)), 200),
        [i for i, p in enumerate(result.proposals) if p.kind in (P.DISABLE_ROLE, P.WILDCARD, P.TOXIC)],
    ]
    for ordinals in selections:
        found = model.evaluate(model.selection(ordinals))
        overlay = P.overlay_from(model, ordinals)
        cut = {pair for pair in overlay.removed if pair[1] not in {n.id for n in snapshot.nodes if n.type.value in (
            "Database", "VectorStore", "S3Bucket")}}  # fmt: skip
        reference = reference_metrics(snapshot, rows, hubs, overlay.removed - cut, cut, overlay.disabled)
        for kind in ("roles", "identities"):
            for side in ("before", "after"):
                for key, value in reference[kind][side].items():
                    assert found["graph"][kind][side][key] == value, (kind, side, key)
    # Nothing selected: after equals before equals the stored aggregate.
    empty = model.evaluate(model.selection([]))
    privilege = computed.summary["privilege"]
    assert empty["graph"]["identities"]["after"]["epi"] == pytest.approx(
        privilege["identities"]["epi"], abs=1e-6
    )
    assert empty["graph"]["identities"]["before"] == empty["graph"]["identities"]["after"]


def test_simulate_overlay_matches_a_rebuilt_graph(planted):
    snapshot, _, _, _, _, result, _ = planted
    model = result.model
    rng = random.Random(2)
    ordinals = rng.sample(range(len(result.proposals)), 300)
    overlay = P.overlay_from(model, ordinals)
    reduced = GraphSnapshot.model_construct(
        nodes=snapshot.nodes,
        edges=[
            e for e in snapshot.edges
            if (e.source, e.target) not in overlay.removed and e.source not in overlay.disabled
            and e.target not in overlay.disabled
        ],
        warnings=[], source="snapshot", policies=[],
    )  # fmt: skip
    total_weight = sum({"public": 1, "internal": 2, "confidential": 5, "restricted": 10}[n.sensitivity.value]
                       for n in snapshot.nodes if n.type.value in ("Database", "VectorStore", "S3Bucket"))  # fmt: skip
    sources = sorted({model.ids[p.subject] for p in result.proposals[:50]})
    for source in sources[:25]:
        before = snapshot_reach(snapshot, source, 5, True)
        after = apply_overlay(before, overlay.removed, set(), overlay.disabled)
        rebuilt = snapshot_reach(reduced, source, 5, True)
        if source in overlay.disabled:
            assert simulate(after, len(snapshot.nodes), total_weight).affected_nodes == []
            continue
        assert simulate(after, len(snapshot.nodes), total_weight) == simulate(
            rebuilt, len(snapshot.nodes), total_weight
        )


# ---------------------------------------------------------------------------
# API


def publish(client, snapshot):
    with patch("app.api.routes.ingest.delay"):
        job = client.post(
            "/api/v1/ingestions", json={"source": "snapshot", "payload": snapshot.model_dump(mode="json")}
        ).json()
    process_job(job["id"])


def test_api_list_detail_simulate_metrics_and_decisions(client, environment):
    from test_privilege import upload_usage

    factory, _ = environment
    snapshot, truth, usage = generate_topics(2000, seed=11)
    publish(client, snapshot)
    # Without usage evidence: no removals, only structural (manual) proposals.
    body = client.get("/api/v1/proposals").json()
    assert body["summary"]["by_type"]["remove_grant"] == 0
    upload_usage(client, snapshot, usage)
    with factory() as db:
        revision = db.get(TenantState, "tenant-a").revision
        assert P.missing_proposals(db, 3) == []  # Topics are stale first; proposals follow them.
    from app.graph.topics import backfill_missing

    backfill_missing()
    with factory() as db:
        summary = P.stored_proposal_summary(db, "tenant-a", revision)
        assert summary.usage_fingerprint != "" and P.missing_proposals(db, 3) == []
    body = client.get("/api/v1/proposals", params={"limit": 20}).json()
    assert body["summary"]["by_type"]["remove_grant"] > 0 and body["view"]["total"] == summary.total
    ordinals = [p["ordinal"] for p in body["proposals"]]
    assert ordinals == sorted(ordinals) and body["proposals"][0]["status"] == "proposed"
    page = client.get("/api/v1/proposals", params={"limit": 20, "cursor": body["view"]["next_cursor"]}).json()
    assert page["proposals"][0]["ordinal"] > ordinals[-1]
    high = client.get("/api/v1/proposals", params={"tier": "high", "type": "remove_grant", "limit": 5}).json()
    assert high["proposals"] and all(p["tier"] == "high" for p in high["proposals"])
    proposal = high["proposals"][0]
    topic = client.get("/api/v1/proposals", params={"topic": proposal["topic_id"], "limit": 200}).json()
    assert all(p["topic_id"] == proposal["topic_id"] for p in topic["proposals"])
    role = client.get("/api/v1/proposals", params={"subject": proposal["subject_id"]}).json()
    assert proposal["id"] in {p["id"] for p in role["proposals"]}
    assert client.get("/api/v1/proposals", params={"tier": "bogus"}).status_code == 422

    detail = client.get(f"/api/v1/proposals/{proposal['id']}").json()
    assert detail["resource"]["label_reason"] and detail["topic"]["reason"]
    assert detail["evidence"]["status"] == "attested" and detail["graph_delta"]["applied"] == {
        "remove_grant": 1
    }
    assert (
        detail["proposal"]["changes"][0]["op"] == "remove_grant"
        and detail["proposal"]["changes"][0]["edge_id"]
    )
    assert client.get("/api/v1/proposals/p" + "0" * 19).status_code == 404

    simulated = client.post("/api/v1/proposals/simulate", json={"proposal_ids": [proposal["id"]]}).json()
    assert simulated["source"] == proposal["subject_id"]
    assert proposal["target_id"] in simulated["whatif"]["assets_removed"]
    assert simulated["whatif"]["risk_delta"] <= 0
    plain = client.post("/api/v1/simulate", json={"node_id": proposal["subject_id"]}).json()
    assert "whatif" not in plain
    explicit = client.post(
        "/api/v1/simulate",
        json={
            "node_id": proposal["subject_id"],
            "include_uncertain": True,
            "overlay": {"edges": [{"source": proposal["subject_id"], "target": proposal["target_id"]}]},
        },
    ).json()
    assert explicit["whatif"]["assets_removed"] == simulated["whatif"]["assets_removed"]
    missing = client.post(
        "/api/v1/simulate", json={"node_id": "x", "overlay": {"proposal_ids": ["p" + "1" * 19]}}
    )
    assert missing.status_code == 404

    metrics = client.post("/api/v1/proposals/metrics", json={"tier": "high"}).json()
    stored = summary.totals["high_tier"]["graph"]
    assert metrics["graph"] == stored and metrics["selected"] == summary.totals["by_tier"]["high"]
    assert metrics["graph"]["identities"]["after"]["epi"] < metrics["graph"]["identities"]["before"]["epi"]
    assert (
        client.post("/api/v1/proposals/metrics", json={"proposal_ids": ["p" + "2" * 19]}).status_code == 404
    )

    # Decisions: admin only, audited, carried forward to the next revision by ID.
    accepted, rejected = high["proposals"][0]["id"], high["proposals"][1]["id"]
    assert (
        client.post(f"/api/v1/proposals/{accepted}/decision", json={"state": "accepted"}).status_code == 200
    )
    assert (
        client.post(f"/api/v1/proposals/{rejected}/decision", json={"state": "rejected", "note": "n"}).json()[
            "decision"
        ]["state"]
        == "rejected"
    )
    by_decision = client.post("/api/v1/proposals/metrics", json={"decision": "accepted"}).json()
    assert by_decision["selected"] == 1
    assert client.get("/api/v1/proposals", params={"state": "accepted"}).json()["view"]["total"] == 1
    with factory() as db:
        actions = set(db.scalars(select(AuditEvent.action).where(AuditEvent.action.like("proposal.%"))))
        assert actions == {"proposal.accepted", "proposal.rejected"}
    publish(client, snapshot)
    with factory() as db:
        later = db.get(TenantState, "tenant-a").revision
        assert later != revision and P.stored_proposal_summary(db, "tenant-a", later) is not None
    carried = client.get(f"/api/v1/proposals/{accepted}").json()
    assert carried["revision"] == later and carried["proposal"]["decision"]["state"] == "accepted"
    assert (
        carried["proposal"]["decision"]["revision"] == revision
        and not carried["proposal"]["decision"]["stale"]
    )
    assert client.get("/api/v1/proposals/summary").json()["decisions"] == {"accepted": 1, "rejected": 1}
    assert client.post(f"/api/v1/proposals/{accepted}/decision", json={"state": "pending"}).status_code == 200
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(ProposalDecision)) == 1
    # Viewers read and simulate but cannot decide.
    client.app.dependency_overrides[current_actor] = lambda: Actor("v", "tenant-a", frozenset({"viewer"}))
    assert client.get("/api/v1/proposals").status_code == 200
    assert client.post("/api/v1/proposals/simulate", json={"proposal_ids": [rejected]}).status_code == 200
    assert (
        client.post(f"/api/v1/proposals/{rejected}/decision", json={"state": "accepted"}).status_code == 403
    )


def test_retention_and_sweep_lifecycle(client, environment):
    factory, _ = environment
    snapshot, _, _ = generate_topics(1000, seed=3)
    publish(client, snapshot)
    with factory() as db:
        revision = db.get(TenantState, "tenant-a").revision
        assert db.scalar(select(func.count()).select_from(RevisionProposal)) > 0
        # A missing summary (e.g. pre-0011 revision) is found by the sweep and backfilled.
        P.delete_proposals(db, "tenant-a", revision)
        db.commit()
        assert P.missing_proposals(db, 3) == [("tenant-a", revision)]
    assert client.get("/api/v1/proposals").status_code == 404
    results = P.backfill_missing()
    assert results[0]["backfilled"]
    with factory() as db:
        assert db.get(RevisionProposalSummary, ("tenant-a", revision)) is not None
        P.delete_proposals(db, "tenant-a", revision)
        assert db.scalar(select(func.count()).select_from(RevisionProposal)) == 0


def test_changes_of_reads_view_changes():
    removed, cut, disabled = changes_of(
        [
            {
                "changes": [
                    {"op": "remove_grant", "source": "a", "target": "b"},
                    {"op": "disable_node", "node": "c"},
                    {"op": "cut_hop", "source": "d", "target": "e"},
                ]
            }
        ]  # fmt: skip
    )
    assert removed == {("a", "b")} and cut == {("d", "e")} and disabled == {"c"}
