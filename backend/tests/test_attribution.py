"""Role-session attribution: CloudTrail session capture, assumption-chain resolution, the
upload commit's attributed rows, identity needed access and dormancy from attributed use,
and never-assumed role proposals."""

import gzip
import json
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select

from app.collectors.cloudtrail import issuer_of, normalize_export, session_of
from app.db.models import AttributedAccess, UsageSessionIssued, UsageSessionStaged, UsageUpload
from app.graph import usage
from app.graph.compact import CompactGraph
from app.graph.privilege import match_usage
from app.graph.proposals import MANUAL, TYPES, check_invariant, compute_proposals
from app.graph.schema import Edge, EdgeType, GraphSnapshot, Node, NodeType
from app.graph.topics import ATTRIBUTED, DORMANT, ROLE_LEVEL, compute_topics
from app.graph.usage import MAX_CHAIN, Evidence, Issuance, ServiceEvidence, resolve_sessions

ACCOUNT = "123456789012"
ROLE_A = f"arn:aws:iam::{ACCOUNT}:role/a"
ROLE_B = f"arn:aws:iam::{ACCOUNT}:role/b"
ALICE = f"arn:aws:iam::{ACCOUNT}:user/alice"
BOB = f"arn:aws:iam::{ACCOUNT}:user/bob"
NOW = datetime.now(UTC).replace(microsecond=0)


def evidence(sufficient=("s3", "sts")) -> Evidence:
    services = {
        name: ServiceEvidence(name, NOW - timedelta(days=95), NOW, 95.0, True, 1, 1, 10, 0, name in sufficient)
        for name in ("s3", "sts")
    }
    return Evidence(NOW, ["u1"], services, 0, NOW - timedelta(days=95), NOW)


def stamp(days_ago: float = 1) -> str:
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def window(days=100):
    return NOW - timedelta(days=days), NOW


def role_session(role, key, name="s", **extra):
    identity = {
        "type": "AssumedRole",
        "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{role.rsplit('/', 1)[-1]}/{name}",
        "sessionContext": {"sessionIssuer": {"type": "Role", "arn": role}},
        **extra,
    }
    if key:
        identity["accessKeyId"] = key
    return identity


def assume(caller, role, key, name="s", days_ago=2, event="AssumeRole", **request):
    return {
        "eventTime": stamp(days_ago),
        "eventSource": "sts.amazonaws.com",
        "eventName": event,
        "userIdentity": caller,
        "requestParameters": {"roleArn": role, "roleSessionName": name, **request},
        "responseElements": {
            "credentials": {"accessKeyId": key},
            "assumedRoleUser": {"arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{role.rsplit('/', 1)[-1]}/{name}"},
        },
    }


def read(identity, bucket="lake", days_ago=1):
    return {
        "eventTime": stamp(days_ago),
        "eventSource": "s3.amazonaws.com",
        "eventName": "GetObject",
        "userIdentity": identity,
        "requestParameters": {"bucketName": bucket, "key": "k"},
    }


def user(arn):
    return {"type": "IAMUser", "arn": arn}


# CloudTrail capture


def test_issuers_of_every_caller_kind_and_malformed_identities():
    assert issuer_of(user(ALICE)) == (ALICE, "", "")
    assert issuer_of({"type": "Root", "arn": "arn:aws:iam::1:root"}) == ("arn:aws:iam::1:root", "", "")
    assert issuer_of({"type": "AWSService", "invokedBy": "lambda.amazonaws.com"}) == (
        "service:lambda.amazonaws.com",
        "",
        "",
    )
    web = {"type": "WebIdentityUser", "identityProvider": "oidc.eks/x", "userName": "system:sa:ns:app"}
    assert issuer_of(web) == ("web-identity:oidc.eks/x:system:sa:ns:app", "", "")
    saml = {"type": "SAMLUser", "identityProvider": "arn:aws:iam::1:saml-provider/okta", "userName": "bob"}
    assert issuer_of(saml)[0] == "saml:arn:aws:iam::1:saml-provider/okta:bob"
    assert issuer_of(role_session(ROLE_A, "K1")) == ("", "K1", ROLE_A)
    # Unidentifiable or malformed callers.
    assert issuer_of({"type": "AWSService"}) == ("", "", "")
    assert issuer_of({"type": "WebIdentityUser", "userName": "x"}) == ("", "", "")
    assert issuer_of({"type": "IAMUser", "arn": 7}) == ("", "", "")
    assert issuer_of({"type": "Unknown"}) == ("", "", "")
    assert session_of(user(ALICE)) is None
    behalf = role_session(
        ROLE_A, "K", onBehalfOf={"userId": "u-1", "identityStoreArn": "arn:aws:identitystore::1:store/d-1"}
    )
    assert session_of(behalf)[3] == "identity-center:arn:aws:identitystore::1:store/d-1:u-1"
    sourced = role_session(ROLE_A, "K", sessionContext={"sourceIdentity": "alice", "sessionIssuer": {}})
    assert session_of(sourced)[2] == "alice"


def test_normalize_records_issuances_and_session_access():
    records = [
        assume(user(ALICE), ROLE_A, "K1", sourceIdentity="alice"),
        read(role_session(ROLE_A, "K1")),
        read(role_session(ROLE_A, "K1")),
        assume(role_session(ROLE_A, "K1"), ROLE_B, "K2"),  # Role chaining.
        read(role_session(ROLE_B, "K2"), bucket="pay"),
        {**assume(user(BOB), ROLE_A, "KX"), "errorCode": "AccessDenied"},  # Denied: no session.
        {**assume(user(BOB), ROLE_A, "KY"), "responseElements": None},  # No credentials.
        assume(user(BOB), ROLE_A, "KZ", days_ago=200),  # Outside the window.
        read(user(ALICE)),  # Not a role session.
    ]
    result = normalize_export(records, *window())
    assert set(result.issued) == {"K1", "K2"}
    arn, role, principal, parent, parent_role, source, _ = result.issued["K1"]
    assert (role, principal, parent, source) == (ROLE_A, ALICE, "", "alice") and arn.endswith("/a/s")
    assert result.issued["K2"][1:5] == [ROLE_B, "", "K1", ROLE_A]
    sessions = {key[:2] + key[5:]: row[2] for key, row in result.sessions.items()}
    assert sessions == {
        (ROLE_A, "K1", "arn:aws:s3:::lake", "read", "s3"): 2,
        (ROLE_A, "K1", ROLE_B, "assume", "sts"): 1,
        (ROLE_B, "K2", "arn:aws:s3:::pay", "read", "s3"): 1,
    }
    stats = result.stats()
    assert stats["sessions_issued"] == 2 and stats["issued_unkeyed"] == 1 and stats["session_events"] == 4
    # Role-level rows are unchanged by session capture.
    assert result.access[(ROLE_A, "arn:aws:s3:::lake", "read", "s3")][2] == 2


# Chain resolution


def issuance(role, principal="", parent="", parent_role="", arn="", source=""):
    return Issuance(arn, role, principal, parent, parent_role, source)


def test_resolve_sessions_follows_bounded_chains():
    issued = {
        "K1": issuance(ROLE_A, ALICE),
        "K2": issuance(ROLE_B, parent="K1", parent_role=ROLE_A),
        "K3": issuance(ROLE_A, parent="K2", parent_role=ROLE_B),
        "orphan": issuance(ROLE_B, parent="gone", parent_role=ROLE_A),
        "orphan-child": issuance(ROLE_A, parent="orphan", parent_role=ROLE_B),
        "mismatch": issuance(ROLE_B, parent="K1", parent_role=ROLE_B),  # Parent session is role a.
        "loop-1": issuance(ROLE_A, parent="loop-2", parent_role=ROLE_B),
        "loop-2": issuance(ROLE_B, parent="loop-1", parent_role=ROLE_A),
        "svc": issuance(ROLE_B, "service:ecs-tasks.amazonaws.com"),
    }
    resolved = resolve_sessions(issued)
    assert resolved == {
        "K1": (ALICE, 1),
        "K2": (ALICE, 2),
        "K3": (ALICE, 3),
        "svc": ("service:ecs-tasks.amazonaws.com", 1),
    }
    # Iteration order does not matter.
    assert resolve_sessions(dict(reversed(issued.items()))) == resolved


def test_resolve_sessions_bounds_chain_depth():
    issued = {"K0": issuance(ROLE_A, ALICE)}
    for depth in range(1, MAX_CHAIN + 2):
        issued[f"K{depth}"] = issuance(ROLE_A, parent=f"K{depth - 1}", parent_role=ROLE_A)
    resolved = resolve_sessions(issued)
    assert resolved[f"K{MAX_CHAIN - 1}"] == (ALICE, MAX_CHAIN)
    assert f"K{MAX_CHAIN}" not in resolved and f"K{MAX_CHAIN + 1}" not in resolved


# Upload commit


def put(client, upload_id, chunk, records):
    body = gzip.compress(json.dumps({"Records": records}).encode())
    response = client.put(f"/api/v1/usage/uploads/{upload_id}/files/{chunk}", content=body)
    assert response.status_code == 200, response.text
    return response


def test_commit_attributes_sessions_across_files(client, environment):
    factory, _ = environment
    start, end = window()
    upload = client.post(
        "/api/v1/usage/uploads",
        json={"window_start": start.isoformat(), "window_end": end.isoformat(), "attested_services": ["s3", "sts"]},
    ).json()
    service = {"type": "AWSService", "invokedBy": "ecs-tasks.amazonaws.com"}
    behalf = {"userId": "u-9", "identityStoreArn": "arn:aws:identitystore::1:store/d-1"}
    # File 0: the issuances; file 1: the sessions' use (attribution spans files of an upload).
    put(
        client,
        upload["id"],
        0,
        [
            assume(user(ALICE), ROLE_A, "K1", name="alice", sourceIdentity="alice"),
            assume(role_session(ROLE_A, "K1", "alice"), ROLE_B, "K2", name="alice"),
            assume(service, ROLE_B, "KS", name="task"),
            assume(user(BOB), ROLE_A, "K3", name="bob", days_ago=150),  # Before the window.
        ],
    )
    put(
        client,
        upload["id"],
        1,
        [
            read(role_session(ROLE_A, "K1", "alice")),
            read(role_session(ROLE_B, "K2", "alice"), bucket="pay"),
            read(role_session(ROLE_B, "KS", "task"), bucket="pay"),
            read(role_session(ROLE_A, "K3", "bob")),  # Issued before the window: unattributed.
            read(role_session(ROLE_A, "K4", "x", sessionContext={"sourceIdentity": "alice", "sessionIssuer": {"arn": ROLE_A}})),
            read(role_session(ROLE_A, "K5", "y", onBehalfOf=behalf)),
            read(role_session(ROLE_A, "", "alice")),  # No key: the session ARN only alice used.
        ],
    )
    committed = client.post(f"/api/v1/usage/uploads/{upload['id']}/commit").json()
    stats = committed["stats"]["attribution"]
    assert stats["sessions_issued"] == 3 and stats["sessions_resolved"] == 3
    assert stats["by_basis"] == {
        "session": 4,  # alice's lake read and a->b assumption, her chained pay read, the task's read
        "on-behalf-of": 1,
        "session-arn": 1,
        "source-identity": 1,
        "unattributed": 1,
    }
    with factory() as db:
        rows = {
            (r.identity_id, r.role_id, r.resource_id, r.action_class): (r.basis, r.depth, r.count)
            for r in db.scalars(select(AttributedAccess))
        }
        assert db.get(UsageUpload, upload["id"]).attributed
        for model in (UsageSessionIssued, UsageSessionStaged):
            assert db.scalar(select(func.count()).select_from(model)) == 0
        assert usage.attribution_ready(db, "tenant-a")
        aggregated = {tuple(row[:4]): row[4] for row in usage.attributed(db, "tenant-a")}
    assert rows[(ALICE, ROLE_B, "arn:aws:s3:::pay", "read")] == ("session", 2, 1)
    assert rows[(ALICE, ROLE_A, ROLE_B, "assume")] == ("session", 1, 1)
    assert rows[("service:ecs-tasks.amazonaws.com", ROLE_B, "arn:aws:s3:::pay", "read")] == ("session", 1, 1)
    assert rows[("", ROLE_A, "arn:aws:s3:::lake", "read")] == ("unattributed", 0, 1)
    assert rows[(ALICE, ROLE_A, "arn:aws:s3:::lake", "read")][2] == 1  # Basis is part of the row key.
    assert rows[("identity-center:arn:aws:identitystore::1:store/d-1:u-9", ROLE_A, "arn:aws:s3:::lake", "read")][0] == (
        "on-behalf-of"
    )
    assert aggregated[(ALICE, ROLE_A, "arn:aws:s3:::lake", "read")] == 3  # session + source-identity + ARN
    # Deleting the upload removes its attribution.
    assert client.delete(f"/api/v1/usage/uploads/{upload['id']}").status_code == 204
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(AttributedAccess)) == 0
        assert not usage.attribution_ready(db, "tenant-a")


def test_uploads_without_attribution_keep_role_level_credit(client, environment):
    factory, _ = environment
    start, end = window()
    upload = client.post(
        "/api/v1/usage/uploads",
        json={"window_start": start.isoformat(), "window_end": end.isoformat(), "attested_services": ["s3"]},
    ).json()
    put(client, upload["id"], 0, [read(role_session(ROLE_A, "K1"))])
    client.post(f"/api/v1/usage/uploads/{upload['id']}/commit")
    with factory() as db:
        assert usage.attribution_ready(db, "tenant-a")
        db.get(UsageUpload, upload["id"]).attributed = False  # As committed before attribution.
        db.commit()
        assert not usage.attribution_ready(db, "tenant-a")


# Identity needed access and dormancy


def node(node_id, kind):
    return Node(id=node_id, type=kind, name=node_id)


def edge(source, target, kind=EdgeType.READ):
    actions = ["sts:AssumeRole"] if kind == EdgeType.ASSUMES else ["s3:GetObject"]
    return Edge(source=source, target=target, type=kind, actions=actions)


def shared_role_graph() -> GraphSnapshot:
    """Three users can assume one busy role; another role is used without attribution."""
    nodes = [node(f"lake:{i}", NodeType.BUCKET) for i in range(4)]
    nodes += [node("role:busy", NodeType.ROLE), node("role:legacy", NodeType.ROLE)]
    nodes += [node(name, NodeType.HUMAN) for name in ("user:alice", "user:bob", "user:idle", "web:app")]
    edges = [edge("role:busy", f"lake:{i}") for i in range(4)] + [edge("role:legacy", "lake:3")]
    edges += [edge(u, "role:busy", EdgeType.ASSUMES) for u in ("user:alice", "user:bob", "user:idle", "web:app")]
    edges += [edge("user:bob", "role:legacy", EdgeType.ASSUMES)]
    return GraphSnapshot(nodes=nodes, edges=edges)


OBSERVED = [
    ("role:busy", "lake:0", "read"),
    ("role:busy", "lake:1", "read"),
    ("role:busy", "lake:2", "read"),
    ("role:legacy", "lake:3", "read"),
    ("user:alice", "role:busy", "assume"),
    ("user:bob", "role:busy", "assume"),
    ("user:bob", "role:legacy", "assume"),
]
SESSIONS = [
    ("user:alice", "role:busy", "lake:0", "read", 5),
    ("user:bob", "role:busy", "lake:1", "read", 5),
    # web:app's session issuance was outside the upload, but its sourceIdentity resolved it.
    ("web:app", "role:busy", "lake:2", "read", 1),
    ("", "role:legacy", "lake:3", "read", 4),  # Never attributed: role-level credit.
    ("service:ecs-tasks.amazonaws.com", "role:busy", "lake:1", "read", 1),
]


def attributed_topics(sessions=SESSIONS, observed=OBSERVED, snapshot=None):
    graph = CompactGraph.from_snapshot(snapshot or shared_role_graph())
    found = match_usage(graph, evidence(("s3", "sts")), observed, sessions=sessions)
    return graph, found, compute_topics(graph, found)


def identity(result, graph, entity):
    return result.identities[graph.index[entity]]


def test_identity_needed_access_is_its_own_attributed_use():
    graph, found, result = attributed_topics()
    assert found.attribution_ready
    assert found.role_attributed(graph.index["role:busy"])
    assert not found.role_attributed(graph.index["role:legacy"])
    alice, bob = identity(result, graph, "user:alice"), identity(result, graph, "user:bob")
    # Each lake asset is internal (weight 2); alice used only lake:0 in her sessions.
    assert (alice["needed_weight"], alice["used_resources"], alice["reach_weight"]) == (2, 1, 8)
    assert alice["flags"] & ATTRIBUTED and not alice["flags"] & ROLE_LEVEL
    # bob: lake:1 attributed, plus role-level credit of the unattributed legacy role (lake:3).
    assert (bob["needed_weight"], bob["used_resources"]) == (4, 2)
    assert bob["flags"] & ROLE_LEVEL and not bob["flags"] & ATTRIBUTED
    # An identity that never assumed the busy role is dormant; one with only attributed use is not.
    idle, web = identity(result, graph, "user:idle"), identity(result, graph, "web:app")
    assert idle["dormant"] and idle["flags"] & DORMANT
    assert not web["dormant"] and web["needed_weight"] == 2
    summary = result.summary["privilege"]["attribution"]
    assert summary["ready"] and summary["roles_attributed"] == 1 and summary["identities_role_level"] == 1
    # Role-level credit only (before attribution): alice is credited with the whole role's use.
    graph, _, before = attributed_topics(sessions=None)
    alice_before = identity(before, graph, "user:alice")
    assert alice_before["needed_weight"] == 6 and alice_before["flags"] & ROLE_LEVEL
    assert identity(before, graph, "web:app")["dormant"]


def test_role_attribution_coverage_threshold_falls_back_to_role_level():
    # 10% of the busy role's session events are unattributed: below the 95% share.
    sessions = [*SESSIONS, ("", "role:busy", "lake:2", "read", 2)]
    graph, found, result = attributed_topics(sessions=sessions)
    assert not found.role_attributed(graph.index["role:busy"])
    alice = identity(result, graph, "user:alice")
    assert alice["needed_weight"] == 6 and alice["flags"] & ROLE_LEVEL
    # Roles keep role-level needed access either way.
    assert result.roles[graph.index["role:busy"]]["needed_weight"] == 6


def test_attribution_matches_the_brute_force_reference():
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    from qualify_usage import reference_privilege

    snapshot = shared_role_graph()
    graph, found, result = attributed_topics(snapshot=snapshot)
    topic_of = {
        graph.ids[n]: (result.topics[row["topic"]].id if row["topic"] >= 0 else None)
        for rows in (result.roles, result.identities)
        for n, row in rows.items()
    }
    reference = reference_privilege(
        snapshot, OBSERVED, {"s3", "sts"}, topic_of, set(), found.peer_share, sessions=SESSIONS
    )
    for rows in (result.roles, result.identities):
        for n, row in rows.items():
            expected = reference[graph.ids[n]]
            assert (row["needed_weight"], row["needed_weight_excl_hubs"], row["dormant"]) == (
                expected["needed"],
                expected["needed_core"],
                expected["dormant"],
            ), graph.ids[n]


# Proposals


def test_never_assumed_role_is_a_manual_trust_proposal():
    snapshot = shared_role_graph()
    snapshot.edges.append(edge("user:alice", "role:legacy", EdgeType.ASSUMES))
    graph, _, result = attributed_topics(snapshot=snapshot)
    proposed = compute_proposals(result)
    pairs = {
        (graph.ids[p.subject], graph.ids[p.target]): p
        for p in proposed.proposals
        if TYPES[p.kind] == "remove_assumption"
    }
    # alice never assumed the legacy role; bob and web:app used what they can assume; idle is
    # disabled as a whole instead.
    assert set(pairs) == {("user:alice", "role:legacy")}
    found = pairs[("user:alice", "role:legacy")]
    assert found.tier == MANUAL and "trust" in found.reasons and found.cuts
    assert found.detail["attribution"] == "role_level" and found.detail["role_used_by_others"]
    disabled = [p for p in proposed.proposals if TYPES[p.kind] == "disable_identity"]
    assert [graph.ids[p.subject] for p in disabled] == ["user:idle"]
    assert disabled[0].detail["attribution"] == "attributed" and disabled[0].detail["roles_used_by_others"] == 1
    assert check_invariant(result, proposed.proposals) == []
    # Without attribution there is no never-assumed proposal (identities are credited per role).
    graph, _, before = attributed_topics(sessions=None, snapshot=snapshot)
    assert not [p for p in compute_proposals(before).proposals if TYPES[p.kind] == "remove_assumption"]


def test_planted_sessions_attribute_each_identity_its_planned_use():
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    from qualify_scale import attribution_plan, cloudtrail_records, generate_topics, plant_never_assumed

    snapshot, truth, planted = generate_topics(3000, seed=11)
    pairs = plant_never_assumed(snapshot, truth, planted)
    assert pairs and all(role not in planted["identity_role_used"].get(i, ()) for i, role in pairs)
    begin, end = NOW - timedelta(days=91), NOW - timedelta(days=1)
    result = normalize_export(list(cloudtrail_records(snapshot, planted, begin, end)), begin, end)
    roots = resolve_sessions({key: Issuance(*row[:6]) for key, row in result.issued.items()})
    plan = attribution_plan(planted)
    got: dict = {}
    unattributed = set()
    for (role, key, _, _, _, resource, action_class, _), _ in result.sessions.items():
        if action_class == "assume":
            continue
        if key in roots:
            got.setdefault(roots[key][0], {}).setdefault(role, set()).add(resource)
        else:
            unattributed.add(role)
    expected = {i: {r: set(items) for r, items in roles.items()} for i, roles in plan["identity_data_used"].items()}
    services = {r: set(planted["role_data_used"][r]) for r in plan["service_roles"]}
    assert got.pop("service:ecs-tasks.amazonaws.com", {}) == services
    assert got == expected
    assert unattributed == set(plan["unattributed_roles"])
