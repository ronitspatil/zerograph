"""Optimizer rollout: Resource scoping and its re-evaluation, CloudTrail AccessDenied capture,
multi-file GitOps reviews and compare-and-swap reverts against a local fake provider (no
network), and the rollout API end to end: diff correctness and the re-ingest round trip,
canary gating, byte-for-byte revert and the AccessDenied watch."""

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.collectors.cloudtrail import normalize_export
from app.core.auth import Actor, current_actor
from app.db.models import (
    AccessDenial,
    AuditEvent,
    Remediation,
    RevisionPolicy,
    RevisionPolicyDocument,
    RolloutChange,
    TenantState,
)
from app.graph import proposals as P
from app.graph.schema import canonical_policy
from app.remediation import rollout
from app.remediation.gitops_sync import FileChange, GitOpsClient, GitOpsConflict, GitOpsError
from app.remediation.policy_optimizer import DENY_ALL, render, scope_policy, verify_scope

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import fake_git  # noqa: E402
from qualify_scale import cloudtrail_files, generate_topics, plant_role_policies  # noqa: E402
from rollout_reference import actual_after, expected_after, round_trip, verify_diffs  # noqa: E402

NOW = datetime.now(UTC).replace(microsecond=0)
A, B, C = "arn:aws:s3:::a", "arn:aws:s3:::b", "arn:aws:s3:::c"


def doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


# ---------------------------------------------------------------------------
# Resource scoping


def test_scope_drops_exact_and_object_entries_and_whole_statements():
    original = doc(
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": [A, A + "/*", B]},
        {"Effect": "Allow", "Action": "s3:PutObject", "Resource": A + "/*"},
        {"Effect": "Allow", "Action": "logs:CreateLogStream", "Resource": "*"},
        {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},
    )
    snapshot = json.dumps(original)
    result = scope_policy(original, {A: ["s3:GetObject", "s3:PutObject"]}, keep=[B])
    assert json.dumps(original) == snapshot  # input never mutated
    assert result.unresolved == {} and result.statements_removed == 1
    assert result.removed == {A: [A, A + "/*", A + "/*"]}
    assert result.optimized["Statement"] == [
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": [B]},
        original["Statement"][2],
        original["Statement"][3],
    ]
    assert verify_scope("p", [original], [result.optimized], {A: ["s3:GetObject"]}, {B: []}) == []


@pytest.mark.parametrize(
    "statement,reason",
    [
        ({"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::*"}, "pattern"),
        ({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}, "pattern"),
        ({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::${aws:username}"}, "pattern"),
        ({"Effect": "Allow", "Action": "s3:GetObject", "Resource": [A], "Condition": {"Bool": {"x": "y"}}}, "Condition"),
        ({"Effect": "Allow", "NotAction": "iam:*", "Resource": [A]}, "Condition/NotAction"),
        ({"Effect": "Allow", "Action": "s3:GetObject", "NotResource": [B]}, "NotResource"),
    ],
)  # fmt: skip
def test_unscopable_grants_stay_manual_and_unchanged(statement, reason):
    original = doc(statement, {"Effect": "Allow", "Action": "s3:GetObject", "Resource": [C]})
    result = scope_policy(original, {A: ["s3:GetObject"]})
    assert A in result.unresolved and (reason in result.unresolved[A] or "pattern" in result.unresolved[A])
    assert result.optimized is None and result.removed == {}


def test_entry_covering_a_kept_resource_and_empty_policy_are_manual():
    covering = doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": [A + "/*", B]})
    assert "kept resource" in scope_policy(covering, {A: ["s3:GetObject"]}, keep=[A + "/x"]).unresolved[A]
    original = doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": [A]})
    emptied = scope_policy(original, {A: ["s3:GetObject"]})
    assert emptied.empty and emptied.optimized is None
    # A string Resource stays a string; a single statement stays a single statement.
    single = {
        "Version": "2012-10-17",
        "Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": [A, B]},
    }
    scoped = scope_policy(single, {B: ["s3:GetObject"]})
    assert scoped.optimized["Statement"] == {"Effect": "Allow", "Action": "s3:GetObject", "Resource": [A]}


def test_verify_scope_catches_widening_and_unchanged_removals():
    before = [doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": [A, B]})]
    wider = [doc({"Effect": "Allow", "Action": "s3:*", "Resource": [B, C]})]
    problems = verify_scope("p", before, wider, {A: ["s3:GetObject"]}, {B: []})
    assert not any(p.startswith("still granted") for p in problems)
    assert verify_scope("p", before, before, {A: ["s3:GetObject"]}, {B: []})[0].startswith("still granted")
    narrowed = [doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": [A]})]
    assert verify_scope("p", before, narrowed, {}, {B: []})[0].startswith("changed")


def test_cloudtrail_denials_are_counted_per_principal_and_resource_never_as_use():
    role = "arn:aws:iam::1:role/r"

    def event(name, code=None, bucket="arn:aws:s3:::x"):
        record = {
            "eventSource": "s3.amazonaws.com",
            "eventName": name,
            "eventTime": (NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "userIdentity": {"type": "AssumedRole", "sessionContext": {"sessionIssuer": {"arn": role}}},
            "requestParameters": {"bucketName": "x"},
            "resources": [{"type": "AWS::S3::Bucket", "ARN": bucket}],
        }
        if code:
            record["errorCode"] = code
        return record

    result = normalize_export(
        [event("GetObject", "AccessDenied"), event("GetObject", "AccessDenied"), event("PutObject")],
        NOW - timedelta(days=1),
        NOW,
    )
    assert result.denied == 2 and result.matched == 1
    assert result.denied_access == {
        (role, "arn:aws:s3:::x", "s3", "AccessDenied"): [
            NOW - timedelta(hours=1),
            NOW - timedelta(hours=1),
            2,
        ]
    }
    assert all("x" not in key[1] or key[2] == "write" for key in result.access)  # denied never use
    assert result.stats()["denied_pairs"] == 1


# ---------------------------------------------------------------------------
# GitOps multi-file reviews and reverts (local fake provider)

TENANT_KEY = "b" * 16


def files_v1():
    return [
        FileChange("role-1/inline-a.json", render(doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": [B]}))),
        FileChange("role-1/ZeroGraphDisable.json", render(DENY_ALL)),
    ]  # fmt: skip


@pytest.mark.parametrize("provider", ["github", "gitlab"])
def test_change_then_revert_restores_original_bytes(provider):
    repo = fake_git.FakeRepository(provider)
    change_id = str(uuid4())
    client = lambda: GitOpsClient(fake_git.settings(provider), repo.transport())  # noqa: E731
    first = client().open_change(change_id, TENANT_KEY, files_v1(), "t", "body")
    writes = len(repo.writes)
    assert client().open_change(change_id, TENANT_KEY, files_v1(), "t", "body") == first
    assert len(repo.writes) == writes  # retry reuses everything
    assert repo.review(1)["draft"] and not repo.review(1)["_merged"]
    root = f"security/zerograph/{TENANT_KEY}/{change_id}"
    assert repo.file(root + "/role-1/inline-a.json") is None  # nothing reaches the base until a person merges
    repo.merge(1)
    original = render(doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": [A, B]}))
    revert = [
        FileChange("role-1/inline-a.json", original, expected=files_v1()[0].content),
        FileChange("role-1/ZeroGraphDisable.json", None, expected=files_v1()[1].content),
    ]
    pr = client().open_change(change_id, TENANT_KEY, revert, "revert", "body", purpose="revert")
    assert (
        pr.branch.endswith("-revert")
        and client().open_change(change_id, TENANT_KEY, revert, "revert", "body", purpose="revert") == pr
    )
    repo.merge(2)
    assert repo.file(root + "/role-1/inline-a.json") == original.encode()
    assert repo.file(root + "/role-1/ZeroGraphDisable.json") is None


@pytest.mark.parametrize("provider", ["github", "gitlab"])
def test_revert_refuses_a_file_changed_after_merge_and_spoofed_markers(provider):
    repo = fake_git.FakeRepository(provider)
    change_id = str(uuid4())
    client = lambda: GitOpsClient(fake_git.settings(provider), repo.transport())  # noqa: E731
    client().open_change(change_id, TENANT_KEY, files_v1(), "t", "<!-- zerograph:fake --> body")
    assert "&lt;!-- zerograph:fake" in repo.review(1)["body"]
    repo.merge(1)
    path = f"security/zerograph/{TENANT_KEY}/{change_id}/role-1/inline-a.json"
    repo.branches["main"]["tree"][path] = b"edited by a person\n"
    writes = len(repo.writes)
    revert = [FileChange("role-1/inline-a.json", "{}\n", expected=files_v1()[0].content)]
    with pytest.raises(GitOpsConflict, match="changed since"):
        client().open_change(change_id, TENANT_KEY, revert, "r", "b", purpose="revert")
    assert (
        len([w for w in repo.writes[writes:] if "/contents/" in w.url.path or "/files/" in w.url.path]) == 0
    )


@pytest.mark.parametrize(
    "files,purpose",
    [
        ([FileChange("../escape.json", "{}")], "change"),
        ([FileChange(".github/workflows/x.json", "{}")], "change"),
        ([FileChange("a.yaml", "{}")], "change"),
        ([FileChange("a.json", None)], "change"),
        ([FileChange("a.json", "{}")], "revert"),
        ([], "change"),
        ([FileChange(f"f{i}.json", "{}") for i in range(41)], "change"),
    ],
)
def test_change_scope_rejects_unsafe_files(files, purpose):
    remote = fake_git.FakeRepository()
    client = GitOpsClient(fake_git.settings(), remote.transport())
    with pytest.raises(GitOpsError):
        client.change_scope(str(uuid4()), TENANT_KEY, files, purpose)
    with pytest.raises(GitOpsError):
        GitOpsClient(fake_git.settings(), remote.transport()).open_change(
            str(uuid4()), TENANT_KEY, files, "t", "b", purpose
        )
    assert not remote.requests


def test_provider_errors_never_expose_the_token():
    import httpx

    def handler(_request):
        return httpx.Response(401, json={"message": "secret-token-value"})

    with pytest.raises(GitOpsError) as error:
        GitOpsClient(fake_git.settings(), httpx.MockTransport(handler)).open_change(
            str(uuid4()), TENANT_KEY, files_v1(), "t", "b"
        )
    assert "secret" not in str(error.value)


# ---------------------------------------------------------------------------
# API end to end (in-memory graph, SQLite, local fake provider)


@pytest.fixture
def repo(client, monkeypatch):
    from app.api import routes

    found = fake_git.FakeRepository()
    config = fake_git.settings()
    monkeypatch.setattr(routes, "get_settings", lambda: config)
    real = routes.GitOpsClient
    monkeypatch.setattr(routes, "GitOpsClient", lambda settings: real(settings, found.transport()))
    return found


def publish(client, snapshot):
    from test_proposals import publish as publish_snapshot

    publish_snapshot(client, snapshot)


def planted_environment(client, size=2000):
    from test_privilege import upload_usage

    from app.graph.topics import backfill_missing

    snapshot, truth, usage = generate_topics(size, seed=11)
    planted = plant_role_policies(snapshot, truth)
    assert planted > 0
    publish(client, snapshot)
    upload_usage(client, snapshot, usage)
    backfill_missing()
    return snapshot, truth, usage


def high_by_subject(client):
    rows = []
    cursor = None
    while True:
        params = {"tier": "high", "limit": 200}
        if cursor is not None:
            params["cursor"] = cursor
        page = client.get("/api/v1/proposals", params=params).json()
        rows += page["proposals"]
        cursor = page["view"]["next_cursor"]
        if cursor is None:
            break
    found: dict[str, list[dict]] = {}
    for row in rows:
        found.setdefault(row["subject_id"], []).append(row)
    return rows, found


def accept(client, proposals):
    for proposal in proposals:
        assert (
            client.post(
                f"/api/v1/proposals/{proposal['id']}/decision", json={"state": "accepted"}
            ).status_code
            == 200
        )


def denied_upload(client, events):
    end = NOW
    created = client.post(
        "/api/v1/usage/uploads",
        json={
            "window_start": (end - timedelta(days=2)).isoformat(),
            "window_end": end.isoformat(),
            "attested_services": ["s3"],
        },
    ).json()
    for number, body in enumerate(cloudtrail_files(events, 1000)):
        assert (
            client.put(f"/api/v1/usage/uploads/{created['id']}/files/{number}", content=body).status_code
            == 200
        )
    return client.post(f"/api/v1/usage/uploads/{created['id']}/commit").json()


def denial(role, bucket, when):
    return {
        "eventVersion": "1.09",
        "eventSource": "s3.amazonaws.com",
        "eventName": "GetObject",
        "eventTime": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "awsRegion": "us-east-1",
        "userIdentity": {
            "type": "AssumedRole",
            "arn": "arn:aws:sts::123456789012:assumed-role/r/s",
            "sessionContext": {"sessionIssuer": {"type": "Role", "arn": role}},
        },
        "requestParameters": {"bucketName": bucket, "key": "k"},
        "resources": [{"type": "AWS::S3::Bucket", "ARN": bucket}],
        "errorCode": "AccessDenied",
        "errorMessage": "Access Denied",
        "recipientAccountId": "123456789012",
    }


def test_rollout_api_canary_revert_and_access_denied(client, environment, repo):  # noqa: C901
    factory, _ = environment
    snapshot, _, _ = planted_environment(client)
    rows, by_subject = high_by_subject(client)
    removals = {s: [p for p in ps if p["type"] == "remove_grant"] for s, ps in by_subject.items()}
    # Two roles of one topic with removals on buckets (for AccessDenied), one role of another topic.
    kinds = {node.id: node.type.value for node in snapshot.nodes}
    by_topic: dict[str, list[str]] = {}
    for subject, found in sorted(removals.items()):
        if (
            found
            and kinds[subject] == "CloudRole"
            and any(kinds[p["target_id"]] == "S3Bucket" for p in found)
        ):
            by_topic.setdefault(found[0]["topic_id"], []).append(subject)
    topics = sorted(by_topic, key=lambda t: (-len(by_topic[t]), t))
    topic, other = topics[0], topics[1]
    first, second = by_topic[topic][:2]
    third = by_topic[other][0]
    for subject in (first, second, third):
        accept(client, removals[subject])

    # Viewers and analysts cannot create changes; analysts may preview.
    client.app.dependency_overrides[current_actor] = lambda: Actor("v", "tenant-a", frozenset({"viewer"}))
    assert client.post("/api/v1/rollout/changes", json={"subject_id": first}).status_code == 403
    assert client.post("/api/v1/rollout/plan", json={"subject_id": first}).status_code == 403
    assert client.get("/api/v1/rollout").status_code == 200
    client.app.dependency_overrides[current_actor] = lambda: Actor(
        "alice", "tenant-a", frozenset({"admin", "analyst", "viewer"})
    )
    plan = client.post("/api/v1/rollout/plan", json={"subject_id": first}).json()
    assert plan["eligible"] and plan["gate"] == "Becomes the topic's canary"
    assert set(plan["proposal_ids"]) == {p["id"] for p in removals[first]}
    assert all(f["op"] == "rewrite" and f["diff"].count("\n-") >= 1 for f in plan["files"])
    assert (
        client.post("/api/v1/rollout/plan", json={"subject_id": first, "topic_id": topic}).status_code == 422
    )

    created = {}
    for subject in (first, second, third):
        response = client.post("/api/v1/rollout/changes", json={"subject_id": subject})
        assert response.status_code == 201, response.text
        created[subject] = response.json()
        assert created[subject]["state"] == "draft" and created[subject]["simulation"]["assets_removed"] >= 1
    # The same proposals cannot be taken twice.
    assert client.post("/api/v1/rollout/changes", json={"subject_id": first}).status_code == 409
    canary = created[first]["id"]
    opened = client.post(f"/api/v1/rollout/changes/{canary}/pr")
    assert opened.status_code == 200, opened.text
    assert opened.json() == {"url": "https://github.com/acme/policies/pull/1", "state": "pr_open"}
    assert client.post(f"/api/v1/rollout/changes/{canary}/pr").json()["url"] == opened.json()["url"]
    # Non-canary changes of the topic are held until the canary is verified; a bundle too.
    held = client.post(f"/api/v1/rollout/changes/{created[second]['id']}/pr")
    assert held.status_code == 409 and "Waiting for canary" in held.json()["detail"]
    listed = {c["id"]: c for c in client.get("/api/v1/rollout").json()["changes"]}
    assert listed[created[second]["id"]]["held"] and listed[canary]["canary"]
    assert len(repo.reviews) == 1
    body = repo.review(1)["body"]
    for section in (
        "Proposals included",
        "Evidence",
        "Excess privilege",
        "Simulation",
        "Canary plan",
        "Revert",
    ):
        assert f"### {section}" in body
    assert "**canary**" in body and "Nothing is applied by ZeroGraph" in body

    # Revert of a change whose PR is not merged is refused (close the PR instead).
    assert client.post(f"/api/v1/rollout/changes/{canary}/revert", json={}).status_code == 409
    # A person merges in the repository; the canary watch starts.
    repo.merge(1)
    merged = client.post(f"/api/v1/rollout/changes/{canary}/merged").json()
    assert merged["state"] == "merged" and 6.9 < merged["watch_remaining_days"] <= 7
    assert client.post(f"/api/v1/rollout/changes/{created[second]['id']}/pr").status_code == 409
    with factory() as db:
        change = db.get(RolloutChange, canary)
        change.merged_at = NOW - timedelta(days=8)
        db.commit()
    listed = {c["id"]: c for c in client.get("/api/v1/rollout").json()["changes"]}
    assert listed[canary]["state"] == "verified"
    widened = client.post(f"/api/v1/rollout/changes/{created[second]['id']}/pr")
    assert widened.status_code == 200 and widened.json()["state"] == "pr_open"
    assert "widens the rollout" in repo.review(2)["body"]

    # Byte-for-byte revert of the canary from Remediation.original.
    reverted = client.post(f"/api/v1/rollout/changes/{canary}/revert", json={"reason": "test"})
    assert reverted.status_code == 200 and reverted.json()["state"] == "revert_open"
    revert_review = len(repo.reviews)
    assert not repo.review(revert_review)["_merged"]
    repo.merge(revert_review)
    with factory() as db:
        change = db.get(RolloutChange, canary)
        revision = change.revision
        for item in change.files:
            record = db.get(Remediation, item["remediation_id"])
            path = f"security/zerograph/{rollout_key()}/{canary}/{item['path']}"
            restored = repo.file(path)
            stored = db.scalar(
                select(RevisionPolicyDocument.document)
                .join(
                    RevisionPolicy,
                    (RevisionPolicy.digest == RevisionPolicyDocument.digest)
                    & (RevisionPolicy.revision == RevisionPolicyDocument.revision),
                )
                .where(
                    RevisionPolicy.revision == revision,
                    RevisionPolicy.principal_id == item["principal"],
                    RevisionPolicy.name == item["policy_name"],
                )
            )
            assert restored == render(record.original).encode()
            assert canonical_policy(json.loads(restored)) == stored  # the stored document, byte for byte
    assert client.post(f"/api/v1/rollout/changes/{canary}/reverted").json()["state"] == "rolled_back"
    # A rolled-back canary no longer counts: the topic's next change becomes its canary.
    assert client.get("/api/v1/rollout").json()["canaries"][topic] is None

    # AccessDenied watch: the other topic's canary is merged, then denials on what it removed.
    other_canary = created[third]["id"]
    assert client.post(f"/api/v1/rollout/changes/{other_canary}/pr").status_code == 200
    client.post(f"/api/v1/rollout/changes/{other_canary}/merged")
    with factory() as db:
        db.get(RolloutChange, other_canary).merged_at = NOW - timedelta(hours=3)
        db.commit()
    touched = created[third]
    bucket = next(
        p["target_id"]
        for p in removals[third]
        if kinds[p["target_id"]] == "S3Bucket" and p["id"] in touched["proposal_ids"]
    )
    untouched = next(n.id for n in snapshot.nodes if n.type.value == "S3Bucket")
    before = len(repo.reviews)
    quiet = denied_upload(
        client,
        [denial(third, bucket, NOW - timedelta(hours=5)), denial(third, untouched, NOW - timedelta(hours=1))]
        if untouched != bucket
        else [denial(third, bucket, NOW - timedelta(hours=5))],
    )
    assert quiet["rollout"] == {"flagged": [], "reverts": []}  # before the merge, or not touched
    noisy = denied_upload(client, [denial(third, bucket, NOW - timedelta(hours=1))] * 2)
    assert noisy["rollout"]["flagged"] == [other_canary]
    assert noisy["rollout"]["reverts"][0]["url"].startswith("https://github.com/acme/policies/pull/")
    assert len(repo.reviews) == before + 1 and not repo.reviews[-1]["_merged"] and repo.reviews[-1]["draft"]
    with factory() as db:
        change = db.get(RolloutChange, other_canary)
        assert change.state == "revert_open" and change.flag["events"] == 2
        assert db.query(AccessDenial).count() >= 3
        events = {
            (e.actor, e.action)
            for e in db.scalars(select(AuditEvent).where(AuditEvent.action.like("rollout.%")))
        }
    assert (rollout.HOOK_ACTOR, "rollout.flagged") in events
    assert (rollout.HOOK_ACTOR, "rollout.revert_opened") in events
    for action in ("rollout.created", "rollout.pr_requested", "rollout.pr_opened", "rollout.merged",
                   "rollout.verified", "rollout.revert_requested", "rollout.rolled_back"):  # fmt: skip
        assert action in {a for _, a in events}
    # Never merged, closed or force-pushed by ZeroGraph; never wrote to the base branch.
    assert all(not r.url.path.endswith("/merge") for r in repo.requests)
    # The legacy single-policy PR route refuses rollout remediations.
    with factory() as db:
        record_id = db.get(RolloutChange, other_canary).remediation_ids[0]
    assert client.post(f"/api/v1/remediations/{record_id}/pr").status_code == 409


def rollout_key():
    import hashlib

    return hashlib.sha256(b"tenant-a").hexdigest()[:16]


def test_drafts_disables_bundles_and_discard(client, environment, repo):
    factory, _ = environment
    snapshot, _, _ = planted_environment(client)
    rows, by_subject = high_by_subject(client)
    disable = next(r for r in rows if r["type"] == "disable_identity" and r["subject_type"] == "HumanUser")
    accept(client, [disable])
    response = client.post("/api/v1/rollout/changes", json={"subject_id": disable["subject_id"]})
    assert response.status_code == 201, response.text
    change = response.json()
    assert [f["op"] for f in change["files"]] == ["add"] and change["files"][0][
        "policy_name"
    ] == "ZeroGraphDisable"
    with factory() as db:
        record = db.get(Remediation, change["files"][0]["remediation_id"])
        assert record.original == {} and record.optimized == DENY_ALL and record.status == "rollout"
    # Manual and structural proposals are draft only, with a reason and text.
    manual = client.get("/api/v1/proposals", params={"tier": "manual", "limit": 50}).json()["proposals"]
    merge = next(p for p in manual if p["type"] == "merge_roles")
    draft = client.get(f"/api/v1/proposals/{merge['id']}/draft").json()
    assert not draft["pr_eligible"] and "Merge role" in draft["text"] and "never delete" in draft["text"]
    eligible = client.get(f"/api/v1/proposals/{disable['id']}/draft").json()
    assert eligible["pr_eligible"] and eligible["change_id"] == change["id"]
    accept(client, [merge])
    assert client.post("/api/v1/rollout/changes", json={"subject_id": merge["subject_id"]}).status_code == 409
    # A topic bundle waits for a verified single-role canary.
    topic = disable["topic_id"]
    accept(client, [r for r in rows if r["topic_id"] == topic and r["type"] == "remove_grant"][:30])
    bundle = client.post("/api/v1/rollout/changes", json={"topic_id": topic})
    assert bundle.status_code == 201, bundle.text
    assert bundle.json()["scope"] == "topic" and len(bundle.json()["principals"]) >= 2
    refused = client.post(f"/api/v1/rollout/changes/{bundle.json()['id']}/pr")
    assert refused.status_code == 409
    # Discard frees the proposals and removes the remediation records.
    assert client.delete(f"/api/v1/rollout/changes/{bundle.json()['id']}").status_code == 204
    with factory() as db:
        assert db.get(RolloutChange, bundle.json()["id"]) is None
    assert client.post("/api/v1/rollout/changes", json={"topic_id": topic}).status_code == 201
    # GitOps not configured for this tenant: 403, nothing sent.
    from app.api import routes

    config = fake_git.settings(tenant="someone-else")
    routes.get_settings = lambda: config  # restored by monkeypatch teardown of the repo fixture
    assert client.post(f"/api/v1/rollout/changes/{change['id']}/pr").status_code == 403
    assert not repo.writes


def test_diff_correctness_and_reingest_round_trip(client, environment):
    """Every accepted eligible high-tier proposal: the generated diffs re-evaluate to exactly the
    target grants, and re-ingesting the applied snapshot reproduces the what-if graph."""
    factory, _ = environment
    snapshot, _, _ = planted_environment(client)
    rows, by_subject = high_by_subject(client)
    eligible = [r for r in rows if r["type"] in ("remove_grant", "disable_role", "disable_identity")]
    accept(client, eligible)
    with factory() as db:
        revision = db.get(TenantState, "tenant-a").revision
        model = P.load_model(db, "tenant-a", revision)
        files, optimized, included, drafts = [], {}, [], []
        for subject in sorted({r["subject_id"] for r in eligible}):
            plan = rollout.plan_change(db, "tenant-a", revision, model, subject=subject)
            for planned in plan.files:
                item = planned.as_dict()
                item["path"] = f"{subject}/{item['path']}"
                files.append(item)
                optimized[item["path"]] = planned.optimized
            included += plan.included
            drafts += plan.drafts
    removed: dict[str, set[str]] = {}
    disabled = set()
    for row in included:
        if row.type in rollout.DISABLE_TYPES:
            disabled.add(row.subject_id)
        else:
            removed.setdefault(row.subject_id, set()).add(row.target_id)
    assert len(included) >= 300 and sum(len(v) for v in removed.values()) >= 200 and disabled
    probes = [n.id for n in snapshot.nodes if n.type.value in ("S3Bucket", "Database", "VectorStore")][:25]
    stats = verify_diffs(snapshot, files, optimized, removed, disabled, probes)
    assert stats["mismatches"] == [] and stats["widened"] == []
    assert stats["removed_edges"] >= sum(len(v) for v in removed.values())
    expected = expected_after(model, [row.ordinal for row in included])
    publish(client, round_trip(snapshot, files, optimized))
    with factory() as db:
        later = db.get(TenantState, "tenant-a").revision
        assert later != revision
        after = actual_after(P.load_model(db, "tenant-a", later))
    assert after[0] == expected[0]
    assert set(after[1]) == set(expected[1]) and all(after[1][k] == expected[1][k] for k in expected[1])
