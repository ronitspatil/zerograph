"""AWS collector enrichment (optimizer Phase 2): raw tags, RoleLastUsed, policy documents,
IAM users and groups, Access Advisor hints, bounds, and per-revision policy storage.

Every AWS response is a stub (Mock or botocore Stubber with synthetic credentials);
nothing here reaches AWS.
"""

import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime
from unittest.mock import Mock, patch

import pytest
from botocore.exceptions import ClientError
from sqlalchemy import func, select

from app.collectors.aws_collector import AWSCollector, CollectionIncomplete, CollectionLimits
from app.collectors.tasks import process_job
from app.db.models import RevisionPolicy, RevisionPolicyDocument, TenantState
from app.graph.schema import GraphSnapshot, Node, NodeType, PolicyAttachment, canonical_policy

ACCOUNT = "123456789012"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/lake-reader"
ADMIN = f"arn:aws:iam::{ACCOUNT}:role/admin"
USER = f"arn:aws:iam::{ACCOUNT}:user/alice"
GROUP = f"arn:aws:iam::{ACCOUNT}:group/analysts"
MANAGED = f"arn:aws:iam::{ACCOUNT}:policy/lake-read"
BOUNDARY = f"arn:aws:iam::{ACCOUNT}:policy/boundary"
READ_LAKE = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::lake-*"}]}
ASSUME_ADMIN = {"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": ADMIN}]}
EVERYTHING = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


def error(code):
    return ClientError({"Error": {"Code": code, "Message": "redacted"}}, "test")


def inventory():
    return {
        "IsTruncated": False,
        "RoleDetailList": [
            {
                "Arn": ROLE,
                "RoleName": "lake-reader",
                "RolePolicyList": [{"PolicyName": "inline-read", "PolicyDocument": READ_LAKE}],
                "AttachedManagedPolicies": [{"PolicyName": "lake-read", "PolicyArn": MANAGED}],
                "PermissionsBoundary": {"PermissionsBoundaryArn": BOUNDARY},
                "AssumeRolePolicyDocument": {"Statement": []},
                "Tags": [{"Key": "topic", "Value": "data-lake"}, {"Key": "team", "Value": "analytics"}],
                "RoleLastUsed": {"LastUsedDate": datetime(2026, 9, 30, tzinfo=UTC), "Region": "us-east-1"},
            },
            {
                "Arn": ADMIN,
                "RoleName": "admin",
                "RolePolicyList": [{"PolicyName": "all", "PolicyDocument": EVERYTHING}],
                "AssumeRolePolicyDocument": {
                    "Statement": [{"Effect": "Allow", "Principal": {"AWS": USER}, "Action": "sts:AssumeRole"}]
                },
            },
        ],
        "UserDetailList": [
            {
                "Arn": USER,
                "UserName": "alice",
                "UserPolicyList": [{"PolicyName": "assume-admin", "PolicyDocument": ASSUME_ADMIN}],
                "GroupList": ["analysts"],
                "Tags": [{"Key": "team", "Value": "analytics"}],
            }
        ],
        "GroupDetailList": [
            {
                "Arn": GROUP,
                "GroupName": "analysts",
                "GroupPolicyList": [{"PolicyName": "group-read", "PolicyDocument": READ_LAKE}],
                "AttachedManagedPolicies": [{"PolicyName": "lake-read", "PolicyArn": MANAGED}],
            }
        ],
    }


def collector(**kwargs):
    iam, s3, sts, org = Mock(), Mock(), Mock(), Mock()
    session = Mock()
    session.client.side_effect = lambda name, **_: {"iam": iam, "s3": s3, "sts": sts, "organizations": org}[
        name
    ]
    sts.get_caller_identity.return_value = {
        "Account": ACCOUNT,
        "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/worker/test",
    }
    org.describe_organization.side_effect = error("AWSOrganizationsNotInUseException")
    iam.get_account_authorization_details.return_value = inventory()
    iam.get_policy.side_effect = lambda PolicyArn: {"Policy": {"DefaultVersionId": "v1"}}
    documents = {
        MANAGED: READ_LAKE,
        BOUNDARY: {"Statement": [{"Effect": "Allow", "Action": ["s3:*", "sts:*"], "Resource": "*"}]},
    }
    iam.get_policy_version.side_effect = lambda PolicyArn, VersionId: {
        "PolicyVersion": {"Document": documents[PolicyArn]}
    }
    s3.list_buckets.return_value = {"Buckets": [{"Name": "lake-raw"}]}
    s3.get_bucket_policy.side_effect = error("NoSuchBucketPolicy")
    s3.get_bucket_tagging.return_value = {
        "TagSet": [
            {"Key": "topic", "Value": "data-lake"},
            {"Key": "classification", "Value": "customer email"},
        ]
    }
    s3.get_bucket_encryption.return_value = {"ServerSideEncryptionConfiguration": {}}
    return AWSCollector(session, **kwargs), iam


def node(snapshot, node_id) -> Node:
    return next(n for n in snapshot.nodes if n.id == node_id)


def test_role_and_bucket_tags_and_role_last_used_are_kept():
    c, _ = collector()
    snapshot = c.collect()
    role = node(snapshot, ROLE)
    assert role.tags == ["team=analytics", "topic=data-lake"]
    assert role.metadata["role_last_used"] == "2026-09-30T00:00:00+00:00"
    assert role.metadata["role_last_used_region"] == "us-east-1"
    assert "role_last_used" not in node(snapshot, ADMIN).metadata
    assert c.coverage["role_last_used"] == {"observed": 1, "absent": 1}
    bucket = node(snapshot, "arn:aws:s3:::lake-raw")
    # Raw tags kept as topic anchors beside classification labels.
    assert "topic=data-lake" in bucket.tags and "classification=customer email" in bucket.tags
    assert "PII" in bucket.tags


def test_policy_documents_are_hashed_attachments_never_node_json():
    c, iam = collector()
    snapshot = c.collect()
    kinds = {(p.principal, p.kind, p.name) for p in snapshot.policies}
    assert {
        (ROLE, "inline", "inline-read"),
        (ROLE, "managed", "lake-read"),
        (ROLE, "boundary", "boundary"),
        (ROLE, "trust", "trust"),
        (USER, "inline", "assume-admin"),
        (USER, "group-inline", "analysts/group-read"),
        (USER, "group-managed", "analysts/lake-read"),
    } <= kinds
    managed = next(p for p in snapshot.policies if p.kind == "managed")
    assert managed.arn == MANAGED
    assert managed.digest == hashlib.sha256(canonical_policy(READ_LAKE).encode()).hexdigest()
    # Identical documents share a digest (stored once per revision).
    inline = next(p for p in snapshot.policies if p.kind == "inline" and p.principal == ROLE)
    assert inline.digest == managed.digest
    # Managed policies are fetched once even when a role and a group attach them.
    assert iam.get_policy.call_count == 2
    for item in snapshot.nodes:
        assert "Statement" not in json.dumps(item.metadata)
    assert c.counts["policy_attachments"] == len(snapshot.policies)


def test_iam_users_are_humans_with_group_policies_folded_in():
    c, _ = collector()
    snapshot = c.collect()
    user = node(snapshot, USER)
    assert user.type == NodeType.HUMAN
    assert user.metadata["iam_user"] is True and user.metadata["groups"] == ["analysts"]
    assert user.tags == ["team=analytics"]
    edges = {(e.source, e.type.value, e.target) for e in snapshot.edges}
    # The read grant comes only from the group's policies; AssumeRole from the user's own policy.
    assert (USER, "CAN_READ", "arn:aws:s3:::lake-raw") in edges
    assert (USER, "ASSUMES_ROLE", ADMIN) in edges
    assert (ROLE, "ASSUMES_ROLE", ADMIN) not in edges  # Trust names only the user.
    assert c.counts["users"] == 1 and c.counts["groups"] == 1
    assert c.coverage["iam_user_inventory_complete"] and c.coverage["iam_group_inventory_complete"]
    assert any("users and groups" in warning for warning in snapshot.warnings)


@pytest.mark.parametrize(
    ("limits", "message"),
    [
        ({"max_users": 1, "max_roles": 2}, "user inventory budget"),
        ({"max_groups": 1}, "group inventory budget"),
        ({"max_policy_attachments": 3}, "attachment budget"),
    ],
)
def test_user_group_and_attachment_bounds_fail_closed(limits, message):
    c, iam = collector(limits=CollectionLimits(**limits))
    details = deepcopy(inventory())
    details["UserDetailList"].append({**details["UserDetailList"][0], "Arn": USER + "2", "UserName": "bob"})
    details["GroupDetailList"].append({**details["GroupDetailList"][0], "Arn": GROUP + "2", "GroupName": "x"})
    iam.get_account_authorization_details.return_value = details
    with pytest.raises(CollectionIncomplete, match=message):
        c.collect()


def test_cross_account_user_and_missing_group_fail_closed():
    c, iam = collector()
    details = deepcopy(inventory())
    details["UserDetailList"][0]["Arn"] = "arn:aws:iam::999999999999:user/alice"
    iam.get_account_authorization_details.return_value = details
    with pytest.raises(CollectionIncomplete, match="user inventory crosses"):
        c.collect()
    c, iam = collector()
    details = deepcopy(inventory())
    details["GroupDetailList"] = []
    iam.get_account_authorization_details.return_value = details
    with pytest.raises(CollectionIncomplete, match="group missing"):
        c.collect()


def test_evaluation_preflight_counts_users():
    c, _ = collector(limits=CollectionLimits(max_evaluations=24))
    # 3 principals x 1 bucket x 6 + 3 principals x 2 roles - 2 = 22 fits; 24 too.
    c.collect()
    c, _ = collector(limits=CollectionLimits(max_evaluations=21))
    with pytest.raises(CollectionIncomplete, match="evaluation budget"):
        c.collect()


def test_access_advisor_is_optional_bounded_and_stored_as_hints():
    c, iam = collector()
    c.collect()
    iam.generate_service_last_accessed_details.assert_not_called()

    sleeps = []
    c, iam = collector(
        access_advisor=True, sleep=sleeps.append, limits=CollectionLimits(max_access_advisor_jobs=2)
    )
    iam.generate_service_last_accessed_details.side_effect = lambda Arn, Granularity: {"JobId": "job-" + Arn}
    polls: dict[str, int] = {}

    def details(JobId, **_):
        polls[JobId] = polls.get(JobId, 0) + 1
        if polls[JobId] == 1:
            return {"JobStatus": "IN_PROGRESS"}
        return {
            "JobStatus": "COMPLETED",
            "IsTruncated": False,
            "ServicesLastAccessed": [
                {"ServiceNamespace": "s3", "LastAuthenticated": datetime(2026, 9, 1, tzinfo=UTC)},
                {"ServiceNamespace": "glue"},
            ],
        }

    iam.get_service_last_accessed_details.side_effect = details
    snapshot = c.collect()
    # Three principals, at most two jobs (sorted ARNs: the admin and lake-reader roles).
    assert iam.generate_service_last_accessed_details.call_count == 2
    assert sleeps == [1.0]
    hint = node(snapshot, ADMIN).metadata["access_advisor"]
    assert hint["basis"] == "access_advisor_activity_hint"
    assert hint["services"][0] == {"service": "s3", "last_authenticated": "2026-09-01T00:00:00+00:00"}
    assert hint["services"][1]["last_authenticated"] == ""
    assert "access_advisor" not in node(snapshot, USER).metadata
    assert c.coverage["access_advisor"] == {"requested": 2, "completed": 2}
    assert any("bounded subset" in warning for warning in snapshot.warnings)
    # Access Advisor calls consume the collector's request budget.
    assert c.requests >= 2 + 4


def test_access_advisor_denial_is_a_warning_not_a_failure():
    c, iam = collector(access_advisor=True, sleep=lambda _: None)
    iam.generate_service_last_accessed_details.side_effect = error("AccessDenied")
    snapshot = c.collect()
    assert any("Access Advisor hints unavailable" in warning for warning in snapshot.warnings)
    assert all("access_advisor" not in n.metadata for n in snapshot.nodes)


def test_botocore_model_accepts_user_group_tag_and_last_used_shapes():
    import boto3
    from botocore.stub import Stubber

    session = boto3.Session(
        aws_access_key_id="synthetic", aws_secret_access_key="synthetic", region_name="us-east-1"
    )
    c = AWSCollector(session)
    sts, iam, s3, org = [Stubber(client) for client in (c.sts, c.iam, c.s3, c.organizations)]
    sts.add_response(
        "get_caller_identity",
        {
            "Account": ACCOUNT,
            "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/worker/test",
            "UserId": "synthetic",
        },
        {},
    )
    created = datetime(2026, 1, 1, tzinfo=UTC)
    iam.add_response(
        "get_account_authorization_details",
        {
            "RoleDetailList": [
                {
                    "Path": "/",
                    "RoleName": "lake-reader",
                    "RoleId": "AROASYNTHETIC123456789",
                    "Arn": ROLE,
                    "CreateDate": created,
                    "AssumeRolePolicyDocument": '{"Statement":[]}',
                    "RolePolicyList": [{"PolicyName": "read", "PolicyDocument": json.dumps(READ_LAKE)}],
                    "Tags": [{"Key": "topic", "Value": "data-lake"}],
                    "RoleLastUsed": {"LastUsedDate": created, "Region": "us-east-1"},
                }
            ],
            "UserDetailList": [
                {
                    "Path": "/",
                    "UserName": "alice",
                    "UserId": "AIDASYNTHETIC123456789",
                    "Arn": USER,
                    "CreateDate": created,
                    "GroupList": ["analysts"],
                    "Tags": [{"Key": "team", "Value": "analytics"}],
                }
            ],
            "GroupDetailList": [
                {
                    "Path": "/",
                    "GroupName": "analysts",
                    "GroupId": "AGPASYNTHETIC123456789",
                    "Arn": GROUP,
                    "CreateDate": created,
                    "GroupPolicyList": [{"PolicyName": "read", "PolicyDocument": json.dumps(READ_LAKE)}],
                }
            ],
            "IsTruncated": False,
        },
        {"Filter": ["Role", "User", "Group"], "MaxItems": 100},
    )
    s3.add_response("list_buckets", {"Buckets": []}, {"MaxBuckets": 100})
    org.add_client_error(
        "describe_organization", service_error_code="AWSOrganizationsNotInUseException", expected_params={}
    )
    with sts, iam, s3, org:
        snapshot = c.collect()
        for stub in (sts, iam, s3, org):
            stub.assert_no_pending_responses()
    assert node(snapshot, ROLE).metadata["role_last_used"].startswith("2026-01-01")
    assert node(snapshot, USER).type == NodeType.HUMAN
    assert {p.kind for p in snapshot.policies} == {"inline", "trust", "group-inline"}


# Per-revision storage of policy documents.


def policy_snapshot() -> GraphSnapshot:
    nodes = [
        Node(id=ROLE, type=NodeType.ROLE, name="lake-reader"),
        Node(id=USER, type=NodeType.HUMAN, name="alice"),
    ]
    policies = [
        PolicyAttachment(principal=ROLE, kind="inline", name="read", document=READ_LAKE),
        PolicyAttachment(principal=ROLE, kind="managed", name="lake-read", arn=MANAGED, document=READ_LAKE),
        PolicyAttachment(principal=USER, kind="group-inline", name="analysts/read", document=ASSUME_ADMIN),
    ]
    return GraphSnapshot(nodes=nodes, policies=policies)


def test_snapshot_rejects_dangling_duplicate_and_oversized_policies():
    nodes = [Node(id=ROLE, type=NodeType.ROLE, name="r")]
    with pytest.raises(ValueError, match="principal must exist"):
        GraphSnapshot(policies=[PolicyAttachment(principal=ROLE, kind="inline", name="a", document={})])
    same = PolicyAttachment(principal=ROLE, kind="inline", name="a", document={})
    with pytest.raises(ValueError, match="Duplicate policy"):
        GraphSnapshot(nodes=nodes, policies=[same, same])
    with pytest.raises(ValueError, match="byte limit"):
        PolicyAttachment(principal=ROLE, kind="inline", name="big", document={"x": "y" * 70000})


def test_published_policies_are_stored_per_revision_deduplicated_and_served(client, environment):
    factory, _ = environment
    with patch("app.api.routes.ingest.delay"):
        job = client.post(
            "/api/v1/ingestions",
            json={"source": "snapshot", "payload": policy_snapshot().model_dump(mode="json")},
        ).json()
    process_job(job["id"])
    with factory() as db:
        revision = db.get(TenantState, "tenant-a").revision
        assert db.scalar(select(func.count()).select_from(RevisionPolicy)) == 3
        # Two distinct documents: the two identical role documents share one row.
        assert db.scalar(select(func.count()).select_from(RevisionPolicyDocument)) == 2
    body = client.get("/api/v1/graph/policies", params={"principal": ROLE}).json()
    assert body["revision"] == revision and not body["truncated"]
    assert [(p["kind"], p["name"]) for p in body["policies"]] == [
        ("inline", "read"),
        ("managed", "lake-read"),
    ]
    assert body["policies"][0]["document"] == READ_LAKE
    assert body["policies"][1]["arn"] == MANAGED
    assert body["policies"][0]["digest"] == body["policies"][1]["digest"]
    assert client.get("/api/v1/graph/policies", params={"principal": "missing"}).json()["policies"] == []
    stale = client.get("/api/v1/graph/policies", params={"principal": ROLE, "revision": "old"})
    assert stale.status_code == 409


def test_policy_lines_upload_through_chunks_and_require_principals(client, environment):
    factory, _ = environment
    lines = [json.dumps({"node": n.model_dump(mode="json")}) for n in policy_snapshot().nodes]
    lines += [json.dumps({"policy": p.model_dump(mode="json")}) for p in policy_snapshot().policies]
    upload = client.post("/api/v1/ingestions/uploads", json={}).json()
    response = client.put(f"/api/v1/ingestions/uploads/{upload['id']}/chunks/0", content="\n".join(lines))
    assert response.status_code == 200
    with patch("app.api.routes.ingest.delay"):
        job = client.post(f"/api/v1/ingestions/uploads/{upload['id']}/commit").json()
    process_job(job["id"])
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(RevisionPolicy)) == 3
    dangling = client.post("/api/v1/ingestions/uploads", json={}).json()
    policy = json.dumps({"policy": policy_snapshot().policies[0].model_dump(mode="json")})
    assert (
        client.put(f"/api/v1/ingestions/uploads/{dangling['id']}/chunks/0", content=policy).status_code == 200
    )
    with patch("app.api.routes.ingest.delay"):
        refused = client.post(f"/api/v1/ingestions/uploads/{dangling['id']}/commit")
    assert refused.status_code == 422


def test_retention_deletes_policy_rows_with_their_revision(environment):
    from app.graph.policies import delete_policies, store_policies

    factory, _ = environment
    rows = [(p.id, json.dumps(p.model_dump(mode="json"))) for p in policy_snapshot().policies]
    with factory() as db:
        assert store_policies(db, "tenant-a", "r1", rows + rows) == 3
        store_policies(db, "tenant-a", "r2", rows)
        db.commit()
        delete_policies(db, "tenant-a", "r1")
        db.commit()
        left = db.execute(select(RevisionPolicy.revision).distinct()).scalars().all()
        assert left == ["r2"]
        assert db.scalar(select(func.count()).select_from(RevisionPolicyDocument)) == 2


def test_revision_policy_byte_budget_fails_publication(environment, monkeypatch):
    from app.graph import policies

    factory, _ = environment
    monkeypatch.setattr(policies, "MAX_REVISION_POLICY_BYTES", 10)
    rows = [(p.id, json.dumps(p.model_dump(mode="json"))) for p in policy_snapshot().policies]
    with factory() as db, pytest.raises(policies.PolicyBudgetExceeded):
        policies.store_policies(db, "tenant-a", "r1", rows)


def test_remediation_preview_accepts_humans_but_not_break_glass(client, environment):
    from datetime import timedelta

    _, graph = environment
    now = datetime.now(UTC)
    snapshot = GraphSnapshot(
        nodes=[
            Node(id=USER, type=NodeType.HUMAN, name="alice"),
            Node(id=USER + "-bg", type=NodeType.HUMAN, name="ops-break-glass"),
            Node(id=USER + "-em", type=NodeType.HUMAN, name="carol", tags=["purpose=emergency"]),
        ]
    )
    graph.publish("tenant-a", "revision-a", snapshot)
    payload = {
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "*"}],
        },
        "usage": {
            "window_start": (now - timedelta(days=100)).isoformat(),
            "window_end": (now - timedelta(days=1)).isoformat(),
            "used_actions": ["s3:GetObject"],
            "covered_services": ["s3"],
            "complete": True,
            "source": "cloudtrail",
        },
    }
    response = client.post("/api/v1/remediations/preview", json={**payload, "identity_id": USER})
    assert response.status_code == 200
    assert response.json()["optimization"]["removed_actions"] == ["s3:PutObject"]
    for identity in (USER + "-bg", USER + "-em"):
        refused = client.post("/api/v1/remediations/preview", json={**payload, "identity_id": identity})
        assert refused.status_code == 409
        assert "manual review" in refused.json()["detail"]
