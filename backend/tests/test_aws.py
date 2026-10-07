from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from app.collectors.aws_collector import AWSCollector

ARN = "arn:aws:iam::123456789012:role/worker"


def error(code):
    return ClientError({"Error": {"Code": code, "Message": "redacted"}}, "test")


def collector():
    iam = Mock()
    s3 = Mock()
    sts = Mock()
    org = Mock()
    session = Mock()
    session.client.side_effect = lambda name, **kwargs: {
        "iam": iam,
        "s3": s3,
        "sts": sts,
        "organizations": org,
    }[name]
    sts.get_caller_identity.return_value = {
        "Account": "123456789012",
        "Arn": "arn:aws:sts::123456789012:assumed-role/worker/test",
    }
    org.describe_organization.side_effect = error("AWSOrganizationsNotInUseException")
    iam.get_account_authorization_details.return_value = {
        "IsTruncated": False,
        "RoleDetailList": [
            {
                "Arn": ARN,
                "RoleName": "worker",
                "RolePolicyList": [
                    {
                        "PolicyDocument": {
                            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
                        }
                    }
                ],
                "AssumeRolePolicyDocument": {"Statement": []},
            }
        ],
    }
    s3.list_buckets.return_value = {"Buckets": [{"Name": "customer-email"}]}
    s3.get_bucket_policy.side_effect = error("NoSuchBucketPolicy")
    s3.get_bucket_tagging.return_value = {"TagSet": [{"Key": "classification", "Value": "patient"}]}
    s3.get_bucket_encryption.return_value = {"ServerSideEncryptionConfiguration": {}}
    return AWSCollector(session), iam, s3, org


def test_live_collector_enriches_metadata_but_does_not_claim_complete_access():
    c, _, _, _ = collector()
    snapshot = c.collect()
    bucket = next(n for n in snapshot.nodes if n.type.value == "S3Bucket")
    # Classification labels plus the raw tag (kept as a topic anchor).
    assert set(bucket.tags) == {"PII", "PHI", "classification=patient"}
    assert snapshot.edges
    assert all(e.certainty == "conditional" for e in snapshot.edges)
    assert any("session" in warning for warning in snapshot.warnings)


def test_bucket_access_denied_is_reported_as_unknown():
    c, _, s3, _ = collector()
    s3.get_bucket_policy.side_effect = error("AccessDenied")
    s3.get_bucket_tagging.side_effect = error("AccessDenied")
    s3.get_bucket_encryption.side_effect = error("AccessDenied")
    snapshot = c.collect()
    assert any("bucket policy unavailable" in w.lower() for w in snapshot.warnings)
    assert any("encryption" in w.lower() for w in snapshot.warnings)
    assert next(n for n in snapshot.nodes if n.type.value == "S3Bucket").encrypted


def test_explicit_deny_does_not_create_permission_edges():
    c, iam, _, _ = collector()
    role = iam.get_account_authorization_details.return_value["RoleDetailList"][0]
    role["RolePolicyList"] = [
        {"PolicyDocument": {"Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}]}}
    ]
    assert c.collect().edges == []


def test_scp_collection_walks_account_ou_and_root():
    c, _, _, org = collector()
    org.describe_organization.side_effect = None
    org.describe_organization.return_value = {"Organization": {"MasterAccountId": "other"}}
    org.list_parents.side_effect = [{"Parents": [{"Id": "ou-1"}]}, {"Parents": [{"Id": "r-1"}]}]
    org.list_policies_for_target.return_value = {"Policies": [{"Id": "p-1"}]}
    org.describe_policy.return_value = {
        "Policy": {"Content": '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'}
    }
    levels, complete = c._organizations("123456789012")
    assert len(levels) == 3
    assert not complete


def test_management_account_not_restricted_by_scp():
    c, _, _, org = collector()
    org.describe_organization.side_effect = None
    org.describe_organization.return_value = {"Organization": {"MasterAccountId": "123456789012"}}
    assert c._organizations("123456789012") == ([], True)


def test_organizations_access_denied_remains_conditional():
    c, _, _, org = collector()
    org.describe_organization.side_effect = error("AccessDeniedException")
    assert c._organizations("123456789012") == ([], False)


def test_iam_access_denied_fails_collection_instead_of_empty_success():
    c, iam, _, _ = collector()
    iam.get_account_authorization_details.side_effect = error("AccessDenied")
    with pytest.raises(ClientError):
        c.collect()


def test_buckets_paginate_and_duplicates_do_not_consume_inventory_budget():
    from app.collectors.aws_collector import CollectionLimits

    c, iam, s3, _ = collector()
    c.limits = CollectionLimits(max_buckets=1, max_roles=1)
    role = iam.get_account_authorization_details.return_value["RoleDetailList"][0]
    iam.get_account_authorization_details.side_effect = [
        {"RoleDetailList": [role], "IsTruncated": True, "Marker": "next"},
        {"RoleDetailList": [role], "IsTruncated": False},
    ]
    s3.list_buckets.side_effect = [
        {"Buckets": [{"Name": "customer-email"}], "ContinuationToken": "next"},
        {"Buckets": [{"Name": "customer-email"}]},
    ]
    snapshot = c.collect()
    assert len(snapshot.nodes) == 2
    assert s3.list_buckets.call_args_list[1].kwargs == {"MaxBuckets": 100, "ContinuationToken": "next"}
    assert iam.get_account_authorization_details.call_args_list[0].kwargs["Filter"] == [
        "Role",
        "User",
        "Group",
    ]
    assert c.counts["roles"] == c.counts["buckets"] == 1
    assert s3.get_bucket_policy.call_count == 1


@pytest.mark.parametrize("domain", ["iam", "s3"])
def test_repeating_tokens_abort_instead_of_publishing_partial_inventory(domain):
    from app.collectors.aws_collector import CollectionIncomplete

    c, iam, s3, _ = collector()
    if domain == "iam":
        iam.get_account_authorization_details.return_value = {
            "RoleDetailList": [],
            "IsTruncated": True,
            "Marker": "loop",
        }
    else:
        s3.list_buckets.return_value = {"Buckets": [], "ContinuationToken": "loop"}
    with pytest.raises(CollectionIncomplete, match="repeated"):
        c.collect()
    s3.get_bucket_policy.assert_not_called()


def test_truncated_page_without_marker_fails_closed():
    from app.collectors.aws_collector import CollectionIncomplete

    c, iam, _, _ = collector()
    iam.get_account_authorization_details.return_value = {"RoleDetailList": [], "IsTruncated": True}
    with pytest.raises(CollectionIncomplete, match="continuation token"):
        c.collect()


def test_conflicting_duplicate_roles_fail_instead_of_last_row_wins():
    from copy import deepcopy

    from app.collectors.aws_collector import CollectionIncomplete

    c, iam, _, _ = collector()
    role = iam.get_account_authorization_details.return_value["RoleDetailList"][0]
    conflicting = deepcopy(role)
    conflicting["RoleName"] = "changed"
    iam.get_account_authorization_details.return_value["RoleDetailList"].append(conflicting)
    with pytest.raises(CollectionIncomplete, match="Conflicting duplicate"):
        c.collect()


def test_evaluation_budget_exhaustion_precedes_metadata_and_policy_requests():
    from app.collectors.aws_collector import CollectionIncomplete, CollectionLimits

    c, iam, s3, org = collector()
    c.limits = CollectionLimits(max_evaluations=1)
    with pytest.raises(CollectionIncomplete, match="evaluation budget"):
        c.collect()
    s3.get_bucket_policy.assert_not_called()
    iam.get_policy.assert_not_called()
    org.describe_organization.assert_not_called()


@pytest.mark.parametrize("kwargs", [{"max_roles": 1}, {"max_buckets": 1}])
def test_inventory_limits_abort_instead_of_truncating(kwargs):
    from copy import deepcopy

    from app.collectors.aws_collector import CollectionIncomplete, CollectionLimits

    c, iam, s3, _ = collector()
    c.limits = CollectionLimits(**kwargs)
    if "max_roles" in kwargs:
        role = deepcopy(iam.get_account_authorization_details.return_value["RoleDetailList"][0])
        role.update(Arn=ARN + "two", RoleName="two")
        iam.get_account_authorization_details.return_value["RoleDetailList"].append(role)
    else:
        s3.list_buckets.return_value["Buckets"].append({"Name": "two"})
    with pytest.raises(CollectionIncomplete, match="inventory budget"):
        c.collect()
    s3.get_bucket_policy.assert_not_called()


def test_org_empty_continuation_pages_and_repeated_policy_ids_are_followed():
    c, _, _, org = collector()
    org.describe_organization.side_effect = None
    org.describe_organization.return_value = {"Organization": {"MasterAccountId": "other"}}
    org.list_policies_for_target.side_effect = [
        {"Policies": [], "NextToken": "policy-next"},
        {"Policies": [{"Id": "p-1"}, {"Id": "p-1"}]},
        {"Policies": [{"Id": "p-1"}]},
    ]
    org.list_parents.side_effect = [{"Parents": [], "NextToken": "parent-next"}, {"Parents": [{"Id": "r-1"}]}]
    org.describe_policy.return_value = {
        "Policy": {"Content": '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'}
    }
    levels, _ = c._organizations("123456789012")
    assert len(levels) == 2
    assert org.describe_policy.call_count == 1
    assert org.list_parents.call_args_list[1].kwargs["NextToken"] == "parent-next"


def test_organization_ancestor_cycle_aborts_not_unknown_empty_success():
    from app.collectors.aws_collector import CollectionIncomplete

    c, _, _, org = collector()
    org.describe_organization.side_effect = None
    org.describe_organization.return_value = {"Organization": {"MasterAccountId": "other"}}
    org.list_policies_for_target.return_value = {"Policies": []}
    org.list_parents.return_value = {"Parents": [{"Id": "123456789012"}]}
    with pytest.raises(CollectionIncomplete, match="ancestor cycle"):
        c._organizations("123456789012")


def test_managed_policy_cache_and_required_fetch_failure():
    c, iam, _, _ = collector()
    iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    iam.get_policy_version.return_value = {"PolicyVersion": {"Document": {"Statement": []}}}
    assert c._managed("policy") == c._managed("policy")
    assert iam.get_policy.call_count == iam.get_policy_version.call_count == 1
    iam.get_policy.side_effect = error("AccessDenied")
    with pytest.raises(ClientError):
        c._managed("different-policy")


def test_metadata_unknown_is_structured_and_artifact_has_no_resource_names():
    import json

    c, _, s3, _ = collector()
    s3.get_bucket_encryption.side_effect = error("AccessDenied")
    c.collect()
    artifact = c.qualification_artifact("123456789012", ARN, "us-east-1", "partial")
    assert artifact["coverage"]["encryption_configuration"]["unknown"] == 1
    assert artifact["coverage"]["iam_role_inventory_complete"]
    assert not artifact["coverage"]["effective_permissions_complete"]
    assert "customer-email" not in json.dumps(artifact)
    assert ARN not in json.dumps(artifact)
    assert "123456789012" not in json.dumps(artifact)


def test_verified_default_encryption_does_not_verify_object_encryption():
    c, _, s3, _ = collector()
    s3.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": {
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        }
    }
    bucket = next(n for n in c.collect().nodes if n.type.value == "S3Bucket")
    assert bucket.metadata["encryption_verified"]
    assert not bucket.metadata["object_encryption_verified"]


def test_same_account_assumption_requires_possible_trust_grant():
    from copy import deepcopy

    c, iam, _, _ = collector()
    role = deepcopy(iam.get_account_authorization_details.return_value["RoleDetailList"][0])
    role.update(Arn=ARN + "other", RoleName="other")
    iam.get_account_authorization_details.return_value["RoleDetailList"].append(role)
    assert all(edge.type.value != "ASSUMES_ROLE" for edge in c.collect().edges)
    role["AssumeRolePolicyDocument"] = {
        "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": ARN}}]
    }
    assert len([edge for edge in c.collect().edges if edge.type.value == "ASSUMES_ROLE"]) == 1


def test_service_linked_roles_are_scp_exempt():
    c, iam, _, _ = collector()
    role = iam.get_account_authorization_details.return_value["RoleDetailList"][0]
    role["Arn"] = "arn:aws:iam::123456789012:role/aws-service-role/example.amazonaws.com/linked"
    c._organizations = Mock(
        return_value=([[{"Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}]}]], False)
    )
    assert c.collect().edges


def test_partition_derived_from_verified_sts_identity():
    c, iam, _, _ = collector()
    c.sts.get_caller_identity.return_value["Arn"] = (
        "arn:aws-us-gov:sts::123456789012:assumed-role/worker/test"
    )
    role = iam.get_account_authorization_details.return_value["RoleDetailList"][0]
    role["Arn"] = ARN.replace("arn:aws:", "arn:aws-us-gov:")
    assert next(n for n in c.collect().nodes if n.type.value == "S3Bucket").id.startswith("arn:aws-us-gov:")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_evaluations": 1000001},
        {"max_requests": 10001},
        {"max_pages": True},
        {"max_policy_documents": 5001},
        {"max_seconds": 601},
        {"max_edges": 15001},
    ],
)
def test_limits_cannot_override_hard_maxima(kwargs):
    from app.collectors.aws_collector import CollectionLimits

    with pytest.raises(ValueError):
        CollectionLimits(**kwargs)


def test_policy_bytes_and_statements_are_bounded():
    from app.collectors.aws_collector import CollectionIncomplete, decode_policy

    with pytest.raises(CollectionIncomplete, match="byte budget"):
        decode_policy(" " * 65537)
    with pytest.raises(CollectionIncomplete, match="statement budget"):
        decode_policy({"Statement": [{}] * 257})


def test_request_page_and_wall_budgets_fail_closed(monkeypatch):
    from app.collectors.aws_collector import CollectionIncomplete, CollectionLimits

    c, _, _, _ = collector()
    c.limits = CollectionLimits(max_requests=1)
    with pytest.raises(CollectionIncomplete, match="request budget"):
        c.collect()
    c.limits = CollectionLimits(max_pages=1)
    with pytest.raises(CollectionIncomplete, match="page budget"):
        c.collect()
    monkeypatch.setattr("app.collectors.aws_collector.time.monotonic", Mock(side_effect=[0, 601]))
    with pytest.raises(CollectionIncomplete, match="wall-time"):
        c.collect()


def test_actual_botocore_models_validate_paginated_requests_without_network():
    from datetime import UTC, datetime

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
            "Account": "123456789012",
            "Arn": "arn:aws:sts::123456789012:assumed-role/worker/test",
            "UserId": "synthetic",
        },
        {},
    )
    iam.add_response(
        "get_account_authorization_details",
        {"RoleDetailList": [], "IsTruncated": True, "Marker": "next"},
        {"Filter": ["Role", "User", "Group"], "MaxItems": 100},
    )
    iam.add_response(
        "get_account_authorization_details",
        {
            "RoleDetailList": [
                {
                    "Path": "/",
                    "RoleName": "worker",
                    "RoleId": "AROASYNTHETIC123456789",
                    "Arn": ARN,
                    "CreateDate": datetime.now(UTC),
                    "AssumeRolePolicyDocument": '{"Statement":[]}',
                    "RolePolicyList": [
                        {
                            "PolicyName": "read",
                            "PolicyDocument": '{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}',
                        }
                    ],
                }
            ],
            "IsTruncated": False,
        },
        {"Filter": ["Role", "User", "Group"], "MaxItems": 100, "Marker": "next"},
    )
    s3.add_response(
        "list_buckets",
        {"Buckets": [{"Name": "customer-email"}], "ContinuationToken": "next"},
        {"MaxBuckets": 100},
    )
    s3.add_response("list_buckets", {"Buckets": []}, {"MaxBuckets": 100, "ContinuationToken": "next"})
    org.add_client_error(
        "describe_organization", service_error_code="AWSOrganizationsNotInUseException", expected_params={}
    )
    s3.add_client_error(
        "get_bucket_policy",
        service_error_code="NoSuchBucketPolicy",
        expected_params={"Bucket": "customer-email", "ExpectedBucketOwner": "123456789012"},
    )
    s3.add_client_error(
        "get_bucket_tagging",
        service_error_code="NoSuchTagSet",
        expected_params={"Bucket": "customer-email", "ExpectedBucketOwner": "123456789012"},
    )
    s3.add_response(
        "get_bucket_encryption",
        {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        },
        {"Bucket": "customer-email", "ExpectedBucketOwner": "123456789012"},
    )
    with sts, iam, s3, org:
        snapshot = c.collect()
        for stub in (sts, iam, s3, org):
            stub.assert_no_pending_responses()
    assert len(snapshot.nodes) == 2
    assert all(edge.certainty == "conditional" for edge in snapshot.edges)
    assert c.requests == 9


def cli_args(tmp_path):
    return [
        "aws_collector",
        "--profile",
        "explicit-sandbox",
        "--region",
        "us-east-1",
        "--account",
        "123456789012",
        "--role-arn",
        ARN,
        "--confirm-account",
        "123456789012",
        "--confirm-role",
        ARN,
        "--ack-readonly-sandbox",
        "--artifact",
        str(tmp_path / "qualification.json"),
    ]


def bootstrap_cli(c, monkeypatch):
    bootstrap, assumed = Mock(), Mock()
    bootstrap.client.return_value.assume_role.return_value = {
        "Credentials": {"AccessKeyId": "SYNTHETIC", "SecretAccessKey": "SECRET", "SessionToken": "TOKEN"}
    }
    factory = Mock(side_effect=[bootstrap, assumed])
    monkeypatch.setattr("app.collectors.aws_collector.boto3.Session", factory)
    monkeypatch.setattr("app.collectors.aws_collector.AWSCollector", Mock(return_value=c))
    return factory


def test_cli_requires_explicit_confirmations_before_credentials_or_files(tmp_path, monkeypatch):
    from app.collectors.aws_collector import main

    factory = Mock()
    monkeypatch.setattr("app.collectors.aws_collector.boto3.Session", factory)
    args = cli_args(tmp_path)
    args[args.index("--confirm-account") + 1] = "999999999999"
    monkeypatch.setattr("sys.argv", args)
    with pytest.raises(SystemExit) as raised:
        main()
    assert raised.value.code == 2
    factory.assert_not_called()
    assert not (tmp_path / "qualification.json").exists()


def test_cli_verified_target_artifact_is_private_aggregate_and_incomplete(tmp_path, monkeypatch, capsys):
    import json
    import stat

    from app.collectors.aws_collector import main

    c, _, _, _ = collector()
    factory = bootstrap_cli(c, monkeypatch)
    c.expected_account, c.expected_role_arn = "123456789012", ARN
    monkeypatch.setattr("sys.argv", cli_args(tmp_path))
    main()
    artifact_path = tmp_path / "qualification.json"
    artifact = json.loads(artifact_path.read_text())
    assert stat.S_IMODE(artifact_path.stat().st_mode) == 0o600
    assert artifact["status"] == "read_only_inventory_complete_with_metadata_gaps"
    assert artifact["counts"]["roles"] == 1
    assert artifact["coverage"]["caller_identity_verified"]
    assert not artifact["coverage"]["effective_permissions_complete"]
    assert factory.call_args_list[0].kwargs == {
        "profile_name": "explicit-sandbox",
        "region_name": "us-east-1",
    }
    for sensitive in ("SECRET", "TOKEN", "customer-email", ARN, "worker"):
        assert sensitive not in artifact_path.read_text()
        assert sensitive not in capsys.readouterr().out


def test_cli_account_mismatch_never_starts_inventory(tmp_path, monkeypatch):
    import json

    from app.collectors.aws_collector import main

    c, iam, s3, org = collector()
    c.expected_account, c.expected_role_arn = "123456789012", ARN
    c.sts.get_caller_identity.return_value = {
        "Account": "999999999999",
        "Arn": "arn:aws:sts::999999999999:assumed-role/worker/test",
    }
    bootstrap_cli(c, monkeypatch)
    monkeypatch.setattr("sys.argv", cli_args(tmp_path))
    with pytest.raises(SystemExit) as raised:
        main()
    assert raised.value.code == 1
    assert json.loads((tmp_path / "qualification.json").read_text())["status"] == "failed"
    iam.get_account_authorization_details.assert_not_called()
    s3.list_buckets.assert_not_called()
    org.describe_organization.assert_not_called()


def test_cli_never_overwrites_artifact_or_discovers_credentials_when_path_exists(tmp_path, monkeypatch):
    from app.collectors.aws_collector import main

    artifact = tmp_path / "qualification.json"
    artifact.write_text("keep")
    factory = Mock()
    monkeypatch.setattr("app.collectors.aws_collector.boto3.Session", factory)
    monkeypatch.setattr("sys.argv", cli_args(tmp_path))
    with pytest.raises(FileExistsError):
        main()
    factory.assert_not_called()
    assert artifact.read_text() == "keep"


def test_optional_scp_failure_preserves_completed_ancestor_evidence():
    c, _, _, org = collector()
    org.describe_organization.side_effect = None
    org.describe_organization.return_value = {"Organization": {"MasterAccountId": "other"}}
    org.list_policies_for_target.side_effect = [{"Policies": [{"Id": "p-deny"}]}, error("AccessDenied")]
    org.describe_policy.return_value = {
        "Policy": {"Content": '{"Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}'}
    }
    org.list_parents.return_value = {"Parents": [{"Id": "r-root"}]}
    levels, _ = c._organizations("123456789012")
    assert len(levels) == 1
    assert c.coverage["scp_inventory"] == "partial"
    assert levels[0][0]["Statement"][0]["Effect"] == "Deny"


def test_success_response_with_missing_optional_metadata_is_unknown():
    c, _, s3, _ = collector()
    s3.get_bucket_policy.side_effect = None
    s3.get_bucket_policy.return_value = {}
    s3.get_bucket_tagging.return_value = {}
    s3.get_bucket_encryption.return_value = {}
    snapshot = c.collect()
    bucket = next(node for node in snapshot.nodes if node.type.value == "S3Bucket")
    assert bucket.metadata["bucket_policy"] == "unknown"
    assert bucket.metadata["classification_tags"] == "unknown"
    assert not bucket.metadata["encryption_verified"]


def test_readonly_permission_templates_match_sdk_operation_contract():
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    policy = json.loads((root / "deploy/aws/collector-role-policy.example.json").read_text())
    actions = {
        action
        for statement in policy["Statement"]
        for action in (
            statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]]
        )
    }
    assert actions == {
        "iam:GetAccountAuthorizationDetails",
        "iam:GenerateServiceLastAccessedDetails",
        "iam:GetServiceLastAccessedDetails",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "s3:ListAllMyBuckets",
        "s3:GetBucketPolicy",
        "s3:GetBucketTagging",
        "s3:GetEncryptionConfiguration",
        "organizations:DescribeOrganization",
        "organizations:ListParents",
        "organizations:ListPoliciesForTarget",
        "organizations:DescribePolicy",
    }
    assert {statement["Sid"] for statement in policy["Statement"] if statement["Resource"] == "*"} == {
        "IamInventoryOnly",
        "OwnedBucketInventory",
        "OptionalAccessAdvisorResults",
        "OptionalOrganizationDescription",
    }
    metadata = next(
        statement for statement in policy["Statement"] if statement["Sid"] == "SandboxBucketMetadataOnly"
    )
    assert metadata["Resource"] == "arn:aws:s3:::zerograph-qualification-*"
    assert metadata["Condition"]["StringEquals"]["s3:ResourceAccount"] == "123456789012"
    assert not any(action.startswith("s3:GetObject") or action == "s3:ListBucket" for action in actions)
    assert all(statement["Effect"] == "Allow" for statement in policy["Statement"])
    trust = json.loads((root / "deploy/aws/collector-role-trust.example.json").read_text())["Statement"][0]
    assert trust["Principal"]["AWS"] == "arn:aws:iam::111122223333:role/ZeroGraphQualificationOperator"
    assert trust["Condition"]["StringEquals"]["sts:ExternalId"]
    bootstrap = json.loads((root / "deploy/aws/assume-role-policy.example.json").read_text())["Statement"][0]
    assert bootstrap["Action"] == "sts:AssumeRole"
    assert bootstrap["Resource"] == "arn:aws:iam::123456789012:role/ZeroGraphReadOnlyCollector"
