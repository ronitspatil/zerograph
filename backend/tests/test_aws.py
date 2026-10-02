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
    sts.get_caller_identity.return_value = {"Account": "123456789012"}
    org.describe_organization.side_effect = error("AWSOrganizationsNotInUseException")
    iam.get_paginator.return_value.paginate.return_value = [
        {
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
            ]
        }
    ]
    s3.list_buckets.return_value = {"Buckets": [{"Name": "customer-email"}]}
    s3.get_bucket_policy.side_effect = error("NoSuchBucketPolicy")
    s3.get_bucket_tagging.return_value = {"TagSet": [{"Key": "classification", "Value": "patient"}]}
    s3.get_bucket_encryption.return_value = {"ServerSideEncryptionConfiguration": {}}
    return AWSCollector(session), iam, s3, org


def test_live_collector_enriches_metadata_but_does_not_claim_complete_access():
    c, _, _, _ = collector()
    snapshot = c.collect()
    bucket = next(n for n in snapshot.nodes if n.type.value == "S3Bucket")
    assert set(bucket.tags) == {"PII", "PHI"}
    assert snapshot.edges
    assert all(e.certainty == "conditional" for e in snapshot.edges)
    assert any("session" in warning for warning in snapshot.warnings)


def test_bucket_access_denied_is_reported_as_unknown():
    c, _, s3, _ = collector()
    s3.get_bucket_policy.side_effect = error("AccessDenied")
    s3.get_bucket_tagging.side_effect = error("AccessDenied")
    s3.get_bucket_encryption.side_effect = error("AccessDenied")
    snapshot = c.collect()
    assert any("bucket policy unavailable" in w for w in snapshot.warnings)
    assert any("encryption" in w for w in snapshot.warnings)
    assert next(n for n in snapshot.nodes if n.type.value == "S3Bucket").encrypted


def test_explicit_deny_does_not_create_permission_edges():
    c, iam, _, _ = collector()
    role = iam.get_paginator.return_value.paginate.return_value[0]["RoleDetailList"][0]
    role["RolePolicyList"] = [
        {"PolicyDocument": {"Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}]}}
    ]
    assert c.collect().edges == []


def test_scp_collection_walks_account_ou_and_root():
    c, _, _, org = collector()
    org.describe_organization.side_effect = None
    org.describe_organization.return_value = {"Organization": {"MasterAccountId": "other"}}
    org.list_parents.side_effect = [{"Parents": [{"Id": "ou-1"}]}, {"Parents": [{"Id": "r-1"}]}]
    org.get_paginator.return_value.paginate.return_value = [{"Policies": [{"Id": "p-1"}]}]
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
    iam.get_paginator.return_value.paginate.side_effect = error("AccessDenied")
    with pytest.raises(ClientError):
        c.collect()
