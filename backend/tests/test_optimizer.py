from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from app.remediation.policy_optimizer import UsageEvidence, optimize, terraform_policy


def evidence(**kwargs):
    now = datetime.now(UTC)
    return UsageEvidence(
        window_start=now - timedelta(days=100),
        window_end=now - timedelta(days=1),
        used_actions=["s3:GetObject"],
        covered_services=["s3"],
        source="cloudtrail-data-events",
        **kwargs,
    )


def policy(statements):
    return {"Version": "2012-10-17", "Statement": statements}


ALLOW = {
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:DeleteObject"],
    "Resource": "arn:aws:s3:::bucket/*",
}
DENY = {
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
}


def test_shrinks_unused_concrete_actions_and_preserves_deny():
    original = policy([ALLOW, DENY])
    result = optimize(original, evidence(complete=True))
    assert result.removed_actions == ["s3:DeleteObject"]
    assert result.optimized["Statement"][1] == DENY
    assert original["Statement"][0]["Action"] == ["s3:GetObject", "s3:DeleteObject"]
    assert "-" in result.diff and "+" in result.diff


@pytest.mark.parametrize(
    "statement",
    [
        {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
        {**ALLOW, "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-1"}}},
        {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"},
        {**ALLOW, "Principal": "*"},
    ],
)
def test_ambiguous_statements_are_preserved(statement):
    original = policy([statement])
    assert optimize(original, evidence(complete=True)).optimized == original


def test_incomplete_or_short_audit_window_cannot_shrink():
    original = policy([ALLOW])
    assert optimize(original, evidence()).removed_actions == []
    usage = evidence(complete=True)
    usage.window_start = usage.window_end - timedelta(days=30)
    assert optimize(original, usage).removed_actions == []


def test_stale_evidence_cannot_shrink():
    usage = evidence(complete=True)
    usage.window_end -= timedelta(days=10)
    assert optimize(policy([ALLOW]), usage).removed_actions == []


def test_uncovered_service_is_preserved():
    stmt = {"Effect": "Allow", "Action": ["ec2:StartInstances", "s3:GetObject"], "Resource": "*"}
    assert optimize(policy([stmt]), evidence(complete=True)).removed_actions == []


def test_all_unused_grants_require_detach_review():
    original = policy([{**ALLOW, "Action": "s3:DeleteObject"}])
    result = optimize(original, evidence(complete=True))
    assert result.optimized == original
    assert result.removed_actions == []


def test_terraform_escapes_iam_policy_variables():
    content = terraform_policy(policy([{**ALLOW, "Resource": "arn:aws:s3:::${aws:username}/*"}]))
    assert "$${aws:username}" in content
    with pytest.raises(ValueError):
        terraform_policy(policy([ALLOW]), 'malicious" name')


def test_bad_policy_and_naive_timestamps_are_rejected():
    with pytest.raises(ValueError):
        optimize({"Statement": []}, evidence())
    with pytest.raises(ValidationError):
        UsageEvidence(
            window_start=datetime(2026, 1, 1),
            window_end=datetime(2026, 2, 1),
            used_actions=[],
            covered_services=[],
            source="test",
        )
