import pytest

from app.collectors.iam_evaluator import Decision, Request, conditions_match, evaluate

PRINCIPAL = "arn:aws:iam::123456789012:role/worker"
RESOURCE = "arn:aws:s3:::private-bucket/report.csv"
REQUEST = Request(PRINCIPAL, "s3:GetObject", RESOURCE)


def policy(effect="Allow", action="s3:*", resource="*", **kwargs):
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": effect, "Action": action, "Resource": resource, **kwargs}],
    }


def test_identity_grant():
    assert evaluate(REQUEST, [policy()]).decision == Decision.ALLOW


def test_default_deny():
    assert evaluate(REQUEST, []).decision == Decision.DENY


@pytest.mark.parametrize(
    "location", ["identity", "resource", "boundary", "session", "scp_levels", "rcp_levels"]
)
def test_explicit_deny_precedence(location):
    kwargs = {location: [policy("Deny")]}
    if location.endswith("levels"):
        kwargs[location] = [[policy("Deny")]]
    identity = kwargs.pop("identity", [policy()])
    assert evaluate(REQUEST, identity, **kwargs).decision == Decision.DENY


def test_boundary_intersection():
    assert evaluate(REQUEST, [policy()], boundary=[policy(action="s3:PutObject")]).decision == Decision.DENY


def test_scp_levels_intersect_but_policies_within_level_union():
    assert (
        evaluate(REQUEST, [policy()], scp_levels=[[policy(action="ec2:*"), policy()], [policy()]]).decision
        == Decision.ALLOW
    )
    assert (
        evaluate(REQUEST, [policy()], scp_levels=[[policy()], [policy(action="ec2:*")]]).decision
        == Decision.DENY
    )


def test_missing_condition_context_is_uncertain():
    conditioned = policy(Condition={"StringEquals": {"aws:SourceVpce": "vpce-123"}})
    assert evaluate(REQUEST, [conditioned]).decision == Decision.CONDITIONAL


def test_conditional_deny_never_becomes_allow():
    deny = policy("Deny", Condition={"Bool": {"aws:SecureTransport": "false"}})
    assert evaluate(REQUEST, [policy(), deny]).decision == Decision.CONDITIONAL


def test_false_deny_condition_can_allow():
    request = Request(PRINCIPAL, "s3:GetObject", RESOURCE, {"aws:SecureTransport": "true"})
    assert (
        evaluate(
            request, [policy(), policy("Deny", Condition={"Bool": {"aws:SecureTransport": "false"}})]
        ).decision
        == Decision.ALLOW
    )


def test_not_action_and_not_resource():
    complement = {
        "Statement": [{"Effect": "Allow", "NotAction": "iam:*", "NotResource": "arn:aws:s3:::other/*"}]
    }
    assert evaluate(REQUEST, [complement]).decision == Decision.ALLOW


def test_resource_grant_requires_matching_principal():
    assert evaluate(REQUEST, [], [policy(Principal={"AWS": PRINCIPAL})]).decision == Decision.ALLOW
    assert evaluate(REQUEST, [], [policy(Principal={"AWS": "other"})]).decision == Decision.DENY


def test_cross_account_requires_both_sides():
    request = Request(PRINCIPAL, "s3:GetObject", RESOURCE, cross_account=True)
    assert evaluate(request, [policy()], []).decision == Decision.DENY
    assert evaluate(request, [policy()], [policy(Principal={"AWS": PRINCIPAL})]).decision == Decision.ALLOW


def test_direct_user_grant_bypasses_implicit_boundary_but_not_explicit_deny():
    user = "arn:aws:iam::123456789012:user/alice"
    request = Request(user, "s3:GetObject", RESOURCE)
    resource = [policy(Principal={"AWS": user})]
    assert evaluate(request, [], resource, boundary=[policy(action="ec2:*")]).decision == Decision.ALLOW
    assert evaluate(request, [], resource, boundary=[policy("Deny")]).decision == Decision.DENY


def test_incomplete_collection_is_not_confirmed():
    assert evaluate(REQUEST, [policy()], scope_complete=False).decision == Decision.CONDITIONAL


def test_ip_and_unsupported_conditions():
    assert (
        conditions_match({"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}, {"aws:SourceIp": "10.2.3.4"}) is True
    )
    assert (
        conditions_match(
            {"DateLessThan": {"aws:CurrentTime": "2027-01-01"}}, {"aws:CurrentTime": "2026-01-01"}
        )
        is None
    )
    assert (
        conditions_match({"StringEquals": {"key": "${aws:PrincipalTag/team}"}}, {"key": "engineering"})
        is None
    )


def test_unresolved_resource_variable_keeps_deny_uncertain():
    variable_deny = policy("Deny", resource="arn:aws:s3:::private-bucket/${aws:username}/*")
    assert evaluate(REQUEST, [policy(), variable_deny]).decision == Decision.CONDITIONAL


def test_same_account_direct_role_trust_does_not_require_identity_allow():
    request = Request(PRINCIPAL, "sts:AssumeRole", "arn:aws:iam::123456789012:role/target")
    trust = [policy(action="sts:AssumeRole", Principal={"AWS": PRINCIPAL})]
    assert evaluate(request, [], trust, require_resource_allow=True).decision == Decision.ALLOW
    assert (
        evaluate(request, [], trust, boundary=[policy(action="s3:*")], require_resource_allow=True).decision
        == Decision.DENY
    )


def test_account_root_trust_requires_identity_allow():
    request = Request(PRINCIPAL, "sts:AssumeRole", "arn:aws:iam::123456789012:role/target")
    trust = [policy(action="sts:AssumeRole", Principal={"AWS": "arn:aws:iam::123456789012:root"})]
    assert evaluate(request, [], trust, require_resource_allow=True).decision == Decision.DENY


def test_unknown_direct_trust_condition_remains_conditional():
    request = Request(PRINCIPAL, "sts:AssumeRole", "arn:aws:iam::123456789012:role/target")
    trust = [
        policy(
            action="sts:AssumeRole",
            Principal={"AWS": PRINCIPAL},
            Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        )
    ]
    assert evaluate(request, [], trust, require_resource_allow=True).decision == Decision.CONDITIONAL
