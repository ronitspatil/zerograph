from datetime import UTC, datetime, timedelta

from app.collectors.execution_audit import AccessAdvisorCollector, normalize_cloudtrail

ARN = "arn:aws:iam::123456789012:role/worker"


def event(name="GetObject", arn=ARN):
    return {
        "eventTime": datetime.now(UTC).isoformat(),
        "eventSource": "s3.amazonaws.com",
        "eventName": name,
        "userIdentity": {
            "arn": "arn:aws:sts::123456789012:assumed-role/worker/session",
            "sessionContext": {"sessionIssuer": {"arn": arn}},
        },
    }


def normalize(events, attest=False):
    now = datetime.now(UTC)
    return normalize_cloudtrail(
        events, ARN, now - timedelta(days=100), now + timedelta(seconds=1), ["s3"], attest
    )


def test_cloudtrail_role_sessions_and_head_object_action_mapping():
    result = normalize([event("HeadObject"), event("PutObject"), event("GetObject", arn="other")], True)
    assert result.matched_events == 2
    assert result.usage.used_actions == ["s3:GetObject", "s3:PutObject"]
    assert result.usage.complete


def test_unknown_api_mapping_prevents_policy_reduction():
    result = normalize([event("UnknownOperation")], True)
    assert result.unresolved_events == 1
    assert not result.usage.complete


def test_event_history_alone_never_proves_coverage():
    assert not normalize([event()]).usage.complete


def test_malformed_timestamp_marks_coverage_incomplete():
    e = event()
    e["eventTime"] = "invalid"
    assert not normalize([e], True).usage.complete


def test_access_advisor_paginates_and_remains_supplementary():
    class IAM:
        def generate_service_last_accessed_details(self, **kwargs):
            return {"JobId": "job"}

        def get_service_last_accessed_details(self, **kwargs):
            return {
                "JobStatus": "COMPLETED",
                "IsTruncated": "Marker" not in kwargs,
                "Marker": "next",
                "ServicesLastAccessed": [{"ServiceNamespace": "s3"}],
            }

    collector = AccessAdvisorCollector(IAM())
    assert collector.start(ARN) == "job"
    result = collector.result("job")
    assert len(result["services"]) == 2
    assert not result["complete"]
