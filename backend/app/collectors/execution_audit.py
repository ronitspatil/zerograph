"""Normalize execution evidence without treating missing CloudTrail events as proof of non-use."""

import json
from datetime import datetime

from pydantic import BaseModel, Field

from app.remediation.policy_optimizer import UsageEvidence

# API operation names are not universally IAM action names. Unsupported operations remain unresolved.
ACTION_MAP = {
    ("s3.amazonaws.com", "GetObject"): "s3:GetObject",
    ("s3.amazonaws.com", "HeadObject"): "s3:GetObject",
    ("s3.amazonaws.com", "GetObjectVersion"): "s3:GetObjectVersion",
    ("s3.amazonaws.com", "ListObjects"): "s3:ListBucket",
    ("s3.amazonaws.com", "ListObjectsV2"): "s3:ListBucket",
    ("s3.amazonaws.com", "PutObject"): "s3:PutObject",
    ("s3.amazonaws.com", "DeleteObject"): "s3:DeleteObject",
    ("sts.amazonaws.com", "AssumeRole"): "sts:AssumeRole",
}


class AuditNormalization(BaseModel):
    usage: UsageEvidence
    matched_events: int
    unresolved_events: int
    warnings: list[str] = Field(default_factory=list)


def normalize_cloudtrail(
    events: list[dict],
    identity_arn: str,
    start: datetime,
    end: datetime,
    covered_services: list[str],
    coverage_attested: bool = False,
) -> AuditNormalization:
    if start.tzinfo is None or end.tzinfo is None:
        raise ValueError("Audit window requires timezone-aware timestamps")
    actions, warnings = set(), set()
    matched = unresolved = 0
    for wrapper in events:
        event = json.loads(wrapper["CloudTrailEvent"]) if "CloudTrailEvent" in wrapper else wrapper
        user = event.get("userIdentity", {})
        issuer = user.get("sessionContext", {}).get("sessionIssuer", {}).get("arn")
        if identity_arn not in {user.get("arn"), issuer}:
            continue
        timestamp = event.get("eventTime")
        try:
            occurred = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except (AttributeError, ValueError):
            unresolved += 1
            warnings.add("Malformed event timestamp; coverage is incomplete")
            continue
        if occurred.tzinfo is None:
            unresolved += 1
            continue
        if not start <= occurred <= end:
            continue
        action = ACTION_MAP.get((event.get("eventSource"), event.get("eventName")))
        if action:
            actions.add(action)
            matched += 1
        else:
            unresolved += 1
            warnings.add("Some API events have no verified IAM action mapping")
    if not coverage_attested:
        warnings.add("Event presence alone does not establish complete audit coverage")
    return AuditNormalization(
        usage=UsageEvidence(
            window_start=start,
            window_end=end,
            used_actions=sorted(actions),
            covered_services=covered_services,
            complete=coverage_attested and unresolved == 0,
            source="cloudtrail-export",
        ),
        matched_events=matched,
        unresolved_events=unresolved,
        warnings=sorted(warnings),
    )


class AccessAdvisorCollector:
    def __init__(self, iam_client):
        self.iam = iam_client

    def start(self, identity_arn: str) -> str:
        return self.iam.generate_service_last_accessed_details(Arn=identity_arn, Granularity="ACTION_LEVEL")[
            "JobId"
        ]

    def result(self, job_id: str) -> dict:
        services = []
        marker = None
        while True:
            params = {"JobId": job_id}
            if marker:
                params["Marker"] = marker
            page = self.iam.get_service_last_accessed_details(**params)
            if page["JobStatus"] != "COMPLETED":
                return {"status": page["JobStatus"], "services": [], "complete": False}
            for service in page.get("ServicesLastAccessed", []):
                services.append(
                    {
                        "service": service["ServiceNamespace"],
                        "last_authenticated": service.get("LastAuthenticated"),
                        "tracked_actions": [
                            a.get("ActionName") for a in service.get("TrackedActionsLastAccessed", [])
                        ],
                        "basis": "access_advisor_activity_hint",
                    }
                )
            if not page.get("IsTruncated"):
                break
            marker = page["Marker"]
        return {
            "status": "COMPLETED",
            "services": services,
            "complete": False,
            "warning": "Access Advisor is supplementary; it does not prove complete CloudTrail coverage or resource-level non-use",
        }
