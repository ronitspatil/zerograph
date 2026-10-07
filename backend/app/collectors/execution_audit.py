"""Normalize execution evidence without treating missing CloudTrail events as proof of non-use."""

import json
from datetime import datetime

from pydantic import BaseModel, Field

from app.remediation.policy_optimizer import UsageEvidence

# API operation names are not universally IAM action names. Unsupported operations remain
# unresolved (and make the service's coverage incomplete). Each entry maps a CloudTrail
# (eventSource, eventName) to (IAM action, action class); the class is provider-neutral:
# "read", "write", "admin" (permissions/configuration) or "assume" (role assumption).
EVENTS: dict[tuple[str, str], tuple[str, str]] = {
    # S3 data events (object level) and bucket-permission management events.
    ("s3.amazonaws.com", "GetObject"): ("s3:GetObject", "read"),
    ("s3.amazonaws.com", "HeadObject"): ("s3:GetObject", "read"),
    ("s3.amazonaws.com", "GetObjectAttributes"): ("s3:GetObject", "read"),
    ("s3.amazonaws.com", "SelectObjectContent"): ("s3:GetObject", "read"),
    ("s3.amazonaws.com", "GetObjectVersion"): ("s3:GetObjectVersion", "read"),
    ("s3.amazonaws.com", "ListObjects"): ("s3:ListBucket", "read"),
    ("s3.amazonaws.com", "ListObjectsV2"): ("s3:ListBucket", "read"),
    ("s3.amazonaws.com", "ListObjectVersions"): ("s3:ListBucketVersions", "read"),
    ("s3.amazonaws.com", "PutObject"): ("s3:PutObject", "write"),
    ("s3.amazonaws.com", "CopyObject"): ("s3:PutObject", "write"),
    ("s3.amazonaws.com", "CreateMultipartUpload"): ("s3:PutObject", "write"),
    ("s3.amazonaws.com", "UploadPart"): ("s3:PutObject", "write"),
    ("s3.amazonaws.com", "CompleteMultipartUpload"): ("s3:PutObject", "write"),
    ("s3.amazonaws.com", "DeleteObject"): ("s3:DeleteObject", "write"),
    ("s3.amazonaws.com", "DeleteObjects"): ("s3:DeleteObject", "write"),
    ("s3.amazonaws.com", "PutBucketPolicy"): ("s3:PutBucketPolicy", "admin"),
    ("s3.amazonaws.com", "DeleteBucketPolicy"): ("s3:DeleteBucketPolicy", "admin"),
    ("s3.amazonaws.com", "PutBucketAcl"): ("s3:PutBucketAcl", "admin"),
    ("s3.amazonaws.com", "PutObjectAcl"): ("s3:PutObjectAcl", "admin"),
    # STS role assumption (the resource is the assumed role).
    ("sts.amazonaws.com", "AssumeRole"): ("sts:AssumeRole", "assume"),
    ("sts.amazonaws.com", "AssumeRoleWithWebIdentity"): ("sts:AssumeRoleWithWebIdentity", "assume"),
    ("sts.amazonaws.com", "AssumeRoleWithSAML"): ("sts:AssumeRoleWithSAML", "assume"),
    # Glue Data Catalog.
    ("glue.amazonaws.com", "GetDatabase"): ("glue:GetDatabase", "read"),
    ("glue.amazonaws.com", "GetDatabases"): ("glue:GetDatabases", "read"),
    ("glue.amazonaws.com", "GetTable"): ("glue:GetTable", "read"),
    ("glue.amazonaws.com", "GetTables"): ("glue:GetTables", "read"),
    ("glue.amazonaws.com", "GetPartition"): ("glue:GetPartition", "read"),
    ("glue.amazonaws.com", "GetPartitions"): ("glue:GetPartitions", "read"),
    ("glue.amazonaws.com", "BatchGetPartition"): ("glue:BatchGetPartition", "read"),
    ("glue.amazonaws.com", "SearchTables"): ("glue:SearchTables", "read"),
    ("glue.amazonaws.com", "CreateTable"): ("glue:CreateTable", "write"),
    ("glue.amazonaws.com", "UpdateTable"): ("glue:UpdateTable", "write"),
    ("glue.amazonaws.com", "CreatePartition"): ("glue:CreatePartition", "write"),
    ("glue.amazonaws.com", "BatchCreatePartition"): ("glue:BatchCreatePartition", "write"),
    ("glue.amazonaws.com", "UpdatePartition"): ("glue:UpdatePartition", "write"),
    ("glue.amazonaws.com", "DeletePartition"): ("glue:DeletePartition", "write"),
    ("glue.amazonaws.com", "BatchDeletePartition"): ("glue:BatchDeletePartition", "write"),
    ("glue.amazonaws.com", "CreateDatabase"): ("glue:CreateDatabase", "admin"),
    ("glue.amazonaws.com", "UpdateDatabase"): ("glue:UpdateDatabase", "admin"),
    ("glue.amazonaws.com", "DeleteDatabase"): ("glue:DeleteDatabase", "admin"),
    ("glue.amazonaws.com", "DeleteTable"): ("glue:DeleteTable", "admin"),
    ("glue.amazonaws.com", "PutResourcePolicy"): ("glue:PutResourcePolicy", "admin"),
    ("glue.amazonaws.com", "DeleteResourcePolicy"): ("glue:DeleteResourcePolicy", "admin"),
    # Athena (the resource is the workgroup).
    ("athena.amazonaws.com", "StartQueryExecution"): ("athena:StartQueryExecution", "read"),
    ("athena.amazonaws.com", "GetQueryExecution"): ("athena:GetQueryExecution", "read"),
    ("athena.amazonaws.com", "GetQueryResults"): ("athena:GetQueryResults", "read"),
    ("athena.amazonaws.com", "StopQueryExecution"): ("athena:StopQueryExecution", "read"),
    ("athena.amazonaws.com", "CreateWorkGroup"): ("athena:CreateWorkGroup", "admin"),
    ("athena.amazonaws.com", "UpdateWorkGroup"): ("athena:UpdateWorkGroup", "admin"),
    ("athena.amazonaws.com", "DeleteWorkGroup"): ("athena:DeleteWorkGroup", "admin"),
    # Lake Formation (credential vending and permission management).
    ("lakeformation.amazonaws.com", "GetDataAccess"): ("lakeformation:GetDataAccess", "read"),
    ("lakeformation.amazonaws.com", "GrantPermissions"): ("lakeformation:GrantPermissions", "admin"),
    ("lakeformation.amazonaws.com", "RevokePermissions"): ("lakeformation:RevokePermissions", "admin"),
    ("lakeformation.amazonaws.com", "BatchGrantPermissions"): (
        "lakeformation:BatchGrantPermissions",
        "admin",
    ),
    ("lakeformation.amazonaws.com", "BatchRevokePermissions"): (
        "lakeformation:BatchRevokePermissions",
        "admin",
    ),
    ("lakeformation.amazonaws.com", "PutDataLakeSettings"): ("lakeformation:PutDataLakeSettings", "admin"),
    # RDS Data API: a statement may read or write; classed as write (never understates use).
    ("rds-data.amazonaws.com", "ExecuteStatement"): ("rds-data:ExecuteStatement", "write"),
    ("rds-data.amazonaws.com", "BatchExecuteStatement"): ("rds-data:BatchExecuteStatement", "write"),
    # OpenSearch Serverless data-plane events (names unverified against a live trail).
    ("aoss.amazonaws.com", "ReadDocument"): ("aoss:ReadDocument", "read"),
    ("aoss.amazonaws.com", "WriteDocument"): ("aoss:WriteDocument", "write"),
}
ACTION_MAP = {key: action for key, (action, _) in EVENTS.items()}
ACTION_CLASSES = ("read", "write", "admin", "assume")
# Coverage is attested per service: the event source without ".amazonaws.com".
SERVICES = tuple(sorted({source.removesuffix(".amazonaws.com") for source, _ in EVENTS}))


def service_of(event_source: str) -> str:
    return event_source.removesuffix(".amazonaws.com") if isinstance(event_source, str) else ""


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
