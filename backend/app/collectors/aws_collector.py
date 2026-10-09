"""Bounded, read-only IAM (roles, users, groups) and S3-metadata inventory; never confirmed access.

Besides the graph, a collection keeps what the optimizer needs as evidence: raw role,
user and bucket tags (``key=value``), each role's ``RoleLastUsed`` and (optionally)
IAM Access Advisor service last-accessed data as **hints** in node metadata, and
every decoded policy document (inline, attached managed, permissions boundary,
trust, and group-inherited for users) as content-hashed ``PolicyAttachment``
entries stored per revision in SQL, never in node JSON. IAM users are modeled as
``HumanUser`` identities; group membership is folded into each user's effective
policies (group policies are attached as ``group-inline``/``group-managed``).
"""

import argparse
import hashlib
import json
import os
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from app.collectors.data_classifier import enrich_node
from app.collectors.execution_audit import AccessAdvisorCollector
from app.collectors.iam_evaluator import Decision, Request, evaluate
from app.graph.schema import (
    MAX_AWS_MANAGED_POLICY_BYTES,
    MAX_POLICY_BYTES,
    MAX_SNAPSHOT_POLICIES,
    Edge,
    EdgeType,
    GraphSnapshot,
    Node,
    NodeType,
    PolicyAttachment,
    aws_managed_policy,
    canonical_policy,
)

READ_ACTIONS = ("s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket")
WRITE_ACTIONS = ("s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion")
SDK_CONFIG = Config(retries={"mode": "standard", "total_max_attempts": 3}, connect_timeout=5, read_timeout=10)
HARD_LIMITS = {
    "max_roles": 1000,
    "max_users": 1000,
    "max_groups": 1000,
    "max_buckets": 1000,
    "max_pages": 1000,
    "max_requests": 10000,
    "max_policy_documents": 5000,
    "max_evaluations": 1000000,
    "max_edges": 15000,
    "max_org_depth": 20,
    "max_seconds": 600,
    "max_policy_attachments": MAX_SNAPSHOT_POLICIES,
    "max_access_advisor_jobs": 1000,
}
MAX_TAGS = 32  # Node.tags bound; raw tags beyond it are dropped and counted.
ACCESS_ADVISOR_POLLS = 10
MAX_ADVISOR_SERVICES = 400
# Customer-authored documents (inline, customer-managed, trust, bucket policies, SCPs):
# MAX_POLICY_BYTES (64 KiB) and 256 statements; exceeding either aborts the collection.
# AWS-managed policies (arn:<partition>:iam::aws:policy/...) are larger in practice and
# get 1 MiB and 2,048 statements; one beyond those is recorded as unevaluated instead.
MAX_POLICY_STATEMENTS = 256
MAX_AWS_MANAGED_POLICY_STATEMENTS = 2048
MAX_UNEVALUATED_PER_PRINCIPAL = 20
UNEVALUATED = "too_large/unevaluated"

ROLE_ARN = re.compile(r"arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role/(.+)")


class CollectionIncomplete(ValueError):
    """A bound or malformed inventory prevents safely publishing any snapshot."""


class PolicyTooLarge(CollectionIncomplete):
    """A policy document exceeds its byte or statement bound."""


@dataclass(frozen=True)
class CollectionLimits:
    max_roles: int = 500
    max_users: int = 500
    max_groups: int = 500
    max_buckets: int = 500
    max_pages: int = 100
    max_requests: int = 3000
    max_policy_documents: int = 1000
    max_evaluations: int = 100000
    max_edges: int = 15000
    max_org_depth: int = 10
    max_seconds: int = 600
    max_policy_attachments: int = 10000
    max_access_advisor_jobs: int = 200

    def __post_init__(self):
        for key, value in asdict(self).items():
            if type(value) is not int or not 1 <= value <= HARD_LIMITS[key]:
                raise ValueError(f"Collection limit {key} must be 1..{HARD_LIMITS[key]}")


def decode_policy(
    document: dict | str,
    *,
    max_bytes: int = MAX_POLICY_BYTES,
    max_statements: int = MAX_POLICY_STATEMENTS,
) -> dict:
    """A decoded policy object; its canonical JSON (as stored) must fit ``max_bytes``."""
    if isinstance(document, str):
        # Bound the raw (possibly URL-encoded) text before parsing it.
        if len(document.encode()) > max_bytes:
            raise PolicyTooLarge("Policy document byte budget exhausted")
        document = json.loads(unquote(document))
    if not isinstance(document, dict):
        raise CollectionIncomplete("Policy document is not an object")
    if len(canonical_policy(document).encode()) > max_bytes:
        raise PolicyTooLarge("Policy document byte budget exhausted")
    statements = document.get("Statement", [])
    statements = statements if isinstance(statements, list) else [statements]
    if len(statements) > max_statements:
        raise PolicyTooLarge("Policy statement budget exhausted")
    if not all(isinstance(statement, dict) for statement in statements):
        raise CollectionIncomplete("Policy statement is not an object")
    return document


def _document_digest(document) -> tuple[str, int, str]:
    """SHA-256, byte size and basis of a document kept only by reference."""
    if isinstance(document, dict):
        encoded, basis = canonical_policy(document).encode(), "canonical_json"
    else:
        encoded, basis = str(document).encode(), "raw_document"
    return hashlib.sha256(encoded).hexdigest(), len(encoded), basis


def unevaluated_document(arn: str, document) -> dict:
    """Stand-in stored for an AWS-managed document beyond the bounds: ARN, SHA-256, status.

    It has no ``Statement``, so nothing reads it as granting or denying anything.
    """
    digest, size, basis = _document_digest(document)
    return {
        "ZeroGraphUnevaluated": {
            "status": UNEVALUATED,
            "arn": arn,
            "sha256": digest,
            "sha256_basis": basis,
            "size_bytes": size,
            "limit_bytes": MAX_AWS_MANAGED_POLICY_BYTES,
            "limit_statements": MAX_AWS_MANAGED_POLICY_STATEMENTS,
        }
    }


def is_unevaluated(document: dict) -> bool:
    return isinstance(document, dict) and "ZeroGraphUnevaluated" in document


def _iso(value) -> str:
    """AWS timestamps (datetime from botocore, or a string) as ISO 8601."""
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value or "")[:64]


def _unevaluated(detail: dict, arn: str) -> None:
    """Note on a role/user detail that an attached policy was kept unevaluated."""
    found = detail.setdefault("unevaluated", [])
    if arn not in found:
        found.append(arn)


def _unevaluated_evidence(detail: dict) -> list[str]:
    if not detail.get("unevaluated"):
        return []
    return [
        "An attached AWS-managed policy was too large to evaluate; its grants and denies are unknown "
        "and were not applied"
    ]


def _privileged(policies: list[dict]) -> bool:
    return any(
        s.get("Effect") == "Allow" and s.get("Action") in ("*", ["*"])
        for p in policies
        for s in (p.get("Statement", []) if isinstance(p.get("Statement", []), list) else [p["Statement"]])
    )


class _CountedClient:
    """Routes a client's calls through the collector's request and wall-time budgets."""

    def __init__(self, collector: "AWSCollector", client):
        self._collector, self._client = collector, client

    def __getattr__(self, operation: str):
        return lambda **kwargs: self._collector._call(self._client, operation, **kwargs)


class AWSCollector:
    def __init__(
        self,
        session: boto3.Session,
        limits: CollectionLimits | None = None,
        *,
        expected_account: str | None = None,
        expected_role_arn: str | None = None,
        access_advisor: bool = False,
        sleep=time.sleep,
    ):
        self.session, self.limits = session, limits or CollectionLimits()
        self.access_advisor, self._sleep = access_advisor, sleep
        self.iam = session.client("iam", config=SDK_CONFIG)
        self.s3 = session.client("s3", config=SDK_CONFIG)
        self.sts = session.client("sts", config=SDK_CONFIG)
        self.organizations = session.client("organizations", config=SDK_CONFIG)
        self.expected_account, self.expected_role_arn = expected_account, expected_role_arn
        self._reset()

    def _reset(self):
        self.started = time.monotonic()
        self.requests = self.pages = self.policy_documents = 0
        self.warnings: list[str] = []
        self.warning_counts: dict[str, int] = {}
        self.managed_cache: dict[str, dict] = {}
        self.unevaluated_policies: set[str] = set()
        self.scp_cache: dict[str, dict] = {}
        self.coverage: dict[str, Any] = {
            "effective_permissions_complete": False,
            "scp_inventory": "unknown",
            "iam_role_inventory_complete": False,
            "general_purpose_bucket_inventory_complete": False,
            "bucket_policy": {"observed": 0, "absent": 0, "unknown": 0},
            "classification_tags": {"observed": 0, "absent": 0, "unknown": 0},
            "encryption_configuration": {"observed": 0, "unknown": 0},
            "object_encryption_verified": False,
            "iam_user_inventory_complete": False,
            "iam_group_inventory_complete": False,
            "role_last_used": {"observed": 0, "absent": 0},
            "unevaluated_policy_documents": 0,
        }
        self.counts = {"roles": 0, "users": 0, "groups": 0, "buckets": 0, "edges": 0, "evaluations": 0}
        self.attachments: list[PolicyAttachment] = []
        self.attachment_ids: set[str] = set()

    def _warning(self, code: str, message: str):
        if code not in self.warning_counts:
            self.warnings.append(message)
        self.warning_counts[code] = self.warning_counts.get(code, 0) + 1

    def _check_time(self):
        if time.monotonic() - self.started > self.limits.max_seconds:
            raise CollectionIncomplete("Collection wall-time budget exhausted")

    def _call(self, client, operation: str, **kwargs):
        self._check_time()
        if self.requests >= self.limits.max_requests:
            raise CollectionIncomplete("Collection request budget exhausted")
        self.requests += 1
        result = getattr(client, operation)(**kwargs)
        self._check_time()
        return result

    def _pages(
        self, client, operation: str, *, token="NextToken", response_token=None, truncated=False, **kwargs
    ):
        seen = set()
        while True:
            if self.pages >= self.limits.max_pages:
                raise CollectionIncomplete("Collection page budget exhausted")
            self.pages += 1
            page = self._call(client, operation, **kwargs)
            if not isinstance(page, dict):
                raise CollectionIncomplete("Malformed inventory page")
            yield page
            next_token = page.get(response_token or token)
            if truncated and type(page.get("IsTruncated")) is not bool:
                raise CollectionIncomplete("IAM inventory pagination status is missing")
            if truncated and not page.get("IsTruncated", False):
                return
            if not next_token:
                if truncated and page.get("IsTruncated"):
                    raise CollectionIncomplete("Truncated inventory lacks a continuation token")
                return
            if not isinstance(next_token, str) or next_token in seen:
                raise CollectionIncomplete("Invalid or repeated inventory continuation token")
            seen.add(next_token)
            kwargs[token] = next_token

    def _policy(self, document, **bounds):
        if self.policy_documents >= self.limits.max_policy_documents:
            raise CollectionIncomplete("Policy document budget exhausted")
        self.policy_documents += 1
        return decode_policy(document, **bounds)

    def _managed(self, arn: str) -> dict:
        """A managed policy's decoded document, or its unevaluated stand-in (AWS-managed only)."""
        if arn not in self.managed_cache:
            version = self._call(self.iam, "get_policy", PolicyArn=arn)["Policy"]["DefaultVersionId"]
            raw = self._call(self.iam, "get_policy_version", PolicyArn=arn, VersionId=version)[
                "PolicyVersion"
            ]["Document"]
            if not aws_managed_policy(arn):
                self.managed_cache[arn] = self._policy(raw)
            else:
                try:
                    self.managed_cache[arn] = self._policy(
                        raw,
                        max_bytes=MAX_AWS_MANAGED_POLICY_BYTES,
                        max_statements=MAX_AWS_MANAGED_POLICY_STATEMENTS,
                    )
                except PolicyTooLarge:
                    # Never abort for an AWS-owned document: keep its reference and digest and
                    # treat the access it grants as unknown (see ``_unevaluated``).
                    self.managed_cache[arn] = unevaluated_document(arn, raw)
                    self.unevaluated_policies.add(arn)
                    self.coverage["unevaluated_policy_documents"] = len(self.unevaluated_policies)
                    self._warning(
                        "policy_unevaluated",
                        "One or more AWS-managed policies exceed 1 MiB or 2,048 statements and were not "
                        "evaluated; access they grant is unknown (no edges claimed from them) and proposals "
                        "for the principals they attach to are manual",
                    )
        return self.managed_cache[arn]

    def _organizations(self, account: str) -> tuple[list[list[dict]], bool]:
        levels = []
        try:
            org = self._call(self.organizations, "describe_organization")["Organization"]
            if org.get("MasterAccountId", org.get("ManagementAccountId")) == account:
                self.coverage["scp_inventory"] = "management_account_exempt"
                return [], True
            visited = set()
            target = account
            while True:
                if target in visited or len(visited) >= self.limits.max_org_depth:
                    raise CollectionIncomplete("Organizations ancestor cycle or depth budget exhausted")
                visited.add(target)
                policies, policy_ids = [], set()
                for page in self._pages(
                    self.organizations,
                    "list_policies_for_target",
                    TargetId=target,
                    Filter="SERVICE_CONTROL_POLICY",
                    MaxResults=20,
                ):
                    for policy in page["Policies"]:
                        policy_id = policy["Id"]
                        if policy_id in policy_ids:
                            continue
                        policy_ids.add(policy_id)
                        if policy_id not in self.scp_cache:
                            self.scp_cache[policy_id] = self._policy(
                                self._call(self.organizations, "describe_policy", PolicyId=policy_id)[
                                    "Policy"
                                ]["Content"]
                            )
                        policies.append(self.scp_cache[policy_id])
                if policies:
                    levels.append(policies)
                if target.startswith("r-"):
                    break
                parents = {}
                for page in self._pages(self.organizations, "list_parents", ChildId=target, MaxResults=20):
                    for parent in page["Parents"]:
                        parents[parent["Id"]] = parent
                if len(parents) != 1:
                    raise CollectionIncomplete("Organizations ancestor inventory is incomplete or ambiguous")
                target = next(iter(parents))
            self.coverage["scp_inventory"] = "collected"
            return levels, False  # Other policy domains are still uncollected.
        except (ClientError, BotoCoreError):
            self._warning(
                "organizations_unknown",
                "Organizations policy collection incomplete; AWS edges remain conditional",
            )
            self.coverage["scp_inventory"] = "partial" if levels else "unknown"
            return levels, False

    def _identity(self):
        identity = self._call(self.sts, "get_caller_identity")
        account, arn = identity.get("Account", ""), identity.get("Arn", "")
        parts = arn.split(":")
        if (
            not re.fullmatch(r"\d{12}", account)
            or len(parts) < 6
            or parts[0] != "arn"
            or parts[2] not in {"iam", "sts"}
            or parts[1] not in {"aws", "aws-us-gov", "aws-cn"}
            or parts[4] != account
        ):
            raise CollectionIncomplete("Caller identity account or partition could not be verified")
        if self.expected_account and account != self.expected_account:
            raise CollectionIncomplete("Caller identity does not match the explicitly expected account")
        if self.expected_role_arn:
            match = ROLE_ARN.fullmatch(self.expected_role_arn)
            if (
                not match
                or match[1] != parts[1]
                or match[2] != account
                or not arn.startswith(
                    f"arn:{match[1]}:sts::{account}:assumed-role/{match[3].rsplit('/', 1)[-1]}/"
                )
            ):
                raise CollectionIncomplete("Caller identity does not match the explicitly expected role")
        self.account = account
        self.coverage["caller_identity_verified"] = True
        return account, parts[1]

    def _inventory(self, account: str, partition: str):
        roles, users, groups, buckets = {}, {}, {}, {}
        kinds = (
            ("RoleDetailList", "role", roles, self.limits.max_roles, "roles"),
            ("UserDetailList", "user", users, self.limits.max_users, "users"),
            ("GroupDetailList", "group", groups, self.limits.max_groups, "groups"),
        )
        for page in self._pages(
            self.iam,
            "get_account_authorization_details",
            token="Marker",
            truncated=True,
            Filter=["Role", "User", "Group"],
            MaxItems=100,
        ):
            for field, kind, found, limit, label in kinds:
                for item in page.get(field, []):
                    arn = item["Arn"]
                    if not arn.startswith(f"arn:{partition}:iam::{account}:{kind}/"):
                        raise CollectionIncomplete(
                            f"IAM {kind} inventory crosses verified account or partition"
                        )
                    if arn in found:
                        if found[arn] != item:
                            raise CollectionIncomplete(f"Conflicting duplicate IAM {kind} inventory")
                        continue
                    if len(found) >= limit:
                        raise CollectionIncomplete(f"IAM {kind} inventory budget exhausted")
                    found[arn] = dict(item)
                    self.counts[label] = len(found)
        self.coverage["iam_role_inventory_complete"] = True
        self.coverage["iam_user_inventory_complete"] = True
        self.coverage["iam_group_inventory_complete"] = True
        for page in self._pages(self.s3, "list_buckets", token="ContinuationToken", MaxBuckets=100):
            for bucket in page["Buckets"]:
                name = bucket["Name"]
                if name in buckets:
                    if buckets[name] != bucket:
                        raise CollectionIncomplete("Conflicting duplicate bucket inventory")
                    continue
                if len(buckets) >= self.limits.max_buckets:
                    raise CollectionIncomplete("S3 bucket inventory budget exhausted")
                buckets[name] = bucket
                self.counts["buckets"] = len(buckets)
        self.coverage["general_purpose_bucket_inventory_complete"] = True
        self.counts.update(roles=len(roles), users=len(users), groups=len(groups), buckets=len(buckets))
        principals = len(roles) + len(users)
        # Each principal x bucket x 6 S3 actions, and each principal x role AssumeRole (not itself).
        evaluations = principals * len(buckets) * 6 + principals * len(roles) - len(roles)
        if evaluations > self.limits.max_evaluations:
            raise CollectionIncomplete("Permission evaluation budget exhausted before enrichment")
        return list(roles.values()), list(users.values()), list(groups.values()), list(buckets.values())

    def _optional(self, client, operation, name, *, absent=None):
        try:
            response = self._call(client, operation, Bucket=name, ExpectedBucketOwner=self.account)
            field = {
                "get_bucket_policy": "Policy",
                "get_bucket_tagging": "TagSet",
                "get_bucket_encryption": "ServerSideEncryptionConfiguration",
            }[operation]
            if isinstance(response, dict) and field in response:
                return response, "observed"
        except ClientError as exc:
            if absent and exc.response.get("Error", {}).get("Code") == absent:
                return {}, "absent"
        except BotoCoreError:
            pass
        self._warning(
            operation + "_unknown",
            {
                "get_bucket_policy": "Bucket policy unavailable for one or more buckets",
                "get_bucket_tagging": "Classification tags unavailable for one or more buckets",
                "get_bucket_encryption": "Encryption configuration could not be verified for one or more buckets",
            }[operation],
        )
        return {}, "unknown"

    def _attach(self, principal: str, kind: str, name: str, document: dict, arn: str = "") -> None:
        """Keep a decoded policy document for SQL storage (content-hashed at publication)."""
        attachment = PolicyAttachment(
            principal=principal, kind=kind, name=name[:256], arn=arn, document=document
        )
        if attachment.id in self.attachment_ids:
            return
        if len(self.attachments) >= self.limits.max_policy_attachments:
            raise CollectionIncomplete("Policy attachment budget exhausted")
        self.attachment_ids.add(attachment.id)
        self.attachments.append(attachment)

    def _identity_policies(self, principal: str, detail: dict, inline_field: str) -> list[dict]:
        """Decoded inline + attached managed policies of a role or user; attachments recorded."""
        policies = []
        for position, item in enumerate(detail.get(inline_field, [])):
            document = self._policy(item["PolicyDocument"])
            self._attach(principal, "inline", item.get("PolicyName") or f"inline-{position}", document)
            policies.append(document)
        attached = {
            p["PolicyArn"]: p.get("PolicyName", "") for p in detail.get("AttachedManagedPolicies", [])
        }
        if len(attached) > 100:
            raise CollectionIncomplete("Policy reference budget exhausted")
        for arn, name in attached.items():
            document = self._managed(arn)
            self._attach(principal, "managed", name or arn.rsplit("/", 1)[-1], document, arn)
            if is_unevaluated(document):
                _unevaluated(detail, arn)
                continue
            policies.append(document)
        return policies

    def _boundary(self, principal: str, detail: dict) -> list[dict] | None:
        boundary_arn = detail.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")
        if not boundary_arn:
            return None
        document = self._managed(boundary_arn)
        self._attach(principal, "boundary", boundary_arn.rsplit("/", 1)[-1], document, boundary_arn)
        if is_unevaluated(document):
            # An unknown boundary allows nothing we can claim: no edges for this principal.
            _unevaluated(detail, boundary_arn)
            return [{"Statement": []}]
        return [document]

    def _tags(self, tags: list[dict], keep: int = MAX_TAGS) -> tuple[list[str], int]:
        """Raw ``key=value`` tags (sorted, bounded) and how many were dropped."""
        values = sorted({f"{tag['Key']}={tag.get('Value', '')}"[:256] for tag in tags if tag.get("Key")})
        if len(values) > keep:
            self._warning("tags_truncated", "Some tags were dropped beyond the per-entity tag bound")
        return values[:keep], max(0, len(values) - keep)

    def _access_advisor(self, principals: list[str]) -> dict[str, dict]:
        """Optional IAM Access Advisor service last-accessed hints (never proof of non-use)."""
        hints: dict[str, dict] = {}
        if not self.access_advisor:
            return hints
        selected = sorted(principals)[: self.limits.max_access_advisor_jobs]
        if len(principals) > len(selected):
            self._warning(
                "access_advisor_bounded",
                "Access Advisor hints were requested for a bounded subset of principals",
            )
        advisor = AccessAdvisorCollector(_CountedClient(self, self.iam))
        jobs: dict[str, str] = {}
        try:
            for arn in selected:
                jobs[arn] = advisor.start(arn)
            for _ in range(ACCESS_ADVISOR_POLLS):
                for arn in sorted(set(jobs) - set(hints)):
                    result = advisor.result(jobs[arn])
                    if result["status"] == "COMPLETED":
                        hints[arn] = {
                            "basis": "access_advisor_activity_hint",
                            "services": [
                                {
                                    "service": service["service"],
                                    "last_authenticated": _iso(service["last_authenticated"]),
                                }
                                for service in result["services"][:MAX_ADVISOR_SERVICES]
                            ],
                        }
                    elif result["status"] == "FAILED":
                        hints[arn] = {
                            "basis": "access_advisor_activity_hint",
                            "status": "failed",
                            "services": [],
                        }
                if len(hints) == len(jobs):
                    break
                self._sleep(1.0)
        except (ClientError, BotoCoreError):
            self._warning(
                "access_advisor_unknown", "Access Advisor hints unavailable for one or more principals"
            )
        if len(hints) < len(jobs):
            self._warning(
                "access_advisor_incomplete", "Access Advisor jobs did not complete within the poll budget"
            )
        self.coverage["access_advisor"] = {"requested": len(jobs), "completed": len(hints)}
        return {arn: hint for arn, hint in hints.items() if hint.get("status") != "failed"}

    def collect(self) -> GraphSnapshot:
        self._reset()
        account, partition = self._identity()
        roles, users, groups, buckets = self._inventory(account, partition)
        scps, _ = self._organizations(account)
        nodes, edges = {}, {}
        group_details = {group["GroupName"]: group for group in groups}
        group_policies: dict[str, list[tuple[str, dict, str, str]]] = {}
        principals: list[dict] = []
        for role in roles:
            policies = self._identity_policies(role["Arn"], role, "RolePolicyList")
            role["policies"] = policies
            role["boundary"] = self._boundary(role["Arn"], role)
            role["trust"] = self._policy(role["AssumeRolePolicyDocument"])
            self._attach(role["Arn"], "trust", "trust", role["trust"])
            linked = ":role/aws-service-role/" in role["Arn"]
            role["scps"] = [] if linked else scps
            tags, dropped = self._tags(role.get("Tags", []))
            metadata = {
                "policy_count": len(policies),
                "scp_inventory": self.coverage["scp_inventory"],
                "scp_exempt_service_linked_role": linked,
            }
            last_used = role.get("RoleLastUsed") or {}
            if last_used.get("LastUsedDate"):
                metadata["role_last_used"] = _iso(last_used["LastUsedDate"])
                metadata["role_last_used_region"] = str(last_used.get("Region", ""))[:64]
                self.coverage["role_last_used"]["observed"] += 1
            else:
                self.coverage["role_last_used"]["absent"] += 1
            if dropped:
                metadata["tags_dropped"] = dropped
            if role.get("unevaluated"):
                metadata["policies_unevaluated"] = sorted(role["unevaluated"])[:MAX_UNEVALUATED_PER_PRINCIPAL]
            nodes[role["Arn"]] = Node(
                id=role["Arn"],
                name=role["RoleName"],
                type=NodeType.ROLE,
                account_id=account,
                provider="aws",
                tags=tags,
                privileged=_privileged(policies),
                metadata=metadata,
            )
            principals.append(role)
        for user in users:
            policies = self._identity_policies(user["Arn"], user, "UserPolicyList")
            memberships = sorted(set(user.get("GroupList", [])))
            for name in memberships:
                group = group_details.get(name)
                if group is None:
                    raise CollectionIncomplete("IAM user belongs to a group missing from the inventory")
                if name not in group_policies:
                    group_policies[name] = []
                    for position, item in enumerate(group.get("GroupPolicyList", [])):
                        document = self._policy(item["PolicyDocument"])
                        policy = item.get("PolicyName") or f"inline-{position}"
                        group_policies[name].append(("group-inline", document, f"{name}/{policy}", ""))
                    attached = {
                        p["PolicyArn"]: p.get("PolicyName", "")
                        for p in group.get("AttachedManagedPolicies", [])
                    }
                    if len(attached) > 100:
                        raise CollectionIncomplete("Policy reference budget exhausted")
                    for arn, policy in attached.items():
                        label = policy or arn.rsplit("/", 1)[-1]
                        group_policies[name].append(
                            ("group-managed", self._managed(arn), f"{name}/{label}", arn)
                        )
                for kind, document, label, arn in group_policies[name]:
                    self._attach(user["Arn"], kind, label, document, arn)
                    if is_unevaluated(document):
                        _unevaluated(user, arn)
                        continue
                    policies.append(document)
            user["policies"] = policies
            user["boundary"] = self._boundary(user["Arn"], user)
            user["scps"] = scps
            tags, dropped = self._tags(user.get("Tags", []))
            metadata = {
                "iam_user": True,
                "policy_count": len(policies),
                "groups": memberships[:50],
                "scp_inventory": self.coverage["scp_inventory"],
            }
            if dropped:
                metadata["tags_dropped"] = dropped
            if user.get("unevaluated"):
                metadata["policies_unevaluated"] = sorted(user["unevaluated"])[:MAX_UNEVALUATED_PER_PRINCIPAL]
            nodes[user["Arn"]] = Node(
                id=user["Arn"],
                name=user["UserName"],
                type=NodeType.HUMAN,
                account_id=account,
                provider="aws",
                tags=tags,
                privileged=_privileged(policies),
                metadata=metadata,
            )
            principals.append(user)
        advisor = self._access_advisor([principal["Arn"] for principal in principals])
        for arn, hint in advisor.items():
            nodes[arn] = nodes[arn].model_copy(
                update={"metadata": {**nodes[arn].metadata, "access_advisor": hint}}
            )
        region_clients = {}
        for bucket in buckets:
            name = bucket["Name"]
            arn = f"arn:{partition}:s3:::{name}"
            client = self.s3
            if region := bucket.get("BucketRegion"):
                if region not in region_clients:
                    region_clients[region] = self.session.client("s3", region_name=region, config=SDK_CONFIG)
                client = region_clients[region]
            policy, policy_status = self._optional(
                client, "get_bucket_policy", name, absent="NoSuchBucketPolicy"
            )
            tagging, tag_status = self._optional(client, "get_bucket_tagging", name, absent="NoSuchTagSet")
            encryption, encryption_status = self._optional(client, "get_bucket_encryption", name)
            resource_policies = [self._policy(policy["Policy"])] if policy_status == "observed" else []
            tags = [str(tag["Key"]) + " " + str(tag["Value"]) for tag in tagging.get("TagSet", [])]
            rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            verified = (
                encryption_status == "observed"
                and bool(rules)
                and all(
                    rule.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
                    in {"AES256", "aws:kms", "aws:kms:dsse"}
                    for rule in rules
                )
            )
            if not verified:
                encryption_status = "unknown"
                self._warning(
                    "encryption_unknown",
                    "Encryption configuration could not be verified for one or more buckets",
                )
            self.coverage["bucket_policy"][policy_status] += 1
            self.coverage["classification_tags"][tag_status] += 1
            self.coverage["encryption_configuration"][encryption_status] += 1
            enriched = enrich_node(
                Node(
                    id=arn,
                    name=name,
                    type=NodeType.BUCKET,
                    account_id=account,
                    provider="aws",
                    encrypted=True,
                    metadata={
                        "bucket_policy": policy_status,
                        "classification_tags": tag_status,
                        "encryption_verified": verified,
                        "encryption_configuration": encryption_status,
                        "object_encryption_verified": False,
                    },
                ),
                [name, *tags],
                tags=[
                    (str(tag.get("Key", "")), str(tag.get("Value", ""))) for tag in tagging.get("TagSet", [])
                ],
            )
            # Raw tags (topic anchors such as topic=/app=/team=) beside classification labels.
            raw, dropped = self._tags(tagging.get("TagSet", []), MAX_TAGS - len(enriched.tags))
            if raw or dropped:
                update = {"tags": sorted(set(enriched.tags) | set(raw))}
                if dropped:
                    update["metadata"] = {**enriched.metadata, "tags_dropped": dropped}
                enriched = enriched.model_copy(update=update)
            nodes[arn] = enriched
            for principal in principals:
                for kind, actions in [(EdgeType.READ, READ_ACTIONS), (EdgeType.WRITE, WRITE_ACTIONS)]:
                    possible = []
                    for action in actions:
                        self._check_time()
                        self.counts["evaluations"] += 1
                        result = evaluate(
                            Request(
                                principal["Arn"],
                                action,
                                arn if action == "s3:ListBucket" else arn + "/*",
                                {"aws:PrincipalArn": principal["Arn"], "aws:PrincipalAccount": account},
                            ),
                            principal["policies"],
                            resource_policies,
                            principal["boundary"],
                            principal["scps"],
                            scope_complete=False,
                        )
                        if result.decision != Decision.DENY:
                            possible.append(action)
                    if possible:
                        edge = Edge(
                            source=principal["Arn"],
                            target=arn,
                            type=kind,
                            actions=possible,
                            certainty="conditional",
                            evidence=[
                                "IAM identity + available bucket policy/boundary/SCP metadata; object scope, ACLs, RCPs and session context unresolved",
                                *_unevaluated_evidence(principal),
                            ],
                        )
                        self._edge(edges, edge)
        for source in principals:
            for target in roles:
                if source["Arn"] == target["Arn"]:
                    continue
                self._check_time()
                self.counts["evaluations"] += 1
                result = evaluate(
                    Request(
                        source["Arn"], "sts:AssumeRole", target["Arn"], {"aws:PrincipalArn": source["Arn"]}
                    ),
                    source["policies"],
                    [target["trust"]],
                    boundary=source["boundary"],
                    scp_levels=source["scps"],
                    require_resource_allow=True,
                    scope_complete=True,
                )
                if result.decision != Decision.DENY:
                    self._edge(
                        edges,
                        Edge(
                            source=source["Arn"],
                            target=target["Arn"],
                            type=EdgeType.ASSUMES,
                            certainty="conditional",
                            actions=["sts:AssumeRole"],
                            evidence=[
                                *result.reasons,
                                "Trust and identity policies collected; missing policy domains can restrict access; AWS access remains conditional",
                                *_unevaluated_evidence(source),
                            ],
                        ),
                    )
        self.counts["edges"] = len(edges)
        self.counts["policy_attachments"] = len(self.attachments)
        self._warning(
            "scope_incomplete",
            "Initial AWS scope: IAM roles, users and groups and general-purpose S3 metadata; no object contents, cross-account inventory or database grants; RCPs, VPC endpoint policies, ACLs and session policies are not collected; all AWS edges conditional; RoleLastUsed and Access Advisor are hints, never proof of non-use",
        )
        return GraphSnapshot(
            nodes=list(nodes.values()),
            edges=list(edges.values()),
            warnings=self.warnings,
            source=f"aws:{account}",
            policies=self.attachments,
        )

    def _edge(self, edges, edge):
        if edge.id not in edges and len(edges) >= self.limits.max_edges:
            raise CollectionIncomplete("Graph edge budget exhausted")
        edges[edge.id] = edge

    def qualification_artifact(self, account: str, role_arn: str, region: str, status: str):
        return {
            "schema_version": 1,
            "status": status,
            "target_account_sha256": hashlib.sha256(account.encode()).hexdigest(),
            "target_role_sha256": hashlib.sha256(role_arn.encode()).hexdigest(),
            "region": region,
            "counts": self.counts,
            "coverage": self.coverage,
            "warning_counts": self.warning_counts,
            "limits": asdict(self.limits),
            "sdk_requests": self.requests,
            "sdk_pages": self.pages,
            "duration_seconds": round(time.monotonic() - self.started, 3),
        }


def access_advisor_default() -> bool:
    """``ZG_AWS_ACCESS_ADVISOR`` parsed as ``Settings.aws_access_advisor`` is (default false).

    Read directly so the qualification CLI does not need the server's other settings.
    """
    from pydantic import TypeAdapter

    value = os.environ.get("ZG_AWS_ACCESS_ADVISOR", "").strip()
    return TypeAdapter(bool).validate_python(value) if value else False


def expected_target(role_arn: str, account: str = "") -> tuple[str, str]:
    """``(expected_account, expected_role_arn)`` the STS caller identity must match.

    The account comes from ``account`` when given, else from ``role_arn``; a malformed
    role ARN or a configured account that differs from the ARN's account is an error.
    """
    match = ROLE_ARN.fullmatch(role_arn)
    if not match:
        raise ValueError("AWS collector role ARN is not an IAM role ARN")
    if account and account != match[2]:
        raise ValueError("AWS collector account does not match the role ARN's account")
    return match[2], role_arn


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Explicit read-only sandbox AWS inventory qualification; never publishes graph data"
    )
    parser.add_argument("--profile", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--account", required=True)
    parser.add_argument("--role-arn", required=True)
    parser.add_argument("--confirm-account", required=True)
    parser.add_argument("--confirm-role", required=True)
    parser.add_argument("--ack-readonly-sandbox", action="store_true", required=True)
    parser.add_argument("--external-id-env")
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument(
        "--access-advisor",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Collect IAM Access Advisor hints (default: ZG_AWS_ACCESS_ADVISOR, as the in-app collector)",
    )
    args = parser.parse_args()
    try:
        access_advisor = access_advisor_default() if args.access_advisor is None else args.access_advisor
    except ValueError:
        parser.error("ZG_AWS_ACCESS_ADVISOR must be a boolean")
    match = ROLE_ARN.fullmatch(args.role_arn)
    if (
        not match
        or match[2] != args.account
        or args.confirm_account != args.account
        or args.confirm_role != args.role_arn
    ):
        parser.error("Account, role and explicit confirmations must match")
    if args.external_id_env and not os.environ.get(args.external_id_env):
        parser.error("External ID environment variable is missing")
    # Exclusive file reservation precedes credentials/network discovery; never overwrite artifacts.
    fd = os.open(args.artifact, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    collector = None
    artifact = {
        "schema_version": 1,
        "status": "failed",
        "target_account_sha256": hashlib.sha256(args.account.encode()).hexdigest(),
        "target_role_sha256": hashlib.sha256(args.role_arn.encode()).hexdigest(),
        "region": args.region,
        "counts": {"roles": 0, "buckets": 0, "edges": 0, "evaluations": 0},
        "coverage": {
            "effective_permissions_complete": False,
            "caller_identity_verified": False,
            "iam_role_inventory_complete": False,
            "general_purpose_bucket_inventory_complete": False,
        },
        "warning_counts": {},
        "limits": asdict(CollectionLimits()),
        "sdk_requests": 0,
        "sdk_pages": 0,
        "duration_seconds": 0,
    }
    failed = False
    try:
        bootstrap = boto3.Session(profile_name=args.profile, region_name=args.region)
        kwargs = {
            "RoleArn": args.role_arn,
            "RoleSessionName": "ZeroGraphSandboxQualification",
            "DurationSeconds": 900,
        }
        if args.external_id_env:
            kwargs["ExternalId"] = os.environ[args.external_id_env]
        credentials = bootstrap.client("sts", config=SDK_CONFIG).assume_role(**kwargs)["Credentials"]
        assumed = boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=args.region,
        )
        collector = AWSCollector(
            assumed,
            expected_account=args.account,
            expected_role_arn=args.role_arn,
            access_advisor=access_advisor,
        )
        collector.collect()  # STS target confirmation is checked before any inventory call.
        artifact = collector.qualification_artifact(
            args.account,
            args.role_arn,
            args.region,
            "read_only_inventory_complete_with_metadata_gaps"
            if any(
                collector.coverage[key]["unknown"]
                for key in ("bucket_policy", "classification_tags", "encryption_configuration")
            )
            or collector.coverage["scp_inventory"] in {"unknown", "partial"}
            else "read_only_inventory_complete_with_unverified_permissions",
        )
    except Exception:
        failed = True
        if collector:
            artifact = collector.qualification_artifact(args.account, args.role_arn, args.region, "failed")
    finally:
        with os.fdopen(fd, "w") as output:
            json.dump(artifact, output, sort_keys=True, indent=2)
            output.write("\n")
    if failed:
        parser.exit(
            1, "Read-only qualification failed; inspect sanitized artifact and connector permissions.\n"
        )
    print("Read-only inventory qualification complete; effective permission coverage remains incomplete.")


if __name__ == "__main__":
    main()
