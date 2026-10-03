"""Bounded, read-only IAM-role and S3-metadata inventory; never confirmed access."""

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
from app.collectors.iam_evaluator import Decision, Request, evaluate
from app.graph.schema import Edge, EdgeType, GraphSnapshot, Node, NodeType

READ_ACTIONS = ("s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket")
WRITE_ACTIONS = ("s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion")
SDK_CONFIG = Config(retries={"mode": "standard", "total_max_attempts": 3}, connect_timeout=5, read_timeout=10)
HARD_LIMITS = {
    "max_roles": 1000,
    "max_buckets": 1000,
    "max_pages": 1000,
    "max_requests": 10000,
    "max_policy_documents": 5000,
    "max_evaluations": 1000000,
    "max_edges": 15000,
    "max_org_depth": 20,
    "max_seconds": 600,
}
MAX_POLICY_BYTES = 65536
MAX_POLICY_STATEMENTS = 256

ROLE_ARN = re.compile(r"arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role/(.+)")


class CollectionIncomplete(ValueError):
    """A bound or malformed inventory prevents safely publishing any snapshot."""


@dataclass(frozen=True)
class CollectionLimits:
    max_roles: int = 500
    max_buckets: int = 500
    max_pages: int = 100
    max_requests: int = 3000
    max_policy_documents: int = 1000
    max_evaluations: int = 100000
    max_edges: int = 15000
    max_org_depth: int = 10
    max_seconds: int = 600

    def __post_init__(self):
        for key, value in asdict(self).items():
            if type(value) is not int or not 1 <= value <= HARD_LIMITS[key]:
                raise ValueError(f"Collection limit {key} must be 1..{HARD_LIMITS[key]}")


def decode_policy(document: dict | str) -> dict:
    encoded = json.dumps(document) if isinstance(document, dict) else document
    if not isinstance(encoded, str) or len(encoded.encode()) > MAX_POLICY_BYTES:
        raise CollectionIncomplete("Policy document byte budget exhausted")
    policy = document if isinstance(document, dict) else json.loads(unquote(document))
    if not isinstance(policy, dict):
        raise CollectionIncomplete("Policy document is not an object")
    statements = policy.get("Statement", [])
    statements = statements if isinstance(statements, list) else [statements]
    if len(statements) > MAX_POLICY_STATEMENTS:
        raise CollectionIncomplete("Policy statement budget exhausted")
    if not all(isinstance(statement, dict) for statement in statements):
        raise CollectionIncomplete("Policy statement is not an object")
    return policy


class AWSCollector:
    def __init__(
        self,
        session: boto3.Session,
        limits: CollectionLimits | None = None,
        *,
        expected_account: str | None = None,
        expected_role_arn: str | None = None,
    ):
        self.session, self.limits = session, limits or CollectionLimits()
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
        }
        self.counts = {"roles": 0, "buckets": 0, "edges": 0, "evaluations": 0}

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

    def _policy(self, document):
        if self.policy_documents >= self.limits.max_policy_documents:
            raise CollectionIncomplete("Policy document budget exhausted")
        self.policy_documents += 1
        return decode_policy(document)

    def _managed(self, arn: str) -> dict:
        if arn not in self.managed_cache:
            version = self._call(self.iam, "get_policy", PolicyArn=arn)["Policy"]["DefaultVersionId"]
            self.managed_cache[arn] = self._policy(
                self._call(self.iam, "get_policy_version", PolicyArn=arn, VersionId=version)["PolicyVersion"][
                    "Document"
                ]
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
        roles, buckets = {}, {}
        for page in self._pages(
            self.iam,
            "get_account_authorization_details",
            token="Marker",
            truncated=True,
            Filter=["Role"],
            MaxItems=100,
        ):
            for role in page.get("RoleDetailList", []):
                arn = role["Arn"]
                if not arn.startswith(f"arn:{partition}:iam::{account}:role/"):
                    raise CollectionIncomplete("Role inventory crosses verified account or partition")
                if arn in roles:
                    if roles[arn] != role:
                        raise CollectionIncomplete("Conflicting duplicate IAM role inventory")
                    continue
                if len(roles) >= self.limits.max_roles:
                    raise CollectionIncomplete("IAM role inventory budget exhausted")
                roles[arn] = dict(role)
                self.counts["roles"] = len(roles)
        self.coverage["iam_role_inventory_complete"] = True
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
        self.counts.update(roles=len(roles), buckets=len(buckets))
        evaluations = len(roles) * len(buckets) * 6 + len(roles) * (len(roles) - 1)
        if evaluations > self.limits.max_evaluations:
            raise CollectionIncomplete("Permission evaluation budget exhausted before enrichment")
        return list(roles.values()), list(buckets.values())

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

    def collect(self) -> GraphSnapshot:
        self._reset()
        account, partition = self._identity()
        roles, buckets = self._inventory(account, partition)
        scps, _ = self._organizations(account)
        nodes, edges = {}, {}
        for role in roles:
            policies = [self._policy(p["PolicyDocument"]) for p in role.get("RolePolicyList", [])]
            attached = dict.fromkeys(p["PolicyArn"] for p in role.get("AttachedManagedPolicies", []))
            if len(attached) > 100:
                raise CollectionIncomplete("Role policy reference budget exhausted")
            policies.extend(self._managed(arn) for arn in attached)
            boundary_arn = role.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")
            role["policies"] = policies
            role["boundary"] = [self._managed(boundary_arn)] if boundary_arn else None
            role["trust"] = self._policy(role["AssumeRolePolicyDocument"])
            linked = ":role/aws-service-role/" in role["Arn"]
            role["scps"] = [] if linked else scps
            nodes[role["Arn"]] = Node(
                id=role["Arn"],
                name=role["RoleName"],
                type=NodeType.ROLE,
                account_id=account,
                provider="aws",
                privileged=any(
                    s.get("Effect") == "Allow" and s.get("Action") in ("*", ["*"])
                    for p in policies
                    for s in (
                        p.get("Statement", [])
                        if isinstance(p.get("Statement", []), list)
                        else [p["Statement"]]
                    )
                ),
                metadata={
                    "policy_count": len(policies),
                    "scp_inventory": self.coverage["scp_inventory"],
                    "scp_exempt_service_linked_role": linked,
                },
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
            nodes[arn] = enrich_node(
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
            )
            for role in roles:
                for kind, actions in [(EdgeType.READ, READ_ACTIONS), (EdgeType.WRITE, WRITE_ACTIONS)]:
                    possible = []
                    for action in actions:
                        self._check_time()
                        self.counts["evaluations"] += 1
                        result = evaluate(
                            Request(
                                role["Arn"],
                                action,
                                arn if action == "s3:ListBucket" else arn + "/*",
                                {"aws:PrincipalArn": role["Arn"], "aws:PrincipalAccount": account},
                            ),
                            role["policies"],
                            resource_policies,
                            role["boundary"],
                            role["scps"],
                            scope_complete=False,
                        )
                        if result.decision != Decision.DENY:
                            possible.append(action)
                    if possible:
                        edge = Edge(
                            source=role["Arn"],
                            target=arn,
                            type=kind,
                            actions=possible,
                            certainty="conditional",
                            evidence=[
                                "IAM roles + available bucket policy/boundary/SCP metadata; object scope, ACLs, RCPs and session context unresolved"
                            ],
                        )
                        self._edge(edges, edge)
        for source in roles:
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
                                "Trust and role policies collected; missing policy domains can restrict access; AWS access remains conditional",
                            ],
                        ),
                    )
        self.counts["edges"] = len(edges)
        self._warning(
            "scope_incomplete",
            "Initial AWS scope: IAM roles and general-purpose S3 metadata; no object contents, IAM-user grants, cross-account inventory or database grants; RCPs, VPC endpoint policies, ACLs and session policies are not collected; all AWS edges conditional",
        )
        return GraphSnapshot(
            nodes=list(nodes.values()),
            edges=list(edges.values()),
            warnings=self.warnings,
            source=f"aws:{account}",
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
    args = parser.parse_args()
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
        collector = AWSCollector(assumed, expected_account=args.account, expected_role_arn=args.role_arn)
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
