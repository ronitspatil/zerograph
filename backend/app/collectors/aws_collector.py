"""Read-only AWS collector. S3 is the initial resource permission domain."""

import json
from typing import Any
from urllib.parse import unquote

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from app.collectors.data_classifier import enrich_node
from app.collectors.iam_evaluator import Decision, Request, evaluate
from app.graph.schema import Edge, EdgeType, GraphSnapshot, Node, NodeType

READ_ACTIONS = ("s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket")
WRITE_ACTIONS = ("s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion")


def decode_policy(document: dict | str) -> dict:
    return document if isinstance(document, dict) else json.loads(unquote(document))


class AWSCollector:
    def __init__(self, session: boto3.Session):
        config = Config(retries={"mode": "adaptive", "max_attempts": 5}, connect_timeout=5, read_timeout=20)
        self.iam = session.client("iam", config=config)
        self.s3 = session.client("s3", config=config)
        self.sts = session.client("sts", config=config)
        self.organizations = session.client("organizations", config=config)
        self.warnings: list[str] = []

    def _managed(self, arn: str) -> dict:
        version = self.iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
        return decode_policy(
            self.iam.get_policy_version(PolicyArn=arn, VersionId=version)["PolicyVersion"]["Document"]
        )

    def _organizations(self, account: str) -> tuple[list[list[dict]], bool]:
        try:
            org = self.organizations.describe_organization()["Organization"]
            if org.get("MasterAccountId", org.get("ManagementAccountId")) == account:
                return [], True  # SCPs do not restrict the management account.
            levels = []
            target = account
            while True:
                policies = []
                for page in self.organizations.get_paginator("list_policies_for_target").paginate(
                    TargetId=target, Filter="SERVICE_CONTROL_POLICY"
                ):
                    for policy in page["Policies"]:
                        content = self.organizations.describe_policy(PolicyId=policy["Id"])["Policy"][
                            "Content"
                        ]
                        policies.append(json.loads(content))
                if policies:
                    levels.append(policies)
                parents = self.organizations.list_parents(ChildId=target)["Parents"]
                if not parents:
                    break
                target = parents[0]["Id"]
                if target.startswith("r-"):
                    # Include root on the next iteration, then stop.
                    root_policies = []
                    for page in self.organizations.get_paginator("list_policies_for_target").paginate(
                        TargetId=target, Filter="SERVICE_CONTROL_POLICY"
                    ):
                        for p in page["Policies"]:
                            root_policies.append(
                                json.loads(
                                    self.organizations.describe_policy(PolicyId=p["Id"])["Policy"]["Content"]
                                )
                            )
                    if root_policies:
                        levels.append(root_policies)
                    break
            # RCP collection is not implemented; do not claim confirmed effective permissions.
            self.warnings.append(
                "RCPs, VPC endpoint policies, ACLs and session policies are not collected; AWS edges are conditional"
            )
            return levels, False
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "AWSOrganizationsNotInUseException":
                self.warnings.append(
                    "VPC endpoint policies, ACLs and session policies are not collected; AWS edges are conditional"
                )
                return [], False
            self.warnings.append(f"Organizations policy collection incomplete ({code})")
            return [], False

    def collect(self) -> GraphSnapshot:
        account = self.sts.get_caller_identity()["Account"]
        scps, complete = self._organizations(account)
        nodes: dict[str, Node] = {}
        roles: list[dict[str, Any]] = []
        edges: dict[str, Edge] = {}
        for page in self.iam.get_paginator("get_account_authorization_details").paginate(
            Filter=["Role", "User", "Group", "LocalManagedPolicy", "AWSManagedPolicy"]
        ):
            roles.extend(page.get("RoleDetailList", []))
        for role in roles:
            arn = role["Arn"]
            policies = [decode_policy(p["PolicyDocument"]) for p in role.get("RolePolicyList", [])]
            policies.extend(self._managed(p["PolicyArn"]) for p in role.get("AttachedManagedPolicies", []))
            boundary_arn = role.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")
            role["policies"] = policies
            role["boundary"] = [self._managed(boundary_arn)] if boundary_arn else None
            nodes[arn] = Node(
                id=arn,
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
                metadata={"policy_count": len(policies)},
            )
        for bucket in self.s3.list_buckets()["Buckets"]:
            name = bucket["Name"]
            arn = f"arn:aws:s3:::{name}"
            resource_policies = []
            encrypted = True
            try:
                resource_policies.append(json.loads(self.s3.get_bucket_policy(Bucket=name)["Policy"]))
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchBucketPolicy":
                    self.warnings.append(f"{name}: bucket policy unavailable")
            tags = []
            try:
                tags = [
                    str(t["Key"]) + " " + str(t["Value"])
                    for t in self.s3.get_bucket_tagging(Bucket=name)["TagSet"]
                ]
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchTagSet":
                    self.warnings.append(f"{name}: classification tags unavailable")
            try:
                self.s3.get_bucket_encryption(Bucket=name)
            except ClientError:
                # Unknown encryption is not evidence of an unencrypted bucket.
                self.warnings.append(f"{name}: encryption configuration could not be verified")
            node = enrich_node(
                Node(
                    id=arn,
                    name=name,
                    type=NodeType.BUCKET,
                    account_id=account,
                    provider="aws",
                    encrypted=encrypted,
                ),
                [name, *tags],
            )
            nodes[arn] = node
            for role in roles:
                for kind, actions in [(EdgeType.READ, READ_ACTIONS), (EdgeType.WRITE, WRITE_ACTIONS)]:
                    possible = []
                    for action in actions:
                        resource = arn if action == "s3:ListBucket" else arn + "/*"
                        result = evaluate(
                            Request(
                                role["Arn"],
                                action,
                                resource,
                                {"aws:PrincipalArn": role["Arn"], "aws:PrincipalAccount": account},
                            ),
                            role["policies"],
                            resource_policies,
                            role["boundary"],
                            scps,
                            scope_complete=complete,
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
                                "IAM + bucket policy + boundary + available SCPs; object scope and session context unresolved"
                            ],
                        )
                        edges[edge.id] = edge
        for source in roles:
            for target in roles:
                if source["Arn"] == target["Arn"]:
                    continue
                result = evaluate(
                    Request(
                        source["Arn"], "sts:AssumeRole", target["Arn"], {"aws:PrincipalArn": source["Arn"]}
                    ),
                    source["policies"],
                    [decode_policy(target["AssumeRolePolicyDocument"])],
                    boundary=source["boundary"],
                    scp_levels=scps,
                    require_resource_allow=True,
                    scope_complete=complete,
                )
                if result.decision != Decision.DENY:
                    edge = Edge(
                        source=source["Arn"],
                        target=target["Arn"],
                        type=EdgeType.ASSUMES,
                        certainty="conditional",
                        actions=["sts:AssumeRole"],
                        evidence=list(result.reasons),
                    )
                    edges[edge.id] = edge
        self.warnings.append(
            "Initial AWS scope: IAM roles and S3 metadata; no object contents, IAM-user grants, cross-account inventory or database grants"
        )
        return GraphSnapshot(
            nodes=list(nodes.values()),
            edges=list(edges.values()),
            warnings=self.warnings[:1000],
            source=f"aws:{account}",
        )
