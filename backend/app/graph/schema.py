import hashlib
import json
import re
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class NodeType(StrEnum):
    HUMAN = "HumanUser"
    SERVICE = "ServiceAccount"
    AGENT = "AIAgent"
    MCP = "MCPServer"
    ROLE = "CloudRole"
    DATABASE = "Database"
    VECTOR = "VectorStore"
    BUCKET = "S3Bucket"
    CATEGORY = "DataCategory"


class EdgeType(StrEnum):
    ASSUMES = "ASSUMES_ROLE"
    INHERITS = "INHERITS_PERMISSIONS"
    INVOKES = "INVOKES_TOOL"
    READ = "CAN_READ"
    WRITE = "CAN_WRITE"
    PII = "STORES_PII"


class Sensitivity(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class Node(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=512)
    type: NodeType
    name: str = Field(min_length=1, max_length=256)
    account_id: str = Field(default="", max_length=64)
    provider: str = Field(default="custom", max_length=32)
    sensitivity: Sensitivity = Sensitivity.INTERNAL
    tags: list[str] = Field(default_factory=list, max_length=32)
    internet_exposed: bool = False
    authenticated: bool = True
    encrypted: bool = True
    privileged: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class Edge(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: str
    target: str
    type: EdgeType
    actions: list[str] = Field(default_factory=list, max_length=500)
    certainty: Literal["confirmed", "conditional", "declared"] = "confirmed"
    evidence: list[str] = Field(default_factory=list, max_length=32)

    @property
    def id(self) -> str:
        content = (
            f"{self.source}\0{self.type}\0{self.target}\0{','.join(sorted(self.actions))}\0{self.certainty}"
        )
        return hashlib.sha256(content.encode()).hexdigest()[:24]


# Policy documents travel beside the graph (staged and stored in SQL per revision),
# never inside node JSON. Each document is bounded like the AWS collector's decoder:
# 64 KiB for customer-authored documents (AWS itself caps those far lower), 1 MiB for
# AWS-managed policies (``arn:<partition>:iam::aws:policy/...``), some of which exceed
# 64 KiB (``AWSSupportServiceRolePolicy`` is ~150 KB). Every revision's distinct
# documents also share ``app.graph.policies.MAX_REVISION_POLICY_BYTES``.
MAX_POLICY_BYTES = 65536
MAX_AWS_MANAGED_POLICY_BYTES = 2**20
AWS_MANAGED_POLICY_ARN = re.compile(r"arn:(?:aws|aws-us-gov|aws-cn):iam::aws:policy/.+")
MANAGED_POLICY_KINDS = ("managed", "boundary", "group-managed")
MAX_SNAPSHOT_POLICIES = 50_000
POLICY_KINDS = ("inline", "managed", "boundary", "trust", "group-inline", "group-managed")


def canonical_policy(document: dict) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def aws_managed_policy(arn: str) -> bool:
    """An AWS-managed policy ARN (owned by the ``aws`` account, not a customer account)."""
    return bool(AWS_MANAGED_POLICY_ARN.fullmatch(arn or ""))


def policy_byte_limit(kind: str, arn: str) -> int:
    """Canonical-JSON byte bound of one attached document of ``kind`` from ``arn``."""
    if kind in MANAGED_POLICY_KINDS and aws_managed_policy(arn):
        return MAX_AWS_MANAGED_POLICY_BYTES
    return MAX_POLICY_BYTES


class PolicyAttachment(BaseModel):
    """One policy document attached to a principal (a role, user or other identity).

    ``kind`` is how it applies: ``inline``/``managed`` identity policies, a permissions
    ``boundary``, a role ``trust`` policy, or a policy inherited from a group the user
    belongs to (``group-inline``/``group-managed``, ``name`` is ``group/policy``).
    """

    model_config = ConfigDict(extra="forbid")
    principal: str = Field(min_length=1, max_length=512)
    kind: Literal["inline", "managed", "boundary", "trust", "group-inline", "group-managed"]
    name: str = Field(min_length=1, max_length=256)
    arn: str = Field(default="", max_length=2048)
    document: dict[str, Any]

    @model_validator(mode="after")
    def validate_document(self) -> "PolicyAttachment":
        if len(canonical_policy(self.document).encode()) > policy_byte_limit(self.kind, self.arn):
            raise ValueError("Policy document exceeds the byte limit")
        return self

    @property
    def id(self) -> str:
        return hashlib.sha256(f"{self.principal}\0{self.kind}\0{self.name}".encode()).hexdigest()[:24]

    @property
    def digest(self) -> str:
        """Content hash of the canonical document (sorted keys, compact separators)."""
        return hashlib.sha256(canonical_policy(self.document).encode()).hexdigest()


class GraphSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Size caps are Settings.max_nodes/max_edges, enforced where snapshots enter the
    # system (inline ingestion, upload sessions) and on the merged published revision.
    nodes: list[Node] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list, max_length=1000)
    source: str = Field(default="snapshot", min_length=1, max_length=128)
    # Policy documents of the snapshot's principals (stored per revision in SQL).
    policies: list[PolicyAttachment] = Field(default_factory=list, max_length=MAX_SNAPSHOT_POLICIES)

    @model_validator(mode="after")
    def validate_graph(self) -> "GraphSnapshot":
        ids = {n.id for n in self.nodes}
        if len(ids) != len(self.nodes):
            raise ValueError("Node IDs must be unique within a snapshot")
        if len({e.id for e in self.edges}) != len(self.edges):
            raise ValueError("Duplicate graph edges")
        if any(e.source not in ids or e.target not in ids for e in self.edges):
            raise ValueError("Every edge endpoint must exist in this snapshot")
        if any(p.principal not in ids for p in self.policies):
            raise ValueError("Every policy principal must exist in this snapshot")
        if len({p.id for p in self.policies}) != len(self.policies):
            raise ValueError("Duplicate policy attachments")
        return self


DATA_TYPES = {NodeType.DATABASE, NodeType.VECTOR, NodeType.BUCKET}
# Non-human identities: the overview's NHI count and blast-radius scoring.
NHI_TYPES = {NodeType.SERVICE, NodeType.AGENT, NodeType.MCP, NodeType.ROLE}
# Every identity whose privilege can be analyzed and optimized (humans included).
IDENTITY_TYPES = NHI_TYPES | {NodeType.HUMAN}
TRAVERSAL_TYPES = {e for e in EdgeType if e != EdgeType.PII}
