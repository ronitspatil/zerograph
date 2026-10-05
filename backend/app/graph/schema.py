import hashlib
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


class GraphSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Size caps are Settings.max_nodes/max_edges, enforced where snapshots enter the
    # system (inline ingestion, upload sessions) and on the merged published revision.
    nodes: list[Node] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list, max_length=1000)
    source: str = Field(default="snapshot", min_length=1, max_length=128)

    @model_validator(mode="after")
    def validate_graph(self) -> "GraphSnapshot":
        ids = {n.id for n in self.nodes}
        if len(ids) != len(self.nodes):
            raise ValueError("Node IDs must be unique within a snapshot")
        if len({e.id for e in self.edges}) != len(self.edges):
            raise ValueError("Duplicate graph edges")
        if any(e.source not in ids or e.target not in ids for e in self.edges):
            raise ValueError("Every edge endpoint must exist in this snapshot")
        return self


DATA_TYPES = {NodeType.DATABASE, NodeType.VECTOR, NodeType.BUCKET}
IDENTITY_TYPES = {NodeType.SERVICE, NodeType.AGENT, NodeType.MCP, NodeType.ROLE}
TRAVERSAL_TYPES = {e for e in EdgeType if e != EdgeType.PII}
