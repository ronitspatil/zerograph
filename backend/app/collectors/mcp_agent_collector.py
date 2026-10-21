from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.graph.schema import Edge, EdgeType, GraphSnapshot, Node, NodeId, NodeType


class ToolBinding(BaseModel):
    """A tool's target asset: restated (``target``) or, when another source such as the AWS
    collector defines it, referenced by ID (``target_id``) so its metadata stays that source's."""

    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=128)
    target: Node | None = None
    target_id: NodeId | None = None
    operations: list[Literal["read", "write"]] = Field(default_factory=lambda: ["read"])
    enforced: bool = False

    @model_validator(mode="after")
    def one_target(self) -> "ToolBinding":
        if (self.target is None) == (self.target_id is None):
            raise ValueError("A tool binding names exactly one of target or target_id")
        return self


class AgentDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    name: str
    framework: Literal["langgraph", "crewai", "autogen", "custom"] = "custom"
    servers: list[str] = Field(default_factory=list, max_length=100)
    # Roles the agent runs as (an AWS role ARN another source defines), by reference: an
    # ``ASSUMES_ROLE`` edge without restating the role.
    roles: list[NodeId] = Field(default_factory=list, max_length=100)
    internet_exposed: bool = False
    authenticated: bool = True


class MCPInventory(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mcpServers: dict[str, dict] = Field(default_factory=dict)
    agents: list[AgentDefinition] = Field(default_factory=list, max_length=500)
    bindings: dict[str, list[ToolBinding]] = Field(default_factory=dict)


def collect_mcp(inventory: MCPInventory) -> GraphSnapshot:
    nodes: dict[str, Node] = {}
    edges: dict[str, Edge] = {}
    references: set[str] = set()
    warnings = []
    for name, definition in inventory.mcpServers.items():
        server_id = f"mcp:{name}"
        nodes[server_id] = Node(
            id=server_id,
            type=NodeType.MCP,
            name=name,
            provider="mcp",
            metadata={"transport": "http" if "url" in definition else "stdio"},
        )
        # Never execute commands, resolve URLs, or persist environment variables/secrets.
        if name not in inventory.bindings:
            warnings.append(f"{name}: tool targets are unknown; supply explicit tool bindings")
        for binding in inventory.bindings.get(name, []):
            if binding.target is not None:
                nodes[binding.target.id] = binding.target
                target_id = binding.target.id
            else:
                target_id = binding.target_id
                references.add(target_id)
            for operation in binding.operations:
                edge = Edge(
                    source=server_id,
                    target=target_id,
                    type=EdgeType.READ if operation == "read" else EdgeType.WRITE,
                    certainty="declared",
                    actions=[binding.name],
                    evidence=[
                        f"tool binding: {name}/{binding.name}; backend enforcement requires verification"
                    ],
                )
                edges[edge.id] = edge
    for agent in inventory.agents:
        node = Node(
            id=f"agent:{agent.id}",
            name=agent.name,
            type=NodeType.AGENT,
            provider=agent.framework,
            internet_exposed=agent.internet_exposed,
            authenticated=agent.authenticated,
        )
        nodes[node.id] = node
        for server in agent.servers:
            target = f"mcp:{server}"
            if target not in nodes:
                warnings.append(f"{agent.name}: missing MCP server {server}")
                continue
            edge = Edge(
                source=node.id,
                target=target,
                type=EdgeType.INVOKES,
                certainty="declared",
                evidence=[f"{agent.framework} tool configuration"],
            )
            edges[edge.id] = edge
        for role in agent.roles:
            references.add(role)
            edge = Edge(
                source=node.id,
                target=role,
                type=EdgeType.ASSUMES,
                certainty="declared",
                evidence=[f"{agent.framework} runtime configuration: execution role"],
            )
            edges[edge.id] = edge
    return GraphSnapshot(
        nodes=list(nodes.values()),
        edges=list(edges.values()),
        warnings=warnings,
        source="mcp",
        references=sorted(references - set(nodes)),
    )
