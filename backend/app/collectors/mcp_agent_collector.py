from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.graph.schema import Edge, EdgeType, GraphSnapshot, Node, NodeType


class ToolBinding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=128)
    target: Node
    operations: list[Literal["read", "write"]] = Field(default_factory=lambda: ["read"])
    enforced: bool = False


class AgentDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    name: str
    framework: Literal["langgraph", "crewai", "autogen", "custom"] = "custom"
    servers: list[str] = Field(default_factory=list, max_length=100)
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
            nodes[binding.target.id] = binding.target
            for operation in binding.operations:
                edge = Edge(
                    source=server_id,
                    target=binding.target.id,
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
    return GraphSnapshot(
        nodes=list(nodes.values()), edges=list(edges.values()), warnings=warnings, source="mcp"
    )
