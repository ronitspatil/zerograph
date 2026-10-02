from app.graph.schema import Edge, EdgeType, GraphSnapshot, Node, NodeType, Sensitivity


def demo_snapshot() -> GraphSnapshot:
    nodes = [
        Node(
            id="agent:support",
            type=NodeType.AGENT,
            name="Support Copilot",
            provider="langgraph",
            account_id="production",
            internet_exposed=True,
            authenticated=False,
        ),
        Node(
            id="agent:research",
            type=NodeType.AGENT,
            name="Research Assistant",
            provider="crewai",
            account_id="sandbox",
        ),
        Node(
            id="svc:billing",
            type=NodeType.SERVICE,
            name="billing-worker",
            provider="aws",
            account_id="production",
        ),
        Node(id="mcp:crm", type=NodeType.MCP, name="CRM Tools", provider="mcp", account_id="production"),
        Node(
            id="mcp:knowledge",
            type=NodeType.MCP,
            name="Knowledge Tools",
            provider="mcp",
            account_id="sandbox",
        ),
        Node(
            id="role:admin",
            type=NodeType.ROLE,
            name="CustomerDataAdmin",
            provider="aws",
            account_id="production",
            privileged=True,
        ),
        Node(
            id="role:billing",
            type=NodeType.ROLE,
            name="BillingReadOnly",
            provider="aws",
            account_id="production",
        ),
        Node(
            id="db:customers",
            type=NodeType.DATABASE,
            name="customers-prod",
            provider="aws",
            account_id="production",
            sensitivity=Sensitivity.RESTRICTED,
            tags=["PII", "PHI"],
            encrypted=False,
        ),
        Node(
            id="s3:exports",
            type=NodeType.BUCKET,
            name="customer-exports",
            provider="aws",
            account_id="production",
            sensitivity=Sensitivity.CONFIDENTIAL,
            tags=["PII"],
        ),
        Node(
            id="db:billing",
            type=NodeType.DATABASE,
            name="billing-ledger",
            provider="aws",
            account_id="production",
            sensitivity=Sensitivity.RESTRICTED,
            tags=["PCI"],
        ),
        Node(
            id="vector:docs",
            type=NodeType.VECTOR,
            name="product-knowledge",
            provider="custom",
            account_id="sandbox",
            sensitivity=Sensitivity.PUBLIC,
        ),
        Node(
            id="human:operator",
            type=NodeType.HUMAN,
            name="Platform Operator",
            provider="okta",
            account_id="production",
        ),
    ]
    tuples = [
        ("agent:support", "mcp:crm", EdgeType.INVOKES),
        ("mcp:crm", "role:admin", EdgeType.ASSUMES),
        ("role:admin", "db:customers", EdgeType.READ),
        ("role:admin", "s3:exports", EdgeType.WRITE),
        ("role:admin", "db:billing", EdgeType.READ),
        ("svc:billing", "role:billing", EdgeType.ASSUMES),
        ("role:billing", "db:billing", EdgeType.READ),
        ("agent:research", "mcp:knowledge", EdgeType.INVOKES),
        ("mcp:knowledge", "vector:docs", EdgeType.READ),
        ("human:operator", "role:admin", EdgeType.ASSUMES),
    ]
    return GraphSnapshot(
        nodes=nodes,
        edges=[
            Edge(source=a, target=b, type=t, evidence=["Synthetic demonstration fixture"])
            for a, b, t in tuples
        ],
        source="demo",
        warnings=["Synthetic data: findings are illustrative, not cloud discoveries"],
    )
