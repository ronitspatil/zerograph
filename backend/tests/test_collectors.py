import pytest

from app.collectors.data_classifier import classify_metadata, enrich_node
from app.collectors.mcp_agent_collector import MCPInventory, collect_mcp
from app.graph.schema import Node, NodeType, Sensitivity


def test_metadata_classification_and_no_downgrade():
    result = classify_metadata(["patient", "email", "api_key"])
    assert set(result.tags) == {"PHI", "PII", "Credentials"}
    assert result.sensitivity == Sensitivity.RESTRICTED
    node = Node(id="db", name="db", type=NodeType.DATABASE, sensitivity=Sensitivity.RESTRICTED)
    assert enrich_node(node, ["public_title"]).sensitivity == Sensitivity.RESTRICTED


@pytest.mark.parametrize(
    ("fields", "labels"),
    [
        # Glue columns are snake_case or camelCase; found against an emulated Glue catalog,
        # where ``user_email`` and ``card_number`` beside other words were not classified.
        (["event_id", "user_email", "payload"], {"PII"}),
        (["customer_ssn"], {"PII"}),
        (["phone_number", "date_of_birth"], {"PII"}),
        (["userEmail", "customerSSN"], {"PII"}),
        (["entry_id", "customer_card_number", "amount"], {"PCI"}),
        (["patient_id"], {"PHI"}),
        (["db_password", "stripeApiKey"], {"Credentials"}),
        (["s3://lake/emails.parquet"], set()),  # "emails" is another word
        (["company", "span_id", "adobe_id", "secretary"], set()),
    ],
)
def test_classification_terms_match_snake_and_camel_case_words(fields, labels):
    assert set(classify_metadata(fields).tags) == labels


@pytest.mark.parametrize(
    ("key", "value", "labels", "sensitivity"),
    [
        ("data-class", "PII", {"PII"}, Sensitivity.CONFIDENTIAL),
        ("Data_Classification", "phi", {"PHI"}, Sensitivity.RESTRICTED),
        ("classification", "PCI, credentials", {"PCI", "Credentials"}, Sensitivity.RESTRICTED),
        ("Sensitivity", "Confidential", set(), Sensitivity.CONFIDENTIAL),
        ("dataclass", "RESTRICTED", set(), Sensitivity.RESTRICTED),
        ("data-class", "credential", {"Credentials"}, Sensitivity.RESTRICTED),
    ],
)
def test_explicit_classification_tags_become_labels(key, value, labels, sensitivity):
    result = classify_metadata(["bucket", f"{key} {value}"], tags=[(key, value)])
    assert set(result.tags) == labels
    assert result.sensitivity == sensitivity
    assert result.basis == "classification_tag"


@pytest.mark.parametrize(
    ("key", "value"),
    [("owner", "PII"), ("team", "restricted"), ("data-class", "public"), ("data-class", "pii-ish")],
)
def test_other_tags_are_not_classification(key, value):
    result = classify_metadata(["bucket"], tags=[(key, value)])
    assert result.tags == ()
    assert result.sensitivity == Sensitivity.INTERNAL
    assert result.basis == "metadata_heuristic"


def test_presidio_results_are_tags_only():
    class Analyzer:
        def analyze(self, **kwargs):
            return [type("Result", (), {"score": 0.9})()]

    assert "PII" in classify_metadata(["metadata"], Analyzer()).tags


def test_mcp_does_not_execute_or_persist_secrets():
    inventory = MCPInventory.model_validate(
        {
            "mcpServers": {"crm": {"command": "rm -rf /", "env": {"SECRET": "do-not-persist"}}},
            "agents": [{"id": "a", "name": "Agent", "framework": "langgraph", "servers": ["crm"]}],
            "bindings": {
                "crm": [
                    {
                        "name": "lookup",
                        "target": {"id": "db:crm", "name": "CRM", "type": "Database"},
                        "operations": ["read"],
                    }
                ]
            },
        }
    )
    snapshot = collect_mcp(inventory)
    assert "do-not-persist" not in snapshot.model_dump_json()
    assert len(snapshot.edges) == 2
    assert all(e.certainty == "declared" for e in snapshot.edges)


def test_missing_tool_targets_are_warnings():
    snapshot = collect_mcp(
        MCPInventory.model_validate(
            {
                "mcpServers": {"unknown": {"url": "https://untrusted"}},
                "agents": [{"id": "a", "name": "A", "servers": ["missing"]}],
            }
        )
    )
    assert len(snapshot.warnings) == 2
    assert snapshot.edges == []


def test_category_edges_do_not_grant_access():
    from app.collectors.data_classifier import classification_edges
    from app.engine.blast_radius import calculate
    from app.graph.schema import GraphSnapshot

    graph = classification_edges(
        GraphSnapshot(nodes=[Node(id="db", name="data", type=NodeType.DATABASE, tags=["PII"])])
    )
    assert graph.edges[0].type.value == "STORES_PII"
    assert graph.nodes[1].type.value == "DataCategory"
    assert calculate(graph, "db").affected_nodes == []
