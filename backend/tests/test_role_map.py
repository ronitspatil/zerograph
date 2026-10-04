import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.dialects import postgresql

from app.api import routes
from app.core.auth import Actor, current_actor
from app.db.models import TenantState
from app.graph.exploration import RevisionUnavailable
from app.graph.repository import CypherGraphStore, MemoryGraphStore
from app.graph.role_map import RoleMapSlice
from app.graph.schema import Edge, EdgeType, GraphSnapshot, Node, NodeType
from app.main import create_app


def role_snapshot():
    nodes = [Node(id=f"role:{index:02}", name=f"Role {index}", type=NodeType.ROLE) for index in range(6)]
    nodes += [Node(id="role:isolated", name="Isolated", type=NodeType.ROLE)]
    types = {
        "a:human": NodeType.HUMAN,
        "a:service": NodeType.SERVICE,
        "a:agent": NodeType.AGENT,
        "a:mcp": NodeType.MCP,
        "a:database": NodeType.DATABASE,
        "a:bucket": NodeType.BUCKET,
        "a:vector": NodeType.VECTOR,
        "a:annotation": NodeType.CATEGORY,
        "a:structural": NodeType.CATEGORY,
    }
    nodes += [Node(id=node_id, name=node_id, type=kind) for node_id, kind in types.items()]
    edges = [
        Edge(source="role:00", target="role:01", type=EdgeType.INHERITS),
        Edge(source="role:02", target="role:00", type=EdgeType.ASSUMES),
        Edge(source="role:03", target="role:04", type=EdgeType.INHERITS),
        Edge(source="role:00", target="a:database", type=EdgeType.READ),
        Edge(source="role:00", target="a:database", type=EdgeType.WRITE, certainty="conditional"),
        Edge(source="a:database", target="role:00", type=EdgeType.INVOKES),
        Edge(source="role:00", target="a:annotation", type=EdgeType.PII),
        Edge(source="role:00", target="a:structural", type=EdgeType.READ),
        Edge(source="role:00", target="role:05", type=EdgeType.PII),
    ]
    edges += [
        Edge(source=node_id, target="role:00", type=EdgeType.ASSUMES, certainty="declared")
        for node_id in ("a:human", "a:service", "a:agent", "a:mcp")
    ]
    edges += [
        Edge(source="role:00", target="a:bucket", type=EdgeType.READ),
        Edge(source="a:vector", target="role:00", type=EdgeType.WRITE),
    ]
    return GraphSnapshot(
        nodes=list(reversed(nodes)), edges=list(reversed(edges)), warnings=["Synthetic structural links"]
    )


def test_memory_global_pages_direct_distinct_counts_and_copy_isolation():
    store = MemoryGraphStore()
    snapshot = role_snapshot()
    store.publish("tenant", "revision", snapshot)
    store.publish(
        "other", "revision", GraphSnapshot(nodes=[Node(id="private", name="Private", type=NodeType.ROLE)])
    )
    with patch.object(store, "snapshot", side_effect=AssertionError("Full snapshot forbidden")):
        first = store.roles("tenant", "revision", 2, 10, None)
        assert [node.id for node in first.nodes] == ["role:00", "role:01"]
        assert first.has_more and first.next_cursor == "role:01"
        assert (first.total_nodes, first.total_edges, first.total_roles, first.total_role_edges) == (
            16,
            15,
            7,
            3,
        )
        assert first.truncated and first.role_map_truncated
        assert [(edge.source, edge.target) for edge in first.edges] == [("role:00", "role:01")]
        # Distinct full-revision structural neighbors include inbound/outbound, all certainties and HumanUser.
        assert first.role_summaries[0].model_dump() == {
            "role_id": "role:00",
            "direct_neighbors": 10,
            "linked_identities": 6,
            "linked_data_assets": 3,
        }
        assert first.role_summaries[1].direct_neighbors == 1
        page = store.roles("tenant", "revision", 2, 10, first.next_cursor)
        assert [node.id for node in page.nodes] == ["role:02", "role:03"]
        assert page.next_cursor == "role:03" and page.edges == []
        # Freely supplied keyset boundary need not match an existing role.
        page = store.roles("tenant", "revision", 100, 10, "role:03a")
        assert [node.id for node in page.nodes] == ["role:04", "role:05", "role:isolated"]
        assert page.next_cursor is None and not page.has_more and page.role_map_truncated
        assert page.role_summaries[-1].direct_neighbors == 0
        complete_roles = store.roles("tenant", "revision", 100, 10, None)
        assert complete_roles.truncated and not complete_roles.role_map_truncated
        assert len(complete_roles.edges) == 3
        assert store.roles("tenant", "revision", 100, 1, None).role_map_truncated
        assert store.roles("tenant", "revision", 100, 10, "z").nodes == []
        assert store.roles("other", "revision", 100, 10, None).total_roles == 1
        with pytest.raises(RevisionUnavailable):
            store.roles("tenant", "missing", 2, 10, None)
    copied_id = first.nodes[0].id
    first.nodes[0].name = "changed"
    assert (
        next(node.name for node in store.snapshots[("tenant", "revision")].nodes if node.id == copied_id)
        == "Role 0"
    )


def test_self_loops_stay_in_role_edges_but_not_direct_neighbor_summaries():
    store = MemoryGraphStore()
    snapshot = role_snapshot()
    snapshot.edges.extend(
        [
            Edge(source="role:00", target="role:00", type=EdgeType.INHERITS),
            Edge(source="role:isolated", target="role:isolated", type=EdgeType.ASSUMES),
        ]
    )
    store.publish("tenant", "revision", snapshot)
    result = store.roles("tenant", "revision", 100, 100, None)
    assert result.total_role_edges == 5
    assert sum(edge.source == edge.target for edge in result.edges) == 2
    summaries = {summary.role_id: summary for summary in result.role_summaries}
    assert summaries["role:00"].direct_neighbors == 10
    assert summaries["role:00"].linked_identities == 6
    assert summaries["role:isolated"].model_dump() == {
        "role_id": "role:isolated",
        "direct_neighbors": 0,
        "linked_identities": 0,
        "linked_data_assets": 0,
    }


def test_memory_dense_role_edges_are_bounded_and_no_dangling_endpoints():
    nodes = [Node(id=f"role:{i:03}", name=f"Role {i}", type=NodeType.ROLE) for i in range(120)]
    edges = [
        Edge(source=a.id, target=b.id, type=EdgeType.INHERITS) for a in nodes for b in nodes if a.id != b.id
    ]
    store = MemoryGraphStore()
    store.publish("tenant", "rev", GraphSnapshot(nodes=nodes, edges=edges))
    result = store.roles("tenant", "rev", 100, 2000, None)
    assert len(result.nodes) == 100 and len(result.edges) == 2000 and result.total_role_edges == 14280
    ids = {node.id for node in result.nodes}
    assert all(edge.source in ids and edge.target in ids for edge in result.edges)
    assert result.has_more and result.role_map_truncated
    assert all(summary.direct_neighbors == 119 for summary in result.role_summaries)


def test_role_api_contract_revision_bounds_global_scope_and_missing_metadata(client, environment):
    factory, store = environment
    store.publish("tenant-a", "revision-a", role_snapshot())
    with patch.object(store, "snapshot", side_effect=AssertionError("Full snapshot forbidden")):
        # Roles outside the initial identity/data sample remain discoverable globally.
        sample = client.get("/api/v1/graph/explore", params={"node_limit": 2}).json()
        assert not any(node["type"] == "CloudRole" for node in sample["nodes"])
        response = client.get("/api/v1/graph/roles", params={"role_limit": 2})
        assert response.status_code == 200
        body = response.json()
        assert body["revision"] == "revision-a" and body["warnings"] == ["Synthetic structural links"]
        assert body["view"] == {
            "mode": "roles",
            "root_id": None,
            "node_limit": 2,
            "edge_limit": 1000,
            "truncated": True,
            "total_nodes": 16,
            "total_edges": 15,
            "total_roles": 7,
            "total_role_edges": 3,
            "role_map_truncated": True,
            "has_more": True,
            "next_cursor": "role:01",
        }
        assert len(body["role_summaries"]) == 2 and all("id" in edge for edge in body["edges"])
        page = client.get(
            "/api/v1/graph/roles",
            params={"role_limit": 2, "cursor": body["view"]["next_cursor"], "revision": "revision-a"},
        ).json()
        assert [node["id"] for node in page["nodes"]] == ["role:02", "role:03"]
        with patch.object(store, "roles") as roles:
            assert (
                client.get("/api/v1/graph/roles", params={"cursor": "role:01", "revision": "old"}).status_code
                == 409
            )
            roles.assert_not_called()
        for params in (
            {"role_limit": 0},
            {"role_limit": 101},
            {"edge_limit": 0},
            {"edge_limit": 2001},
            {"cursor": ""},
            {"cursor": "x" * 513},
        ):
            assert client.get("/api/v1/graph/roles", params=params).status_code == 422
    with factory() as db:
        db.get(TenantState, "tenant-a").revision = "lost"
        db.commit()
    response = client.get("/api/v1/graph/roles")
    assert response.status_code == 503 and response.headers["retry-after"] == "5"


def test_empty_tenant_no_roles_workspace_viewer_and_auth(environment):
    factory, store = environment
    store.publish(
        "tenant-b", "revision-b", GraphSnapshot(nodes=[Node(id="human", name="Human", type=NodeType.HUMAN)])
    )
    with factory() as db:
        db.add(TenantState(tenant_id="tenant-b", revision="revision-b"))
        db.commit()
    app = create_app()
    app.dependency_overrides[current_actor] = lambda: Actor("bob", "tenant-b", frozenset({"viewer"}))
    with TestClient(app) as client:
        body = client.get("/api/v1/graph/roles").json()
        assert body["nodes"] == body["edges"] == body["role_summaries"] == []
        assert body["view"]["total_nodes"] == 1 and body["view"]["total_roles"] == 0
        assert body["view"]["truncated"] and not body["view"]["role_map_truncated"]
        assert not body["view"]["has_more"] and body["view"]["next_cursor"] is None
        app.dependency_overrides[current_actor] = lambda: Actor("nobody", "empty", frozenset({"viewer"}))
        body = client.get("/api/v1/graph/roles").json()
        assert body["revision"] == "" and body["view"]["total_nodes"] == body["view"]["total_roles"] == 0
        assert not body["view"]["truncated"] and not body["view"]["role_map_truncated"]
    with TestClient(create_app()) as client:
        assert client.get("/api/v1/graph/roles").status_code == 401


def test_role_query_holds_shared_revision_lock_without_commit():
    db = MagicMock()
    db.get_bind.return_value.dialect.name = "postgresql"
    db.execute.return_value.scalar_one_or_none.return_value = TenantState(
        tenant_id="tenant", revision="current"
    )
    graph = MagicMock()

    def roles(*args):
        assert args == ("tenant", "current", 3, 4, "role:01")
        statement = db.execute.call_args.args[0]
        assert "FOR SHARE" in str(statement.compile(dialect=postgresql.dialect()))
        assert statement.get_execution_options()["populate_existing"]
        assert db.execute.call_args_list[0].args[1] == {"timeout": "5000ms"}
        db.commit.assert_not_called()
        db.rollback.assert_not_called()
        return RoleMapSlice()

    graph.roles.side_effect = roles
    response = routes.role_map(
        db, graph, Actor("viewer", "tenant", frozenset({"viewer"})), 3, 4, "role:01", "current"
    )
    assert response.revision == "current"
    with pytest.raises(HTTPException) as mismatch:
        routes.role_map(db, graph, Actor("viewer", "tenant", frozenset({"viewer"})), 3, 4, None, "old")
    assert mismatch.value.status_code == 409
    assert graph.roles.call_count == 1


class Rows(list):
    def single(self):
        return self[0] if self else None


class RoleTransaction:
    def __init__(self):
        self.calls = []
        self.missing_meta = False
        self.empty = False
        self.nodes = [Node(id=f"role:{i:02}", name=f"Role {i}", type=NodeType.ROLE) for i in range(3)]
        self.edge = Edge(source="role:00", target="role:01", type=EdgeType.INHERITS)

    def run(self, query, **params):
        self.calls.append((query, params))
        if "Snapshot" in query:
            return Rows([] if self.missing_meta else [{"warnings": []}])
        if "count(" in query and "AS count" in query:
            return Rows([{"count": 0 if self.empty else (3 if "count(n)" in query else 1)}])
        if "n.payload" in query:
            return Rows(
                []
                if self.empty
                else [{"payload": node.model_dump_json()} for node in self.nodes[: params["limit"]]]
            )
        if "r.payload" in query:
            return Rows([{"payload": self.edge.model_dump_json()}])
        return Rows(
            [
                {
                    "role_id": json.loads(role["key"])[2],
                    "direct_neighbors": 10,
                    "linked_identities": 6,
                    "linked_data_assets": 3,
                }
                for role in params["roles"]
            ]
        )


def cypher_store():
    store = CypherGraphStore.__new__(CypherGraphStore)
    store.timeout = 15
    tx = RoleTransaction()
    session = MagicMock()
    session.__enter__.return_value = session

    def read(function):
        assert function.timeout == 15
        return function(tx)

    session.execute_read.side_effect = read
    store.driver = MagicMock()
    store.driver.session.return_value = session
    return store, tx


def test_cypher_role_queries_use_labels_parameter_scope_bounded_rows_and_aggregates():
    store, tx = cypher_store()
    result = store.roles("tenant", "revision", 2, 5, "cursor' MATCH (secret)")
    assert len(result.nodes) == 2 and result.has_more and result.next_cursor == "role:01"
    assert len(result.role_summaries) == 2
    store.driver.session.assert_called_once_with(fetch_size=101)
    for query, params in tx.calls:
        assert params["tenant"] == "tenant" and params["revision"] == "revision"
        assert "n.type" not in query and ".account" not in query and "*" not in query
        assert "MATCH (secret)" not in query
        assert "tenant_id:$tenant" in query and "revision:$revision" in query
        if "payload" in query:
            assert "ORDER BY" in query and "LIMIT $limit" in query
        if "-[r:" in query:
            assert query.count("tenant_id:$tenant") == query.count("revision:$revision") == 3
    page_query, params = next((q, p) for q, p in tx.calls if "n.payload" in q)
    assert ":Entity:CloudRole" in page_query and "n.id > $cursor" in page_query
    assert params["cursor"] == "cursor' MATCH (secret)" and params["limit"] == 3
    summaries, params = next((q, p) for q, p in tx.calls if "direct_neighbors" in q)
    assert "OPTIONAL MATCH" in summaries and "count(DISTINCT neighbor.id)" in summaries
    assert all(
        ":" + kind in summaries
        for kind in (
            "HumanUser",
            "ServiceAccount",
            "AIAgent",
            "MCPServer",
            "CloudRole",
            "Database",
            "S3Bucket",
            "VectorStore",
        )
    )
    assert "STORES_PII" not in summaries and "key:selected.key" in summaries
    assert "WHERE neighbor.id <> role.id" in summaries
    assert params["limit"] == 2 and len(params["roles"]) == 2
    edges, params = next((q, p) for q, p in tx.calls if "r.payload" in q)
    assert edges.count(":Entity:CloudRole") == 2 and "STORES_PII" not in edges
    assert params["ids"] == ["role:00", "role:01"] and params["limit"] == 5
    # Workspace edge totals include annotations; role edge totals and summaries exclude them.
    assert any("STORES_PII" in q and "count(r)" in q for q, p in tx.calls)
    assert any("STORES_PII" not in q and ":Entity:CloudRole" in q and "count(r)" in q for q, p in tx.calls)
    tx.missing_meta = True
    with pytest.raises(RevisionUnavailable):
        store.roles("tenant", "lost", 2, 5, None)
    tx.missing_meta = False
    tx.empty = True
    tx.calls.clear()
    empty = store.roles("tenant", "empty-role-revision", 2, 5, None)
    assert empty.nodes == empty.edges == empty.role_summaries == []
    assert not any("r.payload" in q or "direct_neighbors" in q for q, p in tx.calls)
    assert store.roles("tenant", "", 2, 5, None).total_roles == 0


@pytest.mark.parametrize(
    "role_limit,edge_limit,cursor",
    [(0, 1, None), (101, 1, None), (1, 0, None), (1, 2001, None), (1, 1, ""), (1, 1, "x" * 513)],
)
def test_invalid_role_bounds_refused_before_driver(role_limit, edge_limit, cursor):
    store, _ = cypher_store()
    with pytest.raises(ValueError):
        store.roles("tenant", "revision", role_limit, edge_limit, cursor)
    store.driver.session.assert_not_called()
