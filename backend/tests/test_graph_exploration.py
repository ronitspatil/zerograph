import json
from unittest.mock import MagicMock, patch

import pytest
from app.api import routes
from app.core.auth import Actor, current_actor
from app.db.models import TenantState
from app.graph.exploration import GraphSlice, RevisionUnavailable, RootNotFound
from app.graph.repository import CypherGraphStore, MemoryGraphStore
from app.graph.schema import Edge, EdgeType, GraphSnapshot, Node, NodeType
from app.main import create_app
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import DBAPIError


def dense_snapshot(neighbors=600):
    root = Node(id="root", name="Dense Hub", type=NodeType.AGENT)
    nodes = [root] + [
        Node(id=f"n:{index:04}", name=f"Customer {index}", type=NodeType.DATABASE)
        for index in range(neighbors)
    ]
    edges = [Edge(source=root.id, target=node.id, type=EdgeType.READ) for node in nodes[1:]]
    edges += [Edge(source=node.id, target=root.id, type=EdgeType.INVOKES) for node in nodes[1:]]
    nodes.append(Node(id="category", name="PII", type=NodeType.CATEGORY))
    edges.append(Edge(source="root", target="category", type=EdgeType.PII))
    return GraphSnapshot(
        nodes=list(reversed(nodes)), edges=list(reversed(edges)), warnings=["synthetic fixture"]
    )


def test_memory_dense_bounds_endpoints_directions_annotation_and_no_full_snapshot():
    store = MemoryGraphStore()
    store.publish("tenant", "rev", dense_snapshot())
    store.publish(
        "other", "rev", GraphSnapshot(nodes=[Node(id="private", name="Private", type=NodeType.HUMAN)])
    )
    with patch.object(store, "snapshot", side_effect=AssertionError("full snapshot forbidden")):
        view = store.explore("tenant", "rev", "root", 500, 9)
        ids = {node.id for node in view.nodes}
        assert len(view.nodes) == 500 and len(view.edges) == 9 and "root" in ids
        assert (view.total_nodes, view.total_edges) == (602, 1201)
        assert view.truncated
        assert all(edge.source in ids and edge.target in ids for edge in view.edges)
        assert [node.id for node in view.nodes] == sorted(ids)
        assert [edge.id for edge in view.edges] == sorted(edge.id for edge in view.edges)
        # Incoming edges and annotations are included, never permission traversal.
        small = store.explore("tenant", "rev", "category", 10, 10)
        assert {node.id for node in small.nodes} == {"category", "root"}
        assert [edge.type for edge in small.edges] == [EdgeType.PII]
        assert small.truncated
        isolated = store.explore("tenant", "rev", "n:0599", 2, 10)
        assert {node.id for node in isolated.nodes} == {"n:0599", "root"}
        assert len(isolated.edges) == 2
        assert store.explore("other", "rev", None, 10, 10).total_nodes == 1
        with pytest.raises(RootNotFound):
            store.explore("other", "rev", "root", 10, 10)
        with pytest.raises(RevisionUnavailable):
            store.explore("tenant", "missing", None, 10, 10)
        nodes, more = store.search("tenant", "rev", "  CUSTOMER  ", 50)
        assert len(nodes) == 50 and more
        assert store.search("tenant", "rev", "n:0599", 1)[0][0].id == "n:0599"
        assert store.search("other", "rev", "customer", 50) == ([], False)
    copied_id = view.nodes[0].id
    published_name = next(
        node.name for node in store.snapshots[("tenant", "rev")].nodes if node.id == copied_id
    )
    view.nodes[0].name = "mutated"
    assert (
        next(node.name for node in store.snapshots[("tenant", "rev")].nodes if node.id == copied_id)
        == published_name
    )


def test_api_samples_counts_search_bounds_and_revision(client, environment):
    factory, store = environment
    store.publish("tenant-a", "revision-a", dense_snapshot())
    with patch.object(store, "snapshot", side_effect=AssertionError("full snapshot forbidden")):
        response = client.get("/api/v1/graph/explore", params={"node_limit": 3, "edge_limit": 2})
        assert response.status_code == 200
        body = response.json()
        assert body["revision"] == "revision-a" and len(body["nodes"]) == 3
        assert body["view"] == {
            "mode": "sample",
            "root_id": None,
            "node_limit": 3,
            "edge_limit": 2,
            "truncated": True,
            "total_nodes": 602,
            "total_edges": 1201,
        }
        assert body["warnings"] == ["synthetic fixture"]
        response = client.get("/api/v1/graph/explore", params={"root_id": "root", "node_limit": 1})
        assert response.status_code == 200 and [n["id"] for n in response.json()["nodes"]] == ["root"]
        assert response.json()["view"]["mode"] == "neighborhood"
        assert client.get("/api/v1/graph/explore", params={"root_id": "missing"}).status_code == 404
        response = client.get("/api/v1/graph/search", params={"q": " CUSTOMER ", "limit": 2})
        assert (
            response.status_code == 200 and len(response.json()["nodes"]) == 2 and response.json()["has_more"]
        )
        assert client.get("/api/v1/graph/search", params={"q": "missing"}).json()["nodes"] == []
        with patch.object(store, "explore") as explore, patch.object(store, "search") as search:
            for path, params in (("explore", {}), ("search", {"q": "customer"})):
                assert (
                    client.get("/api/v1/graph/" + path, params={**params, "revision": "obsolete"}).status_code
                    == 409
                )
            explore.assert_not_called()
            search.assert_not_called()
        for params in ({"node_limit": 0}, {"node_limit": 501}, {"edge_limit": 2001}, {"root_id": "x" * 513}):
            assert client.get("/api/v1/graph/explore", params=params).status_code == 422
        for params in ({}, {"q": " "}, {"q": "x" * 129}, {"q": "x", "limit": 51}, {"q": "x", "limit": 0}):
            assert client.get("/api/v1/graph/search", params=params).status_code == 422
    with factory() as db:
        db.get(TenantState, "tenant-a").revision = "lost"
        db.commit()
    for path, params in (("explore", {}), ("search", {"q": "customer"})):
        response = client.get("/api/v1/graph/" + path, params=params)
        assert response.status_code == 503 and response.headers["retry-after"] == "5"


def test_empty_tenant_and_viewer_scope(environment):
    app = create_app()
    app.dependency_overrides[current_actor] = lambda: Actor("viewer", "tenant-b", frozenset({"viewer"}))
    with TestClient(app) as client:
        body = client.get("/api/v1/graph/explore").json()
        assert body["revision"] == "" and body["nodes"] == body["edges"] == []
        assert body["view"]["total_nodes"] == body["view"]["total_edges"] == 0
        assert body["view"]["truncated"] is False
        assert client.get("/api/v1/graph/search", params={"q": "support"}).json() == {
            "revision": "",
            "nodes": [],
            "has_more": False,
        }
        assert client.get("/api/v1/graph/explore", params={"root_id": "agent:support"}).status_code == 404
    with TestClient(create_app()) as client:
        for path, params in (("explore", {}), ("search", {"q": "x"})):
            assert client.get("/api/v1/graph/" + path, params=params).status_code == 401


def test_revision_share_lock_refresh_and_timeout_before_direct_queries():
    db = MagicMock()
    db.get_bind.return_value.dialect.name = "postgresql"
    db.execute.return_value.scalar_one_or_none.return_value = TenantState(
        tenant_id="tenant", revision="current"
    )
    graph = MagicMock()

    def explore(*args):
        assert args == ("tenant", "current", None, 5, 6)
        statement = db.execute.call_args.args[0]
        assert "FOR SHARE" in str(statement.compile(dialect=postgresql.dialect()))
        assert statement.get_execution_options()["populate_existing"]
        assert db.execute.call_args_list[0].args[1] == {"timeout": "5000ms"}
        db.commit.assert_not_called()
        db.rollback.assert_not_called()
        return GraphSlice()

    graph.explore.side_effect = explore
    routes.explore_graph(db, graph, Actor("viewer", "tenant", frozenset({"viewer"})), None, 5, 6, "current")

    class Busy(Exception):
        sqlstate = "55P03"

    db.execute.side_effect = [None, DBAPIError("query", {}, Busy())]
    with pytest.raises(HTTPException) as error:
        routes.pin_revision(db, "tenant")
    assert error.value.status_code == 503 and error.value.headers == {"Retry-After": "5"}
    db.rollback.assert_called_once()
    db.execute.side_effect = [None, DBAPIError("query", {}, RuntimeError("unrelated"))]
    with pytest.raises(DBAPIError):
        routes.pin_revision(db, "tenant")


class Rows(list):
    def single(self):
        return self[0] if self else None


class Transaction:
    def __init__(self):
        self.calls = []
        self.missing_meta = False
        self.missing_root = False
        self.root = Node(id="root", name="Root", type=NodeType.AGENT)
        self.neighbor = Node(id="neighbor", name="Neighbor", type=NodeType.MCP)
        self.edge = Edge(source="neighbor", target="root", type=EdgeType.INVOKES)

    def run(self, query, **params):
        self.calls.append((query, params))
        if "Snapshot" in query:
            return Rows([] if self.missing_meta else [{"warnings": []}])
        if "count(" in query:
            return Rows([{"count": 2 if "count(n)" in query else 1}])
        if "r.payload" in query:
            if self.edge.source not in params["ids"] or self.edge.target not in params["ids"]:
                return Rows([])
            return Rows([{"payload": self.edge.model_dump_json()}])
        if "CONTAINS" in query:
            return Rows([{"payload": node.model_dump_json()} for node in (self.neighbor, self.root)])
        if "WITH DISTINCT" in query:
            return Rows([{"payload": self.neighbor.model_dump_json()}])
        return Rows([] if self.missing_root else [{"payload": self.root.model_dump_json()}])


def cypher_store():
    store = CypherGraphStore.__new__(CypherGraphStore)
    store.timeout = 15
    tx = Transaction()
    session = MagicMock()
    session.__enter__.return_value = session

    def read(function):
        assert function.timeout == 15
        return function(tx)

    session.execute_read.side_effect = read
    store.driver = MagicMock()
    store.driver.session.return_value = session
    return store, tx


def test_cypher_queries_bound_rows_parameterize_and_scope_all_entities_and_relationships():
    store, tx = cypher_store()
    view = store.explore("tenant", "revision", "root", 3, 4)
    assert {node.id for node in view.nodes} == {"root", "neighbor"}
    assert view.edges[0].source == "neighbor" and not view.truncated
    queries = tx.calls
    for query, params in queries:
        assert params["tenant"] == "tenant" and params["revision"] == "revision"
        assert "tenant_id:$tenant" in query and "revision:$revision" in query
        assert "root" not in query.replace("$root", "")
        assert "*" not in query
        if "payload" in query:
            assert "LIMIT" in query and "ORDER BY" in query if "LIMIT $limit" in query else "LIMIT 1" in query
        if "-[r:" in query:
            assert query.count("tenant_id:$tenant") == 3 and query.count("revision:$revision") == 3
            assert "STORES_PII" in query
    neighbor = next((q, p) for q, p in queries if "WITH DISTINCT" in q)
    assert neighbor[1]["limit"] == 2 and neighbor[1]["key"] == json.dumps(["tenant", "revision", "root"])
    edges = next((q, p) for q, p in queries if "r.payload" in q)
    assert edges[1]["limit"] == 4 and set(edges[1]["ids"]) == {"neighbor", "root"}
    tx.calls.clear()
    sample = store.explore("tenant", "revision", None, 500, 2000)
    assert sample.truncated
    payload_query = next((q, p) for q, p in tx.calls if "n.payload" in q)
    assert "ORDER BY n.id LIMIT $limit" in payload_query[0] and payload_query[1]["limit"] == 500
    tx.calls.clear()
    root_only = store.explore("tenant", "revision", "root", 1, 1)
    assert [node.id for node in root_only.nodes] == ["root"] and root_only.edges == []
    assert not any("WITH DISTINCT" in query for query, _ in tx.calls)
    tx.missing_root = True
    with pytest.raises(RootNotFound):
        store.explore("tenant", "revision", "root", 5, 5)
    tx.missing_root = False
    tx.calls.clear()
    nodes, more = store.search("tenant", "revision", " x' MATCH (secret) ", 1)
    assert len(nodes) == 1 and more
    query, params = tx.calls[-1]
    assert "MATCH (secret)" not in query and params["q"] == "x' match (secret)" and params["limit"] == 2
    assert "toLower(n.id)" in query and "toLower(n.name)" in query
    store.driver.session.assert_called_with(fetch_size=51)
    tx.missing_meta = True
    for operation in (
        lambda: store.explore("tenant", "missing", None, 2, 2),
        lambda: store.search("tenant", "missing", "x", 2),
    ):
        with pytest.raises(RevisionUnavailable):
            operation()
    assert store.explore("tenant", "", None, 2, 2).total_nodes == 0
    assert store.search("tenant", "", "x", 2) == ([], False)


@pytest.mark.parametrize(
    "node_limit,edge_limit,root", [(0, 1, None), (501, 1, None), (1, 2001, None), (1, 1, "")]
)
def test_store_rejects_invalid_bounds_before_driver(node_limit, edge_limit, root):
    store, _ = cypher_store()
    with pytest.raises(ValueError):
        store.explore("tenant", "revision", root, node_limit, edge_limit)
    store.driver.session.assert_not_called()


@pytest.mark.parametrize("q,limit", [(" ", 1), ("x" * 129, 1), ("x", 0), ("x", 51)])
def test_search_rejects_invalid_bounds_before_driver(q, limit):
    store, _ = cypher_store()
    with pytest.raises(ValueError):
        store.search("tenant", "revision", q, limit)
    store.driver.session.assert_not_called()
