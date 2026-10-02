import json
from functools import lru_cache
from pathlib import Path
from typing import Protocol

from neo4j import GraphDatabase, Query, unit_of_work
from neo4j.exceptions import Neo4jError

from app.core.config import get_settings
from app.graph.schema import Edge, EdgeType, GraphSnapshot, Node, NodeType


class GraphStore(Protocol):
    def migrate(self) -> None: ...
    def publish(self, tenant: str, revision: str, snapshot: GraphSnapshot) -> None: ...
    def snapshot(self, tenant: str, revision: str) -> GraphSnapshot: ...
    def shortest_paths(
        self, tenant: str, revision: str, source: str, hops: int, include_uncertain: bool
    ) -> dict[str, list[str]]: ...
    def close(self) -> None: ...


class MemoryGraphStore:
    """Explicit test/development adapter, never a production fallback."""

    def __init__(self):
        self.snapshots: dict[tuple[str, str], GraphSnapshot] = {}

    def migrate(self) -> None:
        pass

    def publish(self, tenant: str, revision: str, snapshot: GraphSnapshot) -> None:
        self.snapshots[(tenant, revision)] = snapshot.model_copy(deep=True)

    def snapshot(self, tenant: str, revision: str) -> GraphSnapshot:
        return self.snapshots.get((tenant, revision), GraphSnapshot()).model_copy(deep=True)

    def shortest_paths(
        self, tenant: str, revision: str, source: str, hops: int, include_uncertain: bool
    ) -> dict[str, list[str]]:
        from app.engine.blast_radius import shortest_paths

        return shortest_paths(self.snapshot(tenant, revision), source, hops, include_uncertain)

    def close(self) -> None:
        pass


class CypherGraphStore:
    def __init__(self):
        settings = get_settings()
        self.vendor = settings.graph_vendor
        self.timeout = settings.query_timeout_seconds
        auth = (
            (settings.graph_username, settings.graph_password.get_secret_value())
            if settings.graph_username
            else None
        )
        self.driver = GraphDatabase.driver(
            settings.graph_uri, auth=auth, max_connection_pool_size=20, connection_timeout=10
        )

    def migrate(self) -> None:
        path = Path(__file__).parent / "migrations" / self.vendor / "001_schema.cypher"
        with self.driver.session() as session:
            for statement in path.read_text().split(";"):
                if statement.strip():
                    try:
                        session.run(Query(statement, timeout=self.timeout)).consume()
                    except Neo4jError as exc:
                        if self.vendor != "memgraph" or "already exists" not in str(exc).lower():
                            raise

    def publish(self, tenant: str, revision: str, snapshot: GraphSnapshot) -> None:
        def write(tx):
            for kind in NodeType:
                rows = [
                    {
                        "id": n.id,
                        "name": n.name,
                        "key": json.dumps([tenant, revision, n.id]),
                        "payload": n.model_dump_json(),
                    }
                    for n in snapshot.nodes
                    if n.type == kind
                ]
                if rows:
                    tx.run(
                        f"UNWIND $rows AS row MERGE (n:Entity:{kind.value} {{key: row.key}}) "
                        "SET n.tenant_id=$tenant, n.revision=$revision, n.id=row.id, "
                        "n.name=row.name, n.payload=row.payload",
                        rows=rows,
                        tenant=tenant,
                        revision=revision,
                    ).consume()
            for kind in EdgeType:
                rows = [
                    {
                        "source": e.source,
                        "target": e.target,
                        "id": e.id,
                        "certainty": e.certainty,
                        "payload": e.model_dump_json(),
                    }
                    for e in snapshot.edges
                    if e.type == kind
                ]
                if rows:
                    tx.run(
                        "UNWIND $rows AS row "
                        "MATCH (a:Entity {tenant_id:$tenant, revision:$revision, id:row.source}), "
                        "(b:Entity {tenant_id:$tenant, revision:$revision, id:row.target}) "
                        f"MERGE (a)-[r:{kind.value} {{id:row.id}}]->(b) "
                        "SET r.tenant_id=$tenant, r.revision=$revision, r.certainty=row.certainty, "
                        "r.payload=row.payload",
                        rows=rows,
                        tenant=tenant,
                        revision=revision,
                    ).consume()
            tx.run(
                "MERGE (s:Snapshot {key:$key}) SET s.tenant_id=$tenant, s.revision=$revision, "
                "s.source=$source, s.warnings=$warnings",
                key=json.dumps([tenant, revision]),
                tenant=tenant,
                revision=revision,
                source=snapshot.source,
                warnings=snapshot.warnings,
            ).consume()

        with self.driver.session() as session:
            session.execute_write(unit_of_work(timeout=self.timeout)(write))

    def snapshot(self, tenant: str, revision: str) -> GraphSnapshot:
        if not revision:
            return GraphSnapshot()
        with self.driver.session() as session:
            nodes = [
                Node.model_validate_json(r["payload"])
                for r in session.run(
                    Query(
                        "MATCH (n:Entity {tenant_id:$tenant, revision:$revision}) RETURN n.payload AS payload",
                        timeout=self.timeout,
                    ),
                    tenant=tenant,
                    revision=revision,
                )
            ]
            edges = [
                Edge.model_validate_json(r["payload"])
                for r in session.run(
                    Query(
                        "MATCH (a:Entity {tenant_id:$tenant, revision:$revision})-[r]->"
                        "(b:Entity {tenant_id:$tenant, revision:$revision}) RETURN r.payload AS payload",
                        timeout=self.timeout,
                    ),
                    tenant=tenant,
                    revision=revision,
                )
            ]
            meta = session.run(
                "MATCH (s:Snapshot {tenant_id:$tenant, revision:$revision}) "
                "RETURN s.source AS source, s.warnings AS warnings",
                tenant=tenant,
                revision=revision,
            ).single()
        return GraphSnapshot(
            nodes=nodes,
            edges=edges,
            source=meta["source"] if meta else "snapshot",
            warnings=meta["warnings"] if meta else [],
        )

    def shortest_paths(
        self, tenant: str, revision: str, source: str, hops: int, include_uncertain: bool
    ) -> dict[str, list[str]]:
        if not 1 <= hops <= 5:
            raise ValueError("Hop count must be between 1 and 5")
        types = "ASSUMES_ROLE|INHERITS_PERMISSIONS|INVOKES_TOOL|CAN_READ|CAN_WRITE"
        if self.vendor == "memgraph":
            query = (
                "MATCH p=(s:Entity {tenant_id:$tenant, revision:$revision, id:$source})"
                f"-[r:{types} *BFS 1..{hops} (e,n | "
                "n.tenant_id=$tenant AND n.revision=$revision AND "
                "($uncertain OR e.certainty='confirmed'))]->(t:Entity) "
                "RETURN t.id AS target, [n IN nodes(p) | n.id] AS path"
            )
        else:
            # Filtering inside shortestPath permits a longer confirmed route when an uncertain shortcut exists.
            query = (
                "MATCH (s:Entity {tenant_id:$tenant, revision:$revision, id:$source}), "
                "(t:Entity {tenant_id:$tenant, revision:$revision}) WHERE s <> t "
                f"MATCH p=shortestPath((s)-[:{types}*1..{hops}]->(t)) "
                "WHERE all(n IN nodes(p) WHERE n.tenant_id=$tenant AND n.revision=$revision) "
                "AND all(e IN relationships(p) WHERE $uncertain OR e.certainty='confirmed') "
                "RETURN t.id AS target, [n IN nodes(p) | n.id] AS path"
            )
        with self.driver.session() as session:
            return {
                r["target"]: r["path"]
                for r in session.run(
                    Query(query, timeout=self.timeout),
                    tenant=tenant,
                    revision=revision,
                    source=source,
                    uncertain=include_uncertain,
                )
            }

    def close(self) -> None:
        self.driver.close()


@lru_cache
def get_graph_store() -> GraphStore:
    return MemoryGraphStore() if get_settings().graph_vendor == "memory" else CypherGraphStore()
