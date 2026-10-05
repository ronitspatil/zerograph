import json
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Protocol

from neo4j import GraphDatabase, Query, unit_of_work
from neo4j.exceptions import Neo4jError

from app.core.config import get_settings
from app.graph.exploration import (
    GraphSlice,
    RevisionTotals,
    RevisionUnavailable,
    RootNotFound,
    cypher_explore,
    cypher_search,
    memory_explore,
    memory_search,
    search_text,
    validate_bounds,
)
from app.graph.role_map import RoleMapSlice, cypher_roles, memory_roles, validate_role_bounds
from app.graph.schema import Edge, EdgeType, GraphSnapshot, Node, NodeType


@dataclass(frozen=True)
class RevisionMetadata:
    revision: str
    created_at_ms: int
    # "ready" (published or legacy without a state), "building" (publication in
    # progress or abandoned) or "deleting" (a batched delete started).
    state: str = "ready"


REVISION_STATES = ("ready", "building", "deleting")


@dataclass(frozen=True)
class NodeRow:
    """One entity to write; ``payload`` is the node's JSON document."""

    id: str
    type: str
    name: str
    payload: str


@dataclass(frozen=True)
class EdgeRow:
    """One relationship to write; ``payload`` is the edge's JSON document."""

    id: str
    source: str
    target: str
    type: str
    certainty: str
    payload: str


def node_row(node: Node) -> NodeRow:
    return NodeRow(node.id, node.type.value, node.name, node.model_dump_json())


def edge_row(edge: Edge) -> EdgeRow:
    return EdgeRow(edge.id, edge.source, edge.target, edge.type.value, edge.certainty, edge.model_dump_json())


def _batches(rows, size: int):
    batch = []
    for row in rows:
        batch.append(row)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


class GraphStore(Protocol):
    def migrate(self) -> None: ...
    def publish(self, tenant: str, revision: str, snapshot: GraphSnapshot) -> None: ...
    # Batched publication: the Snapshot node is written first with state "building",
    # rows follow in bounded transactions, and "ready" is set last. The SQL pointer
    # may reference a revision only after finish_revision returned.
    def begin_revision(
        self, tenant: str, revision: str, source: str = "combined", warnings: list[str] | None = None
    ) -> bool: ...
    def write_nodes(self, tenant: str, revision: str, rows: list[NodeRow]) -> None: ...
    def write_edges(self, tenant: str, revision: str, rows: list[EdgeRow]) -> None: ...
    def finish_revision(self, tenant: str, revision: str) -> None: ...
    def snapshot(self, tenant: str, revision: str) -> GraphSnapshot: ...
    def node(self, tenant: str, revision: str, node_id: str) -> Node | None: ...
    def explore(
        self,
        tenant: str,
        revision: str,
        root: str | None,
        node_limit: int,
        edge_limit: int,
        totals: RevisionTotals | None = None,
    ) -> GraphSlice: ...
    def search(self, tenant: str, revision: str, q: str, limit: int) -> tuple[list[Node], bool]: ...
    def roles(
        self,
        tenant: str,
        revision: str,
        role_limit: int,
        edge_limit: int,
        cursor: str | None,
        totals: RevisionTotals | None = None,
    ) -> RoleMapSlice: ...
    def retention_candidates(
        self,
        tenant: str,
        protected: str,
        cutoff_ms: int,
        keep: int,
        limit: int,
        stale_building_cutoff_ms: int | None = None,
    ) -> list[RevisionMetadata]: ...
    def delete_revision(
        self, tenant: str, revision: str, created_at_ms: int, cutoff_ms: int, state: str = "ready"
    ) -> bool: ...
    def shortest_paths(
        self, tenant: str, revision: str, source: str, hops: int, include_uncertain: bool
    ) -> dict[str, list[str]]: ...
    def close(self) -> None: ...


class MemoryGraphStore:
    """Explicit test/development adapter, never a production fallback."""

    def __init__(self):
        # Ready (readable) revisions only; builds in progress live in ``building``.
        self.snapshots: dict[tuple[str, str], GraphSnapshot] = {}
        self.created_at: dict[tuple[str, str], int] = {}
        self.building: dict[tuple[str, str], dict] = {}
        self.deleting: set[tuple[str, str]] = set()

    def migrate(self) -> None:
        pass

    def publish(self, tenant: str, revision: str, snapshot: GraphSnapshot) -> None:
        self.snapshots[(tenant, revision)] = snapshot.model_copy(deep=True)
        self.created_at.setdefault((tenant, revision), time.time_ns() // 1_000_000)

    def begin_revision(
        self, tenant: str, revision: str, source: str = "combined", warnings: list[str] | None = None
    ) -> bool:
        key = tenant, revision
        if key in self.snapshots or key in self.building:
            raise ValueError("Revision already exists")
        self.created_at.setdefault(key, time.time_ns() // 1_000_000)
        self.building[key] = {"source": source, "warnings": list(warnings or []), "nodes": {}, "edges": {}}
        return True

    def write_nodes(self, tenant: str, revision: str, rows: list[NodeRow]) -> None:
        build = self.building[(tenant, revision)]
        for row in rows:
            build["nodes"][row.id] = Node.model_validate_json(row.payload)

    def write_edges(self, tenant: str, revision: str, rows: list[EdgeRow]) -> None:
        build = self.building[(tenant, revision)]
        for row in rows:
            if row.source not in build["nodes"] or row.target not in build["nodes"]:
                raise ValueError("Edge endpoint missing from revision")
            build["edges"][row.id] = Edge.model_validate_json(row.payload)

    def finish_revision(self, tenant: str, revision: str) -> None:
        build = self.building.pop((tenant, revision))
        self.snapshots[(tenant, revision)] = GraphSnapshot.model_construct(
            nodes=list(build["nodes"].values()),
            edges=list(build["edges"].values()),
            warnings=build["warnings"],
            source=build["source"],
        )

    def snapshot(self, tenant: str, revision: str) -> GraphSnapshot:
        return self.snapshots.get((tenant, revision), GraphSnapshot()).model_copy(deep=True)

    def node(self, tenant: str, revision: str, node_id: str) -> Node | None:
        snapshot = self.snapshots.get((tenant, revision)) if revision else None
        found = next((node for node in snapshot.nodes if node.id == node_id), None) if snapshot else None
        return found.model_copy(deep=True) if found else None

    def explore(
        self,
        tenant: str,
        revision: str,
        root: str | None,
        node_limit: int,
        edge_limit: int,
        totals: RevisionTotals | None = None,
    ) -> GraphSlice:
        if revision and (tenant, revision) not in self.snapshots:
            raise RevisionUnavailable("Published graph revision unavailable")
        return memory_explore(
            self.snapshots[(tenant, revision)] if revision else GraphSnapshot(),
            root,
            node_limit,
            edge_limit,
            totals,
        )

    def search(self, tenant: str, revision: str, q: str, limit: int) -> tuple[list[Node], bool]:
        if revision and (tenant, revision) not in self.snapshots:
            raise RevisionUnavailable("Published graph revision unavailable")
        return memory_search(self.snapshots[(tenant, revision)] if revision else GraphSnapshot(), q, limit)

    def roles(
        self,
        tenant: str,
        revision: str,
        role_limit: int,
        edge_limit: int,
        cursor: str | None,
        totals: RevisionTotals | None = None,
    ) -> RoleMapSlice:
        validate_role_bounds(role_limit, edge_limit, cursor)
        if revision and (tenant, revision) not in self.snapshots:
            raise RevisionUnavailable("Published graph revision unavailable")
        return memory_roles(
            self.snapshots[(tenant, revision)] if revision else GraphSnapshot(),
            role_limit,
            edge_limit,
            cursor,
            totals,
        )

    def _state(self, key: tuple[str, str]) -> str | None:
        if key in self.deleting:
            return "deleting"
        if key in self.building:
            return "building"
        return "ready" if key in self.snapshots else None

    def retention_candidates(
        self,
        tenant: str,
        protected: str,
        cutoff_ms: int,
        keep: int,
        limit: int,
        stale_building_cutoff_ms: int | None = None,
    ) -> list[RevisionMetadata]:
        _validate_retention_bounds(keep, limit)
        dated = [
            RevisionMetadata(revision, created, self._state((scope, revision)))
            for (scope, revision), created in self.created_at.items()
            if scope == tenant and self._state((scope, revision)) is not None
        ]
        return _select_candidates(dated, protected, cutoff_ms, keep, limit, stale_building_cutoff_ms)

    def delete_revision(
        self, tenant: str, revision: str, created_at_ms: int, cutoff_ms: int, state: str = "ready"
    ) -> bool:
        key = tenant, revision
        current = self._state(key)
        if self.created_at.get(key) != created_at_ms or created_at_ms >= cutoff_ms:
            return False
        if current is None or not _state_matches(current, state):
            return False
        self.snapshots.pop(key, None)
        self.building.pop(key, None)
        self.deleting.discard(key)
        del self.created_at[key]
        return True

    def shortest_paths(
        self, tenant: str, revision: str, source: str, hops: int, include_uncertain: bool
    ) -> dict[str, list[str]]:
        from app.engine.blast_radius import shortest_paths

        return shortest_paths(self.snapshot(tenant, revision), source, hops, include_uncertain)

    def close(self) -> None:
        pass


def _validate_retention_bounds(keep: int, limit: int) -> None:
    if not 2 <= keep <= 1000 or not 1 <= limit <= 50:
        raise ValueError("Keep count must be 2..1000 and batch size 1..50")


def _state_matches(current: str, expected: str) -> bool:
    # A delete that already started may be resumed whatever state it was chosen in.
    return current == expected or current == "deleting"


def _select_candidates(
    dated: list[RevisionMetadata],
    protected: str,
    cutoff_ms: int,
    keep: int,
    limit: int,
    stale_building_cutoff_ms: int | None,
) -> list[RevisionMetadata]:
    """Shared retention selection over dated revisions (undated ones are never candidates).

    Ready revisions: rank newest first, keep ``keep`` regardless of age, then require
    ``created_at_ms < cutoff_ms``. A building revision is a candidate only once older
    than ``stale_building_cutoff_ms`` (an abandoned publication); a young one is never
    selected and never counts toward ``keep``. An interrupted delete is always resumed.
    The protected (current pointer) revision is never returned.
    """
    order = lambda revision: (revision.created_at_ms, revision.revision)  # noqa: E731
    ready = sorted((r for r in dated if r.state == "ready"), key=order, reverse=True)
    selected = [r for r in ready[keep:] if r.created_at_ms < cutoff_ms]
    for revision in dated:
        if revision.state == "deleting" or (
            revision.state == "building"
            and stale_building_cutoff_ms is not None
            and revision.created_at_ms < stale_building_cutoff_ms
        ):
            selected.append(revision)
    selected = [r for r in selected if r.revision != protected]
    return sorted(selected, key=order, reverse=True)[:limit]


SCHEMA_MIGRATIONS = ("001_schema.cypher", "003_entity_scope_id.cypher")


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
        folder = Path(__file__).parent / "migrations" / self.vendor
        with self.driver.session() as session:
            for name in SCHEMA_MIGRATIONS:
                for statement in (folder / name).read_text().split(";"):
                    if statement.strip():
                        try:
                            session.run(Query(statement, timeout=self.timeout)).consume()
                        except Neo4jError as exc:
                            if self.vendor != "memgraph" or "already exists" not in str(exc).lower():
                                raise

    def _write(self, function, **kwargs):
        with self.driver.session() as session:
            return session.execute_write(unit_of_work(timeout=self.timeout)(function), **kwargs)

    def publish(self, tenant: str, revision: str, snapshot: GraphSnapshot) -> None:
        """Whole-snapshot publication (restore, tests, small graphs) via the batched path.

        Republishing an existing revision MERGEs idempotently; a new revision is created.
        """
        fresh = self.begin_revision(tenant, revision, snapshot.source, snapshot.warnings)
        size = get_settings().graph_batch_size
        for batch in _batches((node_row(node) for node in snapshot.nodes), size):
            self.write_nodes(tenant, revision, batch, merge=not fresh)
        for batch in _batches((edge_row(edge) for edge in snapshot.edges), size):
            self.write_edges(tenant, revision, batch, merge=not fresh)
        self.finish_revision(tenant, revision)

    def begin_revision(
        self, tenant: str, revision: str, source: str = "combined", warnings: list[str] | None = None
    ) -> bool:
        """Write the Snapshot node first, in state "building"; True when newly created."""

        def write(tx):
            return tx.run(
                "MERGE (s:Snapshot {key:$key}) "
                "ON CREATE SET s.created_at_ms=$created_at, s.state='building', s.fresh=true "
                "ON MATCH SET s.fresh=false "
                "SET s.tenant_id=$tenant, s.revision=$revision, s.source=$source, s.warnings=$warnings "
                "RETURN s.fresh AS fresh",
                created_at=time.time_ns() // 1_000_000,
                key=json.dumps([tenant, revision]),
                tenant=tenant,
                revision=revision,
                source=source,
                warnings=list(warnings or []),
            ).single()["fresh"]

        return bool(self._write(write))

    def write_nodes(self, tenant: str, revision: str, rows: list[NodeRow], merge: bool = False) -> None:
        """One transaction per call; callers bound ``rows`` (Settings.graph_batch_size)."""
        verb = "MERGE" if merge else "CREATE"

        def write(tx):
            by_type: dict[str, list[dict]] = {}
            for row in rows:
                by_type.setdefault(NodeType(row.type).value, []).append(
                    {
                        "key": json.dumps([tenant, revision, row.id]),
                        "id": row.id,
                        "name": row.name,
                        "payload": row.payload,
                    }
                )
            for kind, items in by_type.items():
                tx.run(
                    f"UNWIND $rows AS row {verb} (n:Entity:{kind} {{key: row.key}}) "
                    "SET n.tenant_id=$tenant, n.revision=$revision, n.id=row.id, "
                    "n.name=row.name, n.payload=row.payload",
                    rows=items,
                    tenant=tenant,
                    revision=revision,
                ).consume()

        if rows:
            self._write(write)

    def write_edges(self, tenant: str, revision: str, rows: list[EdgeRow], merge: bool = False) -> None:
        """Endpoints are matched through the unique entity key, never a label scan."""
        verb = "MERGE" if merge else "CREATE"

        def write(tx):
            by_type: dict[str, list[dict]] = {}
            for row in rows:
                by_type.setdefault(EdgeType(row.type).value, []).append(
                    {
                        "source": json.dumps([tenant, revision, row.source]),
                        "target": json.dumps([tenant, revision, row.target]),
                        "id": row.id,
                        "certainty": row.certainty,
                        "payload": row.payload,
                    }
                )
            for kind, items in by_type.items():
                summary = tx.run(
                    "UNWIND $rows AS row "
                    "MATCH (a:Entity {key:row.source}) MATCH (b:Entity {key:row.target}) "
                    f"{verb} (a)-[r:{kind} {{id:row.id}}]->(b) "
                    "SET r.tenant_id=$tenant, r.revision=$revision, r.certainty=row.certainty, "
                    "r.payload=row.payload RETURN count(r) AS written",
                    rows=items,
                    tenant=tenant,
                    revision=revision,
                ).single()
                if summary["written"] != len(items):
                    raise ValueError("Edge endpoint missing from revision")

        if rows:
            self._write(write)

    def finish_revision(self, tenant: str, revision: str) -> None:
        def write(tx):
            row = tx.run(
                "MATCH (s:Snapshot {key:$key}) WHERE coalesce(s.state, 'ready') <> 'deleting' "
                "SET s.state='ready' REMOVE s.fresh RETURN s.key AS key",
                key=json.dumps([tenant, revision]),
            ).single()
            if row is None:
                raise ValueError("Revision under construction disappeared")

        self._write(write)

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

    def node(self, tenant: str, revision: str, node_id: str) -> Node | None:
        # One indexed lookup on the unique entity key instead of a full snapshot load.
        if not revision or not 1 <= len(node_id) <= 512:
            return None
        with self.driver.session() as session:
            row = session.execute_read(
                unit_of_work(timeout=self.timeout)(
                    lambda tx: tx.run(
                        "MATCH (n:Entity {key:$key, tenant_id:$tenant, revision:$revision, id:$id}) "
                        "RETURN n.payload AS payload LIMIT 1",
                        key=json.dumps([tenant, revision, node_id]),
                        tenant=tenant,
                        revision=revision,
                        id=node_id,
                    ).single()
                )
            )
        return Node.model_validate_json(row["payload"]) if row else None

    def explore(
        self,
        tenant: str,
        revision: str,
        root: str | None,
        node_limit: int,
        edge_limit: int,
        totals: RevisionTotals | None = None,
    ) -> GraphSlice:
        validate_bounds(node_limit, edge_limit, root)
        if not revision:
            if root is not None:
                raise RootNotFound("Graph root not found")
            return GraphSlice()
        with self.driver.session(fetch_size=500) as session:
            return session.execute_read(
                unit_of_work(timeout=self.timeout)(
                    lambda tx: cypher_explore(tx, tenant, revision, root, node_limit, edge_limit, totals)
                )
            )

    def search(self, tenant: str, revision: str, q: str, limit: int) -> tuple[list[Node], bool]:
        q = search_text(q, limit)
        if not revision:
            return [], False
        with self.driver.session(fetch_size=51) as session:
            return session.execute_read(
                unit_of_work(timeout=self.timeout)(lambda tx: cypher_search(tx, tenant, revision, q, limit))
            )

    def roles(
        self,
        tenant: str,
        revision: str,
        role_limit: int,
        edge_limit: int,
        cursor: str | None,
        totals: RevisionTotals | None = None,
    ) -> RoleMapSlice:
        validate_role_bounds(role_limit, edge_limit, cursor)
        if not revision:
            return RoleMapSlice()
        with self.driver.session(fetch_size=101) as session:
            return session.execute_read(
                unit_of_work(timeout=self.timeout)(
                    lambda tx: cypher_roles(tx, tenant, revision, role_limit, edge_limit, cursor, totals)
                )
            )

    def retention_candidates(
        self,
        tenant: str,
        protected: str,
        cutoff_ms: int,
        keep: int,
        limit: int,
        stale_building_cutoff_ms: int | None = None,
    ) -> list[RevisionMetadata]:
        _validate_retention_bounds(keep, limit)
        # Snapshot metadata only (one small node per revision). Ranking keeps the
        # newest ready revisions regardless of age; undated legacy revisions are never
        # inferred old enough for deletion. Selection is shared with the memory adapter.
        query = (
            "MATCH (s:Snapshot {tenant_id:$tenant}) WHERE s.created_at_ms IS NOT NULL "
            "RETURN s.revision AS revision, s.created_at_ms AS created_at, "
            "coalesce(s.state, 'ready') AS state"
        )
        with self.driver.session() as session:
            dated = [
                RevisionMetadata(row["revision"], row["created_at"], row["state"])
                for row in session.run(Query(query, timeout=self.timeout), tenant=tenant)
                if row["state"] in REVISION_STATES
            ]
        return _select_candidates(dated, protected, cutoff_ms, keep, limit, stale_building_cutoff_ms)

    def delete_revision(
        self, tenant: str, revision: str, created_at_ms: int, cutoff_ms: int, state: str = "ready"
    ) -> bool:
        """Batched delete. Call only while holding the tenant publication lock.

        The Snapshot node is marked "deleting" first and removed last, so an
        interrupted delete stays discoverable and is resumed by the next run. No
        graph-only check can establish which revision the SQL pointer references.
        """
        key = json.dumps([tenant, revision])

        def mark(tx):
            row = tx.run(
                "MATCH (s:Snapshot {key:$key}) "
                "WHERE s.tenant_id=$tenant AND s.revision=$revision "
                "AND s.created_at_ms=$created AND s.created_at_ms < $cutoff "
                "AND coalesce(s.state, 'ready') IN [$state, 'deleting'] "
                "SET s.state='deleting' RETURN s.key AS key",
                key=key,
                tenant=tenant,
                revision=revision,
                created=created_at_ms,
                cutoff=cutoff_ms,
                state=state,
            ).single()
            return row is not None

        if not self._write(mark):
            return False
        size = get_settings().graph_batch_size

        def delete_batch(tx):
            return tx.run(
                "MATCH (n:Entity {tenant_id:$tenant, revision:$revision}) "
                "WITH n LIMIT $limit DETACH DELETE n RETURN count(*) AS deleted",
                tenant=tenant,
                revision=revision,
                limit=max(1, size // 2),
            ).single()["deleted"]

        while self._write(delete_batch):
            pass

        def remove(tx):
            tx.run("MATCH (s:Snapshot {key:$key}) DELETE s", key=key).consume()

        self._write(remove)
        return True

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
