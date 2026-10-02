"""Fixed operator helper executed in the matching backend image, never an API."""

import json
import sys
from importlib.metadata import version
from pathlib import Path

from alembic.script import ScriptDirectory
from app.core.config import get_settings
from app.db.models import (
    AuditEvent,
    IngestionJob,
    Remediation,
    SourceSnapshot,
    TenantState,
)
from app.db.session import session_factory
from app.graph.repository import get_graph_store
from app.graph.schema import GraphSnapshot
from sqlalchemy import func, select, text

MAX_GRAPH_BYTES = 100_000_000
MAX_REVISIONS = 1000
MAX_TENANTS = 1000
MAX_NODES = 100_000
MAX_EDGES = 400_000


def enforce_bounds(counts, payload_characters, tenants):
    if (
        counts["revisions"] > MAX_REVISIONS
        or tenants > MAX_TENANTS
        or counts["nodes"] > MAX_NODES
        or counts["edges"] > MAX_EDGES
        # UTF-8 upper bound plus conservative envelope/pointer overhead.
        or payload_characters * 4 + counts["revisions"] * 2000 + tenants * 2000 > MAX_GRAPH_BYTES
    ):
        raise ValueError("Logical backup exceeds supported graph bounds")


def preflight(graph):
    with session_factory()() as db:
        tenants = db.scalar(select(func.count()).select_from(TenantState))
    with graph.driver.session() as session:
        counts = {
            "nodes": session.run("MATCH (n) RETURN count(n) AS count").single()["count"],
            "edges": session.run("MATCH ()-[r]->() RETURN count(r) AS count").single()["count"],
            "revisions": session.run("MATCH (s:Snapshot) RETURN count(s) AS count").single()["count"],
        }
        enforce_bounds(counts, 0, tenants)
        queries = [
            "MATCH (n:Entity) RETURN sum(size(n.payload)) AS size",
            "MATCH ()-[r]->() RETURN sum(size(r.payload)) AS size",
            "MATCH (s:Snapshot) RETURN sum(size(s.tenant_id)+size(s.revision)+size(s.source)) AS size",
            "MATCH (s:Snapshot) UNWIND s.warnings AS warning RETURN sum(size(warning)) AS size",
        ]
        characters = sum((session.run(query).single()["size"] or 0) for query in queries)
        enforce_bounds(counts, characters, tenants)


def runtime():
    if get_settings().graph_vendor != "memgraph":
        raise ValueError("Only Memgraph backups are supported")
    from app.db import migrations

    head = ScriptDirectory(str(Path(migrations.__file__).parent)).get_current_head()
    return {"app_version": version("zerograph"), "schema_head": head}


def metadata():
    with session_factory()() as db:
        if db.scalar(select(func.count()).select_from(IngestionJob).where(IngestionJob.status == "running")):
            raise ValueError("Drain running jobs before backup")
        return {
            **runtime(),
            "schema_revision": db.scalar(text("SELECT version_num FROM alembic_version")),
            "revision_links": sorted(
                [{"tenant": t.tenant_id, "revision": t.revision} for t in db.scalars(select(TenantState))],
                key=lambda item: item["tenant"],
            ),
            "row_counts": {
                model.__tablename__: db.scalar(select(func.count()).select_from(model))
                for model in (
                    IngestionJob,
                    AuditEvent,
                    Remediation,
                    SourceSnapshot,
                    TenantState,
                )
            },
        }


def validate(data):
    if not isinstance(data, dict) or set(data) != {"snapshots", "metadata"}:
        raise ValueError("Invalid graph envelope")
    current = runtime()
    if any(data["metadata"].get(key) != value for key, value in current.items()):
        raise ValueError("Backup requires the matching application release")
    if data["metadata"]["schema_revision"] != current["schema_head"]:
        raise ValueError("Migrate source before backup")
    identities = set()
    for item in data["snapshots"]:
        if not isinstance(item, dict) or set(item) != {
            "tenant",
            "revision",
            "graph",
            "retention",
        }:
            raise ValueError("Invalid snapshot entry")
        if not isinstance(item["tenant"], str) or not 1 <= len(item["tenant"]) <= 128:
            raise ValueError("Invalid tenant")
        if not isinstance(item["revision"], str) or not 1 <= len(item["revision"]) <= 64:
            raise ValueError("Invalid revision")
        identity = (item["tenant"], item["revision"])
        if identity in identities:
            raise ValueError("Duplicate graph revision")
        identities.add(identity)
        retention = item["retention"]
        if not isinstance(retention, dict) or set(retention) - {"created_at_ms"}:
            raise ValueError("Unknown retention metadata")
        if "created_at_ms" in retention and (
            type(retention["created_at_ms"]) is not int or retention["created_at_ms"] < 0
        ):
            raise ValueError("Invalid retention timestamp")
        GraphSnapshot.model_validate(item["graph"])
    for link in data["metadata"]["revision_links"]:
        if link["revision"] and (link["tenant"], link["revision"]) not in identities:
            raise ValueError("SQL revision pointer has no graph snapshot")
    return data


def execute(action):
    if action == "runtime":
        return runtime()
    if action == "metadata":
        return metadata()
    if action in {"validate", "import"}:
        data = validate(json.load(sys.stdin))
        if action == "validate":
            return data["metadata"]
        graph = get_graph_store()
        with graph.driver.session() as session:
            if session.run("MATCH (n) RETURN count(n) AS count").single()["count"]:
                raise ValueError("Restore requires an empty graph")
        graph.migrate()
        for item in data["snapshots"]:
            graph.publish(
                item["tenant"],
                item["revision"],
                GraphSnapshot.model_validate(item["graph"]),
            )
            with graph.driver.session() as session:
                query = "MATCH (s:Snapshot {tenant_id:$tenant, revision:$revision}) " + (
                    "SET s.created_at_ms=$created"
                    if "created_at_ms" in item["retention"]
                    else "REMOVE s.created_at_ms"
                )
                session.run(
                    query,
                    tenant=item["tenant"],
                    revision=item["revision"],
                    created=item["retention"].get("created_at_ms"),
                ).consume()
        return {"snapshots": len(data["snapshots"])}
    graph = get_graph_store()
    if action == "empty":
        with graph.driver.session() as session:
            if session.run("MATCH (n) RETURN count(n) AS count").single()["count"]:
                raise ValueError("Restore requires an empty graph")
        return {"empty": True}
    if action != "export":
        raise ValueError("Unknown operation")
    preflight(graph)
    with graph.driver.session() as session:
        revisions = [
            dict(record)
            for record in session.run(
                "MATCH (s:Snapshot) RETURN s.tenant_id AS tenant, s.revision AS revision, properties(s) AS properties "
                "ORDER BY s.tenant_id, s.revision"
            )
        ]
    data = {
        "metadata": metadata(),
        "snapshots": [
            {
                "tenant": item["tenant"],
                "revision": item["revision"],
                "graph": canonical_graph(graph.snapshot(item["tenant"], item["revision"])),
                "retention": {
                    key: item["properties"][key] for key in ("created_at_ms",) if key in item["properties"]
                },
            }
            for item in revisions
        ],
    }
    with graph.driver.session() as session:
        nodes = session.run("MATCH (n) RETURN count(n) AS count").single()["count"]
        edges = session.run("MATCH ()-[r]->() RETURN count(r) AS count").single()["count"]
    if nodes != len(revisions) + sum(len(item["graph"]["nodes"]) for item in data["snapshots"]):
        raise ValueError("Graph contains unmanaged or orphaned nodes; archive would be incomplete")
    if edges != sum(len(item["graph"]["edges"]) for item in data["snapshots"]):
        raise ValueError("Graph contains unmanaged or orphaned relationships")
    return validate(data)


def canonical_graph(snapshot):
    # Cypher MATCH does not guarantee row order. Compare logical content, not internal storage IDs.
    return snapshot.model_copy(
        update={
            "nodes": sorted(snapshot.nodes, key=lambda node: node.id),
            "edges": sorted(snapshot.edges, key=lambda edge: edge.id),
        }
    ).model_dump(mode="json")


if __name__ == "__main__":
    try:
        print(json.dumps(execute(sys.argv[1]), separators=(",", ":"), sort_keys=True, ensure_ascii=False))
    except Exception:  # noqa: BLE001 - never expose sensitive driver diagnostics at this operator boundary
        # Do not print connector URLs, credentials, graph metadata or SQL payloads.
        print(
            "Snapshot operation failed; check offline state and release compatibility.",
            file=sys.stderr,
        )
        sys.exit(1)
