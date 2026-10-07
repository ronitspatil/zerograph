"""Fixed operator helper executed in the matching backend image, never an API.

Graph archives are streamed as NDJSON (format version 2): a header line with the
application metadata, then per revision (tenant, revision order) one ``revision``
line followed by its ``node`` lines (ID order) and ``edge`` lines (edge-ID order),
and a closing ``end`` line with totals. Export, validation and import keep one
revision's node IDs in memory at most. Version 1 single-document JSON archives
are still validated and imported (``convert-v1`` rewrites one as version 2).
"""

import json
import sys
from importlib.metadata import version
from pathlib import Path

from alembic.script import ScriptDirectory
from app.collectors.publication import derived_bounds
from app.core.config import get_settings
from app.db.models import (
    AuditEvent,
    IngestionJob,
    ObservedAccess,
    ProposalDecision,
    Remediation,
    RevisionAnalysis,
    RevisionCluster,
    RevisionClusterLink,
    RevisionClusterMember,
    RevisionClusterSummary,
    RevisionFinding,
    RevisionPolicy,
    RevisionPolicyDocument,
    RevisionProposal,
    RevisionProposalModel,
    RevisionProposalSummary,
    RevisionTopic,
    RevisionTopicLink,
    RevisionTopicMember,
    RevisionTopicSummary,
    SourceSnapshot,
    StagedEntity,
    TenantState,
    UploadSession,
    UsageCoverage,
    UsageUpload,
)
from app.db.session import session_factory
from app.graph.repository import EdgeRow, NodeRow, get_graph_store
from app.graph.schema import Edge, GraphSnapshot, Node
from sqlalchemy import func, select, text

GRAPH_FORMAT = "zerograph-graph"
GRAPH_VERSION = 2
MAX_REVISIONS = 1000
MAX_TENANTS = 1000
# Version 1 (single in-memory JSON document) bounds, kept for legacy archives.
MAX_GRAPH_BYTES = 100_000_000
MAX_NODES = 100_000
MAX_EDGES = 400_000
STATES = {"ready", "building", "deleting"}


def revision_bounds():
    """Per-revision bounds of a streamed archive: the publication caps plus the
    classification annotations publication derives on top of submitted entities."""
    settings = get_settings()
    return derived_bounds(settings.max_nodes, settings.max_edges)


def enforce_bounds(counts, payload_characters, tenants):
    """Version 1 whole-archive bounds."""
    if (
        counts["revisions"] > MAX_REVISIONS
        or tenants > MAX_TENANTS
        or counts["nodes"] > MAX_NODES
        or counts["edges"] > MAX_EDGES
        # UTF-8 upper bound plus conservative envelope/pointer overhead.
        or payload_characters * 4 + counts["revisions"] * 2000 + tenants * 2000 > MAX_GRAPH_BYTES
    ):
        raise ValueError("Logical backup exceeds supported graph bounds")


def enforce_revision_bounds(revisions, tenants, per_revision):
    max_nodes, max_edges = revision_bounds()
    if (
        revisions > MAX_REVISIONS
        or tenants > MAX_TENANTS
        or any(nodes > max_nodes or edges > max_edges for nodes, edges in per_revision)
    ):
        raise ValueError("Logical backup exceeds supported graph bounds")


def preflight(graph):
    """Count everything before streaming; refuse unmanaged or orphaned graph data."""
    with session_factory()() as db:
        tenants = db.scalar(select(func.count()).select_from(TenantState))
    with graph.driver.session() as session:
        revisions = [
            dict(record)
            for record in session.run(
                "MATCH (s:Snapshot) RETURN s.tenant_id AS tenant, s.revision AS revision, "
                "s.created_at_ms AS created_at_ms, s.state AS state, s.source AS source, "
                "s.warnings AS warnings ORDER BY tenant, revision"
            )
        ]
        enforce_revision_bounds(len(revisions), tenants, [])
        nodes = {
            (record["tenant"], record["revision"]): record["count"]
            for record in session.run(
                "MATCH (n:Entity) RETURN n.tenant_id AS tenant, n.revision AS revision, count(n) AS count"
            )
        }
        edges = {
            (record["tenant"], record["revision"]): record["count"]
            for record in session.run(
                "MATCH (a:Entity)-[r]->(b:Entity) WHERE r.tenant_id = a.tenant_id AND r.tenant_id = b.tenant_id "
                "AND r.revision = a.revision AND r.revision = b.revision "
                "RETURN r.tenant_id AS tenant, r.revision AS revision, count(r) AS count"
            )
        }
        total_nodes = session.run("MATCH (n) RETURN count(n) AS count").single()["count"]
        total_edges = session.run("MATCH ()-[r]->() RETURN count(r) AS count").single()["count"]
    keys = {(item["tenant"], item["revision"]) for item in revisions}
    if len(keys) != len(revisions):
        raise ValueError("Duplicate graph revision")
    for item in revisions:
        key = item["tenant"], item["revision"]
        item["nodes"], item["edges"] = nodes.get(key, 0), edges.get(key, 0)
    enforce_revision_bounds(len(revisions), tenants, [(item["nodes"], item["edges"]) for item in revisions])
    if set(nodes) - keys or total_nodes != len(revisions) + sum(nodes.values()):
        raise ValueError("Graph contains unmanaged or orphaned nodes; archive would be incomplete")
    if set(edges) - keys or total_edges != sum(edges.values()):
        raise ValueError("Graph contains unmanaged or orphaned relationships")
    return revisions


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
                    UploadSession,
                    StagedEntity,
                    # Per-revision analysis, global-map clusters and topics travel in
                    # the PostgreSQL dump with their revisions (and are recomputable).
                    RevisionAnalysis,
                    RevisionFinding,
                    RevisionClusterSummary,
                    RevisionCluster,
                    RevisionClusterLink,
                    RevisionClusterMember,
                    RevisionTopicSummary,
                    RevisionTopic,
                    RevisionTopicLink,
                    RevisionTopicMember,
                    RevisionPolicyDocument,
                    RevisionPolicy,
                    RevisionProposalSummary,
                    RevisionProposal,
                    RevisionProposalModel,
                    # Tenant usage evidence (observed access) carries forward across revisions,
                    # and so do accept/reject decisions on proposals (by stable proposal ID).
                    UsageUpload,
                    ObservedAccess,
                    UsageCoverage,
                    ProposalDecision,
                )
            },
        }


def check_release(data_metadata):
    current = runtime()
    if any(data_metadata.get(key) != value for key, value in current.items()):
        raise ValueError("Backup requires the matching application release")
    if data_metadata["schema_revision"] != current["schema_head"]:
        raise ValueError("Migrate source before backup")


def dumps(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def canonical_node(node):
    return node.model_dump(mode="json")


def canonical_edge(edge):
    return edge.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Version 2: streamed NDJSON


def export_stream(output):
    graph = get_graph_store()
    revisions = preflight(graph)
    header = {"format": GRAPH_FORMAT, "version": GRAPH_VERSION, "metadata": metadata()}
    output.write(dumps(header) + "\n")
    totals = {"revisions": 0, "nodes": 0, "edges": 0}
    with graph.driver.session(fetch_size=2000) as session:
        for item in revisions:
            retention = {} if item["created_at_ms"] is None else {"created_at_ms": item["created_at_ms"]}
            entry = {
                "tenant": item["tenant"],
                "revision": item["revision"],
                "retention": retention,
                "state": item["state"] or "ready",
                "source": item["source"] or "snapshot",
                "warnings": list(item["warnings"] or []),
                "nodes": item["nodes"],
                "edges": item["edges"],
            }
            output.write(dumps({"revision": entry}) + "\n")
            params = {"tenant": item["tenant"], "revision": item["revision"]}
            written = 0
            for record in session.run(
                "MATCH (n:Entity {tenant_id:$tenant, revision:$revision}) RETURN n.payload AS payload ORDER BY n.id",
                **params,
            ):
                output.write(
                    dumps({"node": canonical_node(Node.model_validate_json(record["payload"]))}) + "\n"
                )
                written += 1
            if written != item["nodes"]:
                raise ValueError("Graph changed during backup")
            written = 0
            for record in session.run(
                "MATCH (a:Entity {tenant_id:$tenant, revision:$revision})-[r]->"
                "(b:Entity {tenant_id:$tenant, revision:$revision}) "
                "WHERE r.tenant_id=$tenant AND r.revision=$revision "
                "RETURN r.payload AS payload ORDER BY r.id",
                **params,
            ):
                output.write(
                    dumps({"edge": canonical_edge(Edge.model_validate_json(record["payload"]))}) + "\n"
                )
                written += 1
            if written != item["edges"]:
                raise ValueError("Graph changed during backup")
            totals["revisions"] += 1
            totals["nodes"] += item["nodes"]
            totals["edges"] += item["edges"]
    output.write(dumps({"end": totals}) + "\n")


def read_stream(lines, on_revision=None, on_nodes=None, on_edges=None, batch=5000):
    """Validate a version 2 stream; callbacks receive validated batches in order."""
    lines = iter(lines)
    try:
        header = json.loads(next(lines))
    except StopIteration:
        raise ValueError("Invalid graph envelope") from None
    if not isinstance(header, dict) or set(header) != {"format", "version", "metadata"}:
        raise ValueError("Invalid graph envelope")
    if header["format"] != GRAPH_FORMAT or header["version"] != GRAPH_VERSION:
        raise ValueError("Unsupported graph format")
    check_release(header["metadata"])
    max_nodes, max_edges = revision_bounds()
    identities, previous, totals = set(), None, None
    counted = {"nodes": 0, "edges": 0}
    current, ended = None, False

    def close(entry):
        if entry is not None and (
            entry["seen_nodes"] != entry["nodes"] or entry["seen_edges"] != entry["edges"]
        ):
            raise ValueError("Revision entity counts do not match its header")

    pending = []

    def flush(kind):
        if pending:
            callback = on_nodes if kind == "node" else on_edges
            if callback:
                callback(current, list(pending))
            pending.clear()

    phase = None
    for raw in lines:
        if ended:
            raise ValueError("Data after graph end marker")
        item = json.loads(raw)
        if not isinstance(item, dict) or len(item) != 1:
            raise ValueError("Invalid graph line")
        kind, value = next(iter(item.items()))
        if kind == "revision":
            flush(phase)
            close(current)
            if not isinstance(value, dict) or set(value) != {
                "tenant",
                "revision",
                "retention",
                "state",
                "source",
                "warnings",
                "nodes",
                "edges",
            }:
                raise ValueError("Invalid snapshot entry")
            if not isinstance(value["tenant"], str) or not 1 <= len(value["tenant"]) <= 128:
                raise ValueError("Invalid tenant")
            if not isinstance(value["revision"], str) or not 1 <= len(value["revision"]) <= 64:
                raise ValueError("Invalid revision")
            identity = value["tenant"], value["revision"]
            if identity in identities or (previous is not None and identity <= previous):
                raise ValueError("Duplicate or unordered graph revision")
            identities.add(identity)
            previous = identity
            retention = value["retention"]
            if not isinstance(retention, dict) or set(retention) - {"created_at_ms"}:
                raise ValueError("Unknown retention metadata")
            if "created_at_ms" in retention and (
                type(retention["created_at_ms"]) is not int or retention["created_at_ms"] < 0
            ):
                raise ValueError("Invalid retention timestamp")
            if value["state"] not in STATES:
                raise ValueError("Invalid revision state")
            GraphSnapshot(warnings=value["warnings"], source=value["source"])
            for count, bound in ((value["nodes"], max_nodes), (value["edges"], max_edges)):
                if type(count) is not int or not 0 <= count <= bound:
                    raise ValueError("Logical backup exceeds supported graph bounds")
            if len(identities) > MAX_REVISIONS:
                raise ValueError("Logical backup exceeds supported graph bounds")
            current = {**value, "seen_nodes": 0, "seen_edges": 0, "ids": set(), "last": ""}
            phase = "node"
            if on_revision:
                on_revision(current)
        elif kind in ("node", "edge"):
            if current is None or (kind == "node" and phase != "node"):
                raise ValueError("Graph entity outside a revision")
            if kind == "edge" and phase == "node":
                flush("node")
                phase, current["last"] = "edge", ""
            if kind == "node":
                node = Node.model_validate(value)
                if node.id <= current["last"]:
                    raise ValueError("Duplicate or unordered graph node")
                current["last"] = node.id
                current["ids"].add(node.id)
                current["seen_nodes"] += 1
                counted["nodes"] += 1
                pending.append(NodeRow(node.id, node.type.value, node.name, node.model_dump_json()))
            else:
                edge = Edge.model_validate(value)
                if edge.id <= current["last"]:
                    raise ValueError("Duplicate or unordered graph edge")
                if edge.source not in current["ids"] or edge.target not in current["ids"]:
                    raise ValueError("Every edge endpoint must exist in this snapshot")
                current["last"] = edge.id
                current["seen_edges"] += 1
                counted["edges"] += 1
                pending.append(
                    EdgeRow(
                        edge.id,
                        edge.source,
                        edge.target,
                        edge.type.value,
                        edge.certainty,
                        edge.model_dump_json(),
                    )
                )
            if len(pending) >= batch:
                flush(phase)
        elif kind == "end":
            flush(phase)
            close(current)
            current, ended = None, True
            totals = value
        else:
            raise ValueError("Invalid graph line")
    if not ended:
        raise ValueError("Truncated graph archive")
    if totals != {"revisions": len(identities), "nodes": counted["nodes"], "edges": counted["edges"]}:
        raise ValueError("Graph archive totals do not match")
    for link in header["metadata"]["revision_links"]:
        if link["revision"] and (link["tenant"], link["revision"]) not in identities:
            raise ValueError("SQL revision pointer has no graph snapshot")
    return header["metadata"]


def import_stream(lines):
    graph = get_graph_store()
    with graph.driver.session() as session:
        if session.run("MATCH (n) RETURN count(n) AS count").single()["count"]:
            raise ValueError("Restore requires an empty graph")
    graph.migrate()
    imported = {"snapshots": 0}
    finished = []

    def finish(entry):
        graph.finish_revision(entry["tenant"], entry["revision"])
        with graph.driver.session() as session:
            query = "MATCH (s:Snapshot {tenant_id:$tenant, revision:$revision}) SET s.state=$state " + (
                ", s.created_at_ms=$created"
                if "created_at_ms" in entry["retention"]
                else "REMOVE s.created_at_ms"
            )
            session.run(
                query,
                tenant=entry["tenant"],
                revision=entry["revision"],
                state=entry["state"],
                created=entry["retention"].get("created_at_ms"),
            ).consume()
        imported["snapshots"] += 1

    def on_revision(entry):
        if finished:
            finish(finished.pop())
        graph.begin_revision(entry["tenant"], entry["revision"], entry["source"], entry["warnings"])
        finished.append(entry)

    read_stream(
        lines,
        on_revision,
        lambda entry, rows: graph.write_nodes(entry["tenant"], entry["revision"], rows),
        lambda entry, rows: graph.write_edges(entry["tenant"], entry["revision"], rows),
        get_settings().graph_batch_size,
    )
    if finished:
        finish(finished.pop())
    return imported


# ---------------------------------------------------------------------------
# Version 1: single JSON document (read-only compatibility)


def validate(data):
    if not isinstance(data, dict) or set(data) != {"snapshots", "metadata"}:
        raise ValueError("Invalid graph envelope")
    check_release(data["metadata"])
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


def import_v1(data):
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


def convert_v1(data, output):
    """Rewrite a validated version 1 document as the equivalent version 2 stream."""
    output.write(
        dumps({"format": GRAPH_FORMAT, "version": GRAPH_VERSION, "metadata": data["metadata"]}) + "\n"
    )
    totals = {"revisions": 0, "nodes": 0, "edges": 0}
    for item in sorted(data["snapshots"], key=lambda entry: (entry["tenant"], entry["revision"])):
        snapshot = GraphSnapshot.model_validate(item["graph"])
        entry = {
            "tenant": item["tenant"],
            "revision": item["revision"],
            "retention": item["retention"],
            "state": "ready",
            "source": snapshot.source,
            "warnings": snapshot.warnings,
            "nodes": len(snapshot.nodes),
            "edges": len(snapshot.edges),
        }
        output.write(dumps({"revision": entry}) + "\n")
        for node in sorted(snapshot.nodes, key=lambda node: node.id):
            output.write(dumps({"node": canonical_node(node)}) + "\n")
        for edge in sorted(snapshot.edges, key=lambda edge: edge.id):
            output.write(dumps({"edge": canonical_edge(edge)}) + "\n")
        totals["revisions"] += 1
        totals["nodes"] += entry["nodes"]
        totals["edges"] += entry["edges"]
    output.write(dumps({"end": totals}) + "\n")


def canonical_graph(snapshot):
    # Cypher MATCH does not guarantee row order. Compare logical content, not internal storage IDs.
    return snapshot.model_copy(
        update={
            "nodes": sorted(snapshot.nodes, key=lambda node: node.id),
            "edges": sorted(snapshot.edges, key=lambda edge: edge.id),
        }
    ).model_dump(mode="json")


def is_v1(first_line):
    try:
        value = json.loads(first_line)
    except ValueError:
        return True  # A pretty-printed or single-line document spanning lines.
    return isinstance(value, dict) and "snapshots" in value


def stdin_lines():
    return (line for line in sys.stdin if line.strip())


def execute(action):
    if action == "runtime":
        return runtime()
    if action == "metadata":
        return metadata()
    if action in {"validate", "import", "convert-v1"}:
        lines = stdin_lines()
        first = next(lines, "")
        if is_v1(first):
            data = validate(json.loads(first + "".join(lines)))
            if action == "validate":
                return data["metadata"]
            if action == "convert-v1":
                convert_v1(data, sys.stdout)
                return None
            return import_v1(data)
        if action == "convert-v1":
            raise ValueError("Archive is already version 2")
        stream = (line for part in ([first], lines) for line in part)
        if action == "validate":
            return read_stream(stream)
        return import_stream(stream)
    graph = get_graph_store()
    if action == "empty":
        with graph.driver.session() as session:
            if session.run("MATCH (n) RETURN count(n) AS count").single()["count"]:
                raise ValueError("Restore requires an empty graph")
        return {"empty": True}
    if action != "export":
        raise ValueError("Unknown operation")
    export_stream(sys.stdout)
    return None


if __name__ == "__main__":
    try:
        result = execute(sys.argv[1])
        if result is not None:
            print(dumps(result))
    except Exception:  # noqa: BLE001 - never expose sensitive driver diagnostics at this operator boundary
        # Do not print connector URLs, credentials, graph metadata or SQL payloads.
        print(
            "Snapshot operation failed; check offline state and release compatibility.",
            file=sys.stderr,
        )
        sys.exit(1)
