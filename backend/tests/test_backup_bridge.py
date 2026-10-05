"""Operator bridge refuses large exports before loading revision payloads."""

import importlib.util
import io
import json
from pathlib import Path
from unittest.mock import MagicMock, Mock

import pytest

spec = importlib.util.spec_from_file_location(
    "backup_bridge", Path(__file__).resolve().parents[2] / "deploy" / "_snapshot_bridge.py"
)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


@pytest.mark.parametrize(
    ("counts", "characters", "tenants"),
    [
        ({"nodes": 0, "edges": 0, "revisions": 1001}, 0, 1),
        ({"nodes": 100001, "edges": 0, "revisions": 1}, 0, 1),
        ({"nodes": 0, "edges": 400001, "revisions": 1}, 0, 1),
        ({"nodes": 0, "edges": 0, "revisions": 1}, 0, 1001),
        ({"nodes": 1, "edges": 1, "revisions": 1}, 25_000_000, 1),
    ],
)
def test_bounds_refuse_oversized_exports(counts, characters, tenants):
    with pytest.raises(ValueError, match="supported graph bounds"):
        bridge.enforce_bounds(counts, characters, tenants)


def preflight_graph(revisions, nodes, edges, total_nodes, total_edges):
    graph = MagicMock()
    session = graph.driver.session.return_value.__enter__.return_value
    session.run.side_effect = [
        revisions,
        nodes,
        edges,
        Mock(single=Mock(return_value={"count": total_nodes})),
        Mock(single=Mock(return_value={"count": total_edges})),
    ]
    return graph, session


def revision(tenant="demo", name="one"):
    return {
        "tenant": tenant,
        "revision": name,
        "created_at_ms": 1,
        "state": None,
        "source": "combined",
        "warnings": [],
    }


@pytest.fixture
def one_tenant(monkeypatch):
    factory = MagicMock()
    factory.return_value.return_value.__enter__.return_value.scalar.return_value = 1
    monkeypatch.setattr(bridge, "session_factory", factory)
    monkeypatch.setattr(bridge, "revision_bounds", lambda: (10, 20))


def test_preflight_refuses_oversized_revision_before_streaming(one_tenant, monkeypatch):
    graph, session = preflight_graph(
        [revision()], [{"tenant": "demo", "revision": "one", "count": 11}], [], 12, 0
    )
    monkeypatch.setattr(bridge, "get_graph_store", lambda: graph)
    metadata = Mock()
    monkeypatch.setattr(bridge, "metadata", metadata)
    with pytest.raises(ValueError, match="supported graph bounds"):
        bridge.execute("export")
    metadata.assert_not_called()
    assert not any("payload" in call.args[0] for call in session.run.call_args_list)


@pytest.mark.parametrize(
    ("nodes", "edges", "total_nodes", "total_edges", "message"),
    [
        ([{"tenant": "demo", "revision": "one", "count": 2}], [], 4, 0, "unmanaged or orphaned nodes"),
        ([{"tenant": "demo", "revision": "gone", "count": 2}], [], 3, 0, "unmanaged or orphaned nodes"),
        ([{"tenant": "demo", "revision": "one", "count": 2}], [], 3, 1, "orphaned relationships"),
    ],
)
def test_preflight_refuses_unmanaged_graph_data(one_tenant, nodes, edges, total_nodes, total_edges, message):
    graph, _ = preflight_graph([revision()], nodes, edges, total_nodes, total_edges)
    with pytest.raises(ValueError, match=message):
        bridge.preflight(graph)


def v2_lines(metadata, revisions):
    lines = [{"format": "zerograph-graph", "version": 2, "metadata": metadata}]
    totals = {"revisions": 0, "nodes": 0, "edges": 0}
    for entry, nodes, edges in revisions:
        lines.append({"revision": {**entry, "nodes": len(nodes), "edges": len(edges)}})
        lines += [{"node": node} for node in nodes] + [{"edge": edge} for edge in edges]
        totals = {
            "revisions": totals["revisions"] + 1,
            "nodes": totals["nodes"] + len(nodes),
            "edges": totals["edges"] + len(edges),
        }
    lines.append({"end": totals})
    return [json.dumps(line) + "\n" for line in lines]


METADATA = {
    "app_version": "0.1.0",
    "schema_head": "0004",
    "schema_revision": "0004",
    "revision_links": [{"tenant": "demo", "revision": "one"}],
}
ENTRY = {
    "tenant": "demo",
    "revision": "one",
    "retention": {"created_at_ms": 5},
    "state": "ready",
    "source": "combined",
    "warnings": ["w"],
}
NODES = [
    {"id": "a", "type": "S3Bucket", "name": "Asset"},
    {"id": "b", "type": "ServiceAccount", "name": "Identity"},
]
EDGES = sorted(
    [
        bridge.Edge(source="b", target="a", type="CAN_READ").model_dump(mode="json"),
        bridge.Edge(source="b", target="a", type="CAN_WRITE").model_dump(mode="json"),
    ],
    key=lambda edge: bridge.Edge.model_validate(edge).id,
)


@pytest.fixture
def release(monkeypatch):
    monkeypatch.setattr(bridge, "runtime", lambda: {"app_version": "0.1.0", "schema_head": "0004"})
    monkeypatch.setattr(bridge, "revision_bounds", lambda: (10, 20))


def test_stream_validation_delivers_ordered_batches(release):
    seen = {"revisions": [], "nodes": [], "edges": []}
    metadata = bridge.read_stream(
        v2_lines(METADATA, [(ENTRY, NODES, EDGES)]),
        lambda entry: seen["revisions"].append(entry["revision"]),
        lambda entry, rows: seen["nodes"].extend(row.id for row in rows),
        lambda entry, rows: seen["edges"].extend(row.id for row in rows),
        batch=1,
    )
    assert metadata == METADATA
    assert seen == {
        "revisions": ["one"],
        "nodes": ["a", "b"],
        "edges": [bridge.Edge.model_validate(edge).id for edge in EDGES],
    }


@pytest.mark.parametrize(
    "mutate",
    [
        lambda lines: lines[:-1],  # truncated: no end marker
        lambda lines: lines + lines[-1:],  # data after end
        lambda lines: [lines[0], lines[1], lines[3], lines[2], *lines[4:]],  # unordered nodes
        lambda lines: [lines[0], lines[1], lines[2], lines[2], *lines[3:]],  # duplicate node
        lambda lines: [*lines[:4], lines[5], lines[4], lines[6]],  # unordered edges
        lambda lines: [lines[0], lines[1], lines[3], *lines[4:]],  # count mismatch / dangling
        lambda lines: [lines[0].replace('"0004"', '"0003"'), *lines[1:]],  # other release
        lambda lines: [lines[0], *lines[1:-1], lines[-1].replace('"nodes": 2', '"nodes": 3')],
        lambda lines: [lines[0], lines[1].replace('"ready"', '"unknown"'), *lines[2:]],
    ],
)
def test_stream_validation_refuses_malformed_archives(release, mutate):
    with pytest.raises(ValueError):
        bridge.read_stream(mutate(v2_lines(METADATA, [(ENTRY, NODES, EDGES)])))


def test_stream_refuses_missing_pointer_revision_and_oversized_revision(release, monkeypatch):
    other = {**METADATA, "revision_links": [{"tenant": "demo", "revision": "missing"}]}
    with pytest.raises(ValueError, match="pointer"):
        bridge.read_stream(v2_lines(other, [(ENTRY, NODES, EDGES)]))
    monkeypatch.setattr(bridge, "revision_bounds", lambda: (1, 20))
    with pytest.raises(ValueError, match="supported graph bounds"):
        bridge.read_stream(v2_lines(METADATA, [(ENTRY, NODES, EDGES)]))


def test_version_1_document_converts_to_an_equivalent_valid_stream(release):
    data = {
        "metadata": METADATA,
        "snapshots": [
            {
                "tenant": "demo",
                "revision": "one",
                "graph": {
                    "nodes": list(reversed(NODES)),
                    "edges": EDGES,
                    "warnings": ["w"],
                    "source": "combined",
                },
                "retention": {"created_at_ms": 5},
            }
        ],
    }
    output = io.StringIO()
    bridge.convert_v1(bridge.validate(data), output)
    full = [bridge.Node.model_validate(node).model_dump(mode="json") for node in NODES]
    expected = v2_lines(METADATA, [(ENTRY, full, EDGES)])
    assert [json.loads(line) for line in output.getvalue().splitlines()] == [
        json.loads(line) for line in expected
    ]
    assert bridge.read_stream(output.getvalue().splitlines()) == METADATA


def test_logical_graph_equality_does_not_depend_on_cypher_row_order():
    nodes = [
        {"id": "b", "type": "ServiceAccount", "name": "Identity"},
        {"id": "a", "type": "S3Bucket", "name": "Asset"},
    ]
    edges = [
        {"source": "b", "target": "a", "type": "CAN_READ"},
        {"source": "b", "target": "a", "type": "CAN_WRITE"},
    ]
    first = bridge.GraphSnapshot.model_validate({"nodes": nodes, "edges": edges})
    second = bridge.GraphSnapshot.model_validate(
        {"nodes": list(reversed(nodes)), "edges": list(reversed(edges))}
    )
    assert bridge.canonical_graph(first) == bridge.canonical_graph(second)
    assert first.nodes[0].id == "b"  # Canonicalization must not mutate a caller's snapshot.


@pytest.mark.parametrize("retention", [{}, {"created_at_ms": 123456789}])
def test_import_preserves_legacy_missing_and_new_retention_timestamp(monkeypatch, retention):
    monkeypatch.setattr(bridge, "runtime", lambda: {"app_version": "0.1.0", "schema_head": "0002"})
    # A version 1 single-document archive still validates and imports.
    data = {
        "metadata": {
            "app_version": "0.1.0",
            "schema_head": "0002",
            "schema_revision": "0002",
            "revision_links": [{"tenant": "demo", "revision": "one"}],
        },
        "snapshots": [
            {"tenant": "demo", "revision": "one", "graph": {"nodes": [], "edges": []}, "retention": retention}
        ],
    }
    monkeypatch.setattr(bridge.sys, "stdin", io.StringIO(json.dumps(data)))
    graph = MagicMock()
    session = graph.driver.session.return_value.__enter__.return_value
    session.run.return_value.single.return_value = {"count": 0}
    monkeypatch.setattr(bridge, "get_graph_store", lambda: graph)
    assert bridge.execute("import") == {"snapshots": 1}
    query = session.run.call_args.args[0]
    if retention:
        assert "SET s.created_at_ms=$created" in query
        assert session.run.call_args.kwargs["created"] == 123456789
    else:
        assert "REMOVE s.created_at_ms" in query


def test_backup_metadata_counts_cluster_and_analysis_rows(environment, monkeypatch):
    """Cluster rows live in PostgreSQL, so the (unfiltered) pg_dump carries them with
    their revisions; the bridge metadata counts them so a change during backup is caught."""
    from app.graph.clusters import backfill

    factory, _ = environment
    monkeypatch.setattr(bridge, "session_factory", lambda: factory)
    monkeypatch.setattr(bridge, "runtime", lambda: {"app_version": "0.1.0", "schema_head": "0005"})
    with factory() as db:
        db.execute(bridge.text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        db.execute(bridge.text("INSERT INTO alembic_version VALUES ('0005')"))
        db.commit()
    before = bridge.metadata()["row_counts"]
    assert before["revision_cluster_summary"] == before["revision_cluster_members"] == 0
    backfill("tenant-a")
    after = bridge.metadata()["row_counts"]
    assert after["revision_cluster_summary"] == 1 and after["revision_clusters"] >= 1
    assert after["revision_cluster_members"] == 12  # Every demo entity has a leaf.
    assert {"revision_analysis", "revision_findings", "revision_cluster_links"} <= set(after)
