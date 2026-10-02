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


def test_preflight_refuses_before_revision_materialization(monkeypatch):
    factory = MagicMock()
    factory.return_value.return_value.__enter__.return_value.scalar.return_value = 1
    monkeypatch.setattr(bridge, "session_factory", factory)
    graph = MagicMock()
    session = graph.driver.session.return_value.__enter__.return_value
    values = [
        {"count": 2},
        {"count": 1},
        {"count": 1},
        {"size": 25_000_000},
        {"size": 0},
        {"size": 0},
        {"size": 0},
    ]
    session.run.side_effect = [Mock(single=Mock(return_value=value)) for value in values]
    monkeypatch.setattr(bridge, "get_graph_store", lambda: graph)
    metadata = Mock()
    monkeypatch.setattr(bridge, "metadata", metadata)
    with pytest.raises(ValueError, match="supported graph bounds"):
        bridge.execute("export")
    graph.snapshot.assert_not_called()
    metadata.assert_not_called()
    assert not any("properties(s)" in call.args[0] for call in session.run.call_args_list)


@pytest.mark.parametrize("retention", [{}, {"created_at_ms": 123456789}])
def test_import_preserves_legacy_missing_and_new_retention_timestamp(monkeypatch, retention):
    monkeypatch.setattr(bridge, "runtime", lambda: {"app_version": "0.1.0", "schema_head": "0002"})
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
