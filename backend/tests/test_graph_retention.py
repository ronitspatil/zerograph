from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from app.graph.retention import RetentionPolicy, main, prune_revisions
from app.graph.schema import GraphSnapshot


def aged_revisions(graph, tenant="tenant-a"):
    timestamp = datetime.now(UTC)
    for index in range(8):
        revision = f"revision-{index}"
        graph.publish(tenant, revision, GraphSnapshot())
        graph.created_at[tenant, revision] = int((timestamp - timedelta(days=40 - index)).timestamp() * 1000)
    return timestamp


def test_dry_run_preserves_current_newest_and_other_tenants(environment):
    _, graph = environment
    timestamp = aged_revisions(graph)
    graph.publish("other-tenant", "other-old", GraphSnapshot())
    graph.created_at["other-tenant", "other-old"] = 0
    # Existing current revision is undated to model a legacy release.
    graph.created_at.pop(("tenant-a", "revision-a"))
    before = dict(graph.snapshots)
    result = prune_revisions("tenant-a", RetentionPolicy(30, 2, 3), timestamp=timestamp)
    assert result.dry_run
    assert result.deleted == []
    assert result.protected_revision == "revision-a"
    assert {revision.revision for revision in result.candidates} == {"revision-5", "revision-4", "revision-3"}
    assert graph.snapshots == before


def test_age_and_minimum_revision_count_are_both_required(environment):
    _, graph = environment
    timestamp = aged_revisions(graph)
    for key in graph.created_at:
        graph.created_at[key] = int(timestamp.timestamp() * 1000)
    assert prune_revisions("tenant-a", RetentionPolicy(1, 2, 10)).candidates == []
    assert graph.retention_candidates("tenant-a", "", 2**63 - 1, 1000, 10) == []


def test_current_old_revision_is_protected_even_outside_keep(environment):
    _, graph = environment
    timestamp = aged_revisions(graph)
    graph.created_at["tenant-a", "revision-a"] = 0
    result = prune_revisions("tenant-a", RetentionPolicy(30, 2, 50), timestamp=timestamp)
    assert "revision-a" not in {revision.revision for revision in result.candidates}


def test_legacy_undated_revisions_retained(environment):
    _, graph = environment
    aged_revisions(graph)
    graph.created_at.clear()
    assert prune_revisions("tenant-a").candidates == []


def test_missing_sql_state_and_sqlite_apply_fail_closed(environment):
    with pytest.raises(ValueError, match="authoritative SQL state"):
        prune_revisions("missing")
    with pytest.raises(ValueError, match="PostgreSQL"):
        prune_revisions("tenant-a", apply=True)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"older_than_days": 0},
        {"older_than_days": 3651},
        {"keep_revisions": 1},
        {"keep_revisions": 1001},
        {"batch_size": 0},
        {"batch_size": 51},
    ],
)
def test_policy_rejects_unbounded_or_unsafe_inputs(kwargs):
    with pytest.raises(ValueError):
        RetentionPolicy(**kwargs)


def test_repository_delete_rechecks_timestamp_and_age(environment):
    _, graph = environment
    graph.publish("tenant-a", "old", GraphSnapshot())
    graph.created_at["tenant-a", "old"] = 1
    assert not graph.delete_revision("other", "old", 1, 2)
    assert not graph.delete_revision("tenant-a", "old", 2, 3)
    assert not graph.delete_revision("tenant-a", "old", 1, 1)
    assert graph.delete_revision("tenant-a", "old", 1, 2)
    assert not graph.delete_revision("tenant-a", "old", 1, 2)


def test_command_defaults_to_dry_run(environment, capsys):
    with patch("sys.argv", ["retention", "--tenant", "tenant-a"]):
        main()
    assert '"dry_run": true' in capsys.readouterr().out


def test_creation_timestamp_not_changed_by_repeat_publish(environment):
    _, graph = environment
    graph.publish("tenant-a", "repeat", GraphSnapshot())
    created_at = graph.created_at["tenant-a", "repeat"]
    graph.publish("tenant-a", "repeat", GraphSnapshot())
    assert graph.created_at["tenant-a", "repeat"] == created_at


def test_snapshot_pin_preserves_non_lock_database_errors(environment):
    from sqlalchemy.exc import DBAPIError

    from app.api.routes import load_snapshot

    factory, graph = environment
    original = DBAPIError("synthetic query", {}, RuntimeError("unrelated database failure"))
    with factory() as db, patch.object(db, "execute", side_effect=original):
        with pytest.raises(DBAPIError) as raised:
            load_snapshot(db, graph, "tenant-a")
    assert raised.value is original


def test_building_revisions_young_are_never_selected_and_stale_are_cleaned(environment):
    from app.graph.retention import STALE_BUILDING_AGE

    _, graph = environment
    timestamp = aged_revisions(graph)
    now_ms = int(timestamp.timestamp() * 1000)
    graph.begin_revision("tenant-a", "young-build")
    graph.created_at["tenant-a", "young-build"] = now_ms - 60_000
    graph.begin_revision("tenant-a", "stale-build")
    stale_ms = int((timestamp - STALE_BUILDING_AGE).timestamp() * 1000) - 1
    graph.created_at["tenant-a", "stale-build"] = stale_ms
    # A young build neither becomes a candidate nor displaces kept ready revisions.
    result = prune_revisions("tenant-a", RetentionPolicy(30, 2, 50), timestamp=timestamp)
    states = {item.revision: item.state for item in result.candidates}
    assert "young-build" not in states
    assert states["stale-build"] == "building"
    assert "revision-7" not in states and "revision-6" in states
    # State-checked deletion: a building revision is not deletable as "ready", a
    # young build is not deletable at all, and an interrupted delete is resumed.
    assert not graph.delete_revision("tenant-a", "stale-build", stale_ms, now_ms, "ready")
    assert not graph.delete_revision("tenant-a", "young-build", now_ms - 60_000, stale_ms, "building")
    graph.deleting.add(("tenant-a", "revision-2"))
    resumed = graph.retention_candidates("tenant-a", "revision-a", 0, 1000, 50, None)
    assert [(item.revision, item.state) for item in resumed] == [("revision-2", "deleting")]
    assert graph.delete_revision("tenant-a", "revision-2", resumed[0].created_at_ms, now_ms, "deleting")
    assert graph.delete_revision("tenant-a", "stale-build", stale_ms, stale_ms + 1, "building")
    assert ("tenant-a", "stale-build") not in graph.building


def test_large_revisions_are_deletable(environment):
    from app.graph.schema import Node, NodeType

    _, graph = environment
    big = GraphSnapshot(nodes=[Node(id=f"n{i}", name="n", type=NodeType.BUCKET) for i in range(6000)])
    graph.publish("tenant-a", "big", big)
    graph.created_at["tenant-a", "big"] = 1
    assert graph.delete_revision("tenant-a", "big", 1, 2)
