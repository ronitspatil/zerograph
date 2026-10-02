"""Run against a real graph database in CI, or set ZG_INTEGRATION_GRAPH locally."""

import os
import time
from uuid import uuid4

import pytest

from app.core.config import get_settings
from app.graph.demo import demo_snapshot
from app.graph.repository import CypherGraphStore


@pytest.mark.skipif(not os.getenv("ZG_INTEGRATION_GRAPH"), reason="No real graph database configured")
def test_real_graph_roundtrip_and_tenant_isolation(monkeypatch):
    monkeypatch.setenv("ZG_GRAPH_VENDOR", os.environ["ZG_INTEGRATION_GRAPH"])
    get_settings.cache_clear()
    store = CypherGraphStore()
    for attempt in range(45):
        try:
            store.driver.verify_connectivity()
            break
        except Exception:
            if attempt == 44:
                raise
            time.sleep(1)
    store.migrate()
    store.migrate()
    tenant = "integration-" + str(uuid4())
    revision = str(uuid4())
    try:
        store.publish(tenant, revision, demo_snapshot())
        snapshot = store.snapshot(tenant, revision)
        assert len(snapshot.nodes) == 12
        assert len(store.snapshot("other-tenant", revision).nodes) == 0
        paths = store.shortest_paths(tenant, revision, "agent:support", 5, False)
        assert paths["db:customers"] == ["agent:support", "mcp:crm", "role:admin", "db:customers"]
    finally:
        with store.driver.session() as session:
            session.run("MATCH (n {tenant_id:$tenant}) DETACH DELETE n", tenant=tenant).consume()
        store.close()
        get_settings.cache_clear()
