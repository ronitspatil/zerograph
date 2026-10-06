"""Synthetic persistence proof executed only inside the disposable backend pod."""

import json
import os
import sys

from app.core.config import get_settings
from app.db.models import TenantState
from app.db.session import session_factory
from app.graph.repository import get_graph_store
from app.graph.schema import Edge, GraphSnapshot, Node
from redis import Redis
from sqlalchemy import select, text

TENANT = "kubernetes-synthetic"
REVISION = "kubernetes-proof-v1"


def main():
    settings = get_settings()
    assert settings.environment == "production" and not settings.demo_mode
    assert os.getuid() == 10001
    assert os.statvfs("/").f_flag & os.ST_RDONLY
    graph = get_graph_store()
    redis = Redis.from_url(settings.redis_url, socket_timeout=3)
    if sys.argv[1] == "seed":
        assert redis.get("kubernetes-qualification:proof") is None
        redis.set("kubernetes-qualification:proof", "synthetic-v1")
    assert redis.get("kubernetes-qualification:proof") == b"synthetic-v1"
    with session_factory()() as db:
        head = db.scalar(text("SELECT version_num FROM alembic_version"))
        assert head == "0006"
        if sys.argv[1] == "seed":
            assert db.get(TenantState, TENANT) is None
            snapshot = GraphSnapshot(
                nodes=[
                    Node(id="agent", type="AIAgent", name="Synthetic agent"),
                    Node(id="data", type="Database", name="Synthetic data"),
                ],
                edges=[Edge(source="agent", target="data", type="CAN_READ")],
                source="kubernetes-qualification",
            )
            graph.publish(TENANT, REVISION, snapshot)
            db.add(TenantState(tenant_id=TENANT, revision=REVISION))
            db.commit()
            with graph.driver.session() as session:
                session.run("CREATE SNAPSHOT").consume()
        state = db.execute(select(TenantState).where(TenantState.tenant_id == TENANT)).scalar_one()
        assert state.revision == REVISION
        snapshot = graph.snapshot(TENANT, state.revision)
        assert sorted(node.id for node in snapshot.nodes) == ["agent", "data"]
        assert len(snapshot.edges) == 1 and snapshot.edges[0].type == "CAN_READ"
        assert snapshot.source == "kubernetes-qualification"
        with graph.driver.session() as session:
            row = session.run(
                "MATCH (s:Snapshot {tenant_id:$tenant, revision:$revision}) RETURN s.created_at_ms AS created",
                tenant=TENANT,
                revision=REVISION,
            ).single()
            assert isinstance(row["created"], int)
    graph.close()
    redis.close()
    print(json.dumps({"migration_head": head, "revision": REVISION, "nodes": 2, "edges": 1}))


if __name__ == "__main__":
    main()
