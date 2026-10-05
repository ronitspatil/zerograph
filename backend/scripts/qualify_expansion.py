"""Phase 5 in-place expansion qualification on a real Memgraph and PostgreSQL.

Publishes one revision through the production worker path (``process_job``: graph
publication, analysis and clusters) made of a synthetic enterprise-shaped graph plus
three disjoint render-benchmark components (``bench500`` 500 nodes / 2,000 edges,
``bench1k`` 1,000 / 4,000, ``bench5k`` 5,000 / 20,000), then times
``GET /graph/clusters/{id}/members`` (the console's in-place expansion) in process:

* each benchmark component alone (whole cluster, all relationships);
* progressive expansion: the largest enterprise clusters that fit the 5,000-member
  budget, each request naming the clusters already expanded, so relationships
  between expanded clusters arrive with the later one;
* the budget refusal (422) for a cluster beyond it.

Counts are checked against the published snapshot. App state lives in a disposable
schema of ``--database-url`` (Alembic head), removed afterwards. ``--graph-uri`` must
be an empty, disposable Memgraph; it is cleared at the end. No cloud services.
"""

import argparse
import json
import os
import platform
import random
import secrets
import statistics
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(BACKEND / "scripts"))

BENCH = (("bench500", 500, 2000), ("bench1k", 1000, 4000), ("bench5k", 5000, 20000))


def component(prefix: str, n: int, m: int, rng: random.Random):
    """A connected random component: a spanning tree plus random pairs, ``m`` edges."""
    from app.graph.schema import Edge, EdgeType, Node, NodeType

    kinds = [NodeType.SERVICE, NodeType.ROLE, NodeType.BUCKET, NodeType.DATABASE, NodeType.AGENT]
    nodes = [
        Node(id=f"{prefix}:{i:05d}", name=f"{prefix} {i}", type=kinds[i % 5], account_id="200000000000")
        for i in range(n)
    ]
    edges = {}
    for i in range(1, n):
        edge = Edge(source=nodes[i].id, target=nodes[rng.randrange(i)].id, type=EdgeType.ASSUMES)
        edges[edge.id] = edge
    while len(edges) < m:
        a, b = rng.randrange(n), rng.randrange(n)
        if a != b:
            edge = Edge(source=nodes[a].id, target=nodes[b].id, type=EdgeType.ASSUMES)
            edges.setdefault(edge.id, edge)
    return nodes, list(edges.values())


def percentiles(samples: list[float]) -> dict:
    ordered = sorted(samples)
    return {
        "p50_ms": round(statistics.median(ordered) * 1000, 1),
        "p95_ms": round(ordered[max(0, int(len(ordered) * 0.95 + 0.999) - 1)] * 1000, 1),
        "max_ms": round(ordered[-1] * 1000, 1),
        "samples": len(ordered),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--database-url", required=True, help="Disposable PostgreSQL (a schema is created)")
    parser.add_argument("--graph-uri", required=True, help="Empty disposable Memgraph bolt URI")
    parser.add_argument("--size", type=int, default=93_500, help="Enterprise-shaped part (bench adds 6,500)")
    parser.add_argument("--repeats", type=int, default=7)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    from qualify_publication import clear_graph, graph_is_empty
    from qualify_scale import FIXTURE, generate
    from sqlalchemy import create_engine, text

    if not graph_is_empty(args.graph_uri):
        parser.error(f"Graph at {args.graph_uri} is not empty; use a disposable instance")
    schema = "zg_expansion_" + uuid.uuid4().hex
    admin = create_engine(args.database_url)
    with admin.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    scoped = admin.url.update_query_dict({"options": f"-csearch_path={schema}"}).render_as_string(
        hide_password=False
    )
    os.environ.update(
        {
            "ZG_ENVIRONMENT": "test",
            "ZG_DEMO_MODE": "true",
            "ZG_DEMO_TOKEN": secrets.token_urlsafe(48),
            "ZG_DATABASE_URL": scoped,
            "ZG_GRAPH_VENDOR": "memgraph",
            "ZG_GRAPH_URI": args.graph_uri,
            "ZG_REDIS_URL": "redis://127.0.0.1:1/0",
        }
    )
    report: dict = {
        "measured_at": datetime.now(UTC).isoformat(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "graph": "memgraph/memgraph:3.2.0 (Docker via colima)",
        "app_database": "postgresql",
        "fixture": FIXTURE
        + f" ({args.size:,} nodes) plus disjoint components "
        + ", ".join(f"{p} {n:,}/{m:,}" for p, n, m in BENCH),
        "checks": {},
    }
    try:
        from alembic import command
        from alembic.config import Config
        from fastapi.testclient import TestClient
        from loguru import logger

        from app.collectors.tasks import process_job
        from app.core.auth import Actor, current_actor
        from app.core.config import get_settings
        from app.db.models import IngestionJob, TenantState
        from app.db.session import session_factory
        from app.graph.repository import get_graph_store
        from app.graph.schema import GraphSnapshot
        from app.main import create_app

        logger.remove()
        get_settings.cache_clear()
        config = Config()
        config.set_main_option("script_location", str(BACKEND / "app" / "db" / "migrations"))
        command.upgrade(config, "head")
        session_factory.cache_clear()
        get_graph_store.cache_clear()
        get_graph_store().migrate()

        base = generate(args.size)
        rng = random.Random(5)
        nodes, edges = list(base.nodes), list(base.edges)
        for prefix, n, m in BENCH:
            extra_nodes, extra_edges = component(prefix, n, m, rng)
            nodes += extra_nodes
            edges += extra_edges
        snapshot = GraphSnapshot(nodes=nodes, edges=edges)
        report["nodes"], report["edges"] = len(nodes), len(edges)
        factory = session_factory()
        job = str(uuid.uuid4())
        with factory() as db:
            db.add(TenantState(tenant_id="tenant-q"))
            db.add(
                IngestionJob(
                    id=job,
                    tenant_id="tenant-q",
                    actor="qualify",
                    source="snapshot",
                    payload=snapshot.model_dump(mode="json"),
                )
            )
            db.commit()
        started = time.perf_counter()
        process_job(job)
        report["publish_seconds"] = round(time.perf_counter() - started, 1)
        with factory() as db:
            status = db.get(IngestionJob, job).status
        assert status == "completed", status

        app = create_app()
        app.dependency_overrides[current_actor] = lambda: Actor("q", "tenant-q", frozenset({"viewer"}))
        client = TestClient(app)
        top = client.get("/api/v1/graph/clusters").json()
        revision = top["revision"]
        clusters = top["clusters"]
        by_prefix = {p: next(c for c in clusters if c["label"].startswith(p + " ")) for p, _, _ in BENCH}
        node_ids = {p: {node.id for node in nodes if node.id.startswith(p + ":")} for p, _, _ in BENCH}

        def members(cluster_id: str, expanded: list[str]) -> tuple[float, dict]:
            t = time.perf_counter()
            response = client.get(
                f"/api/v1/graph/clusters/{cluster_id}/members",
                params={"revision": revision, "expanded": expanded},
            )
            return time.perf_counter() - t, response

        # Each benchmark component alone.
        for prefix, n, m in BENCH:
            cluster = by_prefix[prefix]
            samples = []
            for _ in range(args.repeats):
                elapsed, response = members(cluster["id"], [])
                assert response.status_code == 200, response.text[:300]
                samples.append(elapsed)
            body = response.json()
            ok = (
                {node["id"] for node in body["nodes"]} == node_ids[prefix]
                and len(body["edges"]) == m
                and not body["view"]["truncated"]
            )
            report["checks"][f"{prefix} whole cluster: {n:,} members, {m:,} relationships"] = ok
            report[prefix] = {
                "cluster": cluster["label"],
                "members": len(body["nodes"]),
                "edges": len(body["edges"]),
                "bytes": len(response.content),
                **percentiles(samples),
            }

        # Progressive expansion of the largest enterprise clusters within the budget.
        budget, expanded, steps, shown = 5000, [], [], set()
        candidates = sorted(
            (c for c in clusters if not c["label"].startswith("bench") and c["size"] <= budget),
            key=lambda c: -c["size"],
        )
        for cluster in candidates:
            if sum(s["size"] for s in steps) + cluster["size"] > budget:
                continue
            elapsed, response = members(cluster["id"], expanded)
            assert response.status_code == 200, response.text[:300]
            body = response.json()
            ids = {node["id"] for node in body["nodes"]}
            cross = sum(1 for e in body["edges"] if not ({e["source"], e["target"]} <= ids))
            steps.append(
                {
                    "cluster": cluster["label"],
                    "size": cluster["size"],
                    "already_shown": len(shown),
                    "edges": len(body["edges"]),
                    "edges_to_shown": cross,
                    "ms": round(elapsed * 1000, 1),
                }
            )
            shown |= ids
            expanded.append(cluster["id"])
            if len(steps) >= 12:
                break
        internal = sum(1 for e in edges if e.source in shown and e.target in shown)
        delivered = sum(s["edges"] for s in steps)
        report["progressive"] = {
            "members": len(shown),
            "relationships_delivered": delivered,
            "relationships_among_shown": internal,
            "steps": steps,
            **percentiles([s["ms"] / 1000 for s in steps]),
        }
        report["checks"]["progressive expansion delivers every relationship among shown members once"] = (
            delivered == internal
        )
        over = next(c for c in clusters if c["size"] > budget)
        _, response = members(over["id"], [])
        report["checks"]["a cluster beyond the 5,000 budget is refused with 422"] = (
            response.status_code == 422
        )
        _, response = members(by_prefix["bench500"]["id"], [by_prefix["bench5k"]["id"]])
        report["checks"]["5,000 shown plus another cluster is refused with 422"] = response.status_code == 422
        report["passed"] = all(report["checks"].values())
    finally:
        clear_graph(args.graph_uri)
        with admin.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "progressive"}, indent=2))
    print(json.dumps({k: v for k, v in report["progressive"].items() if k != "steps"}, indent=2))
    sys.exit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
