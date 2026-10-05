"""Scale qualification for publish-time revision analysis; no cloud or network services are used.

For each size, a synthetic enterprise-shaped graph is published through the real
ingestion job (``process_job``) into the in-memory graph adapter, with app state in
temporary SQLite (or a disposable schema of ``--database-url`` PostgreSQL). It records:

* publish time with publish-time analysis, the analysis share of it, and a baseline
  publish of the same graph with analysis disabled;
* ``GET /overview`` and the first ``GET /findings`` page (default limit 200) through
  the in-process ASGI app, warm, as p50/p95/max over ``--requests`` sequential calls;
* the legacy compute-on-read cost of the same two endpoints, for comparison.

Caps are the Settings defaults (100,000 nodes / 500,000 edges), so no cap lifting is
needed. The HTTP ingestion body limit is bypassed by queuing the job row directly.
Memgraph publication at 100k is measured by ``qualify_publication.py``.
"""

import argparse
import json
import os
import platform
import random
import statistics
import tempfile
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

os.environ.update(ZG_ENVIRONMENT="test", ZG_GRAPH_VENDOR="memory")

from loguru import logger  # noqa: E402

from app.graph.schema import Edge, EdgeType, GraphSnapshot, Node, NodeType, Sensitivity  # noqa: E402

MIX = [
    (NodeType.HUMAN, 0.08),
    (NodeType.SERVICE, 0.25),
    (NodeType.AGENT, 0.05),
    (NodeType.MCP, 0.02),
    (NodeType.ROLE, 0.15),
    (NodeType.DATABASE, 0.15),
    (NodeType.BUCKET, 0.20),
    (NodeType.VECTOR, 0.10),
]
SENSITIVITIES = [Sensitivity.PUBLIC, Sensitivity.INTERNAL, Sensitivity.CONFIDENTIAL, Sensitivity.RESTRICTED]
FIXTURE = (
    "Per N nodes: 8% human, 25% service account, 5% agent, 2% MCP, 15% role, 45% data; ~4 edges/node; "
    "Zipf role popularity and data fan-out with 3 admin hub roles; --exposed-rate (default 0.2%) of agents/MCPs "
    "exposed and unauthenticated (seeded, deterministic)."
)
LIMITATIONS = (
    "In-process ASGI calls with the memory graph adapter; excludes network/TLS, the Next.js proxy, "
    "Memgraph/Neo4j publish cost, multi-worker concurrency and fleet load. Single publish runs per size."
)


def zipf_pick(rng: random.Random, n: int, s: float = 1.1) -> int:
    return min(n - 1, int(n ** (rng.random() ** s) - 1))


def generate(n: int, seed: int = 7, exposed_rate: float = 0.002) -> GraphSnapshot:
    """Synthetic enterprise-shaped identity graph (from the scale-plan benchmark generator)."""
    rng = random.Random(seed)
    nodes, by_type = [], {}
    for kind, share in MIX:
        ids = []
        for i in range(max(3, int(n * share))):
            node_id = f"{kind.value.lower()}:{i:07d}"
            data = kind in (NodeType.DATABASE, NodeType.BUCKET, NodeType.VECTOR)
            exposed = kind in (NodeType.AGENT, NodeType.MCP) and rng.random() < exposed_rate
            nodes.append(
                Node(
                    id=node_id,
                    type=kind,
                    name=f"{kind.value} {i}",
                    account_id=f"{100000000000 + rng.randrange(max(2, n // 2000)):012d}",
                    provider="aws",
                    sensitivity=rng.choices(SENSITIVITIES, [2, 5, 2, 1])[0] if data else Sensitivity.INTERNAL,
                    tags=["PII"] if data and rng.random() < 0.1 else [],
                    internet_exposed=exposed,
                    authenticated=not exposed,
                    privileged=kind == NodeType.ROLE and rng.random() < 0.05,
                )
            )
            ids.append(node_id)
        by_type[kind] = ids
    roles = by_type[NodeType.ROLE]
    data = by_type[NodeType.DATABASE] + by_type[NodeType.BUCKET] + by_type[NodeType.VECTOR]
    rng.shuffle(data)
    edges: dict[str, Edge] = {}

    def add(source, target, kind, actions=(), certainty="confirmed"):
        edge = Edge(
            source=source,
            target=target,
            type=kind,
            actions=list(actions),
            certainty=certainty,
            evidence=[f"policy:{source}"],
        )
        edges.setdefault(edge.id, edge)

    hubs = roles[:3]
    for identity in by_type[NodeType.HUMAN] + by_type[NodeType.SERVICE] + by_type[NodeType.AGENT]:
        for _ in range(1 + (rng.random() < 0.6) + (rng.random() < 0.4)):
            add(identity, roles[zipf_pick(rng, len(roles))], EdgeType.ASSUMES, ["sts:AssumeRole"])
        if rng.random() < 0.05:
            add(identity, rng.choice(hubs), EdgeType.ASSUMES, ["sts:AssumeRole"])
    mcp = by_type[NodeType.MCP]
    for agent in by_type[NodeType.AGENT]:
        for _ in range(2):
            add(agent, mcp[zipf_pick(rng, len(mcp))], EdgeType.INVOKES, ["tools/call"], "declared")
    for server in mcp:
        add(server, roles[zipf_pick(rng, len(roles))], EdgeType.ASSUMES, ["sts:AssumeRole"], "conditional")
    for i, role in enumerate(roles):
        fan = max(1, len(data) // 10) if i < 3 else 1 + zipf_pick(rng, 110, 1.0)
        for _ in range(fan):
            target = data[zipf_pick(rng, len(data), 1.02)] if i >= 3 else rng.choice(data)
            if rng.random() < 0.7:
                add(role, target, EdgeType.READ, ["s3:GetObject", "s3:ListBucket"])
            else:
                add(role, target, EdgeType.WRITE, ["s3:PutObject"])
        if rng.random() < 0.3:
            add(role, roles[zipf_pick(rng, len(roles))], EdgeType.INHERITS, ["iam:PassRole"])
    return GraphSnapshot.model_construct(
        nodes=nodes, edges=list(edges.values()), warnings=[], source="snapshot"
    )


@contextmanager
def app_database(url: str | None):
    """Yield a SQLAlchemy URL for disposable app state, removed afterwards."""
    from sqlalchemy import create_engine, text

    if not url:
        with tempfile.TemporaryDirectory(prefix="zerograph-scale-") as directory:
            yield f"sqlite:///{directory}/state.db"
        return
    name = "zg_scale_" + uuid4().hex
    admin = create_engine(url)
    with admin.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{name}"'))
    try:
        scoped = create_engine(url).url.update_query_dict({"options": f"-csearch_path={name}"})
        yield scoped.render_as_string(hide_password=False)
    finally:
        with admin.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{name}" CASCADE'))
        admin.dispose()


def percentiles(samples: list[float]) -> dict:
    ordered = sorted(samples)
    p95 = ordered[max(0, int(len(ordered) * 0.95 + 0.999) - 1)]
    return {
        "p50_ms": round(statistics.median(ordered) * 1000, 3),
        "p95_ms": round(p95 * 1000, 3),
        "max_ms": round(ordered[-1] * 1000, 3),
        "samples": len(ordered),
    }


def timed_requests(client, path: str, requests: int, warmup: int = 3) -> tuple[dict, object]:
    for _ in range(warmup):
        assert client.get(path).status_code == 200
    samples, response = [], None
    for _ in range(requests):
        started = time.perf_counter()
        response = client.get(path)
        samples.append(time.perf_counter() - started)
        assert response.status_code == 200, response.text
    return percentiles(samples), response


def qualify(
    size: int, requests: int, publish_runs: int, database_url: str | None, exposed_rate: float
) -> dict:
    from fastapi.testclient import TestClient

    from app.collectors import tasks
    from app.core.auth import Actor, current_actor
    from app.core.config import get_settings
    from app.db.models import Base, IngestionJob, TenantState
    from app.db.session import session_factory
    from app.graph.compact import CompactGraph
    from app.graph.repository import get_graph_store
    from app.main import create_app

    snapshot = generate(size, exposed_rate=exposed_rate)
    payload = snapshot.model_dump(mode="json")
    result = {"target_nodes": size, "nodes": len(snapshot.nodes), "edges": len(snapshot.edges)}
    with app_database(database_url) as url:
        os.environ["ZG_DATABASE_URL"] = url
        get_settings.cache_clear()
        session_factory.cache_clear()
        get_graph_store.cache_clear()
        factory = session_factory()
        Base.metadata.create_all(factory.kw["bind"])

        def publish(tenant: str) -> float:
            job_id = str(uuid4())
            with factory() as db:
                db.add(TenantState(tenant_id=tenant))
                db.add(
                    IngestionJob(
                        id=job_id, tenant_id=tenant, actor="qualify", source="snapshot", payload=payload
                    )
                )
                db.commit()
            started = time.perf_counter()
            tasks.process_job(job_id)
            elapsed = time.perf_counter() - started
            with factory() as db:
                job = db.get(IngestionJob, job_id)
                assert job.status == "completed", job.status
                result.setdefault("published_nodes", job.node_count)
            return elapsed

        def measured(spent, name, function):
            def wrapper(*args):
                started = time.perf_counter()
                try:
                    return function(*args)
                finally:
                    spent[name] = spent.get(name, 0.0) + time.perf_counter() - started

            return wrapper

        # Alternate a baseline publish of the same graph with publish-time analysis
        # disabled (a legacy-style revision readers compute on read) and a normal
        # publish; each run uses a fresh tenant, and the fastest run of each counts.
        # Publish-time clustering (Phase 4) runs in both arms; its measured time is
        # subtracted so the comparison isolates the analysis cost, and reported.
        runs = {"without": [], "with": [], "analysis": [], "clustering": []}

        def clustered(tenant: str) -> float:
            spent: dict[str, float] = {}
            with (
                patch.object(tasks, "compute_clusters", measured(spent, "compute", tasks.compute_clusters)),
                patch.object(tasks, "store_clusters", measured(spent, "store", tasks.store_clusters)),
                patch.object(tasks, "load_previous", measured(spent, "load", tasks.load_previous)),
            ):
                elapsed = publish(tenant)
            runs["clustering"].append(sum(spent.values()))
            return elapsed - sum(spent.values())

        for run in range(publish_runs):
            with (
                patch.object(CompactGraph, "analyze", lambda self: None),
                patch.object(tasks, "store_analysis", lambda *args: None),
            ):
                runs["without"].append(clustered(f"legacy-{run}"))
            spent: dict[str, float] = {}
            with (
                patch.object(CompactGraph, "analyze", measured(spent, "compute", CompactGraph.analyze)),
                patch.object(tasks, "store_analysis", measured(spent, "store", tasks.store_analysis)),
            ):
                runs["with"].append(clustered(f"stored-{run}"))
            runs["analysis"].append(spent)
        baseline, with_analysis = min(runs["without"]), min(runs["with"])
        analysis_seconds = min(sum(spent.values()) for spent in runs["analysis"])
        result["publish"] = {
            "with_analysis_s": round(with_analysis, 4),
            "without_analysis_s": round(baseline, 4),
            "delta_s": round(with_analysis - baseline, 4),
            "analysis_s": round(analysis_seconds, 4),
            "analysis_compute_s": round(min(spent["compute"] for spent in runs["analysis"]), 4),
            "analysis_store_s": round(min(spent["store"] for spent in runs["analysis"]), 4),
            # Excluded from the publish times above (it runs in both arms).
            "clustering_s": round(min(runs["clustering"]), 4),
            "runs": {
                "with_analysis_s": [round(value, 4) for value in runs["with"]],
                "without_analysis_s": [round(value, 4) for value in runs["without"]],
            },
        }
        stored_tenant, legacy_tenant = f"stored-{publish_runs - 1}", f"legacy-{publish_runs - 1}"

        def client_for(tenant: str) -> TestClient:
            app = create_app()
            app.dependency_overrides[current_actor] = lambda: Actor("qualify", tenant, frozenset({"viewer"}))
            return TestClient(app)

        with client_for(stored_tenant) as client:
            result["overview"], overview = timed_requests(client, "/api/v1/overview", requests)
            result["findings_first_page"], page = timed_requests(client, "/api/v1/findings", requests)
            result["findings_total"] = int(page.headers["x-total-count"])
            result["findings_first_page_count"] = len(page.json())
            result["findings_first_page_bytes"] = len(page.content)
            result["explore_sample"], _ = timed_requests(client, "/api/v1/graph/explore", requests)
            result["roles_page"], _ = timed_requests(client, "/api/v1/graph/roles", requests)
            stored_overview = overview.json()
        with client_for(legacy_tenant) as client:
            legacy_requests = 3
            result["legacy_overview_compute_on_read"], legacy = timed_requests(
                client, "/api/v1/overview", legacy_requests, warmup=0
            )
            result["legacy_findings_compute_on_read"], _ = timed_requests(
                client, "/api/v1/findings", legacy_requests, warmup=0
            )
            legacy_overview = legacy.json()
        # Stored and computed-on-read analysis must agree (revision aside).
        stored_overview.pop("revision"), legacy_overview.pop("revision")
        result["stored_matches_compute_on_read"] = stored_overview == legacy_overview
        result["overview_counts"] = {
            key: stored_overview[key]
            for key in ("total_nhis", "toxic_combinations", "high_blast_radius", "data_assets")
        }
        factory.kw["bind"].dispose()
        session_factory.cache_clear()
        get_graph_store.cache_clear()
        get_settings.cache_clear()
    return result


def evaluate(results: list[dict], latency_budget_ms: float, ratio_budget: float) -> dict:
    checks = {}
    by_size = {r["target_nodes"]: r for r in results}
    for r in results:
        size = r["target_nodes"]
        checks[f"stored_matches_compute_on_read_{size}"] = r["stored_matches_compute_on_read"]
        # Publish grows by no more than the analysis it now performs (5% + 50 ms run-to-run tolerance).
        publish = r["publish"]
        tolerance = max(0.05, 0.05 * publish["without_analysis_s"])
        checks[f"publish_growth_within_analysis_cost_{size}"] = (
            publish["delta_s"] <= publish["analysis_s"] + tolerance
        )
        if size >= 5000:
            for endpoint in ("overview", "findings_first_page"):
                checks[f"{endpoint}_p95_under_{latency_budget_ms:g}ms_{size}"] = (
                    r[endpoint]["p95_ms"] < latency_budget_ms
                )
    small, large = min(by_size), max(by_size)
    if small != large:
        for endpoint in ("overview", "findings_first_page"):
            ratio = by_size[large][endpoint]["p95_ms"] / by_size[small][endpoint]["p95_ms"]
            checks[f"{endpoint}_p95_ratio_{large}_vs_{small}_at_most_{ratio_budget:g}x"] = (
                ratio <= ratio_budget
            )
    return checks


LATENCY_BUDGET_MS = 50
RATIO_BUDGET = 2


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--sizes", type=int, nargs="+", default=[1000, 5000, 20000])
    parser.add_argument("--requests", type=int, default=50)
    parser.add_argument("--publish-runs", type=int, default=2)
    parser.add_argument(
        "--exposed-rate",
        type=float,
        default=0.002,
        help="Share of agents/MCP servers exposed and unauthenticated (more findings per graph)",
    )
    parser.add_argument(
        "--database-url", help="Disposable PostgreSQL URL; a random schema is created and dropped"
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if (
        any(not 100 <= size <= 100_000 for size in args.sizes)
        or not 5 <= args.requests <= 1000
        or not 1 <= args.publish_runs <= 5
        or not 0 <= args.exposed_rate <= 1
    ):
        parser.error("Sizes 100..100000, requests 5..1000 and publish runs 1..5 are required")
    logger.remove()  # Per-request INFO logs would distort sub-millisecond timings.
    report = {
        "measured_at": datetime.now(UTC).isoformat(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "app_database": "postgresql" if args.database_url else "sqlite",
        "graph_adapter": "memory",
        "fixture": FIXTURE,
        "exposed_rate": args.exposed_rate,
        "limitations": LIMITATIONS,
        "budgets": {
            "p95_ms_at_5k_and_above": LATENCY_BUDGET_MS,
            "p95_ratio_largest_vs_smallest": RATIO_BUDGET,
        },
        "results": [],
    }
    for size in args.sizes:
        report["results"].append(
            qualify(size, args.requests, args.publish_runs, args.database_url, args.exposed_rate)
        )
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report["results"][-1]), flush=True)
    report["checks"] = evaluate(report["results"], LATENCY_BUDGET_MS, RATIO_BUDGET)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["checks"], indent=2))
    if not all(report["checks"].values()):
        raise SystemExit("Scale qualification budget failed; inspect the JSON report")


if __name__ == "__main__":
    main()
