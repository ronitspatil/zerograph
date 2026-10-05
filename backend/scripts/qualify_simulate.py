"""Phase 3 qualification: graph-free /simulate and publish-time analysis on a real Memgraph.

Drives the production code paths end to end, each component in its own process:

* an API server (uvicorn, ``app.main:app``) receiving a chunked NDJSON upload of a
  synthetic enterprise-shaped revision (``qualify_scale.generate``);
* one ingestion worker process (``process_job``), timed per phase (analysis and
  clustering included), with its peak RSS from the kernel;
* ``POST /simulate`` latency (p50/p95, sequential, warm) over hub roles, exposed
  entry points and a seeded sample of all entities, with and without uncertain
  relationships, plus response sizes;
* golden parity: every measured response must equal the in-process reference
  engine (``calculate``) over the same published revision, loaded once here;
* the former request path on the same revision for comparison: the whole-snapshot
  load plus ``calculate`` that the route used to do, and the former Memgraph
  ``*BFS`` path query.

App state lives in a disposable schema of ``--database-url`` (Alembic head), removed
afterwards. ``--graph-uri`` must be an empty, disposable Memgraph; it is cleared at
the end. No cloud services are used.
"""

import argparse
import json
import os
import platform
import random
import secrets
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND / "scripts"))

# The former route's Memgraph path query (repository.shortest_paths before Phase 3).
LEGACY_BFS = (
    "MATCH p=(s:Entity {tenant_id:$tenant, revision:$revision, id:$source})"
    "-[r:ASSUMES_ROLE|INHERITS_PERMISSIONS|INVOKES_TOOL|CAN_READ|CAN_WRITE *BFS 1..5 (e,n | "
    "n.tenant_id=$tenant AND n.revision=$revision AND "
    "($uncertain OR e.certainty='confirmed'))]->(t:Entity) "
    "RETURN t.id AS target, [n IN nodes(p) | n.id] AS path"
)
P95_BUDGET_MS = 1000
PUBLISH_BUDGET_S = 60
RSS_BUDGET_MB = 1024


def choose_sources(snapshot, count: int, seed: int = 5) -> dict[str, str]:
    """Source -> kind: highest out-degree entities, exposed entry points (up to 10), a seeded sample."""
    degree: dict[str, int] = {}
    for edge in snapshot.edges:
        degree[edge.source] = degree.get(edge.source, 0) + 1
    hubs = sorted(degree, key=lambda node: (-degree[node], node))[:10]
    entries = [n.id for n in snapshot.nodes if n.internet_exposed and not n.authenticated][:10]
    rest = random.Random(seed).sample([n.id for n in snapshot.nodes], count)
    chosen = {node: "sample" for node in rest}
    chosen.update({node: "entry" for node in entries})
    chosen.update({node: "hub" for node in hubs})
    return chosen


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--database-url", required=True, help="Disposable PostgreSQL (a schema is created)")
    parser.add_argument("--graph-uri", required=True, help="Empty disposable Memgraph bolt URI")
    parser.add_argument("--size", type=int, default=100_000)
    parser.add_argument("--sources", type=int, default=100, help="Random sources besides hubs/entries")
    parser.add_argument("--legacy", type=int, default=3, help="Sources timed on the former path")
    parser.add_argument("--chunk-bytes", type=int, default=3_900_000)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 100 <= args.size <= 1_000_000:
        parser.error("Size 100..1000000 is required")

    from alembic import command
    from alembic.config import Config
    from qualify_clusters import WORKER, percentiles, upload
    from qualify_publication import clear_graph, free_port, graph_is_empty, rss_bytes, run_measured
    from qualify_scale import FIXTURE, generate
    from sqlalchemy import create_engine, text

    if not graph_is_empty(args.graph_uri):
        parser.error(f"Graph at {args.graph_uri} is not empty; use a disposable instance")
    schema = "zg_simulate_" + uuid4().hex
    admin = create_engine(args.database_url)
    with admin.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    scoped = admin.url.update_query_dict({"options": f"-csearch_path={schema}"}).render_as_string(
        hide_password=False
    )
    token = secrets.token_urlsafe(48)
    env = {
        **os.environ,
        "ZG_ENVIRONMENT": "test",
        "ZG_DEMO_MODE": "true",
        "ZG_DEMO_TOKEN": token,
        "ZG_DATABASE_URL": scoped,
        "ZG_GRAPH_VENDOR": "memgraph",
        "ZG_GRAPH_URI": args.graph_uri,
        "ZG_REDIS_URL": "redis://127.0.0.1:1/0",
        "PYTHONPATH": str(BACKEND),
    }
    os.environ.update({key: env[key] for key in env if key.startswith("ZG_")})
    report: dict = {
        "measured_at": datetime.now(UTC).isoformat(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "graph": "memgraph/memgraph:3.2.0 (Docker via colima)",
        "app_database": "postgresql",
        "fixture": FIXTURE,
        "size": args.size,
    }
    api = None
    log = tempfile.NamedTemporaryFile(prefix="zg-qualify-api-", suffix=".log", delete=False)
    try:
        from app.core.config import get_settings

        get_settings.cache_clear()
        config = Config()
        config.set_main_option("script_location", str(BACKEND / "app" / "db" / "migrations"))
        command.upgrade(config, "head")
        from app.engine.analysis_index import AnalysisIndex
        from app.engine.blast_radius import calculate
        from app.graph.repository import get_graph_store

        get_graph_store.cache_clear()
        store = get_graph_store()
        store.migrate()
        port = free_port()
        api = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
            env=env,
            cwd=BACKEND,
            stdout=log,
            stderr=log,
        )
        base = f"http://127.0.0.1:{port}"
        import httpx

        for _ in range(100):
            try:
                if httpx.get(f"{base}/health/live", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.2)
        client = httpx.Client(base_url=base, headers={"Authorization": f"Bearer {token}"}, timeout=120)

        generated = generate(args.size, seed=7)
        job_id = upload(client, generated, args.chunk_bytes)
        worker = run_measured([sys.executable, "-c", WORKER, job_id], env)
        measured = json.loads(worker["stdout"].decode().strip().splitlines()[-1])
        phases = measured["phases"]
        clustering = sum(
            phases.get(k, 0.0) for k in ("clusters_load_previous", "clusters_compute", "clusters_store")
        )
        analysis = phases.get("analyze", 0.0)
        report["publish"] = {
            "nodes": len(generated.nodes),
            "edges": len(generated.edges),
            "seconds": round(measured["seconds"], 2),
            "analysis_seconds": round(analysis, 2),
            "clustering_seconds": round(clustering, 2),
            "analysis_plus_clustering_seconds": round(analysis + clustering, 2),
            "worker_peak_rss_mb": round(rss_bytes(measured["maxrss"]) / 2**20, 1),
            "phases_s": phases,
        }
        job = client.get(f"/api/v1/ingestions/{job_id}").json()
        assert job["status"] == "completed", job
        revision = client.get("/api/v1/overview").json()["revision"]
        report["revision"] = revision
        print(json.dumps(report["publish"]), flush=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")

        # Reference: the published revision (classification nodes/edges included), loaded once.
        started = time.perf_counter()
        snapshot = store.snapshot("demo", revision)
        load_seconds = time.perf_counter() - started
        indexes = {flag: AnalysisIndex.build(snapshot, flag) for flag in (False, True)}
        sources = choose_sources(generated, args.sources)
        del generated

        # Warm-up, then one sequential request per (source, certainty mode).
        for source in list(sources)[:5]:
            client.post("/api/v1/simulate", json={"node_id": source, "revision": revision})
        samples, sizes, reached, mismatches = [], [], [], []
        by_kind: dict[str, list[float]] = {"hub": [], "entry": [], "sample": []}
        for source, kind in sources.items():
            for uncertain in (False, True):
                body = {
                    "node_id": source,
                    "max_hops": 5,
                    "include_uncertain": uncertain,
                    "revision": revision,
                }
                started = time.perf_counter()
                response = client.post("/api/v1/simulate", json=body)
                elapsed = time.perf_counter() - started
                assert response.status_code == 200, (source, response.status_code, response.text[:300])
                samples.append(elapsed)
                by_kind[kind].append(elapsed)
                sizes.append(len(response.content))
                result = response.json()
                reached.append(len(result["affected_nodes"]))
                expected = calculate(snapshot, source, 5, uncertain, index=indexes[uncertain]).model_dump(
                    mode="json"
                )
                if result != expected or list(result["paths"]) != list(expected["paths"]):
                    mismatches.append({"source": source, "include_uncertain": uncertain})
        report["simulate"] = {
            **percentiles(samples),
            "by_source_kind": {kind: percentiles(values) for kind, values in by_kind.items()},
            "sources": len(sources),
            "max_affected_nodes": max(reached),
            "median_affected_nodes": sorted(reached)[len(reached) // 2],
            "max_response_bytes": max(sizes),
            "parity_checked": len(samples),
            "parity_mismatches": mismatches,
        }
        print(json.dumps(report["simulate"]), flush=True)

        # The former request path on the same revision: whole-snapshot load + calculate.
        legacy, bfs = [], []
        hubs = [source for source, kind in sources.items() if kind == "hub"][: args.legacy]
        for source in hubs:
            started = time.perf_counter()
            loaded = store.snapshot("demo", revision)
            calculate(loaded, source, 5, False)
            legacy.append(time.perf_counter() - started)
            del loaded
            with store.driver.session() as session:
                started = time.perf_counter()
                list(
                    session.run(LEGACY_BFS, tenant="demo", revision=revision, source=source, uncertain=False)
                )
                bfs.append(time.perf_counter() - started)
        report["former_path"] = {
            "snapshot_load_plus_calculate": percentiles(legacy),
            "memgraph_bfs_path_query_only": percentiles(bfs),
            "reference_snapshot_load_seconds": round(load_seconds, 2),
            "sources": hubs,
        }
        print(json.dumps(report["former_path"]), flush=True)

        publish = report["publish"]
        report["checks"] = {
            "simulate_p95_under_1s": report["simulate"]["p95_ms"] < P95_BUDGET_MS,
            "golden_parity": not mismatches,
            "analysis_plus_clustering_under_60s": publish["analysis_plus_clustering_seconds"]
            < PUBLISH_BUDGET_S,
            "worker_rss_under_1gb": publish["worker_peak_rss_mb"] < RSS_BUDGET_MB,
        }
        report["passed"] = all(report["checks"].values())
    finally:
        if api is not None:
            api.terminate()
            _, _, usage = os.wait4(api.pid, 0)
            report["api_peak_rss_mb"] = round(rss_bytes(usage.ru_maxrss) / 2**20, 1)
        log.close()
        os.unlink(log.name)
        clear_graph(args.graph_uri)
        with admin.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report.get("checks", {})), flush=True)
    if not report.get("passed"):
        sys.exit(1)


if __name__ == "__main__":
    main()
