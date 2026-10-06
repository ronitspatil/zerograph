"""Phase 4 global-map qualification on a real Memgraph and PostgreSQL.

Drives the production code paths end to end, each component in its own process:

* an API server (uvicorn, ``app.main:app``) receiving chunked NDJSON uploads;
* one ingestion worker process per publication (``process_job``), timed per phase
  (clustering included), with its peak RSS from the kernel;
* revision 1 is a synthetic enterprise-shaped graph; revision 2 is the same graph
  with ``--edge-change`` of its relationships replaced (half removed, as many random
  new ones added), so cluster ID stability is measured on a realistic small change;
* ``GET /graph/clusters`` and ``GET /graph/clusters/{id}`` latency (p50/p95) over
  the top level, every top-level expansion and a sample of leaves, plus structural
  bound checks over every stored cluster;
* ``/graph/explore`` latency on the new key-anchored queries against the former
  scan-based query shapes, on the same revision;
* concurrent pollers on the cluster and explore endpoints during the second
  publication (no 503s), and retention deleting revision 1's cluster rows.

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
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND / "scripts"))

WORKER = """
import json, resource, sys, time
from loguru import logger
logger.remove()
from app.collectors import publication, tasks
from app.graph import clusters
from app.graph.compact import CompactGraph
from app.graph.repository import CypherGraphStore
phases = {}
def timed(owner, name, label=None):
    original = getattr(owner, name)
    def wrapper(*args, **kwargs):
        started = time.perf_counter()
        try:
            return original(*args, **kwargs)
        finally:
            key = label or name
            phases[key] = phases.get(key, 0.0) + time.perf_counter() - started
    setattr(owner, name, wrapper)
for name in ("begin_revision", "write_nodes", "write_edges", "finish_revision"):
    timed(CypherGraphStore, name)
timed(CompactGraph, "analyze")
timed(tasks, "store_analysis")
timed(tasks, "load_previous", "clusters_load_previous")
timed(tasks, "compute_clusters", "clusters_compute")
timed(tasks, "store_clusters", "clusters_store")
timed(clusters, "build_hierarchy", "clusters_build_hierarchy")
timed(clusters, "assign_ids", "clusters_assign_ids")
timed(tasks, "compute_topics", "topics_compute")
timed(tasks, "store_topics", "topics_store")
timed(tasks, "acquire_pointer_gate")
started = time.perf_counter()
tasks.process_job(sys.argv[1])
print(json.dumps({"seconds": time.perf_counter() - started,
                  "phases": {k: round(v, 3) for k, v in phases.items()},
                  "maxrss": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}))
"""

LEGACY_EDGES = (
    "MATCH (a:Entity {tenant_id:$tenant, revision:$revision})-[r:%s {tenant_id:$tenant, revision:$revision}]->"
    "(b:Entity {tenant_id:$tenant, revision:$revision}) WHERE a.id IN $ids AND b.id IN $ids "
    "RETURN r.payload AS payload ORDER BY r.id LIMIT $limit"
)
LEGACY_SAMPLE = (
    "MATCH (n:Entity {tenant_id:$tenant, revision:$revision}) RETURN n.payload AS payload "
    "ORDER BY n.id LIMIT $limit"
)
LEGACY_NEIGHBORS = (
    "MATCH (s:Entity {key:$key, tenant_id:$tenant, revision:$revision, id:$root})"
    "-[r:%s {tenant_id:$tenant, revision:$revision}]-(n:Entity {tenant_id:$tenant, revision:$revision}) "
    "WHERE n.id <> $root WITH DISTINCT n RETURN n.payload AS payload ORDER BY n.id LIMIT $limit"
)


def percentiles(samples: list[float]) -> dict:
    if not samples:
        return {"samples": 0}
    ordered = sorted(samples)
    return {
        "p50_ms": round(statistics.median(ordered) * 1000, 2),
        "p95_ms": round(ordered[max(0, int(len(ordered) * 0.95 + 0.999) - 1)] * 1000, 2),
        "max_ms": round(ordered[-1] * 1000, 2),
        "samples": len(ordered),
    }


def perturbed(snapshot, fraction: float, seed: int = 99):
    from app.graph.schema import Edge, EdgeType

    rng = random.Random(seed)
    edges = list(snapshot.edges)
    drop = set(rng.sample(range(len(edges)), int(len(edges) * fraction / 2)))
    kept = [edge for index, edge in enumerate(edges) if index not in drop]
    ids, seen = [node.id for node in snapshot.nodes], {edge.id for edge in kept}
    while len(kept) < len(edges):
        edge = Edge(source=rng.choice(ids), target=rng.choice(ids), type=EdgeType.READ)
        if edge.id not in seen:
            seen.add(edge.id)
            kept.append(edge)
    return snapshot.model_copy(update={"edges": kept}), len(drop) * 2


def timed_get(client, path: str, params=None) -> tuple[float, object]:
    started = time.perf_counter()
    response = client.get(path, params=params)
    elapsed = time.perf_counter() - started
    assert response.status_code == 200, (path, response.status_code, response.text[:300])
    return elapsed, response.json()


def upload(client, snapshot, chunk_bytes: int) -> str:
    from qualify_publication import chunks

    created = client.post("/api/v1/ingestions/uploads", json={"source": "snapshot"})
    assert created.status_code == 201, created.text
    upload_id = created.json()["id"]
    for number, body in enumerate(chunks(snapshot, chunk_bytes)):
        response = client.put(f"/api/v1/ingestions/uploads/{upload_id}/chunks/{number}", content=body)
        assert response.status_code == 200, response.text
    committed = client.post(f"/api/v1/ingestions/uploads/{upload_id}/commit")
    assert committed.status_code == 202, committed.text
    return committed.json()["id"]


class ClusterPoller:
    """Concurrent readers on cluster and explore endpoints, counting statuses."""

    def __init__(self, base: str, token: str, threads: int):
        self.base, self.token, self.threads = base, token, threads
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.statuses: dict[str, int] = {}

    def run(self, offset: int) -> None:
        import httpx

        paths = ["/api/v1/graph/clusters", "/api/v1/graph/explore"]
        with httpx.Client(
            base_url=self.base, headers={"Authorization": f"Bearer {self.token}"}, timeout=60
        ) as client:
            index = offset
            while not self.stop.is_set():
                path = paths[index % len(paths)]
                index += 1
                try:
                    status = client.get(path).status_code
                except Exception:
                    status = 0
                with self.lock:
                    self.statuses[str(status)] = self.statuses.get(str(status), 0) + 1

    def __enter__(self):
        self.workers = [
            threading.Thread(target=self.run, args=(i,), daemon=True) for i in range(self.threads)
        ]
        for worker in self.workers:
            worker.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        for worker in self.workers:
            worker.join(timeout=120)


def stability(db, tenant: str, before: str, after: str) -> dict:
    from sqlalchemy import select

    from app.db.models import RevisionCluster, RevisionClusterMember

    def members(revision):
        rows = db.execute(
            select(
                RevisionClusterMember.entity_id,
                RevisionClusterMember.cluster_id,
                RevisionClusterMember.top_id,
            ).where(RevisionClusterMember.tenant_id == tenant, RevisionClusterMember.revision == revision)
        )
        return {entity: (leaf, top) for entity, leaf, top in rows}

    def clusters(revision):
        rows = db.execute(
            select(RevisionCluster.cluster_id, RevisionCluster.size, RevisionCluster.parent_id).where(
                RevisionCluster.tenant_id == tenant, RevisionCluster.revision == revision
            )
        )
        return {cluster: (size, parent) for cluster, size, parent in rows}

    first, second = members(before), members(after)
    common = first.keys() & second.keys()
    old, new = clusters(before), clusters(after)
    kept = old.keys() & new.keys()
    old_top = {c for c, (_, parent) in old.items() if not parent}
    return {
        "clusters_before": len(old),
        "clusters_after": len(new),
        "cluster_ids_kept": round(len(kept) / len(old), 4),
        "cluster_ids_kept_size_weighted": round(
            sum(old[c][0] for c in kept) / sum(s for s, _ in old.values()), 4
        ),
        "top_level_ids_kept": round(len(old_top & new.keys()) / len(old_top), 4),
        "entities_same_leaf_id": round(sum(first[e][0] == second[e][0] for e in common) / len(common), 4),
        "entities_same_top_id": round(sum(first[e][1] == second[e][1] for e in common) / len(common), 4),
    }


def structural_bounds(db, tenant: str, revision: str) -> dict:
    from sqlalchemy import func, select

    from app.db.models import RevisionCluster

    scope = (RevisionCluster.tenant_id == tenant, RevisionCluster.revision == revision)
    return {
        "top_level": db.scalar(select(func.count()).where(*scope, RevisionCluster.parent_id == "")),
        "max_children": db.scalar(select(func.max(RevisionCluster.child_count)).where(*scope)),
        "max_members": db.scalar(select(func.max(RevisionCluster.member_count)).where(*scope)),
        "max_depth": db.scalar(select(func.max(RevisionCluster.depth)).where(*scope)) + 1,
        "clusters": db.scalar(select(func.count()).where(*scope)),
        "kinds": {
            kind: count
            for kind, count in db.execute(
                select(RevisionCluster.kind, func.count()).where(*scope).group_by(RevisionCluster.kind)
            )
        },
    }


def explore_comparison(graph_uri: str, tenant: str, revision: str, hub: str, totals, repeat: int) -> dict:
    """Former scan-based explore query shapes vs the current store, same revision."""
    from neo4j import GraphDatabase

    from app.graph.exploration import EDGE_TYPES
    from app.graph.repository import get_graph_store

    store = get_graph_store()
    params = {"tenant": tenant, "revision": revision}
    result = {}
    with GraphDatabase.driver(graph_uri) as driver:

        def legacy(root):
            with driver.session(fetch_size=500) as session:
                if root is None:
                    rows = list(session.run(LEGACY_SAMPLE, **params, limit=250))
                    ids = [json.loads(r["payload"])["id"] for r in rows]
                else:
                    key = json.dumps([tenant, revision, root])
                    rows = list(
                        session.run(LEGACY_NEIGHBORS % EDGE_TYPES, **params, key=key, root=root, limit=249)
                    )
                    ids = [root] + [json.loads(r["payload"])["id"] for r in rows]
                return list(session.run(LEGACY_EDGES % EDGE_TYPES, **params, ids=ids, limit=1000))

        for name, root in (("sample", None), ("hub_neighborhood", hub)):
            before, after = [], []
            for _ in range(repeat):
                started = time.perf_counter()
                legacy(root)
                before.append(time.perf_counter() - started)
                started = time.perf_counter()
                store.explore(tenant, revision, root, 250, 1000, totals)
                after.append(time.perf_counter() - started)
            result[name] = {
                "before_scan_queries": percentiles(before),
                "after_key_anchored": percentiles(after),
            }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--database-url", required=True, help="Disposable PostgreSQL (a schema is created)")
    parser.add_argument("--graph-uri", required=True, help="Empty disposable Memgraph bolt URI")
    parser.add_argument("--size", type=int, default=100_000)
    parser.add_argument("--edge-change", type=float, default=0.01)
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--leaves", type=int, default=150)
    parser.add_argument("--pollers", type=int, default=2)
    parser.add_argument("--chunk-bytes", type=int, default=3_900_000)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 100 <= args.size <= 1_000_000 or not 0 < args.edge_change < 0.5:
        parser.error("Size 100..1000000 and an edge change in (0, 0.5) are required")

    from alembic import command
    from alembic.config import Config
    from qualify_publication import (
        clear_graph,
        free_port,
        graph_is_empty,
        memgraph_storage,
        rss_bytes,
        run_measured,
    )
    from qualify_scale import FIXTURE, generate
    from sqlalchemy import create_engine, text

    if not graph_is_empty(args.graph_uri):
        parser.error(f"Graph at {args.graph_uri} is not empty; use a disposable instance")
    schema = "zg_clusters_" + uuid4().hex
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
        "edge_change": args.edge_change,
        "revisions": [],
    }
    api = None
    log = tempfile.NamedTemporaryFile(prefix="zg-qualify-api-", suffix=".log", delete=False)
    try:
        from app.core.config import get_settings

        get_settings.cache_clear()
        config = Config()
        config.set_main_option("script_location", str(BACKEND / "app" / "db" / "migrations"))
        command.upgrade(config, "head")
        from app.db.session import session_factory
        from app.graph.analysis import stored_totals
        from app.graph.repository import get_graph_store

        session_factory.cache_clear()
        get_graph_store.cache_clear()
        get_graph_store().migrate()
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

        original = generate(args.size, seed=7)
        changed, replaced = perturbed(original, args.edge_change)
        hub = next(n.id for n in original.nodes if n.type.value == "CloudRole")
        for index, snapshot in enumerate((original, changed)):
            entry = {"nodes": len(snapshot.nodes), "edges": len(snapshot.edges)}
            if index:
                entry["edges_replaced"] = replaced
            job_id = upload(client, snapshot, args.chunk_bytes)
            poller = ClusterPoller(base, token, args.pollers if index else 0)
            with poller:
                worker = run_measured([sys.executable, "-c", WORKER, job_id], env)
            measured = json.loads(worker["stdout"].decode().strip().splitlines()[-1])
            phases = measured["phases"]
            clustering = sum(
                phases.get(k, 0.0) for k in ("clusters_load_previous", "clusters_compute", "clusters_store")
            )
            entry["publish"] = {
                "seconds": round(measured["seconds"], 2),
                "clustering_seconds": round(clustering, 2),
                "seconds_without_clustering": round(measured["seconds"] - clustering, 2),
                "worker_peak_rss_mb": round(rss_bytes(measured["maxrss"]) / 2**20, 1),
                "phases_s": phases,
            }
            if index:
                entry["readers_during_publish"] = poller.statuses
            job = client.get(f"/api/v1/ingestions/{job_id}").json()
            entry["job"] = {"status": job["status"], "node_count": job["node_count"]}
            entry["revision"] = client.get("/api/v1/overview").json()["revision"]
            with session_factory()() as db:
                entry["bounds"] = structural_bounds(db, "demo", entry["revision"])
                from app.graph.clusters import stored_summary

                summary = stored_summary(db, "demo", entry["revision"])
                entry["summary"] = {
                    "total_clusters": summary.total_clusters,
                    "top_level": summary.top_level,
                    "isolated_nodes": summary.isolated_nodes,
                    "top_links": summary.top_links,
                    "reused_ids": summary.reused_ids,
                    "compute_ms": summary.compute_ms,
                }
            report["revisions"].append(entry)
            args.output.write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps(entry), flush=True)
        del original, changed

        first, second = (entry["revision"] for entry in report["revisions"])
        with session_factory()() as db:
            report["stability"] = stability(db, "demo", first, second)
            totals = stored_totals(db, "demo", second)
        print(json.dumps(report["stability"]), flush=True)

        # Endpoint latency on the current revision (warm), sequential requests.
        top_samples, top_sizes = [], []
        for _ in range(args.requests):
            elapsed, body = timed_get(client, "/api/v1/graph/clusters", {"revision": second})
            top_samples.append(elapsed)
            top_sizes.append(len(body["clusters"]))
        top = body
        expand, leaf, sizes, leaf_ids = [], [], [], []
        frontier = [c["id"] for c in top["clusters"]]
        while frontier and len(leaf_ids) < args.leaves * 4:
            cluster_id = frontier.pop(0)
            elapsed, detail = timed_get(client, f"/api/v1/graph/clusters/{cluster_id}", {"revision": second})
            (expand if detail["view"]["mode"] == "clusters" else leaf).append(elapsed)
            sizes.append(max(len(detail["children"]), len(detail["nodes"])))
            if detail["view"]["mode"] == "clusters":
                frontier += [c["id"] for c in detail["children"]]
            else:
                leaf_ids.append(cluster_id)
        rng = random.Random(5)
        for cluster_id in rng.sample(leaf_ids, min(args.leaves, len(leaf_ids))):
            elapsed, detail = timed_get(client, f"/api/v1/graph/clusters/{cluster_id}", {"revision": second})
            leaf.append(elapsed)
            sizes.append(len(detail["nodes"]))
        everything = top_samples + expand + leaf
        report["endpoints"] = {
            "level0": {**percentiles(top_samples), "clusters": max(top_sizes), "edges": len(top["edges"])},
            "expand_clusters_mode": percentiles(expand),
            "expand_members_mode": percentiles(leaf),
            "both_endpoints": percentiles(everything),
            "largest_expansion_items": max(sizes),
        }
        print(json.dumps(report["endpoints"]), flush=True)

        get_graph_store.cache_clear()
        report["explore"] = explore_comparison(args.graph_uri, "demo", second, hub, totals, 20)
        explore_http = {}
        for name, params in (("sample", {}), ("hub_neighborhood", {"root_id": hub})):
            samples = [timed_get(client, "/api/v1/graph/explore", params)[0] for _ in range(50)]
            explore_http[name] = percentiles(samples)
        report["explore"]["http_after"] = explore_http
        print(json.dumps(report["explore"]), flush=True)

        # Retention removes revision 1 and its cluster rows.
        from sqlalchemy import func, select

        from app.db.models import RevisionClusterMember
        from app.graph import retention

        # A small third revision makes revision 1 the oldest beyond keep=2.
        job_id = upload(client, generate(min(args.size, 1000), seed=11), args.chunk_bytes)
        run_measured([sys.executable, "-c", WORKER, job_id], env)
        later = datetime.now(UTC) + timedelta(days=2)
        started = time.perf_counter()
        result = retention.prune_revisions(
            "demo", retention.RetentionPolicy(1, 2, 10), apply=True, timestamp=later
        )
        with session_factory()() as db:
            left = db.scalar(
                select(func.count()).where(
                    RevisionClusterMember.tenant_id == "demo", RevisionClusterMember.revision == first
                )
            )
        report["retention"] = {
            "deleted": result.deleted,
            "deleted_first_revision": first in result.deleted,
            "cluster_members_left_for_deleted_revision": left,
            "seconds": round(time.perf_counter() - started, 2),
        }
        report["memgraph"] = memgraph_storage(args.graph_uri)
        print(json.dumps(report["retention"]), flush=True)
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

    publishes = [entry["publish"] for entry in report["revisions"]]
    endpoints = report["endpoints"]
    report["checks"] = {
        "top_level_at_most_300": all(e["bounds"]["top_level"] <= 300 for e in report["revisions"])
        and endpoints["level0"]["clusters"] <= 300,
        "every_expansion_at_most_500": all(
            e["bounds"]["max_children"] <= 500 and e["bounds"]["max_members"] <= 500
            for e in report["revisions"]
        )
        and endpoints["largest_expansion_items"] <= 500,
        "level0_p95_under_200ms": endpoints["level0"]["p95_ms"] < 200,
        "expansion_p95_under_200ms": endpoints["expand_clusters_mode"]["p95_ms"] < 200
        and endpoints["expand_members_mode"]["p95_ms"] < 200,
        "cluster_id_stability_at_least_90pct": report["stability"]["cluster_ids_kept"] >= 0.9,
        "clustering_under_15s": all(p["clustering_seconds"] < 15 for p in publishes),
        "worker_peak_rss_under_1gb": all(p["worker_peak_rss_mb"] < 1024 for p in publishes),
        "zero_503_during_publish": report["revisions"][1]["readers_during_publish"].get("503", 0) == 0,
        "jobs_completed": all(e["job"]["status"] == "completed" for e in report["revisions"]),
        "retention_deleted_cluster_rows": report["retention"]["deleted_first_revision"]
        and report["retention"]["cluster_members_left_for_deleted_revision"] == 0,
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["checks"], indent=2))
    if not all(report["checks"].values()):
        raise SystemExit("Cluster qualification failed; inspect the JSON report")


if __name__ == "__main__":
    main()
