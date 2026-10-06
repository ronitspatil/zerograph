"""Phase 2 publication qualification on a real Memgraph and PostgreSQL.

Drives the production code paths end to end, with each component in its own process:

* an API server (uvicorn, ``app.main:app``) receiving a chunked NDJSON upload
  (``POST /ingestions/uploads`` -> ``PUT .../chunks/{n}`` -> ``commit``);
* one ingestion worker process per publication (``process_job``), timed, with its
  peak RSS from the kernel (``ru_maxrss``);
* concurrent pollers hitting ``/graph/explore`` (sample and hub neighborhood),
  ``/overview`` and ``/findings`` for the whole publication, counting every status;
* retention (``prune_revisions --apply``) deleting a full-size revision while polled;
* the backup bridge streaming a version 2 NDJSON graph archive of all revisions,
  validating and importing it into a second, empty Memgraph, and re-exporting it
  for a byte-for-byte digest comparison.

App state lives in a disposable schema of ``--database-url`` (Alembic head), removed
afterwards. Both graph URIs must point at empty, disposable Memgraph instances; their
contents are deleted at the end. No cloud services are used.
"""

import argparse
import hashlib
import json
import os
import platform
import secrets
import socket
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
BRIDGE = BACKEND.parent / "deploy" / "_snapshot_bridge.py"
sys.path.insert(0, str(BACKEND / "scripts"))

WORKER = """
import json, resource, sys, time
from loguru import logger
logger.remove()
from app.collectors import publication, tasks
from app.graph.compact import CompactGraph
from app.graph.repository import CypherGraphStore
phases = {}
def timed(owner, name):
    original = getattr(owner, name)
    def wrapper(*args, **kwargs):
        started = time.perf_counter()
        try:
            return original(*args, **kwargs)
        finally:
            phases[name] = phases.get(name, 0.0) + time.perf_counter() - started
    setattr(owner, name, wrapper)
for name in ("begin_revision", "write_nodes", "write_edges", "finish_revision"):
    timed(CypherGraphStore, name)
timed(CompactGraph, "analyze")
timed(publication, "check_conflicts")
timed(publication, "check_caps")
timed(tasks, "store_analysis")
timed(tasks, "compute_topics")
timed(tasks, "store_topics")
timed(tasks, "acquire_pointer_gate")
started = time.perf_counter()
tasks.process_job(sys.argv[1])
print(json.dumps({"seconds": time.perf_counter() - started,
                  "phases": {k: round(v, 2) for k, v in phases.items()},
                  "maxrss": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}))
"""

def rss_bytes(value: int) -> int:
    # macOS reports ru_maxrss in bytes, Linux in KiB.
    return value if sys.platform == "darwin" else value * 1024


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


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


def chunks(snapshot, limit: int):
    """NDJSON chunks no larger than ``limit`` bytes, nodes first then edges."""
    lines = (
        *(json.dumps({"node": n.model_dump(mode="json")}) for n in snapshot.nodes),
        *(json.dumps({"edge": e.model_dump(mode="json")}) for e in snapshot.edges),
    )
    buffer, size = [], 0
    for line in lines:
        encoded = (line + "\n").encode()
        if size + len(encoded) > limit and buffer:
            yield b"".join(buffer)
            buffer, size = [], 0
        buffer.append(encoded)
        size += len(encoded)
    if buffer:
        yield b"".join(buffer)


class Poller:
    """Concurrent readers recording every status code and latency until stopped."""

    def __init__(self, base: str, token: str, hub: str, threads: int):
        self.base, self.token, self.hub, self.threads = base, token, hub, threads
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.results: dict[str, dict] = {}

    def record(self, name: str, status: int, seconds: float) -> None:
        with self.lock:
            entry = self.results.setdefault(name, {"statuses": {}, "latencies": []})
            entry["statuses"][str(status)] = entry["statuses"].get(str(status), 0) + 1
            entry["latencies"].append(seconds)

    def run(self, offset: int) -> None:
        import httpx

        paths = {
            "explore_sample": "/api/v1/graph/explore",
            "explore_hub": f"/api/v1/graph/explore?root_id={self.hub}",
            "overview": "/api/v1/overview",
            "findings": "/api/v1/findings?limit=200",
        }
        names = list(paths)
        with httpx.Client(
            base_url=self.base, headers={"Authorization": f"Bearer {self.token}"}, timeout=60
        ) as client:
            index = offset
            while not self.stop.is_set():
                name = names[index % len(names)]
                index += 1
                started = time.perf_counter()
                try:
                    status = client.get(paths[name]).status_code
                except Exception:
                    status = 0
                self.record(name, status, time.perf_counter() - started)

    def __enter__(self):
        self.workers = [
            threading.Thread(target=self.run, args=(offset,), daemon=True) for offset in range(self.threads)
        ]
        for worker in self.workers:
            worker.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        for worker in self.workers:
            worker.join(timeout=120)

    def summary(self) -> dict:
        report, total, unavailable, errors = {}, 0, 0, 0
        for name, entry in sorted(self.results.items()):
            report[name] = {"statuses": entry["statuses"], **percentiles(entry["latencies"])}
            for status, count in entry["statuses"].items():
                total += count
                unavailable += count if status == "503" else 0
                errors += count if status != "200" else 0
        return {"requests": total, "status_503": unavailable, "non_200": errors, "endpoints": report}


def memgraph_storage(uri: str) -> dict:
    from neo4j import GraphDatabase

    with GraphDatabase.driver(uri) as driver, driver.session() as session:
        info = {row["storage info"]: row["value"] for row in session.run("SHOW STORAGE INFO")}
    return {key: info.get(key) for key in ("vertex_count", "edge_count", "memory_res", "peak_memory_res")}


def graph_is_empty(uri: str) -> bool:
    from neo4j import GraphDatabase

    with GraphDatabase.driver(uri) as driver, driver.session() as session:
        return session.run("MATCH (n) RETURN count(n) AS count").single()["count"] == 0


def clear_graph(uri: str) -> None:
    from neo4j import GraphDatabase

    with GraphDatabase.driver(uri) as driver, driver.session() as session:
        while session.run("MATCH (n) WITH n LIMIT 5000 DETACH DELETE n RETURN count(*) AS deleted").single()[
            "deleted"
        ]:
            pass


def run_measured(command: list[str], env: dict, *, stdin=None, stdout=None, timeout=3600) -> dict:
    """Run a child process to completion; wall time and the kernel's peak RSS."""
    started = time.perf_counter()
    process = subprocess.Popen(
        command,
        env=env,
        cwd=BACKEND,
        stdin=stdin,
        stdout=stdout if stdout is not None else subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + timeout
    while True:
        pid, status, usage = os.wait4(process.pid, os.WNOHANG)
        if pid:
            break
        if time.monotonic() > deadline:
            process.kill()
            raise RuntimeError(f"Timed out: {command[:3]}")
        time.sleep(0.05)
    process.returncode = os.waitstatus_to_exitcode(status)
    out = process.stdout.read() if stdout is None else b""
    err = process.stderr.read()
    if process.returncode:
        raise RuntimeError(f"{command[:4]} failed ({process.returncode}): {err.decode()[-2000:]}")
    return {
        "seconds": round(time.perf_counter() - started, 2),
        "peak_rss_mb": round(rss_bytes(usage.ru_maxrss) / 2**20, 1),
        "stdout": out,
    }


def file_digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--database-url", required=True, help="Disposable PostgreSQL (a schema is created)")
    parser.add_argument("--graph-uri", required=True, help="Empty disposable Memgraph bolt URI")
    parser.add_argument("--restore-graph-uri", required=True, help="Second empty Memgraph for the restore")
    parser.add_argument("--size", type=int, default=100_000)
    parser.add_argument("--revisions", type=int, default=3)
    parser.add_argument("--pollers", type=int, default=2)
    parser.add_argument("--chunk-bytes", type=int, default=3_900_000)
    parser.add_argument("--exposed-rate", type=float, default=0.002)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 100 <= args.size <= 1_000_000 or not 2 <= args.revisions <= 10:
        parser.error("Size 100..1000000 and 2..10 revisions are required")
    for uri in (args.graph_uri, args.restore_graph_uri):
        if not graph_is_empty(uri):
            parser.error(f"Graph at {uri} is not empty; use disposable instances")

    from alembic import command
    from alembic.config import Config
    from qualify_scale import FIXTURE, generate
    from sqlalchemy import create_engine, text

    schema = "zg_publication_" + uuid4().hex
    admin = create_engine(args.database_url)
    with admin.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    scoped = admin.url.update_query_dict({"options": f"-csearch_path={schema}"}).render_as_string(
        hide_password=False
    )
    token = secrets.token_urlsafe(48)
    env = {
        **os.environ,
        "ZG_ENVIRONMENT": "test",  # Disables only the Redis-backed demo rate limiter.
        "ZG_DEMO_MODE": "true",
        "ZG_DEMO_TOKEN": token,
        "ZG_DATABASE_URL": scoped,
        "ZG_GRAPH_VENDOR": "memgraph",
        "ZG_GRAPH_URI": args.graph_uri,
        "ZG_REDIS_URL": "redis://127.0.0.1:1/0",  # No broker: the worker is run directly.
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
        from app.graph.repository import get_graph_store

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

        for index in range(args.revisions):
            snapshot = generate(args.size, seed=7 + index, exposed_rate=args.exposed_rate)
            hub = next(n.id for n in snapshot.nodes if n.type.value == "CloudRole")
            entry = {"nodes": len(snapshot.nodes), "edges": len(snapshot.edges)}
            started = time.perf_counter()
            upload = client.post("/api/v1/ingestions/uploads", json={"source": "snapshot"})
            assert upload.status_code == 201, upload.text
            upload_id, sent, count, slowest = upload.json()["id"], 0, 0, 0.0
            for number, body in enumerate(chunks(snapshot, args.chunk_bytes)):
                chunk_started = time.perf_counter()
                response = client.put(f"/api/v1/ingestions/uploads/{upload_id}/chunks/{number}", content=body)
                assert response.status_code == 200, response.text
                slowest = max(slowest, time.perf_counter() - chunk_started)
                sent, count = sent + len(body), count + 1
            commit_started = time.perf_counter()
            committed = client.post(f"/api/v1/ingestions/uploads/{upload_id}/commit")
            assert committed.status_code == 202, committed.text
            entry["upload"] = {
                "seconds": round(time.perf_counter() - started, 2),
                # Includes a failed broker publish (no Redis here); beat would redispatch.
                "commit_s": round(time.perf_counter() - commit_started, 2),
                "chunks": count,
                "bytes": sent,
                "slowest_chunk_s": round(slowest, 2),
            }
            del snapshot
            job_id = committed.json()["id"]
            with Poller(base, token, hub, args.pollers) as poller:
                worker = run_measured([sys.executable, "-c", WORKER, job_id], env)
            measured = json.loads(worker["stdout"].decode().strip().splitlines()[-1])
            entry["publish"] = {
                "seconds": round(measured["seconds"], 2),
                "process_seconds": worker["seconds"],
                "worker_peak_rss_mb": round(rss_bytes(measured["maxrss"]) / 2**20, 1),
                "phases_s": measured["phases"],
            }
            entry["readers_during_publish"] = poller.summary()
            job = client.get(f"/api/v1/ingestions/{job_id}").json()
            entry["job"] = {"status": job["status"], "node_count": job["node_count"]}
            overview = client.get("/api/v1/overview").json()
            entry["revision"] = overview["revision"]
            entry["overview"] = {
                key: overview[key]
                for key in ("total_nhis", "toxic_combinations", "high_blast_radius", "data_assets")
            }
            entry["memgraph"] = memgraph_storage(args.graph_uri)
            report["revisions"].append(entry)
            args.output.write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps(entry), flush=True)

        # Backup (streamed v2 export) of all revisions, restore into the second Memgraph.
        workdir = Path(tempfile.mkdtemp(prefix="zg-qualify-backup-"))
        archive, restored = workdir / "graph.ndjson", workdir / "restored.ndjson"
        bridge = [sys.executable, str(BRIDGE)]
        with archive.open("wb") as output:
            exported = run_measured([*bridge, "export"], env, stdout=output)
        restore_env = {**env, "ZG_GRAPH_URI": args.restore_graph_uri}
        with archive.open("rb") as stream:
            validated = run_measured([*bridge, "validate"], env, stdin=stream)
        with archive.open("rb") as stream:
            imported = run_measured([*bridge, "import"], restore_env, stdin=stream)
        with restored.open("wb") as output:
            reexported = run_measured([*bridge, "export"], restore_env, stdout=output)
        report["backup"] = {
            "archive_bytes": archive.stat().st_size,
            "revisions": sum(1 for line in archive.open("rb") if line.startswith(b'{"revision":')),
            "export": {k: v for k, v in exported.items() if k != "stdout"},
            "validate": {k: v for k, v in validated.items() if k != "stdout"},
            "import": {k: v for k, v in imported.items() if k != "stdout"},
            "reexport": {k: v for k, v in reexported.items() if k != "stdout"},
            "round_trip_identical": file_digest(archive) == file_digest(restored),
            "restore_memgraph": memgraph_storage(args.restore_graph_uri),
        }
        archive.unlink()
        restored.unlink()
        workdir.rmdir()
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report["backup"]), flush=True)

        # Retention deletes the oldest full-size revision while readers poll.
        from app.graph import retention

        get_graph_store.cache_clear()
        later = datetime.now(UTC) + timedelta(days=2)
        hub_id = "cloudrole:0000000"
        with Poller(base, token, hub_id, args.pollers) as poller:
            started = time.perf_counter()
            result = retention.prune_revisions(
                "demo", retention.RetentionPolicy(1, args.revisions - 1, 10), apply=True, timestamp=later
            )
            seconds = time.perf_counter() - started
        from neo4j import GraphDatabase

        with GraphDatabase.driver(args.graph_uri) as driver, driver.session() as session:
            left = session.run(
                "MATCH (n {tenant_id:'demo', revision:$revision}) RETURN count(n) AS count",
                revision=report["revisions"][0]["revision"],
            ).single()["count"]
        report["retention"] = {
            "deleted": result.deleted,
            "entities_left_in_deleted_revision": left,
            "deleted_first_revision": result.deleted == [report["revisions"][0]["revision"]],
            "seconds": round(seconds, 2),
            "readers_during_retention": poller.summary(),
            "memgraph_after": memgraph_storage(args.graph_uri),
        }
        print(json.dumps(report["retention"]), flush=True)
    finally:
        if api is not None:
            api.terminate()
            _, _, usage = os.wait4(api.pid, 0)
            report["api_peak_rss_mb"] = round(rss_bytes(usage.ru_maxrss) / 2**20, 1)
        log.close()
        os.unlink(log.name)
        for uri in (args.graph_uri, args.restore_graph_uri):
            clear_graph(uri)
        with admin.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()

    publishes = [entry["publish"] for entry in report["revisions"]]
    peak_worker = max(item["worker_peak_rss_mb"] for item in publishes)
    report["peak_worker_plus_api_rss_mb"] = round(peak_worker + report["api_peak_rss_mb"], 1)
    report["checks"] = {
        "publish_under_300s": all(item["seconds"] < 300 for item in publishes),
        "peak_worker_plus_api_rss_under_1gb": report["peak_worker_plus_api_rss_mb"] < 1024,
        "zero_503_during_publish": all(
            entry["readers_during_publish"]["status_503"] == 0 for entry in report["revisions"]
        ),
        # The first publication runs against an empty tenant (hub neighborhood 404s).
        "all_reads_200_while_replacing_a_revision": all(
            entry["readers_during_publish"]["non_200"] == 0 for entry in report["revisions"][1:]
        ),
        "jobs_completed": all(entry["job"]["status"] == "completed" for entry in report["revisions"]),
        "retention_deleted_full_revision": report["retention"]["deleted_first_revision"]
        and report["retention"]["entities_left_in_deleted_revision"] == 0,
        "zero_503_during_retention": report["retention"]["readers_during_retention"]["status_503"] == 0,
        "backup_restore_round_trip_identical": report["backup"]["round_trip_identical"],
        "backup_covers_all_revisions": report["backup"]["revisions"] == args.revisions,
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["checks"], indent=2))
    if not all(report["checks"].values()):
        raise SystemExit("Publication qualification failed; inspect the JSON report")


if __name__ == "__main__":
    main()
