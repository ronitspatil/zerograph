"""Optimizer Phase 1 qualification: relationship topics on a real Memgraph and PostgreSQL.

Publishes the planted-topic fixture (``qualify_scale.generate_topics``: 12 named
topics, tags on ~50% of data assets, topic tokens in ~60% of names, 15% cross-topic
over-grants, 3 admin hubs) through the production upload, worker and API processes,
each in its own process, and records:

* publish time and worker peak RSS with publish-time topic analysis disabled
  (``compute_topics``/``store_topics`` patched out) and enabled, alternating, plus
  the topic phases measured inside the enabled worker;
* accuracy of the stored rows against the fixture's ground truth: resource purity
  and NMI, role and identity primary-topic accuracy, hub detection, and how many
  stored cross-topic grants are planted over-grants (granted analysis only; usage
  is generated into a sidecar but never read);
* determinism: the published revision is recomputed twice in process and must give
  row-identical results, equal to the rows the worker stored; a backfill of the
  same revision (rows deleted) stores identical rows again;
* ``GET /graph/topics`` and ``GET /graph/topics/{id}`` latency (p50/p95) over every
  topic, member kind and several pages;
* retention deleting a revision's topic rows.

App state lives in a disposable schema of ``--database-url`` (Alembic head), removed
afterwards. ``--graph-uri`` must be an empty, disposable Memgraph; it is cleared at
the end. No cloud services are used.
"""

import argparse
import hashlib
import json
import math
import os
import platform
import secrets
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND / "scripts"))

WORKER = """
import json, resource, sys, time
from loguru import logger
logger.remove()
from app.collectors import tasks
from app.graph import topics
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
timed(tasks, "compute_clusters", "clusters_compute")
timed(tasks, "store_clusters", "clusters_store")
if sys.argv[2] == "without":
    tasks.compute_topics = lambda graph: None
    tasks.store_topics = lambda *args: None
else:
    timed(tasks, "compute_topics", "topics_compute")
    timed(tasks, "store_topics", "topics_store")
started = time.perf_counter()
tasks.process_job(sys.argv[1])
print(json.dumps({"seconds": time.perf_counter() - started,
                  "phases": {k: round(v, 3) for k, v in phases.items()},
                  "maxrss": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}))
"""


def nmi(a: list, b: list) -> float:
    n = len(a)
    ca, cb, cab = Counter(a), Counter(b), Counter(zip(a, b, strict=True))
    mi = sum(v / n * math.log((v / n) / (ca[x] / n * cb[y] / n)) for (x, y), v in cab.items())
    ha = -sum(v / n * math.log(v / n) for v in ca.values())
    hb = -sum(v / n * math.log(v / n) for v in cb.values())
    return 2 * mi / (ha + hb) if ha + hb else 1.0


def purity(pred: list, truth: list) -> float:
    groups: dict = defaultdict(Counter)
    for p, q in zip(pred, truth, strict=True):
        groups[p][q] += 1
    return sum(c.most_common(1)[0][1] for c in groups.values()) / len(pred)


def stored_rows(db, tenant: str, revision: str) -> list[tuple]:
    from sqlalchemy import select

    from app.db.models import RevisionTopicMember
    from app.graph.topics import MEMBER_COLUMNS

    rows = [
        tuple(json.dumps(v, sort_keys=True) if isinstance(v, list | dict) else v for v in row)
        for row in db.execute(
            select(*(getattr(RevisionTopicMember, c) for c in MEMBER_COLUMNS)).where(
                RevisionTopicMember.tenant_id == tenant, RevisionTopicMember.revision == revision
            )
        )
    ]
    return sorted(rows, key=lambda row: row[2])


def digest(rows: list[tuple]) -> str:
    hasher = hashlib.sha256()
    for row in rows:
        hasher.update(json.dumps(row, default=str).encode())
    return hasher.hexdigest()


def computed_rows(computed, tenant: str, revision: str) -> list[tuple]:
    from app.graph.topics import member_rows

    return sorted(
        (
            tuple(json.dumps(v, sort_keys=True) if isinstance(v, list | dict) else v for v in row)
            for row in member_rows(computed, tenant, revision)
        ),
        key=lambda row: row[2],
    )


def accuracy(db, tenant: str, revision: str, truth: dict) -> dict:
    """Stored rows against the planted ground truth (topics are named by their tag values)."""
    from sqlalchemy import select

    from app.db.models import RevisionTopic, RevisionTopicMember

    names = {
        row.topic_id: (row.name, row.kind)
        for row in db.scalars(
            select(RevisionTopic).where(RevisionTopic.tenant_id == tenant, RevisionTopic.revision == revision)
        )
    }
    members = {
        row.entity_id: row
        for row in db.scalars(
            select(RevisionTopicMember).where(
                RevisionTopicMember.tenant_id == tenant, RevisionTopicMember.revision == revision
            )
        )
    }

    def name(entity: str) -> str | None:
        topic = members[entity].topic_id
        return names[topic][0] if topic else None

    resources = truth["resource_topic"]
    predicted = [name(entity) for entity in resources]
    planted = list(resources.values())
    seeds = Counter(members[entity].seed for entity in resources)
    by_seed = {
        seed: round(
            sum(name(e) == t for e, t in resources.items() if members[e].seed == seed) / max(1, count), 4
        )
        for seed, count in seeds.items()
    }
    roles = truth["role_topic"]
    with_topic = [r for r in roles if members[r].topic_id]
    identities = truth["identity_topic"]
    identities_with_topic = [i for i in identities if members[i].topic_id]
    hubs = {entity for entity, row in members.items() if row.kind == "role" and row.flags & 1}
    return {
        "resources": len(resources),
        "resource_purity": round(purity(predicted, planted), 4),
        "resource_nmi": round(nmi(predicted, planted), 4),
        "resource_purity_assigned_only": round(
            purity(
                [p for p in predicted if not p.startswith("unassigned-")],
                [t for p, t in zip(predicted, planted, strict=True) if not p.startswith("unassigned-")],
            ),
            4,
        ),
        "resources_by_seed": dict(seeds),
        "resource_accuracy_by_seed": by_seed,
        "anchored_topics": sorted(n for n, kind in names.values() if kind == "anchored"),
        "fallback_topics": sorted(n for n, kind in names.values() if kind == "fallback"),
        "role_topic_accuracy": round(sum(name(r) == roles[r] for r in with_topic) / len(with_topic), 4),
        "roles_scored": len(with_topic),
        "roles_without_topic": len(roles) - len(with_topic),
        "identity_topic_accuracy": round(
            sum(name(i) == identities[i] for i in identities_with_topic) / len(identities_with_topic), 4
        ),
        "hub_roles_detected": sorted(hubs),
        "hub_roles_planted": truth["hub_roles"],
    }


def over_grant_overlap(computed, truth: dict) -> dict:
    """Stored cross-topic grants (non-hub roles) against planted over-grants: structural only."""
    from app.graph.topics import GRANT_CODES, HUB

    graph = computed.graph
    planted = {tuple(pair) for pair in truth["over_grants"]}
    planted_non_hub = {(r, d) for r, d in planted if r not in set(truth["hub_roles"])}
    found = set()
    for edge in range(graph.edge_count):
        if graph.edge_kind[edge] not in GRANT_CODES:
            continue
        source, target = graph.edge_source[edge], graph.edge_target[edge]
        row = computed.roles.get(source)
        if row is None or row["flags"] & HUB or row["topic"] < 0:
            continue
        topic = computed.resource_topic[target]
        if topic >= 0 and topic != row["topic"] and computed.topics[topic].kind == "anchored":
            found.add((graph.ids[source], graph.ids[target]))
    hits = len(found & planted_non_hub)
    return {
        "cross_topic_grants": len(found),
        "planted_over_grants_non_hub": len(planted_non_hub),
        "share_of_cross_topic_grants_planted": round(hits / len(found), 4) if found else 0.0,
        "share_of_planted_over_grants_flagged": round(hits / len(planted_non_hub), 4)
        if planted_non_hub
        else 0.0,
        "note": "Granted (structural) only; legitimate cross-topic access needs usage evidence (Phase 2).",
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--database-url", required=True, help="Disposable PostgreSQL (a schema is created)")
    parser.add_argument("--graph-uri", required=True, help="Empty disposable Memgraph bolt URI")
    parser.add_argument("--size", type=int, default=100_000)
    parser.add_argument("--seed", type=int, default=11)
    parser.add_argument("--publish-runs", type=int, default=2, help="Publications per arm (alternating)")
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--chunk-bytes", type=int, default=3_900_000)
    parser.add_argument("--sidecars", type=Path, help="Directory for the ground-truth and usage sidecars")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1000 <= args.size <= 100_000 or not 1 <= args.publish_runs <= 4:
        parser.error("Size 1000..100000 and 1..4 publish runs are required")

    from alembic import command
    from alembic.config import Config
    from qualify_clusters import timed_get, upload
    from qualify_publication import (
        clear_graph,
        free_port,
        graph_is_empty,
        memgraph_storage,
        percentiles,
        rss_bytes,
        run_measured,
    )
    from qualify_scale import TOPIC_FIXTURE, generate_topics
    from sqlalchemy import create_engine, text

    if not graph_is_empty(args.graph_uri):
        parser.error(f"Graph at {args.graph_uri} is not empty; use a disposable instance")
    snapshot, truth, usage = generate_topics(args.size, args.seed)
    if args.sidecars:
        args.sidecars.mkdir(parents=True, exist_ok=True)
        (args.sidecars / f"planted-{args.size}-truth.json").write_text(json.dumps(truth) + "\n")
        (args.sidecars / f"planted-{args.size}-usage.json").write_text(json.dumps(usage) + "\n")
    schema = "zg_topics_" + uuid4().hex
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
        "fixture": TOPIC_FIXTURE,
        "size": args.size,
        "seed": args.seed,
        "nodes": len(snapshot.nodes),
        "edges": len(snapshot.edges),
        "planted": {
            "over_grants": len(truth["over_grants"]),
            "duplicate_roles": len(truth["duplicate_of"]),
            "dormant_identities": len(truth["dormant_identities"]),
            "hub_roles": len(truth["hub_roles"]),
        },
        "publishes": [],
    }
    api = None
    log = tempfile.NamedTemporaryFile(prefix="zg-qualify-topics-api-", suffix=".log", delete=False)
    try:
        from app.core.config import get_settings

        get_settings.cache_clear()
        config = Config()
        config.set_main_option("script_location", str(BACKEND / "app" / "db" / "migrations"))
        command.upgrade(config, "head")
        from app.db.session import session_factory
        from app.graph import topics
        from app.graph.compact import CompactGraph
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

        arms = ["without", "with"] * args.publish_runs
        for arm in arms:
            job_id = upload(client, snapshot, args.chunk_bytes)
            worker = run_measured([sys.executable, "-c", WORKER, job_id, arm], env)
            measured = json.loads(worker["stdout"].decode().strip().splitlines()[-1])
            job = client.get(f"/api/v1/ingestions/{job_id}").json()
            phases = measured["phases"]
            entry = {
                "arm": arm,
                "seconds": round(measured["seconds"], 2),
                "topic_seconds": round(phases.get("topics_compute", 0) + phases.get("topics_store", 0), 3),
                "worker_peak_rss_mb": round(rss_bytes(measured["maxrss"]) / 2**20, 1),
                "phases_s": phases,
                "job": {"status": job["status"], "node_count": job["node_count"]},
                "revision": client.get("/api/v1/overview").json()["revision"],
            }
            report["publishes"].append(entry)
            args.output.write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps(entry), flush=True)
        without = [p for p in report["publishes"] if p["arm"] == "without"]
        enabled = [p for p in report["publishes"] if p["arm"] == "with"]
        report["overhead"] = {
            "topic_phase_seconds": min(p["topic_seconds"] for p in enabled),
            "topic_phase_seconds_runs": [p["topic_seconds"] for p in enabled],
            "publish_seconds_without": [p["seconds"] for p in without],
            "publish_seconds_with": [p["seconds"] for p in enabled],
            "publish_delta_min_seconds": round(
                min(p["seconds"] for p in enabled) - min(p["seconds"] for p in without), 2
            ),
            "worker_rss_mb_without": [p["worker_peak_rss_mb"] for p in without],
            "worker_rss_mb_with": [p["worker_peak_rss_mb"] for p in enabled],
            "worker_rss_delta_mb": round(
                max(p["worker_peak_rss_mb"] for p in enabled) - max(p["worker_peak_rss_mb"] for p in without),
                1,
            ),
        }
        print(json.dumps(report["overhead"]), flush=True)
        revision = enabled[-1]["revision"]
        with session_factory()() as db:
            report["accuracy"] = accuracy(db, "demo", revision, truth)
            summary = topics.stored_topic_summary(db, "demo", revision)
            report["summary"] = {**summary.totals, "compute_ms": summary.compute_ms}
            stored = stored_rows(db, "demo", revision)
        print(json.dumps(report["accuracy"]), flush=True)

        # Determinism: recompute the published revision twice in process.
        published = get_graph_store().snapshot("demo", revision)
        runs = []
        for _ in range(2):
            started = time.perf_counter()
            computed = topics.compute_topics(CompactGraph.from_snapshot(published))
            elapsed = time.perf_counter() - started
            runs.append((digest(computed_rows(computed, "demo", revision)), elapsed))
        report["over_grants"] = over_grant_overlap(computed, truth)
        del computed, published
        report["determinism"] = {
            "recomputed_digests": [d for d, _ in runs],
            "stored_digest": digest(stored),
            "rows": len(stored),
            "recompute_seconds": [round(s, 3) for _, s in runs],
            "identical_reruns": runs[0][0] == runs[1][0],
            "stored_equals_recomputed": digest(stored) == runs[0][0],
        }
        # Backfill: rows deleted, recomputed by the sweep's code path from Memgraph.
        with session_factory()() as db:
            topics.delete_topics(db, "demo", revision)
            db.commit()
        started = time.perf_counter()
        result = topics.backfill("demo")
        with session_factory()() as db:
            report["determinism"]["backfill"] = {
                "backfilled": result["backfilled"],
                "seconds": round(time.perf_counter() - started, 2),
                "identical": digest(stored_rows(db, "demo", revision)) == digest(stored),
            }
        print(json.dumps(report["determinism"]), flush=True)
        print(json.dumps(report["over_grants"]), flush=True)

        # Endpoint latency on the current revision (warm), sequential requests.
        top = []
        for _ in range(args.requests):
            elapsed, body = timed_get(client, "/api/v1/graph/topics", {"revision": revision})
            top.append(elapsed)
        detail, sizes = [], []
        for topic in body["topics"]:
            for kind in ("resource", "role", "identity"):
                for offset in (0, 50, 500):
                    params = {"revision": revision, "kind": kind, "offset": offset, "limit": 50}
                    elapsed, page = timed_get(client, f"/api/v1/graph/topics/{topic['id']}", params)
                    detail.append(elapsed)
                    sizes.append(len(page["members"]))
        large = []
        biggest = max(body["topics"], key=lambda t: t["identities"])
        for _ in range(20):
            params = {"revision": revision, "kind": "identity", "limit": 500}
            large.append(timed_get(client, f"/api/v1/graph/topics/{biggest['id']}", params)[0])
        report["endpoints"] = {
            "topics_map": {**percentiles(top), "topics": len(body["topics"]), "links": len(body["edges"])},
            "topic_detail_page_50": percentiles(detail),
            "topic_detail_page_500": percentiles(large),
            "largest_page": max(sizes),
        }
        print(json.dumps(report["endpoints"]), flush=True)

        # Retention (keep 2) deletes the older revisions; with two runs per arm that
        # includes the first "with" revision, whose topic rows must go with it.
        from sqlalchemy import func, select

        from app.db.models import RevisionTopicMember
        from app.graph import retention

        doomed = enabled[0]["revision"] if len(enabled) > 1 else None
        later = datetime.now(UTC) + timedelta(days=2)
        result = retention.prune_revisions(
            "demo", retention.RetentionPolicy(1, 2, 10), apply=True, timestamp=later
        )
        with session_factory()() as db:
            left = (
                db.scalar(
                    select(func.count()).where(
                        RevisionTopicMember.tenant_id == "demo", RevisionTopicMember.revision == doomed
                    )
                )
                if doomed
                else 0
            )
            kept = topics.count_rows(db, "demo", revision)
        report["retention"] = {
            "deleted": result.deleted,
            "deleted_topic_revision": doomed in result.deleted if doomed else None,
            "topic_members_left_for_deleted_revision": left,
            "current_revision_rows_kept": kept,
        }
        report["memgraph"] = memgraph_storage(args.graph_uri)
        print(json.dumps(report["retention"]), flush=True)
    finally:
        if api is not None:
            api.terminate()
            _, _, usage_ = os.wait4(api.pid, 0)
            report["api_peak_rss_mb"] = round(rss_bytes(usage_.ru_maxrss) / 2**20, 1)
        log.close()
        os.unlink(log.name)
        clear_graph(args.graph_uri)
        with admin.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()

    overhead, endpoints, accuracy_ = report["overhead"], report["endpoints"], report["accuracy"]
    report["checks"] = {
        "role_topic_accuracy_at_least_0.95": accuracy_["role_topic_accuracy"] >= 0.95,
        "resource_purity_at_least_0.9": accuracy_["resource_purity"] >= 0.9,
        "hub_roles_detected": accuracy_["hub_roles_detected"] == sorted(accuracy_["hub_roles_planted"]),
        "deterministic_reruns": report["determinism"]["identical_reruns"],
        "stored_rows_equal_recomputed": report["determinism"]["stored_equals_recomputed"],
        "backfill_rows_identical": report["determinism"]["backfill"]["identical"],
        "topic_phase_at_most_5s": overhead["topic_phase_seconds"] <= 5,
        "worker_rss_delta_at_most_200mb": overhead["worker_rss_delta_mb"] <= 200,
        "topics_map_p95_under_200ms": endpoints["topics_map"]["p95_ms"] < 200,
        "topic_detail_p95_under_200ms": endpoints["topic_detail_page_50"]["p95_ms"] < 200
        and endpoints["topic_detail_page_500"]["p95_ms"] < 200,
        "jobs_completed": all(p["job"]["status"] == "completed" for p in report["publishes"]),
        "retention_deleted_topic_rows": report["retention"]["topic_members_left_for_deleted_revision"] == 0
        and report["retention"]["current_revision_rows_kept"] > 0,
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["checks"], indent=2))
    if not all(report["checks"].values()):
        raise SystemExit("Topic qualification failed; inspect the JSON report")


if __name__ == "__main__":
    main()
