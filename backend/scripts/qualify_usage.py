"""Optimizer Phase 2 qualification: usage evidence and excess privilege on Memgraph and PostgreSQL.

Publishes the planted-topic fixture (``qualify_scale.generate_topics``) through the
production upload, worker and API processes, uploads the fixture's planted usage as
CloudTrail export files through the real usage upload API (``qualify_scale.
cloudtrail_records``: S3/RDS Data/OpenSearch data events and STS AssumeRole, coverage
attested for the window), lets the worker sweep recompute topics and the
excess-privilege index (EPI), and records:

* usage ingest wall time (files, records, bytes) and API peak RSS; the sweep recompute
  time and worker RSS;
* publish time and worker RSS with usage disabled (Phase 1 behaviour: topics without
  usage) and enabled, alternating, plus the role-level EPI compute time;
* topic accuracy after usage refinement (resource NMI and purity, role accuracy) against
  the planted ground truth;
* EPI against an independent brute-force reference (``reference_privilege``: explicit
  sets per role and identity, no caching) for every role and identity, per topic and
  graph-wide, in the attested (used) mode and, evaluated after the evidence goes stale,
  the inferred (peer baseline) mode;
* dormant identities against the planted ones (recall) and against observed and
  attributed use (no identity with either may be dormant);
* role-session attribution (``qualify_scale.ATTRIBUTION_FIXTURE``): attributed and
  unattributed session events, identity EPI with attribution against the same
  evidence with role-level credit only, and ``remove_assumption`` proposals against the
  planted never-assumed (identity, role) edges (``plant_never_assumed``: recall, and
  none on a pair with an observed assumption or attributed use);
* determinism and endpoint latency.

App state lives in a disposable schema of ``--database-url``; ``--graph-uri`` must be an
empty, disposable Memgraph, cleared at the end. No cloud services are used.
"""

import argparse
import json
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
for name in ("publish_sets", "store_analysis", "compute_clusters", "store_clusters"):
    timed(tasks, name)
if sys.argv[2] == "without":
    tasks.load_usage = lambda *args, **kwargs: None
else:
    timed(tasks, "load_usage", "usage_load")
timed(tasks, "compute_topics", "topics_compute")
timed(tasks, "store_topics", "topics_store")
from app.graph import proposals
timed(proposals, "compute_proposals", "proposals_compute")
timed(proposals, "store_proposals", "proposals_store")
started = time.perf_counter()
tasks.process_job(sys.argv[1])
print(json.dumps({"seconds": time.perf_counter() - started,
                  "phases": {k: round(v, 3) for k, v in phases.items()},
                  "maxrss": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}))
"""

SWEEP = """
import json, resource, sys, time
from loguru import logger
logger.remove()
from app.graph import topics
started = time.perf_counter()
results = topics.backfill_missing()
print(json.dumps({"seconds": time.perf_counter() - started, "results": results,
                  "maxrss": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}))
"""

# Worker phases that usage evidence changes: loading it, topics and EPI, and proposals
# (remove_assumption and usage-aware tiers). Graph writes, analysis and clusters do not
# depend on usage and run identically in both arms.
ANALYSIS_PHASES = ("usage_load", "topics_compute", "topics_store", "proposals_compute", "proposals_store")
# The analysis phases split into computation in the worker and storing rows in
# PostgreSQL. The computation floor is steady (2.3-3.2 s at 100k on an Apple M5, also
# under heavy contention); a 2 s regression measured 4.4-4.5 s. Storing is I/O and its
# floor varies by about 2 s between runs (0.8-3.1 s), so it keeps a looser budget.
COMPUTE_PHASES = ("usage_load", "topics_compute", "proposals_compute")
STORE_PHASES = ("topics_store", "proposals_store")
# Usage overhead budgets (seconds), on per-phase floors over the paired publishes
# (scripts/timing.py: the fastest run of each phase per arm): contention only adds
# time and rarely reaches every run of a phase, a regression is in every run. The
# end-to-end publish (fastest with usage minus fastest without) adds the graph writes,
# which drift by seconds, and keeps the loosest bound.
COMPUTE_OVERHEAD_BUDGET_S = 3.75
STORE_OVERHEAD_BUDGET_S = 4
PUBLISH_OVERHEAD_BUDGET_S = 10

DATA = {"Database", "VectorStore", "S3Bucket", "DataTable"}
PRINCIPALS = {"HumanUser", "ServiceAccount", "AIAgent", "MCPServer"}
GRANTS = {"CAN_READ", "CAN_WRITE"}
HOPS = {"ASSUMES_ROLE", "INHERITS_PERMISSIONS", "INVOKES_TOOL"}
WEIGHTS = {"public": 1, "internal": 2, "confidential": 5, "restricted": 10}
SERVICE = {"S3Bucket": "s3", "Database": "rds-data", "VectorStore": "aoss", "DataTable": "glue"}
MAX_HOPS = 5


def reference_privilege(
    snapshot,
    observed,
    sufficient,
    topic_of: dict,
    hubs: set,
    share: float,
    sessions=None,
    attribution_share: float = 0.95,
) -> dict:
    """Independent brute force of the EPI definitions (docs/privilege.md) on explicit sets.

    ``observed`` holds (principal ID, resource ID, action class) triples; ``topic_of`` maps
    every role and principal ID to its primary topic (None: no topic); ``hubs`` are hub
    role IDs. ``sessions`` (attribution ready) holds attributed role-session use as
    (identity ID or "", role ID, resource ID, action class, count). Returns ``{id:
    {"basis", "granted", "needed", "granted_core", "needed_core", "dormant"}}`` for every
    role and principal.
    """
    types = {node.id: node.type.value for node in snapshot.nodes}
    sensitivity = {node.id: node.sensitivity.value for node in snapshot.nodes}
    services = {
        node.id: str(node.metadata["service"]).strip().lower()
        if isinstance(node.metadata.get("service"), str) and node.metadata["service"].strip()
        else SERVICE.get(node.type.value, node.type.value.lower())
        for node in snapshot.nodes
        if node.type.value in DATA
    }
    direct: dict[str, set] = defaultdict(set)
    hop: dict[str, set] = defaultdict(set)
    for edge in snapshot.edges:
        source, target, kind = edge.source, edge.target, edge.type.value
        if kind in GRANTS and types[target] in DATA and types[source] not in DATA:
            direct[source].add(target)
        elif kind in HOPS and types[source] not in DATA and types[target] not in DATA and source != target:
            hop[source].add(target)
    used: dict[str, set] = defaultdict(set)
    assumed: dict[str, set] = defaultdict(set)
    active = set()
    for principal, resource, action_class in observed:
        if principal not in types:
            continue
        active.add(principal)
        if resource not in types:
            continue
        if action_class == "assume":
            assumed[principal].add(resource)
        elif types[resource] in DATA:
            used[principal].add(resource)
    observed_hop = {p: assumed[p] & hop[p] for p in list(assumed)}
    assumed_by_any = {role for roles in assumed.values() for role in roles}
    # Attribution: per role, attributed and total session events; per identity, its own use per role.
    session_total: Counter = Counter()
    session_attributed: Counter = Counter()
    attributed_use: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))
    for identity, role, resource, action_class, count in sessions or ():
        if role not in types:
            continue
        session_total[role] += count
        if identity:
            session_attributed[role] += count
            found = attributed_use[identity][role]  # An attributed session of the role, data or not.
            if resource in types and types[resource] in DATA and action_class != "assume":
                found.add(resource)

    def attributed_role(node) -> bool:
        if sessions is None or types[node] != "CloudRole":
            return False
        total = session_total[node]
        return not total or session_attributed[node] >= attribution_share * total

    def identity_use(node, visited, skip) -> set:
        """Own use, own attributed sessions of attributed roles, role-level use of the others."""
        found = set(used[node])
        for v in visited - skip - {node}:
            if not attributed_role(v):
                found |= used[v]
        for role, items in attributed_use.get(node, {}).items():
            if role not in skip and attributed_role(role):
                found |= items
        return found

    def reach(start, adjacency):
        seen, frontier = {start}, [start]
        for _ in range(MAX_HOPS - 1):
            following = []
            for current in frontier:
                for target in adjacency.get(current, ()):
                    if target not in seen:
                        seen.add(target)
                        following.append(target)
            if not following:
                break
            frontier = following
        return seen

    def weight(items):
        return sum(WEIGHTS[sensitivity[item]] for item in items)

    def union(holders):
        return set().union(*(direct[h] for h in holders)) if holders else set()

    holders_of = {}
    for node, kind in types.items():
        if kind == "CloudRole" or kind in PRINCIPALS:
            holders_of[node] = {h for h in reach(node, hop) if h in direct}
    # Peer baseline per holder: same-topic, non-hub holders granted the asset, and how many used it.
    granted_by: Counter = Counter()
    used_by: Counter = Counter()
    for holder, items in direct.items():
        topic = topic_of.get(holder)
        if holder in hubs or topic is None:
            continue
        for item in items:
            granted_by[(topic, item)] += 1
            used_by[(topic, item)] += item in used[holder]
    peer_needed = {}
    for holder, items in direct.items():
        topic = topic_of.get(holder)
        peer_needed[holder] = {
            item
            for item in items
            if topic is not None
            and granted_by[(topic, item)]
            and used_by[(topic, item)] >= share * granted_by[(topic, item)]
        }
    # Identities: same-topic identities that can assume a role directly, and how many did.
    can_assume: Counter = Counter()
    did_assume: Counter = Counter()
    for node, kind in types.items():
        topic = topic_of.get(node)
        if kind not in PRINCIPALS or topic is None:
            continue
        for role in hop.get(node, ()):
            if types[role] == "CloudRole":
                can_assume[(topic, role)] += 1
                did_assume[(topic, role)] += role in assumed.get(node, ())

    def role_inferred(role, core):
        excluded = hubs - {role}
        holders = holders_of[role] - excluded if core else holders_of[role]
        return set().union(*(peer_needed[h] for h in holders)) if holders else set()

    result = {}
    for node, holders in holders_of.items():
        excluded = hubs - {node}
        core = holders - excluded
        granted, granted_core = union(holders), union(core)
        node_services = {services[item] for item in granted} | ({"sts"} if hop.get(node) else set())
        basis = "used" if node_services <= set(sufficient) else "inferred"
        if basis == "used" and sessions is not None and types[node] in PRINCIPALS:
            visited = reach(node, observed_hop)
            needed = identity_use(node, visited, set()) & granted
            needed_core = identity_use(node, visited, excluded) & granted_core
        elif basis == "used":
            visited = reach(node, observed_hop)
            needed = set().union(*(used[v] for v in visited)) & granted
            needed_core = set().union(*(used[v] for v in visited - excluded)) & granted_core
        elif types[node] == "CloudRole":
            needed, needed_core = role_inferred(node, False), role_inferred(node, True)
        else:
            topic = topic_of.get(node)
            roles = [r for r in hop.get(node, ()) if types[r] == "CloudRole"]
            chosen = [
                role
                for role in roles
                if topic is not None
                and can_assume[(topic, role)]
                and did_assume[(topic, role)] >= share * can_assume[(topic, role)]
            ]
            own = peer_needed.get(node, set())
            needed = set(own).union(*(role_inferred(r, False) for r in chosen)) & granted
            needed_core = (
                set(own).union(*(role_inferred(r, True) for r in chosen if r not in hubs)) & granted_core
            )
        dormant = basis == "used" and bool(node_services) and node not in active
        if types[node] in PRINCIPALS and node in attributed_use:
            dormant = False
        if types[node] == "CloudRole":
            dormant = dormant and node not in assumed_by_any
        result[node] = {
            "basis": basis,
            "granted": weight(granted),
            "needed": weight(needed),
            "granted_core": weight(granted_core),
            "needed_core": weight(needed_core),
            "dormant": dormant,
        }
    return result


def epi(granted: int, needed: int):
    return 1 - needed / granted if granted else None


def reference_aggregate(rows) -> dict:
    granted = sum(r["granted"] for r in rows)
    needed = sum(r["needed"] for r in rows)
    granted_core = sum(r["granted_core"] for r in rows)
    needed_core = sum(r["needed_core"] for r in rows)
    return {"epi": epi(granted, needed), "epi_excl_hubs": epi(granted_core, needed_core)}


def close(a, b, tolerance=1e-6) -> bool:
    if a is None or b is None:
        return a is b
    return abs(a - b) <= tolerance


def compare(reference: dict, stored_rows: dict, privilege: dict, topic_privilege: dict, kinds: dict) -> dict:
    """Stored per-member needed weights and aggregates against the reference."""
    mismatched = [
        entity
        for entity, row in stored_rows.items()
        if (row["basis"], row["reach_weight"], row["needed_weight"], row["reach_weight_excl_hubs"],
            row["needed_weight_excl_hubs"])
        != tuple(reference[entity][k] for k in ("basis", "granted", "needed", "granted_core", "needed_core"))
    ]  # fmt: skip
    member_epi_error = max(
        (
            abs((epi(r["reach_weight"], r["needed_weight"]) or 0) - (epi(reference[e]["granted"], reference[e]["needed"]) or 0))
            for e, r in stored_rows.items()
        ),
        default=0.0,
    )  # fmt: skip
    checks = {}
    for kind in ("roles", "identities"):
        members = [reference[e] for e in stored_rows if kinds[e] == kind]
        expected = reference_aggregate(members)
        got = privilege[kind]
        checks[f"graph_{kind}"] = {
            "stored": [got["epi"], got["epi_excl_hubs"]],
            "reference": [expected["epi"], expected["epi_excl_hubs"]],
            "match": close(got["epi"], expected["epi"])
            and close(got["epi_excl_hubs"], expected["epi_excl_hubs"]),
        }
    topic_errors = []
    for topic, (stored_privilege, members) in topic_privilege.items():
        for kind in ("roles", "identities"):
            expected = reference_aggregate([reference[e] for e in members if kinds[e] == kind])
            got = stored_privilege[kind]
            if not (
                close(got["epi"], expected["epi"]) and close(got["epi_excl_hubs"], expected["epi_excl_hubs"])
            ):
                topic_errors.append([topic, kind, got["epi"], expected["epi"]])
    return {
        "members_compared": len(stored_rows),
        "members_mismatched": len(mismatched),
        "mismatched_sample": mismatched[:10],
        "max_member_epi_error": member_epi_error,
        "graph": checks,
        "topics_compared": len(topic_privilege),
        "topic_mismatches": topic_errors[:10],
        "match": not mismatched
        and member_epi_error <= 1e-6
        and all(c["match"] for c in checks.values())
        and not topic_errors,
    }


def stored_state(db, tenant: str, revision: str):
    """Stored role/identity rows, per-topic privilege with member IDs, graph privilege, names."""
    from sqlalchemy import select

    from app.db.models import RevisionTopic, RevisionTopicMember
    from app.graph.topics import HUB, stored_topic_summary

    topics = {
        row.topic_id: (row.name, row.stats if isinstance(row.stats, dict) else json.loads(row.stats))
        for row in db.scalars(
            select(RevisionTopic).where(RevisionTopic.tenant_id == tenant, RevisionTopic.revision == revision)
        )
    }
    members = list(
        db.scalars(
            select(RevisionTopicMember).where(
                RevisionTopicMember.tenant_id == tenant, RevisionTopicMember.revision == revision
            )
        )
    )
    rows, kinds, topic_of, hubs, by_topic = {}, {}, {}, set(), defaultdict(list)
    resource_topic = {}
    for member in members:
        if member.kind == "resource":
            resource_topic[member.entity_id] = topics[member.topic_id][0]
            continue
        rows[member.entity_id] = {
            "basis": member.basis,
            "reach_weight": member.reach_weight,
            "needed_weight": member.needed_weight,
            "reach_weight_excl_hubs": member.reach_weight_excl_hubs,
            "needed_weight_excl_hubs": member.needed_weight_excl_hubs,
            "flags": member.flags,
        }
        kinds[member.entity_id] = "roles" if member.kind == "role" else "identities"
        topic_of[member.entity_id] = member.topic_id or None
        if member.kind == "role" and member.flags & HUB:
            hubs.add(member.entity_id)
        if member.topic_id:
            by_topic[member.topic_id].append(member.entity_id)
    topic_privilege = {topic: (stats["privilege"], by_topic[topic]) for topic, (_, stats) in topics.items()}
    summary = stored_topic_summary(db, tenant, revision)
    return rows, kinds, topic_of, hubs, topic_privilege, summary, resource_topic, topics


def main() -> None:  # noqa: C901 - one linear qualification run
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--database-url", required=True, help="Disposable PostgreSQL (a schema is created)")
    parser.add_argument("--graph-uri", required=True, help="Empty disposable Memgraph bolt URI")
    parser.add_argument("--size", type=int, default=100_000)
    parser.add_argument("--seed", type=int, default=11)
    parser.add_argument(
        "--glue", action="store_true", help="Add Glue databases/tables to the data-lake topic (GLUE_FIXTURE)"
    )
    parser.add_argument(
        "--publish-runs", type=int, default=3, help="Publication pairs (one per arm, ABBA order)"
    )
    parser.add_argument(
        "--overhead-windows",
        type=int,
        default=2,
        # Every publication keeps a 100k revision in Memgraph until the run ends; a third
        # window (19 publications) exceeded a 5.2 GiB Memgraph.
        help="Windows of pairs measured at most (floors over all)",
    )
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--chunk-bytes", type=int, default=3_900_000)
    parser.add_argument("--records-per-file", type=int, default=25_000)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1000 <= args.size <= 100_000 or not 1 <= args.publish_runs <= 6 or not 1 <= args.overhead_windows <= 2:
        parser.error("Size 1000..100000, 1..6 publish runs and 1..2 overhead windows are required")

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
    from qualify_scale import (
        ATTRIBUTION_FIXTURE,
        GLUE_FIXTURE,
        TOPIC_FIXTURE,
        attribution_plan,
        cloudtrail_files,
        cloudtrail_records,
        generate_topics,
        glue_base_size,
        plant_never_assumed,
    )
    from qualify_topics import accuracy, digest, stored_rows
    from sqlalchemy import create_engine, text
    from timing import arm_order, paired, phase_floor

    if not graph_is_empty(args.graph_uri):
        parser.error(f"Graph at {args.graph_uri} is not empty; use a disposable instance")
    snapshot, truth, planted_usage = (
        generate_topics(glue_base_size(args.size), args.seed, glue=True, glue_size=args.size)
        if args.glue
        else generate_topics(args.size, args.seed)
    )
    never_assumed = plant_never_assumed(snapshot, truth, planted_usage)
    plan = attribution_plan(planted_usage)
    schema = "zg_usage_" + uuid4().hex
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
        "fixture": TOPIC_FIXTURE + (" " + GLUE_FIXTURE if args.glue else "") + " " + ATTRIBUTION_FIXTURE,
        "size": args.size,
        "seed": args.seed,
        "nodes": len(snapshot.nodes),
        "edges": len(snapshot.edges),
        "planted": {
            "dormant_identities": len(truth["dormant_identities"]),
            "role_data_used_pairs": sum(len(v) for v in planted_usage["role_data_used"].values()),
            "identity_role_used_pairs": sum(len(v) for v in planted_usage["identity_role_used"].values()),
            "never_assumed_pairs": len(never_assumed),
            "service_session_roles": len(plan["service_roles"]),
            "unattributed_roles": len(plan["unattributed_roles"]),
        },
        "publishes": [],
    }
    api = None
    log = tempfile.NamedTemporaryFile(prefix="zg-qualify-usage-api-", suffix=".log", delete=False)
    try:
        from app.core.config import get_settings

        get_settings.cache_clear()
        config = Config()
        config.set_main_option("script_location", str(BACKEND / "app" / "db" / "migrations"))
        command.upgrade(config, "head")
        from app.db.session import session_factory
        from app.graph import topics, usage
        from app.graph.compact import CompactGraph
        from app.graph.privilege import load_usage
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
        client = httpx.Client(base_url=base, headers={"Authorization": f"Bearer {token}"}, timeout=300)

        def publish(arm: str) -> dict:
            job_id = upload(client, snapshot, args.chunk_bytes)
            worker = run_measured([sys.executable, "-c", WORKER, job_id, arm], env)
            measured = json.loads(worker["stdout"].decode().strip().splitlines()[-1])
            job = client.get(f"/api/v1/ingestions/{job_id}").json()
            phases = measured["phases"]
            entry = {
                "arm": arm,
                "seconds": round(measured["seconds"], 2),
                "topic_seconds": round(
                    phases.get("topics_compute", 0)
                    + phases.get("topics_store", 0)
                    + phases.get("usage_load", 0),
                    3,
                ),
                "analysis_seconds": round(sum(phases.get(name, 0) for name in ANALYSIS_PHASES), 3),
                "worker_peak_rss_mb": round(rss_bytes(measured["maxrss"]) / 2**20, 1),
                "phases_s": phases,
                "job": {"status": job["status"], "node_count": job["node_count"]},
                "revision": client.get("/api/v1/overview").json()["revision"],
            }
            report["publishes"].append(entry)
            args.output.write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps(entry), flush=True)
            return entry

        # 1. A Phase 1 publication (no usage yet), then the planted usage through the upload API.
        first = publish("without")
        end = datetime.now(UTC).replace(microsecond=0) - timedelta(days=1)
        start = end - timedelta(days=91)

        def api_rss_mb() -> float:
            out = subprocess.run(["ps", "-o", "rss=", "-p", str(api.pid)], capture_output=True, text=True)
            return round(int(out.stdout.strip() or 0) / 1024, 1)

        rss_before = api_rss_mb()
        started = time.perf_counter()
        created = client.post(
            "/api/v1/usage/uploads",
            json={
                "window_start": start.isoformat(),
                "window_end": end.isoformat(),
                "attested_services": ["aoss", "rds-data", "s3", "sts", *(["glue"] if args.glue else [])],
            },
        )
        assert created.status_code == 201, created.text
        upload_id = created.json()["id"]
        files = records = size = 0
        peak = rss_before
        generated = cloudtrail_records(snapshot, planted_usage, start, end)
        for number, body in enumerate(cloudtrail_files(generated, args.records_per_file)):
            response = client.put(f"/api/v1/usage/uploads/{upload_id}/files/{number}", content=body)
            assert response.status_code == 200, response.text
            files += 1
            size += len(body)
            records = response.json()["progress"]["records"]
            peak = max(peak, api_rss_mb())
        committed = client.post(f"/api/v1/usage/uploads/{upload_id}/commit")
        assert committed.status_code == 200, committed.text
        ingest_seconds = time.perf_counter() - started
        body = committed.json()
        report["usage_ingest"] = {
            "files": files,
            "records": records,
            "compressed_bytes": size,
            "seconds": round(ingest_seconds, 2),
            "records_per_second": round(records / ingest_seconds),
            "api_rss_mb_before": rss_before,
            "api_rss_mb_peak_sampled": max(peak, api_rss_mb()),
            "stats": {k: v for k, v in body["stats"].items() if k != "coverage"},
            "coverage": body["stats"]["coverage"],
            "evidence": body["evidence"],
        }
        print(json.dumps(report["usage_ingest"]), flush=True)

        # 2. The worker sweep recomputes topics and EPI for the current revision.
        sweep = run_measured([sys.executable, "-c", SWEEP], env)
        measured = json.loads(sweep["stdout"].decode().strip().splitlines()[-1])
        report["recompute_on_upload"] = {
            "seconds": round(measured["seconds"], 2),
            "worker_peak_rss_mb": round(rss_bytes(measured["maxrss"]) / 2**20, 1),
            "results": measured["results"],
        }
        print(json.dumps(report["recompute_on_upload"]), flush=True)
        with session_factory()() as db:
            summary = topics.stored_topic_summary(db, "demo", first["revision"])
            report["recompute_on_upload"]["stored_fingerprint_matches"] = (
                summary.usage_fingerprint == usage.evidence(db, "demo").fingerprint != ""
            )

        # 3. Publication pairs without and with usage (Phase 1 vs Phase 2 publish) in ABBA
        # order, a window of --publish-runs pairs at a time. When the overhead misses a
        # budget, another window is measured (up to --overhead-windows) and the floors
        # are taken over every pair so far: contention from other work on the machine
        # lasts minutes, a regression is in every run (scripts/timing.py).
        pairs: list[tuple[dict, dict]] = []
        windows = []
        for _ in range(args.overhead_windows):
            for order in arm_order(args.publish_runs):
                pair = {arm: publish(arm) for arm in order}
                pairs.append((pair["without"], pair["with"]))
            without = [a for a, _ in pairs]
            enabled = [b for _, b in pairs]
            compute = phase_floor(
                [a["phases_s"] for a in without], [b["phases_s"] for b in enabled], COMPUTE_PHASES
            )
            store = phase_floor([a["phases_s"] for a in without], [b["phases_s"] for b in enabled], STORE_PHASES)
            publish_floor = round(min(b["seconds"] for b in enabled) - min(a["seconds"] for a in without), 2)
            windows.append(
                {
                    "pairs": len(pairs),
                    "compute_floor_seconds": compute["total"],
                    "store_floor_seconds": store["total"],
                    "publish_floor_seconds": publish_floor,
                }
            )
            print(json.dumps(windows[-1]), flush=True)
            if (
                compute["total"] <= COMPUTE_OVERHEAD_BUDGET_S
                and store["total"] <= STORE_OVERHEAD_BUDGET_S
                and publish_floor <= PUBLISH_OVERHEAD_BUDGET_S
            ):
                break
        analysis_median = paired([a["analysis_seconds"] for a in without], [b["analysis_seconds"] for b in enabled])
        publish_median = paired([a["seconds"] for a in without], [b["seconds"] for b in enabled])
        report["overhead"] = {
            "pairs": len(pairs),
            "order": [list(order) for order in arm_order(args.publish_runs)],
            "windows": windows,
            "analysis_phases": list(ANALYSIS_PHASES),
            "budgets_seconds": {
                "compute": COMPUTE_OVERHEAD_BUDGET_S,
                "store": STORE_OVERHEAD_BUDGET_S,
                "publish": PUBLISH_OVERHEAD_BUDGET_S,
            },
            "compute_floor_seconds": compute["total"],
            "store_floor_seconds": store["total"],
            "analysis_floor_seconds": round(compute["total"] + store["total"], 3),
            "analysis_floor_by_phase_seconds": {**compute["phases"], **store["phases"]},
            "publish_floor_seconds": publish_floor,
            # Paired differences (each with-run against the without-run beside it), for context.
            "analysis_deltas_seconds": analysis_median["deltas"],
            "analysis_delta_median_seconds": analysis_median["median"],
            "publish_deltas_seconds": publish_median["deltas"],
            "publish_delta_median_seconds": publish_median["median"],
            "publish_seconds_without": [p["seconds"] for p in without],
            "publish_seconds_with": [p["seconds"] for p in enabled],
            "analysis_seconds_without": [p["analysis_seconds"] for p in without],
            "analysis_seconds_with": [p["analysis_seconds"] for p in enabled],
            "topic_phase_seconds_without": [p["topic_seconds"] for p in without],
            "topic_phase_seconds_with": [p["topic_seconds"] for p in enabled],
            "worker_rss_mb_without": [p["worker_peak_rss_mb"] for p in without],
            "worker_rss_mb_with": [p["worker_peak_rss_mb"] for p in enabled],
            "load_average": list(os.getloadavg()),
        }
        print(json.dumps(report["overhead"]), flush=True)
        enabled = [p for p in report["publishes"] if p["arm"] == "with"]
        if report["publishes"][-1]["arm"] != "with":
            # An even number of ABBA pairs ends without usage; the checks below read the
            # current revision with usage, so publish it once more (not part of a pair).
            enabled.append(publish("with"))
        revision = enabled[-1]["revision"]

        # 4. Accuracy after usage refinement, and EPI against the brute-force reference.
        with session_factory()() as db:
            report["accuracy"] = accuracy(db, "demo", revision, truth)
            rows, kinds, topic_of, hubs, topic_privilege, summary, _, _ = stored_state(db, "demo", revision)
            privilege = summary.totals["privilege"]
            observed_rows = [(p, r, c) for p, r, c, _, _, _ in usage.observed(db, "demo")]
            session_rows = [tuple(row) for row in usage.attributed(db, "demo")]
            attribution_ready = usage.attribution_ready(db, "demo")
            evidence = usage.evidence(db, "demo")
            stored = stored_rows(db, "demo", revision)
        report["privilege"] = {k: v for k, v in privilege.items() if k not in ("evidence",)}
        report["evidence"] = privilege["evidence"]
        print(json.dumps(report["accuracy"]), flush=True)
        print(json.dumps(report["privilege"]), flush=True)
        published = get_graph_store().snapshot("demo", revision)
        started = time.perf_counter()
        reference = reference_privilege(
            published,
            observed_rows,
            evidence.sufficient_services,
            topic_of,
            hubs,
            get_settings().peer_baseline_share,
            sessions=session_rows if attribution_ready else None,
        )
        report["reference_seconds"] = round(time.perf_counter() - started, 2)
        report["epi_used"] = compare(reference, rows, privilege, topic_privilege, kinds)
        print(json.dumps({k: v for k, v in report["epi_used"].items() if k != "graph"}), flush=True)

        # Dormant identities: recall vs planted; none with observed or attributed use.
        active = {p for p, _, _ in observed_rows}
        attributed_identities = {identity for identity, *_ in session_rows if identity}
        dormant = {e for e, row in rows.items() if kinds[e] == "identities" and row["flags"] & topics.DORMANT}
        planted = set(truth["dormant_identities"])
        report["dormant"] = {
            "detected": len(dormant),
            "planted": len(planted),
            "planted_detected": len(dormant & planted),
            "recall": round(len(dormant & planted) / len(planted), 4) if planted else None,
            "with_observed_use": len(dormant & active),
            "with_attributed_use": len(dormant & attributed_identities),
            "note": "Detected dormant includes identities the fixture left without use by chance (no planted label).",
        }
        events = Counter()
        for identity, _, _, _, count in session_rows:
            events["attributed" if identity else "unattributed"] += count
        identity_flags = Counter(
            name
            for e, row in rows.items()
            if kinds[e] == "identities"
            for flag, name in ((topics.ATTRIBUTED, "attributed"), (topics.ROLE_LEVEL, "role_level"))
            if row["flags"] & flag
        )
        report["attribution"] = {
            "ready": attribution_ready,
            "rows": len(session_rows),
            "session_events": dict(events),
            "attributed_share": round(events["attributed"] / max(1, sum(events.values())), 4),
            "identities_by_label": dict(identity_flags),
            "summary": privilege.get("attribution"),
            "ingest": report["usage_ingest"]["stats"].get("attribution"),
        }
        print(json.dumps(report["dormant"]), flush=True)
        print(json.dumps(report["attribution"]), flush=True)

        # 5. In-process recompute: determinism, role-level timing, and the inferred mode.
        graph = CompactGraph.from_snapshot(published)
        runs = []
        from qualify_topics import computed_rows

        with session_factory()() as db:
            for _ in range(2):
                loaded = time.perf_counter()
                usage_input = load_usage(db, "demo", graph)
                load_seconds = time.perf_counter() - loaded
                started = time.perf_counter()
                computed = topics.compute_topics(graph, usage_input)
                runs.append(
                    (
                        digest(computed_rows(computed, "demo", revision)),
                        time.perf_counter() - started,
                        load_seconds,
                        computed.summary["privilege"]["timings_ms"],
                    )
                )
            stale = load_usage(db, "demo", graph, at=datetime.now(UTC) + timedelta(days=30))
            role_level = load_usage(db, "demo", graph, attribution=False)
        report["determinism"] = {
            "recomputed_digests": [d for d, *_ in runs],
            "stored_digest": digest(stored),
            "identical_reruns": runs[0][0] == runs[1][0],
            "stored_equals_recomputed": digest(stored) == runs[0][0],
            "compute_topics_seconds": [round(s, 3) for _, s, _, _ in runs],
            "usage_load_seconds": [round(s, 3) for _, _, s, _ in runs],
            "privilege_timings_ms": [t for *_, t in runs],
        }
        report["role_epi_seconds"] = min(t["role_ms"] for *_, t in runs) / 1000
        report["epi_seconds"] = min(t["total_ms"] for *_, t in runs) / 1000
        print(json.dumps(report["determinism"]), flush=True)
        # Identity EPI with role-level credit only (before attribution) vs attributed (stored).
        before = topics.compute_topics(graph, role_level).summary["privilege"]
        after = computed.summary["privilege"]
        report["identity_epi_attribution"] = {
            "role_level_only": {k: before["identities"][k] for k in ("epi", "epi_excl_hubs", "needed_weight")},
            "attributed": {k: after["identities"][k] for k in ("epi", "epi_excl_hubs", "needed_weight")},
            "granted_weight": after["identities"]["granted_weight"],
            "dormant_identities": {
                "role_level_only": before["dormant_identities"],
                "attributed": after["dormant_identities"],
            },
        }
        print(json.dumps(report["identity_epi_attribution"]), flush=True)
        del before
        # Never-assumed edges: remove_assumption proposals against the planted pairs.
        from app.graph.proposals import TYPES, check_invariant, compute_proposals

        started = time.perf_counter()
        proposed = compute_proposals(computed)
        proposal_seconds = time.perf_counter() - started
        unassume = {
            (graph.ids[p.subject], graph.ids[p.target])
            for p in proposed.proposals
            if TYPES[p.kind] == "remove_assumption"
        }
        tiers = Counter(p.tier for p in proposed.proposals if TYPES[p.kind] == "remove_assumption")
        used_pairs = {(p, r) for p, r, c in observed_rows if c == "assume"} | {
            (identity, role) for identity, role, *_ in session_rows if identity
        }
        planted_pairs = {tuple(pair) for pair in never_assumed}
        report["never_assumed"] = {
            "planted": len(planted_pairs),
            "proposed": len(unassume),
            "planted_proposed": len(unassume & planted_pairs),
            "recall": round(len(unassume & planted_pairs) / len(planted_pairs), 4) if planted_pairs else None,
            "proposed_on_used_pairs": len(unassume & used_pairs),
            "planted_identities_flagged_dormant": len({i for i, _ in planted_pairs} & dormant),
            "all_manual": set(tiers) <= {4},
            "invariant_violations": len(check_invariant(computed, proposed.proposals)),
            "compute_proposals_seconds": round(proposal_seconds, 2),
        }
        print(json.dumps(report["never_assumed"]), flush=True)
        del proposed
        inferred = topics.compute_topics(graph, stale)
        assert not stale.evidence.sufficient_services
        inferred_rows = {}
        for rows_ in (inferred.roles, inferred.identities):
            for node, row in rows_.items():
                inferred_rows[graph.ids[node]] = {
                    "basis": row["basis"],
                    "reach_weight": row["reach_weight"],
                    "needed_weight": row["needed_weight"],
                    "reach_weight_excl_hubs": row["reach_weight_excl_hubs"],
                    "needed_weight_excl_hubs": row["needed_weight_excl_hubs"],
                }
        inferred_topic_of = {
            graph.ids[node]: inferred.topics[row["topic"]].id if row["topic"] >= 0 else None
            for rows_ in (inferred.roles, inferred.identities)
            for node, row in rows_.items()
        }
        inferred_hubs = {graph.ids[node] for node, row in inferred.roles.items() if row["flags"] & topics.HUB}
        inferred_reference = reference_privilege(
            published,
            observed_rows,
            frozenset(),
            inferred_topic_of,
            inferred_hubs,
            get_settings().peer_baseline_share,
        )
        inferred_topics = {}
        for position, stats in enumerate(inferred.topic_stats):
            topic = inferred.topics[position].id
            inferred_topics[topic] = (
                stats["privilege"],
                [e for e, t in inferred_topic_of.items() if t == topic],
            )
        report["epi_inferred"] = compare(
            inferred_reference,
            inferred_rows,
            inferred.summary["privilege"],
            inferred_topics,
            {
                e: ("roles" if graph.types[graph.index[e]] == "CloudRole" else "identities")
                for e in inferred_rows
            },
        )
        report["epi_inferred"]["graph_identities_epi"] = inferred.summary["privilege"]["identities"]["epi"]
        report["epi_inferred"]["basis"] = inferred.summary["privilege"]["identities"]["basis"]
        print(json.dumps({k: v for k, v in report["epi_inferred"].items() if k != "graph"}), flush=True)
        del graph, computed, inferred, published

        # 6. Endpoint latency on the current revision.
        top, detail = [], []
        for _ in range(args.requests):
            elapsed, body = timed_get(client, "/api/v1/graph/topics", {"revision": revision})
            top.append(elapsed)
        for topic in body["topics"]:
            for kind in ("role", "identity"):
                params = {"revision": revision, "kind": kind, "limit": 50}
                detail.append(timed_get(client, f"/api/v1/graph/topics/{topic['id']}", params)[0])
        overview = []
        for _ in range(args.requests):
            elapsed, tile = timed_get(client, "/api/v1/overview")
            overview.append(elapsed)
        report["endpoints"] = {
            "topics_map": percentiles(top),
            "topic_detail_page_50": percentiles(detail),
            "overview": percentiles(overview),
        }
        report["overview_tile"] = tile["excess_privilege"]
        print(json.dumps(report["endpoints"]), flush=True)
        report["memgraph"] = memgraph_storage(args.graph_uri)
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

    accuracy_, overhead = report["accuracy"], report["overhead"]
    report["checks"] = {
        "data_topic_nmi_at_least_0.85": accuracy_["resource_nmi"] >= 0.85,
        "role_topic_accuracy_at_least_0.95": accuracy_["role_topic_accuracy"] >= 0.95,
        "epi_used_matches_reference_1e-6": report["epi_used"]["match"],
        "epi_inferred_matches_reference_1e-6": report["epi_inferred"]["match"],
        "role_epi_at_most_3s": report["role_epi_seconds"] <= 3,
        f"usage_compute_overhead_at_most_{COMPUTE_OVERHEAD_BUDGET_S}s": overhead["compute_floor_seconds"]
        <= COMPUTE_OVERHEAD_BUDGET_S,
        f"usage_store_overhead_at_most_{STORE_OVERHEAD_BUDGET_S}s": overhead["store_floor_seconds"]
        <= STORE_OVERHEAD_BUDGET_S,
        f"publish_overhead_at_most_{PUBLISH_OVERHEAD_BUDGET_S}s": overhead["publish_floor_seconds"]
        <= PUBLISH_OVERHEAD_BUDGET_S,
        "dormant_recall_at_least_0.9": (report["dormant"]["recall"] or 0) >= 0.9,
        "no_dormant_with_observed_use": report["dormant"]["with_observed_use"] == 0,
        "no_dormant_with_attributed_use": report["dormant"]["with_attributed_use"] == 0,
        "attribution_ready": report["attribution"]["ready"],
        "never_assumed_recall_at_least_0.9": (report["never_assumed"]["recall"] or 0) >= 0.9,
        "no_never_assumed_proposal_on_used_pair": report["never_assumed"]["proposed_on_used_pairs"] == 0,
        "never_assumed_proposals_manual": report["never_assumed"]["all_manual"],
        "no_invariant_violations": report["never_assumed"]["invariant_violations"] == 0,
        "recompute_on_upload_stored": report["recompute_on_upload"]["stored_fingerprint_matches"],
        "deterministic_reruns": report["determinism"]["identical_reruns"],
        "stored_rows_equal_recomputed": report["determinism"]["stored_equals_recomputed"],
        "coverage_attested_complete": all(
            row["complete"] for row in report["usage_ingest"]["coverage"] if row["service"] != "ec2"
        ),
        "jobs_completed": all(p["job"]["status"] == "completed" for p in report["publishes"]),
    }
    args.output.write_text(json.dumps(report, indent=2, default=str) + "\n")
    print(json.dumps(report["checks"], indent=2))
    if not all(report["checks"].values()):
        raise SystemExit("Usage qualification failed; inspect the JSON report")


if __name__ == "__main__":
    main()
