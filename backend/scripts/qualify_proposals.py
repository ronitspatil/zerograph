"""Optimizer Phase 3 qualification: least-privilege proposals and what-if on Memgraph and PostgreSQL.

Publishes the planted-topic fixture (``qualify_scale.generate_topics``) with planted
never-auto cases (``qualify_scale.plant_safety_cases``: break-glass, service-linked and
seasonal roles, Condition and Deny policies, KMS keys, dormant break-glass humans,
exposed agents) through the production upload, worker and API processes, uploads the
planted usage as CloudTrail export files through the usage API, lets the worker sweep
recompute topics and proposals, and records:

* high-tier ``remove_grant`` precision and recall against the planted cross-topic
  over-grants of non-hub roles (hub over-grants are wildcard grants: always manual,
  reported separately), and merge recall against the planted near-duplicate roles;
* the invariant: applying every proposal at once loses no observed use or assumption
  (brute force on the published snapshot), plus ``check_invariant`` in process;
* the never-auto list: no planted case, never-auto reason or restructuring type above
  ``manual``;
* proposal generation time in process and in the worker, publish time and worker RSS
  with proposals disabled (Phase 2 behaviour) and enabled, alternating;
* determinism (stored rows equal two in-process recomputations) and accept/reject
  decisions carried forward to the next revision;
* ``POST /proposals/simulate`` and ``/simulate`` with an overlay, ``POST
  /proposals/metrics`` (high tier, 500 IDs, accepted) and list/detail latency;
  metrics are checked against a brute-force recomputation.

App state lives in a disposable schema of ``--database-url``; ``--graph-uri`` must be an
empty, disposable Memgraph, cleared at the end. No cloud services are used.
"""

import argparse
import hashlib
import json
import os
import platform
import random
import secrets
import subprocess
import sys
import tempfile
import time
from collections import Counter
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
from app.graph import proposals
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
timed(tasks, "compute_topics", "topics_compute")
timed(tasks, "store_topics", "topics_store")
if sys.argv[2] == "phase2":
    tasks.compute_proposals_and_store = lambda *args, **kwargs: None
else:
    timed(proposals, "compute_proposals", "proposals_compute")
    timed(proposals, "store_proposals", "proposals_store")
    timed(proposals, "policy_index", "proposals_policies")
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


def chunks(snapshot, limit: int):
    """NDJSON chunks: nodes, edges, then policy attachments."""
    lines = (
        *(json.dumps({"node": n.model_dump(mode="json")}) for n in snapshot.nodes),
        *(json.dumps({"edge": e.model_dump(mode="json")}) for e in snapshot.edges),
        *(json.dumps({"policy": p.model_dump(mode="json")}) for p in snapshot.policies),
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


def upload(client, snapshot, chunk_bytes: int) -> str:
    created = client.post("/api/v1/ingestions/uploads", json={"source": "snapshot"})
    assert created.status_code == 201, created.text
    upload_id = created.json()["id"]
    for number, body in enumerate(chunks(snapshot, chunk_bytes)):
        response = client.put(f"/api/v1/ingestions/uploads/{upload_id}/chunks/{number}", content=body)
        assert response.status_code == 200, response.text
    committed = client.post(f"/api/v1/ingestions/uploads/{upload_id}/commit")
    assert committed.status_code == 202, committed.text
    return committed.json()["id"]


def stored_views(db, tenant: str, revision: str) -> list[dict]:
    from sqlalchemy import select

    from app.db.models import RevisionProposal
    from app.graph.proposals import PROPOSAL_COLUMNS

    views = []
    for row in db.execute(
        select(*(getattr(RevisionProposal, c) for c in PROPOSAL_COLUMNS))
        .where(RevisionProposal.tenant_id == tenant, RevisionProposal.revision == revision)
        .order_by(RevisionProposal.ordinal)
    ):
        view = dict(zip(PROPOSAL_COLUMNS, row, strict=True))
        view["id"] = view["proposal_id"]
        views.append(view)
    return views


def rows_digest(rows) -> str:
    hasher = hashlib.sha256()
    for row in rows:
        hasher.update(json.dumps([row[c] for c in sorted(row) if c not in ("tenant_id", "revision", "id")],
                                 sort_keys=True, default=str).encode())  # fmt: skip
    return hasher.hexdigest()


def computed_views(result, computed, tenant: str, revision: str) -> list[dict]:
    from app.graph.proposals import PROPOSAL_COLUMNS, proposal_rows

    views = []
    for row in proposal_rows(result, computed, tenant, revision):
        view = dict(zip(PROPOSAL_COLUMNS, row, strict=True))
        view["id"] = view["proposal_id"]
        views.append(view)
    return views


def main() -> None:  # noqa: C901 - one linear qualification run
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--graph-uri", required=True)
    parser.add_argument("--size", type=int, default=100_000)
    parser.add_argument("--seed", type=int, default=11)
    parser.add_argument("--publish-runs", type=int, default=2)
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--chunk-bytes", type=int, default=3_900_000)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1000 <= args.size <= 100_000 or not 1 <= args.publish_runs <= 4:
        parser.error("Size 1000..100000 and 1..4 publish runs are required")

    from alembic import command
    from alembic.config import Config
    from proposal_reference import never_auto_violations, observed_access_kept, reference_metrics
    from qualify_clusters import timed_get
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
        SAFETY_CASES,
        TOPIC_FIXTURE,
        cloudtrail_files,
        cloudtrail_records,
        generate_topics,
        plant_safety_cases,
    )
    from sqlalchemy import create_engine, text

    if not graph_is_empty(args.graph_uri):
        parser.error(f"Graph at {args.graph_uri} is not empty; use a disposable instance")
    snapshot, truth, planted_usage = generate_topics(args.size, args.seed)
    cases = plant_safety_cases(snapshot, truth, planted_usage)
    schema = "zg_proposals_" + uuid4().hex
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
    hubs = set(truth["hub_roles"])
    over = {tuple(pair) for pair in truth["over_grants"]}
    over_nonhub = {pair for pair in over if pair[0] not in hubs}
    report: dict = {
        "measured_at": datetime.now(UTC).isoformat(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "graph": "memgraph/memgraph:3.2.0 (Docker via colima)",
        "app_database": "postgresql 16",
        "fixture": TOPIC_FIXTURE,
        "safety_cases": SAFETY_CASES,
        "size": args.size,
        "seed": args.seed,
        "nodes": len(snapshot.nodes),
        "edges": len(snapshot.edges),
        "policies": len(snapshot.policies),
        "planted": {
            "over_grants": len(over),
            "over_grants_non_hub": len(over_nonhub),
            "over_grants_hub": len(over) - len(over_nonhub),
            "duplicate_roles": len(truth["duplicate_of"]),
            "dormant_identities": len(truth["dormant_identities"]),
            "safety_subjects": {k: len(v) for k, v in cases["subjects"].items()},
            "safety_pairs": {k: len(v) for k, v in cases["pairs"].items()},
            "exposed_agents": len(cases["exposed_agents"]),
        },
        "publishes": [],
    }
    api = None
    log = tempfile.NamedTemporaryFile(prefix="zg-qualify-proposals-api-", suffix=".log", delete=False)
    try:
        from app.core.config import get_settings

        get_settings.cache_clear()
        config = Config()
        config.set_main_option("script_location", str(BACKEND / "app" / "db" / "migrations"))
        command.upgrade(config, "head")
        from app.db.session import session_factory
        from app.graph import proposals, topics, usage
        from app.graph.compact import CompactGraph
        from app.graph.policies import policy_index
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

        def save() -> None:
            args.output.write_text(json.dumps(report, indent=2, default=str) + "\n")

        def publish(arm: str) -> dict:
            job_id = upload(client, snapshot, args.chunk_bytes)
            worker = run_measured([sys.executable, "-c", WORKER, job_id, arm], env)
            measured = json.loads(worker["stdout"].decode().strip().splitlines()[-1])
            job = client.get(f"/api/v1/ingestions/{job_id}").json()
            phases = measured["phases"]
            entry = {
                "arm": arm,
                "seconds": round(measured["seconds"], 2),
                "proposal_seconds": round(
                    sum(
                        phases.get(k, 0)
                        for k in ("proposals_compute", "proposals_store", "proposals_policies")
                    ),
                    3,
                ),
                "worker_peak_rss_mb": round(rss_bytes(measured["maxrss"]) / 2**20, 1),
                "phases_s": phases,
                "job": {"status": job["status"], "node_count": job["node_count"]},
                "revision": client.get("/api/v1/overview").json()["revision"],
            }
            report["publishes"].append(entry)
            save()
            print(json.dumps(entry), flush=True)
            return entry

        # 1. A publication without usage, then the planted usage through the upload API and the sweep.
        publish("phase3")
        end = datetime.now(UTC).replace(microsecond=0) - timedelta(days=1)
        start = end - timedelta(days=91)
        created = client.post(
            "/api/v1/usage/uploads",
            json={
                "window_start": start.isoformat(),
                "window_end": end.isoformat(),
                "attested_services": ["aoss", "rds-data", "s3", "sts"],
            },
        )
        assert created.status_code == 201, created.text
        upload_id = created.json()["id"]
        for number, body in enumerate(
            cloudtrail_files(cloudtrail_records(snapshot, planted_usage, start, end))
        ):
            response = client.put(f"/api/v1/usage/uploads/{upload_id}/files/{number}", content=body)
            assert response.status_code == 200, response.text
        committed = client.post(f"/api/v1/usage/uploads/{upload_id}/commit")
        assert committed.status_code == 200, committed.text
        sweep = run_measured([sys.executable, "-c", SWEEP], env)
        measured = json.loads(sweep["stdout"].decode().strip().splitlines()[-1])
        report["recompute_on_upload"] = {
            "seconds": round(measured["seconds"], 2),
            "worker_peak_rss_mb": round(rss_bytes(measured["maxrss"]) / 2**20, 1),
            "results": measured["results"],
        }
        print(json.dumps(report["recompute_on_upload"]), flush=True)

        # 2. Alternating publications: Phase 2 behaviour (no proposals) vs Phase 3.
        for arm in ["phase2", "phase3"] * args.publish_runs:
            publish(arm)
        phase2 = [p for p in report["publishes"][1:] if p["arm"] == "phase2"]
        phase3 = [p for p in report["publishes"][1:] if p["arm"] == "phase3"]
        report["overhead"] = {
            "publish_seconds_phase2": [p["seconds"] for p in phase2],
            "publish_seconds_phase3": [p["seconds"] for p in phase3],
            "publish_delta_min_seconds": round(
                min(p["seconds"] for p in phase3) - min(p["seconds"] for p in phase2), 2
            ),
            "proposal_phase_seconds": [p["proposal_seconds"] for p in phase3],
            "proposal_compute_seconds": [p["phases_s"].get("proposals_compute") for p in phase3],
            "proposal_store_seconds": [p["phases_s"].get("proposals_store") for p in phase3],
            "worker_rss_mb_phase2": [p["worker_peak_rss_mb"] for p in phase2],
            "worker_rss_mb_phase3": [p["worker_peak_rss_mb"] for p in phase3],
        }
        print(json.dumps(report["overhead"]), flush=True)
        revision = phase3[-1]["revision"]
        save()

        # 3. Accuracy, never-auto and invariant on the stored rows.
        with session_factory()() as db:
            views = stored_views(db, "demo", revision)
            summary = proposals.stored_proposal_summary(db, "demo", revision)
            totals = summary.totals
            observed_rows = [(p, r, c) for p, r, c, _, _, _ in usage.observed(db, "demo")]
            model = proposals.load_model(db, "demo", revision)
        high = {
            (v["subject_id"], v["target_id"])
            for v in views
            if v["type"] == "remove_grant" and v["tier"] == "high"
        }
        removals = {(v["subject_id"], v["target_id"]) for v in views if v["type"] == "remove_grant"}
        tp = len(high & over_nonhub)
        merges = {
            tuple(sorted((v["subject_id"], v["target_id"]))) for v in views if v["type"] == "merge_roles"
        }
        found_dups = sum(1 for a, b in truth["duplicate_of"].items() if tuple(sorted((a, b))) in merges)
        wildcard = [v for v in views if v["type"] == "scope_wildcard"]
        report["proposals"] = {
            "total": totals["total"],
            "by_tier": totals["by_tier"],
            "by_type": totals["by_type"],
            "by_type_tier": totals["by_type_tier"],
            "guards": totals["guards"],
            "high_tier_graph": totals["high_tier"]["graph"],
            "high_tier_counts": totals["high_tier"]["counts"],
        }
        report["accuracy"] = {
            "high_remove": len(high),
            "high_true_positive": tp,
            "high_precision": round(tp / len(high), 4) if high else None,
            "high_recall_non_hub": round(tp / len(over_nonhub), 4),
            "all_removals_recall_non_hub": round(len(removals & over_nonhub) / len(over_nonhub), 4),
            "hub_over_grants_covered_by_scope_wildcard": sum(
                v["evidence"]["remove_unused"] for v in wildcard if v["subject_id"] in hubs
            ),
            "high_recall_all_planted_incl_hub": round(len(high & over) / len(over), 4),
            "merge_pairs": len(merges),
            "merge_recall": round(found_dups / len(truth["duplicate_of"]), 4),
            "note": "Hub over-grants are wildcard grants: scope_wildcard proposals, always manual.",
        }
        print(json.dumps(report["accuracy"]), flush=True)
        violations = never_auto_violations(views, cases)
        reasons = Counter(r for v in views for r in v["reasons"])
        planted_pairs = {tuple(p) for values in cases["pairs"].values() for p in values}
        planted_subjects = {s for values in cases["subjects"].values() for s in values}
        report["never_auto"] = {
            "violations": len(violations),
            "violation_ids": violations[:20],
            "reasons": dict(sorted(reasons.items())),
            "planted_pairs_proposed": sum(
                1 for v in views if (v["subject_id"], v["target_id"]) in planted_pairs
            ),
            "planted_subject_proposals": sum(1 for v in views if v["subject_id"] in planted_subjects),
            "above_manual_with_reasons": sum(1 for v in views if v["reasons"] and v["tier"] != "manual"),
            "toxic_proposals": totals["by_type"]["break_toxic_path"],
        }
        print(json.dumps(report["never_auto"]), flush=True)
        everything = proposals.overlay_from(model, range(len(views)))
        data = {n.id for n in snapshot.nodes if n.type.value in ("Database", "VectorStore", "S3Bucket")}
        cut = {pair for pair in everything.removed if pair[1] not in data}
        started = time.perf_counter()
        lost = observed_access_kept(
            snapshot, observed_rows, everything.removed - cut, cut, everything.disabled
        )
        report["invariant"] = {
            "observed_rows": len(observed_rows),
            "removed_pairs_all_proposals": len(everything.removed),
            "disabled_nodes_all_proposals": len(everything.disabled),
            "observed_access_lost": len(lost),
            "examples": lost[:10],
            "brute_force_seconds": round(time.perf_counter() - started, 2),
        }
        print(json.dumps(report["invariant"]), flush=True)
        save()

        # 4. In process: generation time, determinism, check_invariant, metrics vs brute force.
        published = get_graph_store().snapshot("demo", revision)
        graph = CompactGraph.from_snapshot(published)
        runs = []
        with session_factory()() as db:
            findings = proposals.stored_findings(db, "demo", revision)
            policies = policy_index(db, "demo", revision)
            usage_input = load_usage(db, "demo", graph)
        for _ in range(2):
            computed = topics.compute_topics(graph, usage_input)
            started = time.perf_counter()
            result = proposals.compute_proposals(computed, findings, policies)
            seconds = time.perf_counter() - started
            runs.append(
                (
                    rows_digest(computed_views(result, computed, "demo", revision)),
                    seconds,
                    result.summary["timings_ms"],
                )
            )
        stored_digest = rows_digest(views)
        report["determinism"] = {
            "recomputed_digests": [d for d, _, _ in runs],
            "stored_digest": stored_digest,
            "identical_reruns": runs[0][0] == runs[1][0],
            "stored_equals_recomputed": runs[0][0] == stored_digest,
        }
        report["generation"] = {
            "compute_proposals_seconds": [round(s, 3) for _, s, _ in runs],
            "timings_ms": [t for _, _, t in runs],
        }
        report["invariant"]["check_invariant_violations"] = len(
            proposals.check_invariant(computed, result.proposals)
        )
        rows = {
            graph.ids[n]: row for rows_ in (computed.roles, computed.identities) for n, row in rows_.items()
        }
        stored_hubs = {graph.ids[h] for h in computed.context.hubs}
        high_overlay = proposals.overlay_from(model, [i for i, v in enumerate(views) if v["tier"] == "high"])
        cut = {pair for pair in high_overlay.removed if pair[1] not in data}
        started = time.perf_counter()
        reference = reference_metrics(
            published, rows, stored_hubs, high_overlay.removed - cut, cut, high_overlay.disabled
        )
        metric = client.post("/api/v1/proposals/metrics", json={"tier": "high"}).json()
        mismatches = [
            (kind, side, key)
            for kind in ("roles", "identities")
            for side in ("before", "after")
            for key, value in reference[kind][side].items()
            if metric["graph"][kind][side][key] != value
        ]
        report["metrics_reference"] = {
            "high_tier_mismatches": mismatches,
            "match": not mismatches,
            "reference_seconds": round(time.perf_counter() - started, 2),
            "identities_epi_before": metric["graph"]["identities"]["before"]["epi"],
            "identities_epi_after_high": metric["graph"]["identities"]["after"]["epi"],
            "identities_epi_excl_hubs_before": metric["graph"]["identities"]["before"]["epi_excl_hubs"],
            "identities_epi_excl_hubs_after_high": metric["graph"]["identities"]["after"]["epi_excl_hubs"],
            "roles_epi_before": metric["graph"]["roles"]["before"]["epi"],
            "roles_epi_after_high": metric["graph"]["roles"]["after"]["epi"],
        }
        print(json.dumps(report["metrics_reference"]), flush=True)
        del graph, computed, result, published, rows
        save()

        # 5. Endpoint latency.
        rng = random.Random(7)
        by_type: dict[str, list[dict]] = {}
        for v in views:
            by_type.setdefault(v["type"], []).append(v)
        sample = rng.sample(by_type["remove_grant"], min(60, len(by_type["remove_grant"])))
        for kind in ("disable_identity", "disable_role", "scope_wildcard", "break_toxic_path"):
            sample += rng.sample(
                by_type.get(kind, []), min(10 if kind != "scope_wildcard" else 3, len(by_type.get(kind, [])))
            )
        simulate = []
        for v in sample:
            started = time.perf_counter()
            response = client.post(
                "/api/v1/proposals/simulate", json={"proposal_ids": [v["id"]], "revision": revision}
            )
            simulate.append(time.perf_counter() - started)
            assert response.status_code == 200, response.text
        sets = []
        identities = [v["evidence"].get("identities_sample", []) for v in by_type["remove_grant"]]
        sources = [s[0] for s in identities if s][:20]
        for source in sources:
            chosen = rng.sample(by_type["remove_grant"], 50)
            started = time.perf_counter()
            response = client.post(
                "/api/v1/simulate",
                json={"node_id": source, "include_uncertain": True, "revision": revision,
                      "overlay": {"proposal_ids": [v["id"] for v in chosen]}},
            )  # fmt: skip
            sets.append(time.perf_counter() - started)
            assert response.status_code == 200, response.text
        for v in rng.sample(by_type["remove_grant"], 5):
            client.post(f"/api/v1/proposals/{v['id']}/decision", json={"state": "accepted"})
        metrics = {"tier_high": [], "ids_500": [], "accepted": []}
        ids = [v["id"] for v in views]
        cold = None
        for _ in range(args.requests):
            for name, body in (
                ("tier_high", {"tier": "high"}),
                ("ids_500", {"proposal_ids": rng.sample(ids, 500)}),
                ("accepted", {"decision": "accepted"}),
            ):
                started = time.perf_counter()
                response = client.post("/api/v1/proposals/metrics", json=body)
                elapsed = time.perf_counter() - started
                assert response.status_code == 200, response.text
                metrics[name].append(elapsed)
                if cold is None:
                    cold = elapsed
        listing, detail = [], []
        for position in range(args.requests):
            params = [
                {},
                {"tier": "high"},
                {"type": "merge_roles"},
                {"tier": "manual", "type": "remove_grant"},
            ][position % 4]
            listing.append(timed_get(client, "/api/v1/proposals", {**params, "limit": 50})[0])
        for v in rng.sample(views, min(args.requests, len(views))):
            detail.append(timed_get(client, f"/api/v1/proposals/{v['id']}")[0])
        report["endpoints"] = {
            "proposals_simulate_one": percentiles(simulate),
            "simulate_overlay_50_proposals": percentiles(sets),
            "metrics_tier_high": percentiles(metrics["tier_high"]),
            "metrics_500_ids": percentiles(metrics["ids_500"]),
            "metrics_accepted": percentiles(metrics["accepted"]),
            "metrics_first_request_cold_model_ms": round(cold * 1000, 1),
            "list_page_50": percentiles(listing),
            "detail": percentiles(detail),
        }
        print(json.dumps(report["endpoints"]), flush=True)
        save()

        # 6. Decisions carry forward to the next revision by ID.
        accepted = [v["id"] for v in rng.sample(by_type["remove_grant"], 3)]
        rejected = [v["id"] for v in rng.sample(by_type["merge_roles"], 2)]
        for proposal in accepted:
            assert (
                client.post(f"/api/v1/proposals/{proposal}/decision", json={"state": "accepted"}).status_code
                == 200
            )
        for proposal in rejected:
            assert (
                client.post(f"/api/v1/proposals/{proposal}/decision", json={"state": "rejected"}).status_code
                == 200
            )
        before_counts = client.get("/api/v1/proposals/summary").json()["decisions"]
        later = publish("phase3")["revision"]
        carried = [client.get(f"/api/v1/proposals/{p}").json()["proposal"] for p in accepted + rejected]
        report["decisions"] = {
            "before": before_counts,
            "after_next_revision": client.get("/api/v1/proposals/summary").json()["decisions"],
            "new_revision": later != revision,
            "carried": all(
                c["decision"]
                and c["decision"]["state"] == ("accepted" if c["id"] in accepted else "rejected")
                for c in carried
            ),
            "stale": [c["id"] for c in carried if c["decision"] and c["decision"]["stale"]],
        }
        with session_factory()() as db:
            report["determinism"]["ids_identical_next_revision"] = [v["id"] for v in views] == [
                v["id"] for v in stored_views(db, "demo", later)
            ]
            report["determinism"]["rows_identical_next_revision"] = stored_digest == rows_digest(
                stored_views(db, "demo", later)
            )
        print(json.dumps(report["decisions"]), flush=True)
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

    accuracy, endpoints = report["accuracy"], report["endpoints"]
    report["checks"] = {
        "high_precision_at_least_0.9": (accuracy["high_precision"] or 0) >= 0.9,
        "high_recall_at_least_0.9": accuracy["high_recall_non_hub"] >= 0.9,
        "merge_recall_at_least_0.85": accuracy["merge_recall"] >= 0.85,
        "no_observed_access_removed": report["invariant"]["observed_access_lost"] == 0
        and report["invariant"]["check_invariant_violations"] == 0,
        "never_auto_only_manual": report["never_auto"]["violations"] == 0,
        "generation_at_most_5s": max(report["generation"]["compute_proposals_seconds"]) <= 5,
        "simulate_overlay_p95_under_1s": endpoints["proposals_simulate_one"]["p95_ms"] < 1000
        and endpoints["simulate_overlay_50_proposals"]["p95_ms"] < 1000,
        "metrics_p95_under_500ms": all(
            endpoints[k]["p95_ms"] < 500 for k in ("metrics_tier_high", "metrics_500_ids", "metrics_accepted")
        ),
        "metrics_match_brute_force": report["metrics_reference"]["match"],
        "deterministic_reruns": report["determinism"]["identical_reruns"],
        "stored_rows_equal_recomputed": report["determinism"]["stored_equals_recomputed"],
        "ids_identical_next_revision": report["determinism"]["ids_identical_next_revision"],
        "decisions_carried_forward": report["decisions"]["carried"] and report["decisions"]["new_revision"],
        "jobs_completed": all(p["job"]["status"] == "completed" for p in report["publishes"]),
    }
    args.output.write_text(json.dumps(report, indent=2, default=str) + "\n")
    print(json.dumps(report["checks"], indent=2))
    if not all(report["checks"].values()):
        raise SystemExit("Proposal qualification failed; inspect the JSON report")


if __name__ == "__main__":
    main()
