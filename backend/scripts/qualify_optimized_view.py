"""Optimizer Phase 5 qualification: current vs optimized views on Memgraph and PostgreSQL.

Publishes the planted-topic fixture (``qualify_scale.generate_topics`` with the planted
never-auto cases) through the production upload, worker and API processes, uploads the
planted usage through the usage API, lets the worker sweep recompute topics and proposals,
accepts one tier+topic group through the bulk decision API, and records:

* latency (p50/p95/p99 over ``--requests`` requests each) of the bounded optimized-view
  endpoints: ``GET /graph/topics/{id}/subgraph``, ``POST /proposals/overlay`` (high tier,
  accepted and a 200-ID custom set, on topic subgraphs and on explorer slices),
  ``POST /proposals/links`` (high tier, accepted), ``GET /proposals/overview``, the bulk
  decision, and ``GET /graph/topics`` for reference;
* overlay correctness: on every measured slice, the removed edges and disabled nodes equal
  the stored proposals' own changes (``remove_grant`` / ``cut_hop`` / ``disable_node``)
  restricted to the slice, every removed edge is an edge of the slice, and the totals
  equal ``POST /proposals/metrics`` counts;
* topic links: the model's link count equals the stored topic links, and the removed
  cross-topic grants per link equal a brute-force count over the proposals' changes;
* the overview: after-accepted equals ``/proposals/metrics`` with ``decision=accepted``,
  after-high equals the stored high-tier summary.

App state lives in a disposable schema of ``--database-url``; ``--graph-uri`` must be an
empty, disposable Memgraph, cleared at the end. No cloud services are used.
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
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND / "scripts"))

WORKER = """
import json, sys, time
from loguru import logger
logger.remove()
from app.collectors import tasks
started = time.perf_counter()
tasks.process_job(sys.argv[1])
print(json.dumps({"seconds": time.perf_counter() - started}))
"""

SWEEP = """
import json, time
from loguru import logger
logger.remove()
from app.graph import topics
started = time.perf_counter()
results = topics.backfill_missing()
print(json.dumps({"seconds": time.perf_counter() - started, "results": results}))
"""


def timed(call):
    started = time.perf_counter()
    response = call()
    elapsed = time.perf_counter() - started
    assert response.status_code == 200, response.text[:500]
    return elapsed, response.json()


def main() -> None:  # noqa: C901 - one linear qualification run
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--graph-uri", required=True)
    parser.add_argument("--size", type=int, default=100_000)
    parser.add_argument("--seed", type=int, default=11)
    parser.add_argument("--requests", type=int, default=60)
    parser.add_argument("--chunk-bytes", type=int, default=3_900_000)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1000 <= args.size <= 100_000 or not 10 <= args.requests <= 1000:
        parser.error("Size 1000..100000 and 10..1000 requests are required")

    from alembic import command
    from alembic.config import Config
    from proposal_reference import structure
    from qualify_proposals import upload
    from qualify_publication import (
        clear_graph,
        free_port,
        graph_is_empty,
        percentiles,
        rss_bytes,
        run_measured,
    )
    from qualify_scale import (
        TOPIC_FIXTURE,
        cloudtrail_files,
        cloudtrail_records,
        generate_topics,
        plant_safety_cases,
    )
    from sqlalchemy import create_engine, select, text

    if not graph_is_empty(args.graph_uri):
        parser.error(f"Graph at {args.graph_uri} is not empty; use a disposable instance")
    snapshot, truth, planted_usage = generate_topics(args.size, args.seed)
    plant_safety_cases(snapshot, truth, planted_usage)
    _, direct, hops = structure(snapshot)
    schema = "zg_optimized_" + uuid4().hex
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
        "app_database": "postgresql 16",
        "fixture": TOPIC_FIXTURE,
        "size": args.size,
        "seed": args.seed,
        "nodes": len(snapshot.nodes),
        "edges": len(snapshot.edges),
        "requests_per_endpoint": args.requests,
    }
    api = None
    log = tempfile.NamedTemporaryFile(prefix="zg-qualify-optimized-api-", suffix=".log", delete=False)
    rng = random.Random(args.seed)
    try:
        from app.core.config import get_settings

        get_settings.cache_clear()
        config = Config()
        config.set_main_option("script_location", str(BACKEND / "app" / "db" / "migrations"))
        command.upgrade(config, "head")
        from app.db.models import RevisionTopicLink, RevisionTopicMember
        from app.db.session import session_factory
        from app.graph import optimized
        from app.graph import proposals as P
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

        # 1. Publish, upload the planted usage, recompute topics and proposals.
        job_id = upload(client, snapshot, args.chunk_bytes)
        worker = run_measured([sys.executable, "-c", WORKER, job_id], env)
        report["publish_seconds"] = round(
            json.loads(worker["stdout"].decode().strip().splitlines()[-1])["seconds"], 2
        )
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
        assert client.post(f"/api/v1/usage/uploads/{upload_id}/commit").status_code == 200
        sweep = run_measured([sys.executable, "-c", SWEEP], env)
        report["recompute_seconds"] = round(
            json.loads(sweep["stdout"].decode().strip().splitlines()[-1])["seconds"], 2
        )
        revision = client.get("/api/v1/overview").json()["revision"]
        summary = client.get("/api/v1/proposals/summary").json()
        report["revision"] = revision
        report["proposals"] = {"total": summary["total"], "by_tier": summary["by_tier"]}
        save()

        # Every proposal's own changes (the reference), from the stored rows.
        with session_factory()() as db:
            rows = list(
                db.execute(
                    select(
                        P.RevisionProposal.proposal_id,
                        P.RevisionProposal.tier,
                        P.RevisionProposal.topic_id,
                        P.RevisionProposal.type,
                        P.RevisionProposal.changes,
                    ).where(P.RevisionProposal.tenant_id == "demo", P.RevisionProposal.revision == revision)
                )
            )
            stored_links = {
                (row.source_id, row.target_id): row.weight
                for row in db.scalars(
                    select(RevisionTopicLink).where(
                        RevisionTopicLink.tenant_id == "demo", RevisionTopicLink.revision == revision
                    )
                )
            }
            topic_of = dict(
                db.execute(
                    select(RevisionTopicMember.entity_id, RevisionTopicMember.topic_id).where(
                        RevisionTopicMember.tenant_id == "demo", RevisionTopicMember.revision == revision
                    )
                ).all()
            )
            model = P.load_model(db, "demo", revision)
            assets = optimized.resource_topics(db, "demo", revision, model)

        def reference(selected):
            removed, cut, disabled = set(), set(), set()
            for row in selected:
                for change in row.changes:
                    if change["op"] == "remove_grant":
                        removed.add((change["source"], change["target"]))
                    elif change["op"] == "cut_hop":
                        cut.add((change["source"], change["target"]))
                    elif change["op"] == "disable_node":
                        disabled.add(change["node"])
            return removed, cut, disabled

        high_rows = [r for r in rows if r.tier == "high"]
        high_ref = reference(high_rows)

        # 2. Accept one tier+topic group in bulk (the largest high-tier topic, at most 500).
        topic_counts = Counter(r.topic_id for r in high_rows if r.topic_id)
        topic, _ = topic_counts.most_common(1)[0]
        group = sorted(r.proposal_id for r in high_rows if r.topic_id == topic)[:500]
        bulk_ms, bulk = timed(
            lambda: client.post(
                "/api/v1/proposals/decisions",
                json={
                    "proposal_ids": group,
                    "state": "accepted",
                    "tier": "high",
                    "topic_id": topic,
                    "revision": revision,
                },
            )
        )
        mixed = client.post(
            "/api/v1/proposals/decisions",
            json={
                "proposal_ids": [group[0], next(r.proposal_id for r in high_rows if r.topic_id != topic)],
                "state": "accepted",
                "tier": "high",
                "topic_id": topic,
            },
        )
        accepted_ids = set(group)
        accepted_ref = reference([r for r in rows if r.proposal_id in accepted_ids])
        report["bulk_accept"] = {
            "topic_id": topic,
            "proposals": len(group),
            "decided": bulk["decided"],
            "ms": round(bulk_ms * 1000, 1),
            "mixed_topic_rejected_422": mixed.status_code == 422,
        }
        custom_rows = rng.sample(high_rows, min(200, len(high_rows)))
        custom_ids = [r.proposal_id for r in custom_rows]
        custom_ref = reference(custom_rows)
        # The reference reads each row's listed changes (at most MAX_CHANGES per row): the
        # rows of the measured sets must list all of theirs.
        measured_ids = {r.proposal_id for r in high_rows} | accepted_ids | set(custom_ids)
        truncated_rows = sum(
            1 for r in rows if r.proposal_id in measured_ids and len(r.changes) >= P.MAX_CHANGES
        )
        truncated_any = sum(1 for r in rows if len(r.changes) >= P.MAX_CHANGES)
        save()

        # 3. Slices: topic subgraphs (every topic in turn) and explorer views (sample and neighborhoods).
        topics = [t["id"] for t in client.get("/api/v1/graph/topics?edge_limit=1").json()["topics"]]
        latency: dict[str, list[float]] = {
            k: []
            for k in (
                "topic_subgraph",
                "overlay_high_topic_slice",
                "overlay_accepted_topic_slice",
                "overlay_custom_topic_slice",
                "overlay_high_explorer_slice",
                "links_high",
                "links_accepted",
                "overview",
                "topics_map",
            )
        }
        mismatches: list[dict] = []
        slices_checked = 0
        removed_shown = Counter()
        not_edges = 0
        metrics = {
            name: client.post("/api/v1/proposals/metrics", json=body).json()["counts"]
            for name, body in (
                ("high", {"tier": "high"}),
                ("accepted", {"decision": "accepted"}),
                ("custom", {"proposal_ids": custom_ids}),
            )
        }
        totals_match = True

        def check(name: str, body: dict, ids: list[str], ref, edges: set | None) -> None:
            nonlocal slices_checked, not_edges, totals_match
            inside = set(ids)
            removed, cut, disabled = ref
            got_grants = {(e["source"], e["target"]) for e in body["removed_edges"] if e["kind"] == "grant"}
            got_hops = {(e["source"], e["target"]) for e in body["removed_edges"] if e["kind"] == "hop"}
            expected = (
                {p for p in removed if set(p) <= inside},
                {p for p in cut if set(p) <= inside},
                disabled & inside,
            )
            if (got_grants, got_hops, set(body["disabled_nodes"])) != expected:
                mismatches.append({"set": name, "grants": len(got_grants), "expected": len(expected[0])})
            not_edges += sum(1 for s, t in got_grants if t not in direct.get(s, ()))
            not_edges += sum(1 for s, t in got_hops if t not in hops.get(s, ()))
            if edges is not None:
                not_edges += sum(1 for pair in got_grants | got_hops if pair not in edges)
            removed_shown[name] += len(got_grants) + len(got_hops)
            for key in ("grants_removed", "restricted_grants_removed", "hops_cut", "disabled_nodes"):
                totals_match &= body["totals"][key] == metrics[name.split("_")[0]][key]
            slices_checked += 1

        for position in range(args.requests):
            topic_id = topics[position % len(topics)]
            elapsed, sub = timed(
                lambda topic_id=topic_id: client.get(
                    f"/api/v1/graph/topics/{topic_id}/subgraph", params={"revision": revision}
                )
            )
            latency["topic_subgraph"].append(elapsed)
            ids = [n["id"] for n in sub["nodes"]]
            edges = {(e["source"], e["target"]) for e in sub["edges"]}
            for name, selection, ref in (
                ("high", {"tier": "high"}, high_ref),
                ("accepted", {"decision": "accepted"}, accepted_ref),
                ("custom", {"proposal_ids": custom_ids}, custom_ref),
            ):
                elapsed, body = timed(
                    lambda selection=selection, ids=ids: client.post(
                        "/api/v1/proposals/overlay", json={**selection, "node_ids": ids, "revision": revision}
                    )
                )
                latency[f"overlay_{name}_topic_slice"].append(elapsed)
                check(name, body, ids, ref, edges)
        # Explorer slices: the bounded initial view and neighborhoods of high-tier subjects.
        roots = [None] + [
            r.changes[0].get("source") or r.changes[0].get("node")
            for r in rng.sample(high_rows, args.requests - 1)
            if r.changes
        ]
        for root in roots[: args.requests]:
            params = {"node_limit": 250, "edge_limit": 2000, "revision": revision}
            if root:
                params["root_id"] = root
            explored = client.get("/api/v1/graph/explore", params=params).json()
            ids = [n["id"] for n in explored["nodes"]]
            edges = {(e["source"], e["target"]) for e in explored["edges"]}
            elapsed, body = timed(
                lambda ids=ids: client.post(
                    "/api/v1/proposals/overlay", json={"tier": "high", "node_ids": ids, "revision": revision}
                )
            )
            latency["overlay_high_explorer_slice"].append(elapsed)
            check("high_explorer", body, ids, high_ref, None)
            # Removed edges shown must be edges the explorer returned when both ends are visible.
            got = {(e["source"], e["target"]) for e in body["removed_edges"]}
            not_edges += len(got - edges) if len(explored["edges"]) < 2000 else 0
        for position in range(args.requests):
            name, selection = (("high", {"tier": "high"}), ("accepted", {"decision": "accepted"}))[
                position % 2
            ]
            elapsed, body = timed(
                lambda selection=selection: client.post(
                    "/api/v1/proposals/links", json={**selection, "revision": revision}
                )
            )
            latency[f"links_{name}"].append(elapsed)
            latency["overview"].append(timed(lambda: client.get("/api/v1/proposals/overview"))[0])
            latency["topics_map"].append(
                timed(lambda: client.get("/api/v1/graph/topics", params={"edge_limit": 1000}))[0]
            )
        report["latency"] = {name: percentiles(values) for name, values in latency.items()}
        report["samples_ms"] = {
            name: [round(v * 1000, 1) for v in values] for name, values in latency.items()
        }
        print(json.dumps(report["latency"]), flush=True)

        # 4. Links: the model's counts equal the stored map; removals equal a brute-force count.
        names = model.topics
        model_links = {
            tuple(sorted((names[a][0], names[b][0]))): v
            for (a, b), v in optimized.topic_links(model, assets).items()
        }
        hubs = {model.ids[h] for h in model.hubs}

        def brute(ref) -> dict:
            removed, _, disabled = ref
            found: Counter = Counter()
            for holder, items in [(h, direct.get(h, ())) for h in disabled] + [
                (h, [i]) for h, i in removed if h not in disabled
            ]:
                own = topic_of.get(holder, "")
                if holder in hubs or not own:
                    continue
                for item in items:
                    other = topic_of.get(item, "")
                    if other and other != own:
                        found[tuple(sorted((own, other)))] += 1
            return dict(found)

        links_high = client.post("/api/v1/proposals/links", json={"tier": "high"}).json()
        links_accepted = client.post("/api/v1/proposals/links", json={"decision": "accepted"}).json()
        high_metrics = client.post("/api/v1/proposals/metrics", json={"tier": "high"}).json()
        accepted_metrics = client.post("/api/v1/proposals/metrics", json={"decision": "accepted"}).json()
        overview = client.get("/api/v1/proposals/overview").json()
        report["links"] = {
            "model_equals_stored": model_links == stored_links,
            "stored_links": len(stored_links),
            "high_removed_equals_brute_force": {
                (x["source"], x["target"]): x["removed"] for x in links_high["links"]
            }
            == brute(high_ref),
            "accepted_removed_equals_brute_force": {
                (x["source"], x["target"]): x["removed"] for x in links_accepted["links"]
            }
            == brute(accepted_ref),
            "high_cross_topic_grants_removed": sum(x["removed"] for x in links_high["links"]),
            "cross_topic_grants": sum(stored_links.values()),
            "topics_equal_metrics": links_high["topics"] == high_metrics["topics"],
        }
        report["overview"] = {
            "after_accepted_equals_metrics": overview["after_accepted"]["identities"]
            == accepted_metrics["graph"]["identities"]["after"]
            and overview["after_accepted"]["roles"] == accepted_metrics["graph"]["roles"]["after"],
            "after_high_equals_summary": overview["after_high"]["identities"]
            == summary["high_tier"]["graph"]["identities"]["after"],
            "identity_epi": {
                "now": overview["now"]["identities"]["epi"],
                "after_accepted": overview["after_accepted"]["identities"]["epi"],
                "after_high": overview["after_high"]["identities"]["epi"],
                "now_excl_hubs": overview["now"]["identities"]["epi_excl_hubs"],
                "after_high_excl_hubs": overview["after_high"]["identities"]["epi_excl_hubs"],
            },
            "dormant_identities": overview["dormant_identities"],
            "unused_restricted_grants": overview["unused_restricted_grants"],
            "rollout": overview["rollout"],
        }
        report["overlay"] = {
            "slices_checked": slices_checked,
            "mismatches": mismatches[:20],
            "mismatch_count": len(mismatches),
            "removed_edges_not_in_slice_edges": not_edges,
            "totals_equal_metrics": totals_match,
            "removed_edges_shown": dict(removed_shown),
            "rows_with_truncated_change_lists": truncated_rows,
            "rows_with_truncated_change_lists_outside_sets": truncated_any - truncated_rows,
        }
        save()
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

    latency = report["latency"]
    bounded = (
        "topic_subgraph",
        "overlay_high_topic_slice",
        "overlay_accepted_topic_slice",
        "overlay_custom_topic_slice",
        "overlay_high_explorer_slice",
        "links_high",
        "links_accepted",
        "overview",
    )
    report["checks"] = {
        "optimized_view_endpoints_p95_under_300ms": all(latency[k]["p95_ms"] < 300 for k in bounded),
        "overlay_equals_proposal_changes_in_slice": report["overlay"]["mismatch_count"] == 0
        and report["overlay"]["slices_checked"] > 0
        and report["overlay"]["rows_with_truncated_change_lists"] == 0,
        "removed_edges_are_slice_edges": report["overlay"]["removed_edges_not_in_slice_edges"] == 0,
        "overlay_totals_equal_metrics": report["overlay"]["totals_equal_metrics"],
        "overlay_shows_removals": report["overlay"]["removed_edges_shown"].get("high", 0) > 0,
        "links_match_map_and_brute_force": report["links"]["model_equals_stored"]
        and report["links"]["high_removed_equals_brute_force"]
        and report["links"]["accepted_removed_equals_brute_force"]
        and report["links"]["topics_equal_metrics"],
        "overview_matches_metrics": report["overview"]["after_accepted_equals_metrics"]
        and report["overview"]["after_high_equals_summary"],
        "bulk_accept_within_tier_topic": report["bulk_accept"]["decided"] == len(group)
        and report["bulk_accept"]["mixed_topic_rejected_422"],
    }
    args.output.write_text(json.dumps(report, indent=2, default=str) + "\n")
    print(json.dumps(report["checks"], indent=2))
    if not all(report["checks"].values()):
        raise SystemExit("Optimized-view qualification failed; inspect the JSON report")


if __name__ == "__main__":
    main()
