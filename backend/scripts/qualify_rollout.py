"""Optimizer Phase 4 qualification: proposal pull requests, canary rollout and rollback.

Publishes the planted-topic fixture (``qualify_scale.generate_topics`` with the planted
never-auto cases and ``plant_role_policies``: an inline identity policy per role) on
Memgraph and PostgreSQL through the production upload, worker and API processes, uploads
the planted usage as CloudTrail exports and lets the sweep compute topics and proposals.
Then:

1. accepts the high-tier ``remove_grant`` / ``disable_*`` proposals of a sample of
   principals across topics (through the API);
2. **diff correctness**: plans every accepted principal (``rollout.plan_change``) and
   re-evaluates every grant edge of each touched principal with ``iam_evaluator``
   before and after the diff (``rollout_reference.verify_diffs``): exactly the removed
   grants go, nothing else changes, nothing widens;
3. **rollout API** in process against a local fake Git provider (``tests/fake_git.py``,
   ``httpx.MockTransport``; no network): changes per role, canary per topic, held
   changes refused, merged -> watch -> verified (the watch is advanced by moving
   ``merged_at`` back in the database), a topic bundle, a byte-for-byte revert, and an
   AccessDenied upload that flags a merged canary and auto-opens (never merges) its revert;
4. **round trip**: publishes the snapshot a collector would see after applying every
   generated diff and compares its what-if model to the original model's "after" state.

App state lives in a disposable schema of ``--database-url``; ``--graph-uri`` must be an
empty, disposable Memgraph, cleared at the end. No cloud or Git provider is contacted.
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
sys.path.insert(0, str(BACKEND / "tests"))

WORKER = """
import json, resource, sys, time
from loguru import logger
logger.remove()
from app.collectors import tasks
started = time.perf_counter()
tasks.process_job(sys.argv[1])
print(json.dumps({"seconds": time.perf_counter() - started,
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


def main() -> None:  # noqa: C901 - one linear qualification run
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--graph-uri", required=True)
    parser.add_argument("--size", type=int, default=100_000)
    parser.add_argument("--seed", type=int, default=11)
    parser.add_argument("--roles-per-topic", type=int, default=10)
    parser.add_argument("--disables", type=int, default=60)
    parser.add_argument("--chunk-bytes", type=int, default=3_900_000)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1000 <= args.size <= 100_000:
        parser.error("Size 1000..100000 is required")

    from alembic import command
    from alembic.config import Config
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
        ROLE_POLICIES,
        SAFETY_CASES,
        TOPIC_FIXTURE,
        cloudtrail_files,
        cloudtrail_records,
        generate_topics,
        plant_role_policies,
        plant_safety_cases,
    )
    from sqlalchemy import create_engine, text

    if not graph_is_empty(args.graph_uri):
        parser.error(f"Graph at {args.graph_uri} is not empty; use a disposable instance")
    snapshot, truth, planted_usage = generate_topics(args.size, args.seed)
    plant_safety_cases(snapshot, truth, planted_usage)
    planted_policies = plant_role_policies(snapshot, truth)
    schema = "zg_rollout_" + uuid4().hex
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
        "git_provider": "local fake (tests/fake_git.py via httpx.MockTransport); no network",
        "fixture": TOPIC_FIXTURE,
        "safety_cases": SAFETY_CASES,
        "role_policies": ROLE_POLICIES,
        "size": args.size,
        "seed": args.seed,
        "nodes": len(snapshot.nodes),
        "edges": len(snapshot.edges),
        "policies": len(snapshot.policies),
        "planted_role_policies": planted_policies,
        "publishes": [],
        "timings": {},
        "checks": {},
    }
    api = None
    log = tempfile.NamedTemporaryFile(prefix="zg-qualify-rollout-api-", suffix=".log", delete=False)

    def save() -> None:
        args.output.write_text(json.dumps(report, indent=2, default=str) + "\n")

    try:
        from app.core.config import get_settings

        get_settings.cache_clear()
        config = Config()
        config.set_main_option("script_location", str(BACKEND / "app" / "db" / "migrations"))
        command.upgrade(config, "head")
        from app.db.session import session_factory
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
        client = httpx.Client(base_url=base, headers={"Authorization": f"Bearer {token}"}, timeout=600)

        def publish(label: str, which) -> str:
            job_id = upload(client, which, args.chunk_bytes)
            worker = run_measured([sys.executable, "-c", WORKER, job_id], env)
            measured = json.loads(worker["stdout"].decode().strip().splitlines()[-1])
            job = client.get(f"/api/v1/ingestions/{job_id}").json()
            revision = client.get("/api/v1/overview").json()["revision"]
            entry = {
                "label": label,
                "seconds": round(measured["seconds"], 2),
                "worker_peak_rss_mb": round(rss_bytes(measured["maxrss"]) / 2**20, 1),
                "job": {"status": job["status"], "node_count": job["node_count"]},
                "revision": revision,
            }
            report["publishes"].append(entry)
            save()
            print(json.dumps(entry), flush=True)
            return revision

        def sweep(label: str) -> None:
            measured = json.loads(
                run_measured([sys.executable, "-c", SWEEP], env)["stdout"].decode().strip().splitlines()[-1]
            )
            report["timings"][f"sweep_{label}_s"] = round(measured["seconds"], 2)

        # 0. Publish, upload planted usage, compute topics and proposals.
        publish("initial", snapshot)
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
        sweep("usage")
        revision = client.get("/api/v1/overview").json()["revision"]
        summary = client.get("/api/v1/proposals/summary").json()
        report["proposals"] = {"total": summary["total"], "by_type_tier": summary["by_type_tier"]}
        print(json.dumps(report["proposals"]), flush=True)

        # 1. Accept high-tier proposals of sampled principals across topics.
        rows, cursor = [], None
        while True:
            params = {"tier": "high", "limit": 200}
            if cursor is not None:
                params["cursor"] = cursor
            page = client.get("/api/v1/proposals", params=params).json()
            rows += page["proposals"]
            cursor = page["view"]["next_cursor"]
            if cursor is None:
                break
        rng = random.Random(args.seed)
        kinds = {node.id: node.type.value for node in snapshot.nodes}
        by_topic: dict[str, dict[str, list[dict]]] = {}
        for row in rows:
            if row["type"] == "remove_grant" and kinds.get(row["subject_id"]) == "CloudRole":
                by_topic.setdefault(row["topic_id"], {}).setdefault(row["subject_id"], []).append(row)
        chosen: list[dict] = []
        sampled_roles: dict[str, list[str]] = {}
        for topic in sorted(by_topic):
            roles = sorted(by_topic[topic])
            rng.shuffle(roles)
            sampled_roles[topic] = sorted(roles[: args.roles_per_topic])
            for role in sampled_roles[topic]:
                chosen += by_topic[topic][role]
        disables = [r for r in rows if r["type"] in ("disable_role", "disable_identity")]
        rng.shuffle(disables)
        chosen += disables[: args.disables]
        accept_times = []
        for row in chosen:
            started = time.perf_counter()
            response = client.post(f"/api/v1/proposals/{row['id']}/decision", json={"state": "accepted"})
            accept_times.append(time.perf_counter() - started)
            assert response.status_code == 200, response.text
        report["accepted"] = {
            "proposals": len(chosen),
            "by_type": dict(Counter(r["type"] for r in chosen)),
            "topics": len(sampled_roles),
            "roles": sum(len(v) for v in sampled_roles.values()),
            "high_tier_available": len(rows),
        }
        report["timings"]["accept_decision"] = percentiles(accept_times)
        print(json.dumps(report["accepted"]), flush=True)
        save()

        # 2. Diff correctness in process: plan every principal, re-evaluate with iam_evaluator.
        from rollout_reference import actual_after, expected_after, round_trip, verify_diffs

        from app.graph import proposals as P
        from app.remediation import rollout

        files, optimized, included, drafts = [], {}, [], []
        plan_times = []
        with session_factory()() as db:
            model = P.load_model(db, "demo", revision)
            for subject in sorted({row["subject_id"] for row in chosen}):
                started = time.perf_counter()
                plan = rollout.plan_change(db, "demo", revision, model, subject=subject)
                plan_times.append(time.perf_counter() - started)
                for planned in plan.files:
                    item = planned.as_dict()
                    item["path"] = f"{subject}/{item['path']}"
                    files.append(item)
                    optimized[item["path"]] = planned.optimized
                included += plan.included
                drafts += plan.drafts
        removed: dict[str, set[str]] = {}
        disabled: set[str] = set()
        for row in included:
            if row.type in rollout.DISABLE_TYPES:
                disabled.add(row.subject_id)
            else:
                removed.setdefault(row.subject_id, set()).add(row.target_id)
        data_ids = [n.id for n in snapshot.nodes if n.type.value in ("S3Bucket", "Database", "VectorStore")]
        probes = random.Random(7).sample(data_ids, 40)
        started = time.perf_counter()
        stats = verify_diffs(snapshot, files, optimized, removed, disabled, probes)
        verify_seconds = time.perf_counter() - started
        report["diff_correctness"] = {
            "accepted": len(chosen),
            "included_in_prs": len(included),
            "included_by_type": dict(Counter(row.type for row in included)),
            "resource_scopings": sum(len(v) for v in removed.values()),
            "disables": len(disabled),
            "draft_only": len(drafts),
            "draft_reasons": dict(Counter(d["reason"].split(":")[0][:80] for d in drafts).most_common(10)),
            "files": len(files),
            "principals_evaluated": stats["principals"],
            "grant_edges_evaluated": stats["edges"],
            "grant_edges_removed": stats["removed_edges"],
            "probe_assets": len(probes),
            "mismatches": len(stats["mismatches"]),
            "mismatch_sample": stats["mismatches"][:5],
            "widened": len(stats["widened"]),
            "verify_seconds": round(verify_seconds, 2),
        }
        report["timings"]["plan_principal"] = percentiles(plan_times)
        print(json.dumps(report["diff_correctness"]), flush=True)
        save()

        # 3. Rollout API in process against the local fake provider.
        import fake_git
        from fastapi.testclient import TestClient
        from pydantic import SecretStr
        from sqlalchemy import select

        from app.api import routes
        from app.db.models import (
            AuditEvent,
            Remediation,
            RevisionPolicy,
            RevisionPolicyDocument,
            RolloutChange,
        )
        from app.graph.schema import canonical_policy
        from app.main import create_app
        from app.remediation.policy_optimizer import render

        repo = fake_git.FakeRepository("github")
        settings = get_settings().model_copy(
            update={
                "git_provider": "github",
                "git_repository": fake_git.REPOSITORY,
                "git_token": SecretStr("secret-token-value"),
                "git_tenant_id": "demo",
            }
        )
        real_client = routes.GitOpsClient
        routes.get_settings = lambda: settings
        routes.GitOpsClient = lambda configured: real_client(configured, repo.transport())
        flow: dict = {}
        times: dict[str, list[float]] = {"create": [], "open_pr": [], "revert": []}
        with TestClient(create_app(), headers={"Authorization": f"Bearer {token}"}) as local:

            def call(method, path, key=None, **kwargs):
                started = time.perf_counter()
                response = local.request(method, "/api/v1" + path, **kwargs)
                if key:
                    times[key].append(time.perf_counter() - started)
                return response

            topics = sorted(sampled_roles, key=lambda t: (-len(sampled_roles[t]), t))[:3]
            changes: dict[str, list[str]] = {}
            for topic in topics:
                changes[topic] = []
                for role in sampled_roles[topic][:3]:
                    response = call("POST", "/rollout/changes", "create", json={"subject_id": role})
                    if response.status_code == 201:
                        changes[topic].append(response.json()["id"])
            canaries, held_refused, opened = {}, 0, 0
            for topic, ids in changes.items():
                response = call("POST", f"/rollout/changes/{ids[0]}/pr", "open_pr")
                assert response.status_code == 200, response.text
                canaries[topic] = ids[0]
                opened += 1
                for other in ids[1:]:
                    refused = call("POST", f"/rollout/changes/{other}/pr")
                    held_refused += (
                        refused.status_code == 409 and "Waiting for canary" in refused.json()["detail"]
                    )
            listing = call("GET", "/rollout").json()
            flow["changes_created"] = sum(len(v) for v in changes.values())
            flow["canary_prs_opened"] = opened
            flow["non_canary_refused_while_canary_open"] = held_refused
            flow["non_canary_expected_refused"] = sum(len(v) - 1 for v in changes.values())
            flow["held_flags_in_listing"] = sum(1 for c in listing["changes"] if c["held"])
            first, second, third = topics
            # Topic 1: canary merged -> refused while watching -> verified after the window -> widen.
            repo.merge(next(i + 1 for i, r in enumerate(repo.reviews) if canaries[first] in r["body"]))
            merged = call("POST", f"/rollout/changes/{canaries[first]}/merged").json()
            flow["merged_watch_remaining_days"] = merged["watch_remaining_days"]
            flow["refused_during_watch"] = (
                call("POST", f"/rollout/changes/{changes[first][1]}/pr").status_code == 409
            )
            with session_factory()() as db:
                db.get(RolloutChange, canaries[first]).merged_at = datetime.now(UTC) - timedelta(days=8)
                db.commit()
            states = {c["id"]: c["state"] for c in call("GET", "/rollout").json()["changes"]}
            flow["canary_verified_after_window"] = states[canaries[first]] == "verified"
            widened = [
                call("POST", f"/rollout/changes/{c}/pr", "open_pr").status_code for c in changes[first][1:]
            ]
            flow["widened_after_verify"] = widened
            # Topic bundle after the verified canary (remaining accepted proposals of topic 1).
            bundle = call("POST", "/rollout/changes", "create", json={"topic_id": first})
            flow["bundle_created"] = bundle.status_code
            if bundle.status_code == 201:
                flow["bundle_principals"] = len(bundle.json()["principals"])
                flow["bundle_pr"] = call(
                    "POST", f"/rollout/changes/{bundle.json()['id']}/pr", "open_pr"
                ).status_code
            bundle2 = call("POST", "/rollout/changes", json={"topic_id": second})
            flow["bundle_before_canary_verified_refused"] = (
                bundle2.status_code == 201
                and call("POST", f"/rollout/changes/{bundle2.json()['id']}/pr").status_code == 409
            )
            # Byte-for-byte revert of topic 1's canary.
            response = call(
                "POST", f"/rollout/changes/{canaries[first]}/revert", "revert", json={"reason": "qualify"}
            )
            assert response.status_code == 200, response.text
            repo.merge(len(repo.reviews))
            identical, compared = 0, 0
            key = hashlib.sha256(b"demo").hexdigest()[:16]
            with session_factory()() as db:
                change = db.get(RolloutChange, canaries[first])
                for item in change.files:
                    record = db.get(Remediation, item["remediation_id"])
                    restored = repo.file(f"{settings.git_policy_prefix}/{key}/{change.id}/{item['path']}")
                    stored = db.scalar(
                        select(RevisionPolicyDocument.document)
                        .join(
                            RevisionPolicy,
                            (RevisionPolicy.digest == RevisionPolicyDocument.digest)
                            & (RevisionPolicy.revision == RevisionPolicyDocument.revision)
                            & (RevisionPolicy.tenant_id == RevisionPolicyDocument.tenant_id),
                        )
                        .where(
                            RevisionPolicy.revision == change.revision,
                            RevisionPolicy.principal_id == item["principal"],
                            RevisionPolicy.name == item["policy_name"],
                        )
                    )
                    compared += 1
                    identical += (
                        restored == render(record.original).encode()
                        and stored is not None
                        and canonical_policy(json.loads(restored)) == stored
                    )
            flow["revert_files_byte_identical"] = [identical, compared]
            flow["rolled_back"] = call("POST", f"/rollout/changes/{canaries[first]}/reverted").json()["state"]
            # Topic 2: canary merged, then AccessDenied on a removed bucket inside the watch window.
            repo.merge(next(i + 1 for i, r in enumerate(repo.reviews) if canaries[second] in r["body"]))
            call("POST", f"/rollout/changes/{canaries[second]}/merged")
            with session_factory()() as db:
                change = db.get(RolloutChange, canaries[second])
                change.merged_at = datetime.now(UTC) - timedelta(hours=3)
                touched = change.summary["touched"]
                db.commit()
            principal = sorted(touched)[0]
            resource = sorted(touched[principal]["removed"])[0]
            when = (datetime.now(UTC) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            event = {
                "eventVersion": "1.09",
                "eventSource": "s3.amazonaws.com",
                "eventName": "GetObject",
                "eventTime": when,
                "awsRegion": "us-east-1",
                "userIdentity": {
                    "type": "AssumedRole",
                    "sessionContext": {"sessionIssuer": {"arn": principal}},
                },
                "requestParameters": {"bucketName": resource, "key": "k"},
                "resources": [{"type": "AWS::S3::Bucket", "ARN": resource}],
                "errorCode": "AccessDenied",
                "recipientAccountId": "123456789012",
            }
            now_ = datetime.now(UTC).replace(microsecond=0)
            created = call(
                "POST",
                "/usage/uploads",
                json={
                    "window_start": (now_ - timedelta(days=1)).isoformat(),
                    "window_end": now_.isoformat(),
                    "attested_services": ["s3"],
                },
            ).json()
            for number, body in enumerate(cloudtrail_files([event] * 3)):
                call("PUT", f"/usage/uploads/{created['id']}/files/{number}", content=body)
            reviews_before = len(repo.reviews)
            started = time.perf_counter()
            committed = call("POST", f"/usage/uploads/{created['id']}/commit").json()
            report["timings"]["usage_commit_with_access_denied_watch_s"] = round(
                time.perf_counter() - started, 3
            )
            flow["access_denied_flagged"] = committed["rollout"]["flagged"] == [canaries[second]]
            flow["access_denied_revert_url"] = (committed["rollout"]["reverts"] or [{}])[0].get("url")
            flow["access_denied_revert_is_open_draft_not_merged"] = (
                len(repo.reviews) == reviews_before + 1
                and repo.reviews[-1]["draft"]
                and not repo.reviews[-1]["_merged"]
            )
            states = {c["id"]: c for c in call("GET", "/rollout").json()["changes"]}
            flow["flagged_state"] = states[canaries[second]]["state"]
            # Topic 3: canary still open; its other changes stay held.
            flow["topic3_still_held"] = all(states[c]["held"] for c in changes[third][1:])
            with session_factory()() as db:
                actions = Counter(
                    db.scalars(select(AuditEvent.action).where(AuditEvent.action.like("rollout.%")))
                )
                hook_audits = db.scalar(
                    select(AuditEvent.id).where(
                        AuditEvent.actor == rollout.HOOK_ACTOR, AuditEvent.action == "rollout.revert_opened"
                    )
                )
            flow["audit_actions"] = dict(sorted(actions.items()))
            flow["hook_audited"] = hook_audits is not None
            flow["provider_requests"] = len(repo.requests)
            flow["provider_merge_calls"] = sum(r.url.path.endswith("/merge") for r in repo.requests)
            flow["base_branch_writes"] = sum(
                json.loads(r.content or b"{}").get("branch") == "main" for r in repo.writes if r.content
            )
        routes.GitOpsClient = real_client
        report["rollout_flow"] = flow
        report["timings"].update({f"{k}": percentiles(v) for k, v in times.items()})
        print(json.dumps(flow), flush=True)
        save()

        # 4. Round trip: re-ingest the snapshot with every generated diff applied.
        started = time.perf_counter()
        expected = expected_after(model, [row.ordinal for row in included])
        expected_seconds = time.perf_counter() - started
        after_snapshot = round_trip(snapshot, files, optimized)
        later = publish("round_trip", after_snapshot)
        with session_factory()() as db:
            later_model = P.load_model(db, "demo", later)
        started = time.perf_counter()
        actual = actual_after(later_model)
        compare_seconds = time.perf_counter() - started
        direct_equal = actual[0] == expected[0]
        reach_keys_equal = set(actual[1]) == set(expected[1])
        reach_diff = [k for k in expected[1] if actual[1].get(k) != expected[1][k]]
        report["round_trip"] = {
            "new_revision": later != revision,
            "edges_before": len(snapshot.edges),
            "edges_after": len(after_snapshot.edges),
            "holders_compared": len(expected[0]),
            "records_compared": len(expected[1]),
            "direct_grants_equal": direct_equal,
            "records_equal": reach_keys_equal,
            "reach_mismatches": len(reach_diff),
            "reach_mismatch_sample": reach_diff[:5],
            "expected_seconds": round(expected_seconds, 2),
            "actual_seconds": round(compare_seconds, 2),
        }
        print(json.dumps(report["round_trip"]), flush=True)
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

    diff, flow, trip = report["diff_correctness"], report["rollout_flow"], report["round_trip"]
    report["checks"] = {
        "sample_at_least_500_proposals": diff["included_in_prs"] >= 500,
        "sample_has_scoping_and_disables": diff["resource_scopings"] > 0 and diff["disables"] > 0,
        "diff_exact_target_grants": diff["mismatches"] == 0,
        "diff_never_widens": diff["widened"] == 0,
        "round_trip_direct_grants_equal": trip["direct_grants_equal"],
        "round_trip_reach_equal": trip["records_equal"] and trip["reach_mismatches"] == 0,
        "non_canary_held": flow["non_canary_refused_while_canary_open"] == flow["non_canary_expected_refused"]
        and flow["refused_during_watch"]
        and flow["topic3_still_held"],
        "canary_verified_then_widened": flow["canary_verified_after_window"]
        and all(code == 200 for code in flow["widened_after_verify"]),
        "bundle_waits_for_canary": flow["bundle_before_canary_verified_refused"],
        "revert_byte_for_byte": flow["revert_files_byte_identical"][0]
        == flow["revert_files_byte_identical"][1]
        > 0,
        "access_denied_flags_and_opens_revert": flow["access_denied_flagged"]
        and flow["access_denied_revert_is_open_draft_not_merged"]
        and flow["hook_audited"],
        "never_merges_or_writes_base": flow["provider_merge_calls"] == 0 and flow["base_branch_writes"] == 0,
        "jobs_completed": all(p["job"]["status"] == "completed" for p in report["publishes"]),
    }
    save()
    print(json.dumps(report["checks"], indent=2))
    if not all(report["checks"].values()):
        raise SystemExit("Rollout qualification failed; inspect the JSON report")


if __name__ == "__main__":
    main()
