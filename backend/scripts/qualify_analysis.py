"""Bounded synthetic analysis qualification; no cloud/network services are used."""

import argparse
import json
import os
import platform
import statistics
import tempfile
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

os.environ.update(ZG_ENVIRONMENT="test", ZG_GRAPH_VENDOR="memory")

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.api.routes import overview
from app.core.auth import Actor
from app.db.models import Base, TenantState
from app.engine.blast_radius import calculate
from app.engine.toxic_combos import detect
from app.graph.repository import MemoryGraphStore
from app.graph.schema import Edge, EdgeType, GraphSnapshot, Node, NodeType, Sensitivity


def fixture(size: int) -> GraphSnapshot:
    identities = size // 2
    assets = size - identities
    nodes = [
        Node(
            id=f"identity:{i}",
            name=f"Identity {i}",
            type=NodeType.AGENT if i < 5 else NodeType.ROLE,
            internet_exposed=i < 5,
            authenticated=i >= 5,
            privileged=True,
        )
        for i in range(identities)
    ]
    nodes += [
        Node(id=f"data:{i}", name=f"Asset {i}", type=NodeType.BUCKET, sensitivity=Sensitivity.RESTRICTED)
        for i in range(assets)
    ]
    edges = []
    for identity in range(identities):
        edges.append(
            Edge(
                source=f"identity:{identity}",
                target=f"identity:{(identity + 1) % identities}",
                type=EdgeType.ASSUMES,
            )
        )
        for offset in range(7):
            edges.append(
                Edge(
                    source=f"identity:{identity}",
                    target=f"data:{(identity * 7 + offset) % assets}",
                    type=EdgeType.READ,
                )
            )
    return GraphSnapshot(nodes=nodes, edges=edges)


def elapsed(function):
    start = time.perf_counter()
    result = function()
    return time.perf_counter() - start, result


def qualify(size: int, requests: int, concurrency: int) -> dict:
    snapshot = fixture(size)
    tracemalloc.start()
    simulation_seconds, result = elapsed(lambda: calculate(snapshot, "identity:0", include_uncertain=True))
    findings_seconds, findings = elapsed(lambda: detect(snapshot))
    with tempfile.TemporaryDirectory(prefix="zerograph-qualification-") as directory:
        engine = create_engine(f"sqlite:///{directory}/state.db")
        Base.metadata.create_all(engine)
        store = MemoryGraphStore()
        store.publish("qualification", "revision", snapshot)
        with Session(engine) as db:
            db.add(TenantState(tenant_id="qualification", revision="revision"))
            db.commit()
            overview_seconds, dashboard = elapsed(
                lambda: overview(db, store, Actor("qualification", "qualification", frozenset({"viewer"})))
            )
        engine.dispose()
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        durations = list(
            pool.map(
                lambda _: elapsed(lambda: calculate(snapshot, "identity:0", include_uncertain=True))[0],
                range(requests),
            )
        )
    batch_seconds = time.perf_counter() - started
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        "checks": {
            "bounded_overview": overview_seconds < 10,
            "bounded_simulation_p95": sorted(durations)[max(0, int(len(durations) * 0.95 + 0.999) - 1)] < 5,
            "bounded_python_allocations": peak_bytes < 256 * 1024 * 1024,
            "expected_reachable_assets": len(result.affected_assets) == min(35, size // 2),
            "expected_findings": len(findings) == 5 * min(35, size // 2),
            "expected_identity_count": dashboard["total_nhis"] == size // 2,
        },
        "nodes": len(snapshot.nodes),
        "edges": len(snapshot.edges),
        "identities": size // 2,
        "simulation_seconds": simulation_seconds,
        "findings_seconds": findings_seconds,
        "overview_seconds": overview_seconds,
        "simulation_affected_assets": len(result.affected_assets),
        "findings_count": len(findings),
        "overview_nhis": dashboard["total_nhis"],
        "concurrent_simulation_requests": requests,
        "concurrency": concurrency,
        "batch_seconds": batch_seconds,
        "requests_per_second": requests / batch_seconds,
        "request_p95_seconds": sorted(durations)[max(0, int(len(durations) * 0.95 + 0.999) - 1)],
        "request_median_seconds": statistics.median(durations),
        "tracemalloc_peak_bytes": peak_bytes,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", type=int, nargs="+", default=[500, 2000, 5000])
    parser.add_argument("--requests", type=int, default=12)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if (
        any(size < 20 or size > 5000 or size % 2 for size in args.sizes)
        or not 1 <= args.requests <= 100
        or not 1 <= args.concurrency <= 8
    ):
        parser.error("Even graph sizes 20..5000, requests 1..100 and concurrency 1..8 are required")
    report = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "fixture": "Half identities, half restricted assets; each identity has one cyclic role edge and seven asset edges; five exposed agents",
        "limitations": "Synthetic in-process analysis with SQLite app state; excludes cloud ingestion, graph database roundtrips, HTTP/TLS, multi-tenant fleet load and deployment capacity. tracemalloc adds overhead and measures Python allocations, not RSS.",
        "results": [],
    }
    for size in args.sizes:
        result = qualify(size, args.requests, args.concurrency)
        report["results"].append(result)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(result), flush=True)
    if not all(all(result["checks"].values()) for result in report["results"]):
        raise SystemExit("Synthetic qualification regression budget failed; inspect the JSON report")


if __name__ == "__main__":
    main()
