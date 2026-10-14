"""Real CloudTrail qualification: a public trail through the usage upload API.

Feeds a real, public CloudTrail export (the flaws.cloud logs Summit Route publishes:
http://summitroute.com/downloads/flaws_cloudtrail_logs.tar, 20 gzip files of about
1.9 million records from 2017-2020; download and extract it first, nothing is fetched
here) through the production usage path: ``POST /api/v1/usage/uploads``, ``PUT
.../files/{n}`` (``decode_export`` + ``normalize_export`` + staging) and ``POST
.../commit`` (aggregation, coverage and role-session attribution), on a disposable
SQLite database and the in-memory graph store.

* **Bounds**: each published file is far beyond one export file (about 100 MB of JSON):
  it must be refused cleanly (the request body limit, and ``decode_export``'s
  decompressed-size limit), never crash or partially stage.
* **Upload**: records are re-split into CloudTrail-delivery-sized gzip files
  (``--records-per-file``, default 2,000) and uploaded per usage window of at most
  ``MAX_WINDOW_DAYS`` (consecutive windows over the trail's whole span), as a client
  would.
* **Report**: events read; mapped/unmapped per eventSource and per eventName; errorCode
  (AccessDenied...) counts and how many denied attempts were recorded; STS issuances and
  role-session attribution by basis; malformed or odd records (missing or mistyped
  fields); per-file and per-commit time and the process peak RSS. Any exception from the
  usage path is a failure (non-zero exit), reported with the file and chunk.
"""

import argparse
import gzip
import json
import os
import platform
import resource
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

os.environ.update(ZG_ENVIRONMENT="test", ZG_GRAPH_VENDOR="memory")
BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

ODD_FIELDS = {
    "userIdentity": dict,
    "requestParameters": dict,
    "responseElements": dict,
    "resources": list,
    "eventName": str,
    "eventSource": str,
    "eventTime": str,
    "awsRegion": str,
    "recipientAccountId": str,
    "errorCode": str,
}


def rss_mib() -> float:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return round(peak / (2**20 if sys.platform == "darwin" else 2**10), 1)


def parse_time(value) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None


def load(path: Path) -> list[dict]:
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        value = json.load(stream)
    return value["Records"] if isinstance(value, dict) else value


def survey(records: list[dict], tallies: dict) -> None:
    """Independent per-record tallies (mapping, errors, identity types, odd fields)."""
    from app.collectors.execution_audit import EVENTS

    for record in records:
        tallies["records"] += 1
        for name, kind in ODD_FIELDS.items():
            if name in record and record[name] is not None and not isinstance(record[name], kind):
                tallies["odd_type"][f"{name}:{type(record[name]).__name__}"] += 1
        for name in ("eventSource", "eventName", "eventTime", "userIdentity"):
            if record.get(name) is None:
                tallies["missing"][name] += 1
        source, name = record.get("eventSource"), record.get("eventName")
        key = f"{source} {name}"
        mapped = isinstance(source, str) and isinstance(name, str) and (source, name) in EVENTS
        (tallies["mapped"] if mapped else tallies["unmapped_source"])[source if not mapped else key] += 1
        if not mapped:
            tallies["unmapped_event"][key] += 1
        code = record.get("errorCode")
        if code:
            tallies["error_codes"][str(code)] += 1
            if mapped:
                tallies["mapped_error_codes"][str(code)] += 1
        identity = record.get("userIdentity")
        if isinstance(identity, dict):
            kind = str(identity.get("type"))
            tallies["identity_types"][kind] += 1
            if source == "sts.amazonaws.com" and name in (
                "AssumeRole",
                "AssumeRoleWithWebIdentity",
                "AssumeRoleWithSAML",
            ):
                tallies["assume_callers"][f"{name} by {kind}{' (failed)' if code else ''}"] += 1
            if kind == "AssumedRole":
                tallies["session_records"]["mapped" if mapped else "unmapped"] += 1
            context = identity.get("sessionContext")
            if context is not None and not isinstance(context, dict):
                tallies["odd_type"]["sessionContext:" + type(context).__name__] += 1
        occurred = parse_time(record.get("eventTime"))
        if occurred:
            tallies["first"] = min(tallies["first"] or occurred, occurred)
            tallies["last"] = max(tallies["last"] or occurred, occurred)
        else:
            tallies["missing"]["eventTime_unparsable"] += 1


def windows(first: datetime, last: datetime, days: int) -> list[tuple[datetime, datetime]]:
    start = first.replace(hour=0, minute=0, second=0, microsecond=0)
    found = []
    while start <= last:
        end = start + timedelta(days=days) - timedelta(seconds=1)
        found.append((start, end))
        start = start + timedelta(days=days)
    return found


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--logs", type=Path, required=True, help="Directory of flaws_cloudtrail*.json.gz")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--records-per-file", type=int, default=2000)
    parser.add_argument("--limit-files", type=int, default=0, help="Only the first N files (smoke runs)")
    args = parser.parse_args()
    files = sorted(args.logs.glob("*.json.gz"))[: args.limit_files or None]
    if not files:
        parser.error("No *.json.gz files found")

    work = Path(tempfile.mkdtemp(prefix="zg-cloudtrail-corpus-"))
    os.environ["ZG_DATABASE_URL"] = f"sqlite:///{work}/app.db"
    from fastapi.testclient import TestClient
    from loguru import logger

    from app.collectors import cloudtrail
    from app.core.auth import Actor, current_actor
    from app.core.config import get_settings
    from app.db.models import Base
    from app.db.session import session_factory
    from app.graph import usage
    from app.main import create_app

    logger.remove()
    get_settings.cache_clear()
    session_factory.cache_clear()
    Base.metadata.create_all(session_factory().kw["bind"])
    app = create_app()
    app.dependency_overrides[current_actor] = lambda: Actor(
        "qualifier", "tenant-q", frozenset({"admin", "analyst", "viewer"})
    )
    client = TestClient(app)
    report: dict = {"python": platform.python_version(), "files": [], "failures": []}
    started = time.perf_counter()

    # Pass 1: survey every record and check the bounds on the published (oversized) files.
    tallies = {
        "records": 0,
        "mapped": Counter(),
        "unmapped_source": Counter(),
        "unmapped_event": Counter(),
        "error_codes": Counter(),
        "mapped_error_codes": Counter(),
        "identity_types": Counter(),
        "assume_callers": Counter(),
        "session_records": Counter(),
        "odd_type": Counter(),
        "missing": Counter(),
        "first": None,
        "last": None,
    }
    for path in files:
        records = load(path)
        survey(records, tallies)
        report["files"].append({"file": path.name, "bytes": path.stat().st_size, "records": len(records)})
        del records
    first, last = tallies["first"], tallies["last"]
    spans = windows(first, last, usage.MAX_WINDOW_DAYS)

    body = files[0].read_bytes()
    oversized = {"file": files[0].name, "bytes": len(body)}
    upload = client.post(
        "/api/v1/usage/uploads",
        json={
            "window_start": spans[0][0].isoformat(),
            "window_end": spans[0][1].isoformat(),
            "attested_services": [],
        },
    ).json()
    response = client.put(f"/api/v1/usage/uploads/{upload['id']}/files/0", content=body)
    oversized["api_status"] = response.status_code
    try:
        cloudtrail.decode_export(body)
        oversized["decode_export"] = "accepted"
    except cloudtrail.ExportError as exc:
        oversized["decode_export"] = f"ExportError: {exc}"
    oversized["upload_after_refusal"] = client.get("/api/v1/usage").json()["uploads"][0]
    client.delete(f"/api/v1/usage/uploads/{upload['id']}")
    if oversized["api_status"] not in (413, 422) or oversized["decode_export"] == "accepted":
        report["failures"].append("oversized export file was not refused")
    report["oversized_file"] = oversized
    del body

    # Pass 2: one upload per window; records re-split into delivery-sized files.
    uploads = []
    for start, end in spans:
        created = client.post(
            "/api/v1/usage/uploads",
            json={
                "window_start": start.isoformat(),
                "window_end": end.isoformat(),
                "attested_services": ["s3", "sts"],
            },
        )
        if created.status_code != 201:
            report["failures"].append(
                f"open upload {start.date()}: {created.status_code} {created.text[:200]}"
            )
            continue
        uploads.append({"id": created.json()["id"], "start": start, "end": end, "chunks": 0, "seconds": 0.0})
    put_times = []
    for path in files:
        records = load(path)
        for item in uploads:
            selected = [
                record
                for record in records
                if (occurred := parse_time(record.get("eventTime")))
                and item["start"] <= occurred <= item["end"]
            ]
            for offset in range(0, len(selected), args.records_per_file):
                payload = gzip.compress(
                    json.dumps({"Records": selected[offset : offset + args.records_per_file]}).encode(),
                    compresslevel=5,
                )
                put_started = time.perf_counter()
                try:
                    response = client.put(
                        f"/api/v1/usage/uploads/{item['id']}/files/{item['chunks']}", content=payload
                    )
                except Exception as exc:  # noqa: BLE001 - a crash is the finding
                    report["failures"].append(
                        f"{path.name} chunk {item['chunks']}: {type(exc).__name__}: {exc}"
                    )
                    item["chunks"] += 1
                    continue
                elapsed = time.perf_counter() - put_started
                put_times.append(elapsed)
                item["seconds"] += elapsed
                if response.status_code != 200:
                    report["failures"].append(
                        f"{path.name} chunk {item['chunks']}: HTTP {response.status_code} {response.text[:200]}"
                    )
                item["chunks"] += 1
        del records
    commits = []
    for item in uploads:
        if not item["chunks"]:
            client.delete(f"/api/v1/usage/uploads/{item['id']}")
            continue
        commit_started = time.perf_counter()
        response = client.post(f"/api/v1/usage/uploads/{item['id']}/commit")
        elapsed = time.perf_counter() - commit_started
        if response.status_code != 200:
            report["failures"].append(f"commit {item['start'].date()}: HTTP {response.status_code}")
            continue
        stats = response.json()["stats"]
        commits.append(
            {
                "window": [item["start"].isoformat(), item["end"].isoformat()],
                "files": item["chunks"],
                "upload_seconds": round(item["seconds"], 2),
                "commit_seconds": round(elapsed, 2),
                "stats": stats,
            }
        )
    totals = Counter()
    by_basis = Counter()
    service_unmapped = Counter()
    for item in commits:
        stats = item["stats"]
        for key in (
            "records",
            "matched",
            "outside_window",
            "denied",
            "malformed",
            "unresolved_principal",
            "unresolved_resource",
            "unmapped",
            "pairs",
        ):
            totals[key] += stats.get(key, 0) or 0
        for key, value in (stats.get("attribution") or {}).get("by_basis", {}).items():
            by_basis[key] += value
        for key in (
            "sessions_issued",
            "sessions_resolved",
            "session_events",
            "attributed_events",
            "unattributed_events",
        ):
            totals["attribution_" + key] += (stats.get("attribution") or {}).get(key, 0)
        service_unmapped.update(stats.get("service_unmapped", {}))
    from sqlalchemy import func, select

    from app.db.models import AccessDenial, AttributedAccess, ObservedAccess

    with session_factory()() as db:
        stored = {
            "observed_access_rows": db.scalar(select(func.count()).select_from(ObservedAccess)),
            "observed_access_events": db.scalar(select(func.sum(ObservedAccess.count))),
            "access_denial_rows": db.scalar(select(func.count()).select_from(AccessDenial)),
            "access_denial_events": db.scalar(select(func.sum(AccessDenial.count))),
            "access_denial_by_code": dict(
                db.execute(
                    select(AccessDenial.error_code, func.sum(AccessDenial.count)).group_by(
                        AccessDenial.error_code
                    )
                ).all()
            ),
            "attributed_rows": db.scalar(select(func.count()).select_from(AttributedAccess)),
        }
    put_times.sort()
    report.update(
        {
            "trail": {
                "records": tallies["records"],
                "first_event": first.isoformat(),
                "last_event": last.isoformat(),
                "windows": len(spans),
            },
            "survey": {
                "mapped_events": dict(tallies["mapped"].most_common()),
                "mapped_total": sum(tallies["mapped"].values()),
                "unmapped_total": sum(tallies["unmapped_source"].values()),
                "unmapped_by_source": dict(tallies["unmapped_source"].most_common(40)),
                "unmapped_top_events": dict(tallies["unmapped_event"].most_common(40)),
                "error_codes": dict(tallies["error_codes"].most_common()),
                "mapped_error_codes": dict(tallies["mapped_error_codes"].most_common()),
                "identity_types": dict(tallies["identity_types"].most_common()),
                "assume_role_callers": dict(tallies["assume_callers"].most_common()),
                "role_session_records": dict(tallies["session_records"]),
                "odd_types": dict(tallies["odd_type"]),
                "missing_fields": dict(tallies["missing"]),
            },
            "usage_path": {
                "totals": dict(totals),
                "attribution_by_basis": dict(by_basis),
                "stored": stored,
                "service_unmapped": dict(service_unmapped.most_common()),
                "files_uploaded": len(put_times),
                "file_seconds_p50": round(put_times[len(put_times) // 2], 3) if put_times else None,
                "file_seconds_max": round(put_times[-1], 3) if put_times else None,
                "commits": commits,
            },
            "seconds": round(time.perf_counter() - started, 1),
            "peak_rss_mib": rss_mib(),
        }
    )
    if (stored["access_denial_events"] or 0) > totals["denied"]:
        report["failures"].append("more denied attempts stored than read")
    if totals["records"] != tallies["records"]:
        report["failures"].append(f"usage path read {totals['records']} records, survey {tallies['records']}")
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n")
    print(json.dumps({"records": tallies["records"], "failures": report["failures"][:5], **dict(totals)}))
    client.close()
    sys.exit(1 if report["failures"] else 0)


if __name__ == "__main__":
    main()
