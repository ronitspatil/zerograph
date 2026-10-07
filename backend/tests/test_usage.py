"""Observed-access store: CloudTrail export decoding and normalization, the usage upload API,
coverage attestation and evidence sufficiency, and the planted fixture's export round trip."""

import gzip
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.collectors import cloudtrail
from app.collectors.cloudtrail import ExportError, decode_export, normalize_export
from app.core.auth import Actor, current_actor
from app.db.models import AuditEvent, ObservedAccess, UsageCoverage, UsageStaged, UsageUpload
from app.graph import usage
from app.main import create_app

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from qualify_scale import cloudtrail_files, cloudtrail_records, generate_topics  # noqa: E402

ACCOUNT = "123456789012"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/lake-reader"
USER = f"arn:aws:iam::{ACCOUNT}:user/alice"
NOW = datetime.now(UTC).replace(microsecond=0)


def stamp(days_ago: float = 1) -> str:
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def role_event(
    source="s3.amazonaws.com", name="GetObject", request=None, resources=None, days_ago=1, **extra
):
    return {
        "eventTime": stamp(days_ago),
        "eventSource": source,
        "eventName": name,
        "awsRegion": "us-east-1",
        "recipientAccountId": ACCOUNT,
        "userIdentity": {
            "type": "AssumedRole",
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/lake-reader/s",
            "sessionContext": {"sessionIssuer": {"type": "Role", "arn": ROLE}},
        },
        "requestParameters": request if request is not None else {"bucketName": "lake-raw", "key": "a"},
        "resources": resources or [],
        **extra,
    }


def user_event(name="AssumeRole", **extra):
    return {
        "eventTime": stamp(),
        "eventSource": "sts.amazonaws.com",
        "eventName": name,
        "userIdentity": {"type": "IAMUser", "arn": USER},
        "requestParameters": {"roleArn": ROLE, "roleSessionName": "s"},
        **extra,
    }


def window(days=100):
    return NOW - timedelta(days=days), NOW


# Decoding and normalization


def test_decode_export_accepts_records_array_lines_and_gzip():
    records = [role_event(), user_event()]
    plain = json.dumps({"Records": records}).encode()
    assert decode_export(plain) == records
    assert decode_export(gzip.compress(plain)) == records
    assert decode_export(json.dumps(records).encode()) == records
    assert decode_export("\n".join(json.dumps(r) for r in records).encode()) == records


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (b"\x1f\x8bnot-gzip", "not valid gzip"),
        (b"\xff\xfe", "UTF-8"),
        (b"{not json", "not CloudTrail JSON"),
        (b'{"Records": {"a": 1}}', "Records array"),
        (b"[1, 2]", "Records array"),
    ],
)
def test_decode_export_refuses_malformed_files(body, message):
    with pytest.raises(ExportError, match=message):
        decode_export(body)


def test_decode_export_bounds_decompressed_size_and_records(monkeypatch):
    monkeypatch.setattr(cloudtrail, "MAX_DECOMPRESSED_BYTES", 100)
    with pytest.raises(ExportError, match="size limit"):
        decode_export(gzip.compress(json.dumps({"Records": [role_event()] * 10}).encode()))
    monkeypatch.setattr(cloudtrail, "MAX_RECORDS", 1)
    with pytest.raises(ExportError, match="too many"):
        decode_export(json.dumps([role_event(), role_event()]).encode())


def test_normalize_resolves_principals_and_resources_per_service():
    glue_table = role_event("glue.amazonaws.com", "GetTable", {"databaseName": "lake", "name": "events"})
    glue_db = role_event("glue.amazonaws.com", "GetDatabase", {"name": "lake"})
    athena = role_event("athena.amazonaws.com", "StartQueryExecution", {"workGroup": "analysts"})
    lake = role_event(
        "lakeformation.amazonaws.com", "GetDataAccess", {"tableArn": "arn:aws:glue:us-east-1:1:table/a/b"}
    )
    rds = role_event(
        "rds-data.amazonaws.com", "ExecuteStatement", {"resourceArn": "arn:aws:rds:x:1:cluster:c"}
    )
    vector = role_event(
        "aoss.amazonaws.com", "ReadDocument", {}, [{"type": "AWS::AOSS::Collection", "ARN": "arn:aoss:c"}]
    )
    bucket = role_event(resources=[{"type": "AWS::S3::Bucket", "ARN": "arn:aws:s3:::from-resources"}])
    root = {**user_event(), "userIdentity": {"type": "Root", "arn": f"arn:aws:iam::{ACCOUNT}:root"}}
    service = {**role_event(), "userIdentity": {"type": "AWSService", "invokedBy": "glue.amazonaws.com"}}
    result = normalize_export(
        [role_event(), bucket, user_event(), glue_table, glue_db, athena, lake, rds, vector, root, service],
        *window(),
    )
    keys = set(result.access)
    assert (ROLE, "arn:aws:s3:::lake-raw", "read", "s3") in keys
    assert (ROLE, "arn:aws:s3:::from-resources", "read", "s3") in keys
    assert (USER, ROLE, "assume", "sts") in keys
    assert (ROLE, f"arn:aws:glue:us-east-1:{ACCOUNT}:table/lake/events", "read", "glue") in keys
    assert (ROLE, f"arn:aws:glue:us-east-1:{ACCOUNT}:database/lake", "read", "glue") in keys
    assert (ROLE, f"arn:aws:athena:us-east-1:{ACCOUNT}:workgroup/analysts", "read", "athena") in keys
    assert (ROLE, "arn:aws:glue:us-east-1:1:table/a/b", "read", "lakeformation") in keys
    assert (ROLE, "arn:aws:rds:x:1:cluster:c", "write", "rds-data") in keys
    assert (ROLE, "arn:aoss:c", "read", "aoss") in keys
    assert (f"arn:aws:iam::{ACCOUNT}:root", ROLE, "assume", "sts") in keys
    assert result.unresolved_principal == 1
    assert result.matched == 10


def test_normalize_counts_window_denied_malformed_unmapped_and_aggregates():
    events = [
        role_event(days_ago=3),
        role_event(days_ago=1),
        role_event("s3.amazonaws.com", "PutObject"),
        role_event("s3.amazonaws.com", "PutBucketPolicy"),
        role_event(days_ago=200),  # outside the window
        role_event(errorCode="AccessDenied"),  # a denied attempt is not use
        {**role_event(), "eventTime": "yesterday"},
        role_event("s3.amazonaws.com", "RestoreObject"),  # unmapped
        role_event("ec2.amazonaws.com", "DescribeInstances"),
        role_event(request={}),  # no bucket
    ]
    result = normalize_export(events, *window())
    first, last, count = result.access[(ROLE, "arn:aws:s3:::lake-raw", "read", "s3")]
    assert count == 2 and first < last
    assert (ROLE, "arn:aws:s3:::lake-raw", "write", "s3") in result.access
    assert (ROLE, "arn:aws:s3:::lake-raw", "admin", "s3") in result.access
    stats = result.stats()
    assert stats["outside_window"] == 1 and stats["denied"] == 1 and stats["malformed"] == 1
    assert stats["unresolved_resource"] == 1
    assert stats["service_unmapped"] == {"ec2": 1, "s3": 1}
    assert stats["service_events"] == {"ec2": 1, "s3": 7}
    with pytest.raises(ValueError, match="timezone-aware"):
        normalize_export([], datetime(2026, 1, 1), NOW)


# Upload API


def client_for(roles=("admin", "analyst", "viewer"), tenant="tenant-a"):
    app = create_app()
    app.dependency_overrides[current_actor] = lambda: Actor("alice", tenant, frozenset(roles))
    return TestClient(app)


def start(client, days=100, services=("s3", "sts"), end=None):
    end = end or NOW
    return client.post(
        "/api/v1/usage/uploads",
        json={
            "window_start": (end - timedelta(days=days)).isoformat(),
            "window_end": end.isoformat(),
            "attested_services": list(services),
        },
    )


def put(client, upload_id, chunk, records, compress=True):
    body = json.dumps({"Records": records}).encode()
    return client.put(
        f"/api/v1/usage/uploads/{upload_id}/files/{chunk}", content=gzip.compress(body) if compress else body
    )


def test_usage_upload_stages_files_commits_and_reports_coverage(client, environment):
    factory, _ = environment
    created = start(client)
    assert created.status_code == 201
    upload = created.json()
    assert upload["revision"] == "revision-a" and upload["attested_services"] == ["s3", "sts"]
    assert (
        "glue" in upload["services"] and upload["max_decompressed_bytes"] == cloudtrail.MAX_DECOMPRESSED_BYTES
    )
    first = put(client, upload["id"], 0, [role_event(), role_event("glue.amazonaws.com", "GetTable", {})])
    assert first.status_code == 200 and first.json()["progress"]["records"] == 2
    # Re-sending a file replaces it.
    again = put(client, upload["id"], 0, [role_event(), role_event(days_ago=2)], compress=False)
    assert again.json()["progress"]["records"] == 2 and again.json()["progress"]["staged_pairs"] == 1
    put(client, upload["id"], 1, [user_event(), role_event(days_ago=5)])
    committed = client.post(f"/api/v1/usage/uploads/{upload['id']}/commit")
    assert committed.status_code == 200
    body = committed.json()
    assert body["status"] == "committed" and body["stats"]["pairs"] == 2 and body["stats"]["files"] == 2
    assert {row["service"]: row["complete"] for row in body["stats"]["coverage"]} == {"s3": True, "sts": True}
    evidence = body["evidence"]
    assert evidence["status"] == "attested" and evidence["sufficient_services"] == ["s3", "sts"]
    assert evidence["services"]["s3"]["days"] == 100.0 and evidence["fingerprint"]
    with factory() as db:
        row = db.scalar(select(ObservedAccess).where(ObservedAccess.action_class == "read"))
        assert row.count == 3 and row.source == "cloudtrail-export" and row.upload_id == upload["id"]
        assert db.scalar(select(func.count()).select_from(UsageStaged)) == 0
        actions = set(db.scalars(select(AuditEvent.action)))
        assert {"usage.upload_started", "usage.upload_committed"} <= actions
    assert client.post(f"/api/v1/usage/uploads/{upload['id']}/commit").status_code == 409
    assert put(client, upload["id"], 2, [role_event()]).status_code == 409
    status = client.get("/api/v1/usage").json()
    assert status["evidence"]["observed_pairs"] == 2
    assert status["uploads"][0]["coverage"][0]["service"] == "s3"
    assert "never sufficient" in status["notice"]


def test_usage_upload_validation_auth_and_isolation(client, environment):
    assert start(client, days=500).status_code == 422
    assert start(client, end=NOW + timedelta(days=3)).status_code == 422
    assert start(client, services=("s3", "ec2")).status_code == 422
    naive = client.post(
        "/api/v1/usage/uploads",
        json={"window_start": "2026-01-01T00:00:00", "window_end": "2026-02-01T00:00:00"},
    )
    assert naive.status_code == 422
    other = client.post("/api/v1/usage/uploads", json={**start(client).json(), "source": "lake"})
    assert other.status_code == 422
    viewer = client_for(("viewer",))
    assert start(viewer).status_code == 403
    assert viewer.get("/api/v1/usage").status_code == 200
    upload = start(client).json()
    assert put(client, upload["id"], 0, []).status_code == 200
    assert client.post(f"/api/v1/usage/uploads/{upload['id']}/commit").status_code == 200
    empty = start(client).json()
    assert client.post(f"/api/v1/usage/uploads/{empty['id']}/commit").status_code == 422
    bad = client.put(f"/api/v1/usage/uploads/{empty['id']}/files/0", content=b"{nope")
    assert bad.status_code == 422 and bad.json()["detail"] == "File is not CloudTrail JSON"
    foreign = client_for(tenant="tenant-b")
    assert put(foreign, empty["id"], 0, [role_event()]).status_code == 404
    assert foreign.delete(f"/api/v1/usage/uploads/{upload['id']}").status_code == 404
    assert foreign.get("/api/v1/usage").json()["uploads"] == []


def test_open_usage_uploads_are_bounded_and_expire(client, environment, monkeypatch):
    factory, _ = environment
    ids = [start(client).json()["id"] for _ in range(4)]
    assert start(client).status_code == 429
    with factory() as db:
        db.get(UsageUpload, ids[0]).expires_at = NOW - timedelta(days=1)
        db.commit()
    assert put(client, ids[0], 0, [role_event()]).status_code == 410
    assert start(client).status_code == 201  # The expired upload was purged.
    with factory() as db:
        assert db.get(UsageUpload, ids[0]) is None


def test_deleting_an_upload_removes_its_evidence(client, environment):
    factory, _ = environment
    upload = start(client).json()
    put(client, upload["id"], 0, [role_event()])
    client.post(f"/api/v1/usage/uploads/{upload['id']}/commit")
    assert client.delete(f"/api/v1/usage/uploads/{upload['id']}").status_code == 204
    with factory() as db:
        for model in (UsageUpload, ObservedAccess, UsageCoverage):
            assert db.scalar(select(func.count()).select_from(model)) == 0
    assert client.get("/api/v1/usage").json()["evidence"]["status"] == "none"


def test_upload_pair_bound_refuses_the_file(client, environment, monkeypatch):
    monkeypatch.setattr(usage, "MAX_UPLOAD_PAIRS", 1)
    upload = start(client).json()
    response = put(client, upload["id"], 0, [role_event(), user_event()])
    assert response.status_code == 413


# Evidence sufficiency


def commit_window(client, days, end_days_ago=1, services=("s3",), records=None):
    end = NOW - timedelta(days=end_days_ago)
    upload = start(client, days=days, services=services, end=end).json()
    put(client, upload["id"], 0, records if records is not None else [role_event(days_ago=end_days_ago + 1)])
    return client.post(f"/api/v1/usage/uploads/{upload['id']}/commit").json()


def test_evidence_requires_90_contiguous_attested_days_ending_within_7(client, environment):
    factory, _ = environment
    short = commit_window(client, days=50)
    assert short["evidence"]["status"] == "partial"
    assert short["evidence"]["services"]["s3"]["sufficient"] is False
    # A second, contiguous (1-day gap) earlier window completes 90+ days.
    joined = commit_window(client, days=45, end_days_ago=52)
    s3 = joined["evidence"]["services"]["s3"]
    assert s3["sufficient"] is True and s3["days"] == pytest.approx(96.0)
    fingerprint = joined["evidence"]["fingerprint"]
    with factory() as db:
        stale = usage.evidence(db, "tenant-a", NOW + timedelta(days=7))
        assert not stale.services["s3"].sufficient and not stale.services["s3"].fresh
        assert stale.fingerprint != fingerprint and stale.status == "partial"
        assert usage.evidence(db, "tenant-a", NOW).fingerprint == fingerprint


def test_unattested_unmapped_or_malformed_coverage_is_never_sufficient(client, environment):
    unattested = commit_window(client, days=100, services=())
    assert unattested["evidence"]["services"]["s3"]["sufficient"] is False
    assert unattested["stats"]["coverage"] == [
        {"service": "s3", "attested": False, "events": 1, "unmapped": 0, "complete": False}
    ]
    unmapped = commit_window(client, days=100, records=[role_event("s3.amazonaws.com", "RestoreObject")])
    assert unmapped["stats"]["coverage"][0]["complete"] is False
    malformed = commit_window(client, days=100, records=[{**role_event(), "eventTime": "x"}])
    assert malformed["stats"]["coverage"][0]["complete"] is False
    assert malformed["evidence"]["services"]["s3"]["sufficient"] is False


# Planted fixture: the generated export reproduces the usage sidecar exactly.


def test_planted_cloudtrail_export_round_trips_the_usage_sidecar():
    snapshot, _, planted = generate_topics(3000, seed=11)
    begin, end = NOW - timedelta(days=91), NOW - timedelta(days=1)
    files = list(cloudtrail_files(cloudtrail_records(snapshot, planted, begin, end), per_file=2000))
    assert len(files) > 1
    roles: dict[str, set] = {}
    identities: dict[str, set] = {}
    totals = {"denied": 0, "unmapped": 0}
    for body in files:
        result = normalize_export(decode_export(body), begin, end)
        totals["denied"] += result.denied
        totals["unmapped"] += result.stats()["unmapped"]
        assert result.malformed == result.outside_window == result.unresolved_resource == 0
        assert set(result.service_unmapped) <= {"ec2"}
        for principal, resource, action_class, _ in result.access:
            if action_class == "assume":
                identities.setdefault(principal, set()).add(resource)
            else:
                roles.setdefault(principal, set()).add(resource)
    assert roles == {role: set(items) for role, items in planted["role_data_used"].items()}
    assert identities == {i: set(r) for i, r in planted["identity_role_used"].items()}
    assert totals["denied"] > 0 and totals["unmapped"] > 0
