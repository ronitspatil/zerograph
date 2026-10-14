"""Emulated AWS qualification: the real collector end to end against a local moto server.

No real AWS account is used. The script starts ``moto_server`` (a dev-only dependency,
``requirements-dev.lock``) on 127.0.0.1, seeds a realistic member account of an AWS
Organization and points every SDK client at it with the standard SDK setting
``AWS_ENDPOINT_URL`` (botocore's own endpoint override: there is no ZeroGraph endpoint
setting, so nothing here is reachable from production configuration). Then:

1. **CLI**: ``python -m app.collectors.aws_collector`` with a named profile (temporary
   AWS config/credentials files), AssumeRole with an external ID, Access Advisor and the
   data lake; the sanitized artifact must report a verified identity and complete IAM,
   S3 and Glue inventory.
2. **In-app job**: ``ZG_AWS_ROLE_ARN``/``ZG_AWS_EXTERNAL_ID`` settings, ``POST
   /api/v1/ingestions`` with source ``aws`` and the worker's ``process_job`` (AssumeRole,
   STS target check, collection, staging, publication, topics, proposals) into a
   disposable SQLite database and the in-memory graph store, after uploading 95 days of
   synthetic CloudTrail usage through the usage API, so proposals have sufficient evidence.
3. **Checks** on the published revision: inventory counts, tags, ``RoleLastUsed``
   handling (the collector's own role is used, the dormant role is not), policy documents
   stored once per digest and served by ``/graph/policies`` (including the ~152 KB
   AWS-managed ``AWSSupportServiceRolePolicy``), Glue/Athena/Lake Formation nodes, edges
   and modes, topics (``data-lake`` and ``finance`` forms), proposals (the deliberate
   cross-topic over-grant is a high-tier ``remove_grant``; Lake Formation grants are
   ``manual``; the dormant role is proposed for disabling).
4. **Variants**: SCPs read through the management account (as a delegated administrator
   would; moto keeps Organizations per account), and an LF-Tag grant, whose resolution
   needs APIs moto does not implement: the collector must degrade to ``unknown`` modes,
   never under-state access.

Every API moto lacks or answers differently from AWS is recorded under ``moto_gaps``
(with the collector warning it produced), separately from ``failures`` (real collector
or publication bugs). Exit status is non-zero when any check fails. The moto server is
always stopped.
"""

import argparse
import gzip
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections import Counter
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

BACKEND = Path(__file__).resolve().parents[1]
REGION = "us-east-1"
EXTERNAL_ID = "zg-emulated-external-id-7f3a"
COLLECTOR = "ZeroGraphReadOnlyCollector"
FORBIDDEN_PORTS = {13300, 18300, 17687}
TENANT = "tenant-emulated"
USAGE_DAYS = 95


def document(*statements) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def allow(actions, resources, **extra) -> dict:
    return {"Effect": "Allow", "Action": actions, "Resource": resources, **extra}


# -- moto server -------------------------------------------------------------------------


@contextmanager
def moto_server(port: int, log: Path):
    if port in FORBIDDEN_PORTS:
        raise SystemExit(f"Port {port} is reserved")
    with socket.socket() as probe:
        if probe.connect_ex(("127.0.0.1", port)) == 0:
            raise SystemExit(f"Port {port} is already in use")
    binary = Path(sys.executable).with_name("moto_server")
    env = {**os.environ, "MOTO_IAM_LOAD_MANAGED_POLICIES": "true"}
    with log.open("w") as output:
        process = subprocess.Popen(
            [str(binary), "-H", "127.0.0.1", "-p", str(port)],
            stdout=output,
            stderr=subprocess.STDOUT,
            env=env,
        )
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            with socket.socket() as probe:
                if probe.connect_ex(("127.0.0.1", port)) == 0:
                    break
            if process.poll() is not None:
                raise SystemExit(f"moto_server exited: see {log}")
            time.sleep(0.2)
        else:
            raise SystemExit("moto_server did not start")
        yield f"http://127.0.0.1:{port}"
    finally:
        process.terminate()
        try:
            process.wait(10)
        except subprocess.TimeoutExpired:
            process.kill()


# -- seeding -----------------------------------------------------------------------------


def session(boto3, key: str = "testing", secret: str = "testing", token: str | None = None):
    return boto3.Session(
        aws_access_key_id=key, aws_secret_access_key=secret, aws_session_token=token, region_name=REGION
    )


def seed(boto3) -> dict:
    """An Organization (management = moto's default account) and a member account to collect."""
    management = session(boto3)
    org = management.client("organizations")
    org.create_organization(FeatureSet="ALL")
    request = org.create_account(Email="sandbox@example.com", AccountName="zg-sandbox")["CreateAccountStatus"]
    account = org.describe_create_account_status(CreateAccountRequestId=request["Id"])["CreateAccountStatus"][
        "AccountId"
    ]
    root = org.list_roots()["Roots"][0]["Id"]
    ou = org.create_organizational_unit(ParentId=root, Name="sandbox")["OrganizationalUnit"]["Id"]
    org.move_account(AccountId=account, SourceParentId=root, DestinationParentId=ou)
    scp = org.create_policy(
        Name="deny-object-deletes",
        Description="Sandbox guardrail",
        Type="SERVICE_CONTROL_POLICY",
        Content=document(
            {"Effect": "Deny", "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion"], "Resource": "*"}
        ),
    )["Policy"]["PolicySummary"]["Id"]
    org.attach_policy(PolicyId=scp, TargetId=ou)

    credentials = management.client("sts").assume_role(
        RoleArn=f"arn:aws:iam::{account}:role/OrganizationAccountAccessRole", RoleSessionName="zg-seed"
    )["Credentials"]
    member = session(
        boto3, credentials["AccessKeyId"], credentials["SecretAccessKey"], credentials["SessionToken"]
    )
    iam, s3, glue = member.client("iam"), member.client("s3"), member.client("glue")
    lf, athena = member.client("lakeformation"), member.client("athena")
    arn = f"arn:aws:iam::{account}"
    lake_raw, lake_curated, finance, results = (
        f"zg-lake-raw-{account}",
        f"zg-lake-curated-{account}",
        f"zg-finance-ledger-{account}",
        f"zg-athena-results-{account}",
    )

    # Bootstrap operator (the CLI's named profile) and the read-only collector role.
    iam.create_user(UserName="zg-operator", Tags=[{"Key": "team", "Value": "platform"}])
    iam.put_user_policy(
        UserName="zg-operator",
        PolicyName="assume-collector",
        PolicyDocument=document(allow("sts:AssumeRole", f"{arn}:role/{COLLECTOR}")),
    )
    key = iam.create_access_key(UserName="zg-operator")["AccessKey"]
    iam.create_role(
        RoleName=COLLECTOR,
        AssumeRolePolicyDocument=document(
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"{arn}:user/zg-operator"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": EXTERNAL_ID}},
            }
        ),
        Tags=[{"Key": "team", "Value": "platform"}],
    )
    template = (BACKEND.parent / "deploy/aws/collector-role-policy.example.json").read_text()
    iam.put_role_policy(
        RoleName=COLLECTOR,
        PolicyName="zerograph-read-only",
        PolicyDocument=json.dumps(json.loads(template.replace("123456789012", account))),
    )

    def role(name, trust, topic=None, inline=(), managed=(), boundary=None, path="/", tags=()):
        all_tags = [{"Key": "topic", "Value": topic}] if topic else []
        all_tags += [{"Key": k, "Value": v} for k, v in tags]
        kwargs = {"Path": path, "AssumeRolePolicyDocument": document(trust), "Tags": all_tags}
        if boundary:
            kwargs["PermissionsBoundary"] = boundary
        iam.create_role(RoleName=name, **kwargs)
        for position, policy in enumerate(inline):
            iam.put_role_policy(
                RoleName=name, PolicyName=f"{name}-inline-{position}", PolicyDocument=document(*policy)
            )
        for policy_arn in managed:
            iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
        return f"{arn}:role{path}{name}"

    def service_trust(service):
        return {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}

    def user_trust(*users):
        return {
            "Effect": "Allow",
            "Principal": {"AWS": [f"{arn}:user/{u}" for u in users]},
            "Action": "sts:AssumeRole",
        }

    glue_table = f"arn:aws:glue:{REGION}:{account}:table"
    glue_db = f"arn:aws:glue:{REGION}:{account}:database"
    catalog = f"arn:aws:glue:{REGION}:{account}:catalog"
    boundary = iam.create_policy(
        PolicyName="zg-data-boundary",
        PolicyDocument=document(allow(["s3:*", "glue:*", "athena:*", "lakeformation:GetDataAccess"], "*")),
    )["Policy"]["Arn"]
    lake_read = iam.create_policy(
        PolicyName="zg-lake-read",
        PolicyDocument=document(
            allow(
                ["s3:GetObject", "s3:ListBucket"], [f"arn:aws:s3:::{lake_raw}", f"arn:aws:s3:::{lake_raw}/*"]
            ),
            allow(
                ["glue:GetDatabase", "glue:GetTable", "glue:GetTables", "glue:GetPartitions"],
                [catalog, f"{glue_db}/lake_raw", f"{glue_table}/lake_raw/*"],
            ),
            allow("athena:StartQueryExecution", f"arn:aws:athena:{REGION}:{account}:workgroup/analytics"),
        ),
    )["Policy"]["Arn"]
    roles = {
        "etl": role(
            "zg-lake-etl",
            service_trust("glue.amazonaws.com"),
            "data-lake",
            inline=[
                [
                    allow(
                        ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                        [f"arn:aws:s3:::{b}{s}" for b in (lake_raw, lake_curated) for s in ("", "/*")],
                    ),
                    allow(
                        [
                            "glue:GetTable",
                            "glue:GetTables",
                            "glue:UpdateTable",
                            "glue:BatchCreatePartition",
                            "glue:GetPartitions",
                            "glue:GetDatabase",
                            "glue:CreateTable",
                        ],
                        [
                            catalog,
                            f"{glue_db}/lake_raw",
                            f"{glue_db}/lake_curated",
                            f"{glue_table}/lake_raw/*",
                            f"{glue_table}/lake_curated/*",
                        ],
                    ),
                ]
            ],
            boundary=boundary,
        ),
        # The deliberate cross-topic over-grant: a data-lake reader that may read the ledger.
        "reader": role(
            "zg-lake-reader",
            user_trust("analyst"),
            "data-lake",
            inline=[
                [
                    allow(
                        ["s3:GetObject", "s3:ListBucket"],
                        [f"arn:aws:s3:::{finance}", f"arn:aws:s3:::{finance}/*"],
                    )
                ]
            ],
            managed=[lake_read],
        ),
        "finance": role(
            "zg-finance-app",
            service_trust("lambda.amazonaws.com"),
            "finance",
            inline=[
                [
                    allow(
                        ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                        [f"arn:aws:s3:::{finance}", f"arn:aws:s3:::{finance}/*"],
                    ),
                    allow(
                        ["glue:GetTable", "glue:GetDatabase"],
                        [catalog, f"{glue_db}/finance", f"{glue_table}/finance/*"],
                    ),
                ]
            ],
        ),
        # Never assumed: RoleLastUsed stays absent and no CloudTrail use is uploaded.
        "dormant": role(
            "zg-quarterly-report",
            service_trust("lambda.amazonaws.com"),
            "finance",
            inline=[
                [
                    allow(
                        ["s3:GetObject", "s3:ListBucket"],
                        [f"arn:aws:s3:::{finance}", f"arn:aws:s3:::{finance}/*"],
                    )
                ]
            ],
        ),
        "support": role(
            "AWSServiceRoleForSupport",
            service_trust("support.amazonaws.com"),
            managed=["arn:aws:iam::aws:policy/aws-service-role/AWSSupportServiceRolePolicy"],
            path="/aws-service-role/support.amazonaws.com/",
        ),
        "readonly": role(
            "zg-auditor",
            user_trust("auditor"),
            managed=["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"],
            tags=[("team", "security")],
        ),
    }
    # Humans: an analyst (group data-analysts) and a finance clerk (group finance-team).
    iam.create_group(GroupName="data-analysts")
    iam.put_group_policy(
        GroupName="data-analysts",
        PolicyName="assume-reader",
        PolicyDocument=document(allow("sts:AssumeRole", roles["reader"])),
    )
    iam.create_group(GroupName="finance-team")
    finance_read = iam.create_policy(
        PolicyName="zg-finance-read",
        PolicyDocument=document(
            allow(["s3:GetObject", "s3:ListBucket"], [f"arn:aws:s3:::{finance}", f"arn:aws:s3:::{finance}/*"])
        ),
    )["Policy"]["Arn"]
    iam.attach_group_policy(GroupName="finance-team", PolicyArn=finance_read)
    for name, group, tags in (
        ("analyst", "data-analysts", [("team", "analytics"), ("topic", "data-lake")]),
        ("finance-clerk", "finance-team", [("team", "finance"), ("topic", "finance")]),
        ("auditor", None, [("team", "security")]),
    ):
        iam.create_user(UserName=name, Tags=[{"Key": k, "Value": v} for k, v in tags])
        if group:
            iam.add_user_to_group(UserName=name, GroupName=group)
    iam.put_user_policy(
        UserName="auditor",
        PolicyName="assume-auditor",
        PolicyDocument=document(allow("sts:AssumeRole", roles["readonly"])),
    )

    # S3: tags, bucket policies and default encryption.
    for name, tags, encryption in (
        (lake_raw, {"topic": "data-lake", "data-class": "PII"}, "AES256"),
        (lake_curated, {"topic": "data-lake"}, "aws:kms"),
        (finance, {"topic": "finance", "classification": "confidential"}, "aws:kms"),
        (results, {"topic": "data-lake", "purpose": "athena-results"}, None),
    ):
        s3.create_bucket(Bucket=name)
        s3.put_bucket_tagging(
            Bucket=name, Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in tags.items()]}
        )
        if encryption:
            s3.put_bucket_encryption(
                Bucket=name,
                ServerSideEncryptionConfiguration={
                    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": encryption}}]
                },
            )
    s3.put_bucket_policy(
        Bucket=finance,
        Policy=document(
            {
                "Sid": "DenyInsecureTransport",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [f"arn:aws:s3:::{finance}", f"arn:aws:s3:::{finance}/*"],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            }
        ),
    )

    # Glue Data Catalog: databases with S3 locations and tags, tables with classified columns.
    def table(database, name, location, columns, partitions=(), parameters=None):
        glue.create_table(
            DatabaseName=database,
            TableInput={
                "Name": name,
                "StorageDescriptor": {
                    "Columns": [{"Name": c, "Type": "string"} for c in columns],
                    "Location": location,
                },
                "PartitionKeys": [{"Name": p, "Type": "string"} for p in partitions],
                "Parameters": parameters or {"classification": "parquet"},
            },
        )

    for name, location, tags in (
        ("lake_raw", f"s3://{lake_raw}/", {"topic": "data-lake", "owner": "analytics"}),
        ("lake_curated", f"s3://{lake_curated}/", {"topic": "data-lake"}),
        ("finance", f"s3://{finance}/", {"topic": "finance", "data-class": "PCI"}),
    ):
        glue.create_database(DatabaseInput={"Name": name, "LocationUri": location})
        glue.tag_resource(ResourceArn=f"{glue_db}/{name}", TagsToAdd=tags)
    table("lake_raw", "events", f"s3://{lake_raw}/events/", ["event_id", "user_email", "payload"], ["dt"])
    table("lake_raw", "customers", f"s3://{lake_raw}/customers/", ["customer_id", "ssn", "address"])
    table("lake_curated", "daily_metrics", f"s3://{lake_curated}/daily/", ["day", "metric", "value"], ["dt"])
    table("finance", "ledger", f"s3://{finance}/ledger/", ["entry_id", "card_number", "amount"])
    glue.put_resource_policy(
        PolicyInJson=document(
            {
                "Effect": "Allow",
                "Principal": {"AWS": roles["etl"]},
                "Action": ["glue:GetTable", "glue:GetTables", "glue:GetDatabase"],
                "Resource": [catalog, f"{glue_db}/*", f"{glue_table}/*/*"],
            }
        )
    )
    athena.create_work_group(
        Name="analytics",
        Configuration={
            "ResultConfiguration": {"OutputLocation": f"s3://{results}/analytics/"},
            "EnforceWorkGroupConfiguration": True,
        },
        Tags=[{"Key": "topic", "Value": "data-lake"}],
    )

    # Lake Formation: lake_raw and lake_curated governed by Lake Formation; finance in hybrid
    # mode (IAM_ALLOWED_PRINCIPALS), as tables created with the default settings are.
    lf.put_data_lake_settings(
        DataLakeSettings={
            "DataLakeAdmins": [{"DataLakePrincipalIdentifier": f"{arn}:role/OrganizationAccountAccessRole"}],
            "ReadOnlyAdmins": [{"DataLakePrincipalIdentifier": f"{arn}:role/{COLLECTOR}"}],
            "CreateDatabaseDefaultPermissions": [],
            "CreateTableDefaultPermissions": [],
        }
    )

    def grant(principal, resource, permissions):
        lf.grant_permissions(
            Principal={"DataLakePrincipalIdentifier": principal}, Resource=resource, Permissions=permissions
        )

    grant(
        roles["etl"],
        {"Table": {"DatabaseName": "lake_raw", "TableWildcard": {}}},
        ["SELECT", "INSERT", "ALTER"],
    )
    grant(
        roles["etl"],
        {"Table": {"DatabaseName": "lake_curated", "Name": "daily_metrics"}},
        ["SELECT", "INSERT"],
    )
    grant(roles["reader"], {"Table": {"DatabaseName": "lake_raw", "Name": "events"}}, ["SELECT"])
    grant(
        roles["reader"],
        {
            "TableWithColumns": {
                "DatabaseName": "lake_raw",
                "Name": "customers",
                "ColumnNames": ["customer_id"],
            }
        },
        ["SELECT"],
    )
    grant("IAM_ALLOWED_PRINCIPALS", {"Table": {"DatabaseName": "finance", "Name": "ledger"}}, ["ALL"])
    grant(roles["finance"], {"Table": {"DatabaseName": "finance", "Name": "ledger"}}, ["SELECT", "INSERT"])
    grant(roles["etl"], {"Database": {"Name": "lake_curated"}}, ["CREATE_TABLE"])

    return {
        "account": account,
        "management": "123456789012",
        "ou": ou,
        "scp": scp,
        "operator_key": key,
        "collector": f"{arn}:role/{COLLECTOR}",
        "roles": roles,
        "users": {
            name: f"{arn}:user/{name}" for name in ("analyst", "finance-clerk", "auditor", "zg-operator")
        },
        "groups": ["data-analysts", "finance-team"],
        "buckets": {
            "lake_raw": lake_raw,
            "lake_curated": lake_curated,
            "finance": finance,
            "results": results,
        },
        "glue": {"table": glue_table, "database": glue_db, "catalog": catalog},
        "workgroup": f"arn:aws:athena:{REGION}:{account}:workgroup/analytics",
        "member_credentials": credentials,
    }


# -- synthetic usage ---------------------------------------------------------------------


def usage_records(world: dict, end: datetime) -> list[dict]:
    """95 days of observed use: every grant the scenario needs, never the over-grant."""
    account, roles, users = world["account"], world["roles"], world["users"]
    buckets = world["buckets"]

    def event(principal_role, source, name, request, day, user=None, key=None, response=None):
        occurred = (end - timedelta(days=day, hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        if user:
            identity = {
                "type": "IAMUser",
                "arn": user,
                "accountId": account,
                "accessKeyId": "AKIAEXAMPLEUSER0001",
            }
        else:
            identity = {
                "type": "AssumedRole",
                "arn": f"arn:aws:sts::{account}:assumed-role/{principal_role.rsplit('/', 1)[-1]}/s{day}",
                "accountId": account,
                "accessKeyId": key or f"ASIAEXAMPLE{day:08d}",
                "sessionContext": {"sessionIssuer": {"type": "Role", "arn": principal_role}},
            }
        return {
            "eventVersion": "1.08",
            "eventTime": occurred,
            "eventSource": source,
            "eventName": name,
            "awsRegion": REGION,
            "recipientAccountId": account,
            "userIdentity": identity,
            "requestParameters": request,
            "responseElements": response,
        }

    records = []
    for day in range(USAGE_DAYS):
        # The ETL job reads and writes the lake and its catalog.
        for bucket in (buckets["lake_raw"], buckets["lake_curated"]):
            records.append(
                event(roles["etl"], "s3.amazonaws.com", "GetObject", {"bucketName": bucket, "key": "k"}, day)
            )
            records.append(
                event(roles["etl"], "s3.amazonaws.com", "PutObject", {"bucketName": bucket, "key": "k"}, day)
            )
        for database, name in (
            ("lake_raw", "events"),
            ("lake_raw", "customers"),
            ("lake_curated", "daily_metrics"),
        ):
            records.append(
                event(
                    roles["etl"],
                    "glue.amazonaws.com",
                    "GetTable",
                    {"databaseName": database, "name": name},
                    day,
                )
            )
            records.append(
                event(
                    roles["etl"],
                    "glue.amazonaws.com",
                    "UpdateTable",
                    {"databaseName": database, "tableInput": {"name": name}},
                    day,
                )
            )
        records.append(
            event(roles["etl"], "glue.amazonaws.com", "GetDatabase", {"name": "lake_curated"}, day)
        )
        records.append(
            event(
                roles["etl"],
                "glue.amazonaws.com",
                "CreateTable",
                {"databaseName": "lake_curated", "tableInput": {"name": "t"}},
                day,
            )
        )
        # The analyst assumes the reader role; its session reads the raw lake (attributed to the analyst).
        key = f"ASIAREADER{day:010d}"
        records.append(
            event(
                None,
                "sts.amazonaws.com",
                "AssumeRole",
                {"roleArn": roles["reader"], "roleSessionName": f"analyst-{day}"},
                day,
                user=users["analyst"],
                response={
                    "credentials": {"accessKeyId": key},
                    "assumedRoleUser": {
                        "arn": f"arn:aws:sts::{account}:assumed-role/zg-lake-reader/analyst-{day}"
                    },
                },
            )
        )
        records.append(
            event(
                roles["reader"],
                "s3.amazonaws.com",
                "GetObject",
                {"bucketName": buckets["lake_raw"], "key": "k"},
                day,
                key=key,
            )
        )
        records.append(
            event(
                roles["reader"],
                "s3.amazonaws.com",
                "ListObjects",
                {"bucketName": buckets["lake_raw"]},
                day,
                key=key,
            )
        )
        for name in ("events", "customers"):
            records.append(
                event(
                    roles["reader"],
                    "glue.amazonaws.com",
                    "GetTable",
                    {"databaseName": "lake_raw", "name": name},
                    day,
                    key=key,
                )
            )
        records.append(
            event(roles["reader"], "glue.amazonaws.com", "GetDatabase", {"name": "lake_raw"}, day, key=key)
        )
        records.append(
            event(
                roles["reader"],
                "athena.amazonaws.com",
                "StartQueryExecution",
                {"workGroup": "analytics"},
                day,
                key=key,
            )
        )
        # The finance app and the clerk use the ledger.
        records.append(
            event(
                roles["finance"],
                "s3.amazonaws.com",
                "GetObject",
                {"bucketName": buckets["finance"], "key": "k"},
                day,
            )
        )
        records.append(
            event(
                roles["finance"],
                "s3.amazonaws.com",
                "PutObject",
                {"bucketName": buckets["finance"], "key": "k"},
                day,
            )
        )
        records.append(
            event(
                roles["finance"],
                "glue.amazonaws.com",
                "GetTable",
                {"databaseName": "finance", "name": "ledger"},
                day,
            )
        )
        records.append(event(roles["finance"], "glue.amazonaws.com", "GetDatabase", {"name": "finance"}, day))
        records.append(
            event(
                None,
                "s3.amazonaws.com",
                "GetObject",
                {"bucketName": buckets["finance"], "key": "k"},
                day,
                user=users["finance-clerk"],
            )
        )
        records.append(
            event(
                None,
                "s3.amazonaws.com",
                "ListObjects",
                {"bucketName": buckets["finance"]},
                day,
                user=users["finance-clerk"],
            )
        )
    return records


# -- checks ------------------------------------------------------------------------------


class Checks:
    def __init__(self):
        self.results: list[dict] = []

    def __call__(self, name: str, ok, detail=None) -> bool:
        self.results.append(
            {"check": name, "ok": bool(ok), **({"detail": detail} if detail is not None else {})}
        )
        return bool(ok)

    @property
    def failures(self) -> list[dict]:
        return [result for result in self.results if not result["ok"]]


def env_for_sdk(endpoint: str, work: Path) -> None:
    """Every SDK client (CLI subprocess, worker, variants) talks to the emulator only."""
    for name in list(os.environ):
        if name.startswith("AWS_"):
            del os.environ[name]
    (work / "aws-config").write_text(f"[profile zg-emulated]\nregion = {REGION}\n")
    (work / "aws-credentials").write_text("")
    os.environ.update(
        AWS_ENDPOINT_URL=endpoint,
        AWS_CONFIG_FILE=str(work / "aws-config"),
        AWS_SHARED_CREDENTIALS_FILE=str(work / "aws-credentials"),
        AWS_EC2_METADATA_DISABLED="true",
        AWS_DEFAULT_REGION=REGION,
    )


def run_cli(world: dict, work: Path, output: Path, checks: Checks) -> dict:
    key = world["operator_key"]
    (work / "aws-credentials").write_text(
        f"[zg-emulated]\naws_access_key_id = {key['AccessKeyId']}\naws_secret_access_key = {key['SecretAccessKey']}\n"
    )
    artifact = output / "cli-artifact.json"
    artifact.unlink(missing_ok=True)
    started = time.perf_counter()
    result = subprocess.run(
        [
            sys.executable, "-m", "app.collectors.aws_collector",
            "--profile", "zg-emulated", "--region", REGION,
            "--account", world["account"], "--role-arn", world["collector"],
            "--confirm-account", world["account"], "--confirm-role", world["collector"],
            "--ack-readonly-sandbox", "--external-id-env", "ZG_QUALIFICATION_EXTERNAL_ID",
            "--access-advisor", "--data-lake", "--artifact", str(artifact),
        ],
        cwd=BACKEND,
        env={**os.environ, "ZG_QUALIFICATION_EXTERNAL_ID": EXTERNAL_ID},
        capture_output=True,
        text=True,
        timeout=600,
    )  # fmt: skip
    seconds = round(time.perf_counter() - started, 2)
    data = json.loads(artifact.read_text()) if artifact.exists() else {}
    checks(
        "cli exits 0",
        result.returncode == 0,
        {"returncode": result.returncode, "stderr": result.stderr[-2000:]},
    )
    checks("cli artifact mode 0600", artifact.exists() and (artifact.stat().st_mode & 0o777) == 0o600)
    text = artifact.read_text() if artifact.exists() else ""
    checks(
        "cli artifact never holds the external ID, account or names",
        EXTERNAL_ID not in text and world["account"] not in text and "zg-lake" not in text,
    )
    coverage = data.get("coverage", {})
    checks("cli caller identity verified", coverage.get("caller_identity_verified") is True)
    checks(
        "cli inventory complete",
        all(
            coverage.get(k)
            for k in (
                "iam_role_inventory_complete",
                "iam_user_inventory_complete",
                "iam_group_inventory_complete",
                "general_purpose_bucket_inventory_complete",
            )
        ),
    )
    return {
        "returncode": result.returncode,
        "seconds": seconds,
        "artifact": data,
        "stdout": result.stdout[-500:],
    }


# APIs moto 5.2 lacks or answers differently from AWS, and what the collector did about each.
MOTO_GAPS: list[dict] = []


def gap(api: str, behaviour: str, effect: str) -> None:
    if not any(item["api"] == api for item in MOTO_GAPS):
        MOTO_GAPS.append({"api": api, "moto": behaviour, "collector": effect})


class Recording:
    """Wraps ``AWSCollector`` in the worker so the run can read its warnings and coverage."""

    instances: list = []

    def __new__(cls, *args, **kwargs):
        from app.collectors.aws_collector import AWSCollector

        instance = AWSCollector(*args, **kwargs)
        cls.instances.append(instance)
        return instance


def app_environment(world: dict, work: Path) -> None:
    key = world["operator_key"]
    os.environ.update(
        ZG_ENVIRONMENT="test",
        ZG_GRAPH_VENDOR="memory",
        ZG_DATABASE_URL=f"sqlite:///{work}/app.db",
        ZG_AWS_TENANT_ID=TENANT,
        ZG_AWS_ROLE_ARN=world["collector"],
        ZG_AWS_ACCOUNT_ID=world["account"],
        ZG_AWS_EXTERNAL_ID=EXTERNAL_ID,
        ZG_AWS_REGION=REGION,
        ZG_AWS_ACCESS_ADVISOR="true",
        ZG_AWS_DATA_LAKE="true",
        # The worker's bootstrap credentials (the default chain), as on a deployed worker.
        AWS_ACCESS_KEY_ID=key["AccessKeyId"],
        AWS_SECRET_ACCESS_KEY=key["SecretAccessKey"],
    )


def upload_usage(client, world: dict, checks: Checks) -> dict:
    end = datetime.now(UTC).replace(microsecond=0)
    records = usage_records(world, end)
    created = client.post(
        "/api/v1/usage/uploads",
        json={
            "window_start": (end - timedelta(days=USAGE_DAYS)).isoformat(),
            "window_end": end.isoformat(),
            "attested_services": ["athena", "glue", "lakeformation", "s3", "sts"],
        },
    )
    checks("usage upload opens", created.status_code == 201, created.text[:300])
    upload = created.json()["id"]
    for chunk, offset in enumerate(range(0, len(records), 2000)):
        body = gzip.compress(json.dumps({"Records": records[offset : offset + 2000]}).encode())
        response = client.put(f"/api/v1/usage/uploads/{upload}/files/{chunk}", content=body)
        checks(f"usage file {chunk} staged", response.status_code == 200, response.text[:300])
    committed = client.post(f"/api/v1/usage/uploads/{upload}/commit")
    checks("usage upload commits", committed.status_code == 200, committed.text[:300])
    stats = committed.json()["stats"]
    checks(
        "usage records all matched",
        stats["matched"] == len(records),
        {"stats": stats, "records": len(records)},
    )
    return {"records": len(records), "stats": stats}


def run_in_app(world: dict, work: Path, checks: Checks) -> dict:
    app_environment(world, work)
    from fastapi.testclient import TestClient
    from loguru import logger

    logger.remove()
    from app.collectors import tasks
    from app.core.auth import Actor, current_actor
    from app.db.models import Base, IngestionJob, TenantState
    from app.db.session import session_factory
    from app.graph.repository import get_graph_store
    from app.main import create_app

    Base.metadata.create_all(session_factory().kw["bind"])
    app = create_app()
    app.dependency_overrides[current_actor] = lambda: Actor(
        "qualifier", TENANT, frozenset({"admin", "analyst", "viewer"})
    )
    client = TestClient(app)
    result: dict = {"usage": upload_usage(client, world, checks)}
    started = time.perf_counter()
    with patch("app.api.routes.ingest.delay"):
        response = client.post("/api/v1/ingestions", json={"source": "aws", "payload": {}})
    checks("aws ingestion accepted", response.status_code == 202, response.text[:300])
    job_id = response.json()["id"]
    with patch.object(tasks, "AWSCollector", Recording):
        try:
            tasks.process_job(job_id)
        except Exception as exc:  # noqa: BLE001 - the failure is the finding
            checks("aws job runs", False, f"{type(exc).__name__}: {exc}")
            raise
    result["job_seconds"] = round(time.perf_counter() - started, 2)
    with session_factory()() as db:
        job = db.get(IngestionJob, job_id)
        checks("aws job completed", job.status == "completed", {"status": job.status, "error": job.error})
        revision = db.get(TenantState, TENANT).revision
    collector = Recording.instances[-1]
    snapshot = get_graph_store().snapshot(TENANT, revision)
    result["collector"] = {
        "counts": collector.counts,
        "coverage": collector.coverage,
        "warning_counts": collector.warning_counts,
        "sdk_requests": collector.requests,
        "sdk_pages": collector.pages,
    }
    result["published"] = {
        "nodes": Counter(node.type.value for node in snapshot.nodes),
        "edges": Counter(edge.type.value for edge in snapshot.edges),
    }
    result.update(check_published(client, world, collector, snapshot, checks))
    client.close()
    return result


def check_published(client, world: dict, collector, snapshot, checks: Checks) -> dict:
    nodes = {node.id: node for node in snapshot.nodes}
    edges = [edge for edge in snapshot.edges]
    roles, users, buckets = world["roles"], world["users"], world["buckets"]
    counts = collector.counts
    # moto adds OrganizationAccountAccessRole; the seed adds 7 roles, 4 users, 2 groups, 4 buckets.
    checks("inventory roles", counts["roles"] == 8, counts)
    checks("inventory users", counts["users"] == 4, counts)
    checks("inventory groups", counts["groups"] == 2, counts)
    checks("inventory buckets", counts["buckets"] == 4, counts)
    checks("glue inventory", (counts["glue_databases"], counts["glue_tables"]) == (3, 4), counts)
    checks("athena workgroups", counts["athena_workgroups"] == 2, counts)
    checks("lake formation permissions", counts["lakeformation_permissions"] >= 7, counts)
    reader, dormant = nodes.get(roles["reader"]), nodes.get(roles["dormant"])
    checks("role tags kept", reader is not None and "topic=data-lake" in reader.tags, reader and reader.tags)
    analyst = nodes.get(users["analyst"])
    checks(
        "users are humans with groups",
        analyst is not None
        and analyst.type.value == "HumanUser"
        and analyst.metadata.get("groups") == ["data-analysts"],
        analyst and analyst.metadata,
    )
    collector_node = nodes.get(world["collector"])
    checks(
        "RoleLastUsed observed for the collector role (used by this run's AssumeRole)",
        collector_node is not None and "role_last_used" in collector_node.metadata,
        collector_node and collector_node.metadata,
    )
    checks(
        "RoleLastUsed absent for the dormant role",
        dormant is not None and "role_last_used" not in dormant.metadata,
    )
    checks(
        "RoleLastUsed coverage counts",
        collector.coverage["role_last_used"]["observed"] >= 1
        and collector.coverage["role_last_used"]["absent"] >= 6,
        collector.coverage["role_last_used"],
    )
    raw = nodes.get(f"arn:aws:s3:::{buckets['lake_raw']}")
    checks(
        "bucket classification tag labels PII",
        raw is not None and "PII" in raw.tags and "topic=data-lake" in raw.tags,
        raw and raw.tags,
    )
    checks(
        "bucket encryption verified",
        raw is not None and raw.metadata.get("encryption_verified") is True,
        raw and raw.metadata,
    )
    ledger_bucket = nodes.get(f"arn:aws:s3:::{buckets['finance']}")
    checks(
        "bucket policy observed",
        ledger_bucket is not None and ledger_bucket.metadata.get("bucket_policy") == "observed",
        ledger_bucket and ledger_bucket.metadata,
    )
    # Policy documents: stored once per digest, served per principal, never in node JSON.
    support = client.get("/api/v1/graph/policies", params={"principal": roles["support"]}).json()
    documents = support.get("policies") or support.get("attachments") or []
    big = [item for item in documents if "AWSSupportServiceRolePolicy" in json.dumps(item)[:4000]]
    checks(
        "AWSSupportServiceRolePolicy served for its role",
        bool(big),
        {k: v for k, v in support.items() if k != "policies"},
    )
    size = len(json.dumps(big[0].get("document", {}), separators=(",", ":"))) if big else 0
    checks("AWSSupportServiceRolePolicy is the large document (>64 KiB), evaluated", size > 65536, size)
    checks("no policy left unevaluated", collector.coverage["unevaluated_policy_documents"] == 0)
    checks(
        "node JSON never carries policy documents",
        not any("Statement" in json.dumps(node.metadata) for node in snapshot.nodes),
    )
    reader_docs = client.get("/api/v1/graph/policies", params={"principal": roles["reader"]}).json()
    kinds = sorted(item.get("kind") for item in reader_docs.get("policies", []))
    checks("reader inline, managed and trust stored", kinds == ["inline", "managed", "trust"], kinds)
    analyst_docs = client.get("/api/v1/graph/policies", params={"principal": users["analyst"]}).json()
    checks(
        "group policies folded into the user",
        [item.get("kind") for item in analyst_docs.get("policies", [])] == ["group-inline"],
        analyst_docs.get("policies"),
    )
    result = {"policy_digests": len({item.get("digest") for item in documents})}

    # Data lake nodes and edges.
    table = world["glue"]["table"]
    events, customers = nodes.get(f"{table}/lake_raw/events"), nodes.get(f"{table}/lake_raw/customers")
    ledger = nodes.get(f"{table}/finance/ledger")
    checks(
        "glue tables are DataTable nodes",
        all(n is not None and n.type.value == "DataTable" for n in (events, customers, ledger)),
    )
    checks(
        "column names classify tables", events is not None and "PII" in events.tags, events and events.tags
    )
    checks(
        "tables join the data-lake topic",
        events is not None and events.metadata.get("topic") == "data-lake",
        events and events.metadata,
    )
    checks(
        "table S3 location links the bucket",
        events is not None
        and events.metadata.get("location_bucket") == f"arn:aws:s3:::{buckets['lake_raw']}",
        events and events.metadata,
    )
    modes = collector.coverage["data_lake"]["lakeformation_table_modes"]
    checks(
        "lake formation modes resolved",
        modes == {"iam_allowed_principals": 1, "lakeformation": 3, "unknown": 0},
        modes,
    )
    checks(
        "hybrid table mode",
        ledger is not None and ledger.metadata.get("lakeformation_mode") == "iam_allowed_principals",
        ledger and ledger.metadata,
    )
    by_pair: dict[tuple, list] = {}
    for edge in edges:
        by_pair.setdefault((edge.source, edge.target), []).append(edge)
    reader_events = by_pair.get((roles["reader"], events.id if events else ""), [])
    checks(
        "lake formation grant becomes the edge on a governed table",
        any("lakeformation:SELECT" in edge.actions for edge in reader_events),
        [edge.actions for edge in reader_events],
    )
    reader_customers = by_pair.get((roles["reader"], customers.id if customers else ""), [])
    checks(
        "column grant is partial",
        any("partial access only" in " ".join(edge.evidence) for edge in reader_customers),
        [edge.evidence for edge in reader_customers],
    )
    finance_events = by_pair.get((roles["finance"], events.id if events else ""), [])
    checks("no IAM edge without an LF grant on a governed table", not finance_events)
    workgroup = nodes.get(world["workgroup"])
    checks(
        "athena workgroup node with its result bucket",
        workgroup is not None
        and workgroup.type.value == "QueryWorkgroup"
        and workgroup.metadata.get("output_bucket") == f"arn:aws:s3:::{buckets['results']}",
        workgroup and workgroup.metadata,
    )
    checks(
        "collector role marked lake formation read-only admin",
        collector_node is not None
        and collector_node.metadata.get("lakeformation_admin") == "read_only_admin",
        collector_node and collector_node.metadata,
    )
    checks(
        "catalog resource policy observed",
        collector.coverage["data_lake"]["glue_resource_policy"] == "observed",
        collector.coverage["data_lake"]["glue_resource_policy"],
    )
    over = by_pair.get((roles["reader"], f"arn:aws:s3:::{buckets['finance']}"), [])
    checks("the over-grant is an edge", bool(over), [edge.actions for edge in over])
    assumes = by_pair.get((users["analyst"], roles["reader"]), [])
    checks(
        "analyst may assume the reader role (group policy + trust)",
        any(e.type.value == "ASSUMES_ROLE" for e in assumes),
    )

    # Topics.
    topics = client.get("/api/v1/graph/topics").json()
    names = {topic["name"]: topic for topic in topics.get("topics", [])}
    checks("topics data-lake and finance form", {"data-lake", "finance"} <= set(names), sorted(names))
    result["topics"] = {
        name: {
            k: topic[k]
            for k in ("kind", "resources", "roles", "identities", "cross_grants_out", "cross_grants_in")
        }
        for name, topic in names.items()
    }
    # Proposals.
    listing = client.get("/api/v1/proposals", params={"limit": 200}).json()
    proposals = listing.get("proposals", [])
    result["proposals"] = [
        {k: p[k] for k in ("type", "tier", "subject_name", "target_name", "reasons")} for p in proposals
    ]
    result["proposal_summary"] = listing.get("summary")
    over_grant = [
        p
        for p in proposals
        if p["type"] == "remove_grant"
        and p["subject_id"] == roles["reader"]
        and p["target_id"] == f"arn:aws:s3:::{buckets['finance']}"
    ]
    checks(
        "the cross-topic over-grant is a high-tier remove_grant",
        any(p["tier"] == "high" for p in over_grant),
        [(p["tier"], p["reasons"]) for p in over_grant],
    )
    lake = [p for p in proposals if any("lakeformation:" in json.dumps(c) for c in p["changes"])]
    checks(
        "proposals touching lake formation grants are manual",
        all(p["tier"] == "manual" for p in lake),
        [(p["type"], p["tier"], p["subject_name"], p["target_name"]) for p in lake if p["tier"] != "manual"],
    )
    dormant_role = [
        p for p in proposals if p["type"] == "disable_role" and p["subject_id"] == roles["dormant"]
    ]
    checks(
        "the dormant role is proposed for disabling", bool(dormant_role), [p["tier"] for p in dormant_role]
    )
    used = [
        p
        for p in proposals
        if p["type"] == "remove_grant"
        and p["subject_id"] == roles["reader"]
        and p["target_id"] == f"arn:aws:s3:::{buckets['lake_raw']}"
    ]
    checks("no proposal removes observed use", not used, used)
    return result


def assumed_session(boto3, world: dict):
    key = world["operator_key"]
    bootstrap = session(boto3, key["AccessKeyId"], key["SecretAccessKey"])
    credentials = bootstrap.client("sts").assume_role(
        RoleArn=world["collector"],
        RoleSessionName="ZeroGraphVariant",
        ExternalId=EXTERNAL_ID,
        DurationSeconds=900,
    )["Credentials"]
    return session(
        boto3, credentials["AccessKeyId"], credentials["SecretAccessKey"], credentials["SessionToken"]
    )


def run_variants(boto3, world: dict, checks: Checks) -> dict:
    from app.collectors.aws_collector import SDK_CONFIG, AWSCollector

    result = {}
    # 1. SCPs: Organizations reads through the management account (a delegated administrator).
    collector = AWSCollector(
        assumed_session(boto3, world),
        expected_account=world["account"],
        expected_role_arn=world["collector"],
        data_lake=False,
    )
    collector.organizations = session(boto3).client("organizations", config=SDK_CONFIG)
    snapshot = collector.collect()
    checks(
        "scp inventory collected",
        collector.coverage["scp_inventory"] == "collected",
        collector.coverage["scp_inventory"],
    )
    finance = f"arn:aws:s3:::{world['buckets']['finance']}"
    writes = [
        e
        for e in snapshot.edges
        if e.source == world["roles"]["finance"] and e.target == finance and e.type.value == "CAN_WRITE"
    ]
    checks(
        "scp deny removes s3:DeleteObject from write edges",
        writes and "s3:DeleteObject" not in writes[0].actions and "s3:PutObject" in writes[0].actions,
        [e.actions for e in writes],
    )
    support = next((n for n in snapshot.nodes if n.id == world["roles"]["support"]), None)
    checks(
        "service-linked role exempt from SCPs",
        support is not None and support.metadata.get("scp_exempt_service_linked_role") is True,
        support and support.metadata,
    )
    result["scp"] = {"coverage": collector.coverage["scp_inventory"], "warnings": collector.warning_counts}

    # 2. LF-Tag grant: resolving it needs SearchTablesByLFTags, which moto does not implement.
    credentials = world["member_credentials"]
    member = session(
        boto3, credentials["AccessKeyId"], credentials["SecretAccessKey"], credentials["SessionToken"]
    )
    lf = member.client("lakeformation")
    lf.create_lf_tag(TagKey="domain", TagValues=["analytics", "finance"])
    lf.add_lf_tags_to_resource(
        Resource={"Database": {"Name": "lake_curated"}},
        LFTags=[{"TagKey": "domain", "TagValues": ["analytics"]}],
    )
    lf.grant_permissions(
        Principal={"DataLakePrincipalIdentifier": world["roles"]["reader"]},
        Resource={
            "LFTagPolicy": {
                "ResourceType": "TABLE",
                "Expression": [{"TagKey": "domain", "TagValues": ["analytics"]}],
            }
        },
        Permissions=["SELECT"],
    )
    collector = AWSCollector(
        assumed_session(boto3, world),
        expected_account=world["account"],
        expected_role_arn=world["collector"],
        data_lake=True,
    )
    collector.collect()
    lake = collector.coverage["data_lake"]
    result["lf_tag"] = {
        "coverage": {k: v for k, v in lake.items() if k.startswith("lakeformation")},
        "warnings": collector.warning_counts,
    }
    if lake["lakeformation_lf_tag_assignments"] == "unknown":
        gap(
            "lakeformation:SearchTablesByLFTags / SearchDatabasesByLFTags",
            "HTTP 404 (not implemented)",
            "warning lakeformation_lf_tag_assignments_unknown + lakeformation_lf_tag_unresolved; every table mode unknown, IAM edges stand",
        )
    checks(
        "unresolvable LF-Tag grant degrades every mode to unknown (never under-states)",
        lake["lakeformation_table_modes"]["unknown"] == 4
        and collector.warning_counts.get("lakeformation_lf_tag_unresolved"),
        {"modes": lake["lakeformation_table_modes"], "warnings": collector.warning_counts},
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--output", type=Path, required=True, help="Directory for the report and CLI artifact"
    )
    parser.add_argument("--port", type=int, default=55551)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="zg-aws-emulated-"))
    checks = Checks()
    report: dict = {"python": platform.python_version(), "region": REGION}
    started = time.perf_counter()
    try:
        with moto_server(args.port, args.output / "moto_server.log") as endpoint:
            env_for_sdk(endpoint, work)
            import boto3
            import moto

            report["moto"] = moto.__version__
            world = seed(boto3)
            report["account_seeded"] = True
            report["cli"] = run_cli(world, work, args.output, checks)
            report.update(run_in_app(world, work, checks))
            report["variants"] = run_variants(boto3, world, checks)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    report["seconds"] = round(time.perf_counter() - started, 1)
    report["checks"] = checks.results
    report["failures"] = checks.failures
    report["moto_gaps"] = MOTO_GAPS
    (args.output / "aws-emulated.json").write_text(
        json.dumps(report, indent=2, sort_keys=True, default=str) + "\n"
    )
    print(json.dumps({"checks": len(checks.results), "failures": [f["check"] for f in checks.failures]}))
    sys.exit(1 if checks.failures else 0)


if __name__ == "__main__":
    main()
