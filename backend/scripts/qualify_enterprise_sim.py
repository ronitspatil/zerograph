"""Enterprise simulation: the whole product pipeline against an emulated enterprise AWS account.

No real AWS account is used. Like ``qualify_aws_emulated.py`` the script starts
``moto_server`` (dev-only, ``requirements-dev.lock``) on 127.0.0.1 and points every SDK
client at it with ``AWS_ENDPOINT_URL``. It then:

1. **Seeds** a member account of an AWS Organization at enterprise scale with a known
   ground truth: about 1,500 IAM roles (application roles per topic, near-duplicates,
   dormant roles, human roles assumed through group policies, IAM Identity Center
   permission-set roles, AWS-managed-policy admin hubs, service-linked roles, break-glass
   roles, GitHub OIDC deploy roles and roles trusted by other accounts), 400 users in 40
   Identity-Center-style groups, 300 S3 buckets (tags, bucket policies, encryption and an
   Object Ownership mix), a Glue data lake (databases and tables with S3 locations, a
   Lake Formation governed database with named and column grants, hybrid databases, LF-Tags),
   Athena workgroups, planted cross-topic over-grants, conditional grants, resource-policy
   grants, a seasonal exemption, an unused role assumption and a toxic path (an exposed,
   unauthenticated agent that can assume a role reading restricted HR data).
2. **Simulates** 95 days of activity from that ground truth as CloudTrail export files
   (gzip ``{"Records": [...]}``): ``AssumeRole`` with session keys issued to users (some
   with ``sourceIdentity``), AWS services, SAML (Identity Center, ``onBehalfOf``) and web
   identity (GitHub OIDC), S3 data events, Glue (mixed-case names), Athena and Lake
   Formation events, denied attempts, sessions issued before the window and activity that
   lies entirely outside it.
3. **Runs the real pipeline** as a customer would, in process against the FastAPI app:
   AWS collection through the settings path (``ZG_AWS_ROLE_ARN``/``ZG_AWS_EXTERNAL_ID``,
   ``POST /ingestions`` with source ``aws``, the worker's ``process_job``: STS
   AssumeRole into the emulator, the real collector, staging, publication), the agent
   inventory as a second source that references the AWS role by ID, a re-collection after
   the role's metadata changes (no conflict; restating the role would conflict, and a
   reference no source defines fails clearly), the CloudTrail upload through ``/usage/uploads``, the
   worker's topic and proposal backfill sweeps, topics, the excess-privilege index (EPI),
   proposals, accepting a sample, what-if, GitOps draft PRs against the local fake
   provider (``tests/fake_git.py``) with canary gating, verify, a byte-exact revert and the
   AccessDenied auto-revert from a follow-up CloudTrail upload.
4. **Asserts against the ground truth**: inventory completeness, topic accuracy, EPI
   against the independent brute force (``qualify_usage.reference_privilege``), dormant
   and never-assumed recall, high-tier ``remove_grant`` precision and recall, never-auto
   categories manual (disabling a dormant role a partner account trusts is ``cross_account``;
   same-account dormant roles stay automatic), the toxic path's agent hop labelled
   ``non_aws`` rather than cross-account, the collector excluded, no proposal removing
   observed use, and the
   rollout invariants (draft only, canary gating, byte-exact revert). Timings and RSS are
   reported per phase.

Every API moto lacks or answers differently from AWS is recorded under ``moto_gaps``,
separately from ``failures`` (product bugs). Exit status is non-zero when any check fails.
App state is a disposable SQLite database (or a disposable schema of ``--database-url``)
and the in-memory graph store; the moto server is always stopped.
"""

import argparse
import gzip
import hashlib
import json
import os
import platform
import random
import resource
import shutil
import sys
import tempfile
import time
import zlib
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND / "scripts"))
sys.path.insert(0, str(BACKEND / "tests"))

from qualify_aws_emulated import (  # noqa: E402
    COLLECTOR,
    EXTERNAL_ID,
    MOTO_GAPS,
    REGION,
    AllBuckets,
    Checks,
    allow,
    document,
    env_for_sdk,
    gap,
    moto_server,
    session,
)
from qualify_aws_emulated import Recording as EmulatedRecording  # noqa: E402

TENANT = "tenant-enterprise"

USAGE_DAYS = 95
TOPICS = ("data-lake", "payments", "ml", "ci-cd", "hr", "marketing", "logistics", "security")
OBSERVABILITY = "observability"
BUCKETS_PER_TOPIC = 35
OBSERVABILITY_BUCKETS = 20
APP_ROLES_PER_TOPIC = 150
DORMANT_ROLES_PER_TOPIC = 8
OUT_OF_WINDOW_ROLES_PER_TOPIC = 2
DUPLICATE_PAIRS_PER_TOPIC = 4
USERS_PER_TOPIC = 50
PARTNER_ACCOUNTS = ("111122223333", "444455556666")
IDENTITY_STORE = "arn:aws:identitystore::123456789012:identitystore/d-9067abcdef"
CLASSIFICATION = {
    "payments": {"data-class": "PCI"},
    "hr": {"data-class": "PII", "classification": "restricted"},
    "ml": {"classification": "confidential"},
}
PURPOSES = ("raw", "curated", "exports", "archive", "staging", "reports", "assets")
SERVICES = ("api", "worker", "etl", "batch", "stream", "sync", "scheduler-svc", "ingest")
TRUSTS = ("lambda.amazonaws.com", "ecs-tasks.amazonaws.com", "glue.amazonaws.com", "sagemaker.amazonaws.com")
FIRST = (
    "alex", "blair", "casey", "devon", "emery", "finley", "gray", "harper", "indra", "jules",
    "kai", "logan", "morgan", "noor", "oakley", "parker", "quinn", "reese", "sage", "taylor",
)  # fmt: skip
LAST = (
    "adams", "baker", "chen", "diaz", "evans", "fischer", "garcia", "hughes", "ito", "jones",
    "kim", "lopez", "moore", "nguyen", "okafor", "patel", "quist", "rossi", "singh", "tanaka",
)  # fmt: skip
GROUP_KINDS = ("engineers", "leads", "analysts", "oncall", "contractors")
GROUP_SIZES = {"engineers": 20, "leads": 5, "analysts": 15, "oncall": 5, "contractors": 5}
SSO_PERMISSION_SETS = (
    ("AdministratorAccess", ["AdministratorAccess"]),
    ("PowerUserAccess", ["PowerUserAccess"]),
    ("ReadOnlyAccess", ["ReadOnlyAccess"]),
    ("ViewOnlyAccess", ["ViewOnlyAccess"]),
    ("SecurityAudit", ["SecurityAudit"]),
    ("DataLakeAdmin", ["AWSLakeFormationDataAdmin", "AmazonAthenaFullAccess"]),
    ("DataEngineer", ["AWSGlueConsoleFullAccess", "AmazonS3ReadOnlyAccess"]),
    ("MLScientist", ["AmazonSageMakerFullAccess"]),
    ("S3Admin", ["AmazonS3FullAccess"]),
    ("AnalyticsReader", ["AmazonAthenaFullAccess", "AmazonS3ReadOnlyAccess"]),
)
SERVICE_LINKED = (
    ("support.amazonaws.com", "AWSServiceRoleForSupport", "AWSSupportServiceRolePolicy"),
    ("macie.amazonaws.com", "AWSServiceRoleForAmazonMacie", "AmazonMacieServiceRolePolicy"),
    ("trustedadvisor.amazonaws.com", "AWSServiceRoleForTrustedAdvisor", "AWSTrustedAdvisorServiceRolePolicy"),
    ("rds.amazonaws.com", "AWSServiceRoleForRDS", "AmazonRDSServiceRolePolicy"),
    ("ecs.amazonaws.com", "AWSServiceRoleForECS", "AmazonECSServiceRolePolicy"),
    ("autoscaling.amazonaws.com", "AWSServiceRoleForAutoScaling", "AutoScalingServiceRolePolicy"),
    ("config.amazonaws.com", "AWSServiceRoleForConfig", "AWSConfigServiceRolePolicy"),
    ("guardduty.amazonaws.com", "AWSServiceRoleForAmazonGuardDuty", "AmazonGuardDutyServiceRolePolicy"),
    ("backup.amazonaws.com", "AWSServiceRoleForBackup", "AWSBackupServiceRolePolicyForBackup"),
    (
        "elasticloadbalancing.amazonaws.com",
        "AWSServiceRoleForElasticLoadBalancing",
        "AWSElasticLoadBalancingServiceRolePolicy",
    ),
    ("eks.amazonaws.com", "AWSServiceRoleForAmazonEKS", "AmazonEKSServiceRolePolicy"),
    ("sso.amazonaws.com", "AWSServiceRoleForSSO", "AWSSSOServiceRolePolicy"),
    ("inspector2.amazonaws.com", "AWSServiceRoleForAmazonInspector2", "AmazonInspector2ServiceRolePolicy"),
    ("securityhub.amazonaws.com", "AWSServiceRoleForSecurityHub", "AWSSecurityHubServiceRolePolicy"),
    ("access-analyzer.amazonaws.com", "AWSServiceRoleForAccessAnalyzer", "AccessAnalyzerServiceRolePolicy"),
    ("ssm.amazonaws.com", "AWSServiceRoleForAmazonSSM", "AmazonSSMServiceRolePolicy"),
    ("redshift.amazonaws.com", "AWSServiceRoleForRedshift", "AmazonRedshiftServiceLinkedRolePolicy"),
    (
        "elasticfilesystem.amazonaws.com",
        "AWSServiceRoleForAmazonElasticFileSystem",
        "AmazonElasticFileSystemServiceRolePolicy",
    ),
    ("events.amazonaws.com", "AWSServiceRoleForCloudWatchEvents", "CloudWatchEventsServiceRolePolicy"),
    (
        "ecs.application-autoscaling.amazonaws.com",
        "AWSServiceRoleForApplicationAutoScaling_ECSService",
        "AWSApplicationAutoscalingECSServicePolicy",
    ),
    ("organizations.amazonaws.com", "AWSServiceRoleForOrganizations", "AWSOrganizationsServiceTrustPolicy"),
    ("elasticmapreduce.amazonaws.com", "AWSServiceRoleForEMRCleanup", "AmazonEMRCleanupPolicy"),
)
# Glue data lake: database -> (topic, Lake Formation governed?, tables).
DATABASES = {
    "lake_raw": ("data-lake", True, ("events", "customers", "clickstream", "orders", "sessions", "devices")),
    "lake_curated": ("data-lake", False, ("daily_metrics", "customer_360", "order_facts", "funnel", "cohorts")),
    "payments_ledger": ("payments", False, ("ledger", "settlements", "chargebacks", "payouts")),
    "hr_core": ("hr", False, ("employees", "compensation", "reviews", "benefits")),
    "ml_features": ("ml", False, ("user_features", "item_features", "training_labels", "embeddings_index")),
    "marketing_events": ("marketing", False, ("campaigns", "impressions", "conversions")),
    "shipments": ("logistics", False, ("shipments", "carriers", "routes")),
}
COLUMNS = {
    "customers": ["customer_id", "email", "ssn", "address"],
    "ledger": ["entry_id", "card_number", "amount"],
    "employees": ["employee_id", "email", "date_of_birth", "salary"],
    "compensation": ["employee_id", "salary", "bank_account"],
}
WORKGROUPS = {
    "analytics": "data-lake",
    "payments-reporting": "payments",
    "ml-exploration": "ml",
    "hr-reporting": "hr",
    "marketing-insights": "marketing",
}
S3_READ = ["s3:GetObject", "s3:ListBucket"]
S3_WRITE = ["s3:PutObject"]


class Recording(EmulatedRecording):
    """The worker's collector, recorded; its S3 client lists every bucket in one call because
    moto honours ``MaxBuckets`` but never returns a ``ContinuationToken`` (see moto_gaps)."""

    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls, *args, **kwargs)
        instance.s3 = AllBuckets(instance.s3)
        return instance


def _rng(*parts) -> random.Random:
    return random.Random(zlib.crc32("\0".join(map(str, parts)).encode()))


def managed_arn(name: str) -> str:
    """An AWS-managed policy ARN with its path (``job-function/``, ``aws-service-role/``...)."""
    import moto.iam.aws_managed_policies as managed_data

    available = json.loads(managed_data.aws_managed_policies_data)
    return f"arn:aws:iam::aws:policy{available[name].get('Path', '/')}{name}"


def bucket_arn(name: str) -> str:
    return f"arn:aws:s3:::{name}"


def s3_resources(names) -> list[str]:
    return [f"arn:aws:s3:::{name}{suffix}" for name in names for suffix in ("", "/*")]


class Truth:
    """The planted ground truth: who is granted what, who used what, and what must be proposed."""

    def __init__(self, account: str):
        self.account = account
        self.arn = f"arn:aws:iam::{account}"
        self.table_prefix = f"arn:aws:glue:{REGION}:{account}:table"
        self.database_prefix = f"arn:aws:glue:{REGION}:{account}:database"
        self.catalog = f"arn:aws:glue:{REGION}:{account}:catalog"
        self.buckets: dict[str, dict] = {}  # name -> {"topic", "tagged", "ownership", ...}
        self.tables: dict[str, str] = {}  # table ARN -> topic
        self.databases: dict[str, str] = {}  # database ARN -> topic
        self.roles: dict[str, dict] = {}  # role ARN -> {"topic", "kind", "grants", "used", ...}
        self.users: dict[str, dict] = {}  # user ARN -> {"topic", "groups", "kind", ...}
        self.groups: dict[str, dict] = {}  # group name -> {"topic", "kind", "assume", "grants"}
        self.over_grants: set[tuple[str, str]] = set()  # (holder, asset) unused, outside the topic
        self.conditional: set[tuple[str, str]] = set()  # (holder, asset) granted with a Condition
        self.resource_policy: set[tuple[str, str]] = set()  # (role, bucket) granted by a bucket policy
        self.lf_grants: set[tuple[str, str]] = set()  # (role, table) granted by Lake Formation
        self.lf_unused: set[tuple[str, str]] = set()
        self.duplicates: list[tuple[str, str]] = []
        self.toxic: dict = {}
        self.workgroups: dict[str, str] = {}

    def role(self, name: str, path: str = "/") -> str:
        return f"{self.arn}:role{path}{name}"

    def table(self, database: str, name: str) -> str:
        return f"{self.table_prefix}/{database}/{name}"

    def database(self, name: str) -> str:
        return f"{self.database_prefix}/{name}"

    def topic_buckets(self, topic: str) -> list[str]:
        return sorted(name for name, item in self.buckets.items() if item["topic"] == topic)

    def asset_topic(self, asset: str) -> str | None:
        if asset.startswith("arn:aws:s3:::"):
            item = self.buckets.get(asset.removeprefix("arn:aws:s3:::"))
            return item["topic"] if item else None
        return self.tables.get(asset) or self.databases.get(asset)


# -- seeding -----------------------------------------------------------------------------


def seed(boto3) -> tuple[dict, Truth]:  # noqa: C901 - one linear account build
    """An Organization (management = moto's default account) and a large member account."""
    management = session(boto3)
    org = management.client("organizations")
    org.create_organization(FeatureSet="ALL")
    request = org.create_account(Email="prod-data@example.com", AccountName="acme-prod-data")[
        "CreateAccountStatus"
    ]
    account = org.describe_create_account_status(CreateAccountRequestId=request["Id"])["CreateAccountStatus"][
        "AccountId"
    ]
    root = org.list_roots()["Roots"][0]["Id"]
    ou = org.create_organizational_unit(ParentId=root, Name="production")["OrganizationalUnit"]["Id"]
    org.move_account(AccountId=account, SourceParentId=root, DestinationParentId=ou)
    scp = org.create_policy(
        Name="deny-object-lock-bypass",
        Description="Production guardrail",
        Type="SERVICE_CONTROL_POLICY",
        Content=document(
            {"Effect": "Deny", "Action": ["s3:BypassGovernanceRetention", "s3:DeleteBucket"], "Resource": "*"}
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
    truth = Truth(account)
    arn = truth.arn
    counts = Counter()

    # Bootstrap operator (the worker's default credentials) and the read-only collector role.
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

    # -- S3: 8 topics x 35 buckets + 20 observability buckets.
    ownership_cycle = ("BucketOwnerEnforced", "BucketOwnerEnforced", "ObjectWriter", "BucketOwnerPreferred", None)
    for topic in (*TOPICS, OBSERVABILITY):
        total = OBSERVABILITY_BUCKETS if topic == OBSERVABILITY else BUCKETS_PER_TOPIC
        for index in range(total):
            purpose = ("logs", "access-logs", "cloudtrail", "metrics")[index % 4] if topic == OBSERVABILITY else (
                PURPOSES[index % len(PURPOSES)]
            )
            name = f"acme-{topic}-{purpose}-{index:03d}-{account}"
            tagged = index % 5 != 4  # Every fifth bucket carries its topic only in its name.
            tags = {"topic": topic} if tagged else {}
            if index % 3 == 0:
                tags.update(CLASSIFICATION.get(topic, {}))
            tags["cost-center"] = f"cc-{1000 + TOPICS.index(topic) if topic in TOPICS else 1999}"
            ownership = ownership_cycle[index % len(ownership_cycle)]
            s3.create_bucket(Bucket=name)
            if ownership:
                s3.put_bucket_ownership_controls(
                    Bucket=name, OwnershipControls={"Rules": [{"ObjectOwnership": ownership}]}
                )
            s3.put_bucket_tagging(
                Bucket=name, Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in tags.items()]}
            )
            if index % 4 != 3:
                s3.put_bucket_encryption(
                    Bucket=name,
                    ServerSideEncryptionConfiguration={
                        "Rules": [
                            {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": ("AES256", "aws:kms")[index % 2]}}
                        ]
                    },
                )
            truth.buckets[name] = {"topic": topic, "tagged": tagged, "ownership": ownership or "absent"}
            counts["buckets"] += 1
    # Bucket policies: TLS-only on the payments and HR buckets; a partner account reads data-lake exports.
    for name, item in truth.buckets.items():
        statements = []
        if item["topic"] in ("payments", "hr"):
            statements.append(
                {
                    "Sid": "DenyInsecureTransport",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": s3_resources([name]),
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                }
            )
        if item["topic"] == "data-lake" and "-exports-" in name:
            statements.append(
                {
                    "Sid": "PartnerRead",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{PARTNER_ACCOUNTS[0]}:root"},
                    "Action": S3_READ,
                    "Resource": s3_resources([name]),
                }
            )
        if statements:
            item["policy"] = statements

    # -- Glue Data Catalog, Athena, Lake Formation.
    for database, (topic, _, tables) in DATABASES.items():
        bucket = next(b for b in truth.topic_buckets(topic) if "-curated-" in b or "-raw-" in b)
        glue.create_database(DatabaseInput={"Name": database, "LocationUri": f"s3://{bucket}/{database}/"})
        glue.tag_resource(ResourceArn=truth.database(database), TagsToAdd={"topic": topic})
        truth.databases[truth.database(database)] = topic
        for table in tables:
            glue.create_table(
                DatabaseName=database,
                TableInput={
                    "Name": table,
                    "StorageDescriptor": {
                        "Columns": [{"Name": c, "Type": "string"} for c in COLUMNS.get(table, ["id", "value"])],
                        "Location": f"s3://{bucket}/{database}/{table}/",
                    },
                    "PartitionKeys": [{"Name": "dt", "Type": "string"}],
                    "Parameters": {"classification": "parquet"},
                },
            )
            truth.tables[truth.table(database, table)] = topic
            counts["tables"] += 1
    for name, topic in WORKGROUPS.items():
        output = next(b for b in truth.topic_buckets(topic) if "-reports-" in b)
        athena.create_work_group(
            Name=name,
            Configuration={
                "ResultConfiguration": {"OutputLocation": f"s3://{output}/athena/"},
                "EnforceWorkGroupConfiguration": True,
            },
            Tags=[{"Key": "topic", "Value": topic}],
        )
        truth.workgroups[f"arn:aws:athena:{REGION}:{account}:workgroup/{name}"] = topic

    # -- Roles.
    def create_role(name, trust, *, topic=None, kind, path="/", tags=(), statements=(), managed=(), **extra):
        all_tags = [{"Key": "topic", "Value": topic}] if topic and kind != "app-untagged" else []
        all_tags += [{"Key": k, "Value": v} for k, v in tags]
        trust = trust if isinstance(trust, list) else [trust]
        iam.create_role(
            RoleName=name, Path=path, AssumeRolePolicyDocument=document(*trust), Tags=all_tags[:50]
        )
        if statements:
            iam.put_role_policy(RoleName=name, PolicyName=f"{name}-access", PolicyDocument=document(*statements))
        for policy in managed:
            iam.attach_role_policy(RoleName=name, PolicyArn=policy)
        role_arn = truth.role(name, path)
        truth.roles[role_arn] = {
            "name": name,
            "topic": topic,
            "kind": kind,
            "grants": defaultdict(set),  # asset -> {"read", "write"}
            "used": defaultdict(set),
            "trust": trust,
            **extra,
        }
        counts["roles"] += 1
        return role_arn

    def service_trust(host):
        return {"Effect": "Allow", "Principal": {"Service": host}, "Action": "sts:AssumeRole"}

    root_trust = {"Effect": "Allow", "Principal": {"AWS": f"{arn}:root"}, "Action": "sts:AssumeRole"}

    def grant(role_arn, assets, classes, used=None):
        for asset in assets:
            truth.roles[role_arn]["grants"][asset] |= set(classes)
            if used is not None and asset in used:
                truth.roles[role_arn]["used"][asset] |= set(classes)

    def s3_statements(read=(), write=(), condition=None):
        found = []
        if read:
            found.append(allow(S3_READ, s3_resources(read)))
        if write:
            found.append(allow(S3_WRITE, s3_resources(write)))
        if condition:
            for statement in found:
                statement["Condition"] = condition
        return found

    def glue_statements(tables, write=False):
        databases = sorted({t.split("/")[-2] for t in tables})
        actions = ["glue:GetTable", "glue:GetTables", "glue:GetPartitions"]
        if write:
            actions += ["glue:UpdateTable", "glue:BatchCreatePartition"]
        return [
            allow(actions, [truth.catalog, *(truth.database(d) for d in databases), *tables]),
            allow("glue:GetDatabase", [truth.catalog, *(truth.database(d) for d in databases)]),
        ]

    topic_tables = defaultdict(list)
    for table, topic in truth.tables.items():
        topic_tables[topic].append(table)
    governed = {truth.table("lake_raw", t) for t in DATABASES["lake_raw"][2]}
    resource_policy_grants: dict[str, list[str]] = defaultdict(list)  # bucket -> roles
    for t_index, topic in enumerate(TOPICS):
        buckets = truth.topic_buckets(topic)
        other = truth.topic_buckets(TOPICS[(t_index + 1) % len(TOPICS)])
        tables = sorted(topic_tables.get(topic, []))
        for index in range(APP_ROLES_PER_TOPIC):
            rng = _rng(topic, "app", index)
            name = f"{topic}-{SERVICES[index % len(SERVICES)]}-{index:03d}"
            chosen = rng.sample(buckets, 3)
            used_buckets, spare = chosen[:2], chosen[2]
            conditional = index % 40 == 8
            statements = s3_statements(read=chosen[:2], write=chosen[:2])
            statements += s3_statements(
                read=[spare],
                write=[spare],
                condition={"StringEquals": {"aws:SourceVpce": "vpce-0abc1234"}} if conditional else None,
            )
            over = None
            if index % 8 == 0:  # Planted cross-topic over-grant: read on another topic's bucket, never used.
                over = rng.choice(other)
                statements += s3_statements(read=[over])
            role_tables, lf_tables = [], []
            if tables and index % 3 == 0:
                hybrid = [t for t in tables if t not in governed]
                if topic == "data-lake" and index % 2 == 0:
                    lf_tables = rng.sample(sorted(governed), 2)
                role_tables = rng.sample(hybrid, min(2, len(hybrid)))
                statements += glue_statements(sorted(set(role_tables) | set(lf_tables)), write=index % 6 == 0)
            role_arn = create_role(
                name,
                service_trust(TRUSTS[index % len(TRUSTS)]),
                topic=topic,
                kind="app" if index % 10 != 9 else "app-untagged",
                tags=[("team", topic), ("env", "prod")],
                statements=statements,
                host=TRUSTS[index % len(TRUSTS)],
            )
            grant(role_arn, [bucket_arn(b) for b in chosen], ("read", "write"), {bucket_arn(b) for b in used_buckets})
            if conditional:
                truth.conditional.add((role_arn, bucket_arn(spare)))
            if over:
                grant(role_arn, [bucket_arn(over)], ("read",))
                truth.over_grants.add((role_arn, bucket_arn(over)))
            if role_tables:
                classes = ("read", "write") if index % 6 == 0 else ("read",)
                grant(role_arn, role_tables, classes, set(role_tables))
                databases = {truth.database(t.split("/")[-2]) for t in role_tables}
                grant(role_arn, sorted(databases), ("read",), databases)
            if lf_tables:
                # Governed tables: the Lake Formation grant is the access (used); IAM alone is not.
                truth.roles[role_arn]["lf"] = lf_tables
                grant(role_arn, lf_tables, ("read",), set(lf_tables))
                grant(role_arn, [truth.database("lake_raw")], ("read",), {truth.database("lake_raw")})
                truth.lf_grants |= {(role_arn, t) for t in lf_tables}
            if index % 50 == 25 and topic != "security":
                # A bucket policy grants this role read on another of its topic's buckets (never used).
                target = next(b for b in buckets if b not in chosen)
                resource_policy_grants[target].append(role_arn)
                truth.resource_policy.add((role_arn, bucket_arn(target)))
                grant(role_arn, [bucket_arn(target)], ("read",))
        for index in range(DORMANT_ROLES_PER_TOPIC + OUT_OF_WINDOW_ROLES_PER_TOPIC):
            rng = _rng(topic, "dormant", index)
            chosen = rng.sample(buckets, 2)
            out_of_window = index >= DORMANT_ROLES_PER_TOPIC
            tags = [("team", topic)]
            if index == 0:
                tags.append(("schedule", "quarterly"))  # Seasonal exemption: disable must be manual.
            role_arn = create_role(
                f"{topic}-legacy-{('migration', 'export', 'backfill', 'report')[index % 4]}-{index:02d}",
                service_trust("lambda.amazonaws.com"),
                topic=topic,
                kind="out-of-window" if out_of_window else "dormant",
                tags=tags,
                statements=s3_statements(read=chosen),
                host="lambda.amazonaws.com",
                seasonal=index == 0,
            )
            grant(role_arn, [bucket_arn(b) for b in chosen], ("read",))
            if out_of_window:
                truth.roles[role_arn]["old_use"] = [bucket_arn(b) for b in chosen]
        for index in range(DUPLICATE_PAIRS_PER_TOPIC):
            rng = _rng(topic, "duplicate", index)
            shared = rng.sample(buckets, 6)
            pair = []
            for copy, owned in ((0, shared[:5]), (1, shared)):
                role_arn = create_role(
                    f"{topic}-reporting-{index:02d}" + ("-v2" if copy else ""),
                    service_trust("ecs-tasks.amazonaws.com"),
                    topic=topic,
                    kind="duplicate",
                    tags=[("team", topic)],
                    statements=s3_statements(read=owned),
                    host="ecs-tasks.amazonaws.com",
                )
                grant(role_arn, [bucket_arn(b) for b in owned], ("read",), {bucket_arn(b) for b in owned})
                pair.append(role_arn)
            truth.duplicates.append(tuple(pair))
        # Human roles: developers (assumed by engineers and leads), operators (assumable, never assumed).
        rng = _rng(topic, "human")
        developer_buckets = rng.sample(buckets, 4)
        operator_buckets = rng.sample(buckets, 4)
        developer = create_role(
            f"{topic}-developer",
            root_trust,
            topic=topic,
            kind="developer",
            tags=[("team", topic)],
            statements=s3_statements(read=developer_buckets)
            + (glue_statements(tables[:2]) if tables else [])
            + [allow(["athena:StartQueryExecution", "athena:GetQueryResults"], "*")],
        )
        grant(
            developer,
            [bucket_arn(b) for b in developer_buckets],
            ("read",),
            {bucket_arn(b) for b in developer_buckets[:3]},
        )
        if tables:
            databases = {truth.database(t.split("/")[-2]) for t in tables[:2]}
            # Governed tables need a Lake Formation grant; IAM alone is no access to them.
            hybrid = [t for t in tables[:2] if t not in governed]
            grant(developer, hybrid, ("read",), set(hybrid))
            grant(developer, sorted(databases), ("read",), databases)
        operator = create_role(
            f"{topic}-operator",
            root_trust,
            topic=topic,
            kind="operator",
            tags=[("team", topic)],
            statements=s3_statements(read=operator_buckets, write=operator_buckets),
        )
        grant(operator, [bucket_arn(b) for b in operator_buckets], ("read", "write"))
        truth.roles[developer]["buckets_used"] = developer_buckets[:3]
        truth.groups_topic = getattr(truth, "groups_topic", {})
        truth.groups_topic[topic] = (developer, operator)

    for bucket, roles in resource_policy_grants.items():
        item = truth.buckets[bucket.removeprefix("arn:aws:s3:::")] if bucket.startswith("arn:") else truth.buckets[
            bucket
        ]
        item.setdefault("policy", []).append(
            {
                "Sid": "ReadForReporting",
                "Effect": "Allow",
                "Principal": {"AWS": roles},
                "Action": S3_READ,
                "Resource": s3_resources([bucket]),
            }
        )

    # Observability: log shippers write the log buckets (used).
    log_buckets = truth.topic_buckets(OBSERVABILITY)
    for index in range(30):
        chosen = _rng("log", index).sample(log_buckets, 2)
        role_arn = create_role(
            f"log-shipper-{index:02d}",
            service_trust("firehose.amazonaws.com"),
            topic=OBSERVABILITY,
            kind="app",
            statements=s3_statements(write=chosen),
            host="firehose.amazonaws.com",
        )
        grant(role_arn, [bucket_arn(b) for b in chosen], ("write",), {bucket_arn(b) for b in chosen})

    # Service-linked roles with AWS-managed policies (never proposed for change automatically).
    import moto.iam.aws_managed_policies as managed_data

    available = json.loads(managed_data.aws_managed_policies_data)
    for host, name, policy in SERVICE_LINKED:
        if policy not in available:
            gap(f"AWS managed policy {policy}", "absent from moto's managed policy set", "role seeded without it")
            continue
        path = available[policy].get("Path", "/")
        create_role(
            name,
            service_trust(host),
            kind="service-linked",
            path=f"/aws-service-role/{host}/",
            managed=[f"arn:aws:iam::aws:policy{path}{policy}"],
        )

    # IAM Identity Center permission sets (SAML federation; AWS-managed admin hubs).
    saml = f"{arn}:saml-provider/AWSSSO_5f2a9c3d1e8b7a64_DO_NOT_DELETE"
    sso_trust = {
        "Effect": "Allow",
        "Principal": {"Federated": saml},
        "Action": ["sts:AssumeRoleWithSAML", "sts:TagSession"],
        "Condition": {"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}},
    }
    for permission_set, policies in SSO_PERMISSION_SETS:
        suffix = hashlib.sha256(permission_set.encode()).hexdigest()[:16]
        create_role(
            f"AWSReservedSSO_{permission_set}_{suffix}",
            sso_trust,
            kind="sso",
            path="/aws-reserved/sso.amazonaws.com/",
            managed=[managed_arn(p) for p in policies],
            permission_set=permission_set,
        )
    # Customer-managed admin hubs and break-glass roles.
    for name, policies, kind in (
        ("platform-admin", ["AdministratorAccess"], "admin"),
        ("data-platform-admin", ["AmazonS3FullAccess", "AWSGlueConsoleFullAccess"], "admin"),
        ("sre-oncall", ["PowerUserAccess"], "admin"),
        ("BreakGlassAdministrator", ["AdministratorAccess"], "break-glass"),
        ("emergency-access-readonly", ["ReadOnlyAccess"], "break-glass"),
    ):
        trust = dict(root_trust)
        if kind == "break-glass":
            trust["Condition"] = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
        create_role(name, trust, kind=kind, managed=[managed_arn(p) for p in policies])

    # GitHub OIDC deploy roles (web identity) writing CI artifacts and Terraform state.
    oidc = f"{arn}:oidc-provider/token.actions.githubusercontent.com"
    ci_buckets = truth.topic_buckets("ci-cd")
    for index in range(20):
        chosen = _rng("gha", index).sample(ci_buckets, 2)
        role_arn = create_role(
            f"gha-deploy-{('web', 'api', 'infra', 'data', 'mobile')[index % 5]}-{index:02d}",
            {
                "Effect": "Allow",
                "Principal": {"Federated": oidc},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
                    "StringLike": {"token.actions.githubusercontent.com:sub": f"repo:acme/svc-{index}:*"},
                },
            },
            topic="ci-cd",
            kind="oidc",
            statements=s3_statements(read=chosen, write=chosen),
            repository=f"repo:acme/svc-{index}:ref:refs/heads/main",
        )
        grant(role_arn, [bucket_arn(b) for b in chosen], ("read", "write"), {bucket_arn(b) for b in chosen})
    # Roles trusted by other accounts: audit (used), deploy (half used).
    for index in range(20):
        partner = PARTNER_ACCOUNTS[index % 2]
        chosen = _rng("xacct", index).sample(log_buckets, 2)
        used = index % 2 == 0
        role_arn = create_role(
            f"xacct-{('audit', 'deploy')[index % 2]}-{partner[-4:]}-{index:02d}",
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{partner}:root"}, "Action": "sts:AssumeRole"},
            topic=OBSERVABILITY,
            kind="cross-account" if used else "cross-account-unused",
            statements=s3_statements(read=chosen),
            partner=partner,
        )
        grant(role_arn, [bucket_arn(b) for b in chosen], ("read",), {bucket_arn(b) for b in chosen} if used else None)
    # Toxic path: an exposed, unauthenticated support agent's runtime role reads restricted HR data.
    hr_restricted = next(b for b in truth.topic_buckets("hr") if "classification" in CLASSIFICATION["hr"])
    ml_buckets = truth.topic_buckets("ml")[:2]
    agent_role = create_role(
        "ml-support-agent-runtime",
        service_trust("bedrock.amazonaws.com"),
        topic="ml",
        kind="agent",
        statements=s3_statements(read=[*ml_buckets, hr_restricted]),
        host="bedrock.amazonaws.com",
    )
    grant(agent_role, [bucket_arn(b) for b in (*ml_buckets, hr_restricted)], ("read",), {bucket_arn(b) for b in ml_buckets})
    truth.toxic = {"agent": "agent:support-chatbot", "role": agent_role, "bucket": bucket_arn(hr_restricted)}
    # Lake Formation administrator role.
    create_role(
        "datalake-admin",
        root_trust,
        topic="data-lake",
        kind="lf-admin",
        statements=[allow(["lakeformation:*", "glue:GetDatabase*", "glue:GetTable*"], "*")],
    )

    # Bucket policies.
    for name, item in truth.buckets.items():
        if item.get("policy"):
            s3.put_bucket_policy(Bucket=name, Policy=document(*item["policy"]))

    # -- Users and Identity-Center-style groups.
    user_index = 0
    for t_index, topic in enumerate(TOPICS):
        developer, operator = truth.groups_topic[topic]
        buckets = truth.topic_buckets(topic)
        other = truth.topic_buckets(TOPICS[(t_index + 2) % len(TOPICS)])
        members: dict[str, list[str]] = {}
        for kind in GROUP_KINDS:
            group = f"idc-{topic}-{kind}"
            iam.create_group(GroupName=group, Path="/identity-center/")
            counts["groups"] += 1
            spec = {"topic": topic, "kind": kind, "assume": [], "grants": []}
            if kind in ("engineers", "leads", "oncall"):
                spec["assume"] = [developer, operator]
                if topic == "security" and kind == "oncall":
                    spec["assume"] += [truth.role("platform-admin"), truth.role("sre-oncall")]
                iam.put_group_policy(
                    GroupName=group,
                    PolicyName="assume-topic-roles",
                    PolicyDocument=document(allow("sts:AssumeRole", spec["assume"])),
                )
            elif kind == "analysts":
                spec["grants"] = _rng(topic, "analysts").sample(buckets, 3)
                policy = iam.create_policy(
                    PolicyName=f"{topic}-analyst-read",
                    PolicyDocument=document(
                        *s3_statements(read=spec["grants"]),
                        allow("athena:StartQueryExecution", "*"),
                    ),
                )["Policy"]["Arn"]
                iam.attach_group_policy(GroupName=group, PolicyArn=policy)
            else:  # Contractors: two topic buckets and a planted over-grant on another topic's bucket.
                spec["grants"] = _rng(topic, "contractors").sample(buckets, 2)
                spec["over"] = _rng(topic, "contractors-over").choice(other)
                iam.put_group_policy(
                    GroupName=group,
                    PolicyName="contractor-access",
                    PolicyDocument=document(*s3_statements(read=[*spec["grants"], spec["over"]])),
                )
            truth.groups[group] = spec
            members[group] = []
        for kind in GROUP_KINDS:
            group = f"idc-{topic}-{kind}"
            for _ in range(GROUP_SIZES[kind]):
                first, last = FIRST[user_index % len(FIRST)], LAST[(user_index // len(FIRST)) % len(LAST)]
                name = f"{first}.{last}{user_index // (len(FIRST) * len(LAST)) or ''}"
                user_index += 1
                position = len(members[group])
                # Dormant: the last member of every group never acts; one more in large groups acts
                # only before the window.
                state = (
                    "dormant"
                    if position == GROUP_SIZES[kind] - 1
                    else ("out-of-window" if position == GROUP_SIZES[kind] - 2 and GROUP_SIZES[kind] >= 15 else "active")
                )
                iam.create_user(
                    UserName=name,
                    Path="/identity-center/",
                    Tags=[{"Key": "team", "Value": topic}, {"Key": "email", "Value": f"{name}@acme.example"}],
                )
                iam.add_user_to_group(UserName=name, GroupName=group)
                groups = [group]
                if kind == "leads":  # Leads are also analysts.
                    iam.add_user_to_group(UserName=name, GroupName=f"idc-{topic}-analysts")
                    groups.append(f"idc-{topic}-analysts")
                user_arn = f"{arn}:user/identity-center/{name}"
                truth.users[user_arn] = {
                    "name": name,
                    "topic": topic,
                    "groups": groups,
                    "state": state,
                    "assumable": set(),
                    "assumed": set(),
                    "grants": defaultdict(set),
                    "used": defaultdict(set),
                    "source_identity": topic in ("data-lake", "payments"),
                }
                for g in groups:
                    spec = truth.groups[g]
                    truth.users[user_arn]["assumable"] |= set(spec["assume"])
                    for b in spec["grants"]:
                        truth.users[user_arn]["grants"][bucket_arn(b)].add("read")
                    if spec.get("over"):
                        truth.users[user_arn]["grants"][bucket_arn(spec["over"])].add("read")
                        truth.over_grants.add((user_arn, bucket_arn(spec["over"])))
                if state == "active":
                    if developer in truth.users[user_arn]["assumable"]:
                        truth.users[user_arn]["assumed"].add(developer)
                    truth.users[user_arn]["assumed"] |= truth.users[user_arn]["assumable"] & {
                        truth.role("platform-admin"),
                        truth.role("sre-oncall"),
                    }
                    for b in truth.users[user_arn]["grants"]:
                        if (user_arn, b) not in truth.over_grants:
                            truth.users[user_arn]["used"][b].add("read")
                members[group].append(user_arn)
                counts["users"] += 1

    # -- Lake Formation: settings, named, column and hybrid grants, LF-Tags.
    lf.put_data_lake_settings(
        DataLakeSettings={
            "DataLakeAdmins": [{"DataLakePrincipalIdentifier": truth.role("datalake-admin")}],
            "ReadOnlyAdmins": [{"DataLakePrincipalIdentifier": f"{arn}:role/{COLLECTOR}"}],
            "CreateDatabaseDefaultPermissions": [],
            "CreateTableDefaultPermissions": [],
        }
    )

    def lf_grant(principal, resource_, permissions):
        lf.grant_permissions(
            Principal={"DataLakePrincipalIdentifier": principal}, Resource=resource_, Permissions=permissions
        )

    for database, (_, is_governed, tables) in DATABASES.items():
        if is_governed:
            continue
        # Hybrid: IAM policies decide (moto lists no implicit grant; see gaps).
        lf_grant("IAM_ALLOWED_PRINCIPALS", {"Database": {"Name": database}}, ["ALL"])
        for table in tables:
            lf_grant("IAM_ALLOWED_PRINCIPALS", {"Table": {"DatabaseName": database, "Name": table}}, ["ALL"])
    for role_arn, table in sorted(truth.lf_grants):
        name = table.rsplit("/", 1)[-1]
        if name == "customers":
            lf_grant(
                role_arn,
                {"TableWithColumns": {"DatabaseName": "lake_raw", "Name": name, "ColumnNames": ["customer_id"]}},
                ["SELECT"],
            )
        else:
            lf_grant(role_arn, {"Table": {"DatabaseName": "lake_raw", "Name": name}}, ["SELECT"])
    # Unused Lake Formation grants: the developer of data-lake on two governed tables (manual removals).
    developer = truth.groups_topic["data-lake"][0]
    for name in ("clickstream", "devices"):
        table = truth.table("lake_raw", name)
        lf_grant(developer, {"Table": {"DatabaseName": "lake_raw", "Name": name}}, ["SELECT"])
        truth.lf_grants.add((developer, table))
        truth.lf_unused.add((developer, table))
        truth.roles[developer]["grants"][table].add("read")
    lf.create_lf_tag(TagKey="domain", TagValues=["analytics", "finance", "people"])
    lf.create_lf_tag(TagKey="sensitivity", TagValues=["public", "restricted"])
    lf.add_lf_tags_to_resource(
        Resource={"Database": {"Name": "lake_curated"}}, LFTags=[{"TagKey": "domain", "TagValues": ["analytics"]}]
    )
    lf.add_lf_tags_to_resource(
        Resource={"Database": {"Name": "hr_core"}}, LFTags=[{"TagKey": "domain", "TagValues": ["people"]}]
    )

    world = {
        "account": account,
        "ou": ou,
        "scp": scp,
        "operator_key": key,
        "collector": f"{arn}:role/{COLLECTOR}",
        "member_credentials": credentials,
        "counts": dict(counts),
        "saml": saml,
        "oidc": oidc,
    }
    return world, truth


# -- simulated activity ------------------------------------------------------------------


class Trail:
    """CloudTrail records in the shapes the flaws.cloud corpus proved, built from the truth."""

    def __init__(self, truth: Truth, end: datetime):
        self.truth = truth
        self.account = truth.account
        self.end = end
        self.start = end - timedelta(days=USAGE_DAYS)
        self.records: list[dict] = []
        self.sequence = 0
        self.unattributed_expected = 0

    def at(self, day: float, hour: float = 0) -> str:
        return (self.end - timedelta(days=day, hours=hour)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def key(self, *parts) -> str:
        self.sequence += 1
        return "ASIA" + hashlib.sha256("\0".join(map(str, (*parts, self.sequence))).encode()).hexdigest()[:16].upper()

    def record(self, source, name, identity, request, when, response=None, error=None, resources=None):
        self.sequence += 1
        item = {
            "eventVersion": "1.09",
            "eventTime": when,
            "eventSource": source,
            "eventName": name,
            "awsRegion": REGION,
            "sourceIPAddress": f"10.{self.sequence % 250}.{(self.sequence // 250) % 250}.7",
            "userAgent": "aws-sdk-java/2.25.0",
            "requestParameters": request,
            "responseElements": response,
            "eventID": f"{zlib.crc32(str(self.sequence).encode()):08x}-0000-4000-8000-{self.sequence:012d}",
            "readOnly": name.startswith(("Get", "List", "Head", "Describe")),
            "eventType": "AwsApiCall",
            "managementEvent": source != "s3.amazonaws.com" or name not in ("GetObject", "PutObject", "ListObjects"),
            "recipientAccountId": self.account,
            "userIdentity": identity,
        }
        if source == "s3.amazonaws.com" and isinstance(request, dict) and "bucketName" in request:
            item["resources"] = resources or [
                {"type": "AWS::S3::Bucket", "ARN": f"arn:aws:s3:::{request['bucketName']}", "accountId": self.account}
            ]
            item["eventCategory"] = "Data"
        if error:
            item["errorCode"], item["errorMessage"] = error
            item["responseElements"] = None
        self.records.append(item)
        return item

    # Identities.
    def session_identity(self, role_arn, session_name, key, source_identity=None, on_behalf_of=None):
        name = role_arn.rsplit("/", 1)[-1]
        identity = {
            "type": "AssumedRole",
            "principalId": f"AROA{zlib.crc32(role_arn.encode()):012d}:{session_name}",
            "arn": f"arn:aws:sts::{self.account}:assumed-role/{name}/{session_name}",
            "accountId": self.account,
            "accessKeyId": key,
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": f"AROA{zlib.crc32(role_arn.encode()):012d}",
                    "arn": role_arn,
                    "accountId": self.account,
                    "userName": name,
                },
                "attributes": {"creationDate": self.at(0), "mfaAuthenticated": "false"},
            },
        }
        if source_identity:
            identity["sessionContext"]["sourceIdentity"] = source_identity
        if on_behalf_of:
            identity["onBehalfOf"] = {"userId": on_behalf_of, "identityStoreArn": IDENTITY_STORE}
        return identity

    def user_identity(self, user_arn):
        return {
            "type": "IAMUser",
            "principalId": f"AIDA{zlib.crc32(user_arn.encode()):012d}",
            "arn": user_arn,
            "accountId": self.account,
            "accessKeyId": f"AKIA{zlib.crc32(user_arn.encode()):016d}"[:20],
            "userName": user_arn.rsplit("/", 1)[-1],
        }

    def issue(self, role_arn, when, issuer, session_name, source_identity=None):
        """An STS issuance for ``role_arn``; returns the new session key."""
        key = self.key(role_arn, when, session_name)
        name = role_arn.rsplit("/", 1)[-1]
        response = {
            "credentials": {
                "accessKeyId": key,
                "sessionToken": "IQoJb3JpZ2luX2VjEXAMPLE",
                "expiration": "Jan 1, 2030, 12:00:00 AM",
            },
            "assumedRoleUser": {
                "assumedRoleId": f"AROA{zlib.crc32(role_arn.encode()):012d}:{session_name}",
                "arn": f"arn:aws:sts::{self.account}:assumed-role/{name}/{session_name}",
            },
        }
        request = {"roleArn": role_arn, "roleSessionName": session_name, "durationSeconds": 3600}
        kind = issuer[0]
        if kind == "service":
            identity, event = {"type": "AWSService", "invokedBy": issuer[1]}, "AssumeRole"
        elif kind == "user":
            identity, event = self.user_identity(issuer[1]), "AssumeRole"
            if source_identity:
                request["sourceIdentity"] = source_identity
                response["sourceIdentity"] = source_identity
        elif kind == "saml":
            identity = {
                "type": "SAMLUser",
                "principalId": f"{issuer[1]}:{issuer[2]}",
                "userName": issuer[2],
                "identityProvider": issuer[1],
            }
            event = "AssumeRoleWithSAML"
            request = {
                "roleArn": role_arn,
                "principalArn": issuer[1],
                "durationSeconds": 3600,
            }
        elif kind == "web":
            identity = {
                "type": "WebIdentityUser",
                "principalId": f"{issuer[1]}:sts.amazonaws.com:{issuer[2]}",
                "userName": issuer[2],
                "identityProvider": issuer[1],
            }
            event = "AssumeRoleWithWebIdentity"
        else:  # A role session in a partner account (cross-account role chaining).
            partner = issuer[1]
            identity = {
                "type": "AssumedRole",
                "principalId": f"AROAPARTNER:{session_name}",
                "arn": f"arn:aws:sts::{partner}:assumed-role/ci-runner/{session_name}",
                "accountId": partner,
                "accessKeyId": self.key(partner, when),
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "arn": f"arn:aws:iam::{partner}:role/ci-runner",
                        "accountId": partner,
                        "userName": "ci-runner",
                    }
                },
            }
            event = "AssumeRole"
        self.record("sts.amazonaws.com", event, identity, request, when, response=response)
        return key

    # Data events.
    def s3(self, identity, bucket_arn_, classes, when):
        bucket = bucket_arn_.removeprefix("arn:aws:s3:::")
        if "read" in classes:
            self.record("s3.amazonaws.com", "GetObject", identity, {"bucketName": bucket, "key": "part-0000.parquet"}, when)
            self.record("s3.amazonaws.com", "ListObjects", identity, {"bucketName": bucket, "prefix": "dt="}, when)
        if "write" in classes:
            self.record("s3.amazonaws.com", "PutObject", identity, {"bucketName": bucket, "key": "out/part-0001.parquet"}, when)

    def glue(self, identity, asset, classes, when, mixed: bool):
        parts = asset.split(":", 5)[-1].split("/")
        kind, database = parts[0], parts[1]
        spell = (lambda value: value.title()) if mixed else (lambda value: value)
        if kind == "database":
            self.record("glue.amazonaws.com", "GetDatabase", identity, {"name": spell(database)}, when)
            return
        table = parts[2]
        self.record(
            "glue.amazonaws.com",
            "GetTable",
            identity,
            {"databaseName": spell(database), "name": spell(table), "catalogId": self.account},
            when,
        )
        if "write" in classes:
            self.record(
                "glue.amazonaws.com",
                "UpdateTable",
                identity,
                {"databaseName": spell(database), "tableInput": {"name": spell(table)}},
                when,
            )

    def use(self, identity, used: dict, when, mixed=False, lf=()):
        for asset, classes in sorted(used.items()):
            if asset.startswith("arn:aws:s3:::"):
                self.s3(identity, asset, classes, when)
            elif ":glue:" in asset:
                self.glue(identity, asset, classes, when, mixed)
                if asset in lf:
                    self.record(
                        "lakeformation.amazonaws.com",
                        "GetDataAccess",
                        identity,
                        {"tableArn": asset, "permissions": ["SELECT"], "durationSeconds": 3600},
                        when,
                    )

    def denied(self, identity, principal, action, resource, request, source, name, when):
        message = f"User: {principal} is not authorized to perform: {action} on resource: {resource}"
        self.record(source, name, identity, request, when, error=("AccessDenied", message))


def activity_days(*parts, stride: int = 3) -> list[int]:
    rng = _rng(*parts)
    offset = rng.randrange(stride)
    return sorted(set(range(offset, USAGE_DAYS - 1, stride)) | {1})


def simulate(truth: Truth, world: dict, end: datetime) -> tuple[list[dict], dict]:  # noqa: C901
    """95 days of activity: every planted use, nothing on dormant identities or over-grants."""
    trail = Trail(truth, end)
    service_kinds = {"app", "app-untagged", "duplicate", "agent", "out-of-window"}
    stats = Counter()
    for role_arn, role in sorted(truth.roles.items()):
        kind = role["kind"]
        if kind in service_kinds and kind != "out-of-window" and role["used"]:
            for day in activity_days(role_arn):
                when = trail.at(day, hour=2 + (zlib.crc32(role_arn.encode()) % 12))
                session_name = f"{role['name'][:40]}-{day}"
                key = trail.issue(role_arn, when, ("service", role["host"]), session_name)
                identity = trail.session_identity(role_arn, session_name, key)
                trail.use(identity, role["used"], when, mixed=day % 2 == 0, lf=role.get("lf", ()))
                stats["service_sessions"] += 1
        elif kind == "out-of-window":
            # Used 100-130 days ago only: outside the window, so still dormant.
            for day in (101, 115, 128):
                when = trail.at(day, hour=3)
                key = trail.issue(role_arn, when, ("service", role["host"]), f"old-{day}")
                trail.use(trail.session_identity(role_arn, f"old-{day}", key), {b: {"read"} for b in role["old_use"]}, when)
                stats["outside_window_sessions"] += 1
        elif kind == "oidc":
            for day in activity_days(role_arn, stride=2):
                when = trail.at(day, hour=5)
                session_name = f"GitHubActions-{day}"
                key = trail.issue(
                    role_arn, when, ("web", "token.actions.githubusercontent.com", role["repository"]), session_name
                )
                trail.use(trail.session_identity(role_arn, session_name, key), role["used"], when)
                stats["web_identity_sessions"] += 1
        elif kind == "cross-account":
            for day in activity_days(role_arn, stride=7):
                when = trail.at(day, hour=6)
                session_name = f"audit-{day}"
                key = trail.issue(role_arn, when, ("partner", role["partner"]), session_name)
                before = len(trail.records)
                trail.use(trail.session_identity(role_arn, session_name, key), role["used"], when)
                # Chained from a partner account's session this trail never shows: unattributable.
                # (plus the AssumeRole call itself, made in the partner's role session).
                trail.unattributed_expected += len(trail.records) - before + 1
                stats["cross_account_sessions"] += 1

    # Identity Center permission sets: SAML sessions acting for directory users (onBehalfOf).
    sso_use = {
        "AnalyticsReader": [b for b in truth.topic_buckets("data-lake")[:3]],
        "DataEngineer": [b for b in truth.topic_buckets("data-lake")[3:5]],
        "ReadOnlyAccess": [truth.topic_buckets(OBSERVABILITY)[0]],
        "MLScientist": [truth.topic_buckets("ml")[2]],
    }
    for role_arn, role in sorted(truth.roles.items()):
        if role["kind"] != "sso" or role["permission_set"] not in sso_use:
            continue
        for bucket in sso_use[role["permission_set"]]:
            role["used"][bucket_arn(bucket)].add("read")
        for day in activity_days(role_arn, stride=4):
            directory_user = f"94a8{zlib.crc32((role_arn + str(day % 5)).encode()):08x}-1234-5678-9abc-def012345678"
            email = f"sso-user-{day % 5}@acme.example"
            when = trail.at(day, hour=7)
            key = trail.issue(role_arn, when, ("saml", world["saml"], email), email)
            identity = trail.session_identity(role_arn, email, key, on_behalf_of=directory_user)
            trail.use(identity, role["used"], when)
            stats["identity_center_sessions"] += 1

    # Humans.
    developers = {}
    for topic in TOPICS:
        developers[truth.groups_topic[topic][0]] = topic
    hub_use = {
        truth.role("platform-admin"): {bucket_arn(b): {"read"} for b in truth.topic_buckets(OBSERVABILITY)[:2]},
        truth.role("sre-oncall"): {bucket_arn(truth.topic_buckets("security")[0]): {"read"}},
    }
    for role_arn, used in hub_use.items():
        for asset, classes in used.items():
            truth.roles[role_arn]["used"][asset] |= classes
    for user_arn, user in sorted(truth.users.items()):
        state = user["state"]
        if state == "dormant":
            continue
        days = (
            [104, 117]
            if state == "out-of-window"
            else activity_days(user_arn, stride=2)
        )
        identity = trail.user_identity(user_arn)
        for day in days:
            when = trail.at(day, hour=9 + zlib.crc32(user_arn.encode()) % 6)
            own = {b: c for b, c in user["grants"].items() if (user_arn, b) not in truth.over_grants}
            if own:
                trail.use(identity, own, when)
                if user["groups"][0].endswith(("analysts", "leads")) and user["topic"] in {
                    v for v in WORKGROUPS.values()
                }:
                    group = next(n for n, t in WORKGROUPS.items() if t == user["topic"])
                    trail.record(
                        "athena.amazonaws.com",
                        "StartQueryExecution",
                        identity,
                        {"queryString": "SELECT 1", "workGroup": group},
                        when,
                    )
            assumable = user["assumable"] if state == "active" else user["assumable"] & set(developers)
            for role_arn in sorted(assumable):
                if role_arn not in developers and role_arn not in hub_use:
                    continue  # Operators: assumable by the group, never assumed.
                role = truth.roles[role_arn]
                session_name = f"{user['name']}-{day}"
                source_identity = user["name"] if user["source_identity"] else None
                key = trail.issue(role_arn, when, ("user", user_arn), session_name, source_identity)
                session = trail.session_identity(role_arn, session_name, key, source_identity=source_identity)
                if role_arn in hub_use:
                    used = hub_use[role_arn]
                else:
                    # Each engineer uses part of the developer role's use; together they cover it.
                    items = sorted(role["used"].items())
                    pick = zlib.crc32(f"{user_arn}{day}".encode()) % len(items)
                    used = dict(items[pick : pick + 2] or items[:1])
                    if day % 6 == 1:
                        used = dict(items)
                trail.use(session, used, when, mixed=day % 3 == 0)
                group = next((n for n, t in WORKGROUPS.items() if t == user["topic"]), None)
                if group and role_arn in developers:
                    trail.record(
                        "athena.amazonaws.com",
                        "StartQueryExecution",
                        session,
                        {"queryString": "SELECT count(*) FROM t", "workGroup": group},
                        when,
                    )
                stats["user_sessions"] += 1

    # Sessions issued just before the window opened, used inside it (unattributable: one event each).
    for topic in TOPICS:
        role_arn = truth.role(f"{topic}-{SERVICES[1]}-001")
        role = truth.roles[role_arn]
        issued = (trail.start - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        key = trail.issue(role_arn, issued, ("service", role["host"]), "pre-window")
        asset = next(a for a in sorted(role["used"]) if a.startswith("arn:aws:s3:::"))
        bucket = asset.removeprefix("arn:aws:s3:::")
        trail.record(
            "s3.amazonaws.com",
            "GetObject",
            trail.session_identity(role_arn, "pre-window", key),
            {"bucketName": bucket, "key": "late.parquet"},
            (trail.start + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        trail.unattributed_expected += 1
        stats["pre_window_sessions"] += 1

    # Denied attempts (never use): app roles probing other topics' buckets, engineers trying other
    # topics' developer roles (requestParameters null, as CloudTrail logs denied AssumeRole).
    rng = random.Random(7)
    app_roles = sorted(a for a, r in truth.roles.items() if r["kind"] == "app")
    all_buckets = sorted(truth.buckets)
    denied = []
    for _ in range(300):
        role_arn = rng.choice(app_roles)
        bucket = rng.choice(all_buckets)
        if bucket_arn(bucket) in truth.roles[role_arn]["grants"]:
            continue
        when = trail.at(rng.randrange(USAGE_DAYS - 1), hour=4)
        key = trail.key(role_arn, "denied")
        session_name = "denied-probe"
        identity = trail.session_identity(role_arn, session_name, key)
        trail.denied(
            identity,
            identity["arn"],
            "s3:GetObject",
            f"arn:aws:s3:::{bucket}/k",
            {"bucketName": bucket, "key": "k"},
            "s3.amazonaws.com",
            "GetObject",
            when,
        )
        denied.append((role_arn, bucket_arn(bucket)))
    engineers = sorted(a for a, u in truth.users.items() if u["state"] == "active" and truth.groups_topic[u["topic"]][0] in u["assumable"])
    for index in range(20):
        user_arn = engineers[index * 7 % len(engineers)]
        foreign = truth.groups_topic[TOPICS[(TOPICS.index(truth.users[user_arn]["topic"]) + 3) % len(TOPICS)]][0]
        trail.record(
            "sts.amazonaws.com",
            "AssumeRole",
            trail.user_identity(user_arn),
            None,
            trail.at(index * 3 + 1, hour=8),
            error=("AccessDenied", f"User: {user_arn} is not authorized to perform: sts:AssumeRole on resource: {foreign}"),
        )
        denied.append((user_arn, foreign))
    # Activity entirely before the window: an operator role used once 110 days ago (still dormant).
    stats["records"] = len(trail.records)
    stats["denied"] = len(denied)
    trail.records.sort(key=lambda item: item["eventTime"])
    return trail.records, {"stats": dict(stats), "denied": denied, "start": trail.start, "end": end,
                           "unattributed_expected": trail.unattributed_expected}  # fmt: skip


def cloudtrail_files(records, per_file: int = 5_000):
    """CloudTrail delivery files: gzip ``{"Records": [...]}`` of at most ``per_file`` records."""
    for offset in range(0, len(records), per_file):
        yield gzip.compress(json.dumps({"Records": records[offset : offset + per_file]}).encode(), compresslevel=6)


# -- pipeline ----------------------------------------------------------------------------


def rss_mb() -> float:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return round(peak / 2**20 if sys.platform == "darwin" else peak / 2**10, 1)


class Phases:
    def __init__(self):
        self.items: dict[str, dict] = {}

    def __call__(self, name: str):
        phases = self

        class Timer:
            def __enter__(self):
                self.started = time.perf_counter()
                return self

            def __exit__(self, *exc):
                phases.items[name] = {"seconds": round(time.perf_counter() - self.started, 2), "peak_rss_mb": rss_mb()}

        return Timer()


# Enterprise-scale collection limits, set through the settings path (``ZG_AWS_COLLECTION_LIMITS``).
COLLECTION_LIMITS = {
    "max_roles": 2500,
    "max_users": 1000,
    "max_groups": 200,
    "max_buckets": 600,
    "max_requests": 20000,
    "max_pages": 2000,
    "max_policy_documents": 6000,
    "max_evaluations": 12_000_000,
    "max_edges": 100_000,
}


def app_environment(world: dict, work: Path, database_url: str | None) -> None:
    key = world["operator_key"]
    from fake_git import REPOSITORY

    os.environ.update(
        ZG_ENVIRONMENT="test",
        ZG_GRAPH_VENDOR="memory",
        ZG_DATABASE_URL=database_url or f"sqlite:///{work}/app.db",
        ZG_AWS_TENANT_ID=TENANT,
        ZG_AWS_ROLE_ARN=world["collector"],
        ZG_AWS_ACCOUNT_ID=world["account"],
        ZG_AWS_EXTERNAL_ID=EXTERNAL_ID,
        ZG_AWS_REGION=REGION,
        ZG_AWS_ACCESS_ADVISOR="true",
        ZG_AWS_DATA_LAKE="true",
        ZG_AWS_COLLECTION_LIMITS=json.dumps(COLLECTION_LIMITS),
        ZG_GIT_PROVIDER="github",
        ZG_GIT_REPOSITORY=REPOSITORY,
        ZG_GIT_TOKEN="secret-token-value",  # What tests/fake_git.py expects.
        ZG_GIT_TENANT_ID=TENANT,
        AWS_ACCESS_KEY_ID=key["AccessKeyId"],
        AWS_SECRET_ACCESS_KEY=key["SecretAccessKey"],
    )


def all_proposals(client, **params) -> list[dict]:
    rows, cursor = [], None
    while True:
        query = {"limit": 200, **params}
        if cursor is not None:
            query["cursor"] = cursor
        page = client.get("/api/v1/proposals", params=query).json()
        rows += page["proposals"]
        cursor = page["view"]["next_cursor"]
        if cursor is None:
            return rows


def run_job(client, tasks, payload: dict, checks: Checks, label: str):
    with patch("app.api.routes.ingest.delay"):
        response = client.post("/api/v1/ingestions", json=payload)
    checks(f"{label} ingestion accepted", response.status_code == 202, response.text[:300])
    job_id = response.json()["id"]
    with patch.object(tasks, "AWSCollector", Recording):
        tasks.process_job(job_id)
    job = client.get(f"/api/v1/ingestions/{job_id}").json()
    checks(f"{label} job completed", job["status"] == "completed", {k: job.get(k) for k in ("status", "error")})
    return job


def upload_cloudtrail(client, records, start, end, services, checks: Checks, label: str) -> dict:
    created = client.post(
        "/api/v1/usage/uploads",
        json={"window_start": start.isoformat(), "window_end": end.isoformat(), "attested_services": services},
    )
    checks(f"{label}: usage upload opens", created.status_code == 201, created.text[:300])
    upload = created.json()["id"]
    files = 0
    for number, body in enumerate(cloudtrail_files(records)):
        response = client.put(f"/api/v1/usage/uploads/{upload}/files/{number}", content=body)
        files += 1
        if response.status_code != 200:
            checks(f"{label}: file {number} staged", False, response.text[:300])
    committed = client.post(f"/api/v1/usage/uploads/{upload}/commit")
    checks(f"{label}: usage upload commits", committed.status_code == 200, committed.text[:300])
    body = committed.json()
    body["files"] = files
    return body


def agent_reference_flow(client, tasks, world, truth: Truth, role_node, agent_inventory, checks: Checks) -> dict:
    """The agent inventory links to the AWS role by reference: a later collection that changes
    the role's metadata (a new tag) publishes without a conflict; restating the role as it was
    (the former approach) conflicts, and a reference to a role no source defines never blocks
    publication: its edge is dropped with an ``unresolved_references`` warning."""
    import boto3

    from app.db.models import IngestionJob, TenantState
    from app.db.session import session_factory
    from app.graph.repository import get_graph_store

    def published():
        with session_factory()() as db:
            revision = db.get(TenantState, TENANT).revision
        return revision, get_graph_store().snapshot(TENANT, revision)

    role = truth.toxic["role"]
    revision, graph = published()
    edge = any(e.source == truth.toxic["agent"] and e.target == role for e in graph.edges)
    checks(
        "agent inventory links to the AWS role by reference (no restated node; edge published)",
        edge and [n.id for n in graph.nodes].count(role) == 1,
        {"edge": edge},
    )
    credentials = world["member_credentials"]
    member = session(boto3, credentials["AccessKeyId"], credentials["SecretAccessKey"], credentials["SessionToken"])
    member.client("iam").tag_role(
        RoleName=role.rsplit("/", 1)[-1], Tags=[{"Key": "owner", "Value": "support-platform"}]
    )
    job = run_job(client, tasks, {"source": "aws", "payload": {}}, checks, "aws re-collection after the role's metadata changed")
    revision, graph = published()
    changed = next((n for n in graph.nodes if n.id == role), None)
    edge = any(e.source == truth.toxic["agent"] and e.target == role for e in graph.edges)
    checks(
        "role metadata change re-published without a conflict; the agent edge stays",
        job["status"] == "completed" and changed is not None and "owner=support-platform" in changed.tags and edge,
        {"status": job["status"], "tags": changed.tags if changed else None, "edge": edge},
    )

    def refused(payload: dict) -> dict:
        with patch("app.api.routes.ingest.delay"):
            response = client.post("/api/v1/ingestions", json={"source": "snapshot", "payload": payload})
        job_id = response.json()["id"]
        try:
            tasks.process_job(job_id)
        except ValueError:
            pass
        found = client.get(f"/api/v1/ingestions/{job_id}").json()
        with session_factory()() as db:  # Retire the refused job so nothing retries it later.
            db.get(IngestionJob, job_id).status = "failed"
            db.commit()
        return {"status": found["status"], "error": found.get("error"), "revision_unchanged": published()[0] == revision}

    stale = refused(agent_inventory(role, role_node.model_dump(mode="json")))
    checks(
        "restating the role as first collected conflicts after its metadata changed (the former approach)",
        stale["status"] == "retrying" and "Conflicting node definitions" in (stale["error"] or "") and stale["revision_unchanged"],
        stale,
    )
    absent = f"arn:aws:iam::{world['account']}:role/not-collected"
    job = run_job(client, tasks, {"source": "snapshot", "payload": agent_inventory(absent)}, checks, "agent inventory with an unresolved reference")
    after, graph = published()
    warning = [w for w in graph.warnings if w.startswith("unresolved_references:")]
    missing = {
        "status": job["status"],
        "job_warnings": job.get("warnings"),
        "revision_warning": warning,
        "edge_dropped": not any(absent in (e.source, e.target) for e in graph.edges),
        "agent_published": any(n.id == truth.toxic["agent"] for n in graph.nodes),
        "new_revision": after != revision,
    }
    checks(
        "a reference no source defines publishes with its edge dropped and an unresolved_references warning",
        job["status"] == "completed" and missing["edge_dropped"] and missing["agent_published"] and missing["new_revision"]
        and len(warning) == 1 and "1 referenced node(s) are not defined by any source" in warning[0]
        and "1 edge(s) ending at them were dropped" in warning[0] and f"snapshot: {absent}" in warning[0]
        and job.get("warnings") == warning,
        missing,
    )
    # Restore the real inventory for the rest of the run.
    run_job(client, tasks, {"source": "snapshot", "payload": agent_inventory(role)}, checks, "agent inventory restored")
    return {"tags_after": changed.tags if changed else None, "restated": stale, "missing_reference": missing}


def run_pipeline(world: dict, truth: Truth, work: Path, checks: Checks, phases: Phases, args, result: dict) -> None:  # noqa: C901
    app_environment(world, work, args.database_url)
    from fastapi.testclient import TestClient
    from loguru import logger

    logger.remove()
    logger.add(args.output / "app.log", level="WARNING", backtrace=False, diagnose=False)
    from app.collectors import tasks
    from app.core.auth import Actor, current_actor
    from app.db.models import Base, TenantState
    from app.db.session import session_factory
    from app.graph import proposals as P
    from app.graph import topics as T
    from app.graph.repository import get_graph_store
    from app.main import create_app

    if args.database_url:
        from alembic import command
        from alembic.config import Config

        config = Config()
        config.set_main_option("script_location", str(BACKEND / "app" / "db" / "migrations"))
        command.upgrade(config, "head")
    else:
        Base.metadata.create_all(session_factory().kw["bind"])
    import app.main as main_module

    class FailureLog:
        """The request middleware logs failures without the exception; keep the traceback (it is
        called inside the ``except`` block) so a 500 in the run is diagnosable."""

        def __init__(self, real):
            self.real = real

        def bind(self, **fields):
            real = self.real.bind(**fields)

            class Bound:
                def error(self, message, *rest, **kwargs):
                    import traceback

                    result.setdefault("server_errors", []).append(traceback.format_exc()[-3000:])
                    return real.error(message, *rest, **kwargs)

                def __getattr__(self, name):
                    return getattr(real, name)

            return Bound()

        def __getattr__(self, name):
            return getattr(self.real, name)

    main_module.logger = FailureLog(main_module.logger)
    app = create_app()
    app.dependency_overrides[current_actor] = lambda: Actor(
        "qualifier", TENANT, frozenset({"admin", "analyst", "viewer"})
    )
    client = TestClient(app)

    # 1. AWS collection through the settings path (worker job, AssumeRole into the emulator).
    with phases("aws_collection_and_publish"):
        result["aws_job"] = run_job(client, tasks, {"source": "aws", "payload": {}}, checks, "aws")
    collector = Recording.instances[-1]
    result["collector"] = {
        "counts": collector.counts,
        "coverage": {k: v for k, v in collector.coverage.items() if k != "data_lake"},
        "data_lake": collector.coverage.get("data_lake"),
        "warning_counts": collector.warning_counts,
        "sdk_requests": collector.requests,
        "sdk_pages": collector.pages,
        "limits": {k: getattr(collector.limits, k) for k in COLLECTION_LIMITS},
    }
    with session_factory()() as db:
        revision = db.get(TenantState, TENANT).revision
    published = get_graph_store().snapshot(TENANT, revision)
    nodes = {node.id: node for node in published.nodes}

    # 2. The agent inventory (a second source): an exposed, unauthenticated chatbot that may
    # assume the support runtime role. It references the AWS-collected role by ID (never restates it).
    role_node = nodes.get(truth.toxic["role"])
    checks("toxic-path role collected", role_node is not None)
    agent = {
        "id": truth.toxic["agent"],
        "type": "AIAgent",
        "name": "support-chatbot",
        "provider": "custom",
        "internet_exposed": True,
        "authenticated": False,
    }

    def agent_inventory(role: str, restated=None) -> dict:
        return {
            "nodes": [agent, restated] if restated else [agent],
            "references": [] if restated else [role],
            "edges": [
                {
                    "source": truth.toxic["agent"],
                    "target": role,
                    "type": "ASSUMES_ROLE",
                    "certainty": "declared",
                    "evidence": ["agent runtime configuration: bedrock agent execution role"],
                }
            ],
            "source": "agents",
        }

    with phases("agent_inventory_publish"):
        result["agent_job"] = run_job(
            client, tasks, {"source": "snapshot", "payload": agent_inventory(truth.toxic["role"])}, checks, "agent inventory"
        )
    with phases("agent_reference_metadata_change"):
        result["agent_references"] = agent_reference_flow(
            client, tasks, world, truth, role_node, agent_inventory, checks
        )

    # 3. 95 days of CloudTrail through the usage upload API, then the worker sweeps.
    end = datetime.now(UTC).replace(microsecond=0) - timedelta(hours=1)
    with phases("simulate_cloudtrail"):
        records, simulated = simulate(truth, world, end)
    result["cloudtrail"] = {"records": len(records), **simulated["stats"]}
    with phases("usage_upload_commit"):
        committed = upload_cloudtrail(
            client,
            records,
            simulated["start"],
            end + timedelta(minutes=30),
            ["athena", "glue", "lakeformation", "s3", "sts"],
            checks,
            "cloudtrail",
        )
    stats = committed["stats"]
    result["usage_commit"] = {
        "files": committed["files"],
        "stats": {k: v for k, v in stats.items() if k not in ("coverage",)},
        "evidence": committed["evidence"],
    }
    outside = sum(1 for r in records if r["eventTime"] < simulated["start"].strftime("%Y-%m-%dT%H:%M:%SZ"))
    checks(
        "events before the window are ignored (counted outside_window)",
        stats.get("outside_window") == outside and outside > 0,
        {"outside_window": stats.get("outside_window"), "expected": outside},
    )
    checks(
        "denied attempts counted, never use",
        stats.get("denied") == simulated["stats"]["denied"],
        {"denied": stats.get("denied"), "expected": simulated["stats"]["denied"]},
    )
    attribution = stats.get("attribution", {})
    checks(
        "role sessions attributed except those issued before the window or chained from another account",
        attribution.get("unattributed_events") == simulated["unattributed_expected"],
        {"expected": simulated["unattributed_expected"], **attribution},
    )
    checks(
        "every service attested complete for the window",
        all(item.get("sufficient") for item in committed["evidence"].get("services", {}).values())
        and set(committed["evidence"].get("services", {})) >= {"athena", "glue", "lakeformation", "s3", "sts"},
        {k: v.get("sufficient") for k, v in committed["evidence"].get("services", {}).items()},
    )
    with phases("sweep_topics"):
        swept_topics = T.backfill_missing()
    with phases("sweep_proposals"):
        swept_proposals = P.backfill_missing()
    result["sweeps"] = {"topics": swept_topics, "proposals": swept_proposals}
    checks(
        "sweeps recomputed topics with usage",
        any(item.get("backfilled") or item.get("topics") for item in swept_topics),
        swept_topics,
    )
    with session_factory()() as db:
        revision = db.get(TenantState, TENANT).revision
    published = get_graph_store().snapshot(TENANT, revision)
    result["published"] = {
        "revision": revision,
        "nodes": dict(Counter(node.type.value for node in published.nodes)),
        "edges": dict(Counter(edge.type.value for edge in published.edges)),
        "node_total": len(published.nodes),
        "edge_total": len(published.edges),
    }
    if args.dump:
        dump = {
            "nodes": [n.model_dump(mode="json") for n in published.nodes],
            "edges": [e.model_dump(mode="json") for e in published.edges],
        }
        (args.output / "published.json.gz").write_bytes(gzip.compress(json.dumps(dump).encode()))
    with phases("ground_truth_checks"):
        check_truth(client, world, truth, published, simulated, revision, checks, result)
    with phases("accept_whatif_rollout"):
        result["rollout"] = {}
        rollout_flow(client, world, truth, revision, checks, result["rollout"])
    client.close()


def ratio(hit: int, total: int) -> float | None:
    return round(hit / total, 4) if total else None


def check_truth(client, world, truth: Truth, published, simulated, revision, checks: Checks, result: dict) -> None:  # noqa: C901
    from qualify_usage import compare, reference_privilege, stored_state

    from app.core.config import get_settings
    from app.db.session import session_factory
    from app.graph import topics as T
    from app.graph import usage

    by_type: dict[str, set] = defaultdict(set)
    for node in published.nodes:
        by_type[node.type.value].add(node.id)
    collector = world["collector"]
    known_extra_roles = {collector, f"{truth.arn}:role/OrganizationAccountAccessRole"}

    # Inventory completeness.
    roles = set(truth.roles)
    users = set(truth.users) | {f"{truth.arn}:user/zg-operator"}
    buckets = {bucket_arn(name) for name in truth.buckets}
    inventory = {
        "roles": (roles, by_type["CloudRole"] - known_extra_roles),
        "users": (users, by_type["HumanUser"] | by_type["ServiceAccount"]),
        "buckets": (buckets, by_type["S3Bucket"]),
        "tables": (set(truth.tables), by_type["DataTable"]),
        "databases": (set(truth.databases), by_type["Database"]),
        "workgroups": (set(truth.workgroups), by_type["QueryWorkgroup"]),
    }
    result["inventory"] = {}
    for name, (expected, found) in inventory.items():
        missing, extra = sorted(expected - found), sorted(found - expected)
        result["inventory"][name] = {"expected": len(expected), "found": len(found), "missing": len(missing)}
        if name == "workgroups":
            extra = [item for item in extra if not item.endswith("/primary")]  # Athena's default workgroup.
        checks(f"inventory complete: {name}", not missing and not extra, {"missing": len(missing), "extra": len(extra), "missing_sample": missing[:5], "extra_sample": extra[:5]})
    coverage = client.get("/api/v1/overview").json()
    result["overview"] = {k: coverage.get(k) for k in ("revision", "nodes", "edges", "identities", "findings")}

    # Topics.
    with session_factory()() as db:
        rows, kinds, topic_of, hubs, topic_privilege, summary, resource_topic, stored = stored_state(
            db, TENANT, revision
        )
        observed = [(p, r, c) for p, r, c, _, _, _ in usage.observed(db, TENANT)]
        sessions = [tuple(row) for row in usage.attributed(db, TENANT)]
        ready = usage.attribution_ready(db, TENANT)
        evidence = usage.evidence(db, TENANT)
    names = {topic_id: name for topic_id, (name, _) in stored.items()}
    planted = {bucket_arn(n): (item["topic"], item["tagged"]) for n, item in truth.buckets.items()}
    planted.update({t: (topic, True) for t, topic in truth.tables.items()})
    correct = Counter()
    total = Counter()
    wrong = []
    for asset, (topic, tagged) in planted.items():
        label = "tagged" if tagged else "name_only"
        total[label] += 1
        if resource_topic.get(asset) == topic:
            correct[label] += 1
        else:
            wrong.append((asset, topic, resource_topic.get(asset)))
    role_total = role_correct = 0
    for role_arn, role in truth.roles.items():
        if role["kind"] in ("app", "app-untagged", "duplicate", "developer") and role_arn in topic_of:
            role_total += 1
            role_correct += names.get(topic_of[role_arn]) == role["topic"]
    result["topics"] = {
        "count": len(stored),
        "names": sorted(name for name, _ in stored.values())[:40],
        "resource_accuracy_tagged": ratio(correct["tagged"], total["tagged"]),
        "resource_accuracy_name_only": ratio(correct["name_only"], total["name_only"]),
        "role_primary_accuracy": ratio(role_correct, role_total),
        "wrong_sample": wrong[:8],
    }
    checks("topics: every planted topic forms", set(TOPICS) | {OBSERVABILITY} <= {n for n, _ in stored.values()}, result["topics"]["names"])
    checks("topics: tagged resources 100% correct", correct["tagged"] == total["tagged"], result["topics"])
    checks("topics: name-only resources >= 90% correct", (ratio(correct["name_only"], total["name_only"]) or 0) >= 0.9, result["topics"])
    checks("topics: role primary topics >= 95% correct", (ratio(role_correct, role_total) or 0) >= 0.95, result["topics"])
    collector_row = rows.pop(collector, None)
    checks(
        "collector excluded: no topic, no granted or needed weight",
        collector_row is None
        or (not topic_of.get(collector) and not collector_row["reach_weight"] and not collector_row["needed_weight"]),
        collector_row,
    )
    kinds.pop(collector, None)

    # EPI against the independent brute force (the collector's own grants excluded, as documented).
    reference_snapshot = published.model_copy(
        update={
            "nodes": [n for n in published.nodes if n.id != collector],
            "edges": [e for e in published.edges if collector not in (e.source, e.target)],
        }
    )
    started = time.perf_counter()
    reference = reference_privilege(
        reference_snapshot,
        observed,
        evidence.sufficient_services,
        topic_of,
        hubs,
        get_settings().peer_baseline_share,
        sessions=sessions if ready else None,
    )
    epi = compare(reference, rows, summary.totals["privilege"], topic_privilege, kinds)
    result["epi"] = {
        **{k: v for k, v in epi.items() if k != "graph"},
        "graph": epi["graph"],
        "reference_seconds": round(time.perf_counter() - started, 2),
        "attribution_ready": ready,
        "sufficient_services": sorted(evidence.sufficient_services),
    }
    checks("EPI equals the brute-force reference (members, topics, graph)", epi["match"], result["epi"])
    checks(
        "usage evidence sufficient for every data service",
        {"s3", "glue", "sts"} <= set(evidence.sufficient_services),
        sorted(evidence.sufficient_services),
    )

    # Dormant and never-assumed recall.
    flagged = {e for e, row in rows.items() if row["flags"] & T.DORMANT}
    planted_roles = {
        a for a, r in truth.roles.items() if r["kind"] in ("dormant", "out-of-window", "operator", "cross-account-unused")
    }
    # A role that grants what a principal able to assume it was itself observed using is kept
    # (documented invariant guard): such operators are dormant but not proposed for disabling.
    guarded = {
        a
        for a in planted_roles
        if any(
            a in u["assumable"] and {b for b, c in u["used"].items() if c} & set(truth.roles[a]["grants"])
            for u in truth.users.values()
            if u["state"] == "active"
        )
    }
    planted_users = {a for a, u in truth.users.items() if u["state"] in ("dormant", "out-of-window")}
    active = {p for p, _, _ in observed}
    proposals = all_proposals(client)
    by_type = defaultdict(list)
    for p in proposals:
        by_type[p["type"]].append(p)
    disabled_roles = {p["subject_id"] for p in by_type["disable_role"]}
    disabled_users = {p["subject_id"] for p in by_type["disable_identity"]}
    result["dormant"] = {
        "planted_roles": len(planted_roles),
        "flagged_roles": len(planted_roles & flagged),
        "proposed_roles": len(planted_roles & disabled_roles),
        "planted_users": len(planted_users),
        "flagged_users": len(planted_users & flagged),
        "proposed_users": len(planted_users & disabled_users),
        "flagged_with_observed_use": sorted(flagged & active)[:5],
        "missed_roles": sorted(planted_roles - flagged)[:5],
        "missed_users": sorted(planted_users - flagged)[:5],
    }
    result["dormant"]["not_proposed_roles"] = sorted(planted_roles - disabled_roles)[:5]
    result["dormant"]["guarded_roles"] = sorted(guarded)
    checks(
        "dormant roles: recall 1.0 (flagged; proposed for disabling unless guarded)",
        planted_roles <= flagged and planted_roles - guarded <= disabled_roles and not guarded & disabled_roles,
        result["dormant"],
    )
    checks("dormant users: recall 1.0 (flagged and proposed for disabling)", planted_users <= flagged & disabled_users, result["dormant"])
    checks("no dormant flag on a principal with observed use", not flagged & active, sorted(flagged & active)[:5])
    never_assumed = set()
    observed_pairs = set()
    for user_arn, user in truth.users.items():
        own_use = {a for a, c in user["used"].items() if c}
        for role_arn in user["assumable"]:
            if role_arn in user["assumed"]:
                observed_pairs.add((user_arn, role_arn))
            elif user["state"] == "active" and not own_use & set(truth.roles[role_arn]["grants"]):
                # Dormant identities are disabled as a whole; a role granting what the identity
                # itself was observed using is kept (documented guards).
                never_assumed.add((user_arn, role_arn))
    proposed_unassume = {(p["subject_id"], p["target_id"]) for p in by_type["remove_assumption"]}
    result["never_assumed"] = {
        "planted": len(never_assumed),
        "proposed": len(never_assumed & proposed_unassume),
        "recall": ratio(len(never_assumed & proposed_unassume), len(never_assumed)),
        "on_observed_pairs": sorted(proposed_unassume & observed_pairs)[:5],
        "missed_sample": sorted(never_assumed - proposed_unassume)[:5],
    }
    checks("never-assumed role assumptions: recall 1.0", never_assumed <= proposed_unassume, result["never_assumed"])
    checks("no remove_assumption on an observed assumption", not proposed_unassume & observed_pairs, result["never_assumed"])

    # High-tier remove_grant precision and recall.
    def holder(subject):
        return truth.roles.get(subject) or truth.users.get(subject)

    high = {(p["subject_id"], p["target_id"]) for p in by_type["remove_grant"] if p["tier"] == "high"}
    removable_roles = {
        pair
        for pair in truth.over_grants
        if pair[0] in truth.roles and pair not in truth.conditional and pair not in truth.resource_policy
    }
    user_over = {pair for pair in truth.over_grants if pair[0] in truth.users}

    def correct_high(pair) -> bool:
        subject, target = pair
        item = holder(subject)
        if item is None:
            return False
        granted = target in item["grants"]
        used = bool(item["used"].get(target))
        return granted and not used and truth.asset_topic(target) not in (None, item.get("topic"))

    precise = {pair for pair in high if correct_high(pair)}
    result["high_remove"] = {
        "proposed_high": len(high),
        "precision": ratio(len(precise), len(high)),
        "planted_role_over_grants": len(removable_roles),
        "role_recall": ratio(len(removable_roles & high), len(removable_roles)),
        "planted_user_over_grants": len(user_over),
        "user_recall": ratio(len(user_over & high), len(user_over)),
        "imprecise_sample": sorted(high - precise)[:8],
        "missed_role_sample": sorted(removable_roles - high)[:5],
        "missed_user_sample": sorted(user_over - high)[:5],
        "by_type_tier": dict(Counter((p["type"], p["tier"]) for p in proposals).most_common()),
    }
    result["high_remove"]["by_type_tier"] = {f"{k[0]}:{k[1]}": v for k, v in result["high_remove"]["by_type_tier"].items()}
    checks("high-tier remove_grant precision 1.0 (granted, unused, outside the topic)", high and precise == high, result["high_remove"])
    checks("high-tier remove_grant recall 1.0 on planted role over-grants", removable_roles <= high, result["high_remove"])

    # Never-auto categories are manual.
    def kind_of(subject):
        item = truth.roles.get(subject)
        return item["kind"] if item else ("user" if subject in truth.users else "other")

    never_auto = defaultdict(list)
    for p in proposals:
        subject, target = p["subject_id"], p["target_id"]
        kind = kind_of(subject)
        role = truth.roles.get(subject, {})
        category = None
        if kind == "service-linked":
            category = "service_linked"
        elif kind == "break-glass":
            category = "break_glass"
        elif p["type"] == "remove_assumption":
            category = "trust"
        elif (subject, target) in truth.lf_grants or any("lakeformation:" in json.dumps(c) for c in p["changes"]):
            category = "lakeformation"
        elif (subject, target) in truth.conditional and p["type"] == "remove_grant":
            category = "condition"
        elif (subject, target) in truth.resource_policy and p["type"] == "remove_grant":
            category = "resource_policy"
        elif role.get("seasonal"):
            category = "seasonal"
        elif kind in ("sso", "admin") and p["type"] in ("remove_grant", "scope_wildcard"):
            category = "wildcard"
        if category:
            never_auto[category].append(p)
    result["never_auto"] = {
        category: {
            "proposals": len(items),
            "manual": sum(p["tier"] == "manual" for p in items),
            "not_manual_sample": [(p["type"], p["tier"], p["subject_name"], p["target_name"], p["reasons"]) for p in items if p["tier"] != "manual"][:4],
        }
        for category, items in sorted(never_auto.items())
    }
    for category in ("service_linked", "break_glass", "trust", "lakeformation", "condition", "resource_policy", "seasonal", "wildcard"):
        items = never_auto.get(category, [])
        checks(
            f"never-auto {category}: proposals exist and all are manual",
            items and all(p["tier"] == "manual" for p in items),
            result["never_auto"].get(category, "no proposals"),
        )
    lf_unused = [p for p in by_type["remove_grant"] if (p["subject_id"], p["target_id"]) in truth.lf_unused]
    checks(
        "unused Lake Formation grants proposed (manual, reason lakeformation)",
        len(lf_unused) == len(truth.lf_unused) and all(p["tier"] == "manual" and "lakeformation" in p["reasons"] for p in lf_unused),
        [(p["tier"], p["reasons"], p["target_name"]) for p in lf_unused],
    )
    cross = [p for p in proposals if kind_of(p["subject_id"]) == "cross-account-unused"]
    result["cross_account_unused"] = [(p["type"], p["tier"], p["reasons"]) for p in cross][:6]
    # A dormant role a partner account may assume is the partner's dependency: disabling it is manual.
    partner_roles = {a for a, r in truth.roles.items() if r["kind"] in ("cross-account", "cross-account-unused")}
    partner_unused = {a for a, r in truth.roles.items() if r["kind"] == "cross-account-unused"}
    partner_disable = [p for p in by_type["disable_role"] if p["subject_id"] in partner_unused]
    same_account_disable = [
        p for p in by_type["disable_role"] if kind_of(p["subject_id"]) in ("dormant", "out-of-window")
    ]
    labelled = [p for p in proposals if "cross_account" in p["reasons"]]
    result["partner_trust"] = {
        "partner_unused_roles": len(partner_unused),
        "disable_role": len(partner_disable),
        "manual_cross_account": sum(p["tier"] == "manual" and "cross_account" in p["reasons"] for p in partner_disable),
        "base_tiers": dict(Counter(p["base_tier"] for p in partner_disable)),
        "same_account_disable_tiers": dict(Counter(p["tier"] for p in same_account_disable)),
        "cross_account_labelled": dict(Counter(p["type"] for p in labelled)),
        "labelled_outside_partner_roles": [
            (p["type"], p["subject_name"], p["target_name"]) for p in labelled
            if not {p["subject_id"], p["target_id"]} & partner_roles
        ][:5],
    }
    checks(
        "partner-trusted dormant roles: disable_role is manual (cross_account)",
        {p["subject_id"] for p in partner_disable} == partner_unused - guarded
        and all(p["tier"] == "manual" and "cross_account" in p["reasons"] and p["evidence"].get("external_trust") for p in partner_disable),
        result["partner_trust"],
    )
    checks(
        "same-account dormant roles: disable_role unchanged (no cross_account, automatic tiers remain)",
        same_account_disable
        and not any("cross_account" in p["reasons"] for p in same_account_disable)
        and any(p["tier"] == "high" for p in same_account_disable),
        result["partner_trust"],
    )
    checks(
        "cross_account is labelled only on proposals involving a role another account trusts",
        not result["partner_trust"]["labelled_outside_partner_roles"],
        result["partner_trust"],
    )

    # Collector excluded; no proposal removes observed use (against the ground truth).
    collector_rows = [p for p in proposals if collector in (p["subject_id"], p["target_id"])]
    checks("no proposal names the collector role", not collector_rows, [(p["type"], p["subject_name"]) for p in collector_rows])
    violations = []
    for p in proposals:
        subject, target = p["subject_id"], p["target_id"]
        item = holder(subject)
        if p["type"] == "remove_grant" and item and item["used"].get(target):
            violations.append(("used grant", p["subject_name"], p["target_name"]))
        elif p["type"] in ("disable_role", "disable_identity") and item and (
            item["used"] or (subject in truth.users and item["assumed"])
            or (subject in truth.roles and any(subject in u["assumed"] for u in truth.users.values() if u["state"] == "active"))
        ):
            violations.append(("used principal", p["subject_name"], p["type"]))
        elif p["type"] == "remove_assumption" and (subject, target) in observed_pairs:
            violations.append(("observed assumption", p["subject_name"], p["target_name"]))
        elif p["type"] == "remove_grant" and subject in active and any(
            (subject, target, c) in set(observed) for c in ("read", "write", "admin")
        ):
            violations.append(("observed", p["subject_name"], p["target_name"]))
    checks("no proposal removes observed use (ground truth)", not violations, violations[:8])

    # Toxic path: exposed agent -> runtime role -> restricted HR data.
    findings = client.get("/api/v1/findings").json()
    toxic = [f for f in findings if f["source"] == truth.toxic["agent"] and f["target"] == truth.toxic["bucket"]]
    checks("toxic path found (exposed agent -> role -> restricted data)", bool(toxic), [f["title"] for f in findings][:5])
    breaks = [p for p in by_type["break_toxic_path"] if truth.toxic["role"] in (p["subject_id"], p["target_id"]) or truth.toxic["agent"] in (p["subject_id"], p["target_id"])]
    unused_toxic = [p for p in by_type["remove_grant"] if (p["subject_id"], p["target_id"]) == (truth.toxic["role"], truth.toxic["bucket"])]
    result["toxic"] = {
        "findings": len(toxic),
        "severity": [f["severity"] for f in toxic],
        "break_toxic_path": [(p["tier"], p["subject_name"], p["target_name"], p["reasons"]) for p in breaks][:4],
        "remove_unused_restricted_grant": [(p["tier"], p["reasons"]) for p in unused_toxic],
    }
    checks(
        "the toxic path's unused restricted grant is proposed for removal",
        bool(unused_toxic) or bool(breaks),
        result["toxic"],
    )
    hops = [p for p in breaks if (p["subject_id"], p["target_id"]) == (truth.toxic["agent"], truth.toxic["role"])]
    result["toxic"]["agent_hop"] = [(p["tier"], p["reasons"], p["evidence"].get("trust_scope")) for p in hops]
    checks(
        "toxic-path agent -> role hop is manual trust, labelled non-AWS (not cross_account)",
        hops and all(
            p["tier"] == "manual" and "trust" in p["reasons"] and "cross_account" not in p["reasons"]
            and p["evidence"].get("trust_scope") == "non_aws"
            for p in hops
        ),
        result["toxic"],
    )
    duplicates = {tuple(sorted((p["subject_id"], p["target_id"]))) for p in by_type["merge_roles"]}
    result["merge_roles"] = {
        "planted_pairs": len(truth.duplicates),
        "proposed": len({tuple(sorted(pair)) for pair in truth.duplicates} & duplicates),
        "total_merge_proposals": len(by_type["merge_roles"]),
    }
    checks(
        "near-duplicate roles proposed for merging (recall 1.0)",
        {tuple(sorted(pair)) for pair in truth.duplicates} <= duplicates,
        result["merge_roles"],
    )
    result["proposal_total"] = len(proposals)


def rollout_flow(client, world, truth: Truth, revision: str, checks: Checks, flow: dict) -> None:  # noqa: C901
    """Accept a sample, what-if it, and roll it out as draft PRs against the local fake provider."""
    import fake_git
    from sqlalchemy import select

    from app.api import routes
    from app.core.config import get_settings
    from app.db.models import AuditEvent, Remediation, RevisionPolicy, RevisionPolicyDocument, RolloutChange
    from app.db.session import session_factory
    from app.graph.schema import canonical_policy
    from app.remediation import rollout
    from app.remediation.policy_optimizer import render

    high = all_proposals(client, tier="high")
    by_topic: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for row in high:
        role = truth.roles.get(row["subject_id"])
        if row["type"] == "remove_grant" and role and role["kind"] == "app":
            by_topic[row["topic_id"]][row["subject_id"]].append(row)
    topics = sorted(by_topic, key=lambda t: (-len(by_topic[t]), t))[:3]
    chosen, sampled = [], {}
    for topic in topics:
        sampled[topic] = sorted(by_topic[topic])[:4]
        for subject in sampled[topic]:
            chosen += by_topic[topic][subject]
    disables = sorted(
        (r for r in high if r["type"] == "disable_role" and truth.roles.get(r["subject_id"], {}).get("kind") == "dormant"),
        key=lambda r: r["subject_id"],
    )[:6]
    chosen += disables
    timings = []
    for row in chosen:
        started = time.perf_counter()
        response = client.post(f"/api/v1/proposals/{row['id']}/decision", json={"state": "accepted"})
        timings.append(time.perf_counter() - started)
        checks(f"accept {row['type']} {row['subject_name']}", response.status_code == 200, response.text[:200])
    flow["accepted"] = {
        "proposals": len(chosen),
        "by_type": dict(Counter(r["type"] for r in chosen)),
        "topics": len(topics),
        "decision_ms_max": round(max(timings) * 1000, 1) if timings else None,
    }
    checks("sample spans three topics with over-grants and disables", len(topics) == 3 and disables, flow["accepted"])

    # What-if: the first sampled role's accepted removals.
    subject = sampled[topics[0]][0]
    ids = [r["id"] for r in by_topic[topics[0]][subject]]
    simulated = client.post("/api/v1/proposals/simulate", json={"proposal_ids": ids}).json()
    whatif = simulated.get("whatif") or {}
    removed_targets = {r["target_id"] for r in by_topic[topics[0]][subject]}
    used = {a for a, c in truth.roles[subject]["used"].items() if c}
    after_assets = set((whatif.get("after") or {}).get("affected_assets", []))
    flow["whatif"] = {
        "subject": truth.roles[subject]["name"],
        "before_assets": len(simulated.get("affected_assets", [])),
        "after_assets": len(after_assets),
        "assets_removed": whatif.get("assets_removed", []),
        "risk_delta": whatif.get("risk_delta"),
    }
    flow["whatif"]["accepted_targets"] = sorted(removed_targets)
    flow["whatif"]["used_not_after"] = sorted(used - after_assets)
    checks(
        "what-if removes exactly the accepted unused assets and keeps the used ones",
        set(whatif.get("assets_removed", [])) == removed_targets and used <= after_assets,
        flow["whatif"],
    )

    # GitOps: draft PRs against the fake provider; canary per topic.
    repo = fake_git.FakeRepository("github")
    settings = get_settings()
    real_client = routes.GitOpsClient
    routes.GitOpsClient = lambda configured: real_client(configured, repo.transport())
    try:
        changes: dict[str, list[str]] = {}
        for topic in topics:
            changes[topic] = []
            for role_arn in sampled[topic][:3]:
                response = client.post("/api/v1/rollout/changes", json={"subject_id": role_arn})
                checks(f"rollout change for {truth.roles[role_arn]['name']}", response.status_code == 201, response.text[:300])
                if response.status_code == 201:
                    changes[topic].append(response.json()["id"])
        canaries, refused = {}, 0
        for topic, ids_ in changes.items():
            response = client.post(f"/api/v1/rollout/changes/{ids_[0]}/pr")
            checks(f"canary PR opens ({topic[:12]})", response.status_code == 200, response.text[:300])
            canaries[topic] = ids_[0]
            for other in ids_[1:]:
                held = client.post(f"/api/v1/rollout/changes/{other}/pr")
                refused += held.status_code == 409 and "Waiting for canary" in held.json().get("detail", "")
        flow["canary_prs"] = len(canaries)
        flow["non_canary_refused"] = [refused, sum(len(v) - 1 for v in changes.values())]
        checks("non-canary PRs refused while the canary is open", refused == sum(len(v) - 1 for v in changes.values()), flow["non_canary_refused"])
        first, second, third = topics
        # Topic 1: merged -> refused during the watch -> verified -> widened.
        repo.merge(next(i + 1 for i, r in enumerate(repo.reviews) if canaries[first] in r["body"]))
        merged = client.post(f"/api/v1/rollout/changes/{canaries[first]}/merged").json()
        flow["watch_remaining_days"] = merged.get("watch_remaining_days")
        during = client.post(f"/api/v1/rollout/changes/{changes[first][1]}/pr").status_code
        with session_factory()() as db:
            db.get(RolloutChange, canaries[first]).merged_at = datetime.now(UTC) - timedelta(days=settings.rollout_watch_days + 1)
            db.commit()
        states = {c["id"]: c["state"] for c in client.get("/api/v1/rollout").json()["changes"]}
        widened = [client.post(f"/api/v1/rollout/changes/{c}/pr").status_code for c in changes[first][1:]]
        flow["topic1"] = {"refused_during_watch": during == 409, "verified": states[canaries[first]] == "verified", "widened": widened}
        checks("canary gating: refused during watch, verified after it, then widened", during == 409 and states[canaries[first]] == "verified" and all(c == 200 for c in widened), flow["topic1"])
        # Byte-exact revert of the topic 1 canary.
        response = client.post(f"/api/v1/rollout/changes/{canaries[first]}/revert", json={"reason": "enterprise simulation"})
        checks("revert PR opens", response.status_code == 200, response.text[:300])
        repo.merge(len(repo.reviews))
        identical = compared = 0
        key = hashlib.sha256(TENANT.encode()).hexdigest()[:16]
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
        flow["revert_byte_identical"] = [identical, compared]
        checks("revert restores every file byte for byte", compared > 0 and identical == compared, flow["revert_byte_identical"])
        flow["rolled_back"] = client.post(f"/api/v1/rollout/changes/{canaries[first]}/reverted").json().get("state")
        # Topic 2: merged canary, then AccessDenied on a removed bucket in a follow-up CloudTrail upload.
        repo.merge(next(i + 1 for i, r in enumerate(repo.reviews) if canaries[second] in r["body"]))
        client.post(f"/api/v1/rollout/changes/{canaries[second]}/merged")
        with session_factory()() as db:
            change = db.get(RolloutChange, canaries[second])
            change.merged_at = datetime.now(UTC) - timedelta(hours=3)
            touched = change.summary["touched"]
            db.commit()
        principal = sorted(touched)[0]
        removed = sorted(touched[principal]["removed"])[0]
        bucket = removed.removeprefix("arn:aws:s3:::")
        trail = Trail(truth, datetime.now(UTC).replace(microsecond=0))
        session_name = "after-change"
        key_id = trail.key(principal, "after")
        identity = trail.session_identity(principal, session_name, key_id)
        for minutes in (20, 40, 50):
            trail.denied(
                identity,
                identity["arn"],
                "s3:GetObject",
                f"{removed}/part-0000.parquet",
                {"bucketName": bucket, "key": "part-0000.parquet"},
                "s3.amazonaws.com",
                "GetObject",
                (datetime.now(UTC) - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
        reviews_before = len(repo.reviews)
        now_ = datetime.now(UTC).replace(microsecond=0)
        committed = upload_cloudtrail(
            client, trail.records, now_ - timedelta(hours=2), now_, ["s3"], checks, "follow-up cloudtrail"
        )
        watch = committed.get("rollout") or {}
        flow["access_denied"] = {
            "flagged": watch.get("flagged"),
            "revert_url": (watch.get("reverts") or [{}])[0].get("url"),
            "revert_draft_unmerged": len(repo.reviews) == reviews_before + 1
            and repo.reviews[-1]["draft"]
            and not repo.reviews[-1]["_merged"],
        }
        checks(
            "AccessDenied after the merge flags the canary and opens (never merges) its revert",
            watch.get("flagged") == [canaries[second]] and flow["access_denied"]["revert_draft_unmerged"],
            flow["access_denied"],
        )
        states = {c["id"]: c for c in client.get("/api/v1/rollout").json()["changes"]}
        flow["topic3_held"] = all(states[c]["held"] for c in changes[third][1:])
        checks("topic 3 changes stay held behind its open canary", flow["topic3_held"])
        with session_factory()() as db:
            flow["audit_actions"] = dict(
                sorted(Counter(db.scalars(select(AuditEvent.action).where(AuditEvent.action.like("rollout.%")))).items())
            )
            flow["hook_audited"] = (
                db.scalar(
                    select(AuditEvent.id).where(
                        AuditEvent.actor == rollout.HOOK_ACTOR, AuditEvent.action == "rollout.revert_opened"
                    )
                )
                is not None
            )
        flow["reviews"] = len(repo.reviews)
        flow["all_reviews_draft"] = all(r["draft"] for r in repo.reviews)
        flow["provider_merge_calls"] = sum(r.url.path.endswith("/merge") for r in repo.requests)
        flow["base_branch_writes"] = sum(
            json.loads(r.content or b"{}").get("branch") == "main" for r in repo.writes if r.content
        )
        checks(
            "draft only: every review a draft, no merge call, no base-branch write",
            flow["all_reviews_draft"] and flow["provider_merge_calls"] == 0 and flow["base_branch_writes"] == 0,
            {k: flow[k] for k in ("reviews", "all_reviews_draft", "provider_merge_calls", "base_branch_writes")},
        )
        checks("the auto-revert is audited as the hook actor", flow["hook_audited"])
    finally:
        routes.GitOpsClient = real_client


# -- variants and probes -----------------------------------------------------------------


def lf_tag_variant(boto3, world: dict, truth: Truth, checks: Checks) -> dict:
    """A tag-expression grant needs SearchTablesByLFTags (not in moto): modes must degrade to unknown."""
    from qualify_aws_emulated import assumed_session

    from app.collectors.aws_collector import AWSCollector, CollectionLimits

    credentials = world["member_credentials"]
    member = session(boto3, credentials["AccessKeyId"], credentials["SecretAccessKey"], credentials["SessionToken"])
    lf = member.client("lakeformation")
    lf.grant_permissions(
        Principal={"DataLakePrincipalIdentifier": truth.groups_topic["data-lake"][0]},
        Resource={"LFTagPolicy": {"ResourceType": "TABLE", "Expression": [{"TagKey": "domain", "TagValues": ["analytics"]}]}},
        Permissions=["SELECT"],
    )
    collector = AWSCollector(
        assumed_session(boto3, world),
        CollectionLimits(**COLLECTION_LIMITS),
        expected_account=world["account"],
        expected_role_arn=world["collector"],
        data_lake=True,
    )
    collector.collect()
    lake = collector.coverage["data_lake"]
    if lake.get("lakeformation_lf_tag_assignments") == "unknown":
        gap(
            "lakeformation:SearchTablesByLFTags / SearchDatabasesByLFTags",
            "HTTP 404 (not implemented)",
            "a tag-expression grant leaves every table mode unknown (warning lakeformation_lf_tag_unresolved); "
            "IAM edges stand, never under-stated",
        )
    modes = lake["lakeformation_table_modes"]
    checks(
        "LF-Tag expression grant: unresolvable tags degrade every table mode to unknown",
        modes.get("unknown") == len(truth.tables) and collector.warning_counts.get("lakeformation_lf_tag_unresolved"),
        {"modes": modes, "warnings": collector.warning_counts},
    )
    return {"modes": modes, "warnings": collector.warning_counts}


def record_gaps(result: dict, truth: Truth) -> None:
    """Emulator gaps the main run met (each with what the product did about it)."""
    warnings = result.get("collector", {}).get("warning_counts", {})
    coverage = result.get("collector", {}).get("coverage", {})
    if warnings.get("access_advisor_unknown"):
        gap(
            "iam:GenerateServiceLastAccessedDetails",
            "not implemented (HTML 404)",
            f"warning access_advisor_unknown x{warnings['access_advisor_unknown']}; no last-accessed hints",
        )
    if coverage.get("scp_inventory") != "collected":
        gap(
            "organizations:ListPoliciesForTarget from a member account",
            "AWSOrganizationsNotInUseException (moto keeps the organization in the management account)",
            f"scp_inventory {coverage.get('scp_inventory')}; the SCP is not applied to edges",
        )
    gap(
        "s3:ListBuckets pagination (MaxBuckets)",
        "MaxBuckets honoured but no ContinuationToken: the collector saw 100 of 300 buckets and reported the "
        "inventory complete",
        "the run's collector lists every bucket in one call (MaxBuckets dropped); the collector's "
        "ContinuationToken loop is covered by Stubber tests; live gate for accounts over 100 buckets",
    )
    if warnings.get("glue_resource_policy_unknown"):
        gap(
            "glue:GetResourcePolicy without a policy",
            "HTTP 200 with an empty body instead of EntityNotFoundException",
            "warning glue_resource_policy_unknown (coverage unknown instead of absent)",
        )
    absent = sum(1 for item in truth.buckets.values() if item["ownership"] == "absent")
    gap(
        "s3:GetBucketOwnershipControls / GetBucketEncryption on buckets without explicit configuration",
        "not-found errors; AWS defaults to BucketOwnerEnforced and SSE-S3",
        f"{absent} buckets keep ACLs as an uncollected grant source; unencrypted-by-default buckets read as unverified",
    )
    gap(
        "lakeformation:ListPermissions for tables created with default settings",
        "no implicit IAM_ALLOWED_PRINCIPALS entries",
        "the seed grants IAM_ALLOWED_PRINCIPALS explicitly on every hybrid table",
    )
    gap(
        "sts:AssumeRole trust and IAM authorization",
        "not enforced (any caller may assume any role; no IAM evaluation)",
        "the collector's permission template is installed but not proven minimal; RoleLastUsed is not set by "
        "simulated activity (it is CloudTrail only), so dormant roles have no RoleLastUsed conflicts",
    )
    gap(
        "CloudTrail itself",
        "moto's CloudTrail does not record calls; activity is simulated as export files",
        "the usage pipeline is exercised through the real upload API with records in the flaws.cloud shapes",
    )
    gap(
        "IAM Identity Center / identitystore",
        "permission-set roles are plain IAM roles with a SAML trust; no SSO admin APIs",
        "onBehalfOf users in sessions are Identity Center users, not IAM principals (attribution keeps them)",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path, required=True, help="Directory for the report")
    parser.add_argument("--port", type=int, default=55561)
    parser.add_argument("--dump", action="store_true", help="Also write the published graph (debugging)")
    parser.add_argument(
        "--database-url", help="Disposable PostgreSQL database for app state (migrated); default SQLite"
    )
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="zg-enterprise-sim-"))
    checks = Checks()
    phases = Phases()
    report: dict = {"python": platform.python_version(), "region": REGION, "started_at": datetime.now(UTC).isoformat()}
    started = time.perf_counter()

    def save() -> None:
        report["seconds"] = round(time.perf_counter() - started, 1)
        report["phases"] = phases.items
        report["checks"] = checks.results
        report["failures"] = checks.failures
        report["moto_gaps"] = MOTO_GAPS
        report["peak_rss_mb"] = rss_mb()
        (args.output / "enterprise-sim.json").write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n")

    try:
        with moto_server(args.port, args.output / "moto_server.log") as endpoint:
            env_for_sdk(endpoint, work)
            import boto3
            import moto

            report["moto"] = moto.__version__
            with phases("seed"):
                world, truth = seed(boto3)
            report["seeded"] = world["counts"]
            report["planted"] = {
                "over_grants": len(truth.over_grants),
                "conditional": len(truth.conditional),
                "resource_policy": len(truth.resource_policy),
                "lf_grants": len(truth.lf_grants),
                "duplicates": len(truth.duplicates),
                "dormant_roles": sum(r["kind"] in ("dormant", "out-of-window") for r in truth.roles.values()),
                "dormant_users": sum(u["state"] != "active" for u in truth.users.values()),
            }
            print(json.dumps({"seeded": report["seeded"], "planted": report["planted"]}), flush=True)
            try:
                run_pipeline(world, truth, work, checks, phases, args, report)
            except Exception as exc:  # noqa: BLE001 - the failure is the finding
                import traceback

                checks("pipeline runs", False, f"{type(exc).__name__}: {exc}")
                report["traceback"] = traceback.format_exc()[-6000:]
            save()
            record_gaps(report, truth)
            with phases("lf_tag_variant"):
                try:
                    report["lf_tag_variant"] = lf_tag_variant(boto3, world, truth, checks)
                except Exception as exc:  # noqa: BLE001
                    checks("LF-Tag variant runs", False, f"{type(exc).__name__}: {exc}")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    save()
    print(json.dumps({"checks": len(checks.results), "failures": [f["check"] for f in checks.failures]}, indent=1))
    sys.exit(1 if checks.failures else 0)


if __name__ == "__main__":
    main()
