"""AWS data lake collection: Glue Data Catalog, Lake Formation and Athena workgroups.

Every AWS response is a stub (Mock, or botocore Stubber with synthetic credentials,
which validates requests and responses against the installed service models);
nothing here reaches AWS.
"""

import json
from datetime import UTC, datetime
from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from app.collectors.aws_collector import AWSCollector, CollectionIncomplete, CollectionLimits
from app.collectors.cloudtrail import normalize_export
from app.collectors.execution_audit import EVENTS
from app.graph.compact import CompactGraph
from app.graph.schema import DATA_TYPES, EdgeType, GraphSnapshot, NodeType
from app.graph.topics import compute_topics

ACCOUNT = "123456789012"
REGION = "us-east-1"
GLUE = f"arn:aws:glue:{REGION}:{ACCOUNT}"
ANALYST = f"arn:aws:iam::{ACCOUNT}:role/analyst"
ETL = f"arn:aws:iam::{ACCOUNT}:role/etl"
LF_READER = f"arn:aws:iam::{ACCOUNT}:role/lf-reader"
NOBODY = f"arn:aws:iam::{ACCOUNT}:role/nobody"
RAW_DB, CURATED_DB = f"{GLUE}:database/lake_raw", f"{GLUE}:database/lake_curated"
EVENTS_TABLE = f"{GLUE}:table/lake_raw/events"
CUSTOMERS_TABLE = f"{GLUE}:table/lake_raw/customers"
ORDERS_TABLE = f"{GLUE}:table/lake_curated/orders"
WORKGROUP = f"arn:aws:athena:{REGION}:{ACCOUNT}:workgroup/analysts"
BUCKET = "arn:aws:s3:::datalake-raw"


def error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "redacted"}}, "test")


def policy(*statements) -> dict:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(actions, resources) -> dict:
    return {"Effect": "Allow", "Action": actions, "Resource": resources}


def role(arn: str, *statements) -> dict:
    name = arn.rsplit("/", 1)[-1]
    return {
        "Arn": arn,
        "RoleName": name,
        "RolePolicyList": [{"PolicyName": "p", "PolicyDocument": policy(*statements)}] if statements else [],
        "AssumeRolePolicyDocument": {"Statement": []},
    }


def roles() -> list[dict]:
    return [
        # Reads lake_raw tables through Glue, and queries in the analysts workgroup.
        role(
            ANALYST,
            allow(
                ["glue:GetTable", "glue:GetTables", "glue:GetPartitions", "glue:GetDatabase"],
                [f"{GLUE}:catalog", RAW_DB, f"{GLUE}:table/lake_raw/*"],
            ),
            allow("athena:StartQueryExecution", WORKGROUP),
        ),
        role(ETL, allow("glue:*", "*")),
        role(LF_READER, allow(["glue:GetTable", "lakeformation:GetDataAccess"], "*")),
        role(NOBODY),
    ]


def column(name: str) -> dict:
    return {"Name": name, "Type": "string"}


def table(database: str, name: str, location: str, columns, **extra) -> dict:
    return {
        "Name": name,
        "DatabaseName": database,
        "TableType": "EXTERNAL_TABLE",
        "StorageDescriptor": {"Columns": [column(c) for c in columns], "Location": location},
        "PartitionKeys": [column("dt")],
        "Parameters": {"classification": "parquet"},
        **extra,
    }


def databases_page(*names, token=None) -> dict:
    page = {
        "DatabaseList": [
            {
                "Name": name,
                "LocationUri": f"s3://datalake-raw/{name}/",
                "CreateTableDefaultPermissions": [
                    {
                        "Principal": {"DataLakePrincipalIdentifier": "IAM_ALLOWED_PRINCIPALS"},
                        "Permissions": ["ALL"],
                    }
                ],
            }
            for name in names
        ]
    }
    if token:
        page["NextToken"] = token
    return page


TABLES = {
    "lake_raw": [
        table("lake_raw", "events", "s3://datalake-raw/events/", ["event_id", "payload"]),
        table("lake_raw", "customers", "s3://datalake-raw/customers/", ["customer_id", "email"]),
    ],
    "lake_curated": [
        table("lake_curated", "orders", "s3://curated-elsewhere/orders/", ["order_id", "amount"]),
        # A resource link to another catalog is skipped.
        {
            "Name": "shared_link",
            "TargetTable": {"CatalogId": "999999999999", "DatabaseName": "x", "Name": "y"},
        },
    ],
}


def lf_entry(principal: str, resource: dict, permissions, **extra) -> dict:
    return {
        "Principal": {"DataLakePrincipalIdentifier": principal},
        "Resource": resource,
        "Permissions": list(permissions),
        "PermissionsWithGrantOption": [],
        **extra,
    }


def lf_permissions() -> list[dict]:
    return [
        # lake_raw is in IAM-only/hybrid mode (IAM_ALLOWED_PRINCIPALS on all its tables).
        lf_entry(
            "IAM_ALLOWED_PRINCIPALS",
            {"Table": {"CatalogId": ACCOUNT, "DatabaseName": "lake_raw", "TableWildcard": {}}},
            ["ALL"],
        ),
        lf_entry("IAM_ALLOWED_PRINCIPALS", {"Database": {"CatalogId": ACCOUNT, "Name": "lake_raw"}}, ["ALL"]),
        # lake_curated is governed by Lake Formation: only lf-reader holds a grant (column-scoped).
        lf_entry(
            LF_READER,
            {
                "TableWithColumns": {
                    "CatalogId": ACCOUNT,
                    "DatabaseName": "lake_curated",
                    "Name": "orders",
                    "ColumnNames": ["order_id"],
                }
            },
            ["SELECT"],
        ),
        lf_entry(LF_READER, {"Database": {"CatalogId": ACCOUNT, "Name": "lake_curated"}}, ["DESCRIBE"]),
        # Unresolvable here: LF-Tag policy grants and principals outside the inventory.
        lf_entry(
            ANALYST,
            {"LFTagPolicy": {"CatalogId": ACCOUNT, "ResourceType": "TABLE", "Expression": []}},
            ["SELECT"],
        ),
        lf_entry(
            "arn:aws:iam::999999999999:role/partner",
            {"Table": {"CatalogId": ACCOUNT, "DatabaseName": "lake_raw", "Name": "events"}},
            ["SELECT"],
        ),
    ]


def collector(limits: CollectionLimits | None = None):
    iam, s3, sts, org, glue, lf, athena = (Mock() for _ in range(7))
    clients = {
        "iam": iam,
        "s3": s3,
        "sts": sts,
        "organizations": org,
        "glue": glue,
        "lakeformation": lf,
        "athena": athena,
    }
    session = Mock()
    session.client.side_effect = lambda name, **_: clients[name]
    glue.meta.region_name = REGION
    sts.get_caller_identity.return_value = {
        "Account": ACCOUNT,
        "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/w/t",
    }
    org.describe_organization.side_effect = error("AWSOrganizationsNotInUseException")
    iam.get_account_authorization_details.return_value = {"IsTruncated": False, "RoleDetailList": roles()}
    s3.list_buckets.return_value = {"Buckets": [{"Name": "datalake-raw"}]}
    s3.get_bucket_policy.side_effect = error("NoSuchBucketPolicy")
    s3.get_bucket_tagging.return_value = {"TagSet": [{"Key": "topic", "Value": "data-lake"}]}
    s3.get_bucket_encryption.return_value = {"ServerSideEncryptionConfiguration": {}}
    s3.get_bucket_ownership_controls.return_value = {
        "OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}
    }
    glue.get_resource_policy.side_effect = error("EntityNotFoundException")
    glue.get_databases.side_effect = [
        databases_page("lake_raw", token="next"),
        databases_page("lake_curated"),
    ]
    glue.get_tables.side_effect = lambda **kw: {"TableList": TABLES[kw["DatabaseName"]]}
    glue.get_tags.side_effect = lambda ResourceArn: {
        "Tags": {"topic": "data-lake", "owner": "analytics"} if ResourceArn == RAW_DB else {}
    }
    lf.get_data_lake_settings.return_value = {
        "DataLakeSettings": {
            "DataLakeAdmins": [{"DataLakePrincipalIdentifier": ETL}],
            "CreateTableDefaultPermissions": [
                {
                    "Principal": {"DataLakePrincipalIdentifier": "IAM_ALLOWED_PRINCIPALS"},
                    "Permissions": ["ALL"],
                }
            ],
        }
    }
    lf.list_permissions.return_value = {"PrincipalResourcePermissions": lf_permissions()}
    # No LF-Tags defined: the one (empty) tag-expression grant matches nothing.
    lf.list_lf_tags.return_value = {"LFTags": []}
    athena.list_work_groups.return_value = {"WorkGroups": [{"Name": "analysts", "State": "ENABLED"}]}
    athena.get_work_group.return_value = {
        "WorkGroup": {
            "Name": "analysts",
            "State": "ENABLED",
            "Configuration": {
                "ResultConfiguration": {"OutputLocation": "s3://datalake-raw/athena-results/"},
                "EnforceWorkGroupConfiguration": True,
            },
        }
    }
    return AWSCollector(session, limits, data_lake=True), clients


def edges_of(snapshot: GraphSnapshot, source: str) -> dict[tuple[str, str], list[str]]:
    """Data lake edges of ``source`` (S3 edges, conditional for every principal, are left out)."""
    return {
        (e.target, e.type.value): e.actions
        for e in snapshot.edges
        if e.source == source and not e.target.startswith("arn:aws:s3:::")
    }


def node(snapshot: GraphSnapshot, node_id: str):
    return next(n for n in snapshot.nodes if n.id == node_id)


def test_glue_databases_tables_and_workgroups_become_assets():
    c, clients = collector()
    snapshot = c.collect()
    kinds = {n.id: n.type for n in snapshot.nodes}
    assert kinds[RAW_DB] == kinds[CURATED_DB] == NodeType.DATABASE
    assert kinds[EVENTS_TABLE] == kinds[CUSTOMERS_TABLE] == kinds[ORDERS_TABLE] == NodeType.TABLE
    assert kinds[WORKGROUP] == NodeType.WORKGROUP
    assert NodeType.TABLE in DATA_TYPES and NodeType.WORKGROUP not in DATA_TYPES
    assert not any("shared_link" in node_id for node_id in kinds)  # resource link skipped
    assert c.counts["glue_databases"] == 2 and c.counts["glue_tables"] == 3
    assert c.counts["athena_workgroups"] == 1 and c.counts["lakeformation_permissions"] == 6
    # Pagination followed with the token; tables requested per database, bounded page size.
    calls = clients["glue"].get_databases.call_args_list
    assert calls[0].kwargs == {"CatalogId": ACCOUNT, "MaxResults": 100}
    assert calls[1].kwargs == {"CatalogId": ACCOUNT, "MaxResults": 100, "NextToken": "next"}
    customers = node(snapshot, CUSTOMERS_TABLE)
    assert customers.name == "lake_raw.customers"
    assert customers.metadata["service"] == "glue"
    assert customers.metadata["database"] == RAW_DB
    assert customers.metadata["location_bucket"] == BUCKET  # S3 location links the bucket asset
    assert customers.metadata["format"] == "parquet"
    assert customers.metadata["columns"] == 3 and customers.metadata["partition_keys"] == 1
    # Column names go through the classifier (the "classification=parquet" format parameter does not).
    assert "PII" in customers.tags and customers.sensitivity.value == "confidential"
    assert node(snapshot, EVENTS_TABLE).sensitivity.value == "internal"
    orders = node(snapshot, ORDERS_TABLE)
    assert (
        orders.metadata["location_bucket_inventoried"] is False and "location_bucket" not in orders.metadata
    )
    raw = node(snapshot, RAW_DB)
    assert {"topic=data-lake", "owner=analytics"} <= set(raw.tags)
    assert raw.metadata["location_bucket"] == BUCKET
    workgroup = node(snapshot, WORKGROUP)
    assert workgroup.metadata["output_bucket"] == BUCKET
    assert workgroup.metadata["enforce_configuration"] is True
    assert node(snapshot, ETL).metadata["lakeformation_admin"] == "admin"
    coverage = c.coverage["data_lake"]
    assert coverage["glue_catalog_inventory"] == "complete"
    assert coverage["glue_resource_policy"] == "absent"
    assert coverage["lakeformation_permissions"] == "complete"
    assert coverage["lakeformation_default_iam_allowed_principals"] is True
    assert coverage["lakeformation_table_modes"] == {
        "iam_allowed_principals": 2,
        "lakeformation": 1,
        "unknown": 0,
    }
    assert coverage["skipped_resource_links"] == 1
    assert coverage["lakeformation_unresolved_grants"] == 1
    assert coverage["lakeformation_unmatched_principals"] == 1
    assert any("LF-Tag" in w for w in snapshot.warnings)
    assert any("Glue Data Catalog, Lake Formation and Athena" in w for w in snapshot.warnings)
    assert all(edge.certainty == "conditional" for edge in snapshot.edges)


def test_iam_and_lake_formation_grants_become_edges_by_mode():
    c, _ = collector()
    snapshot = c.collect()
    analyst = edges_of(snapshot, ANALYST)
    # Scoped Glue reads on lake_raw (IAM-only mode: IAM edges stand); no write, nothing curated.
    assert analyst[(EVENTS_TABLE, "CAN_READ")] == ["glue:GetTable", "glue:GetTables", "glue:GetPartitions"]
    assert analyst[(RAW_DB, "CAN_READ")] == ["glue:GetDatabase"]
    assert (EVENTS_TABLE, "CAN_WRITE") not in analyst
    assert not any(target in (ORDERS_TABLE, CURATED_DB) for target, _ in analyst)
    assert analyst[(WORKGROUP, "CAN_READ")] == ["athena:StartQueryExecution"]
    etl = edges_of(snapshot, ETL)
    # glue:* reaches every lake_raw table and database, but Lake Formation governs lake_curated:
    # IAM alone grants nothing there.
    assert etl[(CUSTOMERS_TABLE, "CAN_WRITE")] == [
        "glue:UpdateTable",
        "glue:DeleteTable",
        "glue:BatchCreatePartition",
    ]
    assert etl[(RAW_DB, "CAN_WRITE")] == ["glue:CreateTable"]
    assert not any(target in (ORDERS_TABLE, CURATED_DB) for target, _ in etl)
    assert (WORKGROUP, "CAN_READ") not in etl  # no athena grant
    reader = {(e.target, e.type.value): e for e in snapshot.edges if e.source == LF_READER}
    orders = reader[(ORDERS_TABLE, "CAN_READ")]
    assert orders.actions == ["glue:GetTable", "lakeformation:SELECT"]
    assert any(
        item.startswith("lakeformation: ListPermissions grant (column-scoped)") for item in orders.evidence
    )
    assert any("governed by Lake Formation" in item for item in orders.evidence)
    assert reader[(CURATED_DB, "CAN_READ")].actions == ["lakeformation:DESCRIBE"]
    assert (ORDERS_TABLE, "CAN_WRITE") not in reader
    assert not edges_of(snapshot, NOBODY)
    # The partner principal outside the inventory gets nothing.
    assert {e.source for e in snapshot.edges if "glue" in e.target} <= {ANALYST, ETL, LF_READER}


def test_lake_formation_unavailable_keeps_iam_edges_and_warns():
    c, clients = collector()
    clients["lakeformation"].get_data_lake_settings.side_effect = error("AccessDeniedException")
    clients["lakeformation"].list_permissions.side_effect = error("AccessDeniedException")
    snapshot = c.collect()
    coverage = c.coverage["data_lake"]
    assert coverage["lakeformation_permissions"] == "unknown"
    assert coverage["lakeformation_settings"] == "unknown"
    assert coverage["lakeformation_table_modes"]["unknown"] == 3
    # Mode unknown: IAM edges stand, including on the (actually governed) curated table.
    assert edges_of(snapshot, ETL)[(ORDERS_TABLE, "CAN_READ")]
    assert node(snapshot, ORDERS_TABLE).metadata["lakeformation_mode"] == "unknown"
    assert any("Lake Formation permissions unavailable" in w for w in snapshot.warnings)


def test_denials_are_warnings_and_iam_s3_collection_still_succeeds():
    c, clients = collector()
    clients["glue"].get_resource_policy.side_effect = error("AccessDeniedException")
    clients["glue"].get_databases.side_effect = error("AccessDeniedException")
    clients["lakeformation"].get_data_lake_settings.side_effect = error("AccessDeniedException")
    clients["lakeformation"].list_permissions.side_effect = error("AccessDeniedException")
    clients["athena"].list_work_groups.side_effect = error("AccessDeniedException")
    snapshot = c.collect()
    types = {n.type for n in snapshot.nodes}
    assert NodeType.TABLE not in types and NodeType.WORKGROUP not in types
    assert {NodeType.ROLE, NodeType.BUCKET} <= types
    coverage = c.coverage["data_lake"]
    assert coverage["glue_catalog_inventory"] == "unknown"
    assert coverage["glue_resource_policy"] == "unknown"
    assert coverage["athena_workgroups"] == "unknown"
    for code in (
        "glue_catalog_unknown",
        "glue_resource_policy_unknown",
        "lakeformation_permissions_unknown",
        "athena_workgroups_unknown",
    ):
        assert c.warning_counts[code] == 1


def test_one_database_failing_keeps_the_others():
    c, clients = collector()
    clients["glue"].get_tables.side_effect = lambda **kw: (
        (_ for _ in ()).throw(error("AccessDeniedException"))
        if kw["DatabaseName"] == "lake_curated"
        else {"TableList": TABLES["lake_raw"]}
    )
    snapshot = c.collect()
    ids = {n.id for n in snapshot.nodes}
    assert EVENTS_TABLE in ids and ORDERS_TABLE not in ids and CURATED_DB in ids
    assert c.coverage["data_lake"]["glue_catalog_inventory"] == "partial"
    assert "glue_tables_unknown" in c.warning_counts


@pytest.mark.parametrize(
    ("limits", "code", "coverage_key", "expected"),
    [
        ({"max_glue_databases": 1}, "glue_databases_truncated", "glue_catalog_inventory", "truncated"),
        ({"max_glue_tables": 1}, "glue_tables_truncated", "glue_catalog_inventory", "truncated"),
        (
            {"max_lakeformation_permissions": 2},
            "lakeformation_permissions_truncated",
            "lakeformation_permissions",
            "truncated",
        ),
        ({"max_athena_workgroups": 1}, None, "athena_workgroups", "complete"),
    ],
)
def test_bounds_truncate_with_explicit_warnings(limits, code, coverage_key, expected):
    c, _ = collector(CollectionLimits(**limits))
    snapshot = c.collect()
    assert c.coverage["data_lake"][coverage_key] == expected
    if code:
        assert c.warning_counts[code] == 1
        assert any("max_" in w for w in snapshot.warnings)
    if "max_glue_tables" in limits:
        assert c.counts["glue_tables"] == 1
    if "max_glue_databases" in limits:
        assert c.counts["glue_databases"] == 1
    if "max_lakeformation_permissions" in limits:
        # A partial listing cannot prove Lake Formation mode: IAM edges stand everywhere.
        assert c.coverage["data_lake"]["lakeformation_table_modes"]["unknown"] == 3
        assert edges_of(snapshot, ETL)[(ORDERS_TABLE, "CAN_READ")]


def test_workgroups_beyond_the_bound_are_truncated():
    c, clients = collector(CollectionLimits(max_athena_workgroups=1))
    clients["athena"].list_work_groups.return_value = {
        "WorkGroups": [{"Name": "analysts", "State": "ENABLED"}, {"Name": "primary", "State": "ENABLED"}]
    }
    c.collect()
    assert c.coverage["data_lake"]["athena_workgroups"] == "truncated"
    assert c.warning_counts["athena_workgroups_truncated"] == 1
    assert c.counts["athena_workgroups"] == 1


def test_collector_budgets_truncate_the_data_lake_not_the_collection():
    # Edges: the S3/IAM phase keeps its budget; data lake edges stop at the bound with a warning.
    c, _ = collector(CollectionLimits(max_edges=10))  # 8 S3 edges (4 roles x read/write) first
    snapshot = c.collect()
    assert len(snapshot.edges) == 10
    assert c.coverage["data_lake"]["permission_edges"] == "truncated"
    assert "data_lake_edges_truncated" in c.warning_counts
    # Evaluations: S3 and AssumeRole evaluations come first and are fully counted.
    c, _ = collector(CollectionLimits(max_evaluations=60))
    c.collect()
    assert c.coverage["data_lake"]["permission_edges"] == "truncated"
    # Requests: the data lake phase runs last and stops when the request budget is spent.
    c, _ = collector(CollectionLimits(max_requests=12))
    snapshot = c.collect()
    assert c.requests == 12
    assert "data_lake_budget" in c.warning_counts
    assert any(n.type == NodeType.BUCKET for n in snapshot.nodes)


def test_malformed_glue_pages_still_fail_closed():
    c, clients = collector()
    clients["glue"].get_databases.side_effect = [databases_page("lake_raw", token="next")] * 2
    with pytest.raises(CollectionIncomplete, match="repeated"):
        c.collect()
    c, clients = collector()
    clients["glue"].get_databases.side_effect = None
    clients["glue"].get_databases.return_value = "not a page"
    with pytest.raises(CollectionIncomplete, match="Malformed"):
        c.collect()


def test_data_lake_is_opt_in_for_the_constructor():
    c, clients = collector()
    c.data_lake = False
    snapshot = c.collect()
    assert not any(n.type in (NodeType.TABLE, NodeType.WORKGROUP) for n in snapshot.nodes)
    assert "data_lake" not in c.coverage
    clients["glue"].get_databases.assert_not_called()


def test_tables_inherit_topic_anchors_and_form_the_data_lake_topic():
    c, clients = collector()
    # A database without tags: its tables inherit from their S3 location bucket instead.
    clients["glue"].get_tags.side_effect = lambda ResourceArn: {"Tags": {}}
    clients["glue"].get_databases.side_effect = [databases_page("lake_raw"), databases_page()]
    snapshot = c.collect()
    events = node(snapshot, EVENTS_TABLE)
    assert events.metadata["topic"] == "data-lake"
    assert events.metadata["topic_inherited_from"] == "location_bucket"
    c, _ = collector()
    snapshot = c.collect()
    events = node(snapshot, EVENTS_TABLE)
    assert events.metadata["topic_inherited_from"] == "database"
    # Phase 1 topics: the bucket (tag), lake_raw (tag) and its tables (inherited) form data-lake.
    computed = compute_topics(CompactGraph.from_snapshot(snapshot))
    graph = computed.graph
    topic_of = {
        graph.ids[i]: computed.topics[t].name for i, t in enumerate(computed.resource_topic) if t >= 0
    }
    assert topic_of[EVENTS_TABLE] == topic_of[CUSTOMERS_TABLE] == topic_of[RAW_DB] == "data-lake"
    assert topic_of[BUCKET] == "data-lake"
    seeds = {graph.ids[i]: seed for i, seed in computed.resource_seed.items()}
    assert seeds[EVENTS_TABLE][0] == "metadata"
    # The workgroup is not a data asset and gets no topic.
    assert WORKGROUP not in topic_of


def test_cloudtrail_resources_match_collected_asset_ids():
    c, _ = collector()
    snapshot = c.collect()
    ids = {n.id for n in snapshot.nodes}
    session = {
        "type": "AssumedRole",
        "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/analyst/s",
        "sessionContext": {"sessionIssuer": {"type": "Role", "arn": ANALYST}},
    }

    def record(source, name, request):
        assert (source, name) in EVENTS
        return {
            "eventSource": source,
            "eventName": name,
            "eventTime": "2026-10-01T00:00:00Z",
            "awsRegion": REGION,
            "recipientAccountId": ACCOUNT,
            "userIdentity": session,
            "requestParameters": request,
        }

    records = [
        record("glue.amazonaws.com", "GetTable", {"databaseName": "Lake_Raw", "name": "EVENTS"}),
        record("glue.amazonaws.com", "GetPartitions", {"databaseName": "lake_raw", "tableName": "customers"}),
        record("glue.amazonaws.com", "GetDatabase", {"name": "lake_curated"}),
        record("athena.amazonaws.com", "StartQueryExecution", {"workGroup": "analysts", "queryString": "x"}),
        record("lakeformation.amazonaws.com", "GetDataAccess", {"tableArn": ORDERS_TABLE}),
    ]
    start, end = datetime(2026, 9, 1, tzinfo=UTC), datetime(2026, 10, 2, tzinfo=UTC)
    normalized = normalize_export(records, start, end)
    resources = {resource for (_, resource, _, _) in normalized.access}
    assert resources == {EVENTS_TABLE, CUSTOMERS_TABLE, CURATED_DB, WORKGROUP, ORDERS_TABLE}
    assert resources <= ids


def test_lake_formation_grants_force_manual_proposals():
    from app.graph.privilege import data_service

    c, _ = collector()
    snapshot = c.collect()
    graph = CompactGraph.from_snapshot(snapshot)
    assert data_service(graph, graph.index[ORDERS_TABLE]) == "glue"
    assert data_service(graph, graph.index[RAW_DB]) == "glue"
    from app.graph.proposals import NEVER_AUTO

    assert "lakeformation" in NEVER_AUTO


def test_botocore_models_accept_data_lake_requests_and_responses():
    """Every data lake call and response shape is validated by Stubber against botocore models."""
    import boto3
    from botocore.stub import Stubber

    session = boto3.Session(
        aws_access_key_id="synthetic", aws_secret_access_key="synthetic", region_name=REGION
    )
    c = AWSCollector(session, data_lake=True)
    stubs = {name: Stubber(getattr(c, name)) for name in ("sts", "iam", "s3", "organizations", "glue")}
    stubs["lakeformation"], stubs["athena"] = Stubber(c.lakeformation), Stubber(c.athena)
    sts, iam, s3, org, glue = (stubs[k] for k in ("sts", "iam", "s3", "organizations", "glue"))
    lf, athena = stubs["lakeformation"], stubs["athena"]
    sts.add_response(
        "get_caller_identity", {"Account": ACCOUNT, "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/w/t"}
    )
    detail = role(ETL, allow("glue:*", "*"))
    detail.update(
        Path="/",
        RoleId="AROASYNTHETIC123456789",
        CreateDate=datetime.now(UTC),
        AssumeRolePolicyDocument=json.dumps(detail["AssumeRolePolicyDocument"]),
        RolePolicyList=[
            {"PolicyName": "p", "PolicyDocument": json.dumps(detail["RolePolicyList"][0]["PolicyDocument"])}
        ],
    )
    iam.add_response(
        "get_account_authorization_details",
        {"RoleDetailList": [detail], "IsTruncated": False},
        {"Filter": ["Role", "User", "Group"], "MaxItems": 100},
    )
    s3.add_response("list_buckets", {"Buckets": []}, {"MaxBuckets": 100})
    org.add_client_error("describe_organization", service_error_code="AWSOrganizationsNotInUseException")
    glue.add_response(
        "get_resource_policy",
        {"PolicyInJson": json.dumps(policy(allow("glue:GetTable", "*") | {"Principal": {"AWS": NOBODY}}))},
        {},
    )
    created = datetime(2026, 1, 1, tzinfo=UTC)
    glue.add_response(
        "get_databases",
        {
            **databases_page("lake_raw", token="t2"),
            "DatabaseList": [{**databases_page("lake_raw")["DatabaseList"][0], "CreateTime": created}],
        },
        {"CatalogId": ACCOUNT, "MaxResults": 100},
    )
    glue.add_response(
        "get_databases", {"DatabaseList": []}, {"CatalogId": ACCOUNT, "MaxResults": 100, "NextToken": "t2"}
    )
    glue.add_response(
        "get_tables",
        {"TableList": [TABLES["lake_raw"][0]], "NextToken": "t3"},
        {"CatalogId": ACCOUNT, "DatabaseName": "lake_raw", "MaxResults": 100},
    )
    glue.add_response(
        "get_tables",
        {
            "TableList": [
                {**TABLES["lake_raw"][1], "IsRegisteredWithLakeFormation": True, "CreateTime": created}
            ]
        },
        {"CatalogId": ACCOUNT, "DatabaseName": "lake_raw", "MaxResults": 100, "NextToken": "t3"},
    )
    lf.add_response(
        "get_data_lake_settings",
        {
            "DataLakeSettings": {
                "DataLakeAdmins": [{"DataLakePrincipalIdentifier": ETL}],
                "CreateTableDefaultPermissions": [
                    {
                        "Principal": {"DataLakePrincipalIdentifier": "IAM_ALLOWED_PRINCIPALS"},
                        "Permissions": ["ALL"],
                    }
                ],
            }
        },
        {"CatalogId": ACCOUNT},
    )
    lf.add_response(
        "list_permissions",
        {"PrincipalResourcePermissions": lf_permissions()[:1], "NextToken": "lf2"},
        {"CatalogId": ACCOUNT, "MaxResults": 1000},
    )
    lf.add_response(
        "list_permissions",
        {"PrincipalResourcePermissions": lf_permissions()[1:]},
        {"CatalogId": ACCOUNT, "MaxResults": 1000, "NextToken": "lf2"},
    )
    athena.add_response(
        "list_work_groups",
        {"WorkGroups": [{"Name": "analysts", "State": "ENABLED", "CreationTime": created}]},
        {"MaxResults": 50},
    )
    athena.add_response(
        "get_work_group",
        {
            "WorkGroup": {
                "Name": "analysts",
                "State": "ENABLED",
                "Configuration": {
                    "ResultConfiguration": {"OutputLocation": "s3://datalake-raw/results/"},
                    "EngineVersion": {
                        "SelectedEngineVersion": "AUTO",
                        "EffectiveEngineVersion": "Athena engine version 3",
                    },
                },
            }
        },
        {"WorkGroup": "analysts"},
    )
    glue.add_response("get_tags", {"Tags": {"topic": "data-lake"}}, {"ResourceArn": RAW_DB})
    for stub in stubs.values():
        stub.activate()
    try:
        snapshot = c.collect()
        for stub in stubs.values():
            stub.assert_no_pending_responses()
    finally:
        for stub in stubs.values():
            stub.deactivate()
    ids = {n.id for n in snapshot.nodes}
    assert {RAW_DB, EVENTS_TABLE, CUSTOMERS_TABLE, WORKGROUP} <= ids
    assert c.coverage["data_lake"]["glue_resource_policy"] == "observed"
    assert node(snapshot, WORKGROUP).metadata["engine_version"] == "Athena engine version 3"
    # The catalog resource policy grants "nobody"... but nobody is not in this inventory.
    assert edges_of(snapshot, ETL)[(EVENTS_TABLE, "CAN_READ")]
    assert node(snapshot, CUSTOMERS_TABLE).metadata["registered_with_lakeformation"] is True


def test_catalog_resource_policy_can_grant_without_identity_policy():
    c, clients = collector()
    clients["glue"].get_resource_policy.side_effect = None
    clients["glue"].get_resource_policy.return_value = {
        "PolicyInJson": json.dumps(
            policy(
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": NOBODY},
                    "Action": ["glue:GetTable", "glue:GetTables", "glue:GetPartitions"],
                    "Resource": "*",
                }
            )
        )
    }
    snapshot = c.collect()
    assert edges_of(snapshot, NOBODY)[(EVENTS_TABLE, "CAN_READ")] == [
        "glue:GetTable",
        "glue:GetTables",
        "glue:GetPartitions",
    ]


def test_explicit_deny_on_the_catalog_blocks_every_table():
    c, clients = collector()
    details = clients["iam"].get_account_authorization_details.return_value["RoleDetailList"]
    details[1]["RolePolicyList"][0]["PolicyDocument"]["Statement"].append(
        {"Effect": "Deny", "Action": "glue:*", "Resource": f"{GLUE}:catalog"}
    )
    snapshot = c.collect()
    assert not edges_of(snapshot, ETL)


def test_cli_data_lake_follows_setting_and_flag(tmp_path, monkeypatch):
    from app.collectors import aws_collector
    from app.collectors.aws_collector import data_lake_default

    monkeypatch.delenv("ZG_AWS_DATA_LAKE", raising=False)
    assert data_lake_default() is True
    monkeypatch.setenv("ZG_AWS_DATA_LAKE", "false")
    assert data_lake_default() is False
    monkeypatch.setenv("ZG_AWS_DATA_LAKE", "maybe")
    with pytest.raises(ValueError):
        data_lake_default()
    assert aws_collector.HARD_LIMITS["max_glue_tables"] == 10000
    with pytest.raises(ValueError):
        CollectionLimits(max_glue_tables=10001)


def test_edge_types_into_workgroups_are_reads_only():
    c, _ = collector()
    snapshot = c.collect()
    into = [e for e in snapshot.edges if e.target == WORKGROUP]
    assert into and all(e.type == EdgeType.READ for e in into)


def test_planted_fixture_glue_option_keeps_the_base_and_aligns_cloudtrail_ids():
    import sys
    from datetime import timedelta
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    from qualify_scale import cloudtrail_records, generate_topics

    base, base_truth, _ = generate_topics(4000, 11)
    snapshot, truth, usage = generate_topics(4000, 11, glue=True)
    base_ids = {n.id for n in base.nodes}
    glue = {n.id for n in snapshot.nodes} - base_ids
    assert base_ids < {n.id for n in snapshot.nodes}
    assert {e.id for e in base.edges} <= {e.id for e in snapshot.edges}
    assert all(truth["resource_topic"][k] == v for k, v in base_truth["resource_topic"].items())
    assert glue and all(truth["resource_topic"][item] == "data-lake" for item in glue)
    tables = [n for n in snapshot.nodes if n.id in glue and n.type == NodeType.TABLE]
    assert len(tables) == 40 and all(n.metadata["service"] == "glue" for n in tables)
    assert any(item in glue for role, item in truth["over_grants"])
    end = datetime(2026, 10, 1, tzinfo=UTC)
    records = list(cloudtrail_records(snapshot, usage, end - timedelta(days=90), end))
    normalized = normalize_export(records, end - timedelta(days=90), end)
    observed = {resource for (_, resource, _, service) in normalized.access if service == "glue"}
    used = {item for items in usage["role_data_used"].values() for item in items if item in glue}
    assert observed == used  # every used Glue asset resolves to its collected-style ID
    # Phase 1 topics place the Glue tables in data-lake.
    computed = compute_topics(CompactGraph.from_snapshot(snapshot))
    graph = computed.graph
    labels = [computed.topics[computed.resource_topic[graph.index[n.id]]].name for n in tables]
    assert sum(label == "data-lake" for label in labels) / len(labels) >= 0.95
