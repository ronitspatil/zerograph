"""Lake Formation tag-based access control (LF-TBAC), data cells filters and cross-account grants.

Builds on the data lake fixture of ``test_aws_datalake``. Every AWS response is a stub
(Mock, or botocore Stubber with synthetic credentials validating requests and responses
against the installed service models); nothing here reaches AWS.
"""

import itertools
import json
import random
from datetime import UTC, datetime

import pytest
from test_aws_datalake import (
    ACCOUNT,
    ANALYST,
    CURATED_DB,
    CUSTOMERS_TABLE,
    ETL,
    EVENTS_TABLE,
    GLUE,
    LF_READER,
    NOBODY,
    ORDERS_TABLE,
    RAW_DB,
    REGION,
    TABLES,
    allow,
    collector,
    databases_page,
    error,
    lf_entry,
    lf_permissions,
    node,
    role,
    table,
)

from app.collectors.aws_collector import AWSCollector, CollectionLimits
from app.collectors.aws_datalake import (
    DataLakeInventory,
    lf_conditions,
    lf_expression_text,
    lf_matches,
    lf_tag_map,
)
from app.graph.compact import CompactGraph
from app.graph.schema import GraphSnapshot, NodeType

PAYMENTS_TABLE = f"{GLUE}:table/lake_curated/payments"
PARTNER = "999999999999"
SHARED_TABLE = f"arn:aws:glue:{REGION}:{PARTNER}:table/shared_db/sales"
SHARED_DB = f"arn:aws:glue:{REGION}:{PARTNER}:database/shared_db"

# LF-Tags of the catalog, assigned at database, table and column level.
LF_TAGS = {"domain": ["sales", "marketing"], "tier": ["gold", "silver", "raw"], "pii": ["true", "false"]}
DATABASE_TAGS = {"lake_curated": {"domain": "sales"}, "lake_raw": {"domain": "marketing"}}
TABLE_TAGS = {
    ("lake_curated", "orders"): {"tier": "gold"},
    ("lake_curated", "payments"): {"tier": "silver"},
    ("lake_raw", "events"): {"tier": "raw"},
    ("lake_raw", "customers"): {"tier": "raw", "domain": "sales"},  # overrides its database's domain
}
COLUMN_TAGS = {("lake_curated", "payments"): {"card": {"pii": "true"}}}


def pairs(tags: dict[str, str]) -> list[dict]:
    return [{"CatalogId": ACCOUNT, "TagKey": k, "TagValues": [v]} for k, v in sorted(tags.items())]


def tag_policy(resource_type: str, expression: dict | None = None, name: str = "") -> dict:
    policy = {"CatalogId": ACCOUNT, "ResourceType": resource_type}
    if expression is not None:
        policy["Expression"] = [{"TagKey": k, "TagValues": v} for k, v in expression.items()]
    if name:
        policy["ExpressionName"] = name
    return {"LFTagPolicy": policy}


def tag_permissions() -> list[dict]:
    return [
        # lake_raw IAM-only mode, lf-reader's column grant on orders: as in the base fixture.
        *lf_permissions()[:4],
        lf_entry(ANALYST, tag_policy("TABLE", {"domain": ["sales"], "tier": ["gold", "silver"]}), ["SELECT"]),
        lf_entry(ANALYST, tag_policy("TABLE", name="gold-only"), ["DESCRIBE"]),
        lf_entry(ETL, tag_policy("TABLE", {"domain": ["sales"]}), ["INSERT", "ALTER"]),
        lf_entry(NOBODY, tag_policy("DATABASE", {"domain": ["sales"]}), ["DESCRIBE", "CREATE_TABLE"]),
        lf_entry(LF_READER, tag_policy("TABLE", {"pii": ["true"]}), ["SELECT"]),
        lf_entry(
            LF_READER,
            {
                "DataCellsFilter": {
                    "TableCatalogId": ACCOUNT,
                    "DatabaseName": "lake_curated",
                    "TableName": "payments",
                    "Name": "eu_rows",
                }
            },
            ["SELECT"],
        ),
        # Cross-account: a table and a database shared from another account's catalog.
        lf_entry(
            ANALYST,
            {"Table": {"CatalogId": PARTNER, "DatabaseName": "shared_db", "Name": "sales"}},
            ["SELECT"],
        ),
        lf_entry(ETL, {"Database": {"CatalogId": PARTNER, "Name": "shared_db"}}, ["DESCRIBE"]),
        # Administration of the tags themselves (not data access).
        lf_entry(
            ETL, {"LFTag": {"CatalogId": ACCOUNT, "TagKey": "domain", "TagValues": ["*"]}}, ["ASSOCIATE"]
        ),
    ]


def search_tables(**kwargs) -> dict:
    (condition,) = kwargs["Expression"]
    key, values = condition["TagKey"], set(condition["TagValues"])
    found = []
    for (database, name), tags in sorted(TABLE_TAGS.items()):
        columns = COLUMN_TAGS.get((database, name), {})
        effective = {**DATABASE_TAGS.get(database, {}), **tags}
        if effective.get(key) in values or any(c.get(key) in values for c in columns.values()):
            item = {
                "Table": {"CatalogId": ACCOUNT, "DatabaseName": database, "Name": name},
                "LFTagOnDatabase": pairs(DATABASE_TAGS[database]),
                "LFTagsOnTable": pairs(tags),
            }
            if columns:
                item["LFTagsOnColumns"] = [{"Name": c, "LFTags": pairs(t)} for c, t in columns.items()]
            found.append(item)
    return {"TableList": found}


def search_databases(**kwargs) -> dict:
    (condition,) = kwargs["Expression"]
    return {
        "DatabaseList": [
            {"Database": {"CatalogId": ACCOUNT, "Name": name}, "LFTags": pairs(tags)}
            for name, tags in sorted(DATABASE_TAGS.items())
            if tags.get(condition["TagKey"]) in condition["TagValues"]
        ]
    }


def tagged_collector(limits: CollectionLimits | None = None, permissions=None):
    c, clients = collector(limits)
    curated = TABLES["lake_curated"]
    payments = table("lake_curated", "payments", "s3://curated-elsewhere/payments/", ["payment_id", "card"])
    clients["glue"].get_tables.side_effect = lambda **kw: {
        "TableList": [*curated, payments] if kw["DatabaseName"] == "lake_curated" else TABLES["lake_raw"]
    }
    lf = clients["lakeformation"]
    lf.list_permissions.return_value = {"PrincipalResourcePermissions": permissions or tag_permissions()}
    lf.list_lf_tags.return_value = {
        "LFTags": [{"CatalogId": ACCOUNT, "TagKey": k, "TagValues": v} for k, v in LF_TAGS.items()]
    }
    lf.search_tables_by_lf_tags.side_effect = search_tables
    lf.search_databases_by_lf_tags.side_effect = search_databases
    lf.list_lf_tag_expressions.return_value = {
        "LFTagExpressions": [
            {
                "Name": "gold-only",
                "CatalogId": ACCOUNT,
                "Expression": [{"TagKey": "tier", "TagValues": ["gold"]}],
            }
        ]
    }
    return c, clients


def edges(snapshot: GraphSnapshot, source: str) -> dict:
    return {
        (e.target, e.type.value): e
        for e in snapshot.edges
        if e.source == source and not e.target.startswith("arn:aws:s3:::")
    }


def test_tag_expression_grants_resolve_like_named_grants():
    c, clients = tagged_collector()
    snapshot = c.collect()
    coverage = c.coverage["data_lake"]
    assert coverage["lakeformation_lf_tags"] == "complete"
    assert coverage["lakeformation_lf_tag_assignments"] == "complete"
    assert coverage["lakeformation_lf_tag_expressions"] == "complete"
    assert coverage["lakeformation_lf_tag_grants"]["resolved"] == 5
    assert coverage["lakeformation_lf_tag_grants"]["unresolved"] == 0
    assert coverage["lakeformation_tag_admin_grants"] == 1
    assert coverage["lakeformation_unresolved_grants"] == 0
    # lake_curated is still governed by Lake Formation (no IAM_ALLOWED_PRINCIPALS grant).
    assert node(snapshot, PAYMENTS_TABLE).metadata["lakeformation_mode"] == "lakeformation"
    analyst = edges(snapshot, ANALYST)
    # domain=sales (inherited from lake_curated) AND tier=(gold OR silver): orders and payments.
    orders = analyst[(ORDERS_TABLE, "CAN_READ")]
    assert orders.actions == ["lakeformation:DESCRIBE", "lakeformation:SELECT"]
    assert "lakeformation: lf-tag domain=sales AND tier=(gold OR silver)" in orders.evidence
    assert "lakeformation: lf-tag gold-only: tier=gold" in orders.evidence  # saved expression by name
    assert any("governed by Lake Formation" in item for item in orders.evidence)
    payments = analyst[(PAYMENTS_TABLE, "CAN_READ")]
    assert payments.actions == ["lakeformation:SELECT"]
    assert not any("partial" in item for item in payments.evidence)
    assert (CUSTOMERS_TABLE, "CAN_READ") in analyst  # IAM grant on the IAM-mode table, unchanged
    assert not any("lf-tag" in item for item in analyst[(CUSTOMERS_TABLE, "CAN_READ")].evidence)
    # ETL: domain=sales also matches lake_raw.customers, whose table tag overrides its database's.
    etl = edges(snapshot, ETL)
    for target in (ORDERS_TABLE, PAYMENTS_TABLE):
        # IAM (glue:*) and Lake Formation both grant the write; Lake Formation grants no read.
        assert etl[(target, "CAN_WRITE")].actions[-2:] == ["lakeformation:ALTER", "lakeformation:INSERT"]
        assert (target, "CAN_READ") not in etl
    customers = etl[(CUSTOMERS_TABLE, "CAN_WRITE")]
    assert customers.actions == [
        "glue:UpdateTable",
        "glue:DeleteTable",
        "glue:BatchCreatePartition",
        "lakeformation:ALTER",
        "lakeformation:INSERT",
    ]
    assert "lakeformation: lf-tag domain=sales" in customers.evidence
    assert "lakeformation: lf-tag domain=sales" not in etl[(EVENTS_TABLE, "CAN_WRITE")].evidence
    # A DATABASE expression matches databases, with database permissions.
    nobody = edges(snapshot, NOBODY)
    assert nobody[(CURATED_DB, "CAN_READ")].actions == ["lakeformation:DESCRIBE"]
    assert nobody[(CURATED_DB, "CAN_WRITE")].actions == ["lakeformation:CREATE_TABLE"]
    assert (RAW_DB, "CAN_READ") not in nobody and (ORDERS_TABLE, "CAN_READ") not in nobody
    # Tags become node metadata: in force on tables (inherited), assigned on databases.
    assert node(snapshot, ORDERS_TABLE).metadata["lf_tags"] == ["domain=sales", "tier=gold"]
    assert node(snapshot, CUSTOMERS_TABLE).metadata["lf_tags"] == ["domain=sales", "tier=raw"]
    assert node(snapshot, CURATED_DB).metadata["lf_tags"] == ["domain=sales"]
    assert node(snapshot, PAYMENTS_TABLE).metadata["lf_tagged_columns"] == 1
    # Requests scale with tag keys (one search per key and level), not with tables.
    lf = clients["lakeformation"]
    assert lf.search_tables_by_lf_tags.call_count == lf.search_databases_by_lf_tags.call_count == 3
    assert lf.search_tables_by_lf_tags.call_args_list[0].kwargs == {
        "CatalogId": ACCOUNT,
        "Expression": [{"TagKey": "domain", "TagValues": ["marketing", "sales"]}],
        "MaxResults": 100,
    }


def test_column_tags_and_data_cells_filters_are_partial_access():
    c, _ = tagged_collector()
    snapshot = c.collect()
    reader = edges(snapshot, LF_READER)
    # pii=true is only on the payments card column; plus a data cells filter on the same table.
    payments = reader[(PAYMENTS_TABLE, "CAN_READ")]
    assert payments.actions == ["glue:GetTable", "lakeformation:SELECT"]
    assert "lakeformation: lf-tag pii=true" in payments.evidence
    assert "lakeformation: data cells filter eu_rows (rows or cells filtered)" in payments.evidence
    assert any(item.startswith("lakeformation: partial access only") for item in payments.evidence)
    assert node(snapshot, PAYMENTS_TABLE).metadata["lakeformation_data_filter_grants"] == 1
    assert c.coverage["data_lake"]["lakeformation_data_filter_grants"] == 1
    # The column grant on orders (base fixture) is partial too; no other table matches pii=true.
    assert any(
        item.startswith("lakeformation: partial") for item in reader[(ORDERS_TABLE, "CAN_READ")].evidence
    )
    granted = {target for (target, _), e in reader.items() if any("lf-tag" in item for item in e.evidence)}
    assert granted == {PAYMENTS_TABLE}
    # A whole-table grant beside a partial one is not partial.
    whole = [
        *tag_permissions(),
        lf_entry(
            LF_READER,
            {"Table": {"CatalogId": ACCOUNT, "DatabaseName": "lake_curated", "Name": "payments"}},
            ["SELECT"],
        ),
    ]
    c, _ = tagged_collector(permissions=whole)
    payments = edges(c.collect(), LF_READER)[(PAYMENTS_TABLE, "CAN_READ")]
    assert not any(item.startswith("lakeformation: partial") for item in payments.evidence)


def test_cross_account_catalog_grants_become_external_edges_never_local_changes():
    c, _ = tagged_collector()
    snapshot = c.collect()
    shared = node(snapshot, SHARED_TABLE)
    assert shared.type == NodeType.TABLE and shared.account_id == PARTNER
    assert shared.metadata["external"] is True and shared.metadata["lakeformation_mode"] == "external"
    assert shared.metadata["database"] == SHARED_DB
    assert node(snapshot, SHARED_DB).type == NodeType.DATABASE
    edge = edges(snapshot, ANALYST)[(SHARED_TABLE, "CAN_READ")]
    # Only the Lake Formation permission: IAM is not evaluated against another account's catalog.
    assert edge.actions == ["lakeformation:SELECT"]
    assert any("external resource in another account's catalog" in item for item in edge.evidence)
    assert any(f"external catalog {PARTNER}" in item for item in edge.evidence)
    assert edges(snapshot, ETL)[(SHARED_DB, "CAN_READ")].actions == ["lakeformation:DESCRIBE"]
    assert c.coverage["data_lake"]["lakeformation_external_grants"] == 2
    assert c.coverage["data_lake"]["lakeformation_external_resources"] == 2
    # Every grant into the external resources is a Lake Formation grant: proposals touching
    # them are manual (never-auto reason "lakeformation"), never an IAM change.
    graph = CompactGraph.from_snapshot(snapshot)
    for item in (SHARED_TABLE, SHARED_DB):
        into = [e for e in snapshot.edges if e.target == item]
        assert into and all(all(a.startswith("lakeformation:") for a in e.actions) for e in into)
        assert graph.index[item] >= 0


def test_iam_allowed_principals_by_tag_puts_matched_tables_in_hybrid_mode():
    permissions = [
        *tag_permissions(),
        lf_entry("IAM_ALLOWED_PRINCIPALS", tag_policy("TABLE", {"tier": ["silver"]}), ["ALL"]),
    ]
    c, _ = tagged_collector(permissions=permissions)
    snapshot = c.collect()
    assert node(snapshot, PAYMENTS_TABLE).metadata["lakeformation_mode"] == "iam_allowed_principals"
    assert node(snapshot, ORDERS_TABLE).metadata["lakeformation_mode"] == "lakeformation"
    assert edges(snapshot, ETL)[(PAYMENTS_TABLE, "CAN_READ")].actions[0] == "glue:GetTable"


def test_wildcard_tag_values_match_any_value_of_the_key():
    permissions = [*lf_permissions()[:4], lf_entry(NOBODY, tag_policy("TABLE", {"tier": ["*"]}), ["SELECT"])]
    c, _ = tagged_collector(permissions=permissions)
    nobody = edges(c.collect(), NOBODY)
    assert {target for target, _ in nobody} == {ORDERS_TABLE, PAYMENTS_TABLE, EVENTS_TABLE, CUSTOMERS_TABLE}


@pytest.mark.parametrize(
    ("operation", "code", "stage"),
    [
        ("list_lf_tags", "lakeformation_lf_tags_unknown", "lakeformation_lf_tags"),
        (
            "search_tables_by_lf_tags",
            "lakeformation_lf_tag_assignments_unknown",
            "lakeformation_lf_tag_assignments",
        ),
        (
            "list_lf_tag_expressions",
            "lakeformation_lf_tag_expressions_unknown",
            "lakeformation_lf_tag_expressions",
        ),
    ],
)
def test_lf_tag_denials_are_warnings_and_leave_modes_unknown(operation, code, stage):
    c, clients = tagged_collector()
    getattr(clients["lakeformation"], operation).side_effect = error("AccessDeniedException")
    snapshot = c.collect()
    coverage = c.coverage["data_lake"]
    assert coverage[stage] == "unknown"
    assert c.warning_counts[code] == 1
    assert c.warning_counts["lakeformation_lf_tag_unresolved"] == 1
    assert coverage["lakeformation_lf_tag_grants"]["unresolved"] >= 1
    # Unresolved tag grants may reach governed tables: modes are unknown and IAM edges stand.
    assert coverage["lakeformation_table_modes"]["lakeformation"] == 0
    assert edges(snapshot, ETL)[(ORDERS_TABLE, "CAN_READ")].actions[0] == "glue:GetTable"
    assert {n.type for n in snapshot.nodes} >= {NodeType.TABLE, NodeType.BUCKET}


@pytest.mark.parametrize(
    ("limits", "code", "stage", "expected"),
    [
        ({"max_lf_tags": 1}, "lakeformation_lf_tags_truncated", "lakeformation_lf_tags", "truncated"),
        (
            {"max_lf_tag_assignments": 2},
            "lakeformation_lf_tag_assignments_truncated",
            "lakeformation_lf_tag_assignments",
            "truncated",
        ),
        (
            {"max_lf_tag_expressions": 2},
            "lakeformation_lf_tag_expressions_truncated",
            "lakeformation_lf_tag_assignments",
            "complete",
        ),
    ],
)
def test_lf_tag_bounds_truncate_with_explicit_warnings(limits, code, stage, expected):
    c, _ = tagged_collector(CollectionLimits(**limits))
    snapshot = c.collect()
    coverage = c.coverage["data_lake"]
    assert coverage[stage] == expected
    assert c.warning_counts[code] >= 1  # counted per grant left unresolved by the bound
    assert sum("max_lf_tag" in w for w in snapshot.warnings) == 1
    assert coverage["lakeformation_table_modes"]["lakeformation"] == 0
    assert coverage["lakeformation_lf_tag_grants"]["unresolved"] >= 1


def test_tag_lookups_are_skipped_without_tag_expression_grants():
    c, clients = tagged_collector(permissions=lf_permissions()[:4])
    c.collect()
    clients["lakeformation"].list_lf_tags.assert_not_called()
    clients["lakeformation"].search_tables_by_lf_tags.assert_not_called()
    assert c.coverage["data_lake"]["lakeformation_lf_tags"] == "not_needed"


def test_malformed_tag_search_pages_fail_closed():
    from app.collectors.aws_collector import CollectionIncomplete

    c, clients = tagged_collector()
    clients["lakeformation"].search_tables_by_lf_tags.side_effect = lambda **_: {"TableList": [{"Table": {}}]}
    with pytest.raises(CollectionIncomplete, match="Malformed LF-Tag table search"):
        c.collect()
    c, clients = tagged_collector()
    clients["lakeformation"].list_lf_tags.return_value = {"LFTags": [], "NextToken": "same"}
    clients["lakeformation"].list_lf_tags.side_effect = None
    with pytest.raises(CollectionIncomplete, match="repeated"):
        c.collect()


# -- evaluator vs brute force ----------------------------------------------------------------


def brute_force(expression, resource_type, databases, tables, columns):
    """Reference LF-TBAC semantics written independently: walk every resource and every column.

    A key's value in force on a table is the table's own, else its database's; on a column
    the column's own, else the table's in force. A TABLE expression grants the whole table
    when it matches the table and every column, part of it when it matches some.
    """

    def holds(value_of):
        for condition in expression:
            value = value_of(condition["TagKey"])
            if value is None or ("*" not in condition["TagValues"] and value not in condition["TagValues"]):
                return False
        return True

    found = {}
    if resource_type == "DATABASE":
        for database, tags in databases.items():
            if holds(tags.get):
                found[("db", database)] = "whole"
        return found
    for (database, name), tags in tables.items():

        def table_value(key, database=database, tags=tags):
            return tags.get(key, databases.get(database, {}).get(key))

        verdicts = [holds(table_value)]
        for column_tags in columns.get((database, name), {}).values():
            verdicts.append(holds(lambda key, ct=column_tags, tv=table_value: ct.get(key, tv(key))))
        if all(verdicts):
            found[("table", database, name)] = "whole"
        elif verdicts[0] or any(verdicts[1:]):
            found[("table", database, name)] = "partial"
    return found


def test_expression_evaluator_matches_brute_force_on_random_catalogs():
    rng = random.Random(41)
    keys = {"k1": ["a", "b", "c"], "k2": ["x", "y"], "k3": ["p", "q", "r", "s"]}
    for _ in range(300):

        def assign():
            return {k: rng.choice(v) for k, v in keys.items() if rng.random() < 0.5}

        databases = {f"db{d}": assign() for d in range(3)}
        tables, columns = {}, {}
        for d, t in itertools.product(range(3), range(4)):
            tables[(f"db{d}", f"t{t}")] = assign()
            if rng.random() < 0.4:
                columns[(f"db{d}", f"t{t}")] = {f"c{i}": assign() for i in range(rng.randint(1, 3))}
        expression = [
            {
                "TagKey": key,
                "TagValues": ["*"]
                if rng.random() < 0.1
                else rng.sample(keys[key], rng.randint(1, len(keys[key]))),
            }
            for key in rng.sample(sorted(keys), rng.randint(1, 3))
        ]
        resource_type = rng.choice(["DATABASE", "TABLE", "TABLE"])
        inventory = DataLakeInventory.__new__(DataLakeInventory)
        inventory.partition, inventory.region, inventory.account = "aws", REGION, ACCOUNT
        inventory.lf_databases = {db: lf_tag_map(pairs(tags)) for db, tags in databases.items()}
        inventory.lf_tables = {key: lf_tag_map(pairs(tags)) for key, tags in tables.items()}
        inventory.lf_columns = {
            key: {column: lf_tag_map(pairs(tags)) for column, tags in found.items() if tags}
            for key, found in columns.items()
        }
        listed = {db: [{"Name": name} for (d, name) in tables if d == db] for db in databases}
        conditions = lf_conditions(expression)
        got = {}
        for target, scope in inventory._lf_matches(conditions, resource_type, listed):
            parts = target.split(":", 5)[5].split("/")
            key = ("db", parts[1]) if parts[0] == "database" else ("table", parts[1], parts[2])
            got[key] = "whole" if scope == "lf-tag" else "partial"
        # Columns without tags inherit the table's in force; the reference sees them as such.
        reference_columns = {key: {c: t for c, t in found.items() if t} for key, found in columns.items()}
        assert got == brute_force(expression, resource_type, databases, tables, reference_columns)


def test_expression_parsing_and_text():
    conditions = lf_conditions(
        [{"TagKey": "Tier", "TagValues": ["Gold", "silver"]}, {"TagKey": "domain", "TagValues": ["sales"]}]
    )
    assert lf_expression_text(conditions) == "domain=sales AND tier=(gold OR silver)"
    assert lf_expression_text(conditions, "named") == "named: domain=sales AND tier=(gold OR silver)"
    assert lf_conditions([]) is None and lf_conditions([{"TagKey": "k", "TagValues": []}]) is None
    repeated = [{"TagKey": "k", "TagValues": ["*"]}, {"TagKey": "k", "TagValues": ["a", "b"]}]
    assert lf_conditions(repeated) == (("k", frozenset({"a", "b"})),)
    assert lf_conditions([{"TagKey": "k", "TagValues": ["a"]}, {"TagKey": "k", "TagValues": ["b"]}]) is None
    assert lf_matches(conditions, {"tier": frozenset({"gold"}), "domain": frozenset({"sales"})})
    assert not lf_matches(conditions, {"tier": frozenset({"gold"})})  # AND across keys


def test_botocore_models_accept_lf_tag_requests_and_responses():
    """LF-Tag calls, pagination and the new grant shapes, validated by Stubber against botocore models."""
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
    detail = role(ANALYST, allow("glue:GetTable", "*"))
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
    glue.add_client_error("get_resource_policy", service_error_code="EntityNotFoundException")
    glue.add_response(
        "get_databases", databases_page("lake_curated"), {"CatalogId": ACCOUNT, "MaxResults": 100}
    )
    curated = [
        {k: v for k, v in table("lake_curated", name, f"s3://x/{name}/", ["id", "card"]).items()}
        for name in ("orders", "payments")
    ]
    glue.add_response(
        "get_tables",
        {"TableList": curated},
        {"CatalogId": ACCOUNT, "DatabaseName": "lake_curated", "MaxResults": 100},
    )
    lf.add_response("get_data_lake_settings", {"DataLakeSettings": {}}, {"CatalogId": ACCOUNT})
    entries = [
        lf_entry(ANALYST, tag_policy("TABLE", {"domain": ["sales"], "tier": ["gold"]}), ["SELECT"]),
        lf_entry(ANALYST, tag_policy("TABLE", name="pii-columns"), ["SELECT"]),
        lf_entry(
            ANALYST,
            {
                "DataCellsFilter": {
                    "TableCatalogId": ACCOUNT,
                    "DatabaseName": "lake_curated",
                    "TableName": "payments",
                    "Name": "eu_rows",
                }
            },
            ["SELECT"],
        ),
        lf_entry(
            ANALYST,
            {"Table": {"CatalogId": PARTNER, "DatabaseName": "shared_db", "Name": "sales"}},
            ["SELECT"],
        ),
        lf_entry(ANALYST, {"LFTagExpression": {"CatalogId": ACCOUNT, "Name": "pii-columns"}}, ["DESCRIBE"]),
    ]
    lf.add_response(
        "list_permissions",
        {"PrincipalResourcePermissions": entries[:2], "NextToken": "p2"},
        {"CatalogId": ACCOUNT, "MaxResults": 1000},
    )
    lf.add_response(
        "list_permissions",
        {"PrincipalResourcePermissions": entries[2:]},
        {"CatalogId": ACCOUNT, "MaxResults": 1000, "NextToken": "p2"},
    )
    lf.add_response(
        "list_lf_tags",
        {"LFTags": [{"CatalogId": ACCOUNT, "TagKey": "domain", "TagValues": ["sales"]}], "NextToken": "t2"},
        {"CatalogId": ACCOUNT, "MaxResults": 1000},
    )
    lf.add_response(
        "list_lf_tags",
        {
            "LFTags": [
                {"CatalogId": ACCOUNT, "TagKey": "pii", "TagValues": ["true"]},
                {"CatalogId": ACCOUNT, "TagKey": "tier", "TagValues": ["gold", "silver"]},
            ]
        },
        {"CatalogId": ACCOUNT, "MaxResults": 1000, "NextToken": "t2"},
    )
    domain = [{"TagKey": "domain", "TagValues": ["sales"]}]
    lf.add_response(
        "search_databases_by_lf_tags",
        {
            "DatabaseList": [
                {
                    "Database": {"CatalogId": ACCOUNT, "Name": "lake_curated"},
                    "LFTags": pairs({"domain": "sales"}),
                }
            ]
        },
        {"CatalogId": ACCOUNT, "Expression": domain, "MaxResults": 100},
    )

    def tagged(name, tags, columns=None):
        item = {
            "Table": {"CatalogId": ACCOUNT, "DatabaseName": "lake_curated", "Name": name},
            "LFTagOnDatabase": pairs({"domain": "sales"}),
            "LFTagsOnTable": pairs({"domain": "sales", **tags}),
        }
        if columns:
            item["LFTagsOnColumns"] = [{"Name": c, "LFTags": pairs(t)} for c, t in columns.items()]
        return item

    orders, payments = (
        tagged("orders", {"tier": "gold"}),
        tagged("payments", {"tier": "silver"}, {"card": {"pii": "true"}}),
    )
    lf.add_response(
        "search_tables_by_lf_tags",
        {"TableList": [orders], "NextToken": "s2"},
        {"CatalogId": ACCOUNT, "Expression": domain, "MaxResults": 100},
    )
    lf.add_response(
        "search_tables_by_lf_tags",
        {"TableList": [payments]},
        {"CatalogId": ACCOUNT, "Expression": domain, "MaxResults": 100, "NextToken": "s2"},
    )
    for key, values, found in (
        ("pii", ["true"], [payments]),
        ("tier", ["gold", "silver"], [orders, payments]),
    ):
        expression = [{"TagKey": key, "TagValues": values}]
        lf.add_response(
            "search_databases_by_lf_tags",
            {"DatabaseList": []},
            {"CatalogId": ACCOUNT, "Expression": expression, "MaxResults": 100},
        )
        lf.add_response(
            "search_tables_by_lf_tags",
            {"TableList": found},
            {"CatalogId": ACCOUNT, "Expression": expression, "MaxResults": 100},
        )
    lf.add_response(
        "list_lf_tag_expressions",
        {
            "LFTagExpressions": [
                {
                    "Name": "pii-columns",
                    "CatalogId": ACCOUNT,
                    "Expression": [{"TagKey": "pii", "TagValues": ["true"]}],
                }
            ]
        },
        {"CatalogId": ACCOUNT, "MaxResults": 1000},
    )
    athena.add_response("list_work_groups", {"WorkGroups": []}, {"MaxResults": 50})
    glue.add_response("get_tags", {"Tags": {}}, {"ResourceArn": CURATED_DB})
    for stub in stubs.values():
        stub.activate()
    try:
        snapshot = c.collect()
        for stub in stubs.values():
            stub.assert_no_pending_responses()
    finally:
        for stub in stubs.values():
            stub.deactivate()
    coverage = c.coverage["data_lake"]
    assert coverage["lakeformation_lf_tags"] == coverage["lakeformation_lf_tag_assignments"] == "complete"
    assert coverage["lakeformation_lf_tag_grants"] == {"resolved": 2, "unresolved": 0, "matched_resources": 2}
    assert c.counts["lakeformation_lf_tags"] == 3 and c.counts["lakeformation_lf_tag_assignments"] == 3
    analyst = edges(snapshot, ANALYST)
    assert "lakeformation: lf-tag domain=sales AND tier=gold" in analyst[(ORDERS_TABLE, "CAN_READ")].evidence
    payments_edge = analyst[(PAYMENTS_TABLE, "CAN_READ")]
    assert "lakeformation: lf-tag pii-columns: pii=true" in payments_edge.evidence
    assert any(item.startswith("lakeformation: partial") for item in payments_edge.evidence)
    assert analyst[(SHARED_TABLE, "CAN_READ")].actions == ["lakeformation:SELECT"]
    assert coverage["lakeformation_tag_admin_grants"] == 1


def test_planted_fixture_lf_tag_grants_add_edges_but_keep_the_base():
    import sys
    from datetime import timedelta
    from pathlib import Path

    from app.collectors.cloudtrail import normalize_export

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    from qualify_scale import cloudtrail_records, generate_topics

    snapshot, truth, usage = generate_topics(4000, 11, glue=True)
    lf = truth["lf_tag"]
    assert lf["tagged_tables"] > 0 and lf["tag_grant_roles"] > 1 and lf["over_broad_pairs"]
    tagged = {n.id for n in snapshot.nodes if n.type == NodeType.TABLE and n.metadata.get("lf_tags")}
    assert len(tagged) == lf["tagged_tables"]
    modes = {node(snapshot, item).metadata["lakeformation_mode"] for item in tagged}
    assert modes <= {"lakeformation", "iam_allowed_principals"}
    tag_edges = [
        e for e in snapshot.edges if any(item.startswith("lakeformation: lf-tag") for item in e.evidence)
    ]
    assert len({(e.source, e.target) for e in tag_edges}) == lf["tag_grant_pairs"]
    assert all(
        e.target in tagged and all(a.startswith("lakeformation:") for a in e.actions) for e in tag_edges
    )
    # The over-broad grant reaches every tagged table its holder has no other grant on, unused.
    broad = {
        (e.source, e.target) for e in tag_edges if "lakeformation: lf-tag domain=data-lake" in e.evidence
    }
    assert {tuple(pair) for pair in lf["over_broad_pairs"]} <= broad
    used = set(usage["role_data_used"].get(lf["over_broad_role"], []))
    assert not any(item in used for _, item in lf["over_broad_pairs"])
    # LF-Tag grants are not planted over-grants: those (and the base graph) are unchanged.
    assert not {tuple(pair) for pair in truth["over_grants"]} & broad
    # Used tag grants resolve from CloudTrail like other Glue access.
    end = datetime(2026, 10, 1, tzinfo=UTC)
    records = list(cloudtrail_records(snapshot, usage, end - timedelta(days=90), end))
    observed = {
        (r, item) for (r, item, _, _) in normalize_export(records, end - timedelta(days=90), end).access
    }
    used_tag_pairs = {(e.source, e.target) for e in tag_edges} & {
        (role, item) for role, items in usage["role_data_used"].items() for item in items
    }
    assert used_tag_pairs and used_tag_pairs <= observed
