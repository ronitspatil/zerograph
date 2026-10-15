"""Bounded, read-only AWS data lake inventory: Glue Data Catalog, Lake Formation and Athena.

Run by ``AWSCollector`` after its IAM and S3 inventory (so S3 bucket assets already
exist) in the collector's region. It adds:

* **Glue Data Catalog** databases (``Database`` nodes) and tables (``DataTable``
  nodes) owned by the account, keyed by their Glue ARNs
  (``arn:<partition>:glue:<region>:<account>:database/<db>`` and
  ``.../table/<db>/<table>``), the same IDs ``app.collectors.cloudtrail`` resolves
  Glue events to. A table's S3 location links to the bucket asset when the bucket
  is inventoried (``location_bucket`` metadata). Column and partition-key names,
  table parameters and database tags go through the metadata classifier.
* **Athena workgroups** (``QueryWorkgroup`` nodes, not data assets) with their
  query-result location; queries and results are never read.
* **IAM grants**: identity policies (with the Glue catalog resource policy,
  permissions boundaries and SCPs) evaluated by ``iam_evaluator`` for a bounded
  action set: Glue reads and writes on each table (catalog, database and table
  ARNs must all allow), Glue reads and writes on each database, and
  ``athena:StartQueryExecution`` on each workgroup. They become conditional
  ``CAN_READ``/``CAN_WRITE`` edges, like S3.
* **Lake Formation**: data lake settings (administrators, default permissions) and
  every permission ``ListPermissions`` returns. ``SELECT``/``DESCRIBE`` are reads,
  ``INSERT``/``ALTER``/``DELETE``/``DROP`` writes (``ALL`` both), and the edge actions
  name them (``lakeformation:SELECT``) with evidence starting ``lakeformation:``.
  A table where ``IAM_ALLOWED_PRINCIPALS`` holds a grant is in IAM-only or hybrid
  mode: its IAM edges stand. A table without one, with the permission listing
  complete, is governed by Lake Formation: a principal gets an edge only with a
  Lake Formation grant. With the listing denied or truncated the mode is unknown
  and IAM edges stand (over-stated, never under-stated).

* **LF-Tag grants** (``LFTagPolicy`` resources, inline expressions or saved ones from
  ``ListLFTagExpressions``) are resolved to every inventoried database or table they
  match: tags come from ``ListLFTags`` and one ``SearchDatabasesByLFTags``/
  ``SearchTablesByLFTags`` per tag key (not per table). An expression is an AND across
  keys and an OR within a key's values (``*`` any value); a table inherits its
  database's tags unless it assigns the key itself, and a column likewise from its
  table. Where only some columns match, the grant is column-scoped. They become the
  same ``lakeformation:`` edges as named grants, with evidence
  ``lakeformation: lf-tag <expression>``. If any tag-expression grant cannot be
  resolved for want of tag data (denied or truncated), Lake Formation mode is
  unknown everywhere and IAM edges stand.
* **Partial and external grants.** Column-scoped, data cells filter and column LF-Tag
  grants are marked partial in evidence (filter names, and per-table
  ``lakeformation_data_filter_grants`` metadata), never whole-table access. Grants on
  another account's catalog resources become Lake Formation-only edges to
  ``external`` nodes (``account_id`` the owning account); proposals touching them are
  manual, as for every Lake Formation grant.

Every API denial or service error is a warning with the coverage marked unknown;
inventory beyond a bound (databases, tables, permissions, workgroups, LF-Tags, tag
assignments, tag expressions) and the collector's request, page, evaluation or edge
budgets truncates the data lake part with an explicit warning instead of failing the
whole collection. Malformed pages and repeated continuation tokens still fail closed.
Data filters' row predicates, catalog and data location grants, and resource links
are not resolved.
"""

import re
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from app.collectors.data_classifier import enrich_node
from app.collectors.iam_evaluator import Decision, Request, evaluate
from app.graph.schema import Edge, EdgeType, Node, NodeType

GLUE_TABLE_READ = ("glue:GetTable", "glue:GetTables", "glue:GetPartitions")
GLUE_TABLE_WRITE = ("glue:UpdateTable", "glue:DeleteTable", "glue:BatchCreatePartition")
GLUE_DATABASE_READ = ("glue:GetDatabase",)
GLUE_DATABASE_WRITE = ("glue:CreateTable",)
ATHENA_READ = ("athena:StartQueryExecution",)
LF_READ = frozenset({"SELECT", "DESCRIBE"})
LF_WRITE = frozenset({"INSERT", "ALTER", "DELETE", "DROP"})
LF_DATABASE_READ = frozenset({"DESCRIBE"})
LF_DATABASE_WRITE = frozenset({"CREATE_TABLE", "ALTER", "DROP"})
IAM_ALLOWED = "IAM_ALLOWED_PRINCIPALS"
ALL_TABLES = "/*"  # Key suffix of a database's TableWildcard grants.
LAKEFORMATION = "lakeformation"
MAX_COLUMNS = 1000  # Column/partition names given to the classifier per table.
MAX_PARAMETERS = 64  # Table/database parameters read per entity.
MAX_LOCATION = 1024
# Parameter/tag keys kept as node tags: topic anchors and explicit classification keys.
TOPIC_KEYS = ("topic", "app", "application", "project", "workload", "team")
KEPT_KEYS = frozenset(
    {
        *TOPIC_KEYS,
        "owner",
        "env",
        "environment",
        "data-class",
        "data_class",
        "dataclass",
        "data_classification",
    }
    | {"data-classification", "sensitivity"}
)
S3_LOCATION = re.compile(r"^s3[an]?://([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])(?:/|$)", re.IGNORECASE)
ACCOUNT_ID = re.compile(r"\d{12}")
EXTERNAL = "external"  # Lake Formation mode (and marker) of another account's catalog resource.
LF_TAG_SEARCH_VALUES = 50  # LFTag.TagValues bound of the Lake Formation model, per search.
MAX_NODE_LF_TAGS = 32  # ``key=value`` LF-Tags kept as node metadata.
MAX_EXPRESSION_TEXT = 512
MAX_EVIDENCE_EXPRESSIONS = 4
# Grant scopes that give part of a table (some columns, or filtered rows/cells), never all of it.
PARTIAL_SCOPES = frozenset({"column-scoped", "data-filtered", "lf-tag column-scoped"})
LF_TAG = "lf-tag"
# Grants on LF-Tags or saved tag expressions themselves (ASSOCIATE, DESCRIBE...): administration
# of the tags, not data access.
TAG_ADMIN_RESOURCES = ("LFTag", "LFTagExpression")


class LakeTruncated(Exception):
    """A collector budget ran out during the data lake inventory (truncate, warn, keep going)."""


def bucket_of(location: Any) -> str:
    """The bucket name of an ``s3://bucket/prefix`` location, or ""."""
    if not isinstance(location, str):
        return ""
    match = S3_LOCATION.match(location.strip())
    return match[1].lower() if match else ""


def _key(raw: str) -> str:
    return raw.strip().lower()


def _parameters(values: Any) -> list[tuple[str, str]]:
    if not isinstance(values, dict):
        return []
    return [(str(k)[:128], str(v)[:256]) for k, v in sorted(values.items())[:MAX_PARAMETERS]]


def _kept(pairs: list[tuple[str, str]]) -> list[str]:
    """``key=value`` tags for topic-anchor and classification keys (others feed only the classifier)."""
    return sorted({f"{k}={v}"[:256] for k, v in pairs if _key(k) in KEPT_KEYS and v.strip()})


def _topic_pairs(tags: list[str]) -> dict[str, str]:
    """Topic-anchor keys of ``key=value`` tags (first value per key)."""
    found: dict[str, str] = {}
    for tag in tags:
        key, separator, value = tag.partition("=")
        if separator and _key(key) in TOPIC_KEYS and value.strip():
            found.setdefault(_key(key), value.strip()[:128])
    return found


Conditions = tuple[tuple[str, frozenset[str]], ...]  # LF-Tag expression: (key, values) ANDed.
TagMap = dict[str, frozenset[str]]  # LF-Tag key -> assigned values of one resource.


def lf_tag_map(pairs: Any) -> TagMap:
    """``{key: values}`` of an LF-Tag pair list (keys and values compare case-insensitively)."""
    found: dict[str, set[str]] = {}
    for pair in pairs if isinstance(pairs, list) else []:
        key = pair.get("TagKey") if isinstance(pair, dict) else None
        values = pair.get("TagValues") if isinstance(pair, dict) else None
        if isinstance(key, str) and key and isinstance(values, list):
            found.setdefault(_key(key), set()).update(_key(str(v)) for v in values)
    return {key: frozenset(values) for key, values in found.items()}


def lf_conditions(expression: Any) -> Conditions | None:
    """A tag expression's conditions; None when it is malformed or empty (it matches nothing)."""
    if not isinstance(expression, list) or not expression:
        return None
    merged: dict[str, set[str]] = {}
    for condition in expression:
        key = condition.get("TagKey") if isinstance(condition, dict) else None
        values = condition.get("TagValues") if isinstance(condition, dict) else None
        if not isinstance(key, str) or not key or not isinstance(values, list) or not values:
            return None
        values = {_key(str(v)) for v in values}
        before = merged.get(_key(key))
        if before is not None:  # The same key twice: both conditions must hold.
            values = before if "*" in values else values if "*" in before else before & values
            if not values:
                return None  # Contradictory: matches nothing.
        merged[_key(key)] = values
    return tuple(sorted((key, frozenset(values)) for key, values in merged.items()))


def lf_matches(conditions: Conditions, tags: TagMap) -> bool:
    """LF-Tag expression semantics: every key must be assigned (AND), with one of its values (OR).

    A ``*`` value matches any value of its key.
    """
    for key, values in conditions:
        assigned = tags.get(key)
        if not assigned or ("*" not in values and not assigned & values):
            return False
    return True


def lf_expression_text(conditions: Conditions, name: str = "") -> str:
    """``key=value AND key=(a OR b)``, prefixed with a saved expression's name."""
    parts = []
    for key, values in conditions:
        ordered = sorted(values)
        parts.append(f"{key}={ordered[0]}" if len(ordered) == 1 else f"{key}=({' OR '.join(ordered)})")
    text = " AND ".join(parts)
    return (f"{name}: {text}" if name else text)[:MAX_EXPRESSION_TEXT]


def lf_tag_strings(tags: TagMap) -> list[str]:
    found = sorted(f"{key}={value}"[:256] for key, values in tags.items() for value in values)
    return found[:MAX_NODE_LF_TAGS]


class DataLakeInventory:
    """One data lake pass for an ``AWSCollector`` (shares its budgets, warnings and coverage)."""

    def __init__(self, collector, account: str, partition: str):
        self.c, self.account, self.partition = collector, account, partition
        self.glue, self.lakeformation, self.athena = collector.glue, collector.lakeformation, collector.athena
        self.region = self.glue.meta.region_name or ""
        self.coverage: dict[str, Any] = {
            "region": self.region,
            "glue_catalog_inventory": "unknown",
            "glue_resource_policy": "unknown",
            "glue_database_tags": {"observed": 0, "unknown": 0},
            "lakeformation_settings": "unknown",
            "lakeformation_permissions": "unknown",
            "lakeformation_default_iam_allowed_principals": None,
            "lakeformation_table_modes": {"iam_allowed_principals": 0, "lakeformation": 0, "unknown": 0},
            "lakeformation_unresolved_grants": 0,
            "athena_workgroups": "unknown",
            "permission_edges": "complete",
            "skipped_resource_links": 0,
            # LF-Tag resolution: read only when a tag-expression grant exists ("not_needed" otherwise).
            "lakeformation_lf_tags": "not_needed",
            "lakeformation_lf_tag_assignments": "not_needed",
            "lakeformation_lf_tag_expressions": "not_needed",
            "lakeformation_lf_tag_grants": {"resolved": 0, "unresolved": 0, "matched_resources": 0},
            "lakeformation_data_filter_grants": 0,
            "lakeformation_external_grants": 0,
            "lakeformation_tag_admin_grants": 0,
        }
        collector.coverage["data_lake"] = self.coverage
        for key in (
            "glue_databases",
            "glue_tables",
            "athena_workgroups",
            "lakeformation_permissions",
            "lakeformation_lf_tags",
            "lakeformation_lf_tag_assignments",
        ):
            collector.counts[key] = 0
        # LF-Tag assignments read from the tag searches (as assigned at each level).
        self.lf_databases: dict[str, TagMap] = {}
        self.lf_tables: dict[tuple[str, str], TagMap] = {}
        self.lf_columns: dict[tuple[str, str], dict[str, TagMap]] = {}
        self.lf_named: dict[str, Conditions | None] = {}  # Saved tag expressions by name.
        # A tag-expression grant could not be resolved for want of tag data: Lake Formation
        # mode cannot be proven anywhere, so IAM edges stand (over-stated, never under-stated).
        self.lf_tag_gap = False

    # -- budgets ---------------------------------------------------------------------------

    def _call(self, client, operation: str, **kwargs):
        if self.c.requests >= self.c.limits.max_requests:
            raise LakeTruncated("requests")
        return self.c._call(client, operation, **kwargs)

    def _pages(self, client, operation: str, **kwargs):
        """``NextToken`` pages within the collector's page budget (exhaustion truncates)."""
        seen: set[str] = set()
        while True:
            if self.c.pages >= self.c.limits.max_pages:
                raise LakeTruncated("pages")
            self.c.pages += 1
            page = self._call(client, operation, **kwargs)
            if not isinstance(page, dict):
                raise self.c.incomplete("Malformed inventory page")
            yield page
            token = page.get("NextToken")
            if not token:
                return
            if not isinstance(token, str) or token in seen:
                raise self.c.incomplete("Invalid or repeated inventory continuation token")
            seen.add(token)
            kwargs["NextToken"] = token

    def _truncated(self, code: str, message: str) -> None:
        self.c._warning(code, message)

    _denied = _truncated  # Same reporting: one warning per code, counted.

    # -- ARNs ------------------------------------------------------------------------------

    def _arn(self, service: str, resource: str) -> str:
        return f"arn:{self.partition}:{service}:{self.region}:{self.account}:{resource}"

    def _catalog_arn(self, catalog: Any, resource: str) -> str:
        """A Glue ARN in this account's catalog or another account's (same region); "" if malformed."""
        if catalog == self.account:
            return self._arn("glue", resource)
        if isinstance(catalog, str) and ACCOUNT_ID.fullmatch(catalog):
            return f"arn:{self.partition}:glue:{self.region}:{catalog}:{resource}"
        return ""

    def catalog_arn(self) -> str:
        return self._arn("glue", "catalog")

    def database_arn(self, database: str) -> str:
        return self._arn("glue", f"database/{database}")

    def table_arn(self, database: str, table: str) -> str:
        return self._arn("glue", f"table/{database}/{table}")

    def workgroup_arn(self, name: str) -> str:
        return self._arn("athena", f"workgroup/{name}")

    # -- inventory -------------------------------------------------------------------------

    def _catalog_policy(self) -> list[dict]:
        try:
            response = self._call(self.glue, "get_resource_policy")
            document = response.get("PolicyInJson") if isinstance(response, dict) else None
            if isinstance(document, str) and document:
                self.coverage["glue_resource_policy"] = "observed"
                return [self.c._policy(document)]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "EntityNotFoundException":
                self.coverage["glue_resource_policy"] = "absent"
                return []
        except BotoCoreError:
            pass
        self._denied(
            "glue_resource_policy_unknown",
            "Glue Data Catalog resource policy unavailable; catalog grants it may add are not represented",
        )
        return []

    def _databases(self) -> list[dict]:
        found: dict[str, dict] = {}
        limit = self.c.limits.max_glue_databases
        try:
            for page in self._pages(self.glue, "get_databases", CatalogId=self.account, MaxResults=100):
                for database in page.get("DatabaseList", []):
                    name = database.get("Name") if isinstance(database, dict) else None
                    if not isinstance(name, str) or not name:
                        raise self.c.incomplete("Malformed Glue database inventory")
                    if database.get("TargetDatabase"):
                        self.coverage["skipped_resource_links"] += 1
                        continue
                    if database.get("CatalogId", self.account) != self.account:
                        continue
                    if name in found:
                        continue
                    if len(found) >= limit:
                        self.coverage["glue_catalog_inventory"] = "truncated"
                        self._truncated(
                            "glue_databases_truncated",
                            f"Glue databases beyond max_glue_databases ({limit}) were not inventoried",
                        )
                        return list(found.values())
                    found[name] = database
        except LakeTruncated:
            self.coverage["glue_catalog_inventory"] = "truncated"
            self._truncated(
                "data_lake_budget",
                "Collector request or page budget ran out during the data lake inventory; it is truncated",
            )
            return list(found.values())
        self.coverage["glue_catalog_inventory"] = "complete"
        return list(found.values())

    def _tables(self, databases: list[dict]) -> dict[str, list[dict]]:
        tables: dict[str, list[dict]] = {}
        limit, total = self.c.limits.max_glue_tables, 0
        for database in databases:
            name = database["Name"]
            found: dict[str, dict] = {}
            tables[name] = []
            try:
                for page in self._pages(
                    self.glue, "get_tables", CatalogId=self.account, DatabaseName=name, MaxResults=100
                ):
                    for table in page.get("TableList", []):
                        table_name = table.get("Name") if isinstance(table, dict) else None
                        if not isinstance(table_name, str) or not table_name:
                            raise self.c.incomplete("Malformed Glue table inventory")
                        if table.get("TargetTable"):
                            self.coverage["skipped_resource_links"] += 1
                            continue
                        if table_name in found:
                            continue
                        if total >= limit:
                            tables[name] = list(found.values())
                            self.coverage["glue_catalog_inventory"] = "truncated"
                            self._truncated(
                                "glue_tables_truncated",
                                f"Glue tables beyond max_glue_tables ({limit}) were not inventoried",
                            )
                            return tables
                        found[table_name] = table
                        total += 1
            except (ClientError, BotoCoreError):
                self.coverage["glue_catalog_inventory"] = "partial"
                self._denied("glue_tables_unknown", "Glue tables unavailable for one or more databases")
            except LakeTruncated:
                tables[name] = list(found.values())
                self.coverage["glue_catalog_inventory"] = "truncated"
                self._truncated(
                    "data_lake_budget",
                    "Collector request or page budget ran out during the data lake inventory; it is truncated",
                )
                return tables
            tables[name] = list(found.values())
        return tables

    def _database_tags(self, name: str) -> list[tuple[str, str]]:
        try:
            response = self._call(self.glue, "get_tags", ResourceArn=self.database_arn(name))
            tags = response.get("Tags") if isinstance(response, dict) else None
            if isinstance(tags, dict):
                self.coverage["glue_database_tags"]["observed"] += 1
                return [(str(k)[:128], str(v)[:256]) for k, v in sorted(tags.items())]
        except (ClientError, BotoCoreError):
            pass
        self.coverage["glue_database_tags"]["unknown"] += 1
        self._denied("glue_tags_unknown", "Glue database tags unavailable for one or more databases")
        return []

    def _settings(self) -> tuple[dict[str, str], bool]:
        """Lake Formation administrators (principal ARN -> kind) and whether settings were read."""
        admins: dict[str, str] = {}
        try:
            response = self._call(self.lakeformation, "get_data_lake_settings", CatalogId=self.account)
            settings = response.get("DataLakeSettings") if isinstance(response, dict) else None
            if not isinstance(settings, dict):
                raise ValueError
        except (ClientError, BotoCoreError, ValueError):
            self._denied(
                "lakeformation_settings_unknown",
                "Lake Formation data lake settings unavailable; administrators and default permissions unknown",
            )
            return admins, False
        for field, kind in (("ReadOnlyAdmins", "read_only_admin"), ("DataLakeAdmins", "admin")):
            for item in settings.get(field) or []:
                principal = (item or {}).get("DataLakePrincipalIdentifier")
                if isinstance(principal, str):
                    admins[principal] = kind
        defaults = [
            (entry.get("Principal") or {}).get("DataLakePrincipalIdentifier")
            for entry in settings.get("CreateTableDefaultPermissions") or []
            if isinstance(entry, dict)
        ]
        self.coverage["lakeformation_settings"] = "observed"
        self.coverage["lakeformation_default_iam_allowed_principals"] = IAM_ALLOWED in defaults
        return admins, True

    def _permissions(self) -> tuple[list[dict], str]:
        entries: list[dict] = []
        limit = self.c.limits.max_lakeformation_permissions
        try:
            for page in self._pages(
                self.lakeformation, "list_permissions", CatalogId=self.account, MaxResults=1000
            ):
                for entry in page.get("PrincipalResourcePermissions", []):
                    if len(entries) >= limit:
                        self._truncated(
                            "lakeformation_permissions_truncated",
                            f"Lake Formation permissions beyond max_lakeformation_permissions ({limit}) were "
                            "not read; table modes are unknown and IAM edges stand",
                        )
                        return entries, "truncated"
                    if isinstance(entry, dict):
                        entries.append(entry)
        except (ClientError, BotoCoreError):
            self._denied(
                "lakeformation_permissions_unknown",
                "Lake Formation permissions unavailable; table modes are unknown and IAM edges stand",
            )
            return entries, "unknown"
        except LakeTruncated:
            self._truncated(
                "data_lake_budget",
                "Collector request or page budget ran out during the data lake inventory; it is truncated",
            )
            return entries, "truncated"
        return entries, "complete"

    # -- LF-Tags ---------------------------------------------------------------------------

    def _lf_tag_inventory(self, entries: list[dict]) -> None:
        """LF-Tags, their assignments and saved expressions, read only for tag-expression grants."""
        policies = [
            (entry.get("Resource") or {}).get("LFTagPolicy")
            for entry in entries
            if isinstance(entry.get("Resource"), dict)
        ]
        policies = [policy for policy in policies if isinstance(policy, dict)]
        if not policies:
            return
        stages = ["lakeformation_lf_tags", "lakeformation_lf_tag_assignments"]
        if any(policy.get("ExpressionName") and not policy.get("Expression") for policy in policies):
            stages.append("lakeformation_lf_tag_expressions")
        for stage in stages:
            self.coverage[stage] = "unknown"
        try:
            keys = self._lf_tag_keys()
            if keys is not None:
                self._lf_tag_assignments(keys)
            if "lakeformation_lf_tag_expressions" in stages:
                self._lf_tag_expressions()
        except LakeTruncated:
            for stage in stages:
                if self.coverage[stage] == "unknown":
                    self.coverage[stage] = "truncated"
            self._truncated(
                "data_lake_budget",
                "Collector request or page budget ran out during the data lake inventory; it is truncated",
            )

    def _lf_tag_keys(self) -> dict[str, set[str]] | None:
        """LF-Tag keys and values of the account's catalog (``ListLFTags``); None when unavailable."""
        keys: dict[str, set[str]] = {}
        limit = self.c.limits.max_lf_tags
        try:
            for page in self._pages(
                self.lakeformation, "list_lf_tags", CatalogId=self.account, MaxResults=1000
            ):
                for pair in page.get("LFTags", []):
                    key = pair.get("TagKey") if isinstance(pair, dict) else None
                    values = pair.get("TagValues") if isinstance(pair, dict) else None
                    if not isinstance(key, str) or not key or not isinstance(values, list):
                        raise self.c.incomplete("Malformed LF-Tag inventory")
                    if pair.get("CatalogId", self.account) != self.account:
                        continue
                    if key not in keys and len(keys) >= limit:
                        self.coverage["lakeformation_lf_tags"] = "truncated"
                        self._truncated(
                            "lakeformation_lf_tags_truncated",
                            f"LF-Tags beyond max_lf_tags ({limit}) were not read; LF-Tag grants are not "
                            "fully resolved and IAM edges stand",
                        )
                        self.c.counts["lakeformation_lf_tags"] = len(keys)
                        return keys
                    keys.setdefault(key, set()).update(str(v) for v in values if isinstance(v, str))
        except (ClientError, BotoCoreError):
            self._denied(
                "lakeformation_lf_tags_unknown",
                "LF-Tags unavailable; LF-Tag grants are not resolved and IAM edges stand",
            )
            return None
        self.coverage["lakeformation_lf_tags"] = "complete"
        self.c.counts["lakeformation_lf_tags"] = len(keys)
        return keys

    def _lf_tag_assignments(self, keys: dict[str, set[str]]) -> None:
        """Tagged databases, tables and columns: ``SearchDatabasesByLFTags``/``SearchTablesByLFTags``
        once per tag key (its values in chunks), so requests scale with tags, not tables."""
        limit = self.c.limits.max_lf_tag_assignments
        seen: set[tuple[str, str]] = set()

        def admit(item: tuple[str, str]) -> bool:
            if item in seen:
                return True
            if len(seen) >= limit:
                self.coverage["lakeformation_lf_tag_assignments"] = "truncated"
                self._truncated(
                    "lakeformation_lf_tag_assignments_truncated",
                    f"LF-Tag assignments beyond max_lf_tag_assignments ({limit}) were not read; LF-Tag "
                    "grants are not fully resolved and IAM edges stand",
                )
                return False
            seen.add(item)
            self.c.counts["lakeformation_lf_tag_assignments"] = len(seen)
            return True

        try:
            for key in sorted(keys):
                values = sorted(keys[key])
                for start in range(0, len(values), LF_TAG_SEARCH_VALUES):
                    expression = [{"TagKey": key, "TagValues": values[start : start + LF_TAG_SEARCH_VALUES]}]
                    for page in self._pages(
                        self.lakeformation,
                        "search_databases_by_lf_tags",
                        CatalogId=self.account,
                        Expression=expression,
                        MaxResults=100,
                    ):
                        for item in page.get("DatabaseList", []):
                            database = (item or {}).get("Database") if isinstance(item, dict) else None
                            name = database.get("Name") if isinstance(database, dict) else None
                            if not isinstance(name, str) or not name:
                                raise self.c.incomplete("Malformed LF-Tag database search")
                            if database.get("CatalogId", self.account) != self.account:
                                continue
                            if not admit(("", name)):
                                return
                            self.lf_databases[name] = lf_tag_map(item.get("LFTags"))
                    for page in self._pages(
                        self.lakeformation,
                        "search_tables_by_lf_tags",
                        CatalogId=self.account,
                        Expression=expression,
                        MaxResults=100,
                    ):
                        for item in page.get("TableList", []):
                            table = (item or {}).get("Table") if isinstance(item, dict) else None
                            database = table.get("DatabaseName") if isinstance(table, dict) else None
                            name = table.get("Name") if isinstance(table, dict) else None
                            if not isinstance(database, str) or not database or not isinstance(name, str):
                                raise self.c.incomplete("Malformed LF-Tag table search")
                            if table.get("CatalogId", self.account) != self.account:
                                continue
                            if not admit((database, name)):
                                return
                            if item.get("LFTagOnDatabase"):
                                self.lf_databases.setdefault(database, lf_tag_map(item["LFTagOnDatabase"]))
                            self.lf_tables[(database, name)] = lf_tag_map(item.get("LFTagsOnTable"))
                            columns = {
                                str(column["Name"]): lf_tag_map(column.get("LFTags"))
                                for column in item.get("LFTagsOnColumns") or []
                                if isinstance(column, dict) and column.get("Name") and column.get("LFTags")
                            }
                            if columns:
                                self.lf_columns[(database, name)] = columns
        except (ClientError, BotoCoreError):
            self._denied(
                "lakeformation_lf_tag_assignments_unknown",
                "LF-Tag assignments unavailable; LF-Tag grants are not resolved and IAM edges stand",
            )
            return
        self.coverage["lakeformation_lf_tag_assignments"] = "complete"

    def _lf_tag_expressions(self) -> None:
        """Saved LF-Tag expressions (``ListLFTagExpressions``) that grants name instead of inlining."""
        limit = self.c.limits.max_lf_tag_expressions
        try:
            for page in self._pages(
                self.lakeformation, "list_lf_tag_expressions", CatalogId=self.account, MaxResults=1000
            ):
                for item in page.get("LFTagExpressions", []):
                    name = item.get("Name") if isinstance(item, dict) else None
                    if not isinstance(name, str) or not name:
                        raise self.c.incomplete("Malformed LF-Tag expression inventory")
                    if name not in self.lf_named and len(self.lf_named) >= limit:
                        self.coverage["lakeformation_lf_tag_expressions"] = "truncated"
                        self._truncated(
                            "lakeformation_lf_tag_expressions_truncated",
                            f"Saved LF-Tag expressions beyond max_lf_tag_expressions ({limit}) were not read; "
                            "grants naming them are not resolved and IAM edges stand",
                        )
                        return
                    self.lf_named[name] = lf_conditions(item.get("Expression"))
        except (ClientError, BotoCoreError):
            self._denied(
                "lakeformation_lf_tag_expressions_unknown",
                "Saved LF-Tag expressions unavailable; grants naming them are not resolved and IAM edges stand",
            )
            return
        self.coverage["lakeformation_lf_tag_expressions"] = "complete"

    def _lf_effective(self, database: str, table: str, column: str = "") -> TagMap:
        """Tags in force: the database's, overridden per key by the table's, then by the column's."""
        tags = dict(self.lf_databases.get(database, {}))
        tags.update(self.lf_tables.get((database, table), {}))
        if column:
            tags.update(self.lf_columns.get((database, table), {}).get(column, {}))
        return tags

    def _lf_matches(
        self, conditions: Conditions, resource_type: str, tables: dict[str, list[dict]]
    ) -> list[tuple[str, str]]:
        """(target key, scope) of every inventoried database or table a tag expression matches.

        ``DATABASE`` expressions match database tags. ``TABLE`` expressions match a table's
        tags in force (inherited from its database unless the table overrides the key); when
        only some columns' tags match (a column overrides the key, either way) the grant is
        column-scoped: partial access.
        """
        found: list[tuple[str, str]] = []
        if resource_type == "DATABASE":
            for database in sorted(tables):
                if lf_matches(conditions, self.lf_databases.get(database, {})):
                    found.append((self.database_arn(database), LF_TAG))
            return found
        for database, items in sorted(tables.items()):
            for table in items:
                name = table["Name"]
                tags = self._lf_effective(database, name)
                whole = lf_matches(conditions, tags)
                columns = [
                    lf_matches(conditions, self._lf_effective(database, name, column))
                    for column in self.lf_columns.get((database, name), {})
                ]
                if whole and all(columns):
                    found.append((self.table_arn(database, name), LF_TAG))
                elif whole or any(columns):
                    found.append((self.table_arn(database, name), "lf-tag column-scoped"))
        return found

    def _workgroups(self) -> list[dict]:
        found: dict[str, dict] = {}
        limit = self.c.limits.max_athena_workgroups
        status = "complete"
        try:
            for page in self._pages(self.athena, "list_work_groups", MaxResults=50):
                for summary in page.get("WorkGroups", []):
                    name = summary.get("Name") if isinstance(summary, dict) else None
                    if not isinstance(name, str) or not name:
                        raise self.c.incomplete("Malformed Athena workgroup inventory")
                    if name in found:
                        continue
                    if len(found) >= limit:
                        status = "truncated"
                        self._truncated(
                            "athena_workgroups_truncated",
                            f"Athena workgroups beyond max_athena_workgroups ({limit}) were not inventoried",
                        )
                        break
                    found[name] = dict(summary)
                if status == "truncated":
                    break
        except (ClientError, BotoCoreError):
            self._denied("athena_workgroups_unknown", "Athena workgroups unavailable")
            self.coverage["athena_workgroups"] = "unknown"
            return []
        except LakeTruncated:
            status = "truncated"
            self._truncated(
                "data_lake_budget",
                "Collector request or page budget ran out during the data lake inventory; it is truncated",
            )
        for name, summary in found.items():
            try:
                detail = self._call(self.athena, "get_work_group", WorkGroup=name).get("WorkGroup")
                if isinstance(detail, dict):
                    summary["detail"] = detail
                    continue
            except (ClientError, BotoCoreError, AttributeError):
                pass
            except LakeTruncated:
                status = "truncated"
                break
            self._denied(
                "athena_workgroup_detail_unknown",
                "Athena workgroup configuration unavailable for one or more workgroups",
            )
        self.coverage["athena_workgroups"] = status
        return list(found.values())

    # -- graph -----------------------------------------------------------------------------

    def collect(self, nodes: dict[str, Node], edges: dict, principals: list[dict]) -> None:
        if not self.region:
            self._denied("data_lake_region_unknown", "No AWS region configured; data lake inventory skipped")
            return
        resource_policies: list[dict] = []
        databases: list[dict] = []
        tables: dict[str, list[dict]] = {}
        try:
            resource_policies = self._catalog_policy()
            databases = self._databases()
        except (ClientError, BotoCoreError):
            self.coverage["glue_catalog_inventory"] = "unknown"
            self._denied("glue_catalog_unknown", "Glue Data Catalog inventory unavailable (denied or failed)")
        except LakeTruncated:
            self.coverage["glue_catalog_inventory"] = "truncated"
            self._truncated(
                "data_lake_budget",
                "Collector request or page budget ran out during the data lake inventory; it is truncated",
            )
        if databases:
            tables = self._tables(databases)
        admins, entries, permissions, workgroups = {}, [], "unknown", []
        try:
            admins, _ = self._settings()
            entries, permissions = self._permissions()
            self._lf_tag_inventory(entries)
            workgroups = self._workgroups()
        except LakeTruncated:
            self._truncated(
                "data_lake_budget",
                "Collector request or page budget ran out during the data lake inventory; it is truncated",
            )
        self.coverage["lakeformation_permissions"] = permissions
        database_tags: dict[str, list[tuple[str, str]]] = {}
        for database in databases:
            try:
                database_tags[database["Name"]] = self._database_tags(database["Name"])
            except LakeTruncated:
                break

        by_arn = {principal["Arn"]: principal for principal in principals}
        for arn, kind in sorted(admins.items()):
            if arn in nodes and arn in by_arn:
                nodes[arn] = nodes[arn].model_copy(
                    update={"metadata": {**nodes[arn].metadata, "lakeformation_admin": kind}}
                )
        self.coverage["lakeformation_admins"] = len(admins)

        grants, iam_allowed_tables, iam_allowed_databases, external = self._grants(entries, by_arn, tables)
        # Mode is provable only from a complete listing whose tag-expression grants all resolved.
        complete = permissions == "complete" and not self.lf_tag_gap
        if self.lf_tag_gap:
            self._truncated(
                "lakeformation_lf_tag_unresolved",
                "Some LF-Tag grants could not be resolved (tags, assignments or saved expressions unavailable "
                "or truncated); Lake Formation modes are unknown and IAM edges stand",
            )
        tagged = self.coverage["lakeformation_lf_tag_assignments"] == "complete"
        filtered: dict[str, int] = {}
        for (_, target), found in grants.items():
            if found["filters"]:
                filtered[target] = filtered.get(target, 0) + 1
        database_nodes: dict[str, str] = {}
        for database in databases:
            node = self._database_node(database, database_tags.get(database["Name"], []), nodes)
            if node is None:
                continue
            mode = (
                "unknown"
                if not complete
                else ("iam_allowed_principals" if node.id in iam_allowed_databases else LAKEFORMATION)
            )
            metadata = {**node.metadata, "lakeformation_mode": mode}
            if tagged and self.lf_databases.get(database["Name"]):
                metadata["lf_tags"] = lf_tag_strings(self.lf_databases[database["Name"]])
            node = node.model_copy(update={"metadata": metadata})
            nodes[node.id] = node
            database_nodes[database["Name"]] = node.id
        table_nodes: list[tuple[str, str, str]] = []  # (database, table arn, mode)
        for database_name, items in tables.items():
            if database_name not in database_nodes:
                continue
            parent = nodes[database_nodes[database_name]]
            for table in items:
                arn = self.table_arn(database_name, table["Name"])
                if len(arn) > 512:
                    self._truncated(
                        "glue_id_too_long", "Glue tables with ARNs over 512 characters were skipped"
                    )
                    continue
                mode = "unknown"
                if complete:
                    wildcard = database_nodes[database_name] + ALL_TABLES in iam_allowed_tables
                    mode = (
                        "iam_allowed_principals" if wildcard or arn in iam_allowed_tables else LAKEFORMATION
                    )
                self.coverage["lakeformation_table_modes"][mode] += 1
                node = self._table_node(arn, database_name, table, parent, mode, nodes)
                extra: dict[str, Any] = {}
                if tagged and self._lf_effective(database_name, table["Name"]):
                    extra["lf_tags"] = lf_tag_strings(self._lf_effective(database_name, table["Name"]))
                if tagged and self.lf_columns.get((database_name, table["Name"])):
                    extra["lf_tagged_columns"] = len(self.lf_columns[(database_name, table["Name"])])
                if filtered.get(arn):
                    extra["lakeformation_data_filter_grants"] = filtered[arn]
                if extra:
                    node = node.model_copy(update={"metadata": {**node.metadata, **extra}})
                nodes[arn] = node
                table_nodes.append((database_name, arn, mode))
        self.c.counts["glue_databases"] = len(database_nodes)
        self.c.counts["glue_tables"] = len(table_nodes)
        workgroup_nodes = []
        for workgroup in workgroups:
            node = self._workgroup_node(workgroup, nodes)
            if node is not None:
                nodes[node.id] = node
                workgroup_nodes.append(node.id)
        self.c.counts["athena_workgroups"] = len(workgroup_nodes)
        self.c.counts["lakeformation_permissions"] = len(entries)
        external_nodes = self._external_nodes(external, nodes)
        try:
            self._edges(
                edges,
                principals,
                resource_policies,
                database_nodes,
                table_nodes,
                workgroup_nodes,
                {arn: nodes[arn] for _, arn, _ in table_nodes}
                | {arn: nodes[arn] for arn in database_nodes.values()},
                grants,
            )
            self._external_edges(edges, by_arn, grants, external_nodes)
        except LakeTruncated as exc:
            self.coverage["permission_edges"] = "truncated"
            self._truncated(
                "data_lake_edges_truncated",
                f"Data lake permission edges truncated: the collector's {exc.args[0]} budget ran out",
            )

    def _grants(self, entries: list[dict], by_arn: dict[str, dict], tables: dict[str, list[dict]]):
        """Lake Formation grants per (principal, resource ARN), and IAM_ALLOWED_PRINCIPALS coverage.

        A ``TableWildcard`` grant is keyed by its database ARN + ``ALL_TABLES``. An
        LF-Tag expression grant (``LFTagPolicy``) is resolved to every inventoried
        database or table its expression matches. A grant on another account's catalog
        resource is keyed by that resource's ARN and listed in ``external``.
        ``iam_allowed_tables`` holds the table (and all-tables) keys granting
        IAM_ALLOWED_PRINCIPALS; ``iam_allowed_databases`` the database ARNs.
        """
        grants: dict[tuple[str, str], dict] = {}
        external: dict[str, dict] = {}  # ARN -> {catalog, database, table}
        iam_allowed_tables: set[str] = set()
        iam_allowed_databases: set[str] = set()
        unresolved = unmatched = 0
        tag_counts = self.coverage["lakeformation_lf_tag_grants"]
        matches: dict[tuple[Conditions, str], list[tuple[str, str]]] = {}
        tags_known = (
            self.coverage["lakeformation_lf_tags"] == "complete"
            and self.coverage["lakeformation_lf_tag_assignments"] == "complete"
        )
        matched: set[str] = set()

        def grant(principal: str, target: str, scope: str, entry: dict, permissions: set[str]) -> dict:
            found = grants.setdefault(
                (principal, target),
                {"permissions": set(), "scopes": set(), "expressions": set(), "filters": set()},
            )
            found["permissions"] |= permissions
            found["scopes"].add(scope or "table")
            if entry.get("Condition"):
                found["scopes"].add("conditional")
            return found

        for entry in entries:
            principal = (entry.get("Principal") or {}).get("DataLakePrincipalIdentifier")
            resource = entry.get("Resource") or {}
            permissions = {
                str(p)
                for p in [*(entry.get("Permissions") or []), *(entry.get("PermissionsWithGrantOption") or [])]
            }
            if any(kind in resource for kind in TAG_ADMIN_RESOURCES):
                self.coverage["lakeformation_tag_admin_grants"] += 1
                continue
            if "LFTagPolicy" in resource:
                policy = resource["LFTagPolicy"] or {}
                name = str(policy.get("ExpressionName") or "")[:255]
                resource_type = policy.get("ResourceType")
                missing = False  # A saved expression the (incomplete) listing did not return.
                if policy.get("Expression"):
                    conditions = lf_conditions(policy["Expression"])
                elif name:
                    conditions = self.lf_named.get(name)
                    missing = name not in self.lf_named and (
                        self.coverage["lakeformation_lf_tag_expressions"] != "complete"
                    )
                else:
                    conditions = None
                if (
                    policy.get("CatalogId", self.account) != self.account
                    or resource_type not in ("DATABASE", "TABLE")
                    or (conditions is None and not missing)
                ):
                    # Malformed or empty expressions match nothing; other catalogs' tags are not read.
                    unresolved += 1
                    tag_counts["unresolved"] += 1
                    continue
                if principal != IAM_ALLOWED and principal not in by_arn:
                    unmatched += 1
                    continue
                key = (conditions, resource_type)
                bounded = (
                    conditions is not None
                    and key not in matches
                    and len(matches) >= self.c.limits.max_lf_tag_expressions
                )
                if missing or not tags_known or bounded:
                    if bounded:
                        self._truncated(
                            "lakeformation_lf_tag_expressions_truncated",
                            "Distinct LF-Tag expressions beyond max_lf_tag_expressions "
                            f"({self.c.limits.max_lf_tag_expressions}) were not resolved; IAM edges stand",
                        )
                    # Tag data missing: the grant may reach Lake Formation-governed tables.
                    self.lf_tag_gap = True
                    unresolved += 1
                    tag_counts["unresolved"] += 1
                    continue
                if key not in matches:
                    self.c._check_time()
                    matches[key] = self._lf_matches(conditions, resource_type, tables)
                tag_counts["resolved"] += 1
                text = lf_expression_text(conditions, name)
                for target, scope in matches[key]:
                    matched.add(target)
                    if principal == IAM_ALLOWED:
                        allowed = iam_allowed_databases if resource_type == "DATABASE" else iam_allowed_tables
                        allowed.add(target)
                        continue
                    grant(principal, target, scope, entry, permissions)["expressions"].add(text)
                continue
            target, scope, catalog, place = "", "", self.account, {}
            if "Table" in resource:
                table = resource["Table"] or {}
                catalog, database = table.get("CatalogId", self.account), table.get("DatabaseName")
                if isinstance(database, str):
                    if "TableWildcard" in table:
                        target = self._catalog_arn(catalog, f"database/{database}")
                        target, scope = (target + ALL_TABLES if target else ""), "all tables"
                        place = {"database": database}
                    elif isinstance(table.get("Name"), str):
                        target = self._catalog_arn(catalog, f"table/{database}/{table['Name']}")
                        place = {"database": database, "table": table["Name"]}
            elif "TableWithColumns" in resource:
                table = resource["TableWithColumns"] or {}
                catalog, database = table.get("CatalogId", self.account), table.get("DatabaseName")
                if isinstance(database, str) and isinstance(table.get("Name"), str):
                    target = self._catalog_arn(catalog, f"table/{database}/{table['Name']}")
                    scope, place = "column-scoped", {"database": database, "table": table["Name"]}
            elif "DataCellsFilter" in resource:
                cells = resource["DataCellsFilter"] or {}
                catalog, database = cells.get("TableCatalogId", self.account), cells.get("DatabaseName")
                if isinstance(database, str) and isinstance(cells.get("TableName"), str):
                    target = self._catalog_arn(catalog, f"table/{database}/{cells['TableName']}")
                    scope, place = "data-filtered", {"database": database, "table": cells["TableName"]}
            elif "Database" in resource:
                database = resource["Database"] or {}
                catalog = database.get("CatalogId", self.account)
                if isinstance(database.get("Name"), str):
                    target = self._catalog_arn(catalog, f"database/{database['Name']}")
                    scope, place = "database", {"database": database["Name"]}
            if not target:
                # Catalog and data location grants are not resolved to tables.
                unresolved += 1
                continue
            foreign = catalog != self.account
            if principal == IAM_ALLOWED:
                if not foreign:
                    (iam_allowed_databases if scope == "database" else iam_allowed_tables).add(target)
                continue
            if principal not in by_arn:
                unmatched += 1
                continue
            if foreign:
                self.coverage["lakeformation_external_grants"] += 1
                external.setdefault(target.removesuffix(ALL_TABLES), {"catalog": catalog, **place})
                scope = f"{scope or 'table'}, {EXTERNAL} catalog {catalog}"
            found = grant(principal, target, scope, entry, permissions)
            if "DataCellsFilter" in resource:
                self.coverage["lakeformation_data_filter_grants"] += 1
                found["filters"].add(str((resource["DataCellsFilter"] or {}).get("Name") or "unnamed")[:255])
        tag_counts["matched_resources"] = len(matched)
        self.coverage["lakeformation_unresolved_grants"] = unresolved
        self.coverage["lakeformation_unmatched_principals"] = unmatched
        if unresolved:
            self.c._warning(
                "lakeformation_unresolved",
                "Some Lake Formation grants (catalog, data location, or LF-Tag grants whose expression or "
                "tags could not be read) were not resolved to tables",
            )
        if unmatched:
            self.c._warning(
                "lakeformation_unmatched",
                "Some Lake Formation grants name principals outside the IAM inventory (other accounts, "
                "SAML or Identity Center); they are not represented",
            )
        return grants, iam_allowed_tables, iam_allowed_databases, external

    def _classified(self, node: Node, fields: list[str], pairs: list[tuple[str, str]]) -> Node:
        enriched = enrich_node(node, fields, tags=pairs)
        kept = _kept(pairs)
        tags = sorted(set(enriched.tags) | set(kept))
        if len(tags) > 32:
            self.c._warning("tags_truncated", "Some tags were dropped beyond the per-entity tag bound")
            enriched = enriched.model_copy(
                update={"metadata": {**enriched.metadata, "tags_dropped": len(tags) - 32}}
            )
            tags = sorted(set(enriched.tags)) + [t for t in kept if t not in enriched.tags]
            tags = tags[:32]
        return enriched.model_copy(update={"tags": tags})

    def _location(self, location: Any, nodes: dict[str, Node]) -> dict:
        found: dict[str, Any] = {}
        if isinstance(location, str) and location:
            found["location"] = location[:MAX_LOCATION]
            bucket = bucket_of(location)
            if bucket:
                arn = f"arn:{self.partition}:s3:::{bucket}"
                inventoried = arn in nodes and nodes[arn].type == NodeType.BUCKET
                found["location_bucket_inventoried"] = inventoried
                if inventoried:
                    found["location_bucket"] = arn
        return found

    def _database_node(
        self, database: dict, tags: list[tuple[str, str]], nodes: dict[str, Node]
    ) -> Node | None:
        name = database["Name"]
        arn = self.database_arn(name)
        if len(arn) > 512:
            self._truncated("glue_id_too_long", "Glue tables with ARNs over 512 characters were skipped")
            return None
        parameters = _parameters(database.get("Parameters"))
        defaults = [
            (entry.get("Principal") or {}).get("DataLakePrincipalIdentifier")
            for entry in database.get("CreateTableDefaultPermissions") or []
            if isinstance(entry, dict)
        ]
        metadata = {
            "service": "glue",
            "resource_type": "glue_database",
            "catalog_id": self.account,
            "region": self.region,
            "lakeformation_default_iam_allowed_principals": IAM_ALLOWED in defaults,
            **self._location(database.get("LocationUri"), nodes),
        }
        node = Node(
            id=arn,
            name=name[:256],
            type=NodeType.DATABASE,
            account_id=self.account,
            provider="aws",
            metadata=metadata,
        )
        return self._classified(
            node, [name, str(database.get("Description", ""))[:1024]], [*tags, *parameters]
        )

    def _table_node(
        self, arn: str, database: str, table: dict, parent: Node, mode: str, nodes: dict[str, Node]
    ) -> Node:
        descriptor = table.get("StorageDescriptor") or {}
        columns = [c for c in [*(descriptor.get("Columns") or []), *(table.get("PartitionKeys") or [])] if c]
        fields = [database, table["Name"]]
        for column in columns[:MAX_COLUMNS]:
            fields.append(str(column.get("Name", ""))[:256])
            if column.get("Comment"):
                fields.append(str(column["Comment"])[:256])
        parameters = _parameters(table.get("Parameters"))
        located = self._location(descriptor.get("Location"), nodes)
        metadata: dict[str, Any] = {
            "service": "glue",
            "resource_type": "glue_table",
            "catalog_id": self.account,
            "region": self.region,
            "database": parent.id,
            "table_type": str(table.get("TableType", ""))[:64],
            "columns": len(columns),
            "partition_keys": len(table.get("PartitionKeys") or []),
            "lakeformation_mode": mode,
            "registered_with_lakeformation": table.get("IsRegisteredWithLakeFormation") is True,
            **located,
        }
        file_format = dict(parameters).get("classification")
        if file_format:
            metadata["format"] = file_format[:64]
        node = self._classified(
            Node(
                id=arn,
                name=f"{database}.{table['Name']}"[:256],
                type=NodeType.TABLE,
                account_id=self.account,
                provider="aws",
                metadata=metadata,
            ),
            fields,
            parameters,
        )
        # Topic anchors: the table's own parameters win; else its database's tags/parameters;
        # else its S3 location bucket's tags. Inherited anchors are metadata hints, not tags.
        if not _topic_pairs(node.tags):
            inherited, source = _topic_pairs(parent.tags), "database"
            bucket = nodes.get(located.get("location_bucket", ""))
            if not inherited and bucket is not None:
                inherited, source = _topic_pairs(bucket.tags), "location_bucket"
            if inherited:
                node = node.model_copy(
                    update={"metadata": {**node.metadata, **inherited, "topic_inherited_from": source}}
                )
        return node

    def _workgroup_node(self, workgroup: dict, nodes: dict[str, Node]) -> Node | None:
        name = workgroup["Name"]
        arn = self.workgroup_arn(name)
        if len(arn) > 512:
            return None
        detail = workgroup.get("detail") or {}
        configuration = detail.get("Configuration") or {}
        output = (configuration.get("ResultConfiguration") or {}).get("OutputLocation")
        metadata: dict[str, Any] = {
            "service": "athena",
            "resource_type": "athena_workgroup",
            "region": self.region,
            "state": str(workgroup.get("State") or detail.get("State") or "")[:32],
            "configuration": "observed" if detail else "unknown",
        }
        if detail:
            metadata["enforce_configuration"] = configuration.get("EnforceWorkGroupConfiguration") is True
            engine = (configuration.get("EngineVersion") or {}).get("EffectiveEngineVersion")
            if engine:
                metadata["engine_version"] = str(engine)[:64]
        if isinstance(output, str) and output:
            located = self._location(output, nodes)
            metadata["output_location"] = located.pop("location", "")
            if "location_bucket" in located:
                metadata["output_bucket"] = located["location_bucket"]
            if "location_bucket_inventoried" in located:
                metadata["output_bucket_inventoried"] = located["location_bucket_inventoried"]
        return Node(
            id=arn,
            name=name[:256],
            type=NodeType.WORKGROUP,
            account_id=self.account,
            provider="aws",
            metadata=metadata,
        )

    def _external_nodes(self, external: dict[str, dict], nodes: dict[str, Node]) -> set[str]:
        """Nodes for other accounts' catalog resources that inventoried principals hold grants on.

        They carry ``external: true`` and Lake Formation mode ``external``: the resource
        belongs to that account, so nothing here proposes changing it.
        """
        limit, added = self.c.limits.max_glue_tables, set()
        for arn, place in sorted(external.items()):
            if arn in nodes or len(arn) > 512:
                continue
            if len(added) >= limit:
                self._truncated(
                    "lakeformation_external_truncated",
                    f"Cross-account catalog resources beyond max_glue_tables ({limit}) were not represented",
                )
                break
            catalog, database, table = place["catalog"], place["database"], place.get("table")
            metadata: dict[str, Any] = {
                "service": "glue",
                "resource_type": "glue_table" if table else "glue_database",
                "catalog_id": catalog,
                "region": self.region,
                EXTERNAL: True,
                "lakeformation_mode": EXTERNAL,
            }
            if table:
                metadata["database"] = self._catalog_arn(catalog, f"database/{database}")
            nodes[arn] = Node(
                id=arn,
                name=(f"{database}.{table}" if table else database)[:256],
                type=NodeType.TABLE if table else NodeType.DATABASE,
                account_id=catalog,
                provider="aws",
                metadata=metadata,
            )
            added.add(arn)
        self.coverage["lakeformation_external_resources"] = len(added)
        return added

    def _external_edges(
        self, edges: dict, by_arn: dict[str, dict], grants: dict[tuple[str, str], dict], external: set[str]
    ) -> None:
        """Lake Formation edges into other accounts' catalog resources (IAM there is not evaluated)."""
        none: dict[EdgeType, list[str]] = {EdgeType.READ: [], EdgeType.WRITE: []}
        for (principal, target), found in sorted(grants.items()):
            node = target.removesuffix(ALL_TABLES)
            if node not in external:
                continue
            # A database's all-tables grant carries table permissions; a database grant its own.
            database = ":database/" in target and not target.endswith(ALL_TABLES)
            self._emit(edges, by_arn[principal], node, none, found, EXTERNAL, database=database)

    # -- permission edges ------------------------------------------------------------------

    def _edges(
        self,
        edges: dict,
        principals: list[dict],
        resource_policies: list[dict],
        database_nodes: dict[str, str],
        table_nodes: list[tuple[str, str, str]],
        workgroup_nodes: list[str],
        assets: dict[str, Node],
        grants: dict[tuple[str, str], dict],
    ) -> None:
        catalog = self.catalog_arn()
        modes = {arn: node.metadata.get("lakeformation_mode", "unknown") for arn, node in assets.items()}
        for principal in principals:
            cache: dict[tuple[str, str], bool] = {}

            def glue(
                actions: tuple[str, ...], arns: list[str], principal=principal, cache=cache
            ) -> list[str]:
                # Every resource the operation authorizes against (catalog first) must allow it.
                return [
                    a
                    for a in actions
                    if all(self._allowed(principal, cache, a, arn, resource_policies) for arn in arns)
                ]

            for _, database_arn in sorted(database_nodes.items()):
                self._emit(
                    edges,
                    principal,
                    database_arn,
                    {
                        EdgeType.READ: glue(GLUE_DATABASE_READ, [catalog, database_arn]),
                        EdgeType.WRITE: glue(GLUE_DATABASE_WRITE, [catalog, database_arn]),
                    },
                    grants.get((principal["Arn"], database_arn)),
                    modes[database_arn],
                    database=True,
                )
            for database, table_arn, mode in table_nodes:
                database_arn = database_nodes[database]
                lf = self._table_grant(grants, principal["Arn"], database_arn, table_arn)
                self._emit(
                    edges,
                    principal,
                    table_arn,
                    {
                        EdgeType.READ: glue(GLUE_TABLE_READ, [catalog, database_arn, table_arn]),
                        EdgeType.WRITE: glue(GLUE_TABLE_WRITE, [catalog, database_arn, table_arn]),
                    },
                    lf,
                    mode,
                )
            for workgroup in workgroup_nodes:
                actions = [a for a in ATHENA_READ if self._allowed(principal, cache, a, workgroup, [])]
                if actions:
                    self._edge(
                        edges,
                        Edge(
                            source=principal["Arn"],
                            target=workgroup,
                            type=EdgeType.READ,
                            actions=actions,
                            certainty="conditional",
                            evidence=[
                                "iam: identity policies, boundary and SCP metadata evaluated for Athena query "
                                "execution in this workgroup; data access also needs Glue and S3 or Lake "
                                "Formation grants; session context unresolved",
                            ],
                        ),
                    )

    def _allowed(self, principal: dict, cache: dict, action: str, arn: str, resources: list[dict]) -> bool:
        """Not denied for ``principal`` (cached per principal; counts against the evaluation budget)."""
        key = (action, arn)
        if key not in cache:
            self.c._check_time()
            if self.c.counts["evaluations"] >= self.c.limits.max_evaluations:
                raise LakeTruncated("evaluation")
            self.c.counts["evaluations"] += 1
            result = evaluate(
                Request(
                    principal["Arn"],
                    action,
                    arn,
                    {"aws:PrincipalArn": principal["Arn"], "aws:PrincipalAccount": self.account},
                ),
                principal["policies"],
                resources,
                principal["boundary"],
                principal["scps"],
                restrictions_complete=False,
            )
            cache[key] = result.decision != Decision.DENY
        return cache[key]

    @staticmethod
    def _table_grant(grants, principal: str, database_arn: str, table_arn: str) -> dict | None:
        """The Lake Formation grant on a table: direct, column/filter-scoped, or all tables of its database."""
        direct = grants.get((principal, table_arn))
        wildcard = grants.get((principal, database_arn + ALL_TABLES))
        if direct is None or wildcard is None:
            return direct or wildcard
        return {key: direct[key] | wildcard[key] for key in direct}

    def _emit(
        self,
        edges: dict,
        principal: dict,
        target: str,
        iam: dict[EdgeType, list[str]],
        lf: dict | None,
        mode: str,
        database: bool = False,
    ) -> None:
        read, write = (LF_DATABASE_READ, LF_DATABASE_WRITE) if database else (LF_READ, LF_WRITE)
        lf_permissions = lf["permissions"] if lf else set()
        if "ALL" in lf_permissions:
            lf_permissions = lf_permissions | read | write
        for kind, lf_kind in ((EdgeType.READ, read), (EdgeType.WRITE, write)):
            lf_actions = sorted(f"lakeformation:{p}" for p in lf_permissions & lf_kind)
            iam_actions = iam[kind]
            if mode == LAKEFORMATION and not lf_actions:
                continue  # Lake Formation governs this resource and grants nothing to the principal.
            if not iam_actions and not lf_actions:
                continue
            evidence = []
            if iam_actions:
                evidence.append(
                    "iam: identity policies, Glue catalog resource policy, boundary and SCP metadata evaluated "
                    f"(Lake Formation mode: {mode}); session context unresolved"
                )
            if lf_actions:
                evidence.extend(self._lf_evidence(lf))
            if mode == EXTERNAL:
                evidence.append(
                    "lakeformation: external resource in another account's catalog (cross-account grant); "
                    "its owner changes it there, never from this account"
                )
            if mode == LAKEFORMATION:
                evidence.append(
                    "lakeformation: governed by Lake Formation (no IAM_ALLOWED_PRINCIPALS grant); IAM alone "
                    "does not grant it"
                )
            evidence.extend(
                [
                    "An attached AWS-managed policy was too large to evaluate; its grants and denies are unknown "
                    "and were not applied"
                ]
                if principal.get("unevaluated")
                else []
            )
            self._edge(
                edges,
                Edge(
                    source=principal["Arn"],
                    target=target,
                    type=kind,
                    actions=[*iam_actions, *lf_actions],
                    certainty="conditional",
                    evidence=evidence,
                ),
            )

    @staticmethod
    def _lf_evidence(lf: dict) -> list[str]:
        """Evidence of a Lake Formation grant: named resources, tag expressions, data filters, partiality."""
        found = []
        named = sorted(scope for scope in lf["scopes"] if not scope.startswith(LF_TAG))
        if named and named != ["conditional"]:
            found.append(f"lakeformation: ListPermissions grant ({', '.join(named)})")
        expressions = sorted(lf.get("expressions", ()))
        found.extend(f"lakeformation: lf-tag {text}" for text in expressions[:MAX_EVIDENCE_EXPRESSIONS])
        if len(expressions) > MAX_EVIDENCE_EXPRESSIONS:
            found.append(
                f"lakeformation: lf-tag and {len(expressions) - MAX_EVIDENCE_EXPRESSIONS} more tag expressions"
            )
        filters = sorted(lf.get("filters", ()))
        if filters:
            shown = ", ".join(filters[:MAX_EVIDENCE_EXPRESSIONS]) + (" ..." if len(filters) > 4 else "")
            found.append(f"lakeformation: data cells filter {shown} (rows or cells filtered)")
        scopes = {scope.split(",")[0] for scope in lf["scopes"]} - {"conditional"}
        if scopes and scopes <= PARTIAL_SCOPES:
            found.append(
                "lakeformation: partial access only (column-scoped, data-filtered or column LF-Tag grant), "
                "not the whole table"
            )
        return found

    def _edge(self, edges: dict, edge: Edge) -> None:
        if edge.id not in edges and len(edges) >= self.c.limits.max_edges:
            raise LakeTruncated("edge")
        edges[edge.id] = edge
