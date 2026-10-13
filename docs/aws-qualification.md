# Read-only AWS sandbox qualification

ZeroGraph inventories IAM roles, IAM users (modeled as `HumanUser` identities),
IAM groups, owned general-purpose S3 buckets and, in the collector's region, the
Glue Data Catalog, Lake Formation permissions and Athena workgroups (see
[Data lake](#data-lake-glue-lake-formation-athena)). It reads policy documents, role,
user and bucket tags, each role's `RoleLastUsed`, default encryption configuration
and, optionally, IAM Access Advisor service last-accessed data; it never lists
objects, reads object contents, creates AWS resources or changes policies.

## What a collection keeps for the optimizer

- **Raw tags.** Role, user and bucket tags are kept as `key=value` node tags (at
  most 32 per entity; extra tags are dropped, counted in `tags_dropped` and warned
  about). Bucket classification labels (`PII`, `PHI`, ...) stay beside them. Tags
  such as `topic=`, `app=` and `team=` anchor relationship topics.
- **Classification tags.** Besides words in bucket names and tags (`email`, `ssn`,
  `patient`, ...), explicit classification tags are labels: keys `data-class`,
  `data_classification`, `classification`, `sensitivity` or `dataclass` (case and
  separators ignored) with values `PII`, `PHI`, `PCI` or `Credentials` (case-insensitive;
  several may be separated by commas, spaces, `;`, `/`, `|` or `+`) add that label, and
  `confidential`/`restricted` raise the bucket's sensitivity. So `data-class=PII` labels
  the bucket `PII` (sensitivity `confidential`), with `classification_basis`
  `classification_tag`. Other values (`public`, `internal`) never lower sensitivity.
- **Last-used hints.** `RoleLastUsed` (`LastUsedDate`, `Region`) from
  `GetAccountAuthorizationDetails` becomes `role_last_used`/`role_last_used_region`
  role metadata. With `ZG_AWS_ACCESS_ADVISOR=true`, the collector also starts one
  IAM Access Advisor job per role and user (at most `max_access_advisor_jobs`, sorted
  by ARN), polls each at most 10 times (1 s apart, inside the request and wall-time
  budgets) and keeps service namespaces with their last-authenticated time as
  `access_advisor` metadata. Both are **hints only**: they never prove non-use and are
  never sufficient on their own to remove access. Access Advisor denials or slow
  jobs are warnings, not failures.
- **Policy documents.** Every decoded document (role inline, attached managed,
  permissions boundary and trust; user inline and managed; group inline and managed,
  attached to each member as `group-inline`/`group-managed` named `group/policy`) is
  submitted as a `PolicyAttachment` beside the graph. Publication stores each
  distinct document once per revision in PostgreSQL (`revision_policy_documents`,
  keyed by the SHA-256 of its canonical JSON) and every attachment in
  `revision_policies`; node JSON never carries documents. Bounds: 64 KiB (canonical
  compact JSON) and 256 statements per customer-authored document (inline,
  customer-managed, trust, bucket policy, SCP; AWS caps these far lower, and exceeding
  the bound fails the collection), 1 MiB and 2,048 statements per AWS-managed policy
  (`arn:<partition>:iam::aws:policy/...`, see below), `max_policy_attachments` per
  collection, 50,000 attachments per snapshot and 64 MiB of distinct documents per
  revision (a larger revision fails publication). `GET /api/v1/graph/policies?principal=ARN`
  (analyst) returns one principal's documents.
- **Large AWS-managed policies.** Some AWS-managed policies exceed 64 KiB:
  `AWSSupportServiceRolePolicy`, attached to `AWSServiceRoleForSupport` in essentially
  every account, is about 152 KB of compact JSON. They are collected and evaluated
  like any other document up to 1 MiB and 2,048 statements. An AWS-managed document
  beyond either bound does **not** abort the collection: its attachment is kept with
  the policy ARN and the SHA-256 (and size) of its canonical JSON in place of the
  document (`{"ZeroGraphUnevaluated": {"status": "too_large/unevaluated", ...}}`, no
  `Statement`), warning code `policy_unevaluated` is raised, artifact coverage counts
  `unevaluated_policy_documents`, and the principal gets `policies_unevaluated`
  metadata (the ARNs, at most 20). The access that policy grants or denies is unknown:
  none of its statements is applied (no edge is derived from it; the principal's
  other conditional edges carry evidence that a policy was not evaluated), an
  unevaluated permissions boundary allows nothing that can be claimed (no edges for
  that principal), and every optimizer proposal for that principal is forced to
  `manual` with never-auto reason `unevaluated_policy`. Customer-authored documents
  never get the larger bound, and a snapshot upload may use it only for a
  `managed`/`boundary`/`group-managed` attachment whose ARN is AWS-managed.
- **Users and groups.** Users get the union of their own and their groups'
  policies (permission boundaries and SCPs apply as for roles) and are evaluated for
  the same S3 actions and `sts:AssumeRole` into every role. A user in a group missing
  from the inventory, or a user/group ARN outside the verified account and
  partition, fails the collection.
Every generated AWS permission edge remains **conditional**. A successful
inventory is not complete effective-permission or production qualification.

## Data lake (Glue, Lake Formation, Athena)

With `ZG_AWS_DATA_LAKE` (default `true`; the CLI follows it unless `--data-lake` or
`--no-data-lake` is given) the collector also reads, in the session's region and
only after the IAM and S3 inventory:

- **Glue Data Catalog.** `GetDatabases` and `GetTables` (`CatalogId` = the verified
  account, 100 per page) for the account's own catalog; resource links to other
  catalogs are skipped and counted. Databases become `Database` nodes and tables
  `DataTable` nodes keyed by their ARNs (`arn:<partition>:glue:<region>:<account>:database/<db>`
  and `.../table/<db>/<table>`, the IDs CloudTrail Glue events resolve to, so
  uploaded usage, the excess-privilege index and proposals apply to them). A
  table's (or database's) S3 location becomes `location`, plus `location_bucket`
  (the bucket asset's ID) when the bucket is inventoried. Column, partition-key
  and table names, column comments, table parameters and database tags
  (`GetTags`) go through the same classifier as buckets, so a column named
  `email` labels the table `PII`; topic and classification keys (`topic=`,
  `app=`, `team=`, `owner=`, `env=`, `data-class=`...) become node tags (the
  Glue format parameter `classification=parquet` is kept as `format`, never a
  label). **Topic anchors:** a table without its own anchor inherits its
  database's, else its S3 location bucket's, as metadata (`topic_inherited_from`),
  so Glue tables join the topic of their database and data (for example
  `data-lake`). `GetResourcePolicy` reads the catalog resource policy (absent is
  `EntityNotFoundException`).
- **IAM grants** evaluated per principal (roles and users, with boundaries and
  SCPs, the catalog resource policy as the resource policy) for a bounded action
  set: tables `glue:GetTable`, `glue:GetTables`, `glue:GetPartitions` (read) and
  `glue:UpdateTable`, `glue:DeleteTable`, `glue:BatchCreatePartition` (write),
  each required on the catalog, database and table ARNs; databases
  `glue:GetDatabase` (read) and `glue:CreateTable` (write) on the catalog and
  database ARNs; Athena workgroups `athena:StartQueryExecution` (read). Unlike S3
  (where ACLs keep absence unresolved), an absent Glue/Athena grant is a denial:
  no edge. Evaluations are cached per principal and short-circuit on the catalog.
- **Lake Formation.** `GetDataLakeSettings` (administrators become
  `lakeformation_admin` metadata on their role/user; whether new tables default to
  `IAM_ALLOWED_PRINCIPALS`) and every `ListPermissions` entry (1,000 per page).
  `SELECT`/`DESCRIBE` are reads, `INSERT`/`ALTER`/`DELETE`/`DROP` writes, `ALL`
  both (databases: `DESCRIBE` read, `CREATE_TABLE`/`ALTER`/`DROP` write); table,
  all-tables (`TableWildcard`), column-scoped and data-filter grants apply to
  tables. Edge actions name them (`lakeformation:SELECT`) and evidence starts
  `lakeformation:`. A table whose permissions include `IAM_ALLOWED_PRINCIPALS`
  is in IAM-only or hybrid mode and its IAM edges stand (`lakeformation_mode:
  iam_allowed_principals`). A table without one, with the listing complete, is
  governed by Lake Formation (`lakeformation`): a principal gets an edge only
  with a Lake Formation grant. With the listing denied or truncated the mode is
  `unknown` and IAM edges stand (over-stated, never under-stated). Proposals to
  remove a grant that a Lake Formation permission contributes to are always
  `manual` (never-auto reason `lakeformation`: revoke it in Lake Formation, not
  IAM). Catalog and data-location grants and principals outside the inventory
  (other accounts, SAML, Identity Center) are counted and warned about, not
  resolved.
- **LF-Tag grants (LF-TBAC).** Only when `ListPermissions` returns a tag-expression
  grant (`LFTagPolicy` resource), the collector reads the catalog's LF-Tags
  (`ListLFTags`, 1,000 per page), their assignments with one
  `SearchDatabasesByLFTags` and one `SearchTablesByLFTags` per tag key (up to 50
  values per search, 100 results per page; requests scale with tags, not tables),
  and saved expressions (`ListLFTagExpressions`) when a grant names one
  (`ExpressionName`). An expression is an AND across keys and an OR within a key's
  values (`*` matches any value). A table's tags in force are its database's,
  overridden per key by the table's own; a column's are the table's, overridden by
  the column's. `TABLE` expressions resolve to every inventoried table they match
  and `DATABASE` expressions to every matching database. When only some columns
  match (a column overrides a key, either way) the grant is `lf-tag column-scoped`
  partial access. The result is the same `CAN_READ`/`CAN_WRITE` edges as named
  grants (`lakeformation:SELECT`...), with evidence
  `lakeformation: lf-tag domain=sales AND tier=(gold OR silver)` (a saved expression
  is prefixed with its name); `IAM_ALLOWED_PRINCIPALS` granted by tag puts the
  matched tables in hybrid mode, as a named grant does. Tables and databases get
  `lf_tags` metadata (`key=value`, tags in force) and `lf_tagged_columns`. Grants on
  the tags themselves (`LFTag`, `LFTagExpression` resources: `ASSOCIATE`,
  `DESCRIBE`) administer tags, not data, and are only counted. If any
  tag-expression grant cannot be resolved for want of tag data (denied or
  truncated tags, assignments or saved expressions, or the expression bound), Lake
  Formation mode is `unknown` for every table and IAM edges stand (warning
  `lakeformation_lf_tag_unresolved`): over-stated, never under-stated. Malformed or
  empty expressions match nothing and are counted as unresolved. Tables tagged only
  at column level are found only if Lake Formation's table search returns them;
  live qualification must confirm that.
- **Partial grants.** Column grants (`TableWithColumns`), data cells filter grants
  (`DataCellsFilter`) and column LF-Tag grants give part of a table: their edges
  say `lakeformation: partial access only ... not the whole table`, filter grants
  name the filter (`lakeformation: data cells filter eu_rows (rows or cells
  filtered)`) and the table counts them in `lakeformation_data_filter_grants`. A
  whole-table grant beside them makes the edge whole. Row filter expressions are
  not read. Proposals touching them are `manual` (Lake Formation grants).
- **Cross-account catalogs.** A grant whose resource is in another account's
  catalog (`CatalogId`, or a filter's `TableCatalogId`, is another 12-digit
  account; for example a database shared through RAM) becomes a Lake
  Formation-only edge to an `external` node: a `Database` or `DataTable` with
  `account_id` the owning account and metadata `external: true`,
  `lakeformation_mode: external`; its evidence says the owner changes it there.
  IAM is not evaluated against the other catalog. Proposals touching those edges
  are `manual` (never-auto reason `lakeformation`); nothing proposes changing the
  other account's resources. External nodes share the `max_glue_tables` bound
  (warning `lakeformation_external_truncated`).
- **Athena workgroups.** `ListWorkGroups` (50 per page) and `GetWorkGroup` become
  `QueryWorkgroup` nodes (not data assets) with state, engine version, whether
  the configuration is enforced and the result location (`output_bucket` when
  inventoried). Queries, query history and results are never read.

Glue and Lake Formation only list what the collector may see: in a Lake
Formation-governed catalog, `GetTables` and `ListPermissions` return only
resources the caller holds permissions on, and the LF-Tag listing and searches
return only tags the caller may describe. Make the collector role a Lake
Formation **read-only administrator** (`ReadOnlyAdmins` in the data lake
settings) so the inventory is complete; that grants no data access. The
LF-Tag searches also check Glue read access to the tables they return, which the
`glue:GetDatabases`/`glue:GetTables` grants already give; a live qualification
must confirm that no other action is required.

Bounds (per collection; beyond them the data lake part is **truncated with a
warning**, never the whole collection): `max_glue_databases` 100 (hard 1,000),
`max_glue_tables` 2,000 (10,000), `max_lakeformation_permissions` 10,000
(50,000), `max_athena_workgroups` 50 (500), `max_lf_tags` 1,000 tag keys (5,000),
`max_lf_tag_assignments` 10,000 tagged databases and tables (50,000) and
`max_lf_tag_expressions` 1,000 saved and distinct resolved expressions (5,000);
beyond the LF-Tag bounds the warnings are `lakeformation_lf_tags_truncated`,
`lakeformation_lf_tag_assignments_truncated` and
`lakeformation_lf_tag_expressions_truncated`, and modes become `unknown`. The data lake phase runs last and
shares the request, page, evaluation and edge budgets; if one runs out there it
stops with warning `data_lake_budget` or `data_lake_edges_truncated` and keeps
everything collected before. Every denial or service error is a warning with
coverage `unknown` (`glue_catalog_unknown`, `glue_tables_unknown`,
`glue_tags_unknown`, `glue_resource_policy_unknown`, `lakeformation_settings_unknown`,
`lakeformation_permissions_unknown`, `lakeformation_lf_tags_unknown`,
`lakeformation_lf_tag_assignments_unknown`, `lakeformation_lf_tag_expressions_unknown`,
`athena_workgroups_unknown`); malformed pages and repeated continuation tokens still
fail closed. The artifact adds `coverage.data_lake` (inventory status, modes per
table, unresolved grants; LF-Tag stages `lakeformation_lf_tags`,
`lakeformation_lf_tag_assignments`, `lakeformation_lf_tag_expressions` as
`not_needed`/`complete`/`truncated`/`unknown`; `lakeformation_lf_tag_grants`
resolved/unresolved/matched resources; data filter, external and tag
administration grant counts) and counts `glue_databases`, `glue_tables`,
`athena_workgroups`, `lakeformation_permissions`, `lakeformation_lf_tags` and
`lakeformation_lf_tag_assignments`, never names.

Tests use synthetic credentials with botocore Stubber and mocks; live authentication,
permissions, regional behavior and account-scale timing remain qualification gates.
A read-only live check (2026-10-09, replayed offline) found the 64 KiB cap aborting on
`AWSSupportServiceRolePolicy`, `aws login` profiles failing without `botocore[crt]`, the CLI never
enabling Access Advisor, the in-app path skipping the STS target check, and explicit
classification tags such as `data-class=PII` being ignored; those are fixed as
described here.

## Provision a sandbox read role

`deploy/aws/collector-role-policy.example.json` is a narrow example for sandbox
account `123456789012`, organization management account `111122223333`, organization
`o-example` and bucket prefix `zerograph-qualification-`. Replace those values,
partition and resource ARNs before use. These are illustrative, not deployable
organization identifiers. Prefer explicit policy ARNs and bucket ARNs to widening
wildcards. The account-wide inventory actions cannot be scoped to individual
roles or buckets; metadata access can be restricted to approved sandbox buckets.
Other owned buckets still appear in inventory, with their denied metadata marked
unknown. Do not interpret that as full sandbox metadata coverage.

SDK calls match the supplied permissions:

| SDK operation | IAM action | Example resource scope |
| --- | --- | --- |
| GetAccountAuthorizationDetails (Filter=Role, User, Group) | iam:GetAccountAuthorizationDetails | `*`, operation has no per-entity resource scope |
| GetPolicy / GetPolicyVersion | iam:GetPolicy / iam:GetPolicyVersion | account/AWS managed policy ARNs |
| ListBuckets (MaxBuckets=100) | s3:ListAllMyBuckets | `*` |
| GetBucketPolicy / GetBucketTagging | s3:GetBucketPolicy / s3:GetBucketTagging | approved bucket ARNs, owning-account condition |
| GetBucketEncryption | s3:GetEncryptionConfiguration | approved bucket ARNs, owning-account condition |
| DescribeOrganization | organizations:DescribeOrganization | `*` |
| ListParents | organizations:ListParents | explicit account and ancestor OU resources |
| ListPoliciesForTarget | organizations:ListPoliciesForTarget | account/OU/root resources, SERVICE_CONTROL_POLICY condition |
| DescribePolicy | organizations:DescribePolicy | organization/AWS-managed SCP ARNs, SCP condition |
| GenerateServiceLastAccessedDetails (optional, ACTION_LEVEL) | iam:GenerateServiceLastAccessedDetails | role and user ARNs of the account |
| GetServiceLastAccessedDetails (optional) | iam:GetServiceLastAccessedDetails | `*` |
| GetCallerIdentity | no Allow required | permissionless identity verification |
| GetResourcePolicy (optional, data lake) | glue:GetResourcePolicy | catalog ARN |
| GetDatabases / GetTables (optional) | glue:GetDatabases / glue:GetTables | catalog, `database/*`, `table/*/*` ARNs |
| GetTags (optional) | glue:GetTags | database ARNs |
| GetDataLakeSettings / ListPermissions (optional) | lakeformation:GetDataLakeSettings / lakeformation:ListPermissions | `*` |
| ListLFTags / ListLFTagExpressions (optional, only with LF-Tag grants) | lakeformation:ListLFTags / lakeformation:ListLFTagExpressions | `*` |
| SearchDatabasesByLFTags / SearchTablesByLFTags (optional, only with LF-Tag grants) | lakeformation:SearchDatabasesByLFTags / lakeformation:SearchTablesByLFTags | `*` |
| ListWorkGroups (optional) | athena:ListWorkGroups | `*` |
| GetWorkGroup (optional) | athena:GetWorkGroup | workgroup ARNs |

The Glue actions are listed exactly, never `glue:Get*`: that wildcard also grants
`glue:GetConnection(s)`, which can return connection passwords.

Organizations hierarchy APIs generally require management/delegated authority;
a member-account read role alone may not have it. Optional Organizations denials
are explicit unknown coverage. SCPs do not restrict management-account principals
or service-linked roles; the collector honors those exemptions. No RCP, ACL,
endpoint or session-policy inventory is claimed.

The separate trust example restricts AssumeRole to one operator principal with
an external-ID condition. The bootstrap policy grants only AssumeRole on the
single collector role. Adapt both to your approved trust boundary; adding these
examples does not provision anything. Never attach broad ReadOnlyAccess merely
to avoid investigating a denied operation.

## Run only with explicit sandbox approval

Use an approved named AWS profile and region. The CLI requires repeated account
and role confirmations plus a read-only sandbox acknowledgment; it will not start
credential discovery or network calls when confirmations are missing/mismatched.
It reserves a new artifact file with mode 0600 and refuses existing paths before
credential discovery. The CLI assumes the supplied role for 900 seconds, then
verifies the returned STS account, ARN partition and assumed-role name **before**
any IAM/S3/Organizations inventory. It never publishes to ZeroGraph databases.
Access Advisor follows the in-app setting: `ZG_AWS_ACCESS_ADVISOR` (default false,
read directly so the CLI needs no other server settings) unless `--access-advisor` or
`--no-access-advisor` is given; a malformed value is a usage error before any
credential discovery.

Profiles that sign in with `aws login` need the AWS Common Runtime: the backend
dependencies pin `awscrt` (`boto3[crt]`), so the CLI works with them from a normal
`pip install -r requirements.lock`.

```sh
# Set external ID securely in the process environment; do not put it in arguments.
python -m app.collectors.aws_collector \
  --profile APPROVED_SANDBOX_PROFILE --region us-east-1 \
  --account 123456789012 \
  --role-arn arn:aws:iam::123456789012:role/ZeroGraphReadOnlyCollector \
  --confirm-account 123456789012 \
  --confirm-role arn:aws:iam::123456789012:role/ZeroGraphReadOnlyCollector \
  --ack-readonly-sandbox --external-id-env ZG_QUALIFICATION_EXTERNAL_ID \
  --access-advisor \
  --artifact /approved/private/path/aws-qualification.json
```

Do not run this example against existing credentials without sandbox authorization.
No live invocation was performed as part of these changes. Named profiles can
still depend on configured SSO or credential-process providers; review that profile
before invoking the CLI. There is no implicit default-profile discovery path.

Artifact schema v1 includes hashed target account/role identifiers, region,
aggregate role/user/group/bucket/edge/evaluation/policy-attachment counts, RoleLastUsed
observed/absent counts, Access Advisor requested/completed counts (when Access Advisor
is enabled), unevaluated AWS-managed document counts, inventory-completeness flags,
SCP coverage status, bucket metadata observed/absent/unknown counts, warning-code
counts, budgets, SDK invocation/page counts and duration. It includes no resource
names, raw policy JSON, credentials, external IDs or exception strings. Correlate
its hashes with the approved target in your private change record. Failure returns
nonzero and writes status `failed`; inventory completion with metadata gaps is
labelled explicitly. `effective_permissions_complete` and object-encryption
verification remain false for every outcome.

## Bounded inventory and uncertainty

| Budget | Default | Hard maximum |
| --- | ---: | ---: |
| Unique roles / users / groups / buckets | 500 each | 1000 each |
| Policy attachments | 10000 | 50000 |
| Access Advisor jobs (optional) | 200 | 1000 |
| Aggregate pages | 100 | 1000 |
| SDK invocations | 3000 | 10000 |
| Decoded policy documents | 1000 | 5000 |
| Permission evaluations | 100000 | 1000000 |
| Graph edges | 15000 | 15000 |
| Organizations ancestor depth | 10 | 20 |
| Glue databases / tables (truncates) | 100 / 2000 | 1000 / 10000 |
| Lake Formation permissions (truncates) | 10000 | 50000 |
| Athena workgroups (truncates) | 50 | 500 |
| Collection wall time | 600 seconds | 600 seconds |

Each customer-authored policy document is additionally bounded to 64 KiB and 256
statements (AWS-managed: 1 MiB and 2,048, degrading to unevaluated beyond); each role
has at most 100 unique attached policy references. Duplicate inventory rows and
policy IDs are reconciled before consuming unique-resource budgets. Conflicting
role/bucket duplicates, repeated continuation tokens, malformed/truncated pages,
ancestor cycles and exhausted budgets fail the whole collection instead of
publishing a partial snapshot. Required IAM policy fetch failures also abort.

The evaluation preflight is `principals × buckets × 6 + principals × roles − roles`,
where principals are roles plus users. The default 500-role and 500-bucket bounds
are **individual ceilings**, not simultaneous capacity: 500 of each exceeds 100,000
evaluations and fails before enrichment. A 100-role/100-bucket inventory without
users needs 69,900 evaluations. Operators may construct
`CollectionLimits` within hard caps for an approved larger sandbox; no unbounded
CLI override is exposed. Account inventory is not an AWS transaction and may
change during scanning; conflicting duplicates are rejected rather than guessed.

`sdk_requests` counts collector SDK invocations, excluding the single bootstrap
AssumeRole call and credential-provider activity; it is not a wire-request count.
SDK standard retries are configured for at most 3 total attempts per operation.
Internal regional discovery/redirect requests are not measured by this counter.
Connection/read timeouts are 5/10 seconds. Wall budget
is checked before and after calls and during evaluation; one bounded in-flight
SDK invocation can finish after the deadline, but no snapshot is published then.

Bucket nodes distinguish observed/absent/unknown policy and tags, and have
`encryption_verified` plus `encryption_configuration` metadata. Observing a valid
default-encryption configuration does not prove existing objects are encrypted.
The existing graph boolean `encrypted=True` is retained for unknown S3 data to
avoid fabricating an unencrypted finding; it is **not** verification—consume the
metadata flag. Metadata reads use ExpectedBucketOwner, and listed BucketRegion
selects the regional client when provided.

Missing grants in known role trust policies no longer manufacture AssumeRole
paths. Supported trust/identity policies determine possible assumptions; missing
policy domains can still restrict them, so emitted edges stay conditional. S3
absence-of-grant remains uncertain because ACL/session/resource context is missing.

## Sources and remaining gates

The `Tags`, `RoleLastUsed`, `UserDetailList` and `GroupDetailList` response shapes are
checked against the installed botocore service model by a Stubber test (no network);
that AWS fills them for a real account is a live-qualification gate.
Pagination and operation contracts were checked against official
[AWS ListBuckets](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html),
[GetAccountAuthorizationDetails](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html)
and [ListParents](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListParents.html).
Organizations coverage follows [SCP applicability](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html).
Identity verification follows [STS GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html).
Resource/action constraints follow [Organizations authorization](https://docs.aws.amazon.com/service-authorization/latest/reference/list_organizations.html)
and the [S3 encryption operation](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketEncryption.html).

Before a target rollout: provision/review the sandbox role independently, exercise
real role assumption and optional denials, verify metadata in each relevant
region, compare approved inventory counts, and measure budgets at expected scale.
Preserve the sanitized artifact with release commit and target-environment evidence.
No mocked result substitutes for this live gate, and incomplete policy domains
must remain visible to risk/remediation reviewers.
