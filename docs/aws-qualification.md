# Read-only AWS sandbox qualification

ZeroGraph inventories IAM roles and owned general-purpose S3 buckets. It reads
policy documents, bucket tags and default encryption configuration; it never
lists objects, reads object contents, creates AWS resources or changes policies.
Every generated AWS permission edge remains **conditional**. A successful
inventory is not complete effective-permission or production qualification.

No live sandbox credentials were supplied for this implementation. Tests use
synthetic credentials with botocore Stubber and mocks; live authentication,
permissions, regional behavior and account-scale timing remain qualification gates.

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
| GetAccountAuthorizationDetails (Filter=Role) | iam:GetAccountAuthorizationDetails | `*`, operation has no per-role resource scope |
| GetPolicy / GetPolicyVersion | iam:GetPolicy / iam:GetPolicyVersion | account/AWS managed policy ARNs |
| ListBuckets (MaxBuckets=100) | s3:ListAllMyBuckets | `*` |
| GetBucketPolicy / GetBucketTagging | s3:GetBucketPolicy / s3:GetBucketTagging | approved bucket ARNs, owning-account condition |
| GetBucketEncryption | s3:GetEncryptionConfiguration | approved bucket ARNs, owning-account condition |
| DescribeOrganization | organizations:DescribeOrganization | `*` |
| ListParents | organizations:ListParents | explicit account and ancestor OU resources |
| ListPoliciesForTarget | organizations:ListPoliciesForTarget | account/OU/root resources, SERVICE_CONTROL_POLICY condition |
| DescribePolicy | organizations:DescribePolicy | organization/AWS-managed SCP ARNs, SCP condition |
| GetCallerIdentity | no Allow required | permissionless identity verification |

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

```sh
# Set external ID securely in the process environment; do not put it in arguments.
python -m app.collectors.aws_collector \
  --profile APPROVED_SANDBOX_PROFILE --region us-east-1 \
  --account 123456789012 \
  --role-arn arn:aws:iam::123456789012:role/ZeroGraphReadOnlyCollector \
  --confirm-account 123456789012 \
  --confirm-role arn:aws:iam::123456789012:role/ZeroGraphReadOnlyCollector \
  --ack-readonly-sandbox --external-id-env ZG_QUALIFICATION_EXTERNAL_ID \
  --artifact /approved/private/path/aws-qualification.json
```

Do not run this example against existing credentials without sandbox authorization.
No live invocation was performed as part of these changes. Named profiles can
still depend on configured SSO or credential-process providers; review that profile
before invoking the CLI. There is no implicit default-profile discovery path.

Artifact schema v1 includes hashed target account/role identifiers, region,
aggregate role/bucket/edge/evaluation counts, inventory-completeness flags,
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
| Unique roles / buckets | 500 each | 1000 each |
| Aggregate pages | 100 | 1000 |
| SDK invocations | 3000 | 10000 |
| Decoded policy documents | 1000 | 5000 |
| Permission evaluations | 100000 | 1000000 |
| Graph edges | 15000 | 15000 |
| Organizations ancestor depth | 10 | 20 |
| Collection wall time | 600 seconds | 600 seconds |

Each policy document is additionally bounded to 64 KiB and 256 statements; each role
has at most 100 unique attached policy references. Duplicate inventory rows and
policy IDs are reconciled before consuming unique-resource budgets. Conflicting
role/bucket duplicates, repeated continuation tokens, malformed/truncated pages,
ancestor cycles and exhausted budgets fail the whole collection instead of
publishing a partial snapshot. Required IAM policy fetch failures also abort.

The evaluation preflight is `roles × buckets × 6 + roles × (roles − 1)`. The default
500-role and 500-bucket bounds are **individual ceilings**, not simultaneous
capacity: 500 of each exceeds 100,000 evaluations and fails before enrichment. A
100-role/100-bucket inventory needs 69,900 evaluations. Operators may construct
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
