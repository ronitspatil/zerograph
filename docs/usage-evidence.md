# Usage evidence (observed access)

ZeroGraph separates what an identity is **granted** (the collected graph) from what it
was **observed using**. Usage evidence comes first from customer-uploaded CloudTrail
exports; direct Lake/Athena queries may follow. Observed use only stands for *needed*
access when coverage is attested and complete over a long enough, recent window;
otherwise needed access is inferred from peers and labelled "inferred".

## The store (provider-neutral)

Migration `0009` adds, per tenant:

| Table | Holds |
| --- | --- |
| `usage_uploads` | One upload: declared window, attested services, the revision it was made against, status (`open` -> `committed`) and its counts |
| `usage_upload_chunks` / `usage_staged` | Per-file counts and aggregates while the upload is open (replaced when a file is re-sent) |
| `observed_access` | (principal, resource, action class, service) with first/last seen, count, source and upload, keyed by stable entity IDs |
| `usage_coverage` | Per committed upload and service: window, attested, events, unmapped, complete |

Action classes are `read`, `write`, `admin` (permission or configuration changes) and
`assume` (role assumption; the resource is the role). Usage applies to the revision it
was uploaded against and **carries forward** to later revisions by stable principal and
resource IDs (ARNs for AWS); entities absent from a revision are not matched there.
Usage rows are not tied to graph revisions, so retention does not delete them; delete
an upload with `DELETE /api/v1/usage/uploads/{id}`. They travel in the PostgreSQL dump
and are counted in the backup bridge metadata.

## Uploading CloudTrail exports (admin only)

1. `POST /api/v1/usage/uploads` with `window_start`, `window_end` (timezone-aware, at
   most 400 days, not in the future) and `attested_services`: the services whose events
   you attest are **completely** captured in the files for the whole window (for
   example data events enabled on every relevant bucket). Supported services: `s3`,
   `sts`, `glue`, `athena`, `lakeformation`, `rds-data`, `aoss`.
2. `PUT /api/v1/usage/uploads/{id}/files/{n}` once per export file: the `{"Records":
   [...]}` JSON CloudTrail delivers to S3, gzip or plain (a JSON array or one record per
   line also work). At most `ZG_MAX_BODY_BYTES` per request, 64 MiB decompressed and
   500,000 records per file, 10,000 files and 5,000,000 distinct observed pairs per
   upload. Re-sending a file number replaces it.
3. `POST /api/v1/usage/uploads/{id}/commit` aggregates the files into `observed_access`
   and records coverage. The response carries the counts and the tenant's evidence
   status. The worker then recomputes topics and the excess-privilege index for the
   current revision (see [privilege.md](privilege.md)); later publications use the
   evidence directly.

`GET /api/v1/usage` (viewer) returns the evidence status and the last 20 uploads. At
most `ZG_MAX_OPEN_UPLOADS` usage uploads may be open per tenant; open uploads expire
after `ZG_UPLOAD_SESSION_TTL_SECONDS`.

## Normalization

Each record is mapped by `(eventSource, eventName)` with `execution_audit.EVENTS` (an
extension of the former `ACTION_MAP`): S3 object data events and bucket-permission
events, STS `AssumeRole*`, Glue Data Catalog, Athena, Lake Formation `GetDataAccess` and
permission management, the RDS Data API (classed `write`: a statement may write, and
use is never understated) and OpenSearch Serverless `ReadDocument`/`WriteDocument`
(event names not verified against a live trail).

- **Principal**: an assumed-role session's role (`sessionContext.sessionIssuer.arn`), else
  the IAM user or root ARN. Service principals and callers without an ARN count as
  unresolved.
- **Resource**: the S3 bucket (`resources[]` or `bucketName`), the assumed role, the Glue
  table or database, the Athena workgroup, the Lake Formation table, the RDS Data API
  resource, else the first `resources[].ARN`.
- Records outside the declared window are ignored; records with an `errorCode`
  (`AccessDenied`...) are counted as denied attempts, never as use.
- **Unmapped** events are counted per service and make that service's coverage
  incomplete, as do malformed records (existing behaviour of the single-identity
  normalizer). An unattested service is never complete.

## Sufficiency

A service is **sufficient** when the contiguous union (gaps of at most one day) of its
complete coverage windows that ends latest spans at least **90 days** and ends within
**7 days** of evaluation. The tenant's evidence status is `none` (no uploads),
`attested` (at least one sufficient service) or `partial`. The evidence fingerprint
(committed uploads plus which services are sufficient) changes when an upload is
committed or deleted, or when evidence goes stale; the worker's topic sweep then
recomputes the current revision's topics and EPI (`backfill_topics`, every 60 s).

`RoleLastUsed` and IAM Access Advisor last-accessed data, collected into node metadata
by the AWS collector, are **hints only**: they are reported beside the analysis, never
sufficient on their own and never used to decide that access is unneeded.

## Planted fixture

`qualify_scale.cloudtrail_records()` writes the planted fixture's usage sidecar as
realistic CloudTrail records (assumed-role S3/RDS Data/OpenSearch data events, IAM user
`AssumeRole` calls, plus EC2 noise and AccessDenied attempts) and
`cloudtrail_files()` packs them as gzip export files, so qualification exercises the
real upload path. The synthetic node IDs stand in for ARNs.
