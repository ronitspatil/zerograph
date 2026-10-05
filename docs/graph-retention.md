# Immutable graph revision retention

ZeroGraph publishes immutable graph revisions and advances a PostgreSQL tenant
pointer only after graph publication succeeds. Repeated ingestions therefore
retain historical data; a graph commit followed by SQL failure can also leave an
unreferenced revision. Retention is explicit maintenance, never automatic.

## Review a bounded plan

Run from the backend environment with the target's database/graph configuration:

```sh
python -m app.graph.retention --tenant TENANT_ID \
  --older-than-days 30 --keep-revisions 5 --batch-size 10
```

This defaults to dry run: it emits JSON containing the protected SQL pointer,
cutoff and candidate graph revisions. It changes no graph or SQL data. Requiring
an explicit tenant prevents broad multi-tenant deletion. Review the target
configuration, backup integrity and plan before applying it.

```sh
python -m app.graph.retention --tenant TENANT_ID \
  --older-than-days 30 --keep-revisions 5 --batch-size 10 \
  --actor operator:YOUR_CHANGE_ID --apply
```

Each deleted revision's stored analysis rows (`revision_analysis`, `revision_findings`) are removed in the same locked SQL transaction that records the deletion; see [revision-analysis.md](revision-analysis.md). The apply invocation computes a fresh plan under the tenant publication lock; a
previous dry-run result is advisory, not an authorization token or frozen plan.
Deletion requires PostgreSQL. Keep count must be 2–1000, age 1–3650 days and batch
size 1–50. Both age and keep bounds apply; the current SQL pointer is protected
even when older than all retained history. A batch may be empty. Repeat bounded
runs to work through a backlog, reviewing outputs between runs.

New `Snapshot.created_at_ms` metadata records first publication time in Unix
epoch milliseconds. The graph schema migration adds an age index. Re-publishing
a revision does not reset its age. Historical snapshots lacking a timestamp are
retained indefinitely: no guessed migration timestamp or destructive automatic
backfill is used. Preserve this field (including missing legacy values) in
backup/restore archives. Legacy cleanup requires separately verified age evidence.

## Concurrency and failure behavior

Maintenance holds the same PostgreSQL `TenantState` row lock that ingestion holds
before publishing or advancing its pointer. A publishing ingestion and cleanup
cannot operate on a tenant simultaneously. Maintenance refuses a tenant without
an authoritative SQL row. Lock acquisition has a five-second timeout; rerun
later if an active publisher owns the lock. The lock is held across the bounded
batch, so ingestion of that tenant waits while deletion runs.

Each revision deletion is a graph transaction scoped by tenant and revision,
rechecking its exact creation timestamp and cutoff. It removes at most the normal
5000-node snapshot bound plus relationships and metadata. An unexpected larger
revision fails closed. Driver query timeouts still apply. A failed per-revision
graph transaction rolls back that revision's Entity and Snapshot deletion.

Deletion is irreversible without a verified backup. Graph and SQL operations are
not a distributed transaction: if a later deletion or SQL audit commit fails,
earlier graph deletions may already be committed. Before each graph deletion, a
separate SQL transaction durably commits `graph.revision_delete_requested` with a
unique `operation_id`, revision, cutoff and protected pointer. If that intent
commit fails, no graph deletion for that revision occurs. The tenant publication
lock remains held by the outer SQL transaction. Completion or skip events use
the same operation ID; final SQL completion failure leaves the committed intent
available for operator reconciliation.

For an intent without `graph.revision_deleted` or `graph.revision_delete_skipped`,
inspect the target graph under the tenant publication lock: absent metadata means
deletion may have committed; present matching metadata means it remains eligible
for a fresh bounded plan. Preserve the intent and failure record, investigate the
SQL/graph outage and record the reconciliation in your change system. Do not
infer deletion outcome solely from a missing completion event or blindly edit
tenant pointers. Repeating retention is idempotent and creates a new intent for
any still-present candidate.

Do not run retention during backup/restore or while external tools write graph
revisions or SQL tenant pointers outside the application's lock protocol. API graph readers pin the current SQL pointer using a shared tenant row lock
held by the existing request database session through snapshot and shortest-path
materialization. Publication and cleanup take an exclusive lock, so they wait
for existing readers and new readers wait up to five seconds for cleanup or
publication. A PostgreSQL lock acquisition timeout returns a sanitized HTTP503
with `Retry-After: 5`; other database errors use the existing error handler.
No read-drained window is
required for the current API read paths. Locks end with request transaction
completion/session closure; no long-lived reader registry is added. A future
historical-snapshot or external reader must use an equivalent pinning policy.
Clock synchronization is required because age cutoffs and timestamps use UTC
application clocks. Retention does not delete SQL source snapshots, ingestion
jobs, remediations or audit history.

## Evidence and rollout gates

Tests cover dry-run defaults, tenant boundaries, age/keep/batch limits, legacy
retention, exact timestamp rechecks and PostgreSQL publication-lock exclusion.
The graph integration suite exercises retention queries and transaction rollback
against both Memgraph and Neo4j. These tests operate only on synthetic random test
tenants; no existing application data is deleted.

Before enabling scheduled maintenance in a target environment, verify backup
restore, publication exclusion, permissions, expected candidate volumes and
acceptable lock duration at that environment's scale. No automatic scheduler or
existing-environment deletion is enabled by this change.
