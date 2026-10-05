# Ingestion reliability upgrades

Migration `0002` introduces durable attempt counts, worker lease fencing, retry
availability times, dispatcher reservations and per-source snapshot ordering.

## Upgrade procedure

1. Stop the old Celery beat scheduler and workers, and drain or terminate all
   ingestion tasks. Stop old API processes that can enqueue work. Verify the old
   processes cannot resume before upgrading.
2. Back up PostgreSQL and run `python -m app.db.migrate` with the new release.
3. Start only workers, beat and API processes from the new release. Old queued
   broker messages may remain: the new worker's atomic SQL claim makes duplicate
   deliveries harmless. Jobs left `running` without a lease are recovered by beat.
4. Check ingestion job status and audit events after a test ingestion. Investigate
   terminal failures before submitting a new job; the automatic budget is four
   total attempts, including workers killed while holding a lease.

A mixed-version worker rollout is unsafe: old workers do not understand fencing
and could publish after a new worker recovers their job. Drain them first. Rollback
also requires draining new workers; do not run pre-fencing code against the new
job lifecycle without an explicit compatibility plan.

## Runtime contract

Workers claim jobs with a conditional SQL update and a 21-minute lease, exceeding
the 15-minute hard task limit and 20-minute Redis visibility timeout. Duplicate
messages cannot consume attempts while another worker owns the job. No heartbeat
is needed while these task limits remain in effect. Update lease and timeout
values together if ingestion is allowed to run longer.

Retry delays (10, 20 and 40 seconds) and attempt counts live in PostgreSQL. Beat
redispatches due jobs every 30 seconds. Each dispatcher sweep reserves at most
100 jobs for 60 seconds. A crash after reserving or an ambiguous broker response
may duplicate delivery after the reservation expires; the SQL claim deduplicates
execution. A failed broker send does not revoke a worker that already claimed it.

Publication checks the current lease token and holds the job row lock and the
tenant's advisory publication lock through graph publication and SQL commit; the
tenant row is locked only for the final pointer swap (see migration `0004` below). Older same-source submissions cannot
overwrite newer successfully published snapshots. Such jobs complete with an
`ingestion.superseded` audit event instead of a new graph revision.

Graph and SQL commits are not distributed transactions. Graph revisions are
immutable; a successful graph write followed by SQL failure may leave an orphan
revision. The tenant's SQL pointer stays on its previous revision and retry
publishes a new one. Retention and orphan cleanup remain a separate operational
requirement. PostgreSQL backups alone do not restore graph data.

The concurrency tests use `ZG_INGESTION_POSTGRES_URL` pointing to a dedicated test
database. Each test creates and removes only its own randomly named schema. They
verify real SQL locks and conditional updates with an in-memory graph adapter;
they do not claim real graph/SQL fault-injection or live-cloud validation.

## Revision analysis (migration `0003`)

Migration `0003` adds `revision_analysis` and `revision_findings`, written by the
publish job in the pointer-swap transaction. It creates tables only and needs no
graph access. Drain old workers as above before starting new ones: an old worker
would publish revisions without stored analysis, which stay correct (computed on
read) but slow. Revisions published before the upgrade are computed on read until
republished or backfilled with `python -m app.graph.analysis --tenant TENANT_ID`;
see [revision-analysis.md](revision-analysis.md).

## Chunked ingestion and short-lock publication (migration `0004`)

Migration `0004` adds `upload_sessions` and `staged_entities`. Every source's
latest snapshot is now an *entity set* of validated rows (`staged_entities`) and
`source_snapshots.payload` holds `{"entity_set": <id>}` instead of the whole
snapshot document. Existing documents are not rewritten by the migration: the next
publication of the tenant stages each legacy document as rows under the
publication lock, so the upgrade itself needs no graph access and stays fast.

Large snapshots use upload sessions: `POST /api/v1/ingestions/uploads` (admin)
returns a session; `PUT /api/v1/ingestions/uploads/{id}/chunks/{n}` stages one
NDJSON chunk (at most the 4 MB body limit; lines `{"node": …}`, `{"edge": …}` or
`{"warning": "…"}`), validating each line with the same models as the single-body
endpoint and refusing duplicates within the chunk or across chunks; resending a
chunk number replaces it. `POST …/commit` checks edge endpoints in SQL and queues
the ingestion job (`payload = {"upload_session": id}`). Sessions expire after
`ZG_UPLOAD_SESSION_TTL_SECONDS` (default 24 h) and at most `ZG_MAX_OPEN_UPLOADS`
(default 4) may be open per tenant; expired sessions are purged when the next one
starts. `POST /api/v1/ingestions` keeps working for small snapshots.

Caps come from `ZG_MAX_NODES` / `ZG_MAX_EDGES` (defaults 100,000 / 500,000) and are
enforced on each upload, on single-body snapshots, and on the merged submitted
entities of all sources before any graph write. Classification annotations are
derived on top (at most one category node per rule and one annotation edge per
tagged data asset and rule). The Pydantic list caps no longer exist.

The worker merges all active sets in SQL (conflicting definitions of one node or
edge ID across sources fail the attempt; identical ones collapse), then writes a
new, invisible revision in bounded transactions (`ZG_GRAPH_BATCH_SIZE`, default
5,000 rows; edges are matched through the unique entity key). Its `Snapshot` node
is written first with `state='building'` and set to `ready` last. Publication
analysis is computed from a compact in-worker representation streamed from the
staged rows (no whole-graph Pydantic snapshot). Publishers serialize per tenant on
`pg_advisory_xact_lock`; `TenantState` is locked `FOR UPDATE` only for the pointer
swap and the commit of the analysis rows, so dashboard readers are not blocked
while a revision builds. An abandoned build stays `building` and is removed by
retention once stale ([graph-retention.md](graph-retention.md)).

Run the Cypher schema migration (`python -m app.db.migrate`) to add the
`(tenant_id, revision, id)` entity index (`003_entity_scope_id.cypher`, Memgraph
and Neo4j). Drain old workers before starting new ones, as for earlier migrations:
an old worker locks `TenantState` for its whole publication (safe, but blocks
readers) and would overwrite an `entity_set` pointer with a whole document. An old
retention CLI (row lock only) can run safely beside new workers: a building
revision is younger than its age cutoff (at least one day).
