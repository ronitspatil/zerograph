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

Publication checks the current lease token and holds the job and tenant row locks
through graph publication and SQL commit. Older same-source submissions cannot
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
