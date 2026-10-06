# Coordinated backup and restore

The operator tool supports a dedicated local Compose PostgreSQL 16 / Memgraph 3.2.0 deployment. It creates a logical PostgreSQL custom dump plus all application graph revisions in a single archive, including tenant revision pointers, job/audit/remediation row counts, Alembic revision, application version, exact container image IDs, and SHA-256 checksums. Graph retention timestamps are preserved; missing legacy timestamps remain missing. The tool does not copy `.env`, cloud/Git credentials, PostgreSQL role passwords, or graph server authentication state.

Backups still contain sensitive identity, policy, audit and data metadata. Store archives on encrypted storage with restricted access; use an authenticated encrypted transport and an independently managed encryption key when copying them. Temporary directories are mode 0700, dump/metadata files and the published archive are mode 0600. The archive is not encrypted or signed by this tool. Checksums detect corruption, not a malicious replacement; restore only a trusted operator-generated archive. Never upload backups as public CI artifacts.

## Offline consistency boundary

Acquire an exclusive maintenance window for the entire deployment. Block new requests, disable all ingestion schedules and retention operations, drain workers, and stop frontend/API/scheduler/worker containers. Also stop external SQL/graph writers, retention CLIs, other Compose projects sharing these databases, and unattended maintenance jobs. The tool can check its named Compose containers and running ingestion rows; it cannot discover arbitrary external writers. The operator must enforce this wider exclusive boundary.

For a dedicated project named `zerograph-local`:

```sh
docker compose --project-name zerograph-local stop --timeout 900 frontend scheduler backend worker
python deploy/backup_restore.py backup --project zerograph-local --archive /secure-backups/zerograph-2026-10-01.zip
python deploy/backup_restore.py verify --archive /secure-backups/zerograph-2026-10-01.zip
```

Leave PostgreSQL and Memgraph running during the logical export. Backup refuses active application containers or running ingestion jobs; if graceful drain timed out, resolve the job/worker state before proceeding. It checks SQL metadata again after the dump and refuses detected changes. This comparison is additional evidence, not a substitute for excluding external writes. The output parent directory must already exist. Existing archive paths are never overwritten, including races during publication. No automatic application restart occurs.

After a successful backup, separately approve and perform the application restart with the matching release. On failure, leave the source unchanged and preserve its maintenance window while diagnosing the cause. The backup tool never stops, restarts or deletes source services or volumes.

## Fresh-target restore

Restore requires an empty PostgreSQL public schema and graph. It never uses `DROP`, `--clean` or overwrites an existing database. Provision fresh volumes under a new explicit Compose project, build the original backend release image and use the original database images. Restore intentionally requires exact backend and database image IDs and a matching Alembic head; upgrade only after validating recovery at the source release.

```sh
docker compose --project-name zerograph-recovery up --detach --wait --wait-timeout 240 postgres memgraph redis
python deploy/backup_restore.py restore --project zerograph-recovery --archive /secure-backups/zerograph-2026-10-01.zip
```

The archive has exactly three allowed members: `manifest.json`, `postgres.dump` and the graph. Archive format version 2 (written since Phase 2) streams the graph as `graph.ndjson`: a header line with the application metadata, then for each revision in (tenant, revision) order one `revision` line (retention timestamp, state, source, warnings, entity counts) followed by its `node` lines in ID order and `edge` lines in edge-ID order, and a closing `end` line with totals. Version 1 archives (`graph.json`, one document) are still verified, and restore rewrites them as the equivalent version 2 stream (bridge `convert-v1`) before the identical validation/import/compare path; restore remains bound to the archive's release. Extraction rejects traversal, extra/duplicate members, symlinks, encrypted ZIP entries, oversized files, incompatible format/engines, checksum failures, duplicate graph revisions, and SQL pointers without matching graph revisions. Full graph schema and source-release compatibility checks and `pg_restore --list` run before restore writes. PostgreSQL restore uses a single transaction and fails on errors. The graph is published before SQL pointers become available, and final checks compare restored SQL metadata and the complete logical graph to the archive. Writers stay stopped throughout.

If import fails, retain the failed target offline for diagnosis. Graph and SQL restore are not one distributed transaction; a failed fresh target can contain partial graph data. Provision another empty target and retry the trusted backup rather than deleting or overwriting an existing target automatically. A successful restore verifies data equality, not permission to open network access. Independently validate infrastructure, authentication and recovery behavior before resuming the application.

Redis is intentionally excluded. Its cache and broker are rebuilt; queued/retrying ingestion jobs are recovered from PostgreSQL's durable outbox, while completed jobs, audit history and remediations are preserved. Backups reject running jobs, so no active worker lease is archived. Recovery can wait for an existing dispatch reservation to expire. Existing browser sessions should be invalidated by rotating the session encryption secret during an actual incident recovery, outside this tool.

## Evidence and production mapping

The disposable CI restore drill populates a real built Compose stack, drains writers, includes a durable queued job, archives both stores, destroys only its disposable source volumes, and restores into fresh target volumes. It verifies graph/findings, completed jobs, audit/remediation history and pending-job recovery with a fresh Redis broker. Archives are deleted during unconditional cleanup, never uploaded.

Export, validation and import stream the graph: the bridge holds at most one revision's node IDs in memory (about 130–170 MB peak RSS measured for 3 × 100,000-node revisions). Before streaming, it counts every revision's entities and refuses more than 1,000 revisions or 1,000 tenant states, any revision above the publication caps (`ZG_MAX_NODES`/`ZG_MAX_EDGES` plus derived classification annotations), and unmanaged or orphaned graph data. Host-side member limits default to 50 GB for the graph stream and 20 GB for the PostgreSQL dump (`ZG_BACKUP_MAX_GRAPH_BYTES`, `ZG_BACKUP_MAX_DUMP_BYTES`); ZIP64 is used for large members. Restore verification re-exports the restored graph and compares its SHA-256 with the archived stream. Version 1 archives keep their former 100 MB in-memory bound. Archive contents are flushed and fsynced before atomic publication, then the destination directory is fsynced. Per-revision analysis, global-map cluster and topic rows are PostgreSQL tables, so the unfiltered PostgreSQL dump carries them with their revisions (the bridge metadata counts them); they can also be recomputed with `python -m app.graph.clusters --tenant TENANT_ID` and `python -m app.graph.topics --tenant TENANT_ID`. It backs up application-owned logical graph snapshots and schema migrations, not arbitrary graph extensions, procedures, indexes or authentication. Unmanaged/orphaned graph nodes and relationships cause refusal, since a logical application archive would otherwise be incomplete. Large deployments, Neo4j and managed services require their own tested recovery adapters.

For production managed PostgreSQL and graph services, configure encrypted native backups/PITR, documented retention/RPO/RTO, access controls, and periodic isolated restore drills. Align both stores to an application-consistent checkpoint with ingestion and retention quiesced, or implement a verified revision reconciliation procedure. A PostgreSQL-only restore can leave pointers referencing missing graph revisions. Do not infer recoverability from backup-job success or Helm rendering alone; record restore evidence against the release, infrastructure and recovery objectives used in staging.
