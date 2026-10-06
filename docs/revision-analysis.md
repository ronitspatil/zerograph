# Publish-time revision analysis

Whole-revision analysis runs once per published revision, in the ingestion worker, instead of on every dashboard request. Before the tenant revision pointer advances, the publish job computes the overview counts, every toxic-combination finding, high-blast-radius identity flags, whole-revision totals (nodes, edges, roles, role-to-role traversal edges) and the total sensitivity-weighted asset weight. It stores them in PostgreSQL (alembic migration `0003`):

- `revision_analysis`: one row per (tenant, revision) with `analysis_version`, the overview counts as JSON, the four totals, `total_findings`, `total_asset_weight` and the sorted high-blast identity IDs.
- `revision_findings`: one row per finding with its `ordinal` in API order (critical first, then ID) and payload, keyed by (tenant, revision, ordinal), plus a unique (tenant, revision, finding_id) index for cursors.

The rows are staged in the same SQL transaction that advances the pointer, so a reader that sees a revision also sees its analysis, and a failed commit leaves neither. If analysis raises, the attempt fails before any graph write and is retried like any other publication failure. Analysis semantics are unchanged from the former request-time code (uncertain edges included, five hops, high blast radius at score 70 or more); the tests keep the former implementation as a golden reference.

## Read paths

All readers keep the existing shared pin on the tenant pointer, five-second lock timeout and 503 response while publication or retention holds the lock.

- `GET /api/v1/overview` returns the stored counts. The response shape is unchanged.
- `GET /api/v1/findings` is paged. The body is still a JSON array of findings in the same order. `limit` defaults to 200 (1–1000). `cursor` is the ID of the last finding on the previous page; an ID that is not a finding of the current revision returns 422. `revision` pins the request like the exploration endpoints (409 when the pointer moved). Response headers: `X-Graph-Revision`, `X-Total-Count` and, only when another page exists, `X-Next-Cursor`. The console proxy forwards exactly these three headers. **Behavior change:** a client that relied on one unbounded response now receives at most 200 findings unless it follows the cursor (or passes `limit` up to 1000).
- `GET /api/v1/graph/explore` and `GET /api/v1/graph/roles` take `total_nodes`, `total_edges`, `total_roles` and `total_role_edges` from the stored row instead of whole-revision count scans. The counts have the same definitions as before: all entities, all six relationship types, actual `CloudRole` nodes, and traversal relationships whose two endpoints are roles.
- Remediation preview and CloudTrail normalization check the identity with a single keyed node lookup (`GraphStore.node`), not a full snapshot load.

- `POST /api/v1/simulate` takes the revision's node count and `total_asset_weight` from the stored row and reads only the source's bounded neighborhood from the graph (see [graph-scale.md](graph-scale.md#blast-radius-simulation-phase-3)).

The deprecated whole-revision `GET /graph` is the only remaining full-snapshot read; it returns 413 above `ZG_LEGACY_GRAPH_MAX_NODES`/`ZG_LEGACY_GRAPH_MAX_EDGES` (default 5,000/20,000, from the stored totals).

## Revisions published before this change

Revisions without a stored row, or with a row from another `analysis_version`, are computed on read from the snapshot, exactly as before. This was chosen over a migration-time backfill because it needs no graph access during `alembic upgrade`, is correct by construction, and costs only what every request cost before the change; such revisions were bounded by the former 5,000-node cap and are replaced by the next publication. Operators who want the fast path immediately can backfill a tenant's current revision under the publication lock:

```sh
python -m app.graph.analysis --tenant TENANT_ID
```

It is idempotent and prints JSON stating whether it stored anything. Bump `ANALYSIS_VERSION` in `app/graph/analysis.py` whenever overview, finding or totals logic changes; older rows are then ignored until republished or backfilled.

### Explore samples (`sample_version`, migration `0006`)

The initial explore sample (`sample_ids`, see `app/graph/sample.py`) is stamped with `SAMPLE_VERSION`. A current revision whose analysis row is current but whose sample is older (stored before migration `0006`, when samples were the first IDs in ascending order, or before a `SAMPLE_VERSION` bump) is refreshed by the worker, not the API: Celery beat runs `backfill_samples` every 60 s, which finds such tenants with one SQL query and refreshes at most 3 per run. It uses the same sweep as the global-map cluster backfill (`app/graph/sweep.py`, see [global-map.md](global-map.md)): each tenant in its own transaction under its publication lock taken with `pg_try_advisory_xact_lock`, so a tenant that is publishing is skipped (its publication stores a current sample anyway); the revision is pinned by the lock and a shared row lock on the pointer; a tenant whose refresh fails is logged and not retried by that worker process for an hour.

Only the sample is recomputed. The worker reads the revision's topology from the graph store (node IDs, type labels and relationship endpoints; no payloads, no snapshot) and the stored finding paths and high-blast-radius IDs, which is exactly the input of the publish-time selection, so the result equals what a republication would store. If the graph revision's node or relationship count differs from the stored totals the refresh fails rather than storing a wrong sample. The row is updated in place: `/graph/explore` keeps serving the older sample (bounded and valid, just less representative) until the refresh commits, with no empty or 404 window. A sample stamped with a newer version (written by a newer release during a rolling deploy) is left alone.

Revisions with no current analysis row are not refreshed by the sweep, since recomputing their overview and findings needs a full snapshot; they are computed on read and get a sample at their next publication or from the command above, which also refreshes only the sample when the rest of the row is current.

## Retention

Applied retention deletes a revision's `revision_analysis` and `revision_findings` rows in the transaction that holds the tenant publication lock and records `graph.revision_deleted`. If that final SQL commit fails after the graph deletion, the rows remain but are unreachable (no pointer can name a deleted revision) and inert.

## Cost and capacity

Analysis runs while the publish job builds the revision, before the short pointer swap; since Phase 2 (see [ingestion-upgrades.md](ingestion-upgrades.md)) readers are not blocked during it. The worker computes it from a compact representation of the staged rows (`app/graph/compact.py`), asserted equal to `compute_analysis` on generated and edge-case graphs. Every breadth-first search of the analysis reads one traversal adjacency in compressed sparse row form (`CompactGraph.csr()`: two flat integer arrays of distinct targets in node-ID order), built once per publication; publish-time clustering reads the same compact edge arrays. At 100,000 nodes / 417,009 edges on Memgraph 3.2.0, analysis took 5.3 s and clustering 5.5 s of a 26.3 s publish, with a worker peak RSS of 442 MB (`qualify_simulate.py`, below). Splitting the per-identity reach loop across forked processes was measured at 4.9 s serial, 1.9 s with four processes and 1.3 s with eight; it is not used, because it would save about 3 s of a publish already far inside its 60 s budget, and Celery's prefork pool children are daemonic and may not start child processes. `backend/scripts/qualify_scale.py` measures this alongside endpoint latency:

```sh
cd backend
PYTHONPATH=. python scripts/qualify_scale.py --output scale-qualification.json
# optionally against a disposable PostgreSQL (a random schema is created and dropped):
PYTHONPATH=. python scripts/qualify_scale.py --database-url postgresql+psycopg://... --output scale-pg.json
```

It publishes a synthetic enterprise-shaped graph at 1k, 5k and 20k nodes through the real ingestion job and in-memory graph adapter (lifting the snapshot caps in-process only; product caps are unchanged) and fails unless `/overview` and the first `/findings` page have p95 under 50 ms at 5k and above, p95 grows at most 2x from the smallest to the largest size, publication grows by no more than the measured analysis cost, and stored results equal compute-on-read results. `--exposed-rate 0.05` makes most graphs produce full 200-row first pages. It excludes graph-database publish cost, network, the console proxy and concurrent load.
