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

`/simulate` and the legacy `GET /graph` still load the full snapshot; they are out of scope for this phase.

## Revisions published before this change

Revisions without a stored row, or with a row from another `analysis_version`, are computed on read from the snapshot, exactly as before. This was chosen over a migration-time backfill because it needs no graph access during `alembic upgrade`, is correct by construction, and costs only what every request cost before the change; such revisions are bounded by the existing 5,000-node cap and are replaced by the next publication. Operators who want the fast path immediately can backfill a tenant's current revision under the publication lock:

```sh
python -m app.graph.analysis --tenant TENANT_ID
```

It is idempotent and prints JSON stating whether it stored anything. Bump `ANALYSIS_VERSION` in `app/graph/analysis.py` whenever overview, finding or totals logic changes; older rows are then ignored until republished or backfilled.

## Retention

Applied retention deletes a revision's `revision_analysis` and `revision_findings` rows in the transaction that holds the tenant publication lock and records `graph.revision_deleted`. If that final SQL commit fails after the graph deletion, the rows remain but are unreachable (no pointer can name a deleted revision) and inert.

## Cost and capacity

Analysis runs while the publish job holds the tenant publication lock, so publication (and the reader 503 window) grows by the analysis time until the short-lock publication of a later phase. `backend/scripts/qualify_scale.py` measures this alongside endpoint latency:

```sh
cd backend
PYTHONPATH=. python scripts/qualify_scale.py --output scale-qualification.json
# optionally against a disposable PostgreSQL (a random schema is created and dropped):
PYTHONPATH=. python scripts/qualify_scale.py --database-url postgresql+psycopg://... --output scale-pg.json
```

It publishes a synthetic enterprise-shaped graph at 1k, 5k and 20k nodes through the real ingestion job and in-memory graph adapter (lifting the snapshot caps in-process only; product caps are unchanged) and fails unless `/overview` and the first `/findings` page have p95 under 50 ms at 5k and above, p95 grows at most 2x from the smallest to the largest size, publication grows by no more than the measured analysis cost, and stored results equal compute-on-read results. It excludes graph-database publish cost, network, the console proxy and concurrent load.
