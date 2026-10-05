# Global map: hierarchical structural clusters

The console's **Global map** view shows a whole revision at once, the way an Obsidian-style graph overview does, without sending 100,000 entities to the browser. Each revision is clustered once, at publication, into a bounded hierarchy; the browser loads one level at a time.

**Clusters are structural, not permissions.** A cluster is a group of entities that are densely connected to each other in the graph. It is not a permission, trust or account boundary, and membership implies no access. The API returns this notice with every response and the console shows it on every level.

## How clusters are built

Publication (`app.collectors.tasks._publish_job`) builds the revision's compact integer graph from staged rows (never a Pydantic snapshot). After the analysis is computed, `app.graph.clusters` runs:

1. **Topology.** Relationships become an undirected weighted adjacency; parallel and reverse relationships add weight. Account is a facet only (counted per cluster), never an input.
2. **Louvain.** A seeded (seed 7), deterministic multilevel Louvain (modularity, resolution 1), implemented over integer adjacency lists. When the tenant's current revision has clusters, the run is **warm-started** from them: entities start in their previous cluster and only move when the new topology improves modularity by at least one relationship's weight (`INERTIA`). Entities new to the revision start alone. A cold start is used when fewer than half the entities existed before.
3. **Hierarchy.** The top level holds at most **300** clusters: the Louvain communities plus one bucket per node type for entities with no relationships at all. When there are more than fit, the smallest communities are packed into "small groups" bins of one dominant type (at most 500 entities each). Any cluster with more than **500** entities is split again by Louvain on its induced subgraph (warm-started from the previous revision's children), into at most **300** children; a group Louvain cannot split is cut into ordered parts (breadth-first from its hubs, so neighbors stay together). Depth is capped at 6. Every leaf holds at most 500 entities.
4. **Stable IDs.** Each new cluster reuses the ID of the previous revision's cluster at the same depth with the best Jaccard overlap of members (greedy, one-to-one, minimum 0.3); others get new IDs.
5. **Summaries.** Per cluster: size, type histogram, the 12 largest account facets plus "(other)", relationships inside and leaving, and and a label. A named cluster takes its highest-degree member's name, unless an ancestor or an earlier sibling already uses that name (a child holding its parent's hub would otherwise repeat the parent in the breadcrumb); then the next-best member's name. Siblings that still share a label (duplicate entity names, several "small groups" bins of one type) are numbered "group i of n". Labels are deterministic. Per parent: relationship counts between sibling clusters. Per entity: its leaf, degree and degree inside the leaf.

Rows are written in the publication transaction (PostgreSQL `COPY`), before the pointer swap, so a revision becomes visible with its clusters or not at all; a clustering failure fails the publication (retried like any other failure).

## Storage, retention and backup

Clusters live in PostgreSQL (migration `0005`), keyed by `(tenant_id, revision)`: `revision_cluster_summary`, `revision_clusters`, `revision_cluster_links`, `revision_cluster_members`. PostgreSQL was chosen over properties in the graph store because:

- retention deletes them in the same locked SQL transaction as the revision's analysis rows ([graph-retention.md](graph-retention.md));
- the compose backup's unfiltered `pg_dump` carries them with their revisions, and the backup bridge metadata counts them so a change during backup is detected ([backup-restore.md](backup-restore.md)); the graph archive format is unchanged;
- they are recomputable: `python -m app.graph.clusters --tenant TENANT_ID` backfills the current revision under the publication lock (it loads that revision's snapshot, so run it as an operator task).

`CLUSTER_VERSION` (now 2: distinct labels) marks the format; rows of another version read as missing.

**Backfill.** A current revision without clusters of this version (published before migration `0005`, or before a version bump) gets them from the worker, not the API: Celery beat runs `backfill_clusters` every 60 s, which finds such tenants with one SQL query and computes at most 3 per run with the same code as publication. Each tenant is computed in its own transaction under the tenant's publication lock, taken with `pg_try_advisory_xact_lock` so the sweep skips a tenant that is publishing (that publication stores clusters anyway) instead of queueing behind it; the revision is pinned by the lock and a shared row lock on the pointer, exactly as in the operator backfill. Older-version rows of the same revision seed the run, so cluster IDs survive the recomputation. A tenant whose computation fails is logged and not retried by that worker process for an hour. The API stays bounded: it never loads a snapshot, returns 404 with `Retry-After: 60` until the rows exist, and the console retries every 30 s, so the map appears without a reload. This was chosen over computing lazily on the first API request because clustering a 100k revision takes seconds and a full snapshot in the API process, and over a one-shot migration step because a version bump needs the same path.

## API

Both endpoints require the viewer role, take the tenant only from the verified actor, pin the revision like `/graph/explore` (optional `revision`; a changed pointer returns **409**), return **503** with `Retry-After` when the revision's graph metadata is missing, and return **404** when the revision has no clusters (not computed yet) or the cluster ID does not exist in that revision.

- `GET /api/v1/graph/clusters?level=0[&edge_limit=1..2000][&revision=]` returns the top-level clusters (at most 300), their links (heaviest first, `edge_limit` default 1000) and `view` totals: entities, relationships, clusters at all levels, shown/total clusters and links, entities without relationships, `truncated`, and the structural `notice`. Only level 0 is served.
- `GET /api/v1/graph/clusters/{id}[?member_limit=1..500][&edge_limit=1..2000][&revision=]` returns the cluster, its breadcrumb `path`, and either its child clusters with the links among them (`view.mode = "clusters"`), or, for a leaf, its members (highest degree first, at most 500) with the relationships among them and each member's count of relationships leaving the cluster (`view.mode = "members"`). Shown/total counts and `truncated` are always reported.

Member nodes and relationships come from the graph store by unique entity key (`GraphStore.cluster_members`); everything else is read from PostgreSQL. Leaf neighborhoods stay on `/graph/explore`.

## Console

Knowledge graph → **Global map** (next to Identity & data and Role map) draws the top level as circles sized by entity count (area), colored by the most common node type, with lines weighted by the number of relationships between clusters. Selecting a circle (or its button in the list below the canvas, for keyboard use) opens that cluster in place; the breadcrumb returns to any ancestor or the top. A leaf shows its members with the existing canvas and worker layout; selecting a member shows how many of its relationships leave the cluster, and **Open neighborhood** hands off to the bounded explorer pinned to the same revision. Labels are drawn at a fixed 12 px at every zoom. The largest clusters claim label space first (the largest 14 at the fitted view, more as you zoom in); a label never overlaps another label, never covers the circle of a larger cluster, and moves above its circle when the place below is taken; labeled clusters draw above smaller ones. The hovered cluster's label is always shown. The fitted view leaves room for the labels it shows, the legend and the zoom controls, and the largest circle takes at most a share of the canvas that shrinks with the number of clusters (48–88 px), so a four-cluster map does not fill the canvas.

## Measured capacity (Memgraph 3.2.0, PostgreSQL 16)

`backend/scripts/qualify_clusters.py` publishes a synthetic 100,000-node / 417,009-edge revision through the real upload, worker and API processes, then the same graph with 4,170 relationships (1%) replaced. One M5 MacBook, Memgraph in Docker (colima).

| Measure | Result |
|---|---|
| Top-level clusters | 170 and 159 (limit 300) |
| Largest expansion | 500 items; max children 185, max leaf members 500 (limit 500) |
| Clusters at all levels | 2,164 / 2,317, depth 4 / 6 |
| `GET /graph/clusters` p50 / p95 | 6.06 / 6.6 ms (200 requests) |
| Expansion to child clusters p50 / p95 | 4.37 / 5.94 ms (59) |
| Expansion to members p50 / p95 | 6.05 / 22.6 ms (750) |
| Cluster IDs kept after the change | 94.0% of clusters (95.3% weighted by size; top level 91.2%) |
| Entities keeping their top-level / leaf cluster ID | 98.5% / 86.4% |
| Clustering added to publication | 5.66 s cold, 3.2 s warm (Louvain + hierarchy 4.553 / 1.878 s, rows 1.101 / 1.015 s) |
| Worker peak RSS | 409.1 / 391.1 MB |
| Readers during the second publication | 5,643 requests, all 200 (cluster map and explore pollers) |
| Retention | deleted revision 1 and all its cluster rows |

## Bounded exploration on Memgraph

Phase 2 measured `/graph/explore` at 0.4–0.6 s at 100k. The visible-edge query matched `a.id IN $ids AND b.id IN $ids` over the scoped pattern, so Memgraph scanned every entity of the revision and expanded its relationships; the sample sorted the whole revision by ID. Now:

- the sample reads the first 500 IDs stored at publication (`revision_analysis.sample_ids`, migration `0005`) and fetches them by unique key; older rows without a sample keep the scan;
- the root, its neighbors and the visible edges are anchored on unique entity keys and expanded from there;
- scope filters sit behind `WITH`: given a `WHERE` on `tenant_id` or `revision`, Memgraph 3.2's planner otherwise prefers that non-unique index and scans the whole tenant or revision (3.1 s instead of 2.6 ms for 250 nodes).

| Same 100k revision | Former query shapes p50 / p95 | Now p50 / p95 | Now over HTTP p50 / p95 |
|---|---|---|---|
| Sample (250 nodes) | 333.26 / 446.64 ms | 9.38 / 13.44 ms | 10.78 / 12.41 ms |
| Hub neighborhood | 308.19 / 331.85 ms | 38.54 / 43.14 ms | 41.54 / 46.87 ms |

Limits of this evidence: one machine, synthetic data, no network/TLS or Next.js proxy, no multi-tenant contention. Warm-start stability is measured over one small change; drift across many revisions is bounded by the cold-start rule but not separately measured. Neo4j runs the same functional tests but is not scale-qualified.
