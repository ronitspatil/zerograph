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

- `GET /api/v1/graph/clusters/{id}/members[?expanded=<id>...][&member_limit=1..5000][&edge_limit=1..20000][&revision=]` returns **every** member below the cluster (all levels, highest degree first) for in-place display, with the relationships among them and to the members of the clusters named in `expanded` (the ones already on screen, at most 64), so relationships between expanded clusters arrive with the later one. Each member's whole-revision relationship count is in `degrees`. The clusters shown together may hold at most **5,000** entities: a request beyond that returns **422** with an explanation. `view` reports shown/total members, members visible after this expansion, shown relationships and `truncated` (the relationship limit is 20,000).

Member nodes and relationships come from the graph store by unique entity key (`GraphStore.cluster_members`, `GraphStore.cluster_expansion`); everything else is read from PostgreSQL. Leaf neighborhoods stay on `/graph/explore`.

## Console

Knowledge graph → **Global map** (next to Identity & data and Role map) draws the top level as circles sized by entity count (area), colored by the most common node type, with lines weighted by the number of relationships between clusters. Selecting a circle (or its button in the list below the canvas, for keyboard use) opens that cluster as a new level (its sub-groups); the breadcrumb returns to any ancestor or the top. A cluster that fits the on-screen budget (5,000 members across every expanded cluster) expands **in place** instead: its members are laid out on the worker as a packed disc (one patch per role community, loose members on the rim) at the circle's position, and only the circles that disc overlaps move aside, so the rest of the map keeps its shape. An overlay on the canvas shows how many members are shown and explains a refusal; **Collapse all**, the sidebar's **Collapse cluster** or selecting the cluster's button again removes them. Larger clusters open as a level, and a leaf beyond the remaining budget shows its members with the existing canvas and worker layout; selecting a member shows how many of its relationships leave the cluster, and **Open neighborhood** hands off to the bounded explorer pinned to the same revision. Labels are drawn at a fixed 12 px at every zoom. The largest clusters claim label space first (the largest 14 at the fitted view, more as you zoom in); a label never overlaps another label, never covers the circle of a larger cluster, and moves above its circle when the place below is taken; labeled clusters draw above smaller ones. No label is placed under the legend, the zoom controls or the in-place overlay (they are label obstacles, measured on screen and re-checked after every pan, zoom and overlay change; above 1,000 members on screen, once the view rests), and legend entries sit on a backdrop so the graph never crosses their text; the identity and role maps follow the same rule. The hovered cluster's label is shown unless both sides of its circle are under an overlay. The fitted view leaves room for the labels it shows, the legend, the zoom controls and the in-place overlay, and the largest circle takes at most a share of the canvas that shrinks with the number of clusters (48–88 px), so a four-cluster map does not fill the canvas.

### Rendering

The global map uses Cytoscape's WebGL renderer (`renderer: {name: "canvas", webgl: true}`, Cytoscape 3.34, no extra dependency) whenever the browser offers WebGL 2; detail views of at most 500 nodes (the explorer and leaf members) keep the canvas renderer, whose labels are sharpest. WebGL support is detected once with a throwaway context; if it is missing, or the WebGL renderer fails to start, the same view is built on the canvas renderer (panning a cached texture for large views), so the map always renders. Both work under the console's CSP: no `eval`, no blob workers (`worker-src 'self'`). Labels follow the same rules in both renderers (fixed 12 px, collision thinning, the largest clusters first, hovered and selected shown unless covered by an overlay, never under the legend, zoom controls or in-place overlay); label sizes follow zoom in steps of 1/16 octave so WebGL label textures are reused while zooming, and member labels appear once members are far enough apart on screen, highest degree first. Under `prefers-reduced-motion` the in-place expansion and the neighbours moving aside happen without animation.

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

### In-place expansion and rendering (Phase 5)

`backend/scripts/qualify_expansion.py` publishes a 100,000-node / 416,158-relationship revision (the enterprise-shaped fixture at 93,500 nodes plus three disjoint components of 500 / 2,000, 1,000 / 4,000 and 5,000 / 20,000 nodes / relationships) through the worker on Memgraph 3.2.0 and PostgreSQL 16, then calls `GET /graph/clusters/{id}/members` in process. All 6 checks pass (exact members and relationships for each component, every relationship among progressively expanded clusters delivered exactly once, 422 beyond the budget).

| Expansion (Memgraph) | p50 / p95 (7 requests; p95 includes the first, cold request) | Response |
|---|---|---|
| 500 members / 2,000 relationships | 34 / 466 ms | 0.45 MB |
| 1,000 / 4,000 | 67 / 71 ms | 0.89 MB |
| 5,000 / 20,000 | 309 / 745 ms | 4.4 MB |

The console was measured in headless Chrome 154 (ANGLE Metal, Apple M5, 1440 × 900) against the production build, with the 100k map: expand the component's cluster in place, then 3 s of one viewport change per frame (wheel zoom, then drag pan) while recording `requestAnimationFrame` intervals. Median of 3 runs; "first frame" is from the click to the members drawn, API included (in-memory graph store for these runs).

| Visible members / relationships | WebGL fps, p95 frame, first frame | Canvas fallback fps, p95 frame, first frame |
|---|---|---|
| 500 / 2,000 | 59.8, 16.7 ms, 0.23 s | 59.4, 16.8 ms, 0.28 s |
| 1,000 / 4,000 | 59.8, 16.8 ms, 0.30 s | 59.3, 16.8 ms, 0.44 s |
| 5,000 / 20,000 | 59.6, 16.8 ms, 0.83 s | 55.9, 16.8 ms, 1.26 s (max frame 150 ms) |

The canvas fallback's frame rate comes from panning a cached texture (`textureOnViewport`): the view is not redrawn while it moves. Drawn every frame, as on the Phase 4 benchmark page, the canvas renderer manages 10.7 fps at 5,000 nodes and WebGL 60 fps; at 20,000 nodes (above the console's 5,000 cap, informational) WebGL draws 17.3 fps (p95 62 ms, first frame 2.0 s) and canvas 2 fps.

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
