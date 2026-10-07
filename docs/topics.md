# Relationship topics and structural privilege analysis

Optimizer Phase 1. Each revision's data assets are grouped into **topics**: named groups of resources that belong to one system or workload (`data-lake`, `payments-db`, `ci-cd`). Roles and identities get a **topic profile**, a primary topic, their granted reach and **structural over-privilege flags**. The console shows topics as a lens of the global map.

**Granted, then needed.** Profiles and flags describe granted (structural) access, computed from the graph alone, so a cross-topic grant may be legitimate and nothing here is a recommendation to remove access. Since optimizer Phase 2, when usage evidence exists ([usage-evidence.md](usage-evidence.md)) the same computation refines topics with observed co-use and adds the excess-privilege index: granted vs **used** (attested evidence) or **inferred** (peer baseline) access, see [privilege.md](privilege.md). Proposals are a later phase. **Topics are not policy boundaries either:** they are derived from resource tags, names and access. The API returns this notice with every response and the console shows it in the Topics lens.

## How topics are built

Publication (`app.collectors.tasks._publish_job`) already holds the revision's compact graph (`app.graph.compact.CompactGraph`, never a Pydantic snapshot). It now also carries each node's raw tags (`key=value` strings kept verbatim), provider and string metadata under `topic`, `app`, `application`, `project`, `workload`, `team`, `service`, `data_category`, plus each relationship's type and actions; repeated tag and action lists are interned. After the global-map clusters, `app.graph.topics.compute_topics` runs. It is deterministic: the same revision always gives row-identical results, whatever the node order.

1. **Tags.** A data asset (database, bucket, vector store) tagged `topic=`, else `app=`/`application=`, else `project=`/`workload=`, else `team=` (also `key:value`, keys case-insensitive) belongs to the topic named by the value, normalized (lowercase, other characters become `-`, 64 characters). The same keys as string metadata come next.
2. **Name tokens.** Name tokens (lowercase alphanumeric runs, 2+ characters, not all digits) of tagged assets are counted per topic. A token seen on at least 5 tagged assets, at least 80% of them in one topic, names that topic; an untagged asset whose name carries such tokens joins the topic they point to (ambiguous names are skipped). Generic tokens (`prod`, `raw`, `db`) never qualify.
3. **Shared access.** Each grant holder (a role, or an identity with direct grants) gets a preliminary topic: the plurality of its labeled grants. An unlabeled asset joins the plurality topic of the non-hub holders granted on it (two rounds; ties by topic name). When the asset's service has sufficient usage evidence, only holders observed using it vote: a grant nobody used is not evidence of shared access, and an asset granted but never used falls to its fallback group with that reason.
3b. **Observed co-use (usage refinement).** With usage evidence, a seeded Louvain run on the bipartite graph of observed (principal, asset) use (hub roles excluded) groups assets used together. A community with at least 3 tag/metadata/name-labeled assets, at least 60% in one topic, names its weakly labeled assets (shared access or none): `seed` `usage`, reason `usage co-access: used together with N labeled assets, P% topic`. Tag, metadata and name labels never change.
4. **Service type and data category.** Assets with no signal at all form fallback groups by node type and classification category, such as "Unassigned S3 buckets (PII)".

Each asset row records how it was labeled (`seed`: `tag`, `metadata`, `name`, `usage`, `coaccess`, `fallback`) and why (for example `tag topic=data-lake`, `name token "lake" (98% of tagged assets with it)`, `co-access: 3 of 4 granted roles are crm`). Each topic records a reason built from those, in the form `Tagged topic=data-lake on N assets; N more by name tokens; N by observed co-use; N by shared access`. Topic IDs derive from the name, so the same topic keeps its ID across revisions.

## Profiles, reach and flags

- **Reach.** A role's or identity's grant holders are the nodes reachable over `ASSUMES_ROLE`, `INHERITS_PERMISSIONS` and `INVOKES_TOOL` within the analysis hop bound (5, the data hop included, as for blast radius). Reach is computed once per distinct holder set (the role-level computation; identities derive from their role sets): distinct data assets, sensitivity-weighted (1/2/5/10 for public/internal/confidential/restricted), per topic.
- **Profile.** The share of granted sensitivity weight per topic (top five stored). **Primary topic:** the topic holding most of the granted assets (ties: more weight; for a role, a topic named by its own name tokens; then topic name). Hub roles are excluded from the profile when the entity has other grants.
- **Hub-decomposed.** Every role and identity stores its reach weight with and without hub roles; topics count hub grants separately (`hub_grants_in`), and cross-topic links exclude hubs.
- **Flags.** `hub`: a role granted directly on at least max(50, 2% of all data assets). `via_hub`: can reach a hub role. `privileged`: marked privileged, or holding a grant with a wildcard action (`*`, `service:*`); for an identity, reaching such a node. `cross_topic`: a role with grants on another topic's assets; an identity whose non-hub roles have different primary topics. `restricted_outside`: transitive reach to restricted data outside the primary topic.
- **Counts.** Per topic: assets, sensitivity weight, roles and identities (by primary topic), cross-topic grants out and in, hub grants in, flagged roles and each flag's count, sensitivity and type histograms, how assets were labeled. Graph-wide: the same totals plus identity reach with and without hubs. Topic color in the console is the share of the topic's (non-hub) roles' granted weight that lies outside the topic.

## Storage, retention, backup and backfill

Same lifecycle as the global-map clusters ([global-map.md](global-map.md)). Rows live in PostgreSQL (migration `0007`), keyed by `(tenant_id, revision)`: `revision_topic_summary` (graph-wide totals), `revision_topics`, `revision_topic_links` (cross-topic grants between two topics, hubs excluded) and `revision_topic_members` (every data asset, role and identity: topic, rank, label reason, flags, reach and profile). They are written with `COPY` in the publication transaction before the pointer swap (a failure fails the publication), deleted by retention with their revision, carried by the unfiltered PostgreSQL dump and counted in the backup bridge metadata. `TOPIC_VERSION` (now 2: usage refinement and excess-privilege columns, migration `0010`) marks the format; rows of another version read as missing. `revision_topic_summary.usage_fingerprint` records the usage evidence the rows were computed with.

Current revisions without topics (published before `0007`, or before a version bump), or whose rows were computed with other usage evidence than the tenant's current evidence (an upload committed or deleted, evidence gone stale), are filled by the worker: Celery beat runs `backfill_topics` every 60 s (at most 3 tenants per run, publishing tenants skipped, a failing tenant not retried by that process for an hour; `app/graph/sweep.py`). `python -m app.graph.topics --tenant TENANT_ID` backfills one tenant's current revision under the publication lock (it loads that revision's snapshot, so run it as an operator task). The API never computes topics.

## API

Both endpoints require the viewer role, take the tenant only from the verified actor, pin the revision like `/graph/clusters` (optional `revision`; a changed pointer returns **409**), return **503** with `Retry-After: 5` when the revision's graph metadata is missing, and **404** with `Retry-After: 60` until the revision's topics exist, or when the topic ID is not in that revision. Every response carries `basis: "granted (structural)"` and the notice.

- `GET /api/v1/graph/topics[?edge_limit=1..2000][&revision=]` returns the topics (anchored first, then by sensitivity weight; at most 300), the cross-topic links among them (heaviest first, `edge_limit` default 1000), graph-wide `summary` totals and `view` counts with `truncated`.
- `GET /api/v1/graph/topics/{id}[?kind=resource|role|identity][&offset=0..1000000][&limit=1..500][&revision=]` returns the topic, one page of its members of that kind (default 50; assets by sensitivity, roles by number of flags then cross-topic weight, identities by flags then reach) with `next_offset`, and its ten most over-privileged flagged roles.

## Console

Knowledge graph → Global map → **Topics** (the lens switch at the end of the level bar; **Structure** returns to the clusters). Circles are topics sized by sensitivity weight and colored by the share of their roles' granted weight outside the topic (under 10%, 10–20%, 20–35%, 35% or more; gray for unassigned groups); lines are cross-topic grant counts. The canvas, labels, legend and overlay rules are the cluster map's. Selecting a topic (circle or list button) opens its panel: how it was named, its counts, its most over-privileged roles and its data assets, roles and identities, 50 at a time. Selecting a member shows its flags, reach with and without hub roles and profile; **Open neighborhood** hands off to the bounded explorer pinned to the same revision. The structural notice ("not permission boundaries") appears only in the Structure lens; the Topics lens shows its own.

## Measured (Memgraph 3.2.0, PostgreSQL 16)

`backend/scripts/qualify_topics.py` publishes the planted-topic fixture (`qualify_scale.generate_topics`: 100,000 nodes / 287,959 relationships; 12 topics; tags on ~50% and topic tokens in ~60% of data assets; 41,608 planted cross-topic over-grants; 750 near-duplicate roles; 2,839 dormant identities; 3 admin hubs) through the real upload, worker and API processes, alternating publications with the topic analysis disabled and enabled. One M5 MacBook, Memgraph in Docker (colima).

| Measure | Result |
|---|---|
| Role primary topic vs planted | 96.4% of 14,997 roles |
| Data asset purity / NMI | 0.923 / 0.823 (0.952 purity without the fallback groups) |
| How assets were labeled | tag 22,630 · name token 13,394 (100% correct) · shared access 7,293 (71% correct) · fallback 1,683 |
| Hub roles found | the 3 planted |
| Stored cross-topic grants that are planted over-grants | 92.0% (90.0% of planted non-hub over-grants flagged) |
| Topic analysis in publication | 1.78 / 2.16 s (compute 0.93 s, rows 0.84 / 1.23 s) |
| Whole publication, disabled / enabled | 16.5, 14.5 s / 15.7, 16.8 s |
| Worker peak RSS, disabled / enabled | 366, 400 MB / 376, 393 MB (no measurable increase) |
| Deterministic | two in-process recomputations, the worker's rows and a backfill: identical (100,000 rows) |
| `GET /graph/topics` p50 / p95 | 3.4 / 4.1 ms (200 requests) |
| `GET /graph/topics/{id}` 50-member pages p50 / p95 | 4.3 / 7.4 ms (162: every topic, kind and three offsets) |
| 500-member page p50 / p95 | 10.2 / 29.2 ms |
| Retention | deleted the older revisions and their topic rows |

The existing fixture (no tags) gets fallback groups only; its publication, cluster and scale qualifications are unchanged. Limits of this evidence: synthetic data with clean tag values (real tags need the collectors to keep them, Phase 2); one machine; no network, TLS or proxy.
