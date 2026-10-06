# Excess-privilege index (EPI)

Optimizer Phase 2. For every role and identity of a revision, ZeroGraph compares the
data access it is **granted** with the access it **needs**, weighted by sensitivity
(1/2/5/10 for public/internal/confidential/restricted), and reports the gap as the
excess-privilege index:

> EPI = 1 − weight(needed) / weight(granted)

0 means everything granted is needed; 1 means nothing granted is needed. The index is
computed at publish time with the relationship topics ([topics.md](topics.md)) and
recomputed by the worker when usage evidence changes. It never removes or proposes
removing access by itself; proposals are Phase 3.

## Granted, used, inferred

Every number is labelled with its **basis**:

- **granted**: Phase 1 reach. The grant holders reachable over role/tool hops within the
  analysis bound (`H(x)`), and the data granted to them.
- **used**: needed = observed use, only where the evidence is sufficient for every
  service of the entity's granted data (and `sts` when it can assume roles): attested,
  complete coverage of at least 90 contiguous days ending within 7 days
  ([usage-evidence.md](usage-evidence.md)). Used data = data observed used (read, write
  or admin) by the entity or by a role it was observed assuming (observed assumptions
  that are graph hops, same bound), within its grants. Role usage is attributed to the
  identities observed assuming the role.
- **inferred**: otherwise a peer baseline. A holder's grant on an asset is peer-needed
  when at least *k* of the same-topic, non-hub holders granted that asset were observed
  using it (`ZG_PEER_BASELINE_SHARE`, default 0.5). A role needs the peer-needed grants of
  its holders. An identity needs its own peer-needed grants plus those of the roles it can
  assume directly that at least *k* of its same-topic peers (identities that can assume
  that role) were observed assuming.
- **none**: no usage evidence; EPI is null and only granted reach is shown.

Hub roles (granted on at least max(50, 2% of data assets)) dominate identity reach, so
every EPI is reported **with and without hubs**: without hubs, both the granted and the
used side exclude hub roles other than the entity itself.

## What is reported

- **Per role and identity** (`revision_topic_members`): basis, needed weight with and
  without hubs, used assets, its own grants that are unused (and how many are on
  restricted data), and the `dormant` flag. EPI is derived on read.
- **Per topic** (roles and identities by primary topic) and **graph-wide**: weighted EPI
  `1 − Σ needed / Σ granted` for roles and for identities, with and without hubs, basis
  counts, unused grants, unused grants on restricted data, dormant identities and roles.
- **Dormant**: an identity with sufficient evidence for its access and no observed event
  as a principal in the window; a role that is neither a principal nor observed assumed.
  `RoleLastUsed` stays a hint: a dormant role whose hint falls inside the window is
  counted as a conflict (`dormant_role_hint_conflicts`), never used to decide either way.
- **Evidence**: status (`none`, `partial`, `attested`), window, per-service coverage and
  sufficiency, sources, matched and unmatched observations.

Computation is role-level first (cached per distinct holder set and observed reach;
identities derive from their role sets). Timings are stored in the summary
(`privilege.timings_ms`).

## API and console

- `GET /api/v1/graph/topics`: `summary.privilege` (graph-wide EPI, counts, evidence) and
  `topics[].privilege`.
- `GET /api/v1/graph/topics/{id}`: each role or identity member carries `basis`,
  `needed_weight`, `needed_weight_excl_hubs`, `epi`, `epi_excl_hubs`, `used_resources`,
  `unused_grants`, `unused_restricted` and the `dormant` flag.
- `GET /api/v1/overview`: `excess_privilege` (graph-wide, decomposed) for the Overview
  tile.
- Console: the Topics lens panel shows granted vs used/inferred weight with and without
  hubs, unused and dormant counts and the evidence status; Data sources has the
  CloudTrail upload; Overview has the "Excess privilege" tile.

## Reference implementation

`backend/scripts/qualify_usage.py` holds `reference_privilege`, an independent brute
force of these definitions on explicit sets (no caching), used by the tests and the
qualification to check every role and identity, every topic and the graph-wide values
within 1e-6, in both the used and the inferred mode.
