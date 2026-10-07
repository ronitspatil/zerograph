# Least-privilege proposals and what-if simulation

Optimizer Phase 3. From each revision's relationship topics ([topics.md](topics.md)), its
excess-privilege index ([privilege.md](privilege.md)) and the tenant's observed access
([usage-evidence.md](usage-evidence.md)), ZeroGraph proposes changes that move the
identity graph toward least privilege. **Proposals are proposed, never applied**: nothing
changes a grant, accepting one only records a review decision, and pull requests come in
Phase 4. Code: `app/graph/proposals.py`, `app/graph/whatif.py`.

## Types

| Type | Proposes | Tier |
|---|---|---|
| `remove_grant` | Remove a holder's (role's, or an identity's own) grant on a data asset never observed used | from the evidence (below) |
| `disable_identity`, `disable_role` | Disable or detach an identity or role with no observed use in a sufficient window. **Never delete.** | `high`; `low` when `RoleLastUsed` falls inside the window |
| `merge_roles` | Two roles of one topic whose grants have Jaccard similarity ≥ 0.8 (exact join): the kept role keeps the retired role's *used* grants and its assumers; the retired role is disabled | `manual` (trust policy edits) |
| `split_role` | A role whose used assets span ≥ 2 topics with ≥ 25% each: one role per topic with that topic's used grants | `manual` (trust policy edits) |
| `scope_wildcard` | Scope grants with wildcard actions (`*`, `service:*`) to the assets actually used | `manual` (wildcard rewrite) |
| `break_toxic_path` | On each toxic-combination path, remove the edge with the lowest observed-use weight (preferring grants over trust edges, then the edge nearest the data) | as `remove_grant` for a grant; `manual` for a hop |

Thresholds are the captain's: 90-day window, 7-day freshness, merge Jaccard ≥ 0.8, split
≥ 25% per topic.

## Tiers

For removals of a grant on a data asset whose service has:

- **sufficient** coverage (attested, complete, ≥ 90 contiguous days ending within 7):
  - `high`: the asset is outside the holder's topic (another topic, or a fallback group:
    nothing ties it to the holder's topic) and fewer than the peer share of same-topic
    holders granted it use it;
  - `low`: unused by the holder, but at least the peer share (default 50%) of same-topic
    holders granted it use it;
  - `medium`: otherwise (inside the topic).
- **complete but short or stale** coverage: `inferred` when the peer baseline says the
  grant is not needed (not proposed when peers need it).
- **no complete coverage**: `manual` (reason `coverage`), when peers do not need it.
- No usage evidence at all: no removal is proposed.

## Never-auto list

Any of these forces `manual`, whatever the evidence says; `base_tier` keeps the tier the
evidence alone would give and `reasons` lists why:

| Reason | Detected from |
|---|---|
| `condition` | An identity-policy Allow granting the edge's action on the asset has a `Condition` |
| `deny` | A Deny statement of the principal matches the action and asset |
| `resource_policy` | The principal has identity policies but none grants it (resource policy or elsewhere) |
| `trust` | The change re-points or cuts role assumption (merge, split, cutting an `ASSUMES_ROLE` hop) |
| `cross_account` | A trust change across accounts |
| `service_linked` | `:role/aws-service-role/` ARN, `scp_exempt_service_linked_role` metadata or a `service-linked` tag |
| `break_glass` | `break-glass`, `emergency`, `disaster-recovery` or a `dr` token in ID, name or tags |
| `kms` | A KMS key (`:kms:` ARN or `service=kms` metadata) |
| `wildcard` | A grant with a wildcard action |
| `coverage` | The asset's service lacks attested, complete coverage |
| `seasonal` | `schedule=seasonal|scheduled|quarterly|annual|monthly`, `seasonal`, `zg-optimizer=exempt` tags or `optimizer_exempt` metadata |
| `structure` | Cutting a tool-invocation or inheritance hop |

Deleting an identity is never proposed. Removing an identity-policy grant on an asset in
another account is not a trust change and keeps its evidence tier (the resource-side
policy still has to allow access, so removing the identity side can only reduce access).

## Invariant: no proposal removes observed access

A grant is not proposed for removal when the holder or any principal that can reach it
was observed using the asset, or when the asset has observed use that no graph grant
explains. A dormant role is not proposed for disabling when an active principal whose
closure includes it observed use of data its holders grant. A path edge is never cut when
it was observed (used grant or observed assumption). `check_invariant` applies every
proposal at once and verifies, by brute force, that every observed use and assumption
keeps its path; tests and `qualify_proposals.py` run it over every proposal.

## Evidence

Each proposal row carries: type, tier, base tier, never-auto reasons, topic, subject and
target (IDs and names), sensitivity weight removed, identities whose reach includes the
subject (with up to 3 examples), the subject's EPI before and after the change alone,
evidence (service and its coverage class, same-topic peers granted/used, `RoleLastUsed`
hint, Jaccard and shared grants for merges, topic groups for splits, finding IDs for
toxic paths) and the exact changes (edge IDs, types and actions of every removed grant
edge, the disabled node, the merge or split plan). `GET /proposals/{id}` adds the
revision's usage evidence (window, sources, coverage per service), the topic's label and
reason, the asset's label reason, and the graph-wide EPI before/after the proposal alone.

IDs are deterministic (`p` + 19 hex of SHA-256 over type, subject and target IDs), so
the same change has the same ID in every revision. Rows are ordered by tier, type,
weight (descending), identities (descending), then ID.

## What-if

The worker stores a compressed what-if model per revision (`revision_proposal_models`,
about 3 MB at 100k nodes): grants per holder, role/tool hops, hub roles, each role's and
identity's closure and granted/needed weights, and every proposal's removals, cut hops and
disabled nodes. `POST /proposals/metrics` evaluates any set (explicit IDs, a tier, the
accepted ones) on it, cached per API process: granted weight after = granted minus the
data no remaining holder of the closure still grants; closures through disabled nodes or
cut hops are recomputed with the analysis hop bound; needed weight is held at the analysis
value (proposals never remove observed use), clamped to granted. Merges and splits are
not modelled (reported as skipped). The result matches a brute-force recomputation.

`POST /simulate` accepts an optional `overlay` (proposal IDs of the pinned revision,
explicit `edges` as source/target pairs, `edge_ids`, `disabled_nodes`; bounded) and
returns the current blast radius plus `whatif` (after, risk delta, assets no longer
reachable). Without an overlay the response is unchanged. The overlay filters the
fetched bounded neighborhood, which is exact because removal only shrinks reach.
`POST /proposals/simulate` does the same for one or more proposals from the first
proposal's subject (conditional edges included by default).

## API

| Endpoint | Role |
|---|---|
| `GET /proposals?tier=&type=&topic=&subject=&state=&cursor=&limit=` | viewer |
| `GET /proposals/summary` | viewer |
| `GET /proposals/{id}` | viewer |
| `POST /proposals/simulate` | viewer |
| `POST /proposals/metrics` | viewer |
| `POST /proposals/{id}/decision` (`accepted`, `rejected`, `pending` to clear) | admin, audited (`proposal.accepted`, `proposal.rejected`, `proposal.cleared`) |
| `POST /simulate` with `overlay` | analyst (unchanged) |

Decisions are stored per tenant by proposal ID (`proposal_decisions`) and carry forward
to later revisions; a decision whose proposal content changed since reads `stale`.

## Lifecycle

Rows (`revision_proposal_summary`, `revision_proposals`, `revision_proposal_models`,
migration `0011`) are written with `COPY` in the publication transaction, recomputed with
the topics when usage evidence changes (topic sweep), backfilled by a 60 s worker sweep
(`backfill-proposals`; `python -m app.graph.proposals --tenant T` by hand) for current
revisions without proposals of `PROPOSAL_VERSION` (1), deleted by retention with their
revision, and carried by the PostgreSQL backup (decisions too).
