"""Excess-privilege index (EPI) and usage-based topic refinement, at publish time.

Inputs are the revision's ``CompactGraph``, the Phase 1 topic analysis (grant
holders, holder sets, primary topics) and the tenant's observed access
(``app.graph.usage``), matched to the revision by stable entity IDs.

Definitions (weights are sensitivity weights 1/2/5/10 of data assets):

* ``H(x)``: the grant holders reachable from ``x`` over role/tool hops (Phase 1);
  ``hubs(x)`` = hub roles other than ``x``. ``Granted(x)`` = the data granted to
  ``H(x)``; ``Granted'(x)`` the same without ``hubs(x)`` (Phase 1 reach with and
  without hubs).
* ``V(x)``: ``x`` and the roles reachable from it over **observed** assumptions that
  are also graph hops (same hop bound). ``Used(x)`` = data observed used (read, write
  or admin) by a member of ``V(x)``, within ``Granted(x)``; ``Used'(x)`` excludes
  ``hubs(x)`` on both sides.
* Peer baseline (inferred): for a holder ``h`` of topic ``t``, a grant ``(h, d)`` is
  peer-needed when, among non-hub holders of topic ``t`` granted ``d``, at least
  ``k`` (default 50%) were observed using it. ``Inferred(role)`` = peer-needed grants
  of ``H(role)``. For an identity ``i``, a role ``r`` it can assume directly is
  peer-assumed when at least ``k`` of same-topic identities that can assume ``r``
  were observed assuming it; ``Inferred(i)`` = its own peer-needed grants plus
  ``Inferred(r)`` of its peer-assumed roles, within ``Granted(i)``.
* ``Needed(x)`` = ``Used(x)`` when every service of ``Granted(x)`` (and ``sts`` when
  ``x`` can assume roles) has sufficient evidence (attested, complete, >= 90 days,
  fresh within 7); otherwise ``Inferred(x)`` and the basis is "inferred". Without any
  usage evidence the basis is "none" and no EPI is reported.
* ``EPI(x) = 1 - w(Needed(x)) / w(Granted(x))``; aggregates (per topic, graph) are
  ``1 - sum w(Needed) / sum w(Granted)`` over roles or identities, always reported
  with and without hubs.

Counts: unused grants (a holder's own grants not in its needed set), unused grants on
restricted data, dormant identities (no observed event as principal in a sufficient
window) and dormant roles (never a principal nor assumed). ``RoleLastUsed`` is a hint:
a dormant role whose hint falls inside the window is counted as a conflict, never
used to decide need.
"""

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy.orm import Session

from app.graph.compact import MAX_HOPS, CompactGraph
from app.graph.schema import NodeType
from app.graph.usage import Evidence, evidence, observed, utc

PEER_SHARE = 0.5
USAGE_MIN_LABELED = 3
USAGE_MIN_SHARE = 0.6
STRONG_SEEDS = frozenset({"tag", "metadata", "name"})
DATA_SERVICE = {
    NodeType.BUCKET.value: "s3",
    NodeType.DATABASE.value: "rds-data",
    NodeType.VECTOR.value: "aoss",
}
ASSUME_SERVICE = "sts"
BASES = ("used", "inferred", "none")


@dataclass
class UsageInput:
    """Observed access matched to a revision's node indices (unmatched IDs counted)."""

    evidence: Evidence
    data_used: dict[int, set[int]] = field(default_factory=dict)  # principal -> data used
    assumed: dict[int, set[int]] = field(default_factory=dict)  # principal -> roles assumed
    active: set[int] = field(default_factory=set)  # principals with any observed event
    assumed_by_any: set[int] = field(default_factory=set)
    matched: int = 0
    unmatched: int = 0
    peer_share: float = PEER_SHARE

    @property
    def present(self) -> bool:
        return self.evidence.present


def match_usage(
    graph: CompactGraph, found: Evidence, rows, peer_share: float = PEER_SHARE
) -> UsageInput:
    """Match ``(principal, resource, action class)`` observations to ``graph`` node indices."""
    result = UsageInput(found, peer_share=peer_share)
    index, types = graph.index, graph.types
    data = frozenset(DATA_SERVICE)
    for principal, resource, action_class in rows:
        source = index.get(principal)
        if source is None:
            result.unmatched += 1
            continue
        result.active.add(source)
        target = index.get(resource)
        if target is None:
            result.unmatched += 1
            continue
        result.matched += 1
        if action_class == "assume":
            result.assumed.setdefault(source, set()).add(target)
            result.assumed_by_any.add(target)
        elif types[target] in data:
            result.data_used.setdefault(source, set()).add(target)
    return result


def load_usage(
    db: Session, tenant: str, graph: CompactGraph, at: datetime | None = None, peer_share: float = PEER_SHARE
) -> UsageInput:
    """The tenant's committed observed access, matched to ``graph`` by stable IDs."""
    found = evidence(db, tenant, at)
    if not found.present:
        return UsageInput(found, peer_share=peer_share)
    rows = ((principal, resource, action) for principal, resource, action, _, _, _ in observed(db, tenant))
    return match_usage(graph, found, rows, peer_share)


def data_service(graph: CompactGraph, node: int) -> str:
    for hint in graph.hints.get(node, ()):
        if hint.startswith("service="):
            return hint.split("=", 1)[1].strip().lower()
    return DATA_SERVICE.get(graph.types[node], graph.types[node].lower())


# ---------------------------------------------------------------------------
# Hybrid usage-Louvain topic refinement


def refine_with_usage(
    graph: CompactGraph,
    usage: UsageInput,
    label: dict[int, str],
    seed: dict[int, tuple[str, str]],
    hubs: set[int],
) -> dict:
    """Relabel weakly labeled assets (grant co-access or none) by usage communities.

    A seeded Louvain run on the bipartite graph of observed (principal, data) use (hub
    roles excluded) groups assets accessed together. A community whose strongly
    labeled assets (tag, metadata or name) number at least ``USAGE_MIN_LABELED`` with at
    least ``USAGE_MIN_SHARE`` in one topic names its weakly labeled assets, with the
    reason recorded. Strong labels never change. Deterministic.
    """
    from app.graph.clusters import louvain

    # Ordered by entity ID, not node index: the result must not depend on revision order.
    ids = graph.ids
    pairs = sorted(
        (
            (principal, item)
            for principal, items in usage.data_used.items()
            if principal not in hubs
            for item in items
        ),
        key=lambda pair: (ids[pair[0]], ids[pair[1]]),
    )
    if not pairs:
        return {"communities": 0, "named": 0, "relabeled": 0}
    local: dict[int, int] = {}
    for principal, item in pairs:
        local.setdefault(principal, len(local))
        local.setdefault(item, len(local))
    adjacency: list[dict[int, int]] = [{} for _ in local]
    for principal, item in pairs:
        a, b = local[principal], local[item]
        adjacency[a][b] = adjacency[b][a] = 1
    nodes = list(range(len(local)))
    communities = louvain(adjacency, nodes)[-1]
    member = {position: node for node, position in local.items()}
    is_data = frozenset(DATA_SERVICE)
    named = relabeled = 0
    for community in communities:
        items = [member[position] for position in community if graph.types[member[position]] in is_data]
        strong = Counter(label[item] for item in items if item in seed and seed[item][0] in STRONG_SEEDS)
        total = sum(strong.values())
        if total < USAGE_MIN_LABELED:
            continue
        topic, hits = min(strong.items(), key=lambda kv: (-kv[1], kv[0]))
        if hits / total < USAGE_MIN_SHARE:
            continue
        named += 1
        for item in items:
            if item in seed and seed[item][0] in STRONG_SEEDS:
                continue
            reason = (
                f"usage co-access: used together with {total} labeled assets, "
                f"{round(100 * hits / total)}% {topic}"
            )
            label[item] = topic
            seed[item] = ("usage", reason)
            relabeled += 1
    return {"communities": len(communities), "named": named, "relabeled": relabeled}


# ---------------------------------------------------------------------------
# Excess-privilege index


@dataclass
class PrivilegeContext:
    """Phase 1 structures the EPI is computed from (owned by ``compute_topics``)."""

    graph: CompactGraph
    direct: dict[int, set[int]]
    hops: dict[int, list[int]]
    hubs: set[int]
    weight: dict[int, int]
    restricted: bytearray
    role_rows: dict[int, dict]
    identity_rows: dict[int, dict]
    holders: dict[int, frozenset[int]]  # every role and principal -> H(x)


def _empty(row: dict, basis: str) -> None:
    row.update(
        basis=basis,
        needed_weight=0,
        needed_weight_excl_hubs=0,
        used_resources=0,
        unused_grants=0,
        unused_restricted=0,
        dormant=False,
        hint_conflict=False,
    )


def compute_privilege(context: PrivilegeContext, usage: UsageInput | None) -> dict:
    """Add needed weights, basis and counts to every role and identity row; returns timings."""
    rows = {**context.role_rows, **context.identity_rows}
    if usage is None or not usage.present:
        for row in rows.values():
            _empty(row, "none")
        return {"basis": "none"}
    import time

    started = time.perf_counter()
    graph, direct, hops, hubs, weight = (
        context.graph,
        context.direct,
        context.hops,
        context.hubs,
        context.weight,
    )
    restricted, holders_of = context.restricted, context.holders
    data_used, assumed, share = usage.data_used, usage.assumed, usage.peer_share
    sufficient = usage.evidence.sufficient_services

    # Services per holder (its own grants) and observed hops (observed assumptions that are graph hops).
    services: dict[int, frozenset[str]] = {
        holder: frozenset(data_service(graph, item) for item in items) for holder, items in direct.items()
    }
    observed_hops: dict[int, list[int]] = {}
    for source, targets in assumed.items():
        allowed = set(hops.get(source, ()))
        reached = sorted(target for target in targets if target in allowed)
        if reached:
            observed_hops[source] = reached

    def topic_of(node: int) -> int:
        row = rows.get(node)
        return row["topic"] if row is not None else -1

    # Peer baseline: per (topic, data) grant and use counts among non-hub holders.
    granted_by: Counter = Counter()
    used_by: Counter = Counter()
    for holder, items in direct.items():
        if holder in hubs:
            continue
        topic = topic_of(holder)
        if topic < 0:
            continue
        used = data_used.get(holder, ())
        for item in items:
            granted_by[(topic, item)] += 1
            if item in used:
                used_by[(topic, item)] += 1
    peer_needed: dict[int, frozenset[int]] = {}
    for holder, items in direct.items():
        topic = topic_of(holder)
        peer_needed[holder] = frozenset(
            item
            for item in items
            if topic >= 0
            and granted_by[(topic, item)]
            and used_by[(topic, item)] >= share * granted_by[(topic, item)]
        )
    del granted_by, used_by

    def observed_reach(start: int) -> frozenset[int]:
        seen = {start}
        frontier = [start]
        for _ in range(MAX_HOPS - 1):
            following = []
            for current in frontier:
                for target in observed_hops.get(current, ()):
                    if target not in seen:
                        seen.add(target)
                        following.append(target)
            if not following:
                break
            frontier = following
        return frozenset(seen)

    def granted(item: int, holders) -> bool:
        return any(item in direct[h] for h in holders)

    used_cache: dict[tuple[frozenset[int], frozenset[int]], tuple[int, int]] = {}

    def used(holders: frozenset[int], reach: frozenset[int]) -> tuple[int, int]:
        """(weight, count) of data used by ``reach`` within the grants of ``holders``."""
        key = (holders, reach)
        found = used_cache.get(key)
        if found is None:
            items: set[int] = set()
            for member in reach:
                for item in data_used.get(member, ()):
                    if item not in items and granted(item, holders):
                        items.add(item)
            found = (sum(weight[item] for item in items), len(items))
            used_cache[key] = found
        return found

    inferred_cache: dict[frozenset[int], frozenset[int]] = {}

    def inferred_set(holders: frozenset[int]) -> frozenset[int]:
        found = inferred_cache.get(holders)
        if found is None:
            merged: set[int] = set()
            for holder in holders:
                merged |= peer_needed[holder]
            found = frozenset(merged)
            inferred_cache[holders] = found
        return found

    def services_of(node: int, holders: frozenset[int]) -> frozenset[str]:
        found: set[str] = set()
        for holder in holders:
            found |= services[holder]
        if hops.get(node):
            found.add(ASSUME_SERVICE)
        return frozenset(found)

    window_start = usage.evidence.window_start

    def own_counts(node: int, needed_direct) -> tuple[int, int]:
        unused = unused_restricted = 0
        for item in direct.get(node, ()):
            if item not in needed_direct:
                unused += 1
                unused_restricted += restricted[item]
        return unused, unused_restricted

    # Roles first (identities derive from role-level inferred sets).
    role_started = time.perf_counter()
    role_core: dict[int, frozenset[int]] = {}
    for role, row in context.role_rows.items():
        holders = holders_of[role]
        excluded = hubs - {role}
        core = frozenset(h for h in holders if h not in excluded)
        role_core[role] = core
        role_services = services_of(role, holders)
        basis = "used" if role_services <= sufficient else "inferred"
        if basis == "used":
            reach = observed_reach(role)
            needed, count = used(holders, reach)
            needed_core, _ = used(core, frozenset(v for v in reach if v not in excluded))
            needed_direct = data_used.get(role, frozenset())
        else:
            items = inferred_set(holders)
            needed, count = sum(weight[i] for i in items), len(items)
            needed_core = sum(weight[i] for i in inferred_set(core))
            needed_direct = peer_needed.get(role, frozenset())
        unused, unused_restricted = own_counts(role, needed_direct)
        dormant = (
            basis == "used"
            and bool(role_services)
            and role not in usage.active
            and role not in usage.assumed_by_any
        )
        last_used = graph.last_used.get(role)
        conflict = bool(dormant and last_used and window_start and _after(last_used, window_start))
        row.update(
            basis=basis,
            needed_weight=needed,
            needed_weight_excl_hubs=needed_core,
            used_resources=count,
            unused_grants=unused,
            unused_restricted=unused_restricted,
            dormant=dormant,
            hint_conflict=conflict,
        )
    role_ms = round((time.perf_counter() - role_started) * 1000)

    # Identity peer baseline over directly assumable roles.
    can_assume: dict[int, list[int]] = {
        node: [t for t in hops.get(node, ()) if t in context.role_rows] for node in context.identity_rows
    }
    assumable: Counter = Counter()
    assumed_peers: Counter = Counter()
    for node, row in context.identity_rows.items():
        if row["topic"] < 0:
            continue
        observed_roles = assumed.get(node, ())
        for role in can_assume[node]:
            assumable[(row["topic"], role)] += 1
            if role in observed_roles:
                assumed_peers[(row["topic"], role)] += 1
    for node, row in context.identity_rows.items():
        holders = holders_of[node]
        core = frozenset(h for h in holders if h not in hubs)
        basis = "used" if services_of(node, holders) <= sufficient else "inferred"
        if basis == "used":
            reach = observed_reach(node)
            needed, count = used(holders, reach)
            needed_core, _ = used(core, frozenset(v for v in reach if v not in hubs))
            needed_direct = data_used.get(node, frozenset())
        else:
            topic = row["topic"]
            chosen = [
                role
                for role in can_assume[node]
                if topic >= 0
                and assumable[(topic, role)]
                and assumed_peers[(topic, role)] >= share * assumable[(topic, role)]
            ]
            own = peer_needed.get(node, frozenset())
            full_items = set(own)
            core_items = set(own)
            for role in chosen:
                full_items |= inferred_set(holders_of[role])
                if role not in hubs:
                    core_items |= inferred_set(role_core[role])
            full_items = {item for item in full_items if granted(item, holders)}
            core_items = {item for item in core_items if granted(item, core)}
            needed, count = sum(weight[i] for i in full_items), len(full_items)
            needed_core = sum(weight[i] for i in core_items)
            needed_direct = own
        unused, unused_restricted = own_counts(node, needed_direct)
        row.update(
            basis=basis,
            needed_weight=needed,
            needed_weight_excl_hubs=needed_core,
            used_resources=count,
            unused_grants=unused,
            unused_restricted=unused_restricted,
            # Zero use is only meaningful where some of its access is covered.
            dormant=basis == "used" and bool(services_of(node, holders)) and node not in usage.active,
            hint_conflict=False,
        )
    return {
        "basis": "evidence",
        "role_ms": role_ms,
        "total_ms": round((time.perf_counter() - started) * 1000),
        "distinct_used_sets": len(used_cache),
    }


def _after(value: str, start: datetime) -> bool:
    try:
        return utc(datetime.fromisoformat(value.replace("Z", "+00:00"))) >= start
    except ValueError:
        return False


def epi(granted: int, needed: int) -> float | None:
    return 1 - needed / granted if granted else None


def aggregate(rows) -> dict:
    """Weighted EPI with and without hubs over ``rows``, plus counts by basis."""
    granted = needed = granted_core = needed_core = 0
    bases: Counter = Counter()
    for row in rows:
        bases[row["basis"]] += 1
        if row["basis"] == "none":
            continue
        granted += row["reach_weight"]
        needed += row["needed_weight"]
        granted_core += row["reach_weight_excl_hubs"]
        needed_core += row["needed_weight_excl_hubs"]
    return {
        "granted_weight": granted,
        "needed_weight": needed,
        "granted_weight_excl_hubs": granted_core,
        "needed_weight_excl_hubs": needed_core,
        "epi": epi(granted, needed),
        "epi_excl_hubs": epi(granted_core, needed_core),
        "basis": {basis: bases.get(basis, 0) for basis in BASES},
    }
