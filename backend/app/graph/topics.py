"""Publish-time relationship topics and structural (granted) privilege analysis.

A **topic** is a named group of data assets that belong to one system or workload
(``data-lake``, ``payments-db``, ``ci-cd``...). Topics are anchored on the
resources themselves, deterministically, and every label records its reason:

1. **Tags.** ``topic=``, then ``app=``/``application=``, ``project=``/``workload=``,
   then ``team=`` tags (``key=value`` or ``key:value``), then the same keys as string
   metadata. The value, normalized, names the topic.
2. **Name tokens.** Tokens of tagged assets' names that are specific to one topic
   (at least ``MIN_TOKEN_SUPPORT`` tagged assets, ``MIN_TOKEN_SHARE`` of them in one
   topic) label untagged assets whose names carry them.
3. **Co-access.** Every grant holder (a role, or an identity with direct grants)
   gets a preliminary topic: the plurality of its labeled grants. An unlabeled asset
   takes the plurality topic of the non-hub holders granted on it
   (``PROPAGATION_ROUNDS`` rounds).
4. **Service type and data category.** Assets with no signal at all are grouped as
   fallback topics by node type and classification category ("Unassigned S3 buckets
   (PII)").

Roles and identities then get a **topic profile**: the share of their granted
sensitivity weight (1/2/5/10 by sensitivity) per topic. Their **primary topic** is
the topic holding most of their granted assets (ties: more weight, then name).
Reach is computed per grant-holder set: a role's or identity's effective holders are
the nodes reachable over role/tool edges within the analysis hop bound, each
distinct holder set is evaluated once (the role-level computation identities
derive from), and hub roles are reported separately (hub-decomposed).

**Everything here is granted (structural) access, not needed access.** No usage
evidence is read; a cross-topic grant may be legitimate. Topics are derived from
resource tags, names and access and are not policy boundaries. Flags:

* ``hub``: a role granted on at least ``max(HUB_MIN_RESOURCES, HUB_SHARE`` of all
  data assets``)`` directly;
* ``via_hub``: reaches a hub role (identities and roles that can assume one);
* ``privileged``: marked privileged, or a grant with a wildcard action (``*``,
  ``service:*``); for identities, reaching such a role;
* ``cross_topic``: a role holding grants on assets of another topic; an identity
  whose non-hub roles have different primary topics;
* ``restricted_outside``: transitive reach to restricted data outside the primary topic.

Rows are stored in PostgreSQL keyed by (tenant, revision) in the publication
transaction, deleted by retention with the revision, carried by the database
backup, and backfilled for current revisions by the worker sweep, exactly like the
global-map clusters (``app.graph.clusters``).
"""

import argparse
import hashlib
import json
import re
import time
from array import array
from collections import Counter
from dataclasses import dataclass, field

from pydantic import BaseModel
from sqlalchemy import delete, func, select, text
from sqlalchemy.orm import Session

from app.db.locks import acquire_publication_lock, try_publication_lock
from app.db.models import (
    RevisionTopic,
    RevisionTopicLink,
    RevisionTopicMember,
    RevisionTopicSummary,
    TenantState,
)
from app.db.session import session_factory
from app.graph.compact import DATA, EDGE_CODE, MAX_HOPS, WEIGHT, CompactGraph
from app.graph.privilege import (
    PrivilegeContext,
    UsageInput,
    aggregate,
    compute_privilege,
    data_service,
    refine_with_usage,
)
from app.graph.repository import get_graph_store
from app.graph.schema import EdgeType, NodeType
from app.graph.sweep import SWEEP_TENANTS, run_sweep

# Bump when topic labels, profiles, flags or stored fields change: other versions read as missing.
# 2: usage refinement, excess-privilege index (needed weights, basis, unused, dormant).
TOPIC_VERSION = 2
BASIS = "granted (structural)"
NOTICE = (
    "Topics are derived from resource tags, names and access. They are not policy boundaries. "
    "Profiles and flags describe granted (structural) access, not what is needed or used."
)
# Tag keys that name a topic, by priority (lower wins).
TOPIC_KEYS = {
    "topic": 0,
    "app": 1,
    "application": 1,
    "project": 2,
    "workload": 2,
    "team": 3,
}
MIN_TOKEN_SUPPORT = 5
MIN_TOKEN_SHARE = 0.8
PROPAGATION_ROUNDS = 2
HUB_MIN_RESOURCES = 50
HUB_SHARE = 0.02
PROFILE_TOPICS = 5
MAX_MAP_TOPICS = 300
MAX_PAGE = 500
TOP_ROLES = 10

PRINCIPALS = frozenset(
    kind.value for kind in (NodeType.HUMAN, NodeType.SERVICE, NodeType.AGENT, NodeType.MCP)
)
ROLE = NodeType.ROLE.value
GRANT_CODES = frozenset({EDGE_CODE[EdgeType.READ.value], EDGE_CODE[EdgeType.WRITE.value]})
HOP_CODES = frozenset(
    {EDGE_CODE[EdgeType.ASSUMES.value], EDGE_CODE[EdgeType.INHERITS.value], EDGE_CODE[EdgeType.INVOKES.value]}
)
CATEGORY_CODE = EDGE_CODE[EdgeType.PII.value]
RESTRICTED = "restricted"
TYPE_NAMES = {
    NodeType.DATABASE.value: "databases",
    NodeType.BUCKET.value: "S3 buckets",
    NodeType.VECTOR.value: "vector stores",
}

# Member flags (bitmask).
HUB, VIA_HUB, PRIVILEGED, CROSS_TOPIC, RESTRICTED_OUTSIDE, DORMANT = 1, 2, 4, 8, 16, 32
FLAG_NAMES = [
    (HUB, "hub"),
    (VIA_HUB, "via_hub"),
    (PRIVILEGED, "privileged"),
    (CROSS_TOPIC, "cross_topic"),
    (RESTRICTED_OUTSIDE, "restricted_outside"),
    (DORMANT, "dormant"),
]
# Seed kinds, in label priority.
SEEDS = ("tag", "metadata", "name", "usage", "coaccess", "fallback")

_TOKEN = re.compile(r"[a-z0-9]+")
_SLUG = re.compile(r"[^a-z0-9.]+")


def normalize(value: str) -> str:
    """Topic name from a tag value: lowercase, runs of other characters become "-", 64 chars."""
    return _SLUG.sub("-", value.strip().lower()).strip("-.")[:64].strip("-.")


def tag_topic(values: tuple[str, ...]) -> tuple[str, str] | None:
    """(topic name, "key=value" source) of the highest-priority topic tag, or None."""
    best = None
    for raw in values:
        for separator in ("=", ":"):
            key, found, value = raw.partition(separator)
            if found:
                break
        else:
            continue
        priority = TOPIC_KEYS.get(key.strip().lower())
        name = normalize(value) if priority is not None else ""
        if name and (best is None or priority < best[0]):
            best = (priority, name, f"{key.strip().lower()}={value.strip()}"[:120])
    return (best[1], best[2]) if best else None


def name_tokens(name: str) -> set[str]:
    return {token for token in _TOKEN.findall(name.lower()) if len(token) >= 2 and not token.isdigit()}


def topic_id(kind: str, name: str) -> str:
    """Stable across revisions: the same topic name always has the same ID."""
    return "t" + hashlib.sha256(f"{kind}:{name}".encode()).hexdigest()[:15]


def is_wildcard(action: str) -> bool:
    return action == "*" or action.endswith(":*")


@dataclass
class Topic:
    name: str
    kind: str  # "anchored" or "fallback"
    label: str
    id: str = ""
    resources: list[int] = field(default_factory=list)
    seeds: Counter = field(default_factory=Counter)
    sources: Counter = field(default_factory=Counter)  # "tag topic=x" -> count


@dataclass
class Profile:
    """Granted reach of one grant-holder set (identities and roles share these)."""

    count: int
    weight: int
    restricted: int
    # Top topics by weight: (topic index, weight, count, restricted).
    topics: list[tuple[int, int, int, int]]
    primary: int  # topic index or -1
    tied: tuple[int, ...]  # topics sharing the primary's asset count (primary first)
    restricted_by_topic: dict[int, int]  # non-zero entries only

    def restricted_outside(self, primary: int) -> int:
        return self.restricted - self.restricted_by_topic.get(primary, 0)


@dataclass
class ComputedTopics:
    graph: CompactGraph
    topics: list[Topic]
    resource_topic: array  # topic index per node (-1: not a data asset)
    resource_seed: dict[int, tuple[str, str]]  # data node -> (seed kind, reason)
    roles: dict[int, dict]  # node -> member stats
    identities: dict[int, dict]
    topic_stats: list[dict]
    links: dict[tuple[int, int], int]
    summary: dict
    compute_ms: int
    # Structures the optimizer proposals reuse (``app.graph.proposals``): grants, hops, hubs,
    # holder sets and peer statistics, plus the usage the analysis read.
    context: PrivilegeContext | None = None
    usage: UsageInput | None = None
    wildcard: frozenset[int] = frozenset()


def compute_topics(graph: CompactGraph, usage: UsageInput | None = None) -> ComputedTopics:
    """Topics, profiles and flags; with ``usage``, usage refinement and the EPI too."""
    started = time.perf_counter()
    n = graph.node_count
    types, names, sensitivity = graph.types, graph.names, graph.sensitivity
    is_data = bytearray(kind in DATA for kind in types)
    data_nodes = [i for i in range(n) if is_data[i]]
    weight = {i: WEIGHT.get(sensitivity[i], 0) for i in data_nodes}

    # Direct grants per holder (a non-data node with READ/WRITE edges to data), role/tool hops,
    # wildcard actions and classification categories, from one pass over the edges.
    direct: dict[int, set[int]] = {}
    hops: dict[int, list[int]] = {}
    wildcard: set[int] = set()
    category: dict[int, str] = {}
    kinds, sources, targets, actions = (
        graph.edge_kind,
        graph.edge_source,
        graph.edge_target,
        graph.edge_actions,
    )
    for edge in range(graph.edge_count):
        code, source, target = kinds[edge], sources[edge], targets[edge]
        if code in GRANT_CODES:
            if is_data[target] and not is_data[source]:
                direct.setdefault(source, set()).add(target)
                if source not in wildcard and any(is_wildcard(a) for a in actions[edge]):
                    wildcard.add(source)
        elif code in HOP_CODES:
            if not is_data[source] and not is_data[target] and source != target:
                hops.setdefault(source, []).append(target)
        elif code == CATEGORY_CODE and is_data[source]:
            label = names[target]
            if source not in category or label < category[source]:
                category[source] = label
    granted_on: dict[int, list[int]] = {}
    for holder in sorted(direct):
        for item in direct[holder]:
            granted_on.setdefault(item, []).append(holder)
    hub_cut = max(HUB_MIN_RESOURCES, int(HUB_SHARE * len(data_nodes)))
    hubs = {holder for holder, items in direct.items() if len(items) >= hub_cut}

    # 1. Seeds: tags, then metadata hints.
    label: dict[int, str] = {}
    seed: dict[int, tuple[str, str]] = {}
    for item in data_nodes:
        found = tag_topic(graph.tags[item])
        kind = "tag"
        if found is None and item in graph.hints:
            found, kind = tag_topic(graph.hints[item]), "metadata"
        if found is not None:
            label[item] = found[0]
            seed[item] = (kind, f"{kind} {found[1]}")
    # 2. Name tokens specific to one tagged topic.
    support: dict[str, Counter] = {}
    for item, topic in label.items():
        for token in name_tokens(names[item]):
            support.setdefault(token, Counter())[topic] += 1
    vocabulary: dict[str, tuple[str, float]] = {}
    for token, counts in support.items():
        total = sum(counts.values())
        topic, hits = min(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        if total >= MIN_TOKEN_SUPPORT and hits / total >= MIN_TOKEN_SHARE:
            vocabulary[token] = (topic, hits / total)
    del support

    def from_name(name: str) -> tuple[str, float, str] | None:
        """(topic, token share, token) when a name's specific tokens point to one topic."""
        scores: dict[str, float] = {}
        strongest: dict[str, tuple[float, str]] = {}
        for token in name_tokens(name):
            match = vocabulary.get(token)
            if match is None:
                continue
            topic, share = match
            scores[topic] = scores.get(topic, 0.0) + share
            if topic not in strongest or (share, token) > strongest[topic]:
                strongest[topic] = (share, token)
        if not scores:
            return None
        ranked = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
        if len(ranked) > 1 and ranked[1][1] == ranked[0][1]:
            return None  # Ambiguous name.
        topic = ranked[0][0]
        return topic, *strongest[topic]

    if vocabulary:
        for item in data_nodes:
            if item in label:
                continue
            found = from_name(names[item])
            if found is not None:
                topic, share, token = found
                label[item] = topic
                seed[item] = (
                    "name",
                    f'name token "{token}" ({round(share * 100)}% of tagged assets with it)',
                )
    # 3. Co-access propagation over non-hub grant holders. With sufficient usage evidence for
    # an asset's service, only holders observed using it vote: a never-used grant is not
    # evidence of shared access (it is usually the over-grant the analysis is looking for).
    seeded = set(label)
    users_of: dict[int, set[int]] = {}
    unused_only: set[int] = set()
    observed_votes: set[int] = set()
    if usage is not None and usage.present:
        sufficient = usage.evidence.sufficient_services
        for principal, items in usage.data_used.items():
            for item in items:
                users_of.setdefault(item, set()).add(principal)
        for item in data_nodes:
            if item not in seeded and data_service(graph, item) in sufficient:
                voters = [h for h in granted_on.get(item, ()) if h in users_of.get(item, ())]
                if granted_on.get(item) and not voters:
                    unused_only.add(item)
                granted_on[item] = voters
                observed_votes.add(item)
    for _ in range(PROPAGATION_ROUNDS):
        holder_topic: dict[int, str] = {}
        for holder, items in direct.items():
            if holder in hubs:
                continue
            counts = Counter(label[item] for item in items if item in label)
            if counts:
                holder_topic[holder] = min(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0]
        changed = False
        for item in data_nodes:
            if item in seeded:
                continue
            votes = Counter(holder_topic[h] for h in granted_on.get(item, ()) if h in holder_topic)
            if not votes:
                continue
            topic, hits = min(votes.items(), key=lambda kv: (-kv[1], kv[0]))
            holders_text = "roles observed using it" if item in observed_votes else "granted roles"
            reason = f"co-access: {hits} of {sum(votes.values())} {holders_text} are {topic}"
            if label.get(item) != topic:
                changed = True
            label[item] = topic
            seed[item] = ("coaccess", reason)
        if not changed:
            break
    del seeded
    # 3b. Hybrid refinement: usage co-access communities name weakly labeled assets.
    refine_started = time.perf_counter()
    refinement = (
        refine_with_usage(graph, usage, label, seed, hubs)
        if usage is not None and usage.present
        else {"communities": 0, "named": 0, "relabeled": 0}
    )
    refinement["ms"] = round((time.perf_counter() - refine_started) * 1000)

    # 4. Topics, plus fallback groups by service type and data category.
    topics: list[Topic] = []
    index: dict[tuple[str, str], int] = {}
    resource_topic = array("l", [-1]) * n

    def topic_for(kind: str, name: str, text_label: str) -> int:
        key = (kind, name)
        if key not in index:
            index[key] = len(topics)
            topics.append(Topic(name, kind, text_label, topic_id(kind, name)))
        return index[key]

    for item in data_nodes:
        if item in label:
            position = topic_for("anchored", label[item], label[item])
            kind, reason = seed[item]
            topics[position].sources[reason if kind in ("tag", "metadata") else kind] += 1
        else:
            group = TYPE_NAMES.get(types[item], types[item])
            cat = category.get(item, "")
            name = f"unassigned-{normalize(types[item])}" + (f"-{normalize(cat)}" if cat else "")
            text_label = f"Unassigned {group}" + (f" ({cat})" if cat else "")
            position = topic_for("fallback", name, text_label)
            signal = (
                "granted but never used in the evidence window" if item in unused_only else "access signal"
            )
            reason = f"no tag, name or {signal}; grouped by type {types[item]}" + (
                f" and category {cat}" if cat else ""
            )
            seed[item] = ("fallback", reason)
            topics[position].sources["fallback"] += 1
        resource_topic[item] = position
        topics[position].resources.append(item)
        topics[position].seeds[seed[item][0]] += 1
    del label

    # 5. Profiles per distinct grant-holder set (role level; identities derive from it).
    through: dict[int, frozenset[int]] = {}  # start -> non-holder nodes its hops pass through

    def holder_set(start: int) -> tuple[frozenset[int], bool]:
        """Grant holders reachable over role/tool hops (the data hop counts toward MAX_HOPS),
        and whether a privileged node is reached."""
        seen = {start}
        frontier = [start]
        for _ in range(MAX_HOPS - 1):
            following = []
            for current in frontier:
                for target in hops.get(current, ()):
                    if target not in seen:
                        seen.add(target)
                        following.append(target)
            if not following:
                break
            frontier = following
        holders = frozenset(node for node in seen if node in direct)
        if len(seen) > len(holders) + 1:
            through[start] = frozenset(node for node in seen if node not in direct and node != start)
        return holders, not privileged_nodes.isdisjoint(seen)

    privileged_nodes = {i for i in range(n) if graph.privileged[i]} | wildcard
    by_size = {holder: len(items) for holder, items in direct.items()}
    is_restricted = bytearray(n)
    for item in data_nodes:
        if sensitivity[item] == RESTRICTED:
            is_restricted[item] = 1

    def accumulate(items, stats: dict[int, list[int]], totals: list[int], skip=None) -> None:
        """Add ``items`` (minus ``skip``) to per-topic [weight, count, restricted] and totals."""
        for item in items:
            if skip is not None and item in skip:
                continue
            w, r = weight[item], is_restricted[item]
            row = stats.get(resource_topic[item])
            if row is None:
                stats[resource_topic[item]] = [w, 1, r]
            else:
                row[0] += w
                row[1] += 1
                row[2] += r
            totals[0] += 1
            totals[1] += w
            totals[2] += r

    # Each holder's own grants are summed once; a holder set adds only what its
    # largest holder lacks.
    own: dict[int, tuple[dict[int, list[int]], list[int]]] = {}
    for holder, items in direct.items():
        stats: dict[int, list[int]] = {}
        totals = [0, 0, 0]
        accumulate(items, stats, totals)
        own[holder] = (stats, totals)
    cache: dict[frozenset[int], Profile] = {}

    def profile(holders: frozenset[int]) -> Profile:
        found = cache.get(holders)
        if found is not None:
            return found
        stats: dict[int, list[int]] = {}
        totals = [0, 0, 0]
        if holders:
            ordered = sorted(holders, key=lambda h: (-by_size[h], h))
            base_stats, base_totals = own[ordered[0]]
            stats = {topic: list(row) for topic, row in base_stats.items()}
            totals = list(base_totals)
            if len(ordered) > 1:
                base = direct[ordered[0]]
                extra: set[int] = set()
                for holder in ordered[1:]:
                    extra |= direct[holder]
                accumulate(extra, stats, totals, base)
        ranked = sorted(stats.items(), key=lambda kv: (-kv[1][0], topics[kv[0]].name))
        by_count = sorted(stats.items(), key=lambda kv: (-kv[1][1], -kv[1][0], topics[kv[0]].name))
        primary = by_count[0][0] if by_count else -1
        result = Profile(
            totals[0],
            totals[1],
            totals[2],
            [(t, w, c, r) for t, (w, c, r) in ranked[:PROFILE_TOPICS]],
            primary,
            tuple(t for t, row in by_count if row[1] == by_count[0][1][1]),
            {t: r for t, (_, _, r) in stats.items() if r},
        )
        cache[holders] = result
        return result

    role_rows: dict[int, dict] = {}
    holders_of: dict[int, frozenset[int]] = {}
    for role in range(n):
        if types[role] != ROLE:
            continue
        holders, _ = holder_set(role)
        holders_of[role] = holders
        own_hub = role in hubs
        others = holders - hubs if not own_hub else holders - (hubs - {role})
        full = profile(holders)
        core = profile(others) if others != holders else full
        flags = 0
        if own_hub:
            flags |= HUB
        if holders & hubs - {role}:
            flags |= VIA_HUB
        if role in privileged_nodes:
            flags |= PRIVILEGED
        basis = core if core.count else full
        primary = basis.primary
        if len(basis.tied) > 1 and vocabulary:
            # Equal asset counts: a topic named by the role's own name wins the tie.
            hint = from_name(names[role])
            if hint is not None:
                named = next((t for t in basis.tied if topics[t].name == hint[0]), -1)
                if named >= 0:
                    primary = named
        cross = cross_weight = 0
        own_weight = 0
        for item in direct.get(role, ()):
            own_weight += weight[item]
            topic = resource_topic[item]
            if primary >= 0 and topic != primary and topics[topic].kind == "anchored":
                cross += 1
                cross_weight += weight[item]
        if cross:
            flags |= CROSS_TOPIC
        restricted_outside = full.restricted_outside(primary)
        if restricted_outside:
            flags |= RESTRICTED_OUTSIDE
        role_rows[role] = {
            "topic": primary,
            "flags": flags,
            "direct": len(direct.get(role, ())),
            "own_weight": own_weight,
            "reach": full.count,
            "reach_weight": full.weight,
            "reach_weight_excl_hubs": core.weight,
            "cross": cross,
            "cross_weight": cross_weight,
            "restricted_outside": restricted_outside,
            "profile": core.topics if core.count else full.topics,
            "profile_weight": core.weight if core.count else full.weight,
        }

    identity_rows: dict[int, dict] = {}
    for node in range(n):
        if types[node] not in PRINCIPALS:
            continue
        holders, reached_privileged = holder_set(node)
        holders_of[node] = holders
        others = holders - hubs
        full = profile(holders)
        core = profile(others) if others != holders else full
        flags = 0
        if holders & hubs:
            flags |= VIA_HUB
        if reached_privileged:
            flags |= PRIVILEGED
        primary = core.primary if core.count else full.primary
        role_topics = {role_rows[h]["topic"] for h in others if h in role_rows and role_rows[h]["topic"] >= 0}
        if len(role_topics) > 1:
            flags |= CROSS_TOPIC
        restricted_outside = full.restricted_outside(primary)
        if restricted_outside:
            flags |= RESTRICTED_OUTSIDE
        identity_rows[node] = {
            "topic": primary,
            "flags": flags,
            "direct": len(direct.get(node, ())),
            "reach": full.count,
            "reach_weight": full.weight,
            "reach_weight_excl_hubs": core.weight,
            "roles": len(holders),
            "restricted_outside": restricted_outside,
            "profile": core.topics if core.count else full.topics,
            "profile_weight": core.weight if core.count else full.weight,
        }
    distinct_sets = len(cache)
    cache.clear()

    # 5b. Excess-privilege index (needed vs granted), role level first.
    context = PrivilegeContext(
        graph, direct, hops, hubs, weight, is_restricted, role_rows, identity_rows, holders_of
    )
    context.through = through
    timings = compute_privilege(context, usage)
    for rows in (role_rows, identity_rows):
        for row in rows.values():
            if row["dormant"]:
                row["flags"] |= DORMANT

    # 6. Per-topic and graph-wide counts (hub-decomposed) and cross-topic links.
    topic_stats = [
        {
            "roles": 0,
            "identities": 0,
            "resource_weight": sum(weight[i] for i in t.resources),
            "grants_out": 0,
            "cross_out": 0,
            "cross_in": 0,
            "hub_grants_in": 0,
            "own_weight": 0,
            "cross_weight": 0,
            "hub_roles": 0,
            "privileged_roles": 0,
            "cross_topic_roles": 0,
            "restricted_outside_roles": 0,
            "via_hub_identities": 0,
            "privileged_identities": 0,
            "cross_topic_identities": 0,
            "restricted_outside_identities": 0,
            "sensitivity": dict(Counter(sensitivity[i] for i in t.resources)),
            "types": dict(Counter(types[i] for i in t.resources)),
        }
        for t in topics
    ]
    links: Counter = Counter()
    for holder in sorted(direct):
        row = role_rows.get(holder) or identity_rows.get(holder)
        primary = row["topic"] if row else -1
        hub = holder in hubs
        for item in direct[holder]:
            topic = resource_topic[item]
            if hub:
                topic_stats[topic]["hub_grants_in"] += 1
                continue
            if primary < 0 or topic == primary:
                continue
            if topics[topic].kind == "anchored" and holder in role_rows:
                topic_stats[topic]["cross_in"] += 1
            links[(primary, topic) if primary < topic else (topic, primary)] += 1
    for row in role_rows.values():
        topic = row["topic"]
        if topic < 0:
            continue
        stats = topic_stats[topic]
        stats["roles"] += 1
        if not row["flags"] & HUB:
            stats["grants_out"] += row["direct"]
            stats["cross_out"] += row["cross"]
            stats["own_weight"] += row["own_weight"]
            stats["cross_weight"] += row["cross_weight"]
        for flag, key in (
            (HUB, "hub_roles"),
            (PRIVILEGED, "privileged_roles"),
            (CROSS_TOPIC, "cross_topic_roles"),
            (RESTRICTED_OUTSIDE, "restricted_outside_roles"),
        ):
            if row["flags"] & flag:
                stats[key] += 1
    for row in identity_rows.values():
        topic = row["topic"]
        if topic < 0:
            continue
        stats = topic_stats[topic]
        stats["identities"] += 1
        for flag, key in (
            (VIA_HUB, "via_hub_identities"),
            (PRIVILEGED, "privileged_identities"),
            (CROSS_TOPIC, "cross_topic_identities"),
            (RESTRICTED_OUTSIDE, "restricted_outside_identities"),
        ):
            if row["flags"] & flag:
                stats[key] += 1

    def flagged(rows: dict[int, dict], flag: int) -> int:
        return sum(1 for row in rows.values() if row["flags"] & flag)

    # Excess privilege per topic (roles and identities by primary topic) and graph-wide.
    def privilege_counts(roles: list[dict], identities: list[dict]) -> dict:
        return {
            "roles": aggregate(roles),
            "identities": aggregate(identities),
            "unused_grants": sum(row["unused_grants"] for row in roles),
            "unused_restricted_grants": sum(row["unused_restricted"] for row in roles),
            "dormant_identities": sum(row["dormant"] for row in identities),
            "dormant_roles": sum(row["dormant"] for row in roles),
            "dormant_role_hint_conflicts": sum(row["hint_conflict"] for row in roles),
        }

    by_topic: dict[int, tuple[list[dict], list[dict]]] = {}
    for rows, slot in ((role_rows, 0), (identity_rows, 1)):
        for row in rows.values():
            if row["topic"] >= 0:
                by_topic.setdefault(row["topic"], ([], []))[slot].append(row)
    for position, stats in enumerate(topic_stats):
        roles_, identities_ = by_topic.get(position, ([], []))
        stats["privilege"] = privilege_counts(roles_, identities_)
    privilege = privilege_counts(list(role_rows.values()), list(identity_rows.values()))
    if usage is not None and usage.present:
        privilege["evidence"] = usage.evidence.as_dict()
        privilege["matched_observations"] = usage.matched
        privilege["unmatched_observations"] = usage.unmatched
        privilege["peer_share"] = usage.peer_share
    else:
        privilege["evidence"] = {"status": "none"}
    privilege["timings_ms"] = timings
    privilege["refinement"] = refinement

    seeds = Counter()
    for t in topics:
        seeds.update(t.seeds)
    summary = {
        "basis": BASIS,
        "resources": len(data_nodes),
        "resource_weight": sum(weight.values()),
        "topics": len(topics),
        "anchored_topics": sum(t.kind == "anchored" for t in topics),
        "fallback_topics": sum(t.kind == "fallback" for t in topics),
        "seeded_resources": {kind: seeds.get(kind, 0) for kind in SEEDS},
        "vocabulary_tokens": len(vocabulary),
        "hub_cut": hub_cut,
        "roles": len(role_rows),
        "roles_with_topic": sum(1 for row in role_rows.values() if row["topic"] >= 0),
        "hub_roles": flagged(role_rows, HUB),
        "privileged_roles": flagged(role_rows, PRIVILEGED),
        "cross_topic_roles": flagged(role_rows, CROSS_TOPIC),
        "restricted_outside_roles": flagged(role_rows, RESTRICTED_OUTSIDE),
        "cross_topic_grants": sum(row["cross"] for row in role_rows.values() if not row["flags"] & HUB),
        "hub_grants": sum(len(direct[h]) for h in hubs),
        "role_granted_weight": sum(row["own_weight"] for row in role_rows.values()),
        "role_granted_weight_excl_hubs": sum(
            row["own_weight"] for row in role_rows.values() if not row["flags"] & HUB
        ),
        "identities": len(identity_rows),
        "identities_with_reach": sum(1 for row in identity_rows.values() if row["reach"]),
        "via_hub_identities": flagged(identity_rows, VIA_HUB),
        "privileged_identities": flagged(identity_rows, PRIVILEGED),
        "cross_topic_identities": flagged(identity_rows, CROSS_TOPIC),
        "restricted_outside_identities": flagged(identity_rows, RESTRICTED_OUTSIDE),
        "identity_reach_weight": sum(row["reach_weight"] for row in identity_rows.values()),
        "identity_reach_weight_excl_hubs": sum(
            row["reach_weight_excl_hubs"] for row in identity_rows.values()
        ),
        "distinct_holder_sets": distinct_sets,
        "privilege": privilege,
        "usage_fingerprint": usage.evidence.fingerprint if usage is not None else "",
    }
    return ComputedTopics(
        graph,
        topics,
        resource_topic,
        {item: seed[item] for item in data_nodes},
        role_rows,
        identity_rows,
        topic_stats,
        dict(links),
        summary,
        round((time.perf_counter() - started) * 1000),
        context,
        usage,
        frozenset(wildcard),
    )


# ---------------------------------------------------------------------------
# Storage


def _flag_count(flags: int) -> int:
    return bin(flags).count("1")


def _reason(topic: Topic) -> str:
    """How a topic was named and populated, from its seed sources (deterministic)."""
    if topic.kind == "fallback":
        return (
            f"No tag, name or access signal on these {topic.seeds['fallback']:,} assets; "
            "grouped by service type and data category"
        )
    parts = [
        f"{source.split(' ', 1)[1]} on {count:,} assets"
        for source, count in sorted(
            ((s, c) for s, c in topic.sources.items() if s not in ("name", "usage", "coaccess", "fallback")),
            key=lambda item: (-item[1], item[0]),
        )[:3]
    ]
    text_ = "Tagged " + "; ".join(parts) if parts else "Named"
    if topic.seeds["name"]:
        text_ += f"; {topic.seeds['name']:,} more by name tokens"
    if topic.seeds["usage"]:
        text_ += f"; {topic.seeds['usage']:,} by observed co-use"
    if topic.seeds["coaccess"]:
        text_ += f"; {topic.seeds['coaccess']:,} by shared access"
    return text_[:512]


def topic_order(computed: ComputedTopics) -> list[int]:
    """Anchored topics before fallback groups, each by resource weight, then name."""
    return sorted(
        range(len(computed.topics)),
        key=lambda t: (
            computed.topics[t].kind != "anchored",
            -computed.topic_stats[t]["resource_weight"],
            computed.topics[t].name,
        ),
    )


def member_rows(computed: ComputedTopics, tenant: str, revision: str):
    """Every data asset, role and identity of the revision, ranked within (topic, kind)."""
    graph, topics = computed.graph, computed.topics
    ids, names, types, sensitivity = graph.ids, graph.names, graph.types, graph.sensitivity

    def profile(row: dict) -> list:
        total = row["profile_weight"]
        return [[topics[t].id, round(w / total, 4) if total else 0.0, c] for t, w, c, _ in row["profile"]]

    resources: dict[int, list[int]] = {}
    for position, topic in enumerate(topics):
        resources[position] = sorted(topic.resources, key=lambda i: (-WEIGHT.get(sensitivity[i], 0), ids[i]))
    for position, members in resources.items():
        topic_ref = topics[position].id
        for ordinal, item in enumerate(members):
            kind, reason = computed.resource_seed[item]
            yield (
                tenant, revision, ids[item], topic_ref, "resource", ordinal, names[item][:256], types[item],
                sensitivity[item], kind, reason[:256], 0, 0, 0, 0, 0, 0, 0, [], "", 0, 0, 0, 0, 0,
            )  # fmt: skip
    for kind, rows, rank in (
        (
            "role",
            computed.roles,
            lambda i, r: (-_flag_count(r["flags"]), -r["cross_weight"], -r["reach_weight"], ids[i]),
        ),
        (
            "identity",
            computed.identities,
            lambda i, r: (-_flag_count(r["flags"]), -r["reach_weight"], ids[i]),
        ),
    ):
        grouped: dict[int, list[int]] = {}
        for node, row in rows.items():
            grouped.setdefault(row["topic"], []).append(node)
        for topic, members in sorted(grouped.items()):
            topic_ref = topics[topic].id if topic >= 0 else ""
            members.sort(key=lambda i: rank(i, rows[i]))
            for ordinal, node in enumerate(members):
                row = rows[node]
                yield (
                    tenant, revision, ids[node], topic_ref, kind, ordinal, names[node][:256], types[node], "",
                    "", "", row["flags"], row["direct"], row["reach"], row["reach_weight"],
                    row["reach_weight_excl_hubs"], row.get("cross", 0), row["restricted_outside"], profile(row),
                    row["basis"], row["needed_weight"], row["needed_weight_excl_hubs"], row["used_resources"],
                    row["unused_grants"], row["unused_restricted"],
                )  # fmt: skip


MEMBER_COLUMNS = [
    "tenant_id", "revision", "entity_id", "topic_id", "kind", "ordinal", "name", "entity_type", "sensitivity",
    "seed", "reason", "flags", "direct_grants", "reach_resources", "reach_weight", "reach_weight_excl_hubs",
    "cross_topic_grants", "restricted_outside", "profile", "basis", "needed_weight", "needed_weight_excl_hubs",
    "used_resources", "unused_grants", "unused_restricted",
]  # fmt: skip


def store_topics(db: Session, tenant: str, revision: str, computed: ComputedTopics) -> None:
    """Stage rows in the caller's transaction, which also advances the revision pointer."""
    from app.graph.clusters import _bulk_insert

    topics, stats = computed.topics, computed.topic_stats
    shown = {computed.topics[t].id for t in topic_order(computed)[:MAX_MAP_TOPICS]}
    db.add(
        RevisionTopicSummary(
            tenant_id=tenant,
            revision=revision,
            topic_version=TOPIC_VERSION,
            usage_fingerprint=computed.summary.get("usage_fingerprint", ""),
            total_topics=len(topics),
            total_links=len(computed.links),
            totals={
                **computed.summary,
                "map_links": sum(
                    1 for a, b in computed.links if topics[a].id in shown and topics[b].id in shown
                ),
            },
            compute_ms=computed.compute_ms,
        )
    )
    db.flush()

    flagged: Counter = Counter(row["topic"] for row in computed.roles.values() if row["flags"])

    def topic_rows():
        for ordinal, t in enumerate(topic_order(computed)):
            topic, s = topics[t], stats[t]
            overprivileged = flagged[t]
            extra = {
                key: value
                for key, value in s.items()
                if key
                not in ("roles", "identities", "resource_weight", "cross_out", "cross_in", "hub_grants_in")
            }
            extra["seeds"] = {kind: topic.seeds.get(kind, 0) for kind in SEEDS}
            yield (
                tenant, revision, topic.id, ordinal, topic.name[:128], topic.label[:256], topic.kind,
                _reason(topic), len(topic.resources), s["resource_weight"], s["roles"], s["identities"],
                s["cross_out"], s["cross_in"], s["hub_grants_in"], overprivileged, extra,
            )  # fmt: skip

    _bulk_insert(
        db,
        RevisionTopic,
        [
            "tenant_id",
            "revision",
            "topic_id",
            "ordinal",
            "name",
            "label",
            "kind",
            "reason",
            "resources",
            "resource_weight",
            "roles",
            "identities",
            "cross_grants_out",
            "cross_grants_in",
            "hub_grants_in",
            "overprivileged_roles",
            "stats",
        ],  # fmt: skip
        topic_rows(),
    )
    _bulk_insert(
        db,
        RevisionTopicLink,
        ["tenant_id", "revision", "source_id", "target_id", "weight"],
        (
            (tenant, revision, *sorted((topics[a].id, topics[b].id)), weight)
            for (a, b), weight in sorted(computed.links.items())
        ),
    )
    _bulk_insert(db, RevisionTopicMember, MEMBER_COLUMNS, member_rows(computed, tenant, revision))


def delete_topics(db: Session, tenant: str, revision: str) -> None:
    """Remove a revision's topic rows; call in the transaction holding the publication lock."""
    for model in (RevisionTopicMember, RevisionTopicLink, RevisionTopic, RevisionTopicSummary):
        db.execute(delete(model).where(model.tenant_id == tenant, model.revision == revision))


def stored_topic_summary(db: Session, tenant: str, revision: str) -> RevisionTopicSummary | None:
    if not revision:
        return None
    row = db.get(RevisionTopicSummary, (tenant, revision))
    return row if isinstance(row, RevisionTopicSummary) and row.topic_version == TOPIC_VERSION else None


# ---------------------------------------------------------------------------
# Read API


class TopicFlagCounts(BaseModel):
    hub_roles: int
    privileged_roles: int
    cross_topic_roles: int
    restricted_outside_roles: int
    via_hub_identities: int
    privileged_identities: int
    cross_topic_identities: int
    restricted_outside_identities: int


class TopicSummary(BaseModel):
    id: str
    name: str
    label: str
    kind: str  # "anchored" (tags, names, access) or "fallback" (service type and category)
    reason: str
    resources: int
    resource_weight: int
    roles: int
    identities: int
    # Grants (hub roles excluded) from this topic's roles to other topics' assets, and into
    # this topic's assets from other topics' roles; grants into it from hub roles.
    cross_grants_out: int
    cross_grants_in: int
    hub_grants_in: int
    overprivileged_roles: int
    # Share of this topic's roles with at least one flag.
    overprivileged_share: float
    # Share of the granted sensitivity weight of this topic's (non-hub) roles outside the topic.
    cross_weight_share: float
    flags: TopicFlagCounts
    seeds: dict[str, int]
    sensitivity: dict[str, int]
    types: dict[str, int]
    # Excess privilege of the topic's roles and identities (granted vs needed, with and
    # without hubs), unused and dormant counts; basis counts say how much is inferred.
    privilege: dict | None = None


class TopicLink(BaseModel):
    source: str
    target: str
    weight: int


class TopicMapView(BaseModel):
    total_topics: int
    shown_topics: int
    links: int
    shown_links: int
    edge_limit: int
    truncated: bool
    basis: str = BASIS
    notice: str = NOTICE


class TopicMapResponse(BaseModel):
    revision: str
    topics: list[TopicSummary]
    edges: list[TopicLink]
    summary: dict
    warnings: list[str]
    view: TopicMapView


class TopicShare(BaseModel):
    topic_id: str
    share: float
    resources: int


class TopicMember(BaseModel):
    id: str
    name: str
    type: str
    kind: str  # "resource", "role" or "identity"
    sensitivity: str
    seed: str  # resources: tag, metadata, name, coaccess or fallback
    reason: str
    flags: list[str]
    direct_grants: int
    reach_resources: int
    reach_weight: int
    reach_weight_excl_hubs: int
    cross_topic_grants: int
    restricted_outside: int
    profile: list[TopicShare]
    # Excess privilege (roles and identities): "used" (attested observed use), "inferred"
    # (peer baseline) or "none" (no usage evidence; EPI is null).
    basis: str = ""
    needed_weight: int = 0
    needed_weight_excl_hubs: int = 0
    epi: float | None = None
    epi_excl_hubs: float | None = None
    used_resources: int = 0
    unused_grants: int = 0
    unused_restricted: int = 0


class TopicDetailView(BaseModel):
    kind: str
    total: int
    offset: int
    limit: int
    shown: int
    next_offset: int | None
    truncated: bool
    basis: str = BASIS
    notice: str = NOTICE


class TopicDetailResponse(BaseModel):
    revision: str
    topic: TopicSummary
    members: list[TopicMember]
    # The most over-privileged roles of the topic (flags, then cross-topic weight).
    top_roles: list[TopicMember]
    view: TopicDetailView


class TopicNotFound(LookupError):
    pass


def _summary(row: RevisionTopic) -> TopicSummary:
    stats = row.stats if isinstance(row.stats, dict) else json.loads(row.stats)
    own = stats.get("own_weight", 0)
    return TopicSummary(
        id=row.topic_id,
        name=row.name,
        label=row.label,
        kind=row.kind,
        reason=row.reason,
        resources=row.resources,
        resource_weight=row.resource_weight,
        roles=row.roles,
        identities=row.identities,
        cross_grants_out=row.cross_grants_out,
        cross_grants_in=row.cross_grants_in,
        hub_grants_in=row.hub_grants_in,
        overprivileged_roles=row.overprivileged_roles,
        overprivileged_share=round(row.overprivileged_roles / row.roles, 4) if row.roles else 0.0,
        cross_weight_share=round(stats.get("cross_weight", 0) / own, 4) if own else 0.0,
        flags=TopicFlagCounts(**{key: stats.get(key, 0) for key in TopicFlagCounts.model_fields}),
        seeds=stats.get("seeds", {}),
        sensitivity=stats.get("sensitivity", {}),
        types=stats.get("types", {}),
        privilege=stats.get("privilege"),
    )


def _member(row: RevisionTopicMember) -> TopicMember:
    profile = row.profile if isinstance(row.profile, list) else json.loads(row.profile)
    return TopicMember(
        id=row.entity_id,
        name=row.name,
        type=row.entity_type,
        kind=row.kind,
        sensitivity=row.sensitivity,
        seed=row.seed,
        reason=row.reason,
        flags=[name for flag, name in FLAG_NAMES if row.flags & flag],
        direct_grants=row.direct_grants,
        reach_resources=row.reach_resources,
        reach_weight=row.reach_weight,
        reach_weight_excl_hubs=row.reach_weight_excl_hubs,
        cross_topic_grants=row.cross_topic_grants,
        restricted_outside=row.restricted_outside,
        profile=[TopicShare(topic_id=t, share=s, resources=c) for t, s, c in profile],
        basis=row.basis,
        needed_weight=row.needed_weight,
        needed_weight_excl_hubs=row.needed_weight_excl_hubs,
        epi=_epi(row.basis, row.reach_weight, row.needed_weight),
        epi_excl_hubs=_epi(row.basis, row.reach_weight_excl_hubs, row.needed_weight_excl_hubs),
        used_resources=row.used_resources,
        unused_grants=row.unused_grants,
        unused_restricted=row.unused_restricted,
    )


def _epi(basis: str, granted: int, needed: int) -> float | None:
    if basis not in ("used", "inferred") or not granted:
        return None
    return round(1 - needed / granted, 6)


def stored_privilege(db: Session, tenant: str, revision: str) -> dict | None:
    """Graph-wide excess privilege of a revision (None before topics are stored)."""
    summary = stored_topic_summary(db, tenant, revision)
    if summary is None:
        return None
    totals = summary.totals if isinstance(summary.totals, dict) else json.loads(summary.totals)
    return totals.get("privilege")


def validate_topic_bounds(edge_limit: int) -> None:
    if not 1 <= edge_limit <= 2000:
        raise ValueError("Topic limits outside supported bounds")


def topic_map(
    db: Session, summary: RevisionTopicSummary, warnings: list[str], edge_limit: int
) -> TopicMapResponse:
    validate_topic_bounds(edge_limit)
    tenant, revision = summary.tenant_id, summary.revision
    scope = (RevisionTopic.tenant_id == tenant, RevisionTopic.revision == revision)
    rows = db.scalars(
        select(RevisionTopic).where(*scope).order_by(RevisionTopic.ordinal).limit(MAX_MAP_TOPICS)
    )
    topics = [_summary(row) for row in rows]
    shown = [topic.id for topic in topics]
    links = (
        [
            TopicLink(source=a, target=b, weight=w)
            for a, b, w in db.execute(
                select(RevisionTopicLink.source_id, RevisionTopicLink.target_id, RevisionTopicLink.weight)
                .where(
                    RevisionTopicLink.tenant_id == tenant,
                    RevisionTopicLink.revision == revision,
                    RevisionTopicLink.source_id.in_(shown),
                    RevisionTopicLink.target_id.in_(shown),
                )
                .order_by(
                    RevisionTopicLink.weight.desc(), RevisionTopicLink.source_id, RevisionTopicLink.target_id
                )
                .limit(edge_limit)
            )
        ]
        if shown
        else []
    )
    totals = summary.totals if isinstance(summary.totals, dict) else json.loads(summary.totals)
    map_links = totals.get("map_links", summary.total_links)
    return TopicMapResponse(
        revision=revision,
        topics=topics,
        edges=links,
        summary={key: value for key, value in totals.items() if key != "map_links"},
        warnings=warnings,
        view=TopicMapView(
            total_topics=summary.total_topics,
            shown_topics=len(topics),
            links=summary.total_links,
            shown_links=len(links),
            edge_limit=edge_limit,
            truncated=len(topics) < summary.total_topics or len(links) < map_links,
        ),
    )


MEMBER_KINDS = ("resource", "role", "identity")


MEMBER_ORDERS = ("rank", "excess")


def _members(
    db: Session, tenant: str, revision: str, topic: str, kind: str, offset: int, limit: int, order: str = "rank"
):
    scope = select(RevisionTopicMember).where(
        RevisionTopicMember.tenant_id == tenant,
        RevisionTopicMember.revision == revision,
        RevisionTopicMember.topic_id == topic,
        RevisionTopicMember.kind == kind,
    )
    if order == "excess":
        # Largest granted-but-not-needed weight first (top EPI contributors); stable by rank.
        query = (
            scope.order_by(
                (RevisionTopicMember.reach_weight - RevisionTopicMember.needed_weight).desc(),
                RevisionTopicMember.ordinal,
            )
            .offset(offset)
            .limit(limit)
        )
    else:
        query = (
            scope.where(RevisionTopicMember.ordinal >= offset).order_by(RevisionTopicMember.ordinal).limit(limit)
        )
    return [_member(row) for row in db.scalars(query)]


def topic_detail(
    db: Session, tenant: str, revision: str, topic: str, kind: str, offset: int, limit: int, order: str = "rank"
) -> TopicDetailResponse:
    """One topic with a page of its assets, roles or identities, and its top over-privileged roles."""
    if (
        kind not in MEMBER_KINDS
        or order not in MEMBER_ORDERS
        or not 1 <= limit <= MAX_PAGE
        or not 0 <= offset <= 1_000_000
    ):
        raise ValueError("Topic page outside supported bounds")
    row = db.get(RevisionTopic, (tenant, revision, topic))
    if not isinstance(row, RevisionTopic):
        raise TopicNotFound(topic)
    total = {"resource": row.resources, "role": row.roles, "identity": row.identities}[kind]
    members = _members(db, tenant, revision, topic, kind, offset, limit, order)
    top_roles = _members(db, tenant, revision, topic, "role", 0, TOP_ROLES)
    end = offset + len(members)
    return TopicDetailResponse(
        revision=revision,
        topic=_summary(row),
        members=members,
        top_roles=[member for member in top_roles if member.flags],
        view=TopicDetailView(
            kind=kind,
            total=total,
            offset=offset,
            limit=limit,
            shown=len(members),
            next_offset=end if end < total else None,
            truncated=offset > 0 or end < total,
        ),
    )


# ---------------------------------------------------------------------------
# Operator backfill and worker sweep


def backfill(tenant: str, wait: bool = True) -> dict:
    """Compute and store topics for a tenant's current revision under the publication lock.

    The worker's sweep passes ``wait=False`` and skips a tenant whose publication (or
    another backfill) holds the lock. Rows of an older ``TOPIC_VERSION``, or computed
    with other usage evidence (a committed or deleted upload, evidence gone stale), are
    replaced.
    """
    from app.core.config import get_settings
    from app.graph.privilege import load_usage
    from app.graph.usage import evidence

    with session_factory()() as db:
        if db.get_bind().dialect.name == "postgresql":
            db.execute(text("SET LOCAL lock_timeout = '5s'"))
        if wait:
            acquire_publication_lock(db, tenant)
        elif not try_publication_lock(db, tenant):
            return {"tenant": tenant, "backfilled": False, "busy": True}
        state = db.execute(
            select(TenantState).where(TenantState.tenant_id == tenant).with_for_update(read=True)
        ).scalar_one_or_none()
        if state is None or not state.revision:
            raise ValueError("Tenant has no published revision")
        revision = state.revision
        stored = stored_topic_summary(db, tenant, revision)
        if stored is not None and stored.usage_fingerprint == evidence(db, tenant).fingerprint:
            return {"tenant": tenant, "revision": revision, "backfilled": False}
        delete_topics(db, tenant, revision)
        graph = CompactGraph.from_snapshot(get_graph_store().snapshot(tenant, revision))
        computed = compute_topics(
            graph, load_usage(db, tenant, graph, peer_share=get_settings().peer_baseline_share)
        )
        store_topics(db, tenant, revision, computed)
        # Proposals rest on the same evidence: recompute them in the same transaction.
        from app.graph.proposals import compute_and_store, delete_proposals, stored_findings

        delete_proposals(db, tenant, revision)
        compute_and_store(db, tenant, revision, computed, stored_findings(db, tenant, revision))
        db.commit()
        return {
            "tenant": tenant,
            "revision": revision,
            "backfilled": True,
            "topics": len(computed.topics),
            "usage": computed.summary["usage_fingerprint"] != "",
        }


_failed: dict[tuple[str, str], float] = {}


def missing_topics(db: Session, limit: int) -> list[tuple[str, str]]:
    """(tenant, revision) pairs whose current revision has no topics of this version, or
    topics computed with usage evidence other than the tenant's current evidence."""
    from app.db.models import UsageUpload
    from app.graph.usage import evidence

    present = (
        select(RevisionTopicSummary.tenant_id)
        .where(
            RevisionTopicSummary.tenant_id == TenantState.tenant_id,
            RevisionTopicSummary.revision == TenantState.revision,
            RevisionTopicSummary.topic_version == TOPIC_VERSION,
        )
        .exists()
    )
    rows = db.execute(
        select(TenantState.tenant_id, TenantState.revision)
        .where(TenantState.revision.is_not(None), TenantState.revision != "", ~present)
        .order_by(TenantState.tenant_id)
        .limit(limit)
    )
    pending = [(tenant, revision) for tenant, revision in rows]
    if len(pending) >= limit:
        return pending
    # Stored with usage evidence, or the tenant has committed uploads: compare fingerprints.
    with_usage = select(UsageUpload.tenant_id).where(UsageUpload.status == "committed").distinct()
    candidates = db.execute(
        select(TenantState.tenant_id, TenantState.revision, RevisionTopicSummary.usage_fingerprint)
        .join(
            RevisionTopicSummary,
            (RevisionTopicSummary.tenant_id == TenantState.tenant_id)
            & (RevisionTopicSummary.revision == TenantState.revision),
        )
        .where(
            RevisionTopicSummary.topic_version == TOPIC_VERSION,
            (RevisionTopicSummary.usage_fingerprint != "") | TenantState.tenant_id.in_(with_usage),
        )
        .order_by(TenantState.tenant_id)
    )
    for tenant, revision, fingerprint in candidates:
        if evidence(db, tenant).fingerprint != fingerprint:
            pending.append((tenant, revision))
            if len(pending) >= limit:
                break
    return pending


def backfill_missing(limit: int = SWEEP_TENANTS) -> list[dict]:
    """Backfill up to ``limit`` tenants' current revisions; never raises for one tenant's failure."""

    def pending(count: int) -> list[tuple[str, str]]:
        with session_factory()() as db:
            return missing_topics(db, count)

    return run_sweep(
        "Topic",
        pending,
        lambda tenant: backfill(tenant, wait=False),
        _failed,
        lambda result: f"topics={result['topics']} usage={result.get('usage', False)}",
        limit,
    )


def count_rows(db: Session, tenant: str, revision: str) -> int:
    return db.scalar(
        select(func.count())
        .select_from(RevisionTopicMember)
        .where(RevisionTopicMember.tenant_id == tenant, RevisionTopicMember.revision == revision)
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Store relationship topics for a tenant's current revision")
    parser.add_argument("--tenant", required=True)
    args = parser.parse_args()
    try:
        result = backfill(args.tenant)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
