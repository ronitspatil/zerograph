"""Least-privilege proposals at publish time: what to remove, disable, merge or split.

Proposals are computed from the revision's topic and excess-privilege analysis
(``app.graph.topics``, ``app.graph.privilege``) and the tenant's observed access
(``app.graph.usage``). They are **proposed, never applied**: nothing here changes a
grant, and pull requests come in a later phase. Types:

* ``remove_grant``: a role's (or identity's own) grant on a data asset that was not
  observed used.
* ``disable_identity`` / ``disable_role``: an identity or role with no observed use in a
  sufficient window (disable or detach; deletion is never proposed).
* ``merge_roles``: two roles of the same topic whose grants have Jaccard similarity of
  at least ``MERGE_JACCARD``; the kept role keeps the retired role's used grants and
  its assumers.
* ``split_role``: a role whose used access spans at least two topics with at least
  ``SPLIT_SHARE`` of its used assets each; each topic's used grants go to their own role.
* ``scope_wildcard``: grants with wildcard actions, scoped to the assets actually used.
* ``break_toxic_path``: on a toxic-combination path (exposed entry point to sensitive
  data), remove the edge with the lowest observed-use weight.

Tiers (``TIERS``): ``high`` = unused through a sufficient window (attested, complete
coverage of >= 90 days ending within 7) and the asset is outside the holder's topic;
``medium`` = the same inside the topic (or a fallback group); ``low`` = unused by the
holder but used by at least the peer share of same-topic holders granted it;
``inferred`` = the service's coverage is complete but too short or stale and the peer
baseline says it is not needed; ``manual`` = anything on the never-auto list
(``NEVER_AUTO``), which always forces ``manual`` whatever the evidence says.

**Invariant: no proposal removes observed access.** A grant is never proposed for
removal (or its holder disabled, or a path edge cut) when any principal observed using
the asset can reach the holder, when the asset has observed use that no graph grant
explains, or when the hop was observed as an assumption. ``check_invariant`` verifies
it and tests run it over every proposal.

Rows are stored per (tenant, revision) in the publication transaction (and by the
worker sweep when usage evidence changes or the version is missing), deleted with
the revision by retention and carried by the database backup, like topics. Proposal
IDs are deterministic (type, subject and target IDs), so accept/reject decisions,
stored per tenant by ID, carry forward to later revisions.
"""

import argparse
import gc
import hashlib
import json
import math
import threading
import time
from collections import Counter
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime

from pydantic import BaseModel
from sqlalchemy import delete, func, select, text
from sqlalchemy.orm import Session

from app.db.locks import acquire_publication_lock, try_publication_lock
from app.db.models import (
    ProposalDecision,
    RevisionFinding,
    RevisionProposal,
    RevisionProposalModel,
    RevisionProposalSummary,
    RevisionTopic,
    RevisionTopicMember,
    RevisionTopicSummary,
    TenantState,
    now,
)
from app.db.session import session_factory
from app.graph.compact import BREAK_GLASS, EDGE_CODE, EDGE_KINDS, EXEMPT, KMS, SERVICE_LINKED, CompactGraph
from app.graph.policies import PolicyIndex, policy_index
from app.graph.privilege import data_service
from app.graph.schema import EdgeType
from app.graph.sweep import SWEEP_TENANTS, run_sweep
from app.graph.whatif import BASIS_CODES, IDENTITY_RECORD, ROLE_RECORD, WhatIfModel

# Bump when proposal types, tiers, evidence or stored fields change: other versions read as missing.
PROPOSAL_VERSION = 1
TIERS = ("high", "medium", "low", "inferred", "manual")
TYPES = (
    "remove_grant",
    "disable_identity",
    "disable_role",
    "merge_roles",
    "split_role",
    "scope_wildcard",
    "break_toxic_path",
)
HIGH, MEDIUM, LOW, INFERRED, MANUAL = range(5)
REMOVE, DISABLE_IDENTITY, DISABLE_ROLE, MERGE, SPLIT, WILDCARD, TOXIC = range(7)
MERGE_JACCARD = 0.8
MERGE_MIN_GRANTS = 4
MERGE_MAX_PER_ROLE = 5
SPLIT_SHARE = 0.25
SPLIT_MIN_USED = 4
MAX_FINDINGS = 10_000
MAX_CHANGES = 200  # Edges listed per proposal row (the what-if model keeps all of them).
SAMPLE_IDENTITIES = 3
MAX_PAGE = 200
NEVER_AUTO = {
    "condition": "An Allow granting it carries a policy Condition",
    "deny": "A Deny statement applies to it",
    "resource_policy": "Granted outside the principal's identity policies (resource policy)",
    "trust": "Changes a role trust policy (who can assume which role)",
    "cross_account": "Changes a trust relationship across accounts",
    "service_linked": "Service-linked role (managed by the AWS service)",
    "break_glass": "Break-glass, emergency or disaster-recovery identity",
    "kms": "KMS key access (governed by key policies)",
    "wildcard": "Rewrites a wildcard grant",
    "coverage": "The service lacked attested, complete usage coverage",
    "seasonal": "Scheduled or seasonal identity (exemption tag); needs a longer window",
    "structure": "Changes role or tool relationships (who can invoke or inherit what)",
}
NOTICE = (
    "Proposed, not applied. Every proposal is reviewed by a person; accepted ones become draft pull requests "
    "in your repository (ZeroGraph never merges or applies them). "
    "No proposal removes access that was observed used."
)
GRANT_CODES = frozenset({EDGE_CODE[EdgeType.READ.value], EDGE_CODE[EdgeType.WRITE.value]})
HOP_CODES = frozenset(
    {EDGE_CODE[EdgeType.ASSUMES.value], EDGE_CODE[EdgeType.INHERITS.value], EDGE_CODE[EdgeType.INVOKES.value]}
)


def proposal_id(kind: str, subject: str, target: str = "") -> str:
    """Stable across revisions: the same change to the same entities has the same ID."""
    return "p" + hashlib.sha256(f"{kind}\0{subject}\0{target}".encode()).hexdigest()[:19]


@dataclass(slots=True)
class Proposal:
    kind: int
    tier: int
    base_tier: int  # tier from the evidence alone, before the never-auto override
    subject: int
    target: int  # -1: none
    topic: int  # topic index of the subject (-1: none)
    weight: int  # sensitivity weight of the access removed
    identities: int  # identities whose reach includes the subject
    reasons: tuple[str, ...]
    removals: tuple[int, ...] = ()  # flattened (holder, data) pairs
    cuts: tuple[int, ...] = ()  # flattened (a, b) hop pairs
    disables: tuple[int, ...] = ()
    detail: dict | None = None
    epi: tuple[float | None, float | None] = (None, None)
    id: str = ""


@dataclass
class ComputedProposals:
    proposals: list[Proposal]
    summary: dict
    model: WhatIfModel
    edges: dict[tuple[int, int], list[int]]  # (source, target) -> edge indices of listed changes
    samples: dict[int, list[str]]  # holder -> up to SAMPLE_IDENTITIES identity IDs reaching it
    compute_ms: int


@dataclass(frozen=True)
class FindingPath:
    finding_id: str
    path: tuple[str, ...]


def findings_from(findings) -> list[FindingPath]:
    """Paths of toxic-combination findings (``Finding`` objects or stored payloads)."""
    paths = []
    for finding in findings:
        if isinstance(finding, dict):
            paths.append(FindingPath(str(finding.get("id", "")), tuple(finding.get("path", ()))))
        else:
            paths.append(FindingPath(finding.id, tuple(finding.path)))
    return paths[:MAX_FINDINGS]


def stored_findings(db: Session, tenant: str, revision: str) -> list[FindingPath]:
    return findings_from(
        row.payload if isinstance(row.payload, dict) else json.loads(row.payload)
        for row in db.scalars(
            select(RevisionFinding)
            .where(RevisionFinding.tenant_id == tenant, RevisionFinding.revision == revision)
            .order_by(RevisionFinding.ordinal)
            .limit(MAX_FINDINGS)
        )
    )


def _coverage(usage, service: str) -> str:
    """``sufficient`` (>= 90 days, fresh), ``partial`` (complete but short or stale) or ``none``."""
    found = usage.evidence.services.get(service) if usage is not None else None
    if found is None:
        return "none"
    if found.sufficient:
        return "sufficient"
    return "partial" if found.complete_uploads else "none"


def compute_proposals(
    computed,
    findings: Iterable[FindingPath] = (),
    policies: PolicyIndex | None = None,
) -> ComputedProposals:
    """Every proposal of a revision from its computed topics (``ComputedTopics``)."""
    started = time.perf_counter()
    context, usage = computed.context, computed.usage
    graph: CompactGraph = computed.graph
    ids, types = graph.ids, graph.types
    direct, hubs, weight = context.direct, context.hubs, context.weight
    holders_of, through = context.holders, context.through
    role_rows, identity_rows = computed.roles, computed.identities
    resource_topic, topics = computed.resource_topic, computed.topics
    safety = graph.safety
    policies = policies or PolicyIndex()
    present = usage is not None and usage.present
    data_used = usage.data_used if present else {}
    assumed = usage.assumed if present else {}
    granted_by, used_by, peer_needed = context.granted_by, context.used_by, context.peer_needed
    guards: Counter = Counter()
    proposals: list[Proposal] = []

    def row_of(node: int) -> dict | None:
        return role_rows.get(node) or identity_rows.get(node)

    def topic_of(node: int) -> int:
        row = row_of(node)
        return row["topic"] if row is not None else -1

    # Who reaches each holder (identities), with a small deterministic sample by ID.
    reached_by: Counter = Counter()
    sample: dict[int, list[int]] = {}
    for node in sorted(identity_rows, key=ids.__getitem__):
        for holder in holders_of.get(node, ()):
            reached_by[holder] += 1
            found = sample.setdefault(holder, [])
            if len(found) < SAMPLE_IDENTITIES:
                found.append(node)
        for pivot in through.get(node, ()):
            reached_by[pivot] += 1

    # Observed users per asset; assets whose observed use no graph grant explains are never touched.
    users_of: dict[int, list[int]] = {}
    unexplained: set[int] = set()
    for principal, items in data_used.items():
        reach = holders_of.get(principal, frozenset())
        for item in items:
            users_of.setdefault(item, []).append(principal)
            if not any(item in direct.get(holder, ()) for holder in reach) and item not in direct.get(
                principal, ()
            ):
                unexplained.add(item)

    reaching_users: dict[int, set[int]] = {}

    def protected(holder: int, item: int) -> bool:
        """Removing ``holder``'s grant on ``item`` could remove observed access."""
        if item in unexplained:
            return True
        # Holders through which some observed user of ``item`` reaches it (or the user itself).
        found = reaching_users.get(item)
        if found is None:
            found = reaching_users[item] = set(users_of.get(item, ()))
            for user in users_of.get(item, ()):
                found.update(holders_of.get(user, ()))
        return holder in found

    # Wildcard grant pairs and every edge per (source, target) needed for listed changes.
    wildcard_pairs: set[tuple[int, int]] = set()
    kinds, sources, targets, actions = (
        graph.edge_kind,
        graph.edge_source,
        graph.edge_target,
        graph.edge_actions,
    )
    is_data = {item for item in weight}
    for edge in range(graph.edge_count):
        if kinds[edge] in GRANT_CODES and targets[edge] in is_data:
            if any(a == "*" or a.endswith(":*") for a in actions[edge]):
                wildcard_pairs.add((sources[edge], targets[edge]))
    grant_actions: dict[tuple[int, int], tuple[str, ...]] = {}

    def node_reasons(node: int) -> list[str]:
        flags = safety.get(node, 0)
        found = []
        if flags & SERVICE_LINKED:
            found.append("service_linked")
        if flags & BREAK_GLASS:
            found.append("break_glass")
        if flags & EXEMPT:
            found.append("seasonal")
        return found

    def classify(holder: int, item: int) -> tuple[int, list[str], dict] | None:
        """(tier, never-auto reasons, evidence) for removing ``holder``'s grant on ``item``."""
        service = data_service(graph, item)
        coverage = _coverage(usage, service)
        topic = topic_of(holder)
        granted = granted_by.get((topic, item), 0)
        used = used_by.get((topic, item), 0)
        peer = item in peer_needed.get(holder, ())
        reasons = node_reasons(holder)
        if safety.get(item, 0) & KMS or service == "kms":
            reasons.append("kms")
        if coverage == "sufficient":
            target_topic = resource_topic[item]
            if peer:
                tier = LOW
            elif topic >= 0 and target_topic != topic:
                # Outside the holder's topic: another topic, or a fallback group (no tag, name
                # or observed-use signal ties the asset to the holder's topic).
                tier = HIGH
            else:
                tier = MEDIUM
        elif peer:
            guards["skipped_peer_needed"] += 1
            return None
        elif coverage == "partial":
            tier = INFERRED
        else:
            tier = MANUAL
            reasons.append("coverage")
        evidence = {"service": service, "coverage": coverage, "peers": [granted, used]}
        return tier, reasons, evidence

    def policy_reasons(holder: int, item: int) -> list[str]:
        return policies.constraints(ids[holder], grant_actions.get((holder, item), ()), ids[item])

    def role_epi(holder: int, removed: Iterable[int]) -> tuple[float | None, float | None]:
        row = row_of(holder)
        if row is None or row["basis"] not in ("used", "inferred") or not row["reach_weight"]:
            return None, None
        others = [h for h in holders_of.get(holder, ()) if h != holder]
        lost = sum(weight[item] for item in removed if not any(item in direct[h] for h in others))
        granted = row["reach_weight"]
        before = round(1 - row["needed_weight"] / granted, 6)
        after_granted = granted - lost
        needed = min(row["needed_weight"], after_granted)
        return before, (round(1 - needed / after_granted, 6) if after_granted else None)

    if policies.statements:
        for edge in range(graph.edge_count):
            if kinds[edge] in GRANT_CODES and ids[sources[edge]] in policies.statements:
                pair = (sources[edge], targets[edge])
                grant_actions[pair] = grant_actions.get(pair, ()) + actions[edge]

    # 1. Remove unused grants (non-wildcard), per (holder, asset).
    if present:
        for holder in sorted(direct, key=ids.__getitem__):
            if row_of(holder) is None:
                continue
            used = data_used.get(holder, ())
            for item in sorted(direct[holder], key=ids.__getitem__):
                if item in used:
                    continue
                if (holder, item) in wildcard_pairs:
                    continue  # Scoped by scope_wildcard (manual).
                if protected(holder, item):
                    guards["skipped_observed"] += 1
                    continue
                found = classify(holder, item)
                if found is None:
                    continue
                tier, reasons, evidence = found
                reasons += policy_reasons(holder, item)
                base = tier
                if reasons:
                    tier = MANUAL
                proposals.append(
                    Proposal(
                        REMOVE,
                        tier,
                        base,
                        holder,
                        item,
                        topic_of(holder),
                        weight[item],
                        reached_by[holder],
                        tuple(dict.fromkeys(reasons)),
                        removals=(holder, item),
                        detail=evidence,
                        epi=role_epi(holder, (item,)),
                    )
                )

    # 2. Scope wildcard grants to the assets used (always manual).
    by_holder: dict[int, list[int]] = {}
    for holder, item in wildcard_pairs:
        by_holder.setdefault(holder, []).append(item)
    for holder in sorted(by_holder, key=ids.__getitem__):
        if row_of(holder) is None:
            continue
        items = sorted(by_holder[holder], key=ids.__getitem__)
        used = data_used.get(holder, ())
        keep = [item for item in items if item in used or protected(holder, item)]
        drop = [item for item in items if item not in used and not protected(holder, item)] if present else []
        reasons = ["wildcard", *node_reasons(holder)]
        if not present:
            reasons.append("coverage")
        proposals.append(
            Proposal(
                WILDCARD,
                MANUAL,
                MANUAL,
                holder,
                -1,
                topic_of(holder),
                sum(weight[item] for item in drop),
                reached_by[holder],
                tuple(dict.fromkeys(reasons)),
                removals=tuple(value for item in drop for value in (holder, item)),
                detail={
                    "wildcard_grants": len(items),
                    "keep_used": len(keep),
                    "remove_unused": len(drop),
                    "keep_topics": dict(
                        Counter(topics[resource_topic[item]].id for item in keep).most_common(5)
                    ),
                },
                epi=role_epi(holder, drop),
            )
        )

    # 3. Disable dormant identities and roles (never delete).
    for rows, kind in ((identity_rows, DISABLE_IDENTITY), (role_rows, DISABLE_ROLE)):
        for node in sorted(rows, key=ids.__getitem__):
            row = rows[node]
            if not row["dormant"]:
                continue
            if kind == DISABLE_ROLE:
                # Any active principal whose closure includes the role and that observed use of
                # data the role's holders grant keeps the role.
                granted_items = set()
                for holder in holders_of.get(node, ()):
                    granted_items |= direct.get(holder, set())
                if any(
                    (node in holders_of.get(user, ()) or node in through.get(user, ()))
                    for item in granted_items
                    for user in users_of.get(item, ())
                ):
                    guards["skipped_observed"] += 1
                    continue
            reasons = node_reasons(node)
            base = LOW if row["hint_conflict"] else HIGH
            evidence = {
                "basis": row["basis"],
                "last_used_hint": graph.last_used.get(node),
                "hint_conflict": row["hint_conflict"],
                "granted_weight": row["reach_weight"],
                "type": types[node],
            }
            proposals.append(
                Proposal(
                    kind,
                    MANUAL if reasons else base,
                    base,
                    node,
                    -1,
                    row["topic"],
                    row["reach_weight"] if kind == DISABLE_IDENTITY else row["own_weight"],
                    1 if kind == DISABLE_IDENTITY else reached_by[node],
                    tuple(reasons),
                    disables=(node,),
                    detail=evidence,
                    epi=(
                        round(1 - row["needed_weight"] / row["reach_weight"], 6)
                        if row["reach_weight"]
                        else None,
                        None,
                    ),
                )
            )

    # 4. Merge near-duplicate roles of the same topic (exact Jaccard join, prefix filtered).
    candidates = [
        role
        for role, row in role_rows.items()
        if role not in hubs and row["topic"] >= 0 and len(direct.get(role, ())) >= MERGE_MIN_GRANTS
    ]
    frequency: Counter = Counter(item for role in candidates for item in direct[role])
    rank = {
        item: position
        for position, item in enumerate(sorted(frequency, key=lambda item: (frequency[item], ids[item])))
    }
    tokens = {role: sorted(rank[item] for item in direct[role]) for role in candidates}
    index: dict[tuple[int, int], list[int]] = {}
    pairs: list[tuple[int, int, int, int]] = []  # (a, b, overlap, union)
    for role in sorted(candidates, key=lambda r: (len(tokens[r]), ids[r])):
        mine = tokens[role]
        size = len(mine)
        minimum = math.ceil(MERGE_JACCARD * size - 1e-9)
        prefix = size - minimum + 1
        topic = role_rows[role]["topic"]
        seen: set[int] = set()
        own = set(mine)
        for token in mine[:prefix]:
            for other in index.get((topic, token), ()):
                if other in seen or len(tokens[other]) < minimum:
                    continue
                seen.add(other)
                overlap = len(own.intersection(tokens[other]))
                union = size + len(tokens[other]) - overlap
                if overlap * 5 >= union * 4:  # Jaccard >= 0.8, exact
                    pairs.append((other, role, overlap, union))
            index.setdefault((topic, token), []).append(role)
    per_role: Counter = Counter()
    pairs.sort(key=lambda p: (-p[2] / p[3], *sorted((ids[p[0]], ids[p[1]]))))
    for a, b, overlap, union in pairs:
        if per_role[a] >= MERGE_MAX_PER_ROLE or per_role[b] >= MERGE_MAX_PER_ROLE:
            guards["merge_pairs_capped"] += 1
            continue
        per_role[a] += 1
        per_role[b] += 1
        keep, retire = sorted((a, b), key=lambda r: (-reached_by[r], ids[r]))
        moved = sorted(
            (item for item in direct[retire] - direct[keep] if item in data_used.get(retire, ())),
            key=ids.__getitem__,
        )
        reasons = ["trust", *node_reasons(keep), *node_reasons(retire)]
        if graph.account[keep] != graph.account[retire]:
            reasons.append("cross_account")
        proposals.append(
            Proposal(
                MERGE,
                MANUAL,
                MEDIUM,
                keep,
                retire,
                role_rows[keep]["topic"],
                0,
                reached_by[keep] + reached_by[retire],
                tuple(dict.fromkeys(reasons)),
                detail={
                    "jaccard": round(overlap / union, 4),
                    "shared_grants": overlap,
                    "only_keep": len(direct[keep] - direct[retire]),
                    "only_retire": len(direct[retire] - direct[keep]),
                    "move_used_grants": [ids[item] for item in moved[:MAX_CHANGES]],
                    "identities_keep": reached_by[keep],
                    "identities_retire": reached_by[retire],
                },
            )
        )

    # 5. Split roles whose used access spans topics.
    for role in sorted(role_rows, key=ids.__getitem__):
        row = role_rows[role]
        if role in hubs or row["basis"] != "used":
            continue
        used = [item for item in data_used.get(role, ()) if item in direct.get(role, ())]
        if len(used) < SPLIT_MIN_USED:
            continue
        counts = Counter(
            resource_topic[item] for item in used if topics[resource_topic[item]].kind == "anchored"
        )
        total = sum(counts.values())
        parts = sorted(
            (t for t, c in counts.items() if total and c / total >= SPLIT_SHARE), key=lambda t: topics[t].name
        )
        if len(parts) < 2:
            continue
        main = (
            row["topic"] if row["topic"] in parts else max(parts, key=lambda t: (counts[t], topics[t].name))
        )
        groups: dict[int, list[str]] = {t: [] for t in parts}
        for item in sorted(used, key=ids.__getitem__):
            groups[resource_topic[item] if resource_topic[item] in groups else main].append(ids[item])
        reasons = ["trust", *node_reasons(role)]
        proposals.append(
            Proposal(
                SPLIT,
                MANUAL,
                MEDIUM,
                role,
                -1,
                row["topic"],
                0,
                reached_by[role],
                tuple(dict.fromkeys(reasons)),
                detail={
                    "used_assets": len(used),
                    "groups": [
                        {
                            "topic_id": topics[t].id,
                            "topic": topics[t].name,
                            "share": round(counts[t] / total, 4),
                            "grants": groups[t][:MAX_CHANGES],
                            "count": len(groups[t]),
                        }
                        for t in parts
                    ],
                },
            )
        )

    # 6. Break toxic paths: remove the path edge with the lowest observed-use weight.
    paths = [p for p in findings if len(p.path) >= 2 and all(node in graph.index for node in p.path)]
    path_pairs = {
        (graph.index[a], graph.index[b]) for p in paths for a, b in zip(p.path, p.path[1:], strict=False)
    }
    assumes_pairs: set[tuple[int, int]] = set()
    if path_pairs:
        assume_code = EDGE_CODE[EdgeType.ASSUMES.value]
        for edge in range(graph.edge_count):
            if kinds[edge] == assume_code and (sources[edge], targets[edge]) in path_pairs:
                assumes_pairs.add((sources[edge], targets[edge]))
    chosen: dict[tuple[int, int], list[str]] = {}
    for found in paths:
        path = [graph.index[node] for node in found.path]
        options = []
        for position, (a, b) in enumerate(zip(path, path[1:], strict=False)):
            if b in weight:  # Grant edge to data.
                used_weight = weight[b] if b in data_used.get(a, ()) else 0
                blocked = used_weight > 0 or protected(a, b)
                manual = False
            else:
                observed_ = b in assumed.get(a, ())
                used_weight = sum(weight[item] for item in data_used.get(b, ())) if observed_ else 0
                blocked = observed_
                manual = True
            if not blocked:
                options.append((used_weight, manual, -position, ids[a], ids[b], a, b))
        if not options:
            guards["toxic_unbreakable"] += 1
            continue
        _, _, _, _, _, a, b = min(options)
        chosen.setdefault((a, b), []).append(found.finding_id)
    for (a, b), finding_ids in sorted(chosen.items(), key=lambda kv: (ids[kv[0][0]], ids[kv[0][1]])):
        evidence = {"findings": sorted(finding_ids)[:10], "finding_count": len(finding_ids)}
        if b in weight:
            found = classify(a, b) if present else None
            if found is None:
                tier, reasons, extra = MANUAL, ["coverage"], {}
            else:
                tier, reasons, extra = found
            reasons += policy_reasons(a, b)
            if (a, b) in wildcard_pairs:
                reasons.append("wildcard")
            evidence.update(extra)
            base = tier
            proposals.append(
                Proposal(
                    TOXIC,
                    MANUAL if reasons else tier,
                    base,
                    a,
                    b,
                    topic_of(a),
                    weight[b],
                    reached_by[a],
                    tuple(dict.fromkeys(reasons)),
                    removals=(a, b),
                    detail=evidence,
                    epi=role_epi(a, (b,)),
                )
            )
        else:
            trust = (a, b) in assumes_pairs
            reasons = ["trust" if trust else "structure", *node_reasons(a), *node_reasons(b)]
            if trust and graph.account[a] != graph.account[b]:
                reasons.append("cross_account")
            proposals.append(
                Proposal(
                    TOXIC,
                    MANUAL,
                    MEDIUM,
                    a,
                    b,
                    topic_of(a),
                    0,
                    reached_by[b],
                    tuple(dict.fromkeys(reasons)),
                    cuts=(a, b),
                    detail=evidence,
                )
            )

    # IDs, deterministic order.
    for proposal in proposals:
        target = ids[proposal.target] if proposal.target >= 0 else ""
        subject = ids[proposal.subject]
        if proposal.kind == MERGE:
            subject, target = sorted((subject, target))
        proposal.id = proposal_id(TYPES[proposal.kind], subject, target)
    proposals.sort(key=lambda p: (p.tier, p.kind, -p.weight, -p.identities, p.id))

    # Edges listed in changes (bounded per proposal; the model keeps every pair).
    wanted: set[tuple[int, int]] = set()
    for proposal in proposals:
        for position in range(0, min(len(proposal.removals), 2 * MAX_CHANGES), 2):
            wanted.add((proposal.removals[position], proposal.removals[position + 1]))
        for position in range(0, len(proposal.cuts), 2):
            wanted.add((proposal.cuts[position], proposal.cuts[position + 1]))
    edges: dict[tuple[int, int], list[int]] = {}
    for edge in range(graph.edge_count):
        pair = (sources[edge], targets[edge])
        if pair in wanted and (kinds[edge] in GRANT_CODES or kinds[edge] in HOP_CODES):
            edges.setdefault(pair, []).append(edge)
    generation_ms = round((time.perf_counter() - started) * 1000)

    model_started = time.perf_counter()
    model = build_model(computed, proposals)
    model_ms = round((time.perf_counter() - model_started) * 1000)
    high = model.evaluate(model.selection(i for i, p in enumerate(proposals) if p.tier == HIGH))
    summary = proposal_summary(computed, proposals, high, guards)
    summary["timings_ms"] = {
        "generation": generation_ms,
        "model": model_ms,
        "high_tier_metrics": round((time.perf_counter() - model_started) * 1000) - model_ms,
    }
    samples = {holder: [ids[node] for node in nodes] for holder, nodes in sample.items()}
    return ComputedProposals(
        proposals, summary, model, edges, samples, round((time.perf_counter() - started) * 1000)
    )


def build_model(computed, proposals: list[Proposal]) -> WhatIfModel:
    from array import array

    context, graph = computed.context, computed.graph
    n = graph.node_count
    weight = array("q", bytes(8 * n))
    for item, value in context.weight.items():
        weight[item] = value
    closures: list[tuple[int, ...]] = []
    closure_index: dict[tuple[int, ...], int] = {}
    node, kind, topic, basis = array("q"), bytearray(), array("q"), bytearray()
    granted, granted_core, needed, needed_core, closure = (
        array("q"),
        array("q"),
        array("q"),
        array("q"),
        array("q"),
    )
    for rows, record in ((computed.roles, ROLE_RECORD), (computed.identities, IDENTITY_RECORD)):
        for start in sorted(rows):
            row = rows[start]
            members = tuple(
                sorted(
                    (context.holders.get(start, frozenset()) | context.through.get(start, frozenset()))
                    - {start}
                )
            )
            position = closure_index.get(members)
            if position is None:
                position = closure_index[members] = len(closures)
                closures.append(members)
            node.append(start)
            kind.append(record)
            topic.append(row["topic"])
            basis.append(BASIS_CODES.index(row["basis"]) if row["basis"] in BASIS_CODES else 2)
            granted.append(row["reach_weight"])
            granted_core.append(row["reach_weight_excl_hubs"])
            needed.append(row["needed_weight"])
            needed_core.append(row["needed_weight_excl_hubs"])
            closure.append(position)
    return WhatIfModel(
        ids=list(graph.ids),
        weight=weight,
        restricted=bytearray(context.restricted),
        direct={holder: frozenset(items) for holder, items in context.direct.items()},
        hops={source: tuple(targets) for source, targets in context.hops.items()},
        hubs=frozenset(context.hubs),
        topics=[(t.id, t.name) for t in computed.topics],
        node=node,
        kind=kind,
        topic=topic,
        basis=basis,
        granted=granted,
        granted_core=granted_core,
        needed=needed,
        needed_core=needed_core,
        closure=closure,
        closures=closures,
        proposal_type=[TYPES[p.kind] for p in proposals],
        proposal_tier=[TIERS[p.tier] for p in proposals],
        removals=[p.removals for p in proposals],
        cuts=[p.cuts for p in proposals],
        disables=[p.disables for p in proposals],
    )


def proposal_summary(computed, proposals: list[Proposal], high: dict, guards: Counter) -> dict:
    topics = computed.topics
    by_tier = Counter(TIERS[p.tier] for p in proposals)
    by_type = Counter(TYPES[p.kind] for p in proposals)
    by_type_tier: dict[str, Counter] = {}
    by_topic: dict[str, Counter] = {}
    for p in proposals:
        by_type_tier.setdefault(TYPES[p.kind], Counter())[TIERS[p.tier]] += 1
        if p.topic >= 0:
            by_topic.setdefault(topics[p.topic].id, Counter())[TIERS[p.tier]] += 1
    high_topics = {row["topic_id"]: row for row in high["topics"]}
    usage = computed.usage
    return {
        "version": PROPOSAL_VERSION,
        "total": len(proposals),
        "by_tier": {tier: by_tier.get(tier, 0) for tier in TIERS},
        "by_type": {kind: by_type.get(kind, 0) for kind in TYPES},
        "by_type_tier": {kind: dict(sorted(counts.items())) for kind, counts in sorted(by_type_tier.items())},
        "topics": {
            topic_id: {
                "total": sum(counts.values()),
                "by_tier": {tier: counts.get(tier, 0) for tier in TIERS},
                "high_after": {
                    kind: high_topics[topic_id][kind]["after"]
                    for kind in ("roles", "identities")
                    if topic_id in high_topics and kind in high_topics[topic_id]
                },
            }
            for topic_id, counts in sorted(by_topic.items())
        },
        "high_tier": {"graph": high["graph"], "counts": high["counts"], "applied": high["applied"]},
        "guards": dict(sorted(guards.items())),
        "evidence": usage.evidence.as_dict() if usage is not None and usage.present else {"status": "none"},
        "thresholds": {
            "merge_jaccard": MERGE_JACCARD,
            "split_share": SPLIT_SHARE,
            "peer_share": usage.peer_share if usage is not None else None,
        },
        "never_auto": NEVER_AUTO,
        "notice": NOTICE,
    }


# ---------------------------------------------------------------------------
# Invariant


def check_invariant(computed, proposals: Iterable[Proposal]) -> list[str]:
    """IDs of proposals that would remove observed access (must be empty).

    Applies every modelled change of every proposal at once (removal is monotone, so a
    violation by one proposal shows here) and checks, by brute force over the graph,
    that every observed (principal, data) use still has a grant path within the hop
    bound and every observed assumption keeps its hop and endpoints.
    """
    from app.graph.compact import MAX_HOPS

    context, usage = computed.context, computed.usage
    if usage is None or not usage.present:
        return []
    proposals = list(proposals)
    removed: set[tuple[int, int]] = set()
    cut: set[tuple[int, int]] = set()
    disabled: set[int] = set()
    owner: dict = {}
    for p in proposals:
        for position in range(0, len(p.removals), 2):
            pair = (p.removals[position], p.removals[position + 1])
            removed.add(pair)
            owner.setdefault(pair, p.id)
        for position in range(0, len(p.cuts), 2):
            pair = (p.cuts[position], p.cuts[position + 1])
            cut.add(pair)
            owner.setdefault(pair, p.id)
        for node in p.disables:
            disabled.add(node)
            owner.setdefault(node, p.id)
    violations: set[str] = set()

    def reach(start: int) -> set[int]:
        seen = {start}
        frontier = [start]
        for _ in range(MAX_HOPS - 1):
            following = []
            for current in frontier:
                for target in context.hops.get(current, ()):
                    if target not in seen and target not in disabled and (current, target) not in cut:
                        seen.add(target)
                        following.append(target)
            frontier = following
        return seen

    def grants_before(start: int) -> set[int]:
        found = set()
        for holder in context.holders.get(start, ()) | ({start} if start in context.direct else set()):
            found |= context.direct[holder]
        return found

    for principal, items in usage.data_used.items():
        before = grants_before(principal)
        if principal in disabled:
            violations.add(owner[principal])
            continue
        holders = [h for h in reach(principal) if h in context.direct]
        for item in items:
            if item not in before:
                continue  # Not explained by the graph before either.
            if not any(item in context.direct[h] and (h, item) not in removed for h in holders):
                violations.update(owner.get((h, item), "") for h in holders if (h, item) in removed)
                violations.update(
                    owner.get(h, "") for h in context.holders.get(principal, ()) if h in disabled
                )
                violations.update(owner.get(pair, "") for pair in cut)
    for principal, roles in usage.assumed.items():
        for role in roles:
            if (principal, role) in cut:
                violations.add(owner[(principal, role)])
            for node in (principal, role):
                if node in disabled:
                    violations.add(owner[node])
    violations.discard("")
    return sorted(violations)


# ---------------------------------------------------------------------------
# Storage


def _changes(proposal: Proposal, computed, edges: dict) -> list[dict]:
    graph = computed.graph
    ids = graph.ids
    changes = []
    if proposal.kind == MERGE:
        return [
            {
                "op": "merge_roles",
                "keep": ids[proposal.subject],
                "retire": ids[proposal.target],
                "move_used_grants": proposal.detail["move_used_grants"],
                "repoint_assumers": True,
                "disable_retired": True,
            }
        ]
    if proposal.kind == SPLIT:
        return [{"op": "split_role", "role": ids[proposal.subject], "groups": proposal.detail["groups"]}]
    for node in proposal.disables:
        changes.append({"op": "disable_node", "node": ids[node], "type": graph.types[node], "delete": False})
    for flat, op in ((proposal.removals, "remove_grant"), (proposal.cuts, "cut_hop")):
        for position in range(0, min(len(flat), 2 * MAX_CHANGES), 2):
            pair = (flat[position], flat[position + 1])
            for edge in edges.get(pair, ()):
                changes.append(
                    {
                        "op": op,
                        "source": ids[pair[0]],
                        "target": ids[pair[1]],
                        "edge_id": graph.edge_id(edge),
                        "type": EDGE_KINDS[graph.edge_kind[edge]],
                        "actions": list(graph.edge_actions[edge][:20]),
                    }
                )
    return changes


# json.dumps(row, sort_keys=True, default=str), without building an encoder per row.
_DIGEST_JSON = json.JSONEncoder(sort_keys=True, default=str).encode


def _digest(row: tuple) -> str:
    return hashlib.sha256(_DIGEST_JSON(row).encode()).hexdigest()[:16]


PROPOSAL_COLUMNS = [
    "tenant_id", "revision", "proposal_id", "ordinal", "type", "tier", "base_tier", "topic_id", "subject_id",
    "subject_name", "subject_type", "target_id", "target_name", "weight", "identities", "epi_before",
    "epi_after", "reasons", "evidence", "changes", "digest",
]  # fmt: skip
JSON_POSITIONS = tuple(PROPOSAL_COLUMNS.index(c) for c in ("reasons", "evidence", "changes"))


def proposal_rows(computed_proposals: ComputedProposals, computed, tenant: str, revision: str):
    graph, topics = computed.graph, computed.topics
    ids, names, types = graph.ids, graph.names, graph.types
    for ordinal, p in enumerate(computed_proposals.proposals):
        target = p.target
        evidence = dict(p.detail or {})
        if p.kind in (REMOVE, TOXIC, WILDCARD, DISABLE_ROLE):
            evidence["identities_sample"] = computed_proposals.samples.get(p.subject, [])
        content = (
            TYPES[p.kind],
            TIERS[p.tier],
            TIERS[p.base_tier],
            topics[p.topic].id if p.topic >= 0 else "",
            ids[p.subject],
            names[p.subject][:256],
            types[p.subject],
            ids[target] if target >= 0 else "",
            names[target][:256] if target >= 0 else "",
            p.weight,
            p.identities,
            p.epi[0],
            p.epi[1],
            list(p.reasons),
            evidence,
            _changes(p, computed, computed_proposals.edges),
        )
        yield (tenant, revision, p.id, ordinal, *content, _digest(content))


def store_proposals(
    db: Session, tenant: str, revision: str, computed_proposals: ComputedProposals, computed
) -> None:
    """Stage rows in the caller's transaction (publication or sweep)."""
    from app.graph.clusters import _bulk_insert

    summary = dict(computed_proposals.summary)
    db.add(
        RevisionProposalSummary(
            tenant_id=tenant,
            revision=revision,
            proposal_version=PROPOSAL_VERSION,
            usage_fingerprint=computed.summary.get("usage_fingerprint", ""),
            total=len(computed_proposals.proposals),
            totals=summary,
            compute_ms=computed_proposals.compute_ms,
        )
    )
    db.add(
        RevisionProposalModel(
            tenant_id=tenant,
            revision=revision,
            proposal_version=PROPOSAL_VERSION,
            model=computed_proposals.model.dumps(),
        )
    )
    db.flush()
    _bulk_insert(
        db,
        RevisionProposal,
        PROPOSAL_COLUMNS,
        proposal_rows(computed_proposals, computed, tenant, revision),
        json_columns=JSON_POSITIONS,
    )


def delete_proposals(db: Session, tenant: str, revision: str) -> None:
    """Remove a revision's proposal rows (decisions are per tenant and stay)."""
    for model in (RevisionProposal, RevisionProposalModel, RevisionProposalSummary):
        db.execute(delete(model).where(model.tenant_id == tenant, model.revision == revision))


def stored_proposal_summary(db: Session, tenant: str, revision: str) -> RevisionProposalSummary | None:
    if not revision:
        return None
    row = db.get(RevisionProposalSummary, (tenant, revision))
    return (
        row if isinstance(row, RevisionProposalSummary) and row.proposal_version == PROPOSAL_VERSION else None
    )


@contextmanager
def _without_cycle_collection() -> Iterator[None]:
    """Pause the cyclic garbage collector: with a revision's graph and topics in memory, its
    full passes re-scan millions of live objects while proposals allocate (~a third of the
    proposal phase at 100k). The phase builds no reference cycles worth collecting early."""
    enabled = gc.isenabled()
    gc.disable()
    try:
        yield
    finally:
        if enabled:
            gc.enable()


def compute_and_store(db: Session, tenant: str, revision: str, computed, findings) -> ComputedProposals:
    """Proposals for a revision whose topics were just computed, in the caller's transaction."""
    with _without_cycle_collection():
        result = compute_proposals(computed, findings, policy_index(db, tenant, revision))
        store_proposals(db, tenant, revision, result, computed)
    return result


# ---------------------------------------------------------------------------
# Read API


class ProposalDecisionView(BaseModel):
    state: str  # "accepted" or "rejected"
    actor: str
    decided_at: datetime
    revision: str
    note: str
    # The proposal's content changed since the decision (same ID, new evidence or tier).
    stale: bool


class ProposalView(BaseModel):
    id: str
    ordinal: int
    type: str
    tier: str
    base_tier: str
    status: str = "proposed"  # Never "applied": Phase 3 proposes only.
    topic_id: str
    subject_id: str
    subject_name: str
    subject_type: str
    target_id: str
    target_name: str
    weight: int
    identities: int
    epi_before: float | None
    epi_after: float | None
    reasons: list[str]
    evidence: dict
    changes: list[dict]
    decision: ProposalDecisionView | None = None


class ProposalPageView(BaseModel):
    total: int
    shown: int
    limit: int
    cursor: int | None
    next_cursor: int | None


class ProposalListResponse(BaseModel):
    revision: str
    proposals: list[ProposalView]
    summary: dict
    view: ProposalPageView
    notice: str = NOTICE


class ProposalDetailResponse(BaseModel):
    revision: str
    proposal: ProposalView
    topic: dict | None
    resource: dict | None
    evidence: dict  # Revision-wide usage evidence (window, sources, coverage per service).
    never_auto: dict[str, str]
    graph_delta: dict | None  # Graph-wide excess privilege before/after this proposal alone.
    notice: str = NOTICE


class ProposalNotFound(LookupError):
    pass


def _decision(row: ProposalDecision | None, digest: str) -> ProposalDecisionView | None:
    if row is None:
        return None
    return ProposalDecisionView(
        state=row.state,
        actor=row.actor,
        decided_at=row.decided_at,
        revision=row.revision,
        note=row.note,
        stale=row.digest != digest,
    )


def _view(row: RevisionProposal, decision: ProposalDecision | None) -> ProposalView:
    def loaded(value):
        return json.loads(value) if isinstance(value, str) else value

    return ProposalView(
        id=row.proposal_id,
        ordinal=row.ordinal,
        type=row.type,
        tier=row.tier,
        base_tier=row.base_tier,
        topic_id=row.topic_id,
        subject_id=row.subject_id,
        subject_name=row.subject_name,
        subject_type=row.subject_type,
        target_id=row.target_id,
        target_name=row.target_name,
        weight=row.weight,
        identities=row.identities,
        epi_before=row.epi_before,
        epi_after=row.epi_after,
        reasons=loaded(row.reasons),
        evidence=loaded(row.evidence),
        changes=loaded(row.changes),
        decision=_decision(decision, row.digest),
    )


DECISION_STATES = ("accepted", "rejected")
FILTER_STATES = ("pending", "accepted", "rejected")


def ordinal_ranges(totals: dict, tier: str | None, kind: str | None) -> list[tuple[int, int]]:
    """Half-open ordinal ranges of a revision's proposals of one tier and/or type.

    Proposals are ordered by (tier, type, ...) (``compute_proposals``), so each (tier, type)
    group is one contiguous block whose size is in the stored summary (``by_type_tier``).
    """
    by_type_tier = totals.get("by_type_tier", {})
    ranges: list[tuple[int, int]] = []
    start = 0
    for tier_ in TIERS:
        for kind_ in TYPES:
            count = by_type_tier.get(kind_, {}).get(tier_, 0)
            if count and tier in (None, tier_) and kind in (None, kind_):
                if ranges and ranges[-1][1] == start:
                    ranges[-1] = (ranges[-1][0], start + count)
                else:
                    ranges.append((start, start + count))
            start += count
    return ranges


def summary_count(
    totals: dict, tier: str | None, kind: str | None, topic: str | None, ranges: list | None
) -> int | None:
    """Matching proposals from the stored summary counts, or None if they don't say."""
    if topic:
        if kind:
            return None
        found = totals.get("topics", {}).get(topic)
        if found is None:
            return 0
        return found["by_tier"].get(tier, 0) if tier else found["total"]
    if ranges is not None:
        return sum(high - low for low, high in ranges)
    return totals.get("total")


def proposal_page(
    db: Session,
    summary: RevisionProposalSummary,
    *,
    tier: str | None = None,
    kind: str | None = None,
    topic: str | None = None,
    subject: str | None = None,
    state: str | None = None,
    cursor: int | None = None,
    limit: int = 50,
) -> ProposalListResponse:
    """A page of proposals in their deterministic order (ordinal), optionally filtered."""
    if not 1 <= limit <= MAX_PAGE or (cursor is not None and cursor < -1):
        raise ValueError("Proposal page outside supported bounds")
    if tier is not None and tier not in TIERS or kind is not None and kind not in TYPES:
        raise ValueError("Unknown proposal tier or type")
    if state is not None and state not in FILTER_STATES:
        raise ValueError("Unknown decision state")
    tenant, revision = summary.tenant_id, summary.revision
    totals = summary.totals if isinstance(summary.totals, dict) else json.loads(summary.totals)
    scope = [RevisionProposal.tenant_id == tenant, RevisionProposal.revision == revision]
    # Rows are stored tier first, then type: a tier or type filter is a few ordinal ranges,
    # each read through the order index (no per-tier or per-type index is kept).
    ranges = ordinal_ranges(totals, tier, kind) if tier or kind else None
    if tier:
        scope.append(RevisionProposal.tier == tier)
    if kind:
        scope.append(RevisionProposal.type == kind)
    if topic:
        scope.append(RevisionProposal.topic_id == topic)
    if subject:
        scope.append((RevisionProposal.subject_id == subject) | (RevisionProposal.target_id == subject))
    ordinal = RevisionProposal.ordinal
    total = None if subject else summary_count(totals, tier, kind, topic, ranges)
    if state and total is not None:
        # Decided proposals of the filter, looked up by primary key (decisions are few).
        decided_ = _decided_ids(db, tenant, None if state == "pending" else state)
        found = 0
        for start_ in range(0, len(decided_), DECIDED_BATCH):
            batch = decided_[start_ : start_ + DECIDED_BATCH]
            found += db.scalar(
                select(func.count())
                .select_from(RevisionProposal)
                .where(*scope, RevisionProposal.proposal_id.in_(batch))
            )
        total = total - found if state == "pending" else found
    if state:
        decided = select(ProposalDecision.proposal_id).where(ProposalDecision.tenant_id == tenant)
        if state == "pending":
            scope.append(RevisionProposal.proposal_id.not_in(decided))
        else:
            scope.append(RevisionProposal.proposal_id.in_(decided.where(ProposalDecision.state == state)))
    if total is None:
        total = sum(
            db.scalar(
                select(func.count())
                .select_from(RevisionProposal)
                .where(*scope, *([ordinal >= low, ordinal < high] if high is not None else []))
            )
            for low, high in (ranges if ranges is not None else [(0, None)])
        )
    start = 0 if cursor is None else cursor + 1
    rows: list[RevisionProposal] = []
    for low, high in ranges if ranges is not None else [(0, None)]:
        if high is not None and high <= start:
            continue
        bounded = [ordinal >= max(low, start)] + ([ordinal < high] if high is not None else [])
        query = select(RevisionProposal).where(*scope, *bounded).order_by(ordinal).limit(limit - len(rows))
        rows += db.scalars(query)
        if len(rows) == limit:
            break
    decisions = _decisions(db, tenant, [row.proposal_id for row in rows])
    return ProposalListResponse(
        revision=revision,
        proposals=[_view(row, decisions.get(row.proposal_id)) for row in rows],
        summary={
            **{k: v for k, v in totals.items() if k not in ("topics", "never_auto")},
            "decisions": decision_counts(db, tenant, revision),
        },
        view=ProposalPageView(
            total=total,
            shown=len(rows),
            limit=limit,
            cursor=cursor,
            next_cursor=rows[-1].ordinal if len(rows) == limit and rows else None,
        ),
    )


def _decisions(db: Session, tenant: str, proposal_ids: list[str]) -> dict[str, ProposalDecision]:
    if not proposal_ids:
        return {}
    return {
        row.proposal_id: row
        for row in db.scalars(
            select(ProposalDecision).where(
                ProposalDecision.tenant_id == tenant, ProposalDecision.proposal_id.in_(proposal_ids)
            )
        )
    }


def decision_counts(db: Session, tenant: str, revision: str) -> dict:
    """Accepted and rejected proposals of the revision (decisions carried forward by ID)."""
    states = dict(
        db.execute(
            select(ProposalDecision.proposal_id, ProposalDecision.state).where(
                ProposalDecision.tenant_id == tenant
            )
        ).all()
    )
    found: Counter = Counter()
    decided = sorted(states)
    for start in range(0, len(decided), DECIDED_BATCH):
        for proposal_id_ in db.scalars(
            select(RevisionProposal.proposal_id).where(
                RevisionProposal.tenant_id == tenant,
                RevisionProposal.revision == revision,
                RevisionProposal.proposal_id.in_(decided[start : start + DECIDED_BATCH]),
            )
        ):
            found[states[proposal_id_]] += 1
    return {state: found.get(state, 0) for state in DECISION_STATES}


def proposal_row(db: Session, tenant: str, revision: str, proposal_id_: str) -> RevisionProposal:
    row = db.get(RevisionProposal, (tenant, revision, proposal_id_))
    if not isinstance(row, RevisionProposal):
        raise ProposalNotFound(proposal_id_)
    return row


def proposal_detail(
    db: Session, summary: RevisionProposalSummary, proposal_id_: str
) -> ProposalDetailResponse:
    tenant, revision = summary.tenant_id, summary.revision
    row = proposal_row(db, tenant, revision, proposal_id_)
    decision = db.get(ProposalDecision, (tenant, proposal_id_))
    topic = None
    if row.topic_id:
        found = db.get(RevisionTopic, (tenant, revision, row.topic_id))
        if isinstance(found, RevisionTopic):
            topic = {"id": found.topic_id, "name": found.name, "label": found.label, "reason": found.reason}
    resource = None
    if row.target_id and row.type in ("remove_grant", "break_toxic_path"):
        member = db.scalar(
            select(RevisionTopicMember).where(
                RevisionTopicMember.tenant_id == tenant,
                RevisionTopicMember.revision == revision,
                RevisionTopicMember.entity_id == row.target_id,
                RevisionTopicMember.kind == "resource",
            )
        )
        if member is not None:
            label = db.get(RevisionTopic, (tenant, revision, member.topic_id))
            resource = {
                "id": member.entity_id,
                "name": member.name,
                "type": member.entity_type,
                "sensitivity": member.sensitivity,
                "topic_id": member.topic_id,
                "topic": label.name if isinstance(label, RevisionTopic) else "",
                "label_seed": member.seed,
                "label_reason": member.reason,
            }
    totals = summary.totals if isinstance(summary.totals, dict) else json.loads(summary.totals)
    model = load_model(db, tenant, revision)
    delta = None
    if model is not None:
        delta = model.evaluate(model.selection([row.ordinal]))
        delta = {key: delta[key] for key in ("graph", "counts", "applied", "skipped")}
    return ProposalDetailResponse(
        revision=revision,
        proposal=_view(row, decision if isinstance(decision, ProposalDecision) else None),
        topic=topic,
        resource=resource,
        evidence=totals.get("evidence", {}),
        never_auto={
            reason: NEVER_AUTO[reason] for reason in _view(row, None).reasons if reason in NEVER_AUTO
        },
        graph_delta=delta,
    )


def decide(
    db: Session, tenant: str, revision: str, proposal_id_: str, state: str, actor: str, note: str
) -> ProposalDecision | None:
    """Record (or clear, with state "pending") the tenant's decision on a proposal by ID."""
    if state not in (*DECISION_STATES, "pending"):
        raise ValueError("Unknown decision state")
    row = proposal_row(db, tenant, revision, proposal_id_)
    existing = db.get(ProposalDecision, (tenant, proposal_id_))
    if state == "pending":
        if existing is not None:
            db.delete(existing)
        return None
    if existing is None:
        existing = ProposalDecision(tenant_id=tenant, proposal_id=proposal_id_)
        db.add(existing)
    existing.state = state
    existing.actor = actor[:256]
    existing.revision = revision
    existing.digest = row.digest
    existing.note = note[:500]
    existing.decided_at = now()
    return existing


# ---------------------------------------------------------------------------
# What-if model cache and metrics


_models: dict[tuple[str, str], WhatIfModel] = {}
_models_lock = threading.Lock()
MODEL_CACHE = 2


def load_model(db: Session, tenant: str, revision: str) -> WhatIfModel | None:
    """The revision's what-if model (revisions are immutable, so it is cached per process)."""
    key = (tenant, revision)
    with _models_lock:
        found = _models.get(key)
    if found is not None:
        return found
    row = db.get(RevisionProposalModel, key)
    if not isinstance(row, RevisionProposalModel) or row.proposal_version != PROPOSAL_VERSION:
        return None
    model = WhatIfModel.loads(row.model)
    with _models_lock:
        while len(_models) >= MODEL_CACHE:
            _models.pop(next(iter(_models)))
        _models[key] = model
    return model


MAX_SELECTED = 2000


def selected_ordinals(
    db: Session,
    tenant: str,
    revision: str,
    proposal_ids: list[str] | None,
    tier: str | None,
    decision: str | None,
    model: WhatIfModel,
) -> list[int]:
    """Ordinals of explicit proposals (unknown IDs raise ``ProposalNotFound``), a whole tier,
    or the tenant's accepted proposals (decisions carried forward by ID)."""
    chosen: set[int] = set()
    if proposal_ids:
        if len(proposal_ids) > MAX_SELECTED:
            raise ValueError("Too many proposals selected")
        found = dict(
            db.execute(
                select(RevisionProposal.proposal_id, RevisionProposal.ordinal).where(
                    RevisionProposal.tenant_id == tenant,
                    RevisionProposal.revision == revision,
                    RevisionProposal.proposal_id.in_(proposal_ids),
                )
            ).all()
        )
        missing = sorted(set(proposal_ids) - set(found))
        if missing:
            raise ProposalNotFound(",".join(missing[:5]))
        chosen.update(found.values())
    if tier is not None:
        if tier not in TIERS:
            raise ValueError("Unknown proposal tier")
        chosen.update(i for i, value in enumerate(model.proposal_tier) if value == tier)
    if decision is not None:
        if decision not in DECISION_STATES:
            raise ValueError("Unknown decision state")
        decided = _decided_ids(db, tenant, decision)
        for start in range(0, len(decided), DECIDED_BATCH):
            chosen.update(
                db.scalars(
                    select(RevisionProposal.ordinal).where(
                        RevisionProposal.tenant_id == tenant,
                        RevisionProposal.revision == revision,
                        RevisionProposal.proposal_id.in_(decided[start : start + DECIDED_BATCH]),
                    )
                )
            )
    return sorted(chosen)


DECIDED_BATCH = 1000


def _decided_ids(db: Session, tenant: str, state: str | None = None) -> list[str]:
    """The tenant's decided proposal IDs (optionally of one state).

    Read first and then looked up in the revision by primary key: a join of the two tables
    is planned as repeated scans of the revision's proposals while the decision table's
    statistics are stale (e.g. right after a bulk decision), which took seconds at 100k.
    """
    query = select(ProposalDecision.proposal_id).where(ProposalDecision.tenant_id == tenant)
    if state is not None:
        query = query.where(ProposalDecision.state == state)
    return sorted(db.scalars(query))


@dataclass
class Overlay:
    """Edges removed and nodes disabled, by entity ID (for blast-radius simulation)."""

    removed: set[tuple[str, str]] = field(default_factory=set)
    edge_ids: set[str] = field(default_factory=set)
    disabled: set[str] = field(default_factory=set)
    applied: Counter = field(default_factory=Counter)
    skipped: Counter = field(default_factory=Counter)


def overlay_from(model: WhatIfModel, ordinals: list[int]) -> Overlay:
    chosen = model.selection(ordinals)
    ids = model.ids
    overlay = Overlay(applied=chosen.applied, skipped=chosen.skipped)
    for holder, items in chosen.removed.items():
        for item in items:
            overlay.removed.add((ids[holder], ids[item]))
    for a, b in chosen.cut:
        overlay.removed.add((ids[a], ids[b]))
    overlay.disabled = {ids[node] for node in chosen.disabled}
    return overlay


# ---------------------------------------------------------------------------
# Operator backfill and worker sweep


def backfill(tenant: str, wait: bool = True) -> dict:
    """Compute and store proposals for a tenant's current revision under the publication lock.

    Topic rows must exist for the revision; their computation is repeated in memory (it is
    deterministic) because proposals reuse its grant, hop and peer structures.
    """
    from app.core.config import get_settings
    from app.graph.privilege import load_usage
    from app.graph.repository import get_graph_store
    from app.graph.topics import compute_topics

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
        stored = stored_proposal_summary(db, tenant, revision)
        topic_summary = db.get(RevisionTopicSummary, (tenant, revision))
        if topic_summary is None:
            return {"tenant": tenant, "revision": revision, "backfilled": False, "waiting_for": "topics"}
        if stored is not None and stored.usage_fingerprint == topic_summary.usage_fingerprint:
            return {"tenant": tenant, "revision": revision, "backfilled": False}
        delete_proposals(db, tenant, revision)
        graph = CompactGraph.from_snapshot(get_graph_store().snapshot(tenant, revision))
        computed = compute_topics(
            graph, load_usage(db, tenant, graph, peer_share=get_settings().peer_baseline_share)
        )
        result = compute_and_store(db, tenant, revision, computed, stored_findings(db, tenant, revision))
        db.commit()
        return {
            "tenant": tenant,
            "revision": revision,
            "backfilled": True,
            "proposals": len(result.proposals),
        }


_failed: dict[tuple[str, str], float] = {}


def missing_proposals(db: Session, limit: int) -> list[tuple[str, str]]:
    """(tenant, revision) pairs whose current revision has topics of the current version but no
    proposals of this version, or proposals computed with other usage evidence than its topics."""
    from app.graph.topics import TOPIC_VERSION

    present = (
        select(RevisionProposalSummary.tenant_id)
        .where(
            RevisionProposalSummary.tenant_id == TenantState.tenant_id,
            RevisionProposalSummary.revision == TenantState.revision,
            RevisionProposalSummary.proposal_version == PROPOSAL_VERSION,
            RevisionProposalSummary.usage_fingerprint == RevisionTopicSummary.usage_fingerprint,
        )
        .exists()
    )
    rows = db.execute(
        select(TenantState.tenant_id, TenantState.revision)
        .join(
            RevisionTopicSummary,
            (RevisionTopicSummary.tenant_id == TenantState.tenant_id)
            & (RevisionTopicSummary.revision == TenantState.revision),
        )
        .where(RevisionTopicSummary.topic_version == TOPIC_VERSION, ~present)
        .order_by(TenantState.tenant_id)
        .limit(limit)
    )
    return [(tenant, revision) for tenant, revision in rows]


def backfill_missing(limit: int = SWEEP_TENANTS) -> list[dict]:
    """Backfill up to ``limit`` tenants' current revisions; never raises for one tenant's failure."""

    def pending(count: int) -> list[tuple[str, str]]:
        with session_factory()() as db:
            return missing_proposals(db, count)

    return run_sweep(
        "Proposal",
        pending,
        lambda tenant: backfill(tenant, wait=False),
        _failed,
        lambda result: f"proposals={result.get('proposals', 0)}",
        limit,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Store optimizer proposals for a tenant's current revision")
    parser.add_argument("--tenant", required=True)
    args = parser.parse_args()
    try:
        result = backfill(args.tenant)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
