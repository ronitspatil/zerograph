"""Current vs optimized views: what a set of proposals would change, bounded to what is shown.

Everything here reads the revision's stored what-if model (``app.graph.whatif``) and its
topic rows; nothing loads the revision's snapshot and nothing is applied.

* ``slice_overlay``: of a selection's removed grants ``(holder, data)``, cut hops
  ``(a, b)`` and disabled nodes, the ones whose endpoints are all in a visible slice
  (at most ``MAX_SLICE`` entity IDs), with the selection's graph-wide totals computed
  exactly as ``WhatIfModel.evaluate`` counts them.
* ``link_removals``: per pair of topics, the cross-topic grants the selection removes,
  counted like the topic map's links (``app.graph.topics``): a grant of a non-hub role
  or identity whose primary topic differs from the asset's topic. A disabled holder
  loses every grant it has.
* ``topic_slice``: the entity IDs of a topic's bounded subgraph: its first roles,
  identities and data assets (by their stored rank) and the outside assets its roles
  have removal proposals on, so the optimized view can show those removals.
"""

import hashlib
import threading
from collections import Counter
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import RevisionProposal, RevisionTopicMember
from app.graph.whatif import Selection, WhatIfModel

MAX_SLICE = 500
SLICE_LIMITS = {"role": 60, "identity": 60, "resource": 120, "outside": 160}
CACHE = 8

_lock = threading.Lock()
_resource_topics: dict[tuple[str, str], dict[int, int]] = {}
_selections: dict[tuple, Selection] = {}
_evaluations: dict[tuple, dict] = {}


def _remember(cache: dict, key, value, size: int = CACHE):
    with _lock:
        while len(cache) >= size:
            cache.pop(next(iter(cache)))
        cache[key] = value
    return value


def indexes(model: WhatIfModel) -> tuple[dict[str, int], dict[int, int]]:
    """(entity ID -> node index, record node -> primary topic index), built once per model."""
    found = getattr(model, "_optimized_indexes", None)
    if found is None:
        by_id = {entity: position for position, entity in enumerate(model.ids)}
        primary = {model.node[position]: model.topic[position] for position in range(len(model.node))}
        found = (by_id, primary)
        # Models are immutable and cached by the loader; the indexes live and die with them.
        model._optimized_indexes = found  # type: ignore[attr-defined]
    return found


def selection_key(tenant: str, revision: str, ordinals: list[int]) -> tuple:
    digest = hashlib.sha256(",".join(map(str, ordinals)).encode()).hexdigest()
    return (tenant, revision, digest)


def selection_of(model: WhatIfModel, key: tuple, ordinals: list[int]) -> Selection:
    """The model's selection for these ordinals (cached: tiers and accepted sets repeat)."""
    with _lock:
        found = _selections.get(key)
    if found is not None:
        return found
    return _remember(_selections, key, model.selection(ordinals))


def evaluation_of(model: WhatIfModel, key: tuple, chosen: Selection) -> dict:
    with _lock:
        found = _evaluations.get(key)
    if found is not None:
        return found
    return _remember(_evaluations, key, model.evaluate(chosen))


def selection_totals(model: WhatIfModel, chosen: Selection) -> dict:
    """Graph-wide counts of a selection, as ``WhatIfModel.evaluate`` reports them."""
    direct = model.direct
    removed = sum(len(items & direct.get(holder, frozenset())) for holder, items in chosen.removed.items())
    restricted = sum(
        model.restricted[item]
        for holder, items in chosen.removed.items()
        for item in items & direct.get(holder, frozenset())
    )
    return {
        "grants_removed": removed,
        "restricted_grants_removed": restricted,
        "hops_cut": len(chosen.cut),
        "disabled_nodes": len(chosen.disabled),
    }


@dataclass
class SliceOverlay:
    removed: list[tuple[str, str]]  # (holder, data asset) grants removed
    cut: list[tuple[str, str]]  # (source, target) role or tool hops cut
    disabled: list[str]
    unknown: int  # slice IDs not in the model (not principals or assets of the revision)


def slice_overlay(model: WhatIfModel, chosen: Selection, node_ids: list[str]) -> SliceOverlay:
    """The selection's removals, cut hops and disabled nodes inside a visible slice."""
    if len(node_ids) > MAX_SLICE:
        raise ValueError("Slice above supported bounds")
    by_id, _ = indexes(model)
    ids = model.ids
    shown = {by_id[entity] for entity in node_ids if entity in by_id}
    removed = sorted(
        (ids[holder], ids[item])
        for holder, items in chosen.removed.items()
        if holder in shown
        for item in items & model.direct.get(holder, frozenset())
        if item in shown
    )
    cut = sorted((ids[a], ids[b]) for a, b in chosen.cut if a in shown and b in shown)
    disabled = sorted(ids[node] for node in chosen.disabled if node in shown)
    return SliceOverlay(removed, cut, disabled, len(set(node_ids)) - len(shown))


def resource_topics(db: Session, tenant: str, revision: str, model: WhatIfModel) -> dict[int, int]:
    """Data asset node index -> topic index (from the revision's topic rows; cached)."""
    key = (tenant, revision)
    with _lock:
        found = _resource_topics.get(key)
    if found is not None:
        return found
    by_id, _ = indexes(model)
    topic_index = {topic_id: position for position, (topic_id, _) in enumerate(model.topics)}
    mapping: dict[int, int] = {}
    for entity, topic in db.execute(
        select(RevisionTopicMember.entity_id, RevisionTopicMember.topic_id).where(
            RevisionTopicMember.tenant_id == tenant,
            RevisionTopicMember.revision == revision,
            RevisionTopicMember.kind == "resource",
        )
    ):
        if entity in by_id and topic in topic_index:
            mapping[by_id[entity]] = topic_index[topic]
    return _remember(_resource_topics, key, mapping, size=2)


def topic_links(model: WhatIfModel, assets: dict[int, int], chosen: Selection | None = None) -> Counter:
    """Cross-topic grants per (topic, topic) pair (sorted indices), like the topic map's links.

    Without a selection: all of them (the map's link weights). With one: those it removes.
    """
    _, primary = indexes(model)
    hubs, direct = model.hubs, model.direct
    links: Counter = Counter()

    def count(holder: int, items) -> None:
        own = primary.get(holder, -1)
        if holder in hubs or own < 0:
            return
        for item in items:
            topic = assets.get(item, -1)
            if topic < 0 or topic == own:
                continue
            links[(own, topic) if own < topic else (topic, own)] += 1

    if chosen is None:
        for holder, items in direct.items():
            count(holder, items)
        return links
    for holder in chosen.disabled:
        count(holder, direct.get(holder, ()))
    for holder, items in chosen.removed.items():
        if holder not in chosen.disabled:
            count(holder, items & direct.get(holder, frozenset()))
    return links


def link_removals(model: WhatIfModel, assets: dict[int, int], chosen: Selection) -> list[dict]:
    """Removed cross-topic grants per topic link, keyed like the map's links (``source`` <
    ``target`` by topic ID), largest first."""
    topics = model.topics
    rows = [
        (*sorted((topics[a][0], topics[b][0])), value)
        for (a, b), value in topic_links(model, assets, chosen).items()
    ]
    return [
        {"source": source, "target": target, "removed": value}
        for source, target, value in sorted(rows, key=lambda row: (-row[2], row[0], row[1]))
    ]


def topic_slice(db: Session, tenant: str, revision: str, topic: str, limits: dict[str, int]) -> dict:
    """Entity IDs of a topic's bounded subgraph, grouped: role, identity, resource, outside."""
    if any(not 0 <= limits.get(kind, 0) <= SLICE_LIMITS[kind] for kind in SLICE_LIMITS):
        raise ValueError("Topic subgraph limits outside supported bounds")
    groups: dict[str, list[str]] = {}
    for kind in ("role", "identity", "resource"):
        groups[kind] = list(
            db.scalars(
                select(RevisionTopicMember.entity_id)
                .where(
                    RevisionTopicMember.tenant_id == tenant,
                    RevisionTopicMember.revision == revision,
                    RevisionTopicMember.topic_id == topic,
                    RevisionTopicMember.kind == kind,
                )
                .order_by(RevisionTopicMember.ordinal)
                .limit(limits.get(kind, 0))
            )
        )
    groups["outside"] = []
    if groups["role"] and limits.get("outside", 0):
        shown = set(groups["resource"])
        # The topic's removal proposals on these roles, in proposal order (tier first).
        targets: list[str] = []
        for target in db.scalars(
            select(RevisionProposal.target_id)
            .where(
                RevisionProposal.tenant_id == tenant,
                RevisionProposal.revision == revision,
                RevisionProposal.topic_id == topic,
                RevisionProposal.type.in_(("remove_grant", "break_toxic_path")),
                RevisionProposal.subject_id.in_(groups["role"]),
                RevisionProposal.target_id != "",
            )
            .order_by(RevisionProposal.ordinal)
            .limit(limits["outside"] * 8)
        ):
            if target not in shown and target not in targets:
                targets.append(target)
            if len(targets) >= limits["outside"]:
                break
        home = (
            dict(
                db.execute(
                    select(RevisionTopicMember.entity_id, RevisionTopicMember.topic_id).where(
                        RevisionTopicMember.tenant_id == tenant,
                        RevisionTopicMember.revision == revision,
                        RevisionTopicMember.entity_id.in_(targets),
                    )
                ).all()
            )
            if targets
            else {}
        )
        for target in targets:
            # Assets of this topic beyond the first page still count as its own.
            groups["resource" if home.get(target) == topic else "outside"].append(target)
    return groups
