"""What-if model: excess privilege before and after applying optimizer proposals.

The worker builds a ``WhatIfModel`` with the proposals of a revision and stores it
compressed beside them (``revision_proposal_models``). The API evaluates a set of
proposals against it without loading the revision's snapshot: grants per holder,
role/tool hops, hub roles, each role's and identity's holder closure and granted and
needed weights (with and without hubs), and each proposal's removals.

Applying proposals:

* **Removed grants** ``(holder, data)`` drop out of the holder's grants.
* **Disabled nodes** contribute nothing (granted and needed weight 0) and stop every
  closure that passed through them; **cut hops** ``(a, b)`` stop closures using them.
  Affected closures are recomputed with the same hop bound as the analysis.
* A role's or identity's granted weight after is its granted weight minus the weight of
  data no remaining holder of its closure still grants. Needed weight is held at the
  analysis value (proposals never remove observed use), clamped to the granted weight
  after. Aggregates follow ``app.graph.privilege.aggregate``: ``1 - sum needed / sum
  granted`` over rows with usage evidence, with and without hubs.
* Merges and splits restructure roles while keeping every used grant; they are not
  modelled (reported as skipped).
"""

import json
import zlib
from array import array
from collections import Counter
from dataclasses import dataclass, field

from app.graph.compact import MAX_HOPS

MODEL_VERSION = 1
BASIS_CODES = ("used", "inferred", "none")
ROLE_RECORD, IDENTITY_RECORD = 0, 1
# Proposal types whose effect is modelled (others restructure roles; see module docstring).
MODELLED = frozenset(
    {"remove_grant", "disable_identity", "disable_role", "scope_wildcard", "break_toxic_path"}
)


def _csr(rows) -> tuple[array, array]:
    offsets, values = array("q", [0]), array("q")
    for row in rows:
        values.extend(row)
        offsets.append(len(values))
    return offsets, values


def _rows(offsets: array, values: array) -> list[tuple[int, ...]]:
    return [tuple(values[offsets[i] : offsets[i + 1]]) for i in range(len(offsets) - 1)]


@dataclass
class WhatIfModel:
    ids: list[str]
    weight: array  # sensitivity weight per node (0: not a data asset)
    restricted: bytearray
    direct: dict[int, frozenset[int]]  # holder -> data granted
    hops: dict[int, tuple[int, ...]]
    hubs: frozenset[int]
    topics: list[tuple[str, str]]  # (topic ID, name) by topic index
    # Records (roles and identities), parallel arrays.
    node: array
    kind: bytearray
    topic: array
    basis: bytearray
    granted: array
    granted_core: array
    needed: array
    needed_core: array
    closure: array  # index into ``closures``
    closures: list[tuple[int, ...]]  # holders and pass-through pivots reachable (start excluded)
    # Proposals by ordinal.
    proposal_type: list[str]
    proposal_tier: list[str]
    removals: list[tuple[int, ...]]  # flattened (holder, data) pairs
    cuts: list[tuple[int, ...]]  # flattened (a, b) hop pairs
    disables: list[tuple[int, ...]]
    _holders_of: dict[int, list[int]] = field(default_factory=dict, repr=False)

    # -- serialization -------------------------------------------------------

    def dumps(self) -> bytes:
        holders = sorted(self.direct)
        grant_offsets, grant_values = _csr(sorted(self.direct[h]) for h in holders)
        hop_sources = sorted(self.hops)
        hop_offsets, hop_values = _csr(self.hops[h] for h in hop_sources)
        arrays = {
            "weight": self.weight,
            "restricted": array("b", self.restricted),
            "holders": array("q", holders),
            "grant_offsets": grant_offsets,
            "grant_values": grant_values,
            "hop_sources": array("q", hop_sources),
            "hop_offsets": hop_offsets,
            "hop_values": hop_values,
            "hubs": array("q", sorted(self.hubs)),
            "node": self.node,
            "kind": array("b", self.kind),
            "topic": self.topic,
            "basis": array("b", self.basis),
            "granted": self.granted,
            "granted_core": self.granted_core,
            "needed": self.needed,
            "needed_core": self.needed_core,
            "closure": self.closure,
        }
        for name, rows in (
            ("closures", self.closures),
            ("removals", self.removals),
            ("cuts", self.cuts),
            ("disables", self.disables),
        ):
            arrays[name + "_offsets"], arrays[name + "_values"] = _csr(rows)
        header = {
            "version": MODEL_VERSION,
            "ids": self.ids,
            "topics": self.topics,
            "proposal_type": self.proposal_type,
            "proposal_tier": self.proposal_tier,
            "arrays": [[name, values.typecode, len(values)] for name, values in arrays.items()],
        }
        head = json.dumps(header, separators=(",", ":")).encode()
        body = b"".join(values.tobytes() for values in arrays.values())
        return zlib.compress(len(head).to_bytes(8, "big") + head + body, 1)

    @classmethod
    def loads(cls, blob: bytes) -> "WhatIfModel":
        raw = zlib.decompress(blob)
        size = int.from_bytes(raw[:8], "big")
        header = json.loads(raw[8 : 8 + size])
        if header["version"] != MODEL_VERSION:
            raise ValueError("Unsupported what-if model version")
        position = 8 + size
        arrays: dict[str, array] = {}
        for name, code, length in header["arrays"]:
            values = array(code)
            end = position + length * values.itemsize
            values.frombytes(raw[position:end])
            arrays[name] = values
            position = end
        holders = arrays["holders"]
        grants = _rows(arrays["grant_offsets"], arrays["grant_values"])
        hop_rows = _rows(arrays["hop_offsets"], arrays["hop_values"])
        return cls(
            ids=header["ids"],
            weight=arrays["weight"],
            restricted=bytearray(arrays["restricted"].tobytes()),
            direct={holder: frozenset(row) for holder, row in zip(holders, grants, strict=True)},
            hops=dict(zip(arrays["hop_sources"], hop_rows, strict=True)),
            hubs=frozenset(arrays["hubs"]),
            topics=[tuple(topic) for topic in header["topics"]],
            node=arrays["node"],
            kind=bytearray(arrays["kind"].tobytes()),
            topic=arrays["topic"],
            basis=bytearray(arrays["basis"].tobytes()),
            granted=arrays["granted"],
            granted_core=arrays["granted_core"],
            needed=arrays["needed"],
            needed_core=arrays["needed_core"],
            closure=arrays["closure"],
            closures=_rows(arrays["closures_offsets"], arrays["closures_values"]),
            proposal_type=header["proposal_type"],
            proposal_tier=header["proposal_tier"],
            removals=_rows(arrays["removals_offsets"], arrays["removals_values"]),
            cuts=_rows(arrays["cuts_offsets"], arrays["cuts_values"]),
            disables=_rows(arrays["disables_offsets"], arrays["disables_values"]),
        )

    # -- evaluation ----------------------------------------------------------

    def holders_of(self, holder: int) -> list[int]:
        """Closure indices that contain ``holder`` (built once per model)."""
        if not self._holders_of:
            index: dict[int, list[int]] = {}
            for position, members in enumerate(self.closures):
                for member in members:
                    index.setdefault(member, []).append(position)
            self._holders_of = index
        return self._holders_of.get(holder, [])

    def selection(self, ordinals) -> "Selection":
        """Removals, cut hops and disabled nodes of the modelled proposals in ``ordinals``."""
        chosen = Selection()
        for ordinal in sorted(set(ordinals)):
            kind = self.proposal_type[ordinal]
            if kind not in MODELLED:
                chosen.skipped[kind] += 1
                continue
            chosen.applied[kind] += 1
            chosen.tiers[self.proposal_tier[ordinal]] += 1
            pairs = self.removals[ordinal]
            for position in range(0, len(pairs), 2):
                chosen.removed.setdefault(pairs[position], set()).add(pairs[position + 1])
            pairs = self.cuts[ordinal]
            for position in range(0, len(pairs), 2):
                chosen.cut.add((pairs[position], pairs[position + 1]))
            chosen.disabled.update(self.disables[ordinal])
        return chosen

    def _closure(self, start: int, chosen: "Selection") -> frozenset[int]:
        """Nodes reachable from ``start`` over hops avoiding disabled nodes and cut hops."""
        seen = {start}
        frontier = [start]
        disabled, cut = chosen.disabled, chosen.cut
        for _ in range(MAX_HOPS - 1):
            following = []
            for current in frontier:
                for target in self.hops.get(current, ()):
                    if target not in seen and target not in disabled and (current, target) not in cut:
                        seen.add(target)
                        following.append(target)
            if not following:
                break
            frontier = following
        seen.discard(start)
        return frozenset(seen)

    def evaluate(self, chosen: "Selection") -> dict:
        """Before/after aggregates (graph-wide and per topic) for a selection."""
        removed, disabled, cut = chosen.removed, chosen.disabled, chosen.cut
        direct, weight, hubs = self.direct, self.weight, self.hubs
        touched_closures: set[int] = set()
        for node in (*removed, *disabled, *{a for a, _ in cut}):
            touched_closures.update(self.holders_of(node))
        cut_sources = {a for a, _ in cut}
        after_direct: dict[int, frozenset[int]] = {
            holder: direct[holder] - items for holder, items in removed.items() if holder in direct
        }

        def grants(holder: int) -> frozenset[int]:
            if holder in disabled:
                return frozenset()
            found = after_direct.get(holder)
            return direct.get(holder, frozenset()) if found is None else found

        memo: dict[tuple, tuple[int, int]] = {}

        def loss(
            start: int, members: tuple[int, ...], excluded: frozenset[int], walk: bool
        ) -> tuple[int, int]:
            """(weight, core weight) of data the closure no longer grants."""
            before = [m for m in members if m in direct]
            if start in direct:
                before.append(start)
            if walk:
                after_members = self._closure(start, chosen)
                after = [m for m in after_members if m in direct and m not in disabled]
                if start in direct and start not in disabled:
                    after.append(start)
            else:
                after = [m for m in before if m not in disabled]
            after_set = set(after)
            lost = [m for m in before if m not in after_set]
            touched = [m for m in after if m in removed]
            if not lost and not touched:
                return 0, 0
            providers = [grants(m) for m in after]
            providers_core = [grants(m) for m in after if m not in excluded]
            total = core = 0
            candidates: dict[int, bool] = {}  # data -> from a non-excluded holder
            for holder in lost:
                for item in direct[holder]:
                    candidates[item] = candidates.get(item, False) or holder not in excluded
            for holder in touched:
                for item in removed[holder]:
                    if item in direct[holder]:
                        candidates[item] = candidates.get(item, False) or holder not in excluded
            for item, in_core in candidates.items():
                if not any(item in found for found in providers):
                    total += weight[item]
                if in_core and not any(item in found for found in providers_core):
                    core += weight[item]
            return total, core

        rows = {"roles": Totals(), "identities": Totals()}
        by_topic: dict[int, dict[str, Totals]] = {}
        counts = Counter()
        for position in range(len(self.node)):
            start = self.node[position]
            kind = "roles" if self.kind[position] == ROLE_RECORD else "identities"
            topic = self.topic[position]
            basis = BASIS_CODES[self.basis[position]]
            g, gc, n, nc = (
                self.granted[position],
                self.granted_core[position],
                self.needed[position],
                self.needed_core[position],
            )
            if start in disabled:
                after = (0, 0, 0, 0)
                counts["disabled_" + kind] += 1
            elif self.closure[position] in touched_closures or start in removed or start in cut_sources:
                excluded = hubs - {start} if kind == "roles" else hubs
                members = self.closures[self.closure[position]]
                # A walk (disabled or cut hops on the way) depends on the start's own hops.
                walk = start in cut_sources or (
                    bool(disabled or cut_sources)
                    and (not disabled.isdisjoint(members) or not cut_sources.isdisjoint(members))
                )
                key = (self.closure[position], start if (walk or start in direct) else -1, kind)
                found = memo.get(key)
                if found is None:
                    found = loss(start, members, excluded, walk)
                    memo[key] = found
                ga, gca = g - found[0], gc - found[1]
                after = (ga, gca, min(n, ga), min(nc, gca))
                if found[0]:
                    counts["changed_" + kind] += 1
            else:
                after = (g, gc, n, nc)
            for totals in (rows[kind], by_topic.setdefault(topic, {}).setdefault(kind, Totals())):
                totals.add(basis, (g, gc, n, nc), after)
        removed_pairs = sum(len(items & direct.get(h, frozenset())) for h, items in removed.items())
        restricted_pairs = sum(
            self.restricted[item]
            for h, items in removed.items()
            for item in items & direct.get(h, frozenset())
        )
        grants_before = sum(len(items) for items in direct.values())
        disabled_grants = sum(
            len(grants_ - removed.get(h, set())) for h, grants_ in direct.items() if h in disabled
        )
        return {
            "graph": {kind: totals.as_dict() for kind, totals in rows.items()},
            "topics": [
                {
                    "topic_id": self.topics[topic][0],
                    "name": self.topics[topic][1],
                    **{kind: totals.as_dict() for kind, totals in sorted(kinds.items())},
                }
                for topic, kinds in sorted(
                    by_topic.items(), key=lambda kv: self.topics[kv[0]][0] if kv[0] >= 0 else ""
                )
                if topic >= 0
            ],
            "counts": {
                "grants_before": grants_before,
                "grants_after": grants_before - removed_pairs - disabled_grants,
                "grants_removed": removed_pairs,
                "restricted_grants_removed": restricted_pairs,
                "hops_cut": len(cut),
                "disabled_nodes": len(disabled),
                "disabled_roles": counts["disabled_roles"],
                "disabled_identities": counts["disabled_identities"],
                "roles_with_less_access": counts["changed_roles"],
                "identities_with_less_access": counts["changed_identities"],
            },
            "applied": dict(sorted(chosen.applied.items())),
            "applied_tiers": dict(sorted(chosen.tiers.items())),
            "skipped": dict(sorted(chosen.skipped.items())),
        }


@dataclass
class Selection:
    removed: dict[int, set[int]] = field(default_factory=dict)
    cut: set[tuple[int, int]] = field(default_factory=set)
    disabled: set[int] = field(default_factory=set)
    applied: Counter = field(default_factory=Counter)
    tiers: Counter = field(default_factory=Counter)
    skipped: Counter = field(default_factory=Counter)


def _epi(granted: int, needed: int) -> float | None:
    return round(1 - needed / granted, 6) if granted else None


@dataclass
class Totals:
    """Sums over rows with usage evidence (basis other than "none"), before and after."""

    before: list[int] = field(default_factory=lambda: [0, 0, 0, 0])
    after: list[int] = field(default_factory=lambda: [0, 0, 0, 0])
    rows: int = 0

    def add(self, basis: str, before: tuple, after: tuple) -> None:
        if basis == "none":
            return
        self.rows += 1
        for position in range(4):
            self.before[position] += before[position]
            self.after[position] += after[position]

    def as_dict(self) -> dict:
        def side(values: list[int]) -> dict:
            granted, granted_core, needed, needed_core = values
            return {
                "granted_weight": granted,
                "needed_weight": needed,
                "granted_weight_excl_hubs": granted_core,
                "needed_weight_excl_hubs": needed_core,
                "epi": _epi(granted, needed),
                "epi_excl_hubs": _epi(granted_core, needed_core),
            }

        return {"rows": self.rows, "before": side(self.before), "after": side(self.after)}
