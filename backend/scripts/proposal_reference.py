"""Independent references for optimizer proposals (tests and ``qualify_proposals.py``).

Nothing here imports the proposal engine's internals: the checks work on the snapshot,
the observed access and the proposals' stored changes (edge pairs and disabled nodes).
"""

from collections import defaultdict

DATA = {"Database", "VectorStore", "S3Bucket"}
GRANTS = {"CAN_READ", "CAN_WRITE"}
HOPS = {"ASSUMES_ROLE", "INHERITS_PERMISSIONS", "INVOKES_TOOL"}
WEIGHTS = {"public": 1, "internal": 2, "confidential": 5, "restricted": 10}
MAX_HOPS = 5
NEVER_AUTO_TYPES = {"merge_roles", "split_role", "scope_wildcard"}


def structure(snapshot):
    types = {node.id: node.type.value for node in snapshot.nodes}
    direct, hop = defaultdict(set), defaultdict(set)
    for edge in snapshot.edges:
        kind = edge.type.value
        if kind in GRANTS and types[edge.target] in DATA and types[edge.source] not in DATA:
            direct[edge.source].add(edge.target)
        elif kind in HOPS and types[edge.source] not in DATA and types[edge.target] not in DATA:
            if edge.source != edge.target:
                hop[edge.source].add(edge.target)
    return types, direct, hop


def closure(start, hop, disabled=frozenset(), cut=frozenset()):
    seen, frontier = {start}, [start]
    for _ in range(MAX_HOPS - 1):
        following = []
        for current in frontier:
            for target in sorted(hop.get(current, ())):
                if target not in seen and target not in disabled and (current, target) not in cut:
                    seen.add(target)
                    following.append(target)
        frontier = following
    return seen


def granted(
    start, direct, hop, removed=frozenset(), disabled=frozenset(), cut=frozenset(), exclude=frozenset()
):
    """Data reachable from ``start`` over hops then one grant, after the changes."""
    if start in disabled:
        return set()
    found = set()
    for holder in closure(start, hop, disabled, cut):
        if holder in exclude:
            continue
        for item in direct.get(holder, ()):
            if (holder, item) not in removed:
                found.add(item)
    return found


def changes_of(proposals):
    """(removed pairs, cut hops, disabled nodes) from proposal views (``changes`` lists)."""
    removed, cut, disabled = set(), set(), set()
    for proposal in proposals:
        for change in proposal["changes"]:
            if change["op"] == "remove_grant":
                removed.add((change["source"], change["target"]))
            elif change["op"] == "cut_hop":
                cut.add((change["source"], change["target"]))
            elif change["op"] == "disable_node":
                disabled.add(change["node"])
    return removed, cut, disabled


def observed_access_kept(snapshot, observed, removed, cut, disabled) -> list:
    """Observed (principal, data) uses and (principal, role) assumptions lost by the changes.

    A use counts only when the graph explained it before (some grant path existed).
    """
    types, direct, hop = structure(snapshot)
    lost = []
    for principal, resource, action in observed:
        if principal not in types or resource not in types:
            continue
        if action == "assume":
            if (principal, resource) in cut or principal in disabled or resource in disabled:
                lost.append((principal, resource, action))
            continue
        if types[resource] not in DATA:
            continue
        if resource in granted(principal, direct, hop) and resource not in granted(
            principal, direct, hop, removed, disabled, cut
        ):
            lost.append((principal, resource, action))
    return lost


def reference_metrics(snapshot, rows: dict, hubs: set, removed, cut, disabled) -> dict:
    """Brute-force identity and role granted weight after the changes (with and without hubs).

    ``rows`` maps every role and principal ID to its stored ``basis``, granted and needed
    weights (with and without hubs). Needed stays as stored, clamped to granted after.
    """
    types, direct, hop = structure(snapshot)
    sensitivity = {node.id: node.sensitivity.value for node in snapshot.nodes}
    totals = {"roles": [0, 0, 0, 0, 0, 0, 0, 0], "identities": [0, 0, 0, 0, 0, 0, 0, 0]}
    for entity, row in rows.items():
        if row["basis"] == "none":
            continue
        kind = "roles" if types[entity] == "CloudRole" else "identities"
        excluded = hubs - {entity}
        after = granted(entity, direct, hop, removed, disabled, cut)
        after_core = granted(entity, direct, hop, removed, disabled, cut, excluded)
        g = sum(WEIGHTS[sensitivity[i]] for i in after)
        gc = sum(WEIGHTS[sensitivity[i]] for i in after_core)
        n = 0 if entity in disabled else min(row["needed_weight"], g)
        nc = 0 if entity in disabled else min(row["needed_weight_excl_hubs"], gc)
        values = totals[kind]
        for position, value in enumerate(
            (row["reach_weight"], row["reach_weight_excl_hubs"], row["needed_weight"], row["needed_weight_excl_hubs"],
             g, gc, n, nc)
        ):  # fmt: skip
            values[position] += value
    return {
        kind: {
            "before": {
                "granted_weight": v[0],
                "granted_weight_excl_hubs": v[1],
                "needed_weight": v[2],
                "needed_weight_excl_hubs": v[3],
            },
            "after": {
                "granted_weight": v[4],
                "granted_weight_excl_hubs": v[5],
                "needed_weight": v[6],
                "needed_weight_excl_hubs": v[7],
            },
        }  # fmt: skip
        for kind, v in totals.items()
    }


def never_auto_violations(proposals, cases: dict) -> list[str]:
    """Proposals above ``manual`` that touch a planted never-auto case, or whose own reasons
    or type put them on the never-auto list."""
    subjects = {entity for values in cases["subjects"].values() for entity in values}
    pairs = {tuple(pair) for values in cases["pairs"].values() for pair in values}
    bad = []
    for proposal in proposals:
        if proposal["tier"] == "manual":
            continue
        touched = {proposal["subject_id"], proposal["target_id"]} & subjects
        removes = {
            (change["source"], change["target"])
            for change in proposal["changes"]
            if change["op"] == "remove_grant"
        }
        if touched or removes & pairs or proposal["reasons"] or proposal["type"] in NEVER_AUTO_TYPES:
            bad.append(proposal["id"])
        if any(change["op"] == "cut_hop" for change in proposal["changes"]):
            bad.append(proposal["id"])
    return bad
