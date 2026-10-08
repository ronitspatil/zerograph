"""Reference checks for optimizer rollout diffs (tests and ``qualify_rollout.py``).

Independent of the API: applies a change's files to a snapshot's stored policy
documents and re-evaluates every grant edge of the touched principals with
``app.collectors.iam_evaluator``, then rebuilds the snapshot as a collector would see
it after the change (round trip), and compares the result to the what-if model.
"""

from collections.abc import Iterable

from app.collectors.iam_evaluator import Decision, Request, evaluate
from app.graph.compact import MAX_HOPS
from app.graph.schema import Edge, EdgeType, GraphSnapshot, PolicyAttachment

GRANTS = (EdgeType.READ, EdgeType.WRITE)
IDENTITY = ("inline", "managed", "group-inline", "group-managed")


def documents_by_principal(snapshot: GraphSnapshot) -> dict[str, dict[tuple[str, str], dict]]:
    found: dict[str, dict[tuple[str, str], dict]] = {}
    for policy in snapshot.policies:
        if policy.kind in IDENTITY:
            found.setdefault(policy.principal, {})[(policy.kind, policy.name)] = policy.document
    return found


def applied_documents(snapshot: GraphSnapshot, files: Iterable[dict], optimized: dict[str, dict]):
    """(before, after) identity documents per touched principal; ``optimized`` maps a file
    path to the document the change writes there."""
    current = documents_by_principal(snapshot)
    before: dict[str, list[dict]] = {}
    after: dict[str, dict[tuple[str, str], dict]] = {}
    for item in files:
        principal = item["principal"]
        before.setdefault(principal, list(current.get(principal, {}).values()))
        docs = after.setdefault(principal, dict(current.get(principal, {})))
        docs[("inline", item["policy_name"])] = optimized[item["path"]]
    return before, {principal: list(docs.values()) for principal, docs in after.items()}


def allows(documents: list[dict], principal: str, action: str, resource: str) -> Decision:
    return evaluate(Request(principal, action, resource), identity=documents).decision


def edge_granted(documents: list[dict], edge: Edge) -> bool:
    """A grant edge stands when any of its actions is allowed (or conditionally allowed)."""
    actions = edge.actions or ["*"]
    return any(allows(documents, edge.source, action, edge.target) != Decision.DENY for action in actions)


def explicitly_denied(documents: list[dict], edge: Edge) -> bool:
    actions = edge.actions or ["*"]
    return all(
        evaluate(Request(edge.source, action, edge.target), identity=documents)
        .reasons[0]
        .startswith("An applicable explicit deny")
        for action in actions
    )


def verify_diffs(
    snapshot: GraphSnapshot,
    files: list[dict],
    optimized: dict[str, dict],
    removed: dict[str, set[str]],
    disabled: set[str],
    probes: list[str] = (),
) -> dict:
    """Re-evaluate every grant edge of each touched principal before and after the change.

    Target: before minus the removed (principal, asset) grants (all of them for a disabled
    principal); nothing else changes; probes (assets the principal is not granted) are
    never allowed after when they were not before.
    """
    before_docs, after_docs = applied_documents(snapshot, files, optimized)
    for principal in disabled:
        before_docs.setdefault(principal, list(documents_by_principal(snapshot).get(principal, {}).values()))
    by_source: dict[str, list[Edge]] = {}
    for edge in snapshot.edges:
        if edge.type in GRANTS and edge.source in before_docs:
            by_source.setdefault(edge.source, []).append(edge)
    stats = {"principals": len(before_docs), "edges": 0, "removed_edges": 0, "mismatches": [], "widened": []}
    for principal, docs in before_docs.items():
        after = after_docs.get(principal, docs)
        for edge in by_source.get(principal, []):
            granted_before = edge_granted(docs, edge)
            granted_after = edge_granted(after, edge) and principal not in disabled
            expected = granted_before and edge.target not in removed.get(principal, set())
            if principal in disabled:
                expected = False
            stats["edges"] += 1
            stats["removed_edges"] += granted_before and not expected
            if granted_after != expected:
                stats["mismatches"].append([principal, edge.target, granted_before, granted_after, expected])
        granted = {edge.target for edge in by_source.get(principal, [])}
        for target in probes:
            if target in granted:
                continue
            for action in ("s3:GetObject", "s3:PutObject", "rds-data:ExecuteStatement", "aoss:ReadDocument"):
                if (
                    allows(docs, principal, action, target) == Decision.DENY
                    and allows(after, principal, action, target) != Decision.DENY
                ):
                    stats["widened"].append([principal, target, action])
    return stats


def round_trip(snapshot: GraphSnapshot, files: list[dict], optimized: dict[str, dict]) -> GraphSnapshot:
    """The snapshot a collector would produce after the change: policies replaced (and the
    deny-all disable policy attached), every edge of a touched principal re-evaluated."""
    before_docs, after_docs = applied_documents(snapshot, files, optimized)
    edges = []
    for edge in snapshot.edges:
        if edge.source not in after_docs:
            edges.append(edge)
            continue
        after = after_docs[edge.source]
        if explicitly_denied(after, edge):
            continue  # Disabled: an explicit deny-all blocks every action, trust included.
        if (
            edge.type in GRANTS
            and edge_granted(before_docs[edge.source], edge)
            and not edge_granted(after, edge)
        ):
            continue
        edges.append(edge)
    policies = []
    written = {(item["principal"], item["policy_name"]): optimized[item["path"]] for item in files}
    for policy in snapshot.policies:
        key = (policy.principal, policy.name)
        if policy.kind == "inline" and key in written:
            policies.append(policy.model_copy(update={"document": written.pop(key)}))
        else:
            policies.append(policy)
    for (principal, name), document in sorted(written.items()):
        policies.append(PolicyAttachment(principal=principal, kind="inline", name=name, document=document))
    return GraphSnapshot.model_construct(
        nodes=snapshot.nodes, edges=edges, warnings=[], source=snapshot.source, policies=policies
    )


def expected_after(model, ordinals: list[int]) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """(direct grants, reachable data per identity/role record) of the what-if model after
    applying ``ordinals``, by entity ID (brute force over hops with the same bound)."""
    chosen = model.selection(ordinals)
    ids = model.ids
    direct: dict[str, set[str]] = {}
    for holder, items in model.direct.items():
        if holder in chosen.disabled:
            continue
        kept = set(items) - chosen.removed.get(holder, set())
        if kept:
            direct[ids[holder]] = {ids[item] for item in kept}
    reach: dict[str, set[str]] = {}
    for position in range(len(model.node)):
        start = model.node[position]
        if start in chosen.disabled:
            reach[ids[start]] = set()
            continue
        members = model._closure(start, chosen) | {start}
        found: set[str] = set()
        for member in members:
            if member in chosen.disabled:
                continue
            found |= {
                ids[item]
                for item in model.direct.get(member, ())
                if item not in chosen.removed.get(member, set())
            }
        reach[ids[start]] = found
    return direct, reach


def actual_after(model) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """(direct grants, reachable data per record) of a re-ingested revision's what-if model."""
    return expected_after(model, [])


__all__ = ["MAX_HOPS", "actual_after", "expected_after", "round_trip", "verify_diffs"]
