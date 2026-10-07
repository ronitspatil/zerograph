import copy
import difflib
import json
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.collectors.iam_evaluator import glob, statements, values


class UsageEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    window_start: datetime
    window_end: datetime
    used_actions: list[str] = Field(max_length=10000)
    covered_services: list[str] = Field(max_length=500)
    complete: bool = False
    source: str = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def validate_window(self) -> "UsageEvidence":
        if self.window_start.tzinfo is None or self.window_end.tzinfo is None:
            raise ValueError("Audit timestamps must include timezone information")
        if self.window_end <= self.window_start or self.window_end > datetime.now(UTC) + timedelta(minutes=5):
            raise ValueError("Invalid audit observation window")
        if any(":" not in action or "*" in action or "?" in action for action in self.used_actions):
            raise ValueError("Usage must contain concrete IAM actions, not API event names or wildcards")
        return self


class Optimization(BaseModel):
    original: dict[str, Any]
    optimized: dict[str, Any]
    removed_actions: list[str]
    retained_reasons: list[str]
    diff: str
    review_required: bool = True


def optimize(policy: dict[str, Any], usage: UsageEvidence, minimum_days: int = 90) -> Optimization:
    if policy.get("Version") != "2012-10-17" or "Statement" not in policy:
        raise ValueError("Expected an IAM policy with Version 2012-10-17 and Statement")
    original = copy.deepcopy(policy)
    optimized = copy.deepcopy(policy)
    retained = []
    removed = set()
    result = []
    enough = usage.complete and usage.window_end - usage.window_start >= timedelta(days=minimum_days)
    # Stale evidence must not produce a policy shrink recommendation.
    fresh = datetime.now(UTC) - usage.window_end <= timedelta(days=7)
    used = {a.lower() for a in usage.used_actions}
    covered = {s.lower() for s in usage.covered_services}
    for index, statement in enumerate(statements(policy)):
        stmt = copy.deepcopy(statement)
        if not isinstance(stmt, dict) or stmt.get("Effect") not in {"Allow", "Deny"}:
            raise ValueError("Every policy statement needs a valid Effect")
        actions = values(stmt.get("Action", []))
        if stmt.get("Effect") == "Deny":
            retained.append(f"Statement {index}: explicit deny preserved verbatim")
        elif not enough or not fresh:
            retained.append(f"Statement {index}: insufficient, incomplete, or stale audit coverage")
        elif any(k in stmt for k in ("Condition", "NotAction", "NotResource", "Principal", "NotPrincipal")):
            retained.append(
                f"Statement {index}: conditional or resource-policy semantics require manual review"
            )
        elif not actions or any(
            not isinstance(a, str) or "*" in a or "?" in a or ":" not in a for a in actions
        ):
            retained.append(f"Statement {index}: wildcard/unknown action semantics require manual review")
        else:
            keep = []
            for action in actions:
                if action.lower() in used or action.split(":", 1)[0].lower() not in covered:
                    keep.append(action)
                else:
                    removed.add(action)
            if not keep:
                continue
            stmt["Action"] = keep
        result.append(stmt)
    if not result:
        # An empty policy is not a valid attachable AWS policy. Preserve rather than invent a deny.
        optimized = copy.deepcopy(original)
        removed.clear()
        retained.append(
            "All grants appeared unused; detach-policy review is required instead of an empty document"
        )
    else:
        optimized["Statement"] = result
    before = json.dumps(original, indent=2, sort_keys=True) + "\n"
    after = json.dumps(optimized, indent=2, sort_keys=True) + "\n"
    return Optimization(
        original=original,
        optimized=optimized,
        removed_actions=sorted(removed),
        retained_reasons=retained,
        diff="".join(
            difflib.unified_diff(
                before.splitlines(keepends=True),
                after.splitlines(keepends=True),
                fromfile="original.json",
                tofile="least-privilege.json",
            )
        ),
    )


def terraform_policy(policy: dict, name: str = "zerograph_review") -> str:
    if not name.replace("_", "").isalnum():
        raise ValueError("Invalid Terraform resource name")
    encoded = json.dumps(policy, indent=2).replace("${", "$${").replace("%{", "%%{")
    # JSON is a valid HCL expression; escape template interpolation in policy variables.
    return f'resource "aws_iam_policy" "{name}" {{\n  name = "{name}"\n  policy = jsonencode({encoded})\n}}\n'


# ---------------------------------------------------------------------------
# Graph-derived policy diffs (optimizer Phase 4): scope Resource, disable

# Statement keys whose semantics a Resource rewrite cannot reason about: always manual.
MANUAL_KEYS = ("Condition", "NotAction", "NotResource", "Principal", "NotPrincipal")
DISABLE_POLICY_NAME = "ZeroGraphDisable"
DENY_ALL: dict[str, Any] = {
    "Version": "2012-10-17",
    "Statement": [{"Sid": "ZeroGraphDisableDenyAll", "Effect": "Deny", "Action": "*", "Resource": "*"}],
}


def render(document: dict[str, Any]) -> str:
    """The exact bytes written to a review file (and restored byte for byte by a revert)."""
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def unified_diff(before: dict[str, Any] | None, after: dict[str, Any] | None, name: str) -> str:
    old = render(before).splitlines(keepends=True) if before is not None else []
    new = render(after).splitlines(keepends=True) if after is not None else []
    return "".join(difflib.unified_diff(old, new, fromfile=f"a/{name}", tofile=f"b/{name}"))


class PolicyScope(BaseModel):
    """A policy document with the Resource entries of removed grants dropped.

    ``optimized`` is ``None`` when nothing changed or when every statement would go (an
    empty document is not attachable: detaching it is a manual review). ``removed`` maps
    each removed resource to the Resource entries dropped for it; ``unresolved`` maps a
    resource this document grants but cannot be scoped safely to the reason.
    """

    original: dict[str, Any]
    optimized: dict[str, Any] | None
    removed: dict[str, list[str]]
    unresolved: dict[str, str]
    statements_removed: int
    empty: bool = False


def _entries(statement: dict, key: str) -> list:
    raw = statement.get(key, [])
    return raw if isinstance(raw, list) else [raw]


def _grants(statement: dict, resource: str, actions: Iterable[str]) -> bool:
    """The Allow statement may grant ``actions`` (any, when empty) on ``resource`` or its objects."""
    actions = [a for a in actions if isinstance(a, str)]
    if "Action" in statement:
        patterns = _entries(statement, "Action")
        if actions and not any(glob(a, patterns, insensitive=True) for a in actions):
            return False
    elif "NotAction" in statement:
        patterns = _entries(statement, "NotAction")
        if actions and all(glob(a, patterns, insensitive=True) for a in actions):
            return False
    else:
        return False
    targets = (resource, resource + "/*")
    if "Resource" in statement:
        return any("${" in str(p) or glob(t, p) for p in _entries(statement, "Resource") for t in targets)
    if "NotResource" in statement:
        return not all(glob(t, _entries(statement, "NotResource")) for t in targets)
    return False


def _owned(entry: Any, resource: str) -> bool:
    """A Resource entry that concerns only ``resource``: the ARN itself or a path under it."""
    return (
        isinstance(entry, str)
        and "${" not in entry
        and (entry == resource or entry.startswith(resource + "/"))
    )


def scope_policy(
    policy: dict[str, Any], remove: Mapping[str, Iterable[str]], keep: Iterable[str] = ()
) -> PolicyScope:
    """Drop the Resource entries granting each removed resource; never widen anything.

    ``remove`` maps a resource (graph node ID: its ARN) to the actions of the grant being
    removed; ``keep`` lists the holder's other granted resources. A resource is removed
    only when every Allow statement granting it does so through entries that name it
    exactly (``arn`` or ``arn/...``) and no kept resource matches those entries. Deny
    statements and any statement with Condition, NotAction, NotResource, Principal or
    NotPrincipal are never touched: a removal that depends on one is left unresolved
    (manual). Only entries and whole statements left without a Resource are removed;
    actions are removed with their statement.
    """
    if not isinstance(policy, dict) or "Statement" not in policy:
        raise ValueError("Expected an IAM policy document with Statement")
    raw = policy["Statement"]
    listed = isinstance(raw, list)
    items = raw if listed else [raw]
    for statement in items:
        if not isinstance(statement, dict) or statement.get("Effect") not in {"Allow", "Deny"}:
            raise ValueError("Every policy statement needs a valid Effect")
    kept = [k for k in keep if k not in remove]
    unresolved: dict[str, str] = {}
    drop: dict[int, set[int]] = {}  # statement index -> Resource entry positions dropped
    removed: dict[str, list[str]] = {}
    for resource, actions in remove.items():
        actions = list(actions)
        plan: dict[int, set[int]] = {}
        reason = ""
        granting = False
        for index, statement in enumerate(items):
            if statement["Effect"] != "Allow" or not _grants(statement, resource, actions):
                continue
            granting = True
            if any(key in statement for key in MANUAL_KEYS):
                reason = f"Statement {index} uses Condition/NotAction/NotResource/Principal semantics"
                break
            entries = _entries(statement, "Resource")
            matching = [
                (position, entry)
                for position, entry in enumerate(entries)
                if "${" in str(entry) or glob(resource, entry) or glob(resource + "/*", entry)
            ]
            foreign = [entry for _, entry in matching if not _owned(entry, resource)]
            if foreign:
                reason = f"Statement {index} grants it through a pattern ({str(foreign[0])[:80]}); scoping it is manual"
                break
            positions = {position for position, _ in matching}
            shared = [k for k in kept for _, e in matching if glob(k, e) or glob(k + "/*", e)]
            if shared:
                reason = f"Statement {index} entry also covers kept resource {shared[0][:80]}"
                break
            plan[index] = positions
        if reason:
            unresolved[resource] = reason
            continue
        if not granting:
            continue  # This document does not grant it (another policy might).
        for index, positions in plan.items():
            drop.setdefault(index, set()).update(positions)
            entries = _entries(items[index], "Resource")
            removed.setdefault(resource, []).extend(str(entries[p]) for p in sorted(positions))
    if not drop:
        return PolicyScope(
            original=copy.deepcopy(policy),
            optimized=None,
            removed={},
            unresolved=unresolved,
            statements_removed=0,
        )
    result = []
    gone = 0
    for index, statement in enumerate(items):
        positions = drop.get(index)
        if not positions:
            result.append(copy.deepcopy(statement))
            continue
        entries = _entries(statement, "Resource")
        left = [entry for position, entry in enumerate(entries) if position not in positions]
        if not left:
            gone += 1
            continue
        stmt = copy.deepcopy(statement)
        stmt["Resource"] = left if isinstance(statement["Resource"], list) else left[0]
        result.append(stmt)
    optimized = copy.deepcopy(policy)
    if not result:
        return PolicyScope(
            original=copy.deepcopy(policy),
            optimized=None,
            removed=removed,
            unresolved=unresolved,
            statements_removed=gone,
            empty=True,
        )
    optimized["Statement"] = result if listed or len(result) != 1 else result[0]
    return PolicyScope(
        original=copy.deepcopy(policy),
        optimized=optimized,
        removed=removed,
        unresolved=unresolved,
        statements_removed=gone,
    )


def probe_actions(documents: Iterable[dict[str, Any]]) -> set[str]:
    """Concrete actions named by Allow statements (probes for before/after evaluation)."""
    found = set()
    for document in documents:
        for statement in statements(document):
            if isinstance(statement, dict) and statement.get("Effect") == "Allow":
                for action in _entries(statement, "Action"):
                    if isinstance(action, str) and ":" in action and "*" not in action and "?" not in action:
                        found.add(action)
    return found


def verify_scope(
    principal: str,
    before: list[dict[str, Any]],
    after: list[dict[str, Any]],
    removed: Mapping[str, Iterable[str]],
    kept: Mapping[str, Iterable[str]],
) -> list[str]:
    """Re-evaluate the principal's identity policies with ``iam_evaluator`` (empty: correct).

    Every removed (resource, action) must no longer be allowed (nor conditionally) by
    the documents after; every kept (resource, action), and every concrete action the
    documents name on a kept resource or its objects, must evaluate exactly as before.
    """
    from app.collectors.iam_evaluator import Decision, Request, evaluate

    problems = []
    extra = probe_actions(before)

    def decision(documents, action, resource):
        return evaluate(Request(principal, action, resource), identity=documents).decision

    for resource, actions in removed.items():
        for action in set(actions) | extra:
            for target in (resource, resource + "/*"):
                if action in extra and action not in set(actions):
                    # Unmodelled actions: never allowed more than before.
                    if (
                        decision(before, action, target) == Decision.DENY
                        and decision(after, action, target) != Decision.DENY
                    ):
                        problems.append(f"widened {action} on {target}")
                    continue
                if decision(after, action, target) != Decision.DENY:
                    problems.append(f"still granted {action} on {target}")
    for resource, actions in kept.items():
        for action in set(actions) | extra:
            for target in (resource, resource + "/*"):
                if decision(before, action, target) != decision(after, action, target):
                    problems.append(f"changed {action} on {target}")
    return problems
