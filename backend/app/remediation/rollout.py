"""Optimizer rollout: accepted proposals -> policy diffs -> draft pull requests, canary, rollback.

Nothing here applies a change. A **change** is one draft pull request (or merge request)
in the customer's policy repository: one principal (role, user or service account) by
default, or a bundle of a topic's principals. It is built from the tenant's *accepted*
proposals of the current revision:

* ``remove_grant`` (and a ``break_toxic_path`` that removes a grant): the principal's
  stored inline identity policies with the Resource entries of the removed asset dropped
  (``policy_optimizer.scope_policy``). Statements with Condition, NotAction, NotResource
  or Principal, grants through wildcard patterns, managed or group policies, and
  removals that would empty a policy stay **draft only** with the reason.
* ``disable_role`` / ``disable_identity``: an added inline deny-all policy
  (``ZeroGraphDisable``); nothing is deleted or detached.
* ``merge_roles``, ``split_role``, ``scope_wildcard`` and every ``manual``-tier
  proposal: a reviewed draft text only, never a pull request.

Every diff is re-evaluated with ``iam_evaluator`` (removed grants no longer allowed,
everything else unchanged) before it can be proposed. Each written file is recorded as
a ``Remediation`` whose ``original`` is the stored document, so a revert restores it
byte for byte.

**Canary.** Per topic, the first single-principal change to open a pull request is the
canary; every other change of the topic (and any topic bundle) is held until the canary
is marked merged and its watch window (``rollout_watch_days``, default 7) passes without
AccessDenied events on what it touched. States: ``draft`` -> ``pr_open`` -> ``merged``
(canary watch) -> ``verified``, or -> ``revert_open`` -> ``rolled_back``. A rolled-back
canary no longer counts: the next change of the topic becomes its canary.

**AccessDenied watch.** When a committed CloudTrail upload holds denied attempts by a
principal a merged change touched (on a resource it removed, or any resource when it
disabled the principal) inside the change's watch window, the change is flagged and a
revert pull request is opened (never merged), audited.
"""

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import (
    AccessDenial,
    ProposalDecision,
    Remediation,
    RevisionPolicy,
    RevisionPolicyDocument,
    RevisionProposal,
    RolloutChange,
    UsageUpload,
    now,
)
from app.graph.policies import IDENTITY_KINDS
from app.graph.schema import NodeType, canonical_policy
from app.remediation.gitops_sync import MAX_CHANGE_FILES, FileChange
from app.remediation.policy_optimizer import (
    DENY_ALL,
    DISABLE_POLICY_NAME,
    _grants,
    render,
    scope_policy,
    unified_diff,
    verify_scope,
)

REMOVE_TYPES = ("remove_grant", "break_toxic_path")
DISABLE_TYPES = ("disable_role", "disable_identity")
PR_TYPES = REMOVE_TYPES + DISABLE_TYPES
DRAFT_TYPES = ("merge_roles", "split_role", "scope_wildcard")
# Principals ZeroGraph can disable with an attached inline deny-all policy (IAM roles and users).
DISABLE_PRINCIPALS = (NodeType.ROLE.value, NodeType.HUMAN.value, NodeType.SERVICE.value)
STATES = ("draft", "pr_open", "merged", "verified", "revert_open", "rolled_back")
ACTIVE = ("draft", "pr_open", "merged", "verified", "revert_open")
MAX_PRINCIPAL_PROPOSALS = 500
MAX_BUNDLE_PRINCIPALS = 25
MAX_LISTED = 100  # proposals listed per pull request body
MAX_CHANGES_LISTED = 200
NOTICE = (
    "Nothing is applied by ZeroGraph. Each change is a draft pull request in your policy repository; "
    "merging (and applying) happens there, by your team."
)
HOOK_ACTOR = "system:access-denied-watch"


class RolloutError(ValueError):
    """A client-correctable problem with a change (409/404 at the API)."""


class ChangeNotFound(LookupError):
    pass


# ---------------------------------------------------------------------------
# Planning: accepted proposals -> per-principal policy diffs


@dataclass
class PlannedFile:
    path: str  # relative to <policy_prefix>/<tenant_key>/<change_id>/
    principal: str
    op: str  # "rewrite" (scoped inline policy) or "add" (deny-all disable policy)
    policy_kind: str
    policy_name: str
    original: dict | None
    optimized: dict
    removed: dict[str, list[str]] = field(default_factory=dict)
    proposal_ids: list[str] = field(default_factory=list)

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_policy(self.original).encode()).hexdigest() if self.original else ""

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "principal": self.principal,
            "op": self.op,
            "policy_kind": self.policy_kind,
            "policy_name": self.policy_name,
            "original_digest": self.digest,
            "content_sha256": hashlib.sha256(render(self.optimized).encode()).hexdigest(),
            "removed": self.removed,
            "proposal_ids": self.proposal_ids,
            "diff": unified_diff(self.original, self.optimized, self.path),
        }


@dataclass
class Plan:
    revision: str
    scope: str  # "role" or "topic"
    topic_id: str
    subject_id: str
    subject_name: str
    files: list[PlannedFile]
    included: list[RevisionProposal]
    drafts: list[dict]  # {"proposal_id", "type", "reason", "text"}
    touched: dict[str, dict]  # principal -> {"removed": [resources], "disabled": bool}
    principals: list[str]

    @property
    def proposal_ids(self) -> list[str]:
        return [row.proposal_id for row in self.included]


def slug(value: str, limit: int = 48) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-._")[:limit].strip("-._") or "x"


def principal_key(principal: str, name: str) -> str:
    return f"{slug(name or principal)}-{hashlib.sha256(principal.encode()).hexdigest()[:10]}"


def _loaded(value):
    return json.loads(value) if isinstance(value, str) else value


def accepted_rows(
    db: Session, tenant: str, revision: str, *, subject: str | None = None, topic: str | None = None
) -> list[RevisionProposal]:
    """Accepted proposals of the revision for one principal or one topic (deterministic order)."""
    query = (
        select(RevisionProposal)
        .join(
            ProposalDecision,
            (ProposalDecision.tenant_id == RevisionProposal.tenant_id)
            & (ProposalDecision.proposal_id == RevisionProposal.proposal_id),
        )
        .where(
            RevisionProposal.tenant_id == tenant,
            RevisionProposal.revision == revision,
            ProposalDecision.state == "accepted",
        )
    )
    if subject is not None:
        query = query.where(RevisionProposal.subject_id == subject)
    if topic is not None:
        query = query.where(RevisionProposal.topic_id == topic)
    rows = list(db.scalars(query.order_by(RevisionProposal.ordinal).limit(MAX_PRINCIPAL_PROPOSALS * 40)))
    return rows


def active_proposals(db: Session, tenant: str, exclude: str | None = None) -> dict[str, str]:
    """Proposal ID -> change ID for every proposal held by a change that is not rolled back."""
    found: dict[str, str] = {}
    for change_id, ids in db.execute(
        select(RolloutChange.id, RolloutChange.proposal_ids).where(
            RolloutChange.tenant_id == tenant, RolloutChange.state.in_(ACTIVE)
        )
    ):
        if change_id == exclude:
            continue
        for proposal in _loaded(ids):
            found[proposal] = change_id
    return found


def principal_policies(db: Session, tenant: str, revision: str, principal: str) -> list[tuple]:
    """(kind, name, arn, document) of the principal's identity policies in the revision."""
    rows = db.execute(
        select(RevisionPolicy.kind, RevisionPolicy.name, RevisionPolicy.arn, RevisionPolicyDocument.document)
        .join(
            RevisionPolicyDocument,
            (RevisionPolicyDocument.tenant_id == RevisionPolicy.tenant_id)
            & (RevisionPolicyDocument.revision == RevisionPolicy.revision)
            & (RevisionPolicyDocument.digest == RevisionPolicy.digest),
        )
        .where(
            RevisionPolicy.tenant_id == tenant,
            RevisionPolicy.revision == revision,
            RevisionPolicy.principal_id == principal,
            RevisionPolicy.kind.in_(IDENTITY_KINDS),
        )
        .order_by(RevisionPolicy.kind, RevisionPolicy.name, RevisionPolicy.attachment_id)
        .limit(200)
    ).all()
    return [(kind, name, arn, json.loads(document)) for kind, name, arn, document in rows]


def removal_of(row: RevisionProposal) -> tuple[str, list[str]] | None:
    """(resource, actions) a remove-type proposal takes from its subject, or None (hop cut)."""
    grants = [change for change in _loaded(row.changes) if change.get("op") == "remove_grant"]
    if not grants or row.type not in REMOVE_TYPES:
        return None
    actions = {a for change in grants for a in change.get("actions", []) if isinstance(a, str)}
    return grants[0].get("target") or row.target_id, sorted(actions)


def draft_reason(row: RevisionProposal) -> str | None:
    """Why a proposal can only be a reviewed draft (None: it can go into a pull request)."""
    if row.type in DRAFT_TYPES:
        return {
            "merge_roles": "Merging roles changes trust policies and who assumes what: draft for review only",
            "split_role": "Splitting a role creates roles and moves assumers: draft for review only",
            "scope_wildcard": "Rewriting a wildcard grant is always manual: draft for review only",
        }[row.type]
    if row.tier == "manual":
        return "On the never-auto list (" + ", ".join(_loaded(row.reasons)) + "): draft for review only"
    if row.type == "break_toxic_path" and removal_of(row) is None:
        return "Cutting a role hop changes a trust relationship: draft for review only"
    if row.type in DISABLE_TYPES and row.subject_type not in DISABLE_PRINCIPALS:
        return f"{row.subject_type} is not an IAM principal ZeroGraph can disable by policy; disable it at its source"
    if row.type not in PR_TYPES:
        return "Not a policy change: draft for review only"
    return None


def draft_text(row: RevisionProposal, reason: str | None = None) -> str:
    """A reviewed, human-readable description of the change (what a person would do)."""
    evidence = _loaded(row.evidence)
    changes = _loaded(row.changes)
    subject = f"{row.subject_name} ({row.subject_id})"
    lines = []
    if row.type == "merge_roles":
        change = changes[0] if changes else {}
        moved = change.get("move_used_grants", [])
        lines.append(f"Merge role {row.target_name} ({row.target_id}) into {subject}.")
        lines.append(
            f"1. Grant {row.subject_name} the {len(moved)} used grant(s) only the retired role holds."
        )
        lines.append(f"2. Repoint every principal that assumes {row.target_name} to {row.subject_name}.")
        lines.append(f"3. Disable {row.target_name} (attach a deny-all policy); never delete it.")
        lines.append(
            f"Jaccard similarity {evidence.get('jaccard')}; shared grants {evidence.get('shared_grants')}."
        )
    elif row.type == "split_role":
        lines.append(f"Split {subject} by topic; each group gets its own role with only its used grants:")
        for group in evidence.get("groups", []):
            lines.append(f"- {group.get('topic')}: {group.get('count')} used grant(s) ({group.get('share')})")
        lines.append("Move each assumer to the role(s) of the topics it uses; then disable the old role.")
    elif row.type == "scope_wildcard":
        lines.append(
            f"Replace the wildcard grants of {subject} with the {evidence.get('keep_used')} asset(s) it used;"
            f" {evidence.get('remove_unused')} unused asset(s) lose access."
        )
    elif row.type in DISABLE_TYPES:
        lines.append(
            f"Disable {subject}: attach an inline deny-all policy named {DISABLE_POLICY_NAME}."
            " Do not delete the principal; detach the policy to restore it."
        )
    else:
        removal = removal_of(row)
        if removal is not None:
            resource, actions = removal
            lines.append(
                f"Remove the grant of {subject} on {row.target_name} ({resource})"
                + (f" for {', '.join(actions)}" if actions else "")
                + ": drop that resource from the Resource of its identity policy statements."
            )
        else:
            for change in changes:
                if change.get("op") == "cut_hop":
                    lines.append(
                        f"Remove the hop {change.get('source')} -> {change.get('target')} ({change.get('type')})."
                    )
    if reason:
        lines.append(f"Why draft only: {reason}.")
    return "\n".join(lines)


class ModelIndex:
    """Entity ID -> what-if model index (cached per model)."""

    def __init__(self, model):
        cached = getattr(model, "_rollout_index", None)
        if cached is None:
            cached = {value: position for position, value in enumerate(model.ids)}
            model._rollout_index = cached
        self.model, self.index = model, cached

    def grants(self, principal: str) -> list[str]:
        position = self.index.get(principal)
        if position is None:
            return []
        ids = self.model.ids
        return sorted(ids[item] for item in self.model.direct.get(position, ()))


def plan_principal(
    db: Session,
    tenant: str,
    revision: str,
    principal: str,
    name: str,
    rows: list[RevisionProposal],
    model,
) -> tuple[list[PlannedFile], list[RevisionProposal], list[dict], dict]:
    """Files, included proposals, drafts and touched resources for one principal."""
    drafts: list[dict] = []
    removals: dict[str, tuple[list[str], list[RevisionProposal]]] = {}
    disables: list[RevisionProposal] = []
    for row in rows:
        reason = draft_reason(row)
        if reason is not None:
            drafts.append(_draft(row, reason))
            continue
        if row.type in DISABLE_TYPES:
            disables.append(row)
            continue
        resource, actions = removal_of(row)
        entry = removals.setdefault(resource, ([], []))
        entry[0].extend(a for a in actions if a not in entry[0])
        entry[1].append(row)
    files: list[PlannedFile] = []
    included: list[RevisionProposal] = []
    key = principal_key(principal, name)
    touched = {"removed": [], "disabled": False}
    if removals:
        policies = principal_policies(db, tenant, revision, principal)
        pending = dict(removals)

        def drop(resource: str, reason: str) -> None:
            for row in pending.pop(resource)[1]:
                drafts.append(_draft(row, reason))

        if not policies:
            for resource in list(pending):
                drop(resource, "No stored identity policy document for this principal")
        for resource in list(pending):
            actions = pending[resource][0]
            granting = [
                (kind, name_) for kind, name_, _, doc in policies if _document_grants(doc, resource, actions)
            ]
            shared = [f"{kind} {name_}" for kind, name_ in granting if kind != "inline"]
            if shared:
                drop(resource, f"Granted by {shared[0]} (shared or inherited); edit or detach it manually")
            elif not granting:
                drop(resource, "No stored identity policy grants it (resource policy or unknown source)")
        kept = [k for k in ModelIndex(model).grants(principal) if k not in removals] if model else []
        scoped: dict[int, object] = {}
        for _attempt in range(4):
            scoped = {}
            failed = False
            for position, (kind, name_, _, doc) in enumerate(policies):
                if kind != "inline" or not pending:
                    continue
                remove = {r: pending[r][0] for r in pending if _document_grants(doc, r, pending[r][0])}
                if not remove:
                    continue
                result = scope_policy(doc, remove, keep=kept)
                for resource, reason in result.unresolved.items():
                    if resource in pending:
                        drop(resource, f"Inline policy {name_}: {reason}")
                        failed = True
                if result.empty:
                    for resource in remove:
                        if resource in pending:
                            drop(
                                resource, f"Removing it would empty inline policy {name_}; detach it manually"
                            )
                    failed = True
                scoped[position] = result
            if not failed:
                break
        if pending:
            before = [doc for _, _, _, doc in policies]
            after = [
                scoped[position].optimized if position in scoped and scoped[position].optimized else doc
                for position, (_, _, _, doc) in enumerate(policies)
            ]
            problems = verify_scope(
                principal,
                before,
                after,
                {r: pending[r][0] for r in pending},
                {k: [] for k in kept},
            )
            if problems:
                for resource in list(pending):
                    drop(resource, f"Re-evaluation did not confirm the diff ({problems[0]})")
                scoped = {}
        for position, result in sorted(scoped.items()):
            kind, name_, _, doc = policies[position]
            if result.optimized is None:
                continue
            ids = sorted({row.proposal_id for r in result.removed if r in pending for row in pending[r][1]})
            files.append(
                PlannedFile(
                    path=f"{key}/inline-{slug(name_, 40)}-{hashlib.sha256(name_.encode()).hexdigest()[:8]}.json",
                    principal=principal,
                    op="rewrite",
                    policy_kind=kind,
                    policy_name=name_,
                    original=doc,
                    optimized=result.optimized,
                    removed={r: e for r, e in result.removed.items() if r in pending},
                    proposal_ids=ids,
                )
            )
        for resource, (_, resource_rows) in sorted(pending.items()):
            included.extend(resource_rows)
            touched["removed"].append(resource)
    if disables:
        files.append(
            PlannedFile(
                path=f"{key}/{DISABLE_POLICY_NAME}.json",
                principal=principal,
                op="add",
                policy_kind="inline",
                policy_name=DISABLE_POLICY_NAME,
                original=None,
                optimized=DENY_ALL,
                proposal_ids=sorted(row.proposal_id for row in disables),
            )
        )
        included.extend(disables)
        touched["disabled"] = True
    return files, included, drafts, touched


def _document_grants(document: dict, resource: str, actions: list[str]) -> bool:
    raw = document.get("Statement", []) if isinstance(document, dict) else []
    items = raw if isinstance(raw, list) else [raw]
    return any(
        isinstance(s, dict) and s.get("Effect") == "Allow" and _grants(s, resource, actions) for s in items
    )


def _draft(row: RevisionProposal, reason: str) -> dict:
    return {
        "proposal_id": row.proposal_id,
        "type": row.type,
        "tier": row.tier,
        "subject_id": row.subject_id,
        "target_id": row.target_id,
        "reason": reason,
        "text": draft_text(row, reason),
    }


def plan_change(
    db: Session,
    tenant: str,
    revision: str,
    model,
    *,
    subject: str | None = None,
    topic: str | None = None,
    exclude_change: str | None = None,
    only: Iterable[str] | None = None,
) -> Plan:
    """The change for one principal (``subject``) or a topic bundle (``topic``) from the
    tenant's accepted proposals of ``revision``. Proposals already held by another active
    change are left out."""
    if (subject is None) == (topic is None):
        raise RolloutError("Choose one principal or one topic")
    rows = accepted_rows(db, tenant, revision, subject=subject, topic=topic)
    taken = active_proposals(db, tenant, exclude=exclude_change)
    rows = [row for row in rows if row.proposal_id not in taken]
    if only is not None:
        wanted = set(only)
        rows = [row for row in rows if row.proposal_id in wanted]
    by_principal: dict[str, list[RevisionProposal]] = {}
    for row in rows:
        by_principal.setdefault(row.subject_id, []).append(row)
    if subject is not None and len(by_principal.get(subject, [])) > MAX_PRINCIPAL_PROPOSALS:
        raise RolloutError("Too many accepted proposals for one change")
    principals = sorted(by_principal)
    files: list[PlannedFile] = []
    included: list[RevisionProposal] = []
    drafts: list[dict] = []
    touched: dict[str, dict] = {}
    used: list[str] = []
    for principal in principals:
        if topic is not None and len(used) >= MAX_BUNDLE_PRINCIPALS:
            break
        found = by_principal[principal][:MAX_PRINCIPAL_PROPOSALS]
        planned, taken_rows, principal_drafts, principal_touched = plan_principal(
            db, tenant, revision, principal, found[0].subject_name, found, model
        )
        drafts.extend(principal_drafts)
        if not planned:
            continue
        if len(files) + len(planned) > MAX_CHANGE_FILES:
            if topic is None:
                raise RolloutError("The change has more files than one review supports")
            break
        files.extend(planned)
        included.extend(taken_rows)
        touched[principal] = principal_touched
        used.append(principal)
    if subject is not None:
        topic_id = rows[0].topic_id if rows else ""
        name = rows[0].subject_name if rows else subject
        subject_id = subject
    else:
        topic_id, name, subject_id = topic, topic, topic
    return Plan(
        revision,
        "role" if subject is not None else "topic",
        topic_id,
        subject_id,
        name,
        files,
        included,
        drafts,
        touched,
        used,
    )


# ---------------------------------------------------------------------------
# Changes and their state


def summary_of(plan: Plan, model, evidence: dict, simulation: dict | None) -> dict:
    """Facts shown in the pull request body and the rollout panel."""
    epi = None
    if model is not None and plan.included:
        selection = model.selection(row.ordinal for row in plan.included)
        result = model.evaluate(selection)
        epi = {"graph": result["graph"], "counts": result["counts"], "applied": result["applied"]}
    by_type: dict[str, int] = {}
    for row in plan.included:
        by_type[row.type] = by_type.get(row.type, 0) + 1
    return {
        "revision": plan.revision,
        "principals": plan.principals,
        "touched": plan.touched,
        "proposals": [
            {
                "id": row.proposal_id,
                "type": row.type,
                "tier": row.tier,
                "subject_id": row.subject_id,
                "subject_name": row.subject_name,
                "target_id": row.target_id,
                "target_name": row.target_name,
                "epi_before": row.epi_before,
                "epi_after": row.epi_after,
            }
            for row in plan.included[:MAX_CHANGES_LISTED]
        ],
        "proposal_count": len(plan.included),
        "by_type": by_type,
        "drafts": plan.drafts[:MAX_CHANGES_LISTED],
        "draft_count": len(plan.drafts),
        "evidence": {
            key: evidence.get(key)
            for key in (
                "status",
                "window_start",
                "window_end",
                "sufficient_services",
                "uploads",
                "observed_pairs",
            )
        },
        "epi": epi,
        "simulation": simulation,
    }


def create_change(
    db: Session,
    tenant: str,
    actor: str,
    plan: Plan,
    model,
    evidence: dict,
    simulation: dict | None,
    watch_days: int,
) -> RolloutChange:
    """Store a draft change and one ``Remediation`` per file (original kept for revert)."""
    if not plan.files:
        raise RolloutError("No accepted proposal of this selection can become a pull request")
    change = RolloutChange(
        id=str(uuid4()),
        tenant_id=tenant,
        scope=plan.scope,
        topic_id=plan.topic_id,
        subject_id=plan.subject_id[:512],
        subject_name=plan.subject_name[:256],
        proposal_ids=plan.proposal_ids,
        state="draft",
        canary=False,
        revision=plan.revision,
        remediation_ids=[],
        files=[],
        summary=summary_of(plan, model, evidence, simulation),
        watch_days=watch_days,
        actor=actor[:256],
    )
    _store_files(db, change, plan, actor)
    db.add(change)
    return change


def _store_files(db: Session, change: RolloutChange, plan: Plan, actor: str) -> None:
    remediation_ids, files = [], []
    for planned in plan.files:
        record = Remediation(
            id=str(uuid4()),
            tenant_id=change.tenant_id,
            actor=actor[:256],
            status="rollout",
            identity_id=planned.principal,
            original=planned.original if planned.original is not None else {},
            optimized=planned.optimized,
            evidence={
                "revision": plan.revision,
                "rollout_id": change.id,
                "path": planned.path,
                "file_op": planned.op,
                "policy_kind": planned.policy_kind,
                "policy_name": planned.policy_name,
                "original_digest": planned.digest,
                "proposal_ids": planned.proposal_ids,
                "removed": planned.removed,
            },
        )
        db.add(record)
        remediation_ids.append(record.id)
        files.append({**planned.as_dict(), "remediation_id": record.id})
    change.remediation_ids, change.files = remediation_ids, files


def regenerate(
    db: Session, change: RolloutChange, plan: Plan, model, evidence: dict, simulation: dict | None, actor: str
) -> None:
    """Rebuild a draft change against a newer revision (same proposals by ID)."""
    if change.state != "draft" or change.gitops_scope is not None:
        raise RolloutError("Only a draft without a requested pull request can be regenerated")
    missing = sorted(set(_loaded(change.proposal_ids)) - set(plan.proposal_ids))
    if missing or not plan.files:
        raise RolloutError(
            "Accepted proposals of this change are no longer eligible in the current revision"
            f" ({', '.join(missing[:3]) or 'none left'}); discard the change"
        )
    for remediation_id in _loaded(change.remediation_ids):
        record = db.get(Remediation, remediation_id)
        if record is not None:
            db.delete(record)
    change.revision = plan.revision
    change.proposal_ids = plan.proposal_ids
    change.summary = summary_of(plan, model, evidence, simulation)
    _store_files(db, change, plan, actor)
    change.updated_at = now()


def get_change(db: Session, tenant: str, change_id: str, lock: bool = False) -> RolloutChange:
    query = select(RolloutChange).where(RolloutChange.id == change_id, RolloutChange.tenant_id == tenant)
    if lock:
        query = query.with_for_update().execution_options(populate_existing=True)
    change = db.execute(query).scalar_one_or_none()
    if change is None:
        raise ChangeNotFound(change_id)
    return change


def watch_ends(change: RolloutChange) -> datetime | None:
    if change.merged_at is None:
        return None
    return _aware(change.merged_at) + timedelta(days=change.watch_days)


def _aware(value: datetime) -> datetime:
    from datetime import UTC

    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def canary_of(db: Session, tenant: str, topic_id: str) -> RolloutChange | None:
    """The topic's current canary: the latest canary change that was not rolled back."""
    return db.scalars(
        select(RolloutChange)
        .where(
            RolloutChange.tenant_id == tenant,
            RolloutChange.topic_id == topic_id,
            RolloutChange.canary.is_(True),
            RolloutChange.state != "rolled_back",
        )
        .order_by(RolloutChange.created_at.desc(), RolloutChange.id)
        .limit(1)
    ).first()


@dataclass
class Gate:
    allowed: bool
    canary: bool  # this change becomes (or is) the topic's canary
    reason: str = ""
    canary_id: str | None = None


def gate(db: Session, change: RolloutChange) -> Gate:
    """May this change open its pull request now (canary gating per topic)?"""
    current = canary_of(db, change.tenant_id, change.topic_id)
    if current is None:
        if change.scope != "role":
            return Gate(
                False, False, "A topic bundle opens after a single-role canary of the topic is verified"
            )
        return Gate(True, True)
    if current.id == change.id:
        return Gate(True, True, canary_id=current.id)
    if current.state == "verified":
        return Gate(True, False, canary_id=current.id)
    ends = watch_ends(current)
    detail = {
        "draft": "its pull request is not open yet",
        "pr_open": "its pull request is not merged yet",
        "merged": f"watching for AccessDenied until {ends.date().isoformat()}" if ends else "merged",
        "revert_open": "it is being reverted",
    }.get(current.state, current.state)
    if current.flagged_at is not None:
        detail = "AccessDenied events were seen; it is flagged for revert"
    return Gate(False, False, f"Waiting for canary {current.subject_name}: {detail}", current.id)


def refresh(db: Session, tenant: str, at: datetime | None = None) -> list[RolloutChange]:
    """Merged changes whose watch window passed without a flag become verified (audited)."""
    from app.core.auth import Actor
    from app.db.session import audit

    at = at or now()
    verified = []
    for change in db.scalars(
        select(RolloutChange).where(
            RolloutChange.tenant_id == tenant,
            RolloutChange.state == "merged",
            RolloutChange.flagged_at.is_(None),
        )
    ):
        ends = watch_ends(change)
        if ends is not None and at >= ends:
            change.state, change.verified_at, change.updated_at = "verified", at, at
            audit(
                db,
                Actor("system:rollout", tenant, frozenset()),
                "rollout.verified",
                {"change_id": change.id, "canary": change.canary, "watch_days": change.watch_days},
            )
            verified.append(change)
    return verified


def transition(change: RolloutChange, target: str, at: datetime | None = None) -> None:
    """Person-reported state changes: merged (in the customer's repository) and reverted."""
    at = at or now()
    allowed = {"merged": ("pr_open",), "rolled_back": ("revert_open",)}
    if target not in allowed or change.state not in allowed[target]:
        raise RolloutError(f"A {change.state} change cannot become {target}")
    change.state, change.updated_at = target, at
    if target == "merged":
        change.merged_at = at
    else:
        change.rolled_back_at = at


def can_revert(change: RolloutChange) -> None:
    if change.state not in ("merged", "verified", "revert_open"):
        raise RolloutError(
            "Only a merged change can be reverted; close an unmerged pull request in your repository instead"
        )


def change_files(db: Session, change: RolloutChange) -> list[FileChange]:
    """The forward change's files (created only) from its remediation records."""
    found = []
    for item in _loaded(change.files):
        record = db.get(Remediation, item["remediation_id"])
        if record is None or record.tenant_id != change.tenant_id:
            raise RolloutError("A remediation record of this change is missing")
        found.append(FileChange(item["path"], render(record.optimized)))
    return found


def revert_files(db: Session, change: RolloutChange) -> list[FileChange]:
    """Restore every file to ``Remediation.original`` byte for byte (remove an added deny-all)."""
    found = []
    for item in _loaded(change.files):
        record = db.get(Remediation, item["remediation_id"])
        if record is None or record.tenant_id != change.tenant_id:
            raise RolloutError("A remediation record of this change is missing")
        restored = render(record.original) if item["op"] == "rewrite" else None
        found.append(FileChange(item["path"], restored, expected=render(record.optimized)))
    return found


# ---------------------------------------------------------------------------
# Pull request text


def _md(value) -> str:
    text = str(value if value is not None else "")
    return text.replace("|", "\\|").replace("<", "&lt;").replace("`", "'").replace("\n", " ")[:200]


def _pct(value) -> str:
    return f"{value * 100:.1f}%" if isinstance(value, int | float) else "n/a"


def pr_title(change: RolloutChange) -> str:
    count = change.summary.get("proposal_count", 0)
    if change.scope == "topic":
        return f"ZeroGraph: least-privilege bundle for topic {change.subject_name} ({count} proposals)"
    return f"ZeroGraph: least-privilege change for {change.subject_name} ({count} proposals)"


def pr_body(change: RolloutChange, plan_note: str, tenant_key: str, prefix: str) -> str:
    """Markdown body: proposals, evidence, EPI, simulation, canary plan, revert instructions."""
    summary = change.summary
    lines = [
        f"## ZeroGraph least-privilege change {change.id[:8]}",
        "",
        f"> {NOTICE} Generated from graph revision `{_md(change.revision)}`; review before merging.",
        "",
        "### Proposals included",
        "",
        "| Proposal | Type | Tier | Principal | Asset |",
        "|---|---|---|---|---|",
    ]
    for item in summary.get("proposals", [])[:MAX_LISTED]:
        lines.append(
            f"| {_md(item['id'])} | {_md(item['type'])} | {_md(item['tier'])} | {_md(item['subject_name'])} "
            f"| {_md(item['target_name'] or '-')} |"
        )
    extra = summary.get("proposal_count", 0) - min(MAX_LISTED, len(summary.get("proposals", [])))
    if extra > 0:
        lines.append(f"\n{extra} more proposal(s) are listed in ZeroGraph.")
    evidence = summary.get("evidence") or {}
    lines += [
        "",
        "### Evidence",
        "",
        f"- Usage evidence: {_md(evidence.get('status'))}; window {_md(evidence.get('window_start'))}"
        f" to {_md(evidence.get('window_end'))}; services with sufficient coverage:"
        f" {_md(', '.join(evidence.get('sufficient_services') or []) or 'none')}.",
        "- Every removed grant was unused for the full attested window; no proposal removes observed access.",
    ]
    epi = summary.get("epi")
    if epi:
        roles, identities = epi["graph"]["roles"], epi["graph"]["identities"]
        lines += [
            "",
            "### Excess privilege (what-if, before -> after this change)",
            "",
            f"- Roles: {_pct(roles['before']['epi'])} -> {_pct(roles['after']['epi'])}"
            f" (without hub roles {_pct(roles['before']['epi_excl_hubs'])} -> {_pct(roles['after']['epi_excl_hubs'])})",
            f"- Identities: {_pct(identities['before']['epi'])} -> {_pct(identities['after']['epi'])}",
            f"- Grants removed: {epi['counts'].get('grants_removed', 0)};"
            f" principals disabled: {epi['counts'].get('disabled_nodes', 0)}",
        ]
    simulation = summary.get("simulation")
    if simulation:
        lines += [
            "",
            "### Simulation (blast radius of the principal, conditional grants included)",
            "",
            f"- Risk score {simulation.get('risk_before')} -> {simulation.get('risk_after')};"
            f" reachable data assets {simulation.get('assets_before')} -> {simulation.get('assets_after')}"
            f" ({simulation.get('assets_removed')} no longer reachable).",
        ]
    lines += ["", "### Canary plan", "", plan_note, ""]
    lines += [
        "### Files",
        "",
        f"Under `{_md(prefix)}/{tenant_key}/{change.id}/`:",
        "",
    ]
    for item in _loaded(change.files)[:MAX_CHANGES_LISTED]:
        action = (
            f"replaces inline policy `{_md(item['policy_name'])}` of `{_md(item['principal'])}`"
            if item["op"] == "rewrite"
            else f"adds inline deny-all policy `{_md(item['policy_name'])}` to `{_md(item['principal'])}` (disable; never delete)"
        )
        lines.append(f"- `{_md(item['path'])}` {action}")
    drafts = summary.get("draft_count", 0)
    if drafts:
        lines.append(
            f"\n{drafts} accepted proposal(s) of this selection stay draft-only (manual) in ZeroGraph."
        )
    lines += [
        "",
        "### Revert",
        "",
        "Use **Open revert PR** on this change in ZeroGraph (Proposals > Rollout). The revert restores every"
        " rewritten file byte for byte from the stored original policy and removes an added deny-all policy;"
        " it is opened as a draft and never merged by ZeroGraph. ZeroGraph opens it automatically if"
        " AccessDenied events for a touched principal appear in uploaded CloudTrail during the watch window.",
    ]
    return "\n".join(lines)


def canary_note(change: RolloutChange, decision: Gate) -> str:
    if decision.canary:
        return (
            f"This is the **canary** for its topic: other changes of the topic wait until it is merged and"
            f" {change.watch_days} day(s) pass without AccessDenied events for what it touched."
        )
    return (
        "The topic's canary was verified; this change widens the rollout. It is watched for AccessDenied too."
    )


def revert_body(change: RolloutChange, reason: str) -> str:
    lines = [
        f"## Revert of ZeroGraph change {change.id[:8]}",
        "",
        f"> {NOTICE}",
        "",
        f"Reason: {_md(reason)}",
        "",
        f"Original pull request: {_md(change.pr_url)}",
        "",
        "Restores each rewritten inline policy file byte for byte to the stored original document and removes"
        " the added deny-all policy files. Review and merge to roll the change back.",
    ]
    flag = change.flag or {}
    if flag:
        lines += ["", f"AccessDenied events in the watch window: {flag.get('events', 0)}"]
        for pair in flag.get("pairs", [])[:20]:
            lines.append(f"- `{_md(pair['principal'])}` on `{_md(pair['resource'])}`: {pair['count']}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# AccessDenied watch


def access_denied(
    db: Session, tenant: str, threshold: int, at: datetime | None = None
) -> list[RolloutChange]:
    """Flag merged changes with AccessDenied events on what they touched inside their window."""
    at = at or now()
    flagged = []
    candidates = list(
        db.scalars(
            select(RolloutChange).where(
                RolloutChange.tenant_id == tenant,
                RolloutChange.state.in_(("merged", "verified")),
                RolloutChange.flagged_at.is_(None),
            )
        )
    )
    for change in candidates:
        start, end = _aware(change.merged_at), watch_ends(change)
        touched = change.summary.get("touched", {})
        if not touched:
            continue
        rows = db.execute(
            select(AccessDenial.principal_id, AccessDenial.resource_id, func.sum(AccessDenial.count))
            .join(UsageUpload, UsageUpload.id == AccessDenial.upload_id)
            .where(
                AccessDenial.tenant_id == tenant,
                UsageUpload.tenant_id == tenant,
                UsageUpload.status == "committed",
                AccessDenial.principal_id.in_(list(touched)[:1000]),
                AccessDenial.last_seen >= start,
                AccessDenial.first_seen <= end,
            )
            .group_by(AccessDenial.principal_id, AccessDenial.resource_id)
        ).all()
        pairs = []
        for principal, resource, count in rows:
            item = touched.get(principal, {})
            if item.get("disabled") or resource in set(item.get("removed", [])):
                pairs.append({"principal": principal, "resource": resource, "count": int(count)})
        events = sum(pair["count"] for pair in pairs)
        if events >= threshold:
            pairs.sort(key=lambda pair: (-pair["count"], pair["principal"], pair["resource"]))
            change.flagged_at, change.updated_at = at, at
            change.flag = {"events": events, "pairs": pairs[:50], "threshold": threshold}
            flagged.append(change)
    return flagged


# ---------------------------------------------------------------------------
# Views


def view(change: RolloutChange, decision: Gate | None = None, at: datetime | None = None) -> dict:
    at = at or now()
    ends = watch_ends(change)
    remaining = None
    if ends is not None and change.state == "merged":
        remaining = max(0.0, round((ends - at).total_seconds() / 86400, 2))
    files = _loaded(change.files)
    return {
        "id": change.id,
        "scope": change.scope,
        "topic_id": change.topic_id,
        "subject_id": change.subject_id,
        "subject_name": change.subject_name,
        "state": change.state,
        "canary": change.canary,
        "held": decision is not None and not decision.allowed and change.state == "draft",
        "held_reason": decision.reason if decision is not None and not decision.allowed else "",
        "revision": change.revision,
        "proposal_ids": _loaded(change.proposal_ids),
        "proposal_count": change.summary.get("proposal_count", 0),
        "draft_count": change.summary.get("draft_count", 0),
        "by_type": change.summary.get("by_type", {}),
        "principals": change.summary.get("principals", []),
        "files": [{k: v for k, v in item.items() if k != "diff"} for item in files],
        "epi": change.summary.get("epi"),
        "simulation": change.summary.get("simulation"),
        "pr_url": change.pr_url,
        "pr_requested": change.gitops_scope is not None,
        "merged_at": change.merged_at,
        "watch_days": change.watch_days,
        "watch_ends": ends,
        "watch_remaining_days": remaining,
        "verified_at": change.verified_at,
        "flagged_at": change.flagged_at,
        "flag": change.flag,
        "revert_pr_url": change.revert_pr_url,
        "revert_requested": change.revert_scope is not None,
        "revert_error": change.revert_error,
        "rolled_back_at": change.rolled_back_at,
        "actor": change.actor,
        "created_at": change.created_at,
        "updated_at": change.updated_at,
    }


def detail(change: RolloutChange, decision: Gate | None = None) -> dict:
    return {
        **view(change, decision),
        "diffs": [{"path": item["path"], "diff": item.get("diff", "")} for item in _loaded(change.files)],
        "drafts": change.summary.get("drafts", []),
        "proposals": change.summary.get("proposals", []),
        "notice": NOTICE,
    }


def plan_view(plan: Plan, decision_note: str = "") -> dict:
    return {
        "revision": plan.revision,
        "scope": plan.scope,
        "topic_id": plan.topic_id,
        "subject_id": plan.subject_id,
        "subject_name": plan.subject_name,
        "eligible": bool(plan.files),
        "proposal_ids": plan.proposal_ids,
        "principals": plan.principals,
        "files": [item.as_dict() for item in plan.files],
        "drafts": plan.drafts[:MAX_CHANGES_LISTED],
        "draft_count": len(plan.drafts),
        "gate": decision_note,
        "notice": NOTICE,
    }


def rows_by_id(rows: Iterable[RevisionProposal]) -> dict[str, RevisionProposal]:
    return {row.proposal_id: row for row in rows}
