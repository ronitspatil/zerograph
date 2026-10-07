"""Policy documents of a revision: stored once per content hash, attached to principals.

Collectors (and snapshot uploads) submit ``PolicyAttachment`` entries beside the
graph: the principal, how the policy applies (inline, managed, boundary, trust or
inherited from a group) and the document. Publication stores each distinct
document once per revision in ``revision_policy_documents`` (keyed by the SHA-256
of its canonical JSON) and every attachment in ``revision_policies``, in the
publication transaction. Node JSON never carries documents. Rows are deleted by
retention with their revision and travel in the PostgreSQL dump.
"""

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from fnmatch import fnmatchcase

from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.db.models import RevisionPolicy, RevisionPolicyDocument
from app.graph.schema import canonical_policy

# Distinct document bytes a single revision may store (each document is also bounded).
MAX_REVISION_POLICY_BYTES = 64 * 2**20
MAX_PRINCIPAL_POLICIES = 200


class PolicyBudgetExceeded(ValueError):
    pass


def store_policies(db: Session, tenant: str, revision: str, payloads: Iterable[tuple[str, str]]) -> int:
    """Store ``(attachment ID, canonical attachment JSON)`` rows; first attachment ID wins.

    Returns the number of attachments stored. Raises ``PolicyBudgetExceeded`` when the
    revision's distinct documents exceed ``MAX_REVISION_POLICY_BYTES``.
    """
    from app.graph.clusters import _bulk_insert

    seen: set[str] = set()
    documents: dict[str, str] = {}
    attachments: list[tuple] = []
    total = 0
    for attachment_id, payload in payloads:
        if attachment_id in seen:
            continue
        seen.add(attachment_id)
        value = json.loads(payload)
        document = canonical_policy(value["document"])
        digest = hashlib.sha256(document.encode()).hexdigest()
        if digest not in documents:
            total += len(document.encode())
            if total > MAX_REVISION_POLICY_BYTES:
                raise PolicyBudgetExceeded("Revision policy documents exceed the configured byte limit")
            documents[digest] = document
        attachments.append(
            (
                tenant,
                revision,
                attachment_id,
                value["principal"],
                value["kind"],
                value["name"][:256],
                value.get("arn", ""),
                digest,
            )
        )
    _bulk_insert(
        db,
        RevisionPolicyDocument,
        ["tenant_id", "revision", "digest", "size_bytes", "document"],
        ((tenant, revision, digest, len(doc.encode()), doc) for digest, doc in sorted(documents.items())),
    )
    _bulk_insert(
        db,
        RevisionPolicy,
        ["tenant_id", "revision", "attachment_id", "principal_id", "kind", "name", "arn", "digest"],
        attachments,
    )
    return len(attachments)


def delete_policies(db: Session, tenant: str, revision: str) -> None:
    for model in (RevisionPolicy, RevisionPolicyDocument):
        db.execute(delete(model).where(model.tenant_id == tenant, model.revision == revision))


class PrincipalPolicy(BaseModel):
    kind: str
    name: str
    arn: str
    digest: str
    size_bytes: int
    document: dict


class PrincipalPoliciesResponse(BaseModel):
    revision: str
    principal: str
    policies: list[PrincipalPolicy]
    truncated: bool


def principal_policies(db: Session, tenant: str, revision: str, principal: str) -> PrincipalPoliciesResponse:
    rows = db.execute(
        select(
            RevisionPolicy.kind,
            RevisionPolicy.name,
            RevisionPolicy.arn,
            RevisionPolicy.digest,
            RevisionPolicyDocument.size_bytes,
            RevisionPolicyDocument.document,
        )
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
        )
        .order_by(RevisionPolicy.kind, RevisionPolicy.name, RevisionPolicy.attachment_id)
        .limit(MAX_PRINCIPAL_POLICIES + 1)
    ).all()
    return PrincipalPoliciesResponse(
        revision=revision,
        principal=principal,
        policies=[
            PrincipalPolicy(
                kind=kind, name=name, arn=arn, digest=digest, size_bytes=size, document=json.loads(document)
            )
            for kind, name, arn, digest, size, document in rows[:MAX_PRINCIPAL_POLICIES]
        ],
        truncated=len(rows) > MAX_PRINCIPAL_POLICIES,
    )


# ---------------------------------------------------------------------------
# Policy constraints for optimizer proposals (``app.graph.proposals``)

IDENTITY_KINDS = ("inline", "managed", "group-inline", "group-managed")


@dataclass(frozen=True)
class Statement:
    effect: str  # "allow" or "deny"
    actions: tuple[str, ...]  # lowercase patterns; NotAction statements match every action
    any_action: bool
    resources: tuple[str, ...]
    any_resource: bool
    condition: bool

    def matches(self, actions: tuple[str, ...], resource: str) -> bool:
        if not self.any_action and not any(
            fnmatchcase(action.lower(), pattern) for action in actions for pattern in self.actions
        ):
            return False
        if self.any_resource:
            return True
        return any(fnmatchcase(target, pattern) for target in (resource, resource + "/*") for pattern in self.resources)


def _strings(value) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(item for item in value if isinstance(item, str))
    return ()


def statements(document: dict) -> list[Statement]:
    """Allow and Deny statements of an identity policy document (malformed entries skipped)."""
    raw = document.get("Statement", [])
    if isinstance(raw, dict):
        raw = [raw]
    found = []
    for statement in raw if isinstance(raw, list) else []:
        if not isinstance(statement, dict):
            continue
        effect = str(statement.get("Effect", "")).lower()
        if effect not in ("allow", "deny"):
            continue
        actions = tuple(action.lower() for action in _strings(statement.get("Action")))
        resources = _strings(statement.get("Resource"))
        found.append(
            Statement(
                effect,
                actions,
                "NotAction" in statement or "*" in actions,
                resources,
                "NotResource" in statement or "*" in resources or not resources,
                bool(statement.get("Condition")),
            )
        )
    return found


@dataclass
class PolicyIndex:
    """Identity-policy statements per principal of a revision (only principals with documents)."""

    statements: dict[str, list[Statement]] = field(default_factory=dict)

    def constraints(self, principal: str, actions: tuple[str, ...], resource: str) -> list[str]:
        """Never-auto reasons for removing ``actions`` on ``resource`` from ``principal``.

        ``condition``: an Allow granting it carries a Condition; ``deny``: a Deny statement
        applies to it (removal interplays with Deny semantics); ``resource_policy``: the
        principal has identity policies but none grants it (the grant comes from a resource
        policy or elsewhere). Principals without stored documents have no constraints here.
        """
        found = self.statements.get(principal)
        if not found:
            return []
        reasons = []
        allows = [s for s in found if s.effect == "allow" and s.matches(actions, resource)]
        if any(s.condition for s in allows):
            reasons.append("condition")
        if any(s.effect == "deny" and s.matches(actions, resource) for s in found):
            reasons.append("deny")
        if not allows:
            reasons.append("resource_policy")
        return reasons


def policy_index(db: Session, tenant: str, revision: str) -> PolicyIndex:
    """Statements of every identity policy attached to a principal of the revision."""
    documents: dict[str, list[Statement]] = {}
    index = PolicyIndex()
    rows = db.execute(
        select(RevisionPolicy.principal_id, RevisionPolicy.digest, RevisionPolicyDocument.document)
        .join(
            RevisionPolicyDocument,
            (RevisionPolicyDocument.tenant_id == RevisionPolicy.tenant_id)
            & (RevisionPolicyDocument.revision == RevisionPolicy.revision)
            & (RevisionPolicyDocument.digest == RevisionPolicy.digest),
        )
        .where(
            RevisionPolicy.tenant_id == tenant,
            RevisionPolicy.revision == revision,
            RevisionPolicy.kind.in_(IDENTITY_KINDS),
        )
        .order_by(RevisionPolicy.principal_id, RevisionPolicy.attachment_id)
    )
    for principal, digest, document in rows:
        if digest not in documents:
            try:
                documents[digest] = statements(json.loads(document))
            except (ValueError, AttributeError):
                documents[digest] = []
        index.statements.setdefault(principal, []).extend(documents[digest])
    return index
