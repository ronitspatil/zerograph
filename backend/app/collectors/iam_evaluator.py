"""Conservative, finite-request IAM evaluation. Unknown context never becomes a confirmed allow."""

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    CONDITIONAL = "conditional"


@dataclass(frozen=True)
class Request:
    principal: str
    action: str
    resource: str
    context: dict[str, Any] = field(default_factory=dict)
    cross_account: bool = False


@dataclass(frozen=True)
class Evaluation:
    decision: Decision
    reasons: tuple[str, ...]


def values(value: Any) -> list:
    return value if isinstance(value, list) else [value]


def statements(policy: dict) -> list[dict]:
    return values(policy.get("Statement", []))


def glob(value: str, patterns: Any, insensitive: bool = False) -> bool:
    if insensitive:
        return any(fnmatch.fnmatchcase(value.lower(), str(p).lower()) for p in values(patterns))
    return any(fnmatch.fnmatchcase(value, str(p)) for p in values(patterns))


def conditions_match(conditions: dict, context: dict) -> bool | None:
    unknown = False
    for operator, entries in conditions.items():
        for key, expected in entries.items():
            present = key in context
            if operator == "Null":
                if not present:
                    unknown = True
                elif str(expected).lower() == "true":
                    return False
                continue
            if not present:
                # Missing collection context is not evidence that a request key is absent.
                unknown = True
                continue
            actuals = values(context[key])
            if len(actuals) != 1:
                unknown = True  # Multivalued keys require explicit IAM set-operator semantics.
                continue
            expected_values = values(expected)
            if any("${" in str(e) for e in expected_values):
                unknown = True
                continue
            base_op = operator.removesuffix("IfExists")
            if base_op in {"StringEquals", "ArnEquals", "Bool"}:
                match = any(
                    str(a).lower() == str(e).lower() if base_op == "Bool" else str(a) == str(e)
                    for a in actuals
                    for e in expected_values
                )
            elif base_op in {"StringLike", "ArnLike"}:
                match = any(glob(str(a), expected_values) for a in actuals)
            elif base_op in {"StringNotEquals", "ArnNotEquals"}:
                match = all(str(a) != str(e) for a in actuals for e in expected_values)
            elif base_op in {"StringNotLike", "ArnNotLike"}:
                match = all(not glob(str(a), expected_values) for a in actuals)
            elif base_op in {"IpAddress", "NotIpAddress"}:
                try:
                    match = any(
                        ipaddress.ip_address(str(a)) in ipaddress.ip_network(str(e))
                        for a in actuals
                        for e in expected_values
                    )
                    if base_op == "NotIpAddress":
                        match = not match
                except ValueError:
                    unknown = True
                    continue
            else:
                unknown = True
                continue
            if not match:
                return False
    return None if unknown else True


def principal_match(statement: dict, principal: str) -> bool | None:
    if "NotPrincipal" in statement:
        return None  # Boundary-dependent NotPrincipal deny semantics need provider-side simulation.
    selected = statement.get("Principal", "*")
    if isinstance(selected, dict):
        selected = selected.get("AWS", [])
    for item in values(selected):
        if item == "*" or item == principal:
            return True
        if isinstance(item, str) and item.endswith(":root"):
            if len(principal.split(":")) > 4 and item.split(":")[4] == principal.split(":")[4]:
                return True
        if isinstance(item, str) and item.isdigit() and len(principal.split(":")) > 4:
            if item == principal.split(":")[4]:
                return True
    return False


def statement_match(statement: dict, request: Request, resource_policy: bool = False) -> bool | None:
    if "Action" in statement:
        action_match = glob(request.action, statement["Action"], insensitive=True)
    elif "NotAction" in statement:
        action_match = not glob(request.action, statement["NotAction"], insensitive=True)
    else:
        return None
    if not action_match:
        return False
    resource_unknown = any(
        "${" in str(pattern)
        for pattern in values(statement.get("Resource", statement.get("NotResource", [])))
    )
    if "Resource" in statement:
        resource_match = True if resource_unknown else glob(request.resource, statement["Resource"])
    elif "NotResource" in statement:
        resource_match = True if resource_unknown else not glob(request.resource, statement["NotResource"])
    else:
        resource_match = True if resource_policy else False
    if not resource_match:
        return False
    principal = principal_match(statement, request.principal) if resource_policy else True
    if principal is False:
        return False
    condition = conditions_match(statement.get("Condition", {}), request.context)
    if condition is False:
        return False
    return None if resource_unknown or principal is None or condition is None else True


def policy_result(
    policies: list[dict], request: Request, resource_policy: bool = False
) -> tuple[bool, bool, bool, bool]:
    allowed = denied = maybe_allow = maybe_deny = False
    for policy in policies:
        for statement in statements(policy):
            match = statement_match(statement, request, resource_policy)
            if match is False:
                continue
            if statement.get("Effect") == "Deny":
                denied |= match is True
                maybe_deny |= match is None
            elif statement.get("Effect") == "Allow":
                allowed |= match is True
                maybe_allow |= match is None
            else:
                maybe_deny = True
    return allowed, denied, maybe_allow, maybe_deny


def evaluate(
    request: Request,
    identity: list[dict],
    resource: list[dict] | None = None,
    boundary: list[dict] | None = None,
    scp_levels: list[list[dict]] | None = None,
    session: list[dict] | None = None,
    rcp_levels: list[list[dict]] | None = None,
    scope_complete: bool = True,
    require_resource_allow: bool = False,
) -> Evaluation:
    identity_result = policy_result(identity, request)
    resource_result = policy_result(resource or [], request, True)
    gates = [policy_result(p, request) for p in (boundary, session) if p is not None]
    organization = [policy_result(level, request) for level in (scp_levels or []) + (rcp_levels or [])]
    all_results = [identity_result, resource_result, *gates, *organization]
    if any(result[1] for result in all_results):
        return Evaluation(Decision.DENY, ("An applicable explicit deny overrides all grants",))
    if any(not result[0] and not result[2] for result in organization):
        return Evaluation(Decision.DENY, ("An Organizations policy level does not allow this request",))
    direct_grant = False
    direct_trust_possible = direct_trust_certain = False
    # A literal same-account principal in a role trust policy grants AssumeRole
    # without an identity Allow. Account-root delegation still requires both sides.
    if not request.cross_account and request.action.lower() == "sts:assumerole":
        for policy in resource or []:
            for stmt in statements(policy):
                selected = stmt.get("Principal", {})
                selected = selected.get("AWS", []) if isinstance(selected, dict) else selected
                if request.principal in values(selected) and stmt.get("Effect") == "Allow":
                    match = statement_match(stmt, request, True)
                    direct_trust_possible |= match is not False
                    direct_trust_certain |= match is True
    # Same-account direct IAM-user and STS-session grants bypass implicit boundary/session denial.
    if not request.cross_account and (":user/" in request.principal or ":assumed-role/" in request.principal):
        for policy in resource or []:
            for stmt in statements(policy):
                selected = stmt.get("Principal", {})
                selected = selected.get("AWS", []) if isinstance(selected, dict) else selected
                if request.principal in values(selected) and stmt.get("Effect") == "Allow":
                    direct_grant |= statement_match(stmt, request, True) is True
    if not direct_grant and any(not result[0] and not result[2] for result in gates):
        return Evaluation(
            Decision.DENY, ("A permissions boundary or session policy does not allow this request",)
        )
    identity_possible = identity_result[0] or identity_result[2]
    resource_possible = resource_result[0] or resource_result[2]
    both_required = request.cross_account or (require_resource_allow and not direct_trust_possible)
    possible = (
        identity_possible and resource_possible if both_required else identity_possible or resource_possible
    )
    if require_resource_allow and direct_trust_possible:
        possible = resource_possible
    if not possible:
        if not scope_complete:
            return Evaluation(
                Decision.CONDITIONAL, ("Collection is incomplete; absent grants are not proof of denial",)
            )
        return Evaluation(Decision.DENY, ("No applicable grant",))
    certain = (
        identity_result[0] and resource_result[0]
        if both_required
        else identity_result[0] or resource_result[0]
    )
    if require_resource_allow and direct_trust_possible:
        certain = direct_trust_certain or (identity_result[0] and resource_result[0])
    if (
        not scope_complete
        or not certain
        or any(r[3] for r in all_results)
        or any(not r[0] for r in organization)
    ):
        return Evaluation(
            Decision.CONDITIONAL,
            ("Policy context, collection coverage, or conditional denies are unresolved",),
        )
    if not direct_grant and any(not r[0] for r in gates):
        return Evaluation(
            Decision.CONDITIONAL, ("A boundary or session grant depends on unresolved context",)
        )
    return Evaluation(Decision.ALLOW, ("Applicable grant with all collected boundaries satisfied",))
