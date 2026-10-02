import copy
import difflib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.collectors.iam_evaluator import statements, values


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
