"""AWS-managed policy corpus qualification: bounds, canonical hashing and IAM evaluation.

Reads every AWS-managed policy document from a local copy of a public corpus (the
``aws/managedpolicies/*.json`` files of https://github.com/iann0036/iam-dataset, one
file per policy with ``arn``, ``document`` and ``effective_actions``) and runs each one
through what a collection does with it:

* ``decode_policy`` with the AWS-managed bounds (1 MiB, 2,048 statements), from the
  decoded object botocore returns, from its JSON text and from URL-encoded JSON text
  (the wire form of ``GetPolicyVersion``); every document must decode (0 beyond the
  bounds), and the customer bound (64 KiB) is reported for comparison;
* ``PolicyAttachment`` validation as an attached ``managed`` policy, canonical hashing
  (the digest must be stable across key order, a JSON round trip and the upload
  staging round trip, so one document is stored once per revision);
* ``iam_evaluator.evaluate`` against representative S3, STS, Glue, Athena, Lake
  Formation and IAM requests, plus an oracle check: every effective action the corpus
  lists for an Allow statement (sampled per policy) must not be denied when requested on
  a resource that statement names.

Nothing is fetched here: pass ``--corpus`` pointing at the dataset's
``aws/managedpolicies`` directory. Exceptions are counted per stage, never raised, and
the report lists the policies involved.
"""

import argparse
import fnmatch
import hashlib
import json
import platform
import sys
import time
import tracemalloc
from collections import Counter
from pathlib import Path
from urllib.parse import quote

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from app.collectors import staging  # noqa: E402
from app.collectors.aws_collector import (  # noqa: E402
    MAX_AWS_MANAGED_POLICY_STATEMENTS,
    MAX_POLICY_STATEMENTS,
    PolicyTooLarge,
    decode_policy,
)
from app.collectors.iam_evaluator import Decision, Request, evaluate, statements, values  # noqa: E402
from app.graph.schema import (  # noqa: E402
    MAX_AWS_MANAGED_POLICY_BYTES,
    MAX_POLICY_BYTES,
    PolicyAttachment,
    aws_managed_policy,
    canonical_policy,
)

ACCOUNT = "123456789012"
REGION = "us-east-1"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/corpus-probe"
REPRESENTATIVE = (
    ("s3:GetObject", "arn:aws:s3:::corpus-bucket/key"),
    ("s3:PutObject", "arn:aws:s3:::corpus-bucket/key"),
    ("s3:ListBucket", "arn:aws:s3:::corpus-bucket"),
    ("s3:DeleteObject", "arn:aws:s3:::corpus-bucket/key"),
    ("sts:AssumeRole", f"arn:aws:iam::{ACCOUNT}:role/target"),
    ("iam:PassRole", f"arn:aws:iam::{ACCOUNT}:role/target"),
    ("glue:GetTable", f"arn:aws:glue:{REGION}:{ACCOUNT}:table/sales/orders"),
    ("glue:UpdateTable", f"arn:aws:glue:{REGION}:{ACCOUNT}:table/sales/orders"),
    ("glue:GetDatabase", f"arn:aws:glue:{REGION}:{ACCOUNT}:database/sales"),
    ("athena:StartQueryExecution", f"arn:aws:athena:{REGION}:{ACCOUNT}:workgroup/primary"),
    ("lakeformation:GetDataAccess", "*"),
    ("kms:Decrypt", f"arn:aws:kms:{REGION}:{ACCOUNT}:key/1234"),
)
# Expected decisions for well-known policies (never DENY = allow or conditional).
SPOT_CHECKS = {
    "AdministratorAccess": {"s3:GetObject": "allow", "s3:PutObject": "allow", "sts:AssumeRole": "allow"},
    "ReadOnlyAccess": {"s3:GetObject": "allow", "s3:PutObject": "deny", "glue:GetTable": "allow"},
    "AmazonS3ReadOnlyAccess": {"s3:GetObject": "allow", "s3:PutObject": "deny", "glue:GetTable": "deny"},
    "AmazonS3FullAccess": {"s3:PutObject": "allow", "s3:DeleteObject": "allow", "sts:AssumeRole": "deny"},
    "AmazonAthenaFullAccess": {"athena:StartQueryExecution": "allow", "glue:GetTable": "allow"},
    "AWSLakeFormationDataAdmin": {"lakeformation:GetDataAccess": "allow", "glue:GetTable": "allow"},
    "AWSGlueConsoleFullAccess": {"glue:UpdateTable": "allow", "athena:StartQueryExecution": "deny"},
    "AWSSupportServiceRolePolicy": {"s3:GetObject": "deny", "s3:PutObject": "deny"},
}
ORACLE_SAMPLE = 200  # Effective actions checked per policy (deterministic sample).


def concrete(resource: str) -> str:
    """A resource string a pattern matches: wildcards replaced by a literal."""
    return resource.replace("*", "x").replace("?", "x") if resource != "*" else "*"


def oracle_requests(document: dict, effective: list[dict]) -> list[tuple[str, str, str]]:
    """(effective action, granting pattern, concrete resource) for sampled Allow actions."""
    allows = [
        statement
        for statement in statements(document)
        if statement.get("Effect") == "Allow" and "Action" in statement and "Resource" in statement
    ]
    found = []
    seen = set()
    for item in effective:
        action, pattern = item.get("effective_action"), item.get("action")
        if not isinstance(action, str) or not isinstance(pattern, str) or action in seen:
            continue
        if item.get("condition"):
            continue  # Conditional grants are allowed to come back conditional or denied context.
        for statement in allows:
            if any(fnmatch.fnmatchcase(pattern.lower(), str(p).lower()) for p in values(statement["Action"])):
                seen.add(action)
                found.append((action, pattern, concrete(str(values(statement["Resource"])[0]))))
                break
    found.sort()
    step = max(1, len(found) // ORACLE_SAMPLE)
    return found[::step][:ORACLE_SAMPLE]


def run(corpus: Path) -> dict:
    files = sorted(corpus.glob("*.json"))
    errors: dict[str, list[str]] = {}
    decisions: Counter = Counter()
    stats = Counter()
    sizes: list[tuple[int, str]] = []
    statement_counts: list[tuple[int, str]] = []
    encoded_sizes: list[tuple[int, str]] = []
    spot: dict[str, dict] = {}
    oracle_misses: list[dict] = []
    digests: dict[str, str] = {}
    evaluate_seconds = 0.0
    evaluations = 0
    tracemalloc.start()
    started = time.perf_counter()

    def error(stage: str, name: str, exc: BaseException) -> None:
        errors.setdefault(stage, []).append(f"{name}: {type(exc).__name__}")

    for path in files:
        name = path.stem
        stats["files"] += 1
        try:
            entry = json.loads(path.read_text())
        except ValueError as exc:
            error("read", name, exc)
            continue
        document, arn = entry.get("document"), entry.get("arn") or f"arn:aws:iam::aws:policy/{name}"
        if not isinstance(document, dict):
            error("read", name, TypeError("document is not an object"))
            continue
        if not aws_managed_policy(arn):
            stats["not_aws_managed_arn"] += 1
        stats["deprecated"] += bool(entry.get("deprecated"))
        stats["corpus_malformed_flag"] += bool(entry.get("malformed"))
        canonical = canonical_policy(document).encode()
        sizes.append((len(canonical), name))
        count = len(statements(document))
        statement_counts.append((count, name))
        encoded = quote(json.dumps(document, separators=(",", ":")), safe="")
        encoded_sizes.append((len(encoded.encode()), name))
        stats["over_customer_bytes"] += len(canonical) > MAX_POLICY_BYTES
        stats["over_customer_statements"] += count > MAX_POLICY_STATEMENTS
        bounds = {
            "max_bytes": MAX_AWS_MANAGED_POLICY_BYTES,
            "max_statements": MAX_AWS_MANAGED_POLICY_STATEMENTS,
        }
        for form, value in (
            ("object", json.loads(json.dumps(document))),
            ("json_text", json.dumps(document)),
            ("url_encoded", encoded),
        ):
            try:
                decoded = decode_policy(value, **bounds)
                if canonical_policy(decoded).encode() != canonical:
                    error(f"decode_{form}", name, ValueError("decoded document differs"))
            except PolicyTooLarge as exc:
                stats[f"over_aws_managed_bound_{form}"] += 1
                error(f"decode_{form}", name, exc)
            except Exception as exc:  # noqa: BLE001 - counted and reported, never raised
                error(f"decode_{form}", name, exc)
        try:
            attachment = PolicyAttachment(
                principal=ROLE, kind="managed", name=name[:256], arn=arn, document=document
            )
            digest = attachment.digest
            reordered = json.loads(json.dumps(document, sort_keys=False))
            reordered = dict(reversed(list(reordered.items())))
            if digest != hashlib.sha256(canonical_policy(reordered).encode()).hexdigest():
                error("hash", name, ValueError("digest depends on key order"))
            row = staging.policy_staged(attachment, 0, 0)
            restored = PolicyAttachment.model_validate(json.loads(row["payload"]))
            if restored.digest != digest or row["target_id"] != digest:
                error("hash", name, ValueError("digest changes across the staging round trip"))
            if digest in digests:
                stats["duplicate_documents"] += 1
            digests.setdefault(digest, name)
        except Exception as exc:  # noqa: BLE001
            error("attachment", name, exc)
        policy_started = time.perf_counter()
        results = {}
        for action, resource in REPRESENTATIVE:
            try:
                result = evaluate(
                    Request(
                        ROLE, action, resource, {"aws:PrincipalArn": ROLE, "aws:PrincipalAccount": ACCOUNT}
                    ),
                    [document],
                    scope_complete=True,
                )
                decisions[(action, result.decision.value)] += 1
                results[action] = result.decision.value
                evaluations += 1
            except Exception as exc:  # noqa: BLE001
                error("evaluate", name, exc)
        if name in SPOT_CHECKS:
            spot[name] = {
                action: {"expected": expected, "got": results.get(action)}
                for action, expected in SPOT_CHECKS[name].items()
            }
        effective = entry.get("effective_actions") if isinstance(entry.get("effective_actions"), list) else []
        for action, pattern, resource in oracle_requests(document, effective):
            try:
                result = evaluate(Request(ROLE, action, resource, {}), [document], scope_complete=True)
                evaluations += 1
                stats["oracle_checked"] += 1
                if result.decision == Decision.DENY:
                    stats["oracle_denied"] += 1
                    # The corpus expands Allow statements only; an explicit Deny in the same
                    # policy legitimately overrides them.
                    allows_only = {
                        **document,
                        "Statement": [s for s in statements(document) if s.get("Effect") != "Deny"],
                    }
                    again = evaluate(Request(ROLE, action, resource, {}), [allows_only], scope_complete=True)
                    if again.decision != Decision.DENY:
                        stats["oracle_denied_by_explicit_deny"] += 1
                        continue
                    stats["oracle_unexplained"] += 1
                    if len(oracle_misses) < 50:
                        oracle_misses.append(
                            {"policy": name, "action": action, "pattern": pattern, "resource": resource}
                        )
            except Exception as exc:  # noqa: BLE001
                error("oracle", name, exc)
        evaluate_seconds += time.perf_counter() - policy_started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    sizes.sort()
    statement_counts.sort()
    encoded_sizes.sort()
    spot_failures = [
        f"{policy}:{action} expected {check['expected']} got {check['got']}"
        for policy, checks in spot.items()
        for action, check in checks.items()
        if not (
            check["got"] == check["expected"]
            or (check["expected"] == "allow" and check["got"] == "conditional")
        )
    ]
    return {
        "corpus": str(corpus),
        "policies": stats["files"],
        "distinct_documents": len(digests),
        "max_canonical_bytes": sizes[-1] if sizes else None,
        "largest_canonical": sizes[-5:],
        "max_statements": statement_counts[-1] if statement_counts else None,
        "max_url_encoded_bytes": encoded_sizes[-1] if encoded_sizes else None,
        "over_aws_managed_bound": {
            form: stats[f"over_aws_managed_bound_{form}"] for form in ("object", "json_text", "url_encoded")
        },
        "over_customer_bound": {
            "bytes": stats["over_customer_bytes"],
            "statements": stats["over_customer_statements"],
        },
        "deprecated": stats["deprecated"],
        "corpus_malformed_flag": stats["corpus_malformed_flag"],
        "not_aws_managed_arn": stats["not_aws_managed_arn"],
        "duplicate_documents": stats["duplicate_documents"],
        "errors": {stage: {"count": len(items), "examples": items[:20]} for stage, items in errors.items()},
        "representative_decisions": {f"{a}={d}": n for (a, d), n in sorted(decisions.items())},
        "spot_checks": spot,
        "spot_check_failures": spot_failures,
        "oracle": {
            "checked": stats["oracle_checked"],
            "denied": stats["oracle_denied"],
            "denied_by_explicit_deny": stats["oracle_denied_by_explicit_deny"],
            "unexplained": stats["oracle_unexplained"],
            "examples": oracle_misses[:20],
        },
        "evaluations": evaluations,
        "evaluate_seconds": round(evaluate_seconds, 3),
        "seconds": round(time.perf_counter() - started, 3),
        "peak_traced_mib": round(peak / 2**20, 1),
        "python": platform.python_version(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--corpus", type=Path, required=True, help="iam-dataset aws/managedpolicies directory"
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.corpus)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    failed = (
        bool(report["errors"])
        or bool(report["spot_check_failures"])
        or bool(report["oracle"]["unexplained"])
        or any(report["over_aws_managed_bound"].values())
    )
    print(
        json.dumps(
            {
                k: report[k]
                for k in (
                    "policies",
                    "max_canonical_bytes",
                    "max_statements",
                    "over_aws_managed_bound",
                    "oracle",
                )
            }
        )
    )
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
