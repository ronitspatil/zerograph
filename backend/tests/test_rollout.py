"""Optimizer rollout: Resource scoping and its re-evaluation, CloudTrail AccessDenied capture,
multi-file GitOps reviews and compare-and-swap reverts against a local fake provider (no
network), and the rollout API end to end: diff correctness and the re-ingest round trip,
canary gating, byte-for-byte revert and the AccessDenied watch."""

import json
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.collectors.cloudtrail import normalize_export
from app.core.auth import Actor, current_actor
from app.db.models import (
    AccessDenial,
    AuditEvent,
    Remediation,
    RevisionPolicy,
    RevisionPolicyDocument,
    RolloutChange,
    TenantState,
)
from app.graph import proposals as P
from app.graph.schema import canonical_policy
from app.remediation import rollout
from app.remediation.gitops_sync import FileChange, GitOpsClient, GitOpsConflict, GitOpsError
from app.remediation.policy_optimizer import DENY_ALL, render, scope_policy, verify_scope

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import fake_git  # noqa: E402
from qualify_scale import cloudtrail_files, generate_topics, plant_role_policies  # noqa: E402
from rollout_reference import actual_after, expected_after, round_trip, verify_diffs  # noqa: E402

NOW = datetime.now(UTC).replace(microsecond=0)
A, B, C = "arn:aws:s3:::a", "arn:aws:s3:::b", "arn:aws:s3:::c"


def doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


# ---------------------------------------------------------------------------
# Resource scoping


def test_scope_drops_exact_and_object_entries_and_whole_statements():
    original = doc(
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": [A, A + "/*", B]},
        {"Effect": "Allow", "Action": "s3:PutObject", "Resource": A + "/*"},
        {"Effect": "Allow", "Action": "logs:CreateLogStream", "Resource": "*"},
        {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},
    )
    snapshot = json.dumps(original)
    result = scope_policy(original, {A: ["s3:GetObject", "s3:PutObject"]}, keep=[B])
    assert json.dumps(original) == snapshot  # input never mutated
    assert result.unresolved == {} and result.statements_removed == 1
    assert result.removed == {A: [A, A + "/*", A + "/*"]}
    assert result.optimized["Statement"] == [
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": [B]},
        original["Statement"][2],
        original["Statement"][3],
    ]
    assert verify_scope("p", [original], [result.optimized], {A: ["s3:GetObject"]}, {B: []}) == []


@pytest.mark.parametrize(
    "statement,reason",
    [
        ({"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::*"}, "pattern"),
        ({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}, "pattern"),
        ({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::${aws:username}"}, "pattern"),
        ({"Effect": "Allow", "Action": "s3:GetObject", "Resource": [A], "Condition": {"Bool": {"x": "y"}}}, "Condition"),
        ({"Effect": "Allow", "NotAction": "iam:*", "Resource": [A]}, "Condition/NotAction"),
        ({"Effect": "Allow", "Action": "s3:GetObject", "NotResource": [B]}, "NotResource"),
    ],
)  # fmt: skip
def test_unscopable_grants_stay_manual_and_unchanged(statement, reason):
    original = doc(statement, {"Effect": "Allow", "Action": "s3:GetObject", "Resource": [C]})
    result = scope_policy(original, {A: ["s3:GetObject"]})
    assert A in result.unresolved and (reason in result.unresolved[A] or "pattern" in result.unresolved[A])
    assert result.optimized is None and result.removed == {}


def test_entry_covering_a_kept_resource_and_empty_policy_are_manual():
    covering = doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": [A + "/*", B]})
    assert "kept resource" in scope_policy(covering, {A: ["s3:GetObject"]}, keep=[A + "/x"]).unresolved[A]
    original = doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": [A]})
    emptied = scope_policy(original, {A: ["s3:GetObject"]})
    assert emptied.empty and emptied.optimized is None
    # A string Resource stays a string; a single statement stays a single statement.
    single = {
        "Version": "2012-10-17",
        "Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": [A, B]},
    }
    scoped = scope_policy(single, {B: ["s3:GetObject"]})
    assert scoped.optimized["Statement"] == {"Effect": "Allow", "Action": "s3:GetObject", "Resource": [A]}


def test_verify_scope_catches_widening_and_unchanged_removals():
    before = [doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": [A, B]})]
    wider = [doc({"Effect": "Allow", "Action": "s3:*", "Resource": [B, C]})]
    problems = verify_scope("p", before, wider, {A: ["s3:GetObject"]}, {B: []})
    assert not any(p.startswith("still granted") for p in problems)
    assert verify_scope("p", before, before, {A: ["s3:GetObject"]}, {B: []})[0].startswith("still granted")
    narrowed = [doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": [A]})]
    assert verify_scope("p", before, narrowed, {}, {B: []})[0].startswith("changed")


def test_cloudtrail_denials_are_counted_per_principal_and_resource_never_as_use():
    role = "arn:aws:iam::1:role/r"

    def event(name, code=None, bucket="arn:aws:s3:::x"):
        record = {
            "eventSource": "s3.amazonaws.com",
            "eventName": name,
            "eventTime": (NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "userIdentity": {"type": "AssumedRole", "sessionContext": {"sessionIssuer": {"arn": role}}},
            "requestParameters": {"bucketName": "x"},
            "resources": [{"type": "AWS::S3::Bucket", "ARN": bucket}],
        }
        if code:
            record["errorCode"] = code
        return record

    result = normalize_export(
        [event("GetObject", "AccessDenied"), event("GetObject", "AccessDenied"), event("PutObject")],
        NOW - timedelta(days=1),
        NOW,
    )
    assert result.denied == 2 and result.matched == 1
    assert result.denied_access == {
        (role, "arn:aws:s3:::x", "s3", "AccessDenied"): [
            NOW - timedelta(hours=1),
            NOW - timedelta(hours=1),
            2,
        ]
    }
    assert all("x" not in key[1] or key[2] == "write" for key in result.access)  # denied never use
    assert result.stats()["denied_pairs"] == 1


# ---------------------------------------------------------------------------
# GitOps multi-file reviews and reverts (local fake provider)

TENANT_KEY = "b" * 16


def files_v1():
    return [
        FileChange("role-1/inline-a.json", render(doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": [B]}))),
        FileChange("role-1/ZeroGraphDisable.json", render(DENY_ALL)),
    ]  # fmt: skip


@pytest.mark.parametrize("provider", ["github", "gitlab"])
def test_change_then_revert_restores_original_bytes(provider):
    repo = fake_git.FakeRepository(provider)
    change_id = str(uuid4())
    client = lambda: GitOpsClient(fake_git.settings(provider), repo.transport())  # noqa: E731
    first = client().open_change(change_id, TENANT_KEY, files_v1(), "t", "body")
    writes = len(repo.writes)
    assert client().open_change(change_id, TENANT_KEY, files_v1(), "t", "body") == first
    assert len(repo.writes) == writes  # retry reuses everything
    assert repo.review(1)["draft"] and not repo.review(1)["_merged"]
    root = f"security/zerograph/{TENANT_KEY}/{change_id}"
    assert repo.file(root + "/role-1/inline-a.json") is None  # nothing reaches the base until a person merges
    repo.merge(1)
    original = render(doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": [A, B]}))
    revert = [
        FileChange("role-1/inline-a.json", original, expected=files_v1()[0].content),
        FileChange("role-1/ZeroGraphDisable.json", None, expected=files_v1()[1].content),
    ]
    pr = client().open_change(change_id, TENANT_KEY, revert, "revert", "body", purpose="revert")
    assert (
        pr.branch.endswith("-revert")
        and client().open_change(change_id, TENANT_KEY, revert, "revert", "body", purpose="revert") == pr
    )
    repo.merge(2)
    assert repo.file(root + "/role-1/inline-a.json") == original.encode()
    assert repo.file(root + "/role-1/ZeroGraphDisable.json") is None


@pytest.mark.parametrize("provider", ["github", "gitlab"])
def test_revert_refuses_a_file_changed_after_merge_and_spoofed_markers(provider):
    repo = fake_git.FakeRepository(provider)
    change_id = str(uuid4())
    client = lambda: GitOpsClient(fake_git.settings(provider), repo.transport())  # noqa: E731
    client().open_change(change_id, TENANT_KEY, files_v1(), "t", "<!-- zerograph:fake --> body")
    assert "&lt;!-- zerograph:fake" in repo.review(1)["body"]
    repo.merge(1)
    path = f"security/zerograph/{TENANT_KEY}/{change_id}/role-1/inline-a.json"
    repo.branches["main"]["tree"][path] = b"edited by a person\n"
    writes = len(repo.writes)
    revert = [FileChange("role-1/inline-a.json", "{}\n", expected=files_v1()[0].content)]
    with pytest.raises(GitOpsConflict, match="changed since"):
        client().open_change(change_id, TENANT_KEY, revert, "r", "b", purpose="revert")
    assert (
        len([w for w in repo.writes[writes:] if "/contents/" in w.url.path or "/files/" in w.url.path]) == 0
    )


def revert_of(files, original):
    """The revert of ``files_v1()``-style changes: rewrites restore ``original``, adds are removed."""
    return [
        FileChange(f.path, original if "Disable" not in f.path else None, expected=f.content) for f in files
    ]


def file_writes(repo, since=0):
    return [w for w in repo.writes[since:] if "/contents/" in w.url.path or "/files/" in w.url.path]


@pytest.mark.parametrize("provider", ["github", "gitlab"])
@pytest.mark.parametrize(
    "files",
    [
        pytest.param(lambda: files_v1()[:1], id="single-rewrite"),
        pytest.param(lambda: files_v1()[1:], id="disable-only"),
        pytest.param(files_v1, id="multi-file"),
    ],
)
def test_revert_refuses_a_change_that_is_not_on_the_base_branch(provider, files):
    """The change's review was never merged: the base lacks every file it wrote. The revert is a
    conflict, writes nothing and leaves no branch or review behind (no new original file)."""
    repo = fake_git.FakeRepository(provider)
    change_id = str(uuid4())
    client = lambda: GitOpsClient(fake_git.settings(provider), repo.transport())  # noqa: E731
    client().open_change(change_id, TENANT_KEY, files(), "t", "body")
    assert not repo.review(1)["_merged"]
    writes, branches, main = len(repo.writes), set(repo.branches), dict(repo.branches["main"]["tree"])
    original = render(doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": [A, B]}))
    for _ in range(2):  # a retry is refused the same way
        with pytest.raises(GitOpsConflict, match="not on the base branch"):
            client().open_change(
                change_id, TENANT_KEY, revert_of(files(), original), "r", "b", purpose="revert"
            )
    assert repo.writes[writes:] == [] and set(repo.branches) == branches and len(repo.reviews) == 1
    assert repo.branches["main"]["tree"] == main
    # Once a person merges the change, the same revert opens and restores the original.
    repo.merge(1)
    pr = client().open_change(change_id, TENANT_KEY, revert_of(files(), original), "r", "b", purpose="revert")
    assert pr.branch.endswith("-revert") and len(repo.reviews) == 2
    repo.merge(2)
    root = f"security/zerograph/{TENANT_KEY}/{change_id}"
    for item in revert_of(files(), original):
        restored = repo.file(f"{root}/{item.path}")
        assert restored == (item.content.encode() if item.content is not None else None)


@pytest.mark.parametrize("provider", ["github", "gitlab"])
def test_revert_with_one_of_two_files_missing_writes_nothing(provider):
    repo = fake_git.FakeRepository(provider)
    change_id = str(uuid4())
    client = lambda: GitOpsClient(fake_git.settings(provider), repo.transport())  # noqa: E731
    client().open_change(change_id, TENANT_KEY, files_v1(), "t", "body")
    repo.merge(1)
    root = f"security/zerograph/{TENANT_KEY}/{change_id}"
    original = render(doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": [A, B]}))
    revert = revert_of(files_v1(), original)
    for missing in (revert[0].path, revert[1].path):
        repo.merge(1)  # restore both files on the base
        del repo.branches["main"]["tree"][f"{root}/{missing}"]
        writes, branches = len(repo.writes), set(repo.branches)
        with pytest.raises(GitOpsConflict, match="not on the base branch"):
            client().open_change(change_id, TENANT_KEY, revert, "r", "b", purpose="revert")
        assert repo.writes[writes:] == [] and set(repo.branches) == branches and len(repo.reviews) == 1
    # A base already holding the restored original (reverted elsewhere) is refused too.
    repo.merge(1)
    repo.branches["main"]["tree"][f"{root}/{revert[0].path}"] = original.encode()
    with pytest.raises(GitOpsConflict, match="not on the base branch"):
        client().open_change(change_id, TENANT_KEY, revert, "r", "b", purpose="revert")


@pytest.mark.parametrize("provider", ["github", "gitlab"])
def test_revert_branch_changed_on_one_file_writes_nothing(provider):
    """The revert branch exists (an interrupted earlier attempt) and one of its files no longer
    holds what the change wrote: every file is checked before any write, so none is written."""
    repo = fake_git.FakeRepository(provider)
    change_id = str(uuid4())
    client = lambda: GitOpsClient(fake_git.settings(provider), repo.transport())  # noqa: E731
    client().open_change(change_id, TENANT_KEY, files_v1(), "t", "body")
    repo.merge(1)
    branch = f"zerograph/{TENANT_KEY}/{change_id}-revert"
    repo.fork(branch)
    root = f"security/zerograph/{TENANT_KEY}/{change_id}"
    repo.branches[branch]["tree"][f"{root}/role-1/ZeroGraphDisable.json"] = b"edited\n"
    original = render(doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": [A, B]}))
    writes = len(repo.writes)
    with pytest.raises(GitOpsConflict, match="changed since"):
        client().open_change(
            change_id, TENANT_KEY, revert_of(files_v1(), original), "r", "b", purpose="revert"
        )
    assert file_writes(repo, writes) == [] and len(repo.reviews) == 1
    assert repo.branches[branch]["tree"][f"{root}/role-1/inline-a.json"] == files_v1()[0].content.encode()


@pytest.mark.parametrize("provider", ["github", "gitlab"])
def test_review_merged_is_a_single_read(provider):
    import httpx

    repo = fake_git.FakeRepository(provider)
    change_id = str(uuid4())
    client = lambda: GitOpsClient(fake_git.settings(provider), repo.transport())  # noqa: E731
    assert client().review_merged(change_id, TENANT_KEY) is None
    client().open_change(change_id, TENANT_KEY, files_v1(), "t", "body")
    writes = len(repo.writes)
    assert client().review_merged(change_id, TENANT_KEY) is False
    repo.merge(1)
    assert client().review_merged(change_id, TENANT_KEY) is True
    assert len(repo.writes) == writes

    def failing(_request):
        return httpx.Response(500, json={"message": "secret-token-value"})

    with pytest.raises(GitOpsError) as error:
        GitOpsClient(fake_git.settings(provider), httpx.MockTransport(failing)).review_merged(
            change_id, TENANT_KEY
        )
    assert "secret" not in str(error.value)


@pytest.mark.parametrize("provider", ["github", "gitlab"])
def test_a_person_editing_a_file_between_read_and_write_keeps_their_edit(provider):
    """Compare-and-swap is what protects a concurrent edit: the client writes with the blob SHA
    (GitHub) or last commit (GitLab) it just read, so an edit landing between that read and the
    write is refused by the provider, kept, and reported as a conflict."""
    repo = fake_git.FakeRepository(provider)
    change_id = str(uuid4())
    client = lambda: GitOpsClient(fake_git.settings(provider), repo.transport())  # noqa: E731
    client().open_change(change_id, TENANT_KEY, files_v1()[:1], "t", "body")
    repo.merge(1)
    path = f"security/zerograph/{TENANT_KEY}/{change_id}/role-1/inline-a.json"
    edited = []

    def person(request):
        if (
            not edited
            and request.method == "PUT"
            and ("/contents/" in request.url.path or "/files/" in request.url.path)
        ):
            branch = json.loads(request.content)["branch"]
            repo._set(branch, path, b"edited by a person\n")
            edited.append(branch)

    repo.before_write = person
    original = render(doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": [A, B]}))
    with pytest.raises(GitOpsConflict, match="existing content was preserved"):
        client().open_change(
            change_id, TENANT_KEY, revert_of(files_v1()[:1], original), "r", "b", purpose="revert"
        )
    assert edited and repo.file(path, edited[0]) == b"edited by a person\n"
    assert len(repo.reviews) == 1  # no revert review over a branch it could not write


def test_fake_gitlab_compare_and_swap_matches_the_live_contract():
    """Pins what GitLab CE 19.4 did in the live qualification: ``last_commit_id`` is checked by
    the file's content at that commit; an absent file at that commit or an unknown commit skips
    the check (so the client must send the last commit it read; tests/fake_git.py asserts it)."""
    import httpx

    repo = fake_git.FakeRepository("gitlab")
    http = httpx.Client(
        transport=repo.transport(),
        base_url="https://gitlab.com/api/v4/projects/acme%2Fpolicies",
        headers={"Authorization": "Bearer secret-token-value"},
    )
    repo.fork("probe")
    base = repo.branches["main"]["head"]

    def post(name, content):
        return http.post(
            f"/repository/files/{name}",
            json={"branch": "probe", "content": content, "commit_message": "m"},
        ).status_code

    def put(name, content, commit):
        return http.put(
            f"/repository/files/{name}",
            json={"branch": "probe", "content": content, "commit_message": "m", "last_commit_id": commit},
        ).status_code

    assert post("c.json", "c1") == 201
    k1 = repo.branches["probe"]["head"]
    assert post("d.json", "d1") == 201
    k2 = repo.branches["probe"]["head"]
    assert put("c.json", "c2", k2) == 200  # not c's last commit, same content there: accepted
    assert put("c.json", "c3", k1) == 400  # c changed since k1: refused
    assert put("c.json", "c4", "0" * 40) == 200  # unknown commit: no check
    assert put("d.json", "d2", base) == 200  # d absent at that commit: no check
    assert repo.last_commit("c.json", "probe") != k1
    # After a merge, a merged file's last commit is the branch commit that changed it.
    repo.reviews.append(
        {"number": 1, "_branch": "probe", "_merged": False, "draft": True, "title": "t", "body": ""}
    )
    repo.merge(1)
    merged_last = repo.last_commit("c.json")
    assert merged_last == repo.branches["probe"]["last"]["c.json"] != repo.branches["main"]["head"]
    with pytest.raises(AssertionError, match="last_commit_id"):
        http.put("/repository/files/c.json", json={"branch": "probe", "content": "x", "commit_message": "m"})


@pytest.mark.parametrize(
    "files,purpose",
    [
        ([FileChange("../escape.json", "{}")], "change"),
        ([FileChange(".github/workflows/x.json", "{}")], "change"),
        ([FileChange("a.yaml", "{}")], "change"),
        ([FileChange("a.json", None)], "change"),
        ([FileChange("a.json", "{}")], "revert"),
        ([], "change"),
        ([FileChange(f"f{i}.json", "{}") for i in range(41)], "change"),
    ],
)
def test_change_scope_rejects_unsafe_files(files, purpose):
    remote = fake_git.FakeRepository()
    client = GitOpsClient(fake_git.settings(), remote.transport())
    with pytest.raises(GitOpsError):
        client.change_scope(str(uuid4()), TENANT_KEY, files, purpose)
    with pytest.raises(GitOpsError):
        GitOpsClient(fake_git.settings(), remote.transport()).open_change(
            str(uuid4()), TENANT_KEY, files, "t", "b", purpose
        )
    assert not remote.requests


def test_provider_errors_never_expose_the_token():
    import httpx

    def handler(_request):
        return httpx.Response(401, json={"message": "secret-token-value"})

    with pytest.raises(GitOpsError) as error:
        GitOpsClient(fake_git.settings(), httpx.MockTransport(handler)).open_change(
            str(uuid4()), TENANT_KEY, files_v1(), "t", "b"
        )
    assert "secret" not in str(error.value)


# ---------------------------------------------------------------------------
# Pull request text

# "47.9% -> 47.9%" or "0 -> 0": a before/after pair that reads as no change.
IDENTICAL = re.compile(r"(?<![\w.])(\d+(?:\.\d+)?%?) -> \1(?![\w.])")


def side(granted, needed):
    return {
        "granted_weight": granted,
        "needed_weight": needed,
        "epi": round(1 - needed / granted, 6),
        "epi_excl_hubs": round(1 - needed / granted, 6),
    }


def live_summary(legacy=False):
    """The live 1-grant canary (graph-wide roles 47.9% -> 47.9%, risk 0 -> 0)."""
    epi = {
        "graph": {
            "roles": {"rows": 900, "before": side(1_000_000, 521_000), "after": side(999_920, 521_000)},
            "identities": {"rows": 5000, "before": side(2_000_000, 34_000), "after": side(1_999_000, 34_000)},
        },
        "counts": {"grants_removed": 1, "restricted_grants_removed": 1, "disabled_nodes": 0},
        "applied": {"remove_grant": 1},
    }
    if not legacy:
        epi["counts"].update(roles_with_less_access=1, identities_with_less_access=3)
        epi["affected"] = {
            "roles": {"rows": 1, "before": side(800, 300), "after": side(720, 300)},
            "identities": {"rows": 3, "before": side(3000, 900), "after": side(2990, 900)},
        }
        epi["principals"] = [
            {"id": "cloudrole:0000086", "name": "role-00086 | <!-- x -->", "kind": "roles",
             "basis": "used", "disabled": False, "epi_before": 0.625, "epi_after": 0.583333},
            {"id": "cloudrole:0000087", "name": "role-00087", "kind": "roles", "basis": "none",
             "disabled": False, "epi_before": None, "epi_after": None},
        ]  # fmt: skip
    return {
        "revision": "r1",
        "proposals": [],
        "proposal_count": 1,
        "evidence": {"status": "attested"},
        "epi": epi,
        "simulation": {
            "risk_before": 0, "risk_after": 0, "assets_before": 7, "assets_after": 6, "assets_removed": 1,
            **({} if legacy else {"exposure_before": 0.0021, "exposure_after": 0.0019}),
        },  # fmt: skip
    }


def test_pr_body_leads_with_the_changes_own_impact_and_never_shows_identical_pairs():
    change = RolloutChange(
        id="a3c0d99f-0abe-4944-80bc-f9816143d50c", scope="role", subject_name="role-00086",
        revision="r1", files=[], summary=live_summary(), pr_url="https://example.test/pull/1",
    )  # fmt: skip
    body = rollout.pr_body(change, "canary", "k", "security/zerograph")
    impact = body[body.index("### Impact of this change") : body.index("### Simulation")]
    lines = impact.splitlines()
    assert lines[2] == "- Grants removed: 1 (1 on restricted data); principals disabled: 0."
    assert lines[3] == "- `role-00086 \\| &lt;!-- x -->` excess privilege: 62.50% -> 58.33% (-4.17 pp)."
    assert lines[4] == "- `role-00087`: excess privilege not measured (no usage evidence for this principal)."
    assert "- Roles with less access: 1; identities with less access: 3." in lines
    assert "- Excess privilege of those identities (3 with usage evidence): 70.00% -> 69.90% (-0.10 pp)." in lines
    assert not any("of those roles" in line for line in lines)  # the principal's own line says it
    # Graph-wide shares come after, with a delta instead of "47.9% -> 47.9%".
    assert impact.index("Graph-wide") > impact.index("identities with less access")
    assert "- All roles: 47.90% before, -0.004 pp after this change." in lines
    assert "- All identities: 98.30% before, -0.001 pp after this change." in lines
    simulation = body[body.index("### Simulation") : body.index("### Canary plan")]
    assert "- Reachable data assets: 7 -> 6 (1 no longer reachable)." in simulation
    assert "0.21% -> 0.19% (-0.02 pp)" in simulation
    assert "Risk score (0-100, relative to the whole graph, rounded) stays 0:" in simulation
    assert not IDENTICAL.search(body), IDENTICAL.search(body)
    assert "<!--" not in body.replace("&lt;!--", "")

    restored = rollout.revert_body(change, "AccessDenied")
    section = restored[restored.index("### What the revert restores") :]
    assert "- Grants restored: 1 (1 on restricted data); principals re-enabled: 0." in section
    assert "excess privilege returns: 58.33% -> 62.50% (+4.17 pp)." in section
    assert "- Access returns to 1 role(s) and 3 identity(ies)." in section
    assert "- Reachable data assets of the principal: 6 -> 7 (1 reachable again)." in section
    assert not IDENTICAL.search(restored)


def test_pr_body_of_a_change_stored_before_per_principal_impact():
    change = RolloutChange(
        id="b3c0d99f-0abe-4944-80bc-f9816143d50c", scope="role", subject_name="role-00086",
        revision="r1", files=[], summary=live_summary(legacy=True), pr_url="",
    )  # fmt: skip
    body = rollout.pr_body(change, "canary", "k", "security/zerograph")
    assert "- Grants removed: 1 (1 on restricted data); principals disabled: 0." in body
    assert "- All roles: 47.90% before, -0.004 pp after this change." in body
    assert "Sensitivity-weighted" not in body and "stays 0:" in body
    assert not IDENTICAL.search(body)
    assert "- Grants restored: 1 (1 on restricted data)" in rollout.revert_body(change, "r")
    assert rollout._shift(0.5, 0.5) == "unchanged at 50.00%"
    assert rollout._shift(0.5, 0.4999999) == "50.00% before, -<0.0001 pp after this change"
    assert rollout._shift(None, 0.5) == "n/a before, 50.00% after"


# ---------------------------------------------------------------------------
# API end to end (in-memory graph, SQLite, local fake provider)


@pytest.fixture
def repo(client, monkeypatch):
    from app.api import routes

    found = fake_git.FakeRepository()
    config = fake_git.settings()
    monkeypatch.setattr(routes, "get_settings", lambda: config)
    real = routes.GitOpsClient
    monkeypatch.setattr(routes, "GitOpsClient", lambda settings: real(settings, found.transport()))
    return found


def publish(client, snapshot):
    from test_proposals import publish as publish_snapshot

    publish_snapshot(client, snapshot)


def planted_environment(client, size=2000):
    from test_privilege import upload_usage

    from app.graph.topics import backfill_missing

    snapshot, truth, usage = generate_topics(size, seed=11)
    planted = plant_role_policies(snapshot, truth)
    assert planted > 0
    publish(client, snapshot)
    upload_usage(client, snapshot, usage)
    backfill_missing()
    return snapshot, truth, usage


def high_by_subject(client):
    rows = []
    cursor = None
    while True:
        params = {"tier": "high", "limit": 200}
        if cursor is not None:
            params["cursor"] = cursor
        page = client.get("/api/v1/proposals", params=params).json()
        rows += page["proposals"]
        cursor = page["view"]["next_cursor"]
        if cursor is None:
            break
    found: dict[str, list[dict]] = {}
    for row in rows:
        found.setdefault(row["subject_id"], []).append(row)
    return rows, found


def accept(client, proposals):
    for proposal in proposals:
        assert (
            client.post(
                f"/api/v1/proposals/{proposal['id']}/decision", json={"state": "accepted"}
            ).status_code
            == 200
        )


def denied_upload(client, events):
    end = NOW
    created = client.post(
        "/api/v1/usage/uploads",
        json={
            "window_start": (end - timedelta(days=2)).isoformat(),
            "window_end": end.isoformat(),
            "attested_services": ["s3"],
        },
    ).json()
    for number, body in enumerate(cloudtrail_files(events, 1000)):
        assert (
            client.put(f"/api/v1/usage/uploads/{created['id']}/files/{number}", content=body).status_code
            == 200
        )
    return client.post(f"/api/v1/usage/uploads/{created['id']}/commit").json()


def denial(role, bucket, when):
    return {
        "eventVersion": "1.09",
        "eventSource": "s3.amazonaws.com",
        "eventName": "GetObject",
        "eventTime": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "awsRegion": "us-east-1",
        "userIdentity": {
            "type": "AssumedRole",
            "arn": "arn:aws:sts::123456789012:assumed-role/r/s",
            "sessionContext": {"sessionIssuer": {"type": "Role", "arn": role}},
        },
        "requestParameters": {"bucketName": bucket, "key": "k"},
        "resources": [{"type": "AWS::S3::Bucket", "ARN": bucket}],
        "errorCode": "AccessDenied",
        "errorMessage": "Access Denied",
        "recipientAccountId": "123456789012",
    }


def assert_impact_body(body: str, change: dict) -> None:
    """The change's own impact leads; graph-wide shares are context, never identical pairs."""
    epi = change["epi"]
    impact = body[body.index("### Impact of this change") : body.index("### Simulation")]
    assert impact.index("Grants removed") < impact.index("Graph-wide")
    counts = epi["counts"]
    assert (
        f"- Grants removed: {counts['grants_removed']} ({counts['restricted_grants_removed']} on restricted data)"
        in impact
    )
    assert f"identities with less access: {counts['identities_with_less_access']}" in impact
    (principal,) = epi["principals"]
    assert principal["id"] == change["subject_id"] and principal["epi_before"] > principal["epi_after"]
    assert f"`{change['subject_name']}` excess privilege: " in impact
    assert "pp)" in impact.split("Graph-wide")[0]
    assert epi["affected"]["roles"]["rows"] >= 1 and epi["affected"]["identities"]["rows"] >= 1
    assert "Excess privilege of those identities" in impact
    assert not IDENTICAL.search(body), IDENTICAL.search(body)
    simulation = change["simulation"]
    assert isinstance(simulation["exposure_before"], float)
    assert f"Reachable data assets: {simulation['assets_before']} -> {simulation['assets_after']}" in body


def test_rollout_api_canary_revert_and_access_denied(client, environment, repo):  # noqa: C901
    factory, _ = environment
    snapshot, _, _ = planted_environment(client)
    rows, by_subject = high_by_subject(client)
    removals = {s: [p for p in ps if p["type"] == "remove_grant"] for s, ps in by_subject.items()}
    # Two roles of one topic with removals on buckets (for AccessDenied), one role of another topic.
    kinds = {node.id: node.type.value for node in snapshot.nodes}
    by_topic: dict[str, list[str]] = {}
    for subject, found in sorted(removals.items()):
        if (
            found
            and kinds[subject] == "CloudRole"
            and any(kinds[p["target_id"]] == "S3Bucket" for p in found)
        ):
            by_topic.setdefault(found[0]["topic_id"], []).append(subject)
    topics = sorted(by_topic, key=lambda t: (-len(by_topic[t]), t))
    topic, other = topics[0], topics[1]
    first, second = by_topic[topic][:2]
    third = by_topic[other][0]
    for subject in (first, second, third):
        accept(client, removals[subject])

    # Viewers and analysts cannot create changes; analysts may preview.
    client.app.dependency_overrides[current_actor] = lambda: Actor("v", "tenant-a", frozenset({"viewer"}))
    assert client.post("/api/v1/rollout/changes", json={"subject_id": first}).status_code == 403
    assert client.post("/api/v1/rollout/plan", json={"subject_id": first}).status_code == 403
    assert client.get("/api/v1/rollout").status_code == 200
    client.app.dependency_overrides[current_actor] = lambda: Actor(
        "alice", "tenant-a", frozenset({"admin", "analyst", "viewer"})
    )
    plan = client.post("/api/v1/rollout/plan", json={"subject_id": first}).json()
    assert plan["eligible"] and plan["gate"] == "Becomes the topic's canary"
    assert set(plan["proposal_ids"]) == {p["id"] for p in removals[first]}
    assert all(f["op"] == "rewrite" and f["diff"].count("\n-") >= 1 for f in plan["files"])
    assert (
        client.post("/api/v1/rollout/plan", json={"subject_id": first, "topic_id": topic}).status_code == 422
    )

    created = {}
    for subject in (first, second, third):
        response = client.post("/api/v1/rollout/changes", json={"subject_id": subject})
        assert response.status_code == 201, response.text
        created[subject] = response.json()
        assert created[subject]["state"] == "draft" and created[subject]["simulation"]["assets_removed"] >= 1
    # The same proposals cannot be taken twice.
    assert client.post("/api/v1/rollout/changes", json={"subject_id": first}).status_code == 409
    canary = created[first]["id"]
    opened = client.post(f"/api/v1/rollout/changes/{canary}/pr")
    assert opened.status_code == 200, opened.text
    assert opened.json() == {"url": "https://github.com/acme/policies/pull/1", "state": "pr_open"}
    assert client.post(f"/api/v1/rollout/changes/{canary}/pr").json()["url"] == opened.json()["url"]
    # Non-canary changes of the topic are held until the canary is verified; a bundle too.
    held = client.post(f"/api/v1/rollout/changes/{created[second]['id']}/pr")
    assert held.status_code == 409 and "Waiting for canary" in held.json()["detail"]
    listed = {c["id"]: c for c in client.get("/api/v1/rollout").json()["changes"]}
    assert listed[created[second]["id"]]["held"] and listed[canary]["canary"]
    assert len(repo.reviews) == 1
    body = repo.review(1)["body"]
    for section in (
        "Proposals included",
        "Evidence",
        "Impact of this change",
        "Simulation",
        "Canary plan",
        "Revert",
    ):
        assert f"### {section}" in body
    assert "**canary**" in body and "Nothing is applied by ZeroGraph" in body
    assert_impact_body(body, created[first])

    # Revert of a change whose PR is not merged is refused (close the PR instead).
    assert client.post(f"/api/v1/rollout/changes/{canary}/revert", json={}).status_code == 409
    # A person merges in the repository; the canary watch starts.
    repo.merge(1)
    merged = client.post(f"/api/v1/rollout/changes/{canary}/merged").json()
    assert merged["state"] == "merged" and 6.9 < merged["watch_remaining_days"] <= 7
    assert client.post(f"/api/v1/rollout/changes/{created[second]['id']}/pr").status_code == 409
    with factory() as db:
        change = db.get(RolloutChange, canary)
        change.merged_at = NOW - timedelta(days=8)
        db.commit()
    listed = {c["id"]: c for c in client.get("/api/v1/rollout").json()["changes"]}
    assert listed[canary]["state"] == "verified"
    widened = client.post(f"/api/v1/rollout/changes/{created[second]['id']}/pr")
    assert widened.status_code == 200 and widened.json()["state"] == "pr_open"
    assert "widens the rollout" in repo.review(2)["body"]

    # Byte-for-byte revert of the canary from Remediation.original.
    reverted = client.post(f"/api/v1/rollout/changes/{canary}/revert", json={"reason": "test"})
    assert reverted.status_code == 200 and reverted.json()["state"] == "revert_open"
    revert_review = len(repo.reviews)
    restored = repo.review(revert_review)["body"]
    assert "### What the revert restores" in restored
    assert f"- Grants restored: {created[first]['epi']['counts']['grants_removed']} (" in restored
    assert "excess privilege returns" in restored and "reachable again" in restored
    assert not IDENTICAL.search(restored)
    assert not repo.review(revert_review)["_merged"]
    repo.merge(revert_review)
    with factory() as db:
        change = db.get(RolloutChange, canary)
        revision = change.revision
        for item in change.files:
            record = db.get(Remediation, item["remediation_id"])
            path = f"security/zerograph/{rollout_key()}/{canary}/{item['path']}"
            restored = repo.file(path)
            stored = db.scalar(
                select(RevisionPolicyDocument.document)
                .join(
                    RevisionPolicy,
                    (RevisionPolicy.digest == RevisionPolicyDocument.digest)
                    & (RevisionPolicy.revision == RevisionPolicyDocument.revision),
                )
                .where(
                    RevisionPolicy.revision == revision,
                    RevisionPolicy.principal_id == item["principal"],
                    RevisionPolicy.name == item["policy_name"],
                )
            )
            assert restored == render(record.original).encode()
            assert canonical_policy(json.loads(restored)) == stored  # the stored document, byte for byte
    assert client.post(f"/api/v1/rollout/changes/{canary}/reverted").json()["state"] == "rolled_back"
    # A rolled-back canary no longer counts: the topic's next change becomes its canary.
    assert client.get("/api/v1/rollout").json()["canaries"][topic] is None

    # AccessDenied watch: the other topic's canary is merged, then denials on what it removed.
    other_canary = created[third]["id"]
    assert client.post(f"/api/v1/rollout/changes/{other_canary}/pr").status_code == 200
    repo.merge(len(repo.reviews))
    assert "warning" not in client.post(f"/api/v1/rollout/changes/{other_canary}/merged").json()
    with factory() as db:
        db.get(RolloutChange, other_canary).merged_at = NOW - timedelta(hours=3)
        db.commit()
    touched = created[third]
    bucket = next(
        p["target_id"]
        for p in removals[third]
        if kinds[p["target_id"]] == "S3Bucket" and p["id"] in touched["proposal_ids"]
    )
    untouched = next(n.id for n in snapshot.nodes if n.type.value == "S3Bucket")
    before = len(repo.reviews)
    quiet = denied_upload(
        client,
        [denial(third, bucket, NOW - timedelta(hours=5)), denial(third, untouched, NOW - timedelta(hours=1))]
        if untouched != bucket
        else [denial(third, bucket, NOW - timedelta(hours=5))],
    )
    assert quiet["rollout"] == {"flagged": [], "reverts": []}  # before the merge, or not touched
    noisy = denied_upload(client, [denial(third, bucket, NOW - timedelta(hours=1))] * 2)
    assert noisy["rollout"]["flagged"] == [other_canary]
    assert noisy["rollout"]["reverts"][0]["url"].startswith("https://github.com/acme/policies/pull/")
    assert len(repo.reviews) == before + 1 and not repo.reviews[-1]["_merged"] and repo.reviews[-1]["draft"]
    with factory() as db:
        change = db.get(RolloutChange, other_canary)
        assert change.state == "revert_open" and change.flag["events"] == 2
        assert db.query(AccessDenial).count() >= 3
        events = {
            (e.actor, e.action)
            for e in db.scalars(select(AuditEvent).where(AuditEvent.action.like("rollout.%")))
        }
    assert (rollout.HOOK_ACTOR, "rollout.flagged") in events
    assert (rollout.HOOK_ACTOR, "rollout.revert_opened") in events
    for action in ("rollout.created", "rollout.pr_requested", "rollout.pr_opened", "rollout.merged",
                   "rollout.verified", "rollout.revert_requested", "rollout.rolled_back"):  # fmt: skip
        assert action in {a for _, a in events}
    # Never merged, closed or force-pushed by ZeroGraph; never wrote to the base branch.
    assert all(not r.url.path.endswith("/merge") for r in repo.requests)
    # The legacy single-policy PR route refuses rollout remediations.
    with factory() as db:
        record_id = db.get(RolloutChange, other_canary).remediation_ids[0]
    assert client.post(f"/api/v1/remediations/{record_id}/pr").status_code == 409


def test_revert_of_a_change_not_on_the_base_branch_is_refused(client, environment, repo):
    """"Mark merged" was recorded but the pull request was never merged in the repository. A
    revert (by hand or by the AccessDenied watch) is a conflict: nothing is written, no branch
    or review is created, and the change returns to merged with the error shown and audited."""
    factory, _ = environment
    snapshot, _, _ = planted_environment(client)
    rows, by_subject = high_by_subject(client)
    kinds = {node.id: node.type.value for node in snapshot.nodes}
    subject, removals = next(
        (s, [p for p in ps if p["type"] == "remove_grant"])
        for s, ps in sorted(by_subject.items())
        if kinds[s] == "CloudRole"
        and any(p["type"] == "remove_grant" and kinds[p["target_id"]] == "S3Bucket" for p in ps)
    )
    accept(client, removals)
    created = client.post("/api/v1/rollout/changes", json={"subject_id": subject})
    assert created.status_code == 201, created.text
    change_id = created.json()["id"]
    assert client.post(f"/api/v1/rollout/changes/{change_id}/pr").status_code == 200
    reads = len(repo.requests)
    marked = client.post(f"/api/v1/rollout/changes/{change_id}/merged").json()
    # Recorded anyway, with a warning from one read-only look at the provider.
    assert marked["state"] == "merged" and "does not show this pull request as merged" in marked["warning"]
    assert [r.method for r in repo.requests[reads:]] == ["GET"]
    branches, main = set(repo.branches), dict(repo.branches["main"]["tree"])
    writes = len(repo.writes)

    refused = client.post(f"/api/v1/rollout/changes/{change_id}/revert", json={"reason": "test"})
    assert refused.status_code == 409 and "not on the base branch" in refused.json()["detail"]
    shown = client.get(f"/api/v1/rollout/changes/{change_id}").json()
    assert shown["state"] == "merged" and not shown["revert_requested"] and not shown["revert_pr_url"]
    assert "not on the base branch" in shown["revert_error"]

    # The AccessDenied watch flags the change and records the same refusal.
    with factory() as db:
        db.get(RolloutChange, change_id).merged_at = NOW - timedelta(hours=3)
        db.commit()
    bucket = next(p["target_id"] for p in removals if kinds[p["target_id"]] == "S3Bucket")
    noisy = denied_upload(client, [denial(subject, bucket, NOW - timedelta(hours=1))])
    assert noisy["rollout"]["flagged"] == [change_id]
    assert "not on the base branch" in noisy["rollout"]["reverts"][0]["error"]
    assert "url" not in noisy["rollout"]["reverts"][0]
    shown = client.get(f"/api/v1/rollout/changes/{change_id}").json()
    assert shown["state"] == "merged" and shown["flag"]["events"] == 1 and shown["flagged_at"]
    assert "not on the base branch" in shown["revert_error"] and not shown["revert_requested"]
    # Nothing was written to the repository and no revert branch or review exists.
    assert repo.writes[writes:] == [] and set(repo.branches) == branches and len(repo.reviews) == 1
    assert repo.branches["main"]["tree"] == main
    with factory() as db:
        failed = [
            e
            for e in db.scalars(select(AuditEvent).where(AuditEvent.action == "rollout.revert_failed"))
        ]
    assert [(e.actor, e.detail["automatic"], e.detail["state"]) for e in failed] == [
        ("alice", False, "merged"),
        (rollout.HOOK_ACTOR, True, "merged"),
    ]
    # A flagged change is not verified when its window passes; it keeps holding its topic.
    with factory() as db:
        db.get(RolloutChange, change_id).merged_at = NOW - timedelta(days=8)
        db.commit()
    assert {c["id"]: c for c in client.get("/api/v1/rollout").json()["changes"]}[change_id]["state"] == "merged"

    # Once a person actually merges it, "Open revert PR" opens the revert and clears the error.
    repo.merge(1)
    opened = client.post(f"/api/v1/rollout/changes/{change_id}/revert", json={})
    assert opened.status_code == 200 and opened.json()["state"] == "revert_open"
    shown = client.get(f"/api/v1/rollout/changes/{change_id}").json()
    assert shown["revert_pr_url"] and shown["revert_error"] is None and shown["revert_requested"]


def rollout_key():
    import hashlib

    return hashlib.sha256(b"tenant-a").hexdigest()[:16]


def test_drafts_disables_bundles_and_discard(client, environment, repo):
    factory, _ = environment
    snapshot, _, _ = planted_environment(client)
    rows, by_subject = high_by_subject(client)
    disable = next(r for r in rows if r["type"] == "disable_identity" and r["subject_type"] == "HumanUser")
    accept(client, [disable])
    response = client.post("/api/v1/rollout/changes", json={"subject_id": disable["subject_id"]})
    assert response.status_code == 201, response.text
    change = response.json()
    assert [f["op"] for f in change["files"]] == ["add"] and change["files"][0][
        "policy_name"
    ] == "ZeroGraphDisable"
    with factory() as db:
        record = db.get(Remediation, change["files"][0]["remediation_id"])
        assert record.original == {} and record.optimized == DENY_ALL and record.status == "rollout"
    # Manual and structural proposals are draft only, with a reason and text.
    manual = client.get("/api/v1/proposals", params={"tier": "manual", "limit": 50}).json()["proposals"]
    merge = next(p for p in manual if p["type"] == "merge_roles")
    draft = client.get(f"/api/v1/proposals/{merge['id']}/draft").json()
    assert not draft["pr_eligible"] and "Merge role" in draft["text"] and "never delete" in draft["text"]
    eligible = client.get(f"/api/v1/proposals/{disable['id']}/draft").json()
    assert eligible["pr_eligible"] and eligible["change_id"] == change["id"]
    accept(client, [merge])
    assert client.post("/api/v1/rollout/changes", json={"subject_id": merge["subject_id"]}).status_code == 409
    # A topic bundle waits for a verified single-role canary.
    topic = disable["topic_id"]
    accept(client, [r for r in rows if r["topic_id"] == topic and r["type"] == "remove_grant"][:30])
    bundle = client.post("/api/v1/rollout/changes", json={"topic_id": topic})
    assert bundle.status_code == 201, bundle.text
    assert bundle.json()["scope"] == "topic" and len(bundle.json()["principals"]) >= 2
    refused = client.post(f"/api/v1/rollout/changes/{bundle.json()['id']}/pr")
    assert refused.status_code == 409
    # Discard frees the proposals and removes the remediation records.
    assert client.delete(f"/api/v1/rollout/changes/{bundle.json()['id']}").status_code == 204
    with factory() as db:
        assert db.get(RolloutChange, bundle.json()["id"]) is None
    assert client.post("/api/v1/rollout/changes", json={"topic_id": topic}).status_code == 201
    # GitOps not configured for this tenant: 403, nothing sent.
    from app.api import routes

    config = fake_git.settings(tenant="someone-else")
    routes.get_settings = lambda: config  # restored by monkeypatch teardown of the repo fixture
    assert client.post(f"/api/v1/rollout/changes/{change['id']}/pr").status_code == 403
    assert not repo.writes


def test_diff_correctness_and_reingest_round_trip(client, environment):
    """Every accepted eligible high-tier proposal: the generated diffs re-evaluate to exactly the
    target grants, and re-ingesting the applied snapshot reproduces the what-if graph."""
    factory, _ = environment
    snapshot, _, _ = planted_environment(client)
    rows, by_subject = high_by_subject(client)
    eligible = [r for r in rows if r["type"] in ("remove_grant", "disable_role", "disable_identity")]
    accept(client, eligible)
    with factory() as db:
        revision = db.get(TenantState, "tenant-a").revision
        model = P.load_model(db, "tenant-a", revision)
        files, optimized, included, drafts = [], {}, [], []
        for subject in sorted({r["subject_id"] for r in eligible}):
            plan = rollout.plan_change(db, "tenant-a", revision, model, subject=subject)
            for planned in plan.files:
                item = planned.as_dict()
                item["path"] = f"{subject}/{item['path']}"
                files.append(item)
                optimized[item["path"]] = planned.optimized
            included += plan.included
            drafts += plan.drafts
    removed: dict[str, set[str]] = {}
    disabled = set()
    for row in included:
        if row.type in rollout.DISABLE_TYPES:
            disabled.add(row.subject_id)
        else:
            removed.setdefault(row.subject_id, set()).add(row.target_id)
    assert len(included) >= 300 and sum(len(v) for v in removed.values()) >= 200 and disabled
    probes = [n.id for n in snapshot.nodes if n.type.value in ("S3Bucket", "Database", "VectorStore")][:25]
    stats = verify_diffs(snapshot, files, optimized, removed, disabled, probes)
    assert stats["mismatches"] == [] and stats["widened"] == []
    assert stats["removed_edges"] >= sum(len(v) for v in removed.values())
    expected = expected_after(model, [row.ordinal for row in included])
    publish(client, round_trip(snapshot, files, optimized))
    with factory() as db:
        later = db.get(TenantState, "tenant-a").revision
        assert later != revision
        after = actual_after(P.load_model(db, "tenant-a", later))
    assert after[0] == expected[0]
    assert set(after[1]) == set(expected[1]) and all(after[1][k] == expected[1][k] for k in expected[1])


@pytest.fixture
def rollout_postgres(monkeypatch):
    import os

    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    from app.api import routes
    from app.db.models import Base

    url = os.getenv("ZG_INGESTION_POSTGRES_URL")
    if not url:
        pytest.skip("No disposable PostgreSQL integration database configured")
    namespace = "zg_rollout_" + uuid4().hex
    admin = create_engine(url)
    with admin.begin() as db:
        db.execute(text(f'CREATE SCHEMA "{namespace}"'))
    engine = create_engine(url, connect_args={"options": f"-csearch_path={namespace}"}, pool_size=10)
    factory = sessionmaker(engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    config = fake_git.settings()
    monkeypatch.setattr(routes, "get_settings", lambda: config)
    try:
        yield factory
    finally:
        engine.dispose()
        with admin.begin() as db:
            db.execute(text(f'DROP SCHEMA "{namespace}" CASCADE'))
        admin.dispose()


def test_postgres_concurrent_pr_opens_elect_exactly_one_canary(rollout_postgres, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from fastapi import HTTPException

    from app.api import routes
    from app.remediation.gitops_sync import PullRequest

    factory = rollout_postgres
    ids = [str(uuid4()) for _ in range(4)]
    with factory() as db:
        db.add(TenantState(tenant_id="tenant-a", revision="r1"))
        for number, change_id in enumerate(ids):
            record = Remediation(
                id=str(uuid4()),
                tenant_id="tenant-a",
                actor="t",
                status="rollout",
                identity_id=f"role:{number}",
                original=doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": [A, B]}),
                optimized=doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": [B]}),
                evidence={"rollout_id": change_id},
            )
            db.add(record)
            db.add(
                RolloutChange(
                    id=change_id,
                    tenant_id="tenant-a",
                    scope="role",
                    topic_id="t1",
                    subject_id=f"role:{number}",
                    subject_name=f"role {number}",
                    proposal_ids=[f"p{number}"],
                    state="draft",
                    canary=False,
                    revision="r1",
                    remediation_ids=[record.id],
                    files=[
                        {
                            "path": f"role-{number}/inline-a.json",
                            "op": "rewrite",
                            "principal": f"role:{number}",
                            "policy_name": "a",
                            "remediation_id": record.id,
                        }
                    ],
                    summary={"proposal_count": 1},
                    watch_days=7,
                    actor="t",
                    created_at=NOW,
                    updated_at=NOW,
                )
            )
        db.commit()
    barrier = Barrier(len(ids))

    class Client:
        def __init__(self, settings):
            self.real = GitOpsClient(settings, fake_git.FakeRepository().transport())

        def change_scope(self, *args):
            return self.real.change_scope(*args)

        def close(self):
            self.real.close()

        def open_change(self, change_id, *args, **kwargs):
            return PullRequest(f"https://github.com/acme/policies/pull/{ids.index(change_id) + 1}", "b")

    monkeypatch.setattr(routes, "GitOpsClient", Client)
    actor = Actor("alice", "tenant-a", frozenset({"admin"}))

    def request(change_id):
        barrier.wait(5)
        with factory() as db:
            try:
                return routes.open_rollout_pr(change_id, db, None, actor)["state"]
            except HTTPException as exc:
                return exc.status_code

    with ThreadPoolExecutor(max_workers=len(ids)) as pool:
        results = list(pool.map(request, ids))
    assert sorted(results, key=str) == [409, 409, 409, "pr_open"]
    with factory() as db:
        canaries = db.scalars(select(RolloutChange).where(RolloutChange.canary.is_(True))).all()
        assert len(canaries) == 1 and canaries[0].state == "pr_open"


# ---------------------------------------------------------------------------
# Self-managed GitLab (ZG_GIT_GITLAB_URL)


@pytest.mark.parametrize(
    "instance",
    ["https://git.example.com:8443/gitlab", "https://git.example.com", "http://127.0.0.1:18929"],
)
def test_self_managed_gitlab_change_revert_and_merge_check(instance):
    """The whole flow against a self-managed instance: API under the instance (and its relative
    root), review URLs on the instance, the merge check, and the revert after a person merges."""
    repo = fake_git.FakeRepository("gitlab", gitlab_url=instance)
    change_id = str(uuid4())
    config = fake_git.settings("gitlab", git_gitlab_url=instance + "/")
    client = lambda: GitOpsClient(config, repo.transport())  # noqa: E731
    pr = client().open_change(change_id, TENANT_KEY, files_v1(), "t", "body")
    assert pr.url == f"{instance}/{fake_git.REPOSITORY}/-/merge_requests/1"
    assert client().open_change(change_id, TENANT_KEY, files_v1(), "t", "body") == pr
    assert client().review_merged(change_id, TENANT_KEY) is False
    repo.merge(1)
    assert client().review_merged(change_id, TENANT_KEY) is True
    original = render(doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": [A, B]}))
    revert = client().open_change(
        change_id, TENANT_KEY, revert_of(files_v1(), original), "r", "b", purpose="revert"
    )
    assert revert.url == f"{instance}/{fake_git.REPOSITORY}/-/merge_requests/2"
    assert all(str(r.url).startswith(f"{instance}/api/v4/projects/") for r in repo.requests)


def test_review_url_on_another_host_than_the_instance_is_refused():
    repo = fake_git.FakeRepository("gitlab", gitlab_url="https://git.example.com")
    real = repo._review_json
    repo._review_json = lambda review: {
        **real(review),
        "web_url": real(review)["web_url"].replace("git.example.com", "gitlab.com"),
    }
    config = fake_git.settings("gitlab", git_gitlab_url="https://git.example.com")
    with pytest.raises(GitOpsError, match="review URL"):
        GitOpsClient(config, repo.transport()).open_change(str(uuid4()), TENANT_KEY, files_v1(), "t", "body")


@pytest.mark.parametrize(
    "url",
    [
        "http://git.example.com",  # plain HTTP off loopback
        "http://10.0.0.5:8080",
        "ftp://git.example.com",
        "https://user:secret@git.example.com",
        "https://git.example.com/?x=1",
        "https://git.example.com/#x",
        "https://git.example.com/a/../b",
        "https://",
        "https://git.example.com:99999",
        "https://git.example.com/a b",
        "https://git.example.com/" + "a/" * 5,
    ],
)
def test_invalid_gitlab_instance_url_is_refused_before_any_request(url):
    repo = fake_git.FakeRepository("gitlab")
    with pytest.raises(GitOpsError, match="GitLab instance URL"):
        GitOpsClient(fake_git.settings("gitlab", git_gitlab_url=url), repo.transport())
    assert not repo.requests


def test_plain_http_gitlab_is_loopback_only_and_never_in_production():
    from app.remediation.gitops_sync import gitlab_instance

    assert gitlab_instance("http://127.0.0.1:18929", "development") == ("http", "127.0.0.1", 18929, "")
    assert gitlab_instance("http://[::1]:8080/gl/", "test") == ("http", "::1", 8080, "/gl")
    assert gitlab_instance("https://gitlab.com", "production") == ("https", "gitlab.com", 443, "")
    with pytest.raises(GitOpsError):
        gitlab_instance("http://127.0.0.1:18929", "production")
    # GitHub ignores the GitLab instance setting.
    client = GitOpsClient(fake_git.settings("github", git_gitlab_url="http://git.example.com"))
    assert client.api == f"https://api.github.com/repos/{fake_git.REPOSITORY}"
