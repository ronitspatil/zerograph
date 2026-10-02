import base64
import hashlib
import json

import httpx
import pytest

from app.core.config import Settings
from app.remediation.gitops_sync import GitOpsClient, GitOpsConflict, GitOpsError

RID = "11111111-1111-1111-1111-111111111111"
TENANT = "a" * 16
CONTENT = '{"Version":"2012-10-17"}\n'
BRANCH = f"zerograph/{TENANT}/{RID}"
PATH = f"security/zerograph/{TENANT}/{RID}.json"


def settings(provider="github"):
    return Settings(
        environment="test",
        demo_mode=False,
        git_provider=provider,
        git_repository="acme/policies",
        git_token="secret",
    )


class Provider:
    """Stateful documented provider contracts, including accepted-write/lost-response races."""

    def __init__(self, provider, remediation_id=RID, tenant_key=TENANT):
        self.provider, self.requests = provider, []
        self.proposal_branch = f"zerograph/{tenant_key}/{remediation_id}"
        self.proposal_path = f"security/zerograph/{tenant_key}/{remediation_id}.json"
        self.branch, self.head, self.content, self.review = False, "a" * 40, None, None
        self.fail_after = None
        self.conflict_at = None

    @property
    def writes(self):
        return [r for r in self.requests if r.method != "GET"]

    def fault(self, phase, request):
        if self.fail_after == phase:
            self.fail_after = None
            raise httpx.ReadTimeout("SECRET provider body and policy", request=request)
        if self.conflict_at == phase:
            self.conflict_at = None
            return httpx.Response(409, json={"message": "already exists"})
        return None

    def review_data(self, payload):
        if self.provider == "github":
            return {
                "number": 1,
                "state": "open",
                "draft": True,
                "merged_at": None,
                "html_url": "https://github.com/acme/policies/pull/1",
                "head": {
                    "ref": self.proposal_branch,
                    "sha": self.head,
                    "repo": {"full_name": "acme/policies"},
                },
                "base": {"ref": "main", "repo": {"full_name": "acme/policies"}},
                "body": payload["body"],
            }
        return {
            "iid": 1,
            "state": "opened",
            "draft": True,
            "merged_at": None,
            "web_url": "https://gitlab.com/acme/policies/-/merge_requests/1",
            "source_branch": self.proposal_branch,
            "target_branch": "main",
            "source_project_id": 100,
            "target_project_id": 100,
            "sha": self.head,
            "description": payload["description"],
        }

    def __call__(self, request):
        self.requests.append(request)
        path, method = request.url.path, request.method
        payload = json.loads(request.content) if request.content else {}
        assert request.url.host == ("api.github.com" if self.provider == "github" else "gitlab.com")
        assert "/acme/policies" in path
        if self.provider == "gitlab" and path.endswith("/projects/acme/policies"):
            return httpx.Response(200, json={"id": 100, "path_with_namespace": "acme/policies"})
        if method == "GET" and ("/git/ref/heads/" in path or "/repository/branches/" in path):
            branch = (
                path.split("/heads/", 1)[1] if self.provider == "github" else path.split("/branches/", 1)[1]
            )
            if branch != "main" and not self.branch:
                return httpx.Response(404)
            head = "a" * 40 if branch == "main" else self.head
            return httpx.Response(
                200,
                json={"ref": f"refs/heads/{branch}", "object": {"type": "commit", "sha": head}}
                if self.provider == "github"
                else {"name": branch, "commit": {"id": head}},
            )
        if method == "POST" and path.endswith(("/git/refs", "/repository/branches")):
            assert not self.branch
            assert payload == (
                {"ref": f"refs/heads/{self.proposal_branch}", "sha": "a" * 40}
                if self.provider == "github"
                else {"branch": self.proposal_branch, "ref": "a" * 40}
            )
            self.branch = True
            return self.fault("branch", request) or httpx.Response(201, json={})
        if path.endswith(("/pulls", "/merge_requests")):
            if method == "GET":
                assert request.url.params["state"] == "all"
                return httpx.Response(200, json=[self.review] if self.review else [])
            assert method == "POST" and self.review is None
            assert (
                payload.get("draft") is True
                if self.provider == "github"
                else payload["title"].startswith("Draft:")
            )
            self.review = self.review_data(payload)
            return self.fault("review", request) or httpx.Response(201, json=self.review)
        if "/contents/" in path or "/repository/files/" in path:
            assert path.endswith(self.proposal_path)
            if method == "GET":
                assert request.url.params["ref"] == self.proposal_branch
                if self.content is None:
                    return httpx.Response(404)
                blob = hashlib.sha1(
                    f"blob {len(self.content)}\0".encode() + self.content, usedforsecurity=False
                ).hexdigest()
                data = {
                    "encoding": "base64",
                    "size": len(self.content),
                    "content": base64.encodebytes(self.content).decode(),
                }
                data.update(
                    {"type": "file", "path": self.proposal_path, "sha": blob}
                    if self.provider == "github"
                    else {
                        "file_path": self.proposal_path,
                        "ref": self.proposal_branch,
                        "blob_id": blob,
                        "content_sha256": hashlib.sha256(self.content).hexdigest(),
                    }
                )
                return httpx.Response(200, json=data)
            assert method == ("PUT" if self.provider == "github" else "POST")
            assert self.content is None, "An existing proposal must never be rewritten"
            assert payload["branch"] == self.proposal_branch and "sha" not in payload
            self.content = (
                base64.b64decode(payload["content"])
                if self.provider == "github"
                else payload["content"].encode()
            )
            self.head = "b" * 40
            return self.fault("file", request) or httpx.Response(201, json={})
        raise AssertionError(f"Unexpected provider contract: {method} {path}")

    def client(self):
        return GitOpsClient(settings(self.provider), httpx.MockTransport(self))


@pytest.mark.parametrize("provider", ["github", "gitlab"])
def test_create_is_draft_and_retry_has_no_remote_writes(provider):
    remote = Provider(provider)
    first = remote.client().create_pr(RID, TENANT, CONTENT)
    writes = len(remote.writes)
    second = remote.client().create_pr(RID, TENANT, CONTENT)
    assert first == second
    assert len(remote.writes) == writes == 3
    assert not any(r.method in {"PATCH", "DELETE"} or r.url.path.endswith("/merge") for r in remote.writes)


@pytest.mark.parametrize("provider", ["github", "gitlab"])
def test_existing_review_with_deleted_branch_never_recreates_branch(provider):
    remote = Provider(provider)
    remote.client().create_pr(RID, TENANT, CONTENT)
    remote.branch = False
    writes = len(remote.writes)
    with pytest.raises(GitOpsConflict, match="branch was removed"):
        remote.client().create_pr(RID, TENANT, CONTENT)
    assert len(remote.writes) == writes


@pytest.mark.parametrize("provider", ["github", "gitlab"])
@pytest.mark.parametrize("phase", ["branch", "file", "review"])
def test_accepted_write_lost_response_retry_reuses_resource(provider, phase):
    remote = Provider(provider)
    remote.fail_after = phase
    with pytest.raises(GitOpsError) as error:
        remote.client().create_pr(RID, TENANT, CONTENT)
    assert "SECRET" not in str(error.value)
    result = remote.client().create_pr(RID, TENANT, CONTENT)
    assert result.branch == BRANCH
    assert len(remote.writes) == 3


@pytest.mark.parametrize("provider", ["github", "gitlab"])
@pytest.mark.parametrize("phase", ["branch", "file", "review"])
def test_create_conflict_race_rereads_matching_resource(provider, phase):
    remote = Provider(provider)
    remote.conflict_at = phase
    assert remote.client().create_pr(RID, TENANT, CONTENT).branch == BRANCH
    assert len(remote.writes) == 3


@pytest.mark.parametrize("provider", ["github", "gitlab"])
def test_published_file_never_overwritten_with_different_content(provider):
    remote = Provider(provider)
    remote.branch, remote.content = True, b"different-policy"
    with pytest.raises(GitOpsConflict, match="content differs"):
        remote.client().create_pr(RID, TENANT, CONTENT)
    assert not remote.writes
    assert remote.content == b"different-policy"


@pytest.mark.parametrize("provider", ["github", "gitlab"])
@pytest.mark.parametrize(
    "defect", ["draft", "base", "repo", "sha", "marker", "closed", "url", "missing_file"]
)
def test_existing_review_mismatch_or_removed_file_is_not_mutated(provider, defect):
    remote = Provider(provider)
    remote.client().create_pr(RID, TENANT, CONTENT)
    writes = len(remote.writes)
    if defect == "draft":
        remote.review["draft"] = False
    elif defect == "base":
        if provider == "github":
            remote.review["base"]["ref"] = "production"
        else:
            remote.review["target_branch"] = "production"
    elif defect == "repo":
        if provider == "github":
            remote.review["head"]["repo"]["full_name"] = "attacker/fork"
        else:
            remote.review["source_project_id"] = 999
    elif defect == "sha":
        if provider == "github":
            remote.review["head"]["sha"] = "c" * 40
        else:
            remote.review["sha"] = "c" * 40
    elif defect == "marker":
        remote.review["body" if provider == "github" else "description"] = "foreign review"
    elif defect == "closed":
        remote.review["state"] = "closed"
    elif defect == "url":
        remote.review["html_url" if provider == "github" else "web_url"] = "https://attacker.example/token"
    else:
        remote.content = None
    with pytest.raises(GitOpsError):
        remote.client().create_pr(RID, TENANT, CONTENT)
    assert len(remote.writes) == writes


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(302, headers={"location": "https://attacker.example"}),
        httpx.Response(200, content=b"SECRET invalid JSON"),
        httpx.Response(200, json=True),
        httpx.Response(200, json={"object": {"sha": "not-a-sha"}}),
        httpx.Response(200, content=b"{}", headers={"content-length": "1000001"}),
    ],
)
def test_redirect_and_malformed_unexpected_responses_fail_safely(response):
    requests = []

    def handler(request):
        requests.append(request)
        return response

    with pytest.raises(GitOpsError) as error:
        GitOpsClient(settings(), httpx.MockTransport(handler)).create_pr(RID, TENANT, CONTENT)
    assert "SECRET" not in str(error.value)
    assert len(requests) == 1


def test_provider_error_does_not_expose_token_or_response():
    with pytest.raises(GitOpsError, match="HTTP 403") as error:
        GitOpsClient(
            settings(), httpx.MockTransport(lambda _: httpx.Response(403, json={"secret": "secret"}))
        ).create_pr(RID, TENANT, CONTENT)
    assert "secret" not in str(error.value)


@pytest.mark.parametrize(
    "attribute,value",
    [
        ("git_policy_prefix", "../../.github/workflows"),
        ("git_base_branch", "main?token=secret"),
        ("git_repository", "acme/../policies"),
    ],
)
def test_invalid_destination_rejected(attribute, value):
    config = settings()
    setattr(config, attribute, value)
    with pytest.raises(GitOpsError):
        GitOpsClient(config)


def test_missing_config_rejected():
    with pytest.raises(GitOpsError):
        GitOpsClient(Settings(environment="test", demo_mode=False))


class Chunks(httpx.SyncByteStream):
    def __init__(self):
        self.reads, self.closed = 0, False

    def __iter__(self):
        for _ in range(5):
            self.reads += 1
            yield b" " * 400_000

    def close(self):
        self.closed = True


def test_stream_size_limit_stops_reading_and_closes_response():
    chunks = Chunks()

    def handler(_request):
        return httpx.Response(200, headers={"content-type": "application/json"}, stream=chunks)

    with pytest.raises(GitOpsError, match="request budget"):
        GitOpsClient(settings(), httpx.MockTransport(handler)).create_pr(RID, TENANT, CONTENT)
    assert chunks.reads == 3 and chunks.closed


def test_declared_size_limit_rejects_before_reading_stream():
    chunks = Chunks()

    def handler(_request):
        return httpx.Response(
            200, headers={"content-type": "application/json", "content-length": "1000001"}, stream=chunks
        )

    with pytest.raises(GitOpsError, match="supported size"):
        GitOpsClient(settings(), httpx.MockTransport(handler)).create_pr(RID, TENANT, CONTENT)
    assert chunks.reads == 0 and chunks.closed


def test_excessively_nested_json_is_sanitized():
    response = b"[" * 2000 + b"]" * 2000
    with pytest.raises(GitOpsError) as error:
        GitOpsClient(
            settings(),
            httpx.MockTransport(
                lambda _request: httpx.Response(
                    200, content=response, headers={"content-type": "application/json"}
                )
            ),
        ).create_pr(RID, TENANT, CONTENT)
    assert str(error.value) in {"GitOps request failed; retry the same proposal", "Malformed provider response"}


def test_request_and_elapsed_deadline_budget(monkeypatch):
    remote = Provider("github")
    monkeypatch.setattr("app.remediation.gitops_sync.MAX_REQUESTS", 1)
    with pytest.raises(GitOpsError, match="budget exhausted"):
        remote.client().create_pr(RID, TENANT, CONTENT)
    assert not remote.writes
    monkeypatch.setattr("app.remediation.gitops_sync.MAX_REQUESTS", 20)
    monkeypatch.setattr("app.remediation.gitops_sync.DEADLINE_SECONDS", 0)
    with pytest.raises(GitOpsError, match="budget exhausted"):
        remote.client().create_pr(RID, TENANT, CONTENT)
    assert not remote.writes


@pytest.fixture
def gitops_postgres(monkeypatch):
    import os
    from uuid import uuid4

    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    from app.api import routes
    from app.db.models import Base, Remediation, TenantState

    url = os.getenv("ZG_INGESTION_POSTGRES_URL")
    if not url:
        pytest.skip("No disposable PostgreSQL integration database configured")
    namespace = "zg_gitops_" + uuid4().hex
    admin = create_engine(url)
    with admin.begin() as db:
        db.execute(text(f'CREATE SCHEMA "{namespace}"'))
    engine = create_engine(
        url, connect_args={"options": f"-csearch_path={namespace} -capplication_name={namespace}"}
    )
    factory = sessionmaker(engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    config = settings()
    config.git_tenant_id = "tenant-a"
    monkeypatch.setattr(routes, "get_settings", lambda: config)
    with factory() as db:
        db.add(TenantState(tenant_id="tenant-a", revision="revision-a"))
        db.add(
            Remediation(
                id=RID,
                tenant_id="tenant-a",
                actor="test",
                identity_id="identity",
                original={"old": True},
                optimized={"old": False},
                evidence={"revision": "revision-a"},
            )
        )
        db.commit()
    try:
        yield factory, admin, namespace
    finally:
        engine.dispose()
        with admin.begin() as db:
            db.execute(text(f'DROP SCHEMA "{namespace}" CASCADE'))
        admin.dispose()


def test_postgres_concurrent_same_proposal_serializes_remote_call(gitops_postgres, monkeypatch):
    import time
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from sqlalchemy import text

    from app.api import routes
    from app.core.auth import Actor
    from app.remediation.gitops_sync import PullRequest

    factory, admin, namespace = gitops_postgres
    entered, release = Event(), Event()
    calls = []

    class Client:
        def __init__(self, config):
            self.config = config

        def scope(self, *args):
            actual = GitOpsClient(
                self.config, httpx.MockTransport(lambda _request: pytest.fail("Unexpected remote request"))
            )
            try:
                return actual.scope(*args)
            finally:
                actual.close()

        def close(self):
            pass

        def create_pr(self, *args):
            calls.append(args)
            entered.set()
            assert release.wait(4)
            return PullRequest("https://github.com/acme/policies/pull/1", BRANCH)

    monkeypatch.setattr(routes, "GitOpsClient", Client)
    actor = Actor("test", "tenant-a", frozenset({"admin"}))

    def request():
        with factory() as db:
            return routes.create_pr(RID, db, actor)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(request)
        assert entered.wait(3)
        second = pool.submit(request)
        try:
            waiting = False
            for _attempt in range(100):
                with admin.connect() as db:
                    waiting = (
                        db.scalar(
                            text(
                                "SELECT count(*) FROM pg_stat_activity WHERE application_name=:name AND wait_event_type='Lock'"
                            ),
                            {"name": namespace},
                        )
                        > 0
                    )
                if waiting:
                    break
                time.sleep(0.01)
            assert waiting, "Second request must actually wait on PostgreSQL row lock"
        finally:
            release.set()
        assert first.result(timeout=3) == second.result(timeout=3)
    assert len(calls) == 1


def test_postgres_publisher_lock_is_bounded_retryable_and_rolls_back(gitops_postgres):
    import time

    from fastapi import HTTPException
    from sqlalchemy import select

    from app.api import routes
    from app.core.auth import Actor
    from app.db.models import Remediation, TenantState

    factory, _admin, _namespace = gitops_postgres
    with factory() as publisher, factory() as request_db:
        publisher.execute(select(TenantState).with_for_update()).scalar_one()
        started = time.monotonic()
        with pytest.raises(HTTPException) as error:
            routes.create_pr(RID, request_db, Actor("test", "tenant-a", frozenset({"admin"})))
        assert error.value.status_code == 503
        assert error.value.headers == {"Retry-After": "5"}
        assert 4.5 <= time.monotonic() - started < 8
        assert not request_db.in_transaction()
        publisher.rollback()
    with factory() as db:
        assert "gitops_scope" not in db.get(Remediation, RID).evidence
