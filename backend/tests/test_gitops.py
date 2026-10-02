import json

import httpx
import pytest

from app.core.config import Settings
from app.remediation.gitops_sync import GitOpsClient, GitOpsError

RID = "11111111-1111-1111-1111-111111111111"
TENANT = "a" * 16


def settings(provider="github"):
    return Settings(
        environment="test",
        demo_mode=False,
        git_provider=provider,
        git_repository="acme/policies",
        git_token="secret",
    )


def test_github_pr_is_draft_in_configured_repository():
    requests = []

    def handler(request):
        requests.append(request)
        path = request.url.path
        if request.method == "GET" and path.endswith("/git/ref/heads/main"):
            return httpx.Response(200, json={"object": {"sha": "base-sha"}})
        if request.method == "GET" and path.endswith("/pulls"):
            return httpx.Response(200, json=[])
        if request.method == "GET":
            return httpx.Response(404, json={})
        if path.endswith("/pulls"):
            assert json.loads(request.content)["draft"] is True
            return httpx.Response(201, json={"html_url": "https://github.com/acme/policies/pull/1"})
        return httpx.Response(201, json={})

    result = GitOpsClient(settings(), httpx.MockTransport(handler)).create_pr(
        RID, TENANT, '{"Version":"2012-10-17"}'
    )
    assert result.url.endswith("/pull/1")
    assert all(r.url.host == "api.github.com" for r in requests)
    assert all("/repos/acme/policies/" in r.url.path for r in requests)


def test_gitlab_draft_merge_request():
    def handler(request):
        if request.method == "GET" and request.url.path.endswith("merge_requests"):
            return httpx.Response(200, json=[])
        if request.method == "GET":
            return httpx.Response(404, json={})
        if request.url.path.endswith("merge_requests"):
            assert json.loads(request.content)["title"].startswith("Draft:")
            return httpx.Response(
                201, json={"web_url": "https://gitlab.com/acme/policies/-/merge_requests/1"}
            )
        return httpx.Response(201, json={})

    result = GitOpsClient(settings("gitlab"), httpx.MockTransport(handler)).create_pr(RID, TENANT, "{}")
    assert result.url.endswith("/1")


def test_provider_error_does_not_expose_token_or_response():
    client = GitOpsClient(
        settings(), httpx.MockTransport(lambda _: httpx.Response(403, json={"secret": "secret"}))
    )
    with pytest.raises(GitOpsError, match="HTTP 403") as error:
        client.create_pr(RID, TENANT, "{}")
    assert "secret" not in str(error.value)


def test_missing_config_and_path_traversal_rejected():
    with pytest.raises(GitOpsError):
        GitOpsClient(Settings(environment="test", demo_mode=False))
    config = settings()
    config.git_policy_prefix = "../../.github/workflows"
    with pytest.raises(GitOpsError):
        GitOpsClient(config)
