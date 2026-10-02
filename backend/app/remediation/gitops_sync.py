import base64
import hashlib
import json
import re
import time
from dataclasses import dataclass
from urllib.parse import quote, urlsplit
from uuid import UUID

import httpx

from app.core.config import Settings

MAX_CONTENT_BYTES = 256_000
MAX_RESPONSE_BYTES = 1_000_000
MAX_REQUESTS = 20
DEADLINE_SECONDS = 60


@dataclass(frozen=True)
class PullRequest:
    url: str
    branch: str


class GitOpsError(RuntimeError):
    pass


class GitOpsConflict(GitOpsError):
    """Existing state must never be rewritten under the same proposal ID."""


def object_response(value):
    if not isinstance(value, dict):
        raise GitOpsError("Malformed provider response")
    return value


def sha(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{40}", value):
        raise GitOpsError("Malformed provider commit identity")
    return value


def valid_branch(value):
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 200
        or re.search(r"[\s~^:?*\[\\\x00-\x1f\x7f]", value)
        or ".." in value
        or "@{" in value
        or value == "@"
        or any(not p or p.startswith(".") or p.endswith((".", ".lock")) for p in value.split("/"))
    ):
        raise GitOpsError("Invalid base branch")
    return value


class GitOpsClient:
    """Bounded review-only adapter: create missing resources, never update them."""

    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None):
        repository, token = settings.git_repository, settings.git_token.get_secret_value()
        if not repository or not token:
            raise GitOpsError("GitOps repository and token are not configured")
        if (
            settings.git_provider not in {"github", "gitlab"}
            or not token.isascii()
            or len(token) > 8192
            or any(c.isspace() or not c.isprintable() for c in token)
        ):
            raise GitOpsError("Invalid GitOps provider or credential configuration")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+", repository) or any(
            p in {".", ".."} for p in repository.split("/")
        ):
            raise GitOpsError("Invalid repository path")
        if settings.git_provider == "github" and len(repository.split("/")) != 2:
            raise GitOpsError("GitHub requires an owner/repository destination")
        prefix = settings.git_policy_prefix.strip("/")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", prefix) or any(
            p in {".", "..", ".git"} for p in prefix.split("/")
        ):
            raise GitOpsError("Invalid policy destination")
        self.provider, self.repository, self.prefix = settings.git_provider, repository, prefix
        self.base = valid_branch(settings.git_base_branch)
        self.api = (
            f"https://api.github.com/repos/{repository}"
            if self.provider == "github"
            else f"https://gitlab.com/api/v4/projects/{quote(repository, safe='')}"
        )
        self.client = httpx.Client(
            timeout=20,
            follow_redirects=False,
            transport=transport,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        self.requests, self.deadline = 0, 0.0

    def close(self):
        self.client.close()

    def scope(self, remediation_id, tenant_key, content, extension="json"):
        try:
            if str(UUID(remediation_id)) != remediation_id:
                raise ValueError
        except (ValueError, TypeError, AttributeError) as exc:
            raise GitOpsError("Invalid remediation identifier") from exc
        if not re.fullmatch(r"[a-f0-9]{16}", tenant_key) or extension not in {"json", "tf"}:
            raise GitOpsError("Invalid proposal scope")
        if not isinstance(content, str) or not 1 <= len(content.encode()) <= MAX_CONTENT_BYTES:
            raise GitOpsError("Policy proposal exceeds supported size")
        return {
            "provider": self.provider,
            "repository": self.repository,
            "base_branch": self.base,
            "policy_prefix": self.prefix,
            "tenant_key": tenant_key,
            "format": extension,
            "content_sha256": hashlib.sha256(content.encode()).hexdigest(),
        }

    def request(self, method, suffix, *, statuses=(200,), **kwargs):
        remaining = self.deadline - time.monotonic()
        self.requests += 1
        if self.requests > MAX_REQUESTS or remaining <= 0:
            raise GitOpsError("GitOps request budget exhausted; retry the same proposal")
        with self.client.stream(method, self.api + suffix, timeout=min(20, remaining), **kwargs) as response:
            if response.status_code not in statuses:
                raise GitOpsError(f"Git provider returned HTTP {response.status_code}")
            if response.status_code not in {200, 201}:
                return response.status_code, None
            media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if media_type != "application/json" and not media_type.endswith("+json"):
                raise GitOpsError("Provider response is not JSON")
            length = response.headers.get("content-length")
            if length and (not length.isdigit() or int(length) > MAX_RESPONSE_BYTES):
                raise GitOpsError("Provider response exceeds supported size")
            body = bytearray()
            for chunk in response.iter_bytes():
                if len(body) + len(chunk) > MAX_RESPONSE_BYTES or time.monotonic() > self.deadline:
                    raise GitOpsError("Provider response exceeds request budget")
                body.extend(chunk)
            if 'rel="next"' in response.headers.get("link", "") or response.headers.get("x-next-page"):
                raise GitOpsConflict("Ambiguous existing review requests")
            return response.status_code, json.loads(body)

    def get(self, suffix, **kwargs):
        status, data = self.request("GET", suffix, statuses=(200, 404), **kwargs)
        return None if status == 404 else data

    def ref(self, branch):
        if self.provider == "github":
            data = self.get(f"/git/ref/heads/{quote(branch, safe='')}")
            if data is None:
                return None
            data = object_response(data)
            if (
                data.get("ref") != f"refs/heads/{branch}"
                or object_response(data.get("object")).get("type") != "commit"
            ):
                raise GitOpsConflict("Review branch identity does not match")
            return sha(data["object"]["sha"])
        data = self.get(f"/repository/branches/{quote(branch, safe='')}")
        if data is None:
            return None
        data = object_response(data)
        if data.get("name") != branch:
            raise GitOpsConflict("Review branch identity does not match")
        return sha(object_response(data.get("commit"))["id"])

    def ensure_branch(self, branch):
        head = self.ref(branch)
        if head is not None:
            return head
        base = self.ref(self.base)
        if base is None:
            raise GitOpsError("Configured base branch was not found")
        suffix = "/git/refs" if self.provider == "github" else "/repository/branches"
        payload = (
            {"ref": f"refs/heads/{branch}", "sha": base}
            if self.provider == "github"
            else {"branch": branch, "ref": base}
        )
        self.request(
            "POST",
            suffix,
            statuses=(201, 400, 409, 422) if self.provider == "gitlab" else (201, 409, 422),
            json=payload,
        )
        head = self.ref(branch)
        if head is None:
            raise GitOpsError("Review branch creation did not complete")
        return head

    def file(self, path, branch):
        suffix = (
            f"/contents/{quote(path, safe='/')}"
            if self.provider == "github"
            else f"/repository/files/{quote(path, safe='')}"
        )
        data = self.get(suffix, params={"ref": branch})
        if data is None:
            return None
        data = object_response(data)
        if self.provider == "github":
            if data.get("type") != "file" or data.get("path") != path:
                raise GitOpsConflict("Existing proposal is not the expected file")
            blob_id = data.get("sha")
        else:
            if data.get("file_path") != path or data.get("ref") != branch:
                raise GitOpsConflict("Existing proposal file scope does not match")
            blob_id = data.get("blob_id")
        if (
            data.get("encoding") != "base64"
            or type(data.get("size")) is not int
            or not 0 <= data["size"] <= MAX_CONTENT_BYTES
            or not isinstance(data.get("content"), str)
        ):
            raise GitOpsError("Malformed provider file response")
        content = base64.b64decode(data["content"].replace("\n", "").replace("\r", ""), validate=True)
        blob = hashlib.sha1(f"blob {len(content)}\0".encode() + content, usedforsecurity=False).hexdigest()
        if (
            len(content) != data["size"]
            or sha(blob_id) != blob
            or (
                self.provider == "gitlab"
                and data.get("content_sha256") != hashlib.sha256(content).hexdigest()
            )
        ):
            raise GitOpsError("Provider file integrity check failed")
        return content

    def reviews(self, branch):
        suffix = "/pulls" if self.provider == "github" else "/merge_requests"
        params = {"state": "all", "per_page": 2}
        params.update(
            {"head": f"{self.repository.split('/')[0]}:{branch}"}
            if self.provider == "github"
            else {"source_branch": branch, "scope": "all"}
        )
        _, data = self.request("GET", suffix, params=params)
        if not isinstance(data, list):
            raise GitOpsError("Malformed provider review response")
        if len(data) > 1:
            raise GitOpsConflict("Multiple review requests exist for this proposal")
        return object_response(data[0]) if data else None

    def validate_review(self, data, branch, head, marker, project_id):
        data = object_response(data)
        if self.provider == "github":
            origin, target = object_response(data.get("head")), object_response(data.get("base"))
            matching = (
                origin.get("ref") == branch
                and target.get("ref") == self.base
                and object_response(origin.get("repo")).get("full_name", "").casefold()
                == self.repository.casefold()
                and object_response(target.get("repo")).get("full_name", "").casefold()
                == self.repository.casefold()
                and origin.get("sha") == head
                and data.get("state") == "open"
                and data.get("merged_at") is None
            )
            number, url, body = data.get("number"), data.get("html_url"), data.get("body")
            expected, host = f"/{self.repository}/pull/{number}", "github.com"
        else:
            matching = (
                data.get("source_branch") == branch
                and data.get("target_branch") == self.base
                and data.get("source_project_id") == project_id
                and data.get("target_project_id") == project_id
                and data.get("sha") == head
                and data.get("state") == "opened"
                and data.get("merged_at") is None
            )
            number, url, body = data.get("iid"), data.get("web_url"), data.get("description")
            expected, host = f"/{self.repository}/-/merge_requests/{number}", "gitlab.com"
        if not matching or data.get("draft") is not True or not isinstance(body, str) or marker not in body:
            raise GitOpsConflict("Existing review identity, draft state or proposal scope does not match")
        parsed = urlsplit(url) if isinstance(url, str) else None
        if (
            type(number) is not int
            or number <= 0
            or parsed is None
            or parsed.scheme != "https"
            or parsed.netloc != host
            or parsed.path.casefold() != expected.casefold()
            or parsed.query
            or parsed.fragment
        ):
            raise GitOpsError("Malformed provider review URL")
        return PullRequest(url, branch)

    def create_pr(
        self, remediation_id: str, tenant_key: str, content: str, extension: str = "json"
    ) -> PullRequest:
        self.deadline, self.requests = time.monotonic() + DEADLINE_SECONDS, 0
        try:
            scope = self.scope(remediation_id, tenant_key, content, extension)
            branch, path = (
                f"zerograph/{tenant_key}/{remediation_id}",
                f"{self.prefix}/{tenant_key}/{remediation_id}.{extension}",
            )
            if branch == self.base:
                raise GitOpsConflict("Review branch cannot be the configured base branch")
            digest = hashlib.sha256(
                json.dumps(scope, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            marker = f"<!-- zerograph:{remediation_id}:{tenant_key}:{digest} -->"
            title = f"ZeroGraph: review least-privilege policy {remediation_id[:8]}"
            body = (
                "Review-only least-privilege proposal. Validate workload coverage and resource scope before applying. This adds a proposal file; wire it into IaC only after review.\n\n"
                + marker
            )
            project_id = None
            if self.provider == "gitlab":
                _, project = self.request("GET", "")
                project = object_response(project)
                project_id = project.get("id")
                if (
                    type(project_id) is not int
                    or project_id <= 0
                    or project.get("path_with_namespace") != self.repository
                ):
                    raise GitOpsError("Configured GitLab project identity does not match")
            review = self.reviews(branch)
            head = self.ref(branch)
            if head is None:
                if review is not None:
                    raise GitOpsConflict("Existing review branch was removed; do not recreate it")
                head = self.ensure_branch(branch)
            if review is not None:
                self.validate_review(review, branch, head, marker, project_id)
            existing = self.file(path, branch)
            if existing is not None and existing != content.encode():
                raise GitOpsConflict("Published proposal content differs; generate a fresh remediation")
            if review is not None:
                if existing is None:
                    raise GitOpsConflict("Existing review proposal was removed; do not rewrite it")
                return self.validate_review(review, branch, head, marker, project_id)
            if existing is None:
                if self.provider == "github":
                    suffix, method = f"/contents/{quote(path, safe='/')}", "PUT"
                    payload, statuses = (
                        {
                            "message": title,
                            "content": base64.b64encode(content.encode()).decode(),
                            "branch": branch,
                        },
                        (201, 409, 422),
                    )
                else:
                    suffix, method = f"/repository/files/{quote(path, safe='')}", "POST"
                    payload, statuses = (
                        {"content": content, "commit_message": title, "branch": branch},
                        (201, 400, 409),
                    )
                self.request(method, suffix, statuses=statuses, json=payload)
                if self.file(path, branch) != content.encode():
                    raise GitOpsConflict("Proposal creation conflicted; existing content was preserved")
            head = self.ref(branch)
            if head is None:
                raise GitOpsError("Review branch disappeared")
            review = self.reviews(branch)
            if review is None:
                suffix = "/pulls" if self.provider == "github" else "/merge_requests"
                payload = (
                    {"title": title, "body": body, "head": branch, "base": self.base, "draft": True}
                    if self.provider == "github"
                    else {
                        "title": f"Draft: {title}",
                        "description": body,
                        "source_branch": branch,
                        "target_branch": self.base,
                    }
                )
                status, review = self.request("POST", suffix, statuses=(201, 400, 409, 422), json=payload)
                if status != 201:
                    review = self.reviews(branch)
                    if review is None:
                        raise GitOpsError("Review creation conflicted; retry the same proposal")
            return self.validate_review(review, branch, head, marker, project_id)
        except (httpx.HTTPError, KeyError, ValueError, TypeError, AttributeError, RecursionError) as exc:
            raise GitOpsError("GitOps request failed; retry the same proposal") from exc
        finally:
            self.close()
