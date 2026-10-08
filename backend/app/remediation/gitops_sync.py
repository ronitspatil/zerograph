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
# Multi-file changes (optimizer rollout): files per review, body size, extra budget per file.
MAX_CHANGE_FILES = 40
MAX_TITLE_CHARS = 200
MAX_BODY_CHARS = 60_000
REQUESTS_PER_FILE = 4
SECONDS_PER_FILE = 3
FILE_PATH = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+){0,3}")
PURPOSES = ("change", "revert")


@dataclass(frozen=True)
class PullRequest:
    url: str
    branch: str


@dataclass(frozen=True)
class FileChange:
    """One file of a multi-file review, relative to ``<policy_prefix>/<tenant_key>/<change_id>/``.

    ``content`` is the file's new text (``None``: remove it). ``expected`` is set only
    for a revert: the exact text the base branch must hold (what the change wrote) for
    the file to be rewritten or removed; anything else is a conflict and nothing is
    written. Without ``expected`` the file must not exist yet (create only).
    """

    path: str
    content: str | None
    expected: str | None = None


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
        self.requests, self.deadline, self.extra = 0, 0.0, 0

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
        if self.requests > MAX_REQUESTS + self.extra or remaining <= 0:
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
        found = self.file_state(path, branch)
        return None if found is None else found[0]

    def file_state(self, path, branch):
        """(content, blob ID, last commit ID or None) of a file on a branch, or None."""
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
        commit = data.get("last_commit_id") if self.provider == "gitlab" else None
        if commit is not None:
            commit = sha(commit)
        return content, blob_id, commit

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

    # -- multi-file changes and reverts (optimizer rollout) -------------------

    def change_scope(self, change_id, tenant_key, files, purpose="change"):
        """Validate a multi-file change; returns its scope (destination and content digests)."""
        try:
            if str(UUID(change_id)) != change_id:
                raise ValueError
        except (ValueError, TypeError, AttributeError) as exc:
            raise GitOpsError("Invalid change identifier") from exc
        if not re.fullmatch(r"[a-f0-9]{16}", tenant_key) or purpose not in PURPOSES:
            raise GitOpsError("Invalid proposal scope")
        if not isinstance(files, list | tuple) or not 1 <= len(files) <= MAX_CHANGE_FILES:
            raise GitOpsError("Change has no files or too many files")
        seen = set()
        digests = []
        for item in files:
            if (
                not isinstance(item, FileChange)
                or not isinstance(item.path, str)
                or len(item.path) > 200
                or not FILE_PATH.fullmatch(item.path)
                or not item.path.endswith(".json")
                or any(p in {".", "..", ".git"} or p.startswith(".") for p in item.path.split("/"))
                or item.path in seen
            ):
                raise GitOpsError("Invalid change file path")
            seen.add(item.path)
            for text in (item.content, item.expected):
                if text is not None and (
                    not isinstance(text, str) or not 1 <= len(text.encode()) <= MAX_CONTENT_BYTES
                ):
                    raise GitOpsError("Policy proposal exceeds supported size")
            if purpose == "change" and (item.content is None or item.expected is not None):
                raise GitOpsError("A change only creates files")
            if purpose == "revert" and item.expected is None:
                raise GitOpsError("A revert needs the content it replaces")
            digests.append(
                [
                    item.path,
                    hashlib.sha256(item.content.encode()).hexdigest() if item.content is not None else None,
                    hashlib.sha256(item.expected.encode()).hexdigest() if item.expected is not None else None,
                ]
            )
        return {
            "provider": self.provider,
            "repository": self.repository,
            "base_branch": self.base,
            "policy_prefix": self.prefix,
            "tenant_key": tenant_key,
            "purpose": purpose,
            "files": sorted(digests),
        }

    def write_file(self, path, branch, content, state, message):
        """Create (``state`` None), rewrite or remove (``content`` None) one file; compare-and-swap
        on the blob (GitHub) or last commit (GitLab) read in ``state``."""
        github = self.provider == "github"
        suffix = (
            f"/contents/{quote(path, safe='/')}" if github else f"/repository/files/{quote(path, safe='')}"
        )
        if state is None:
            if github:
                payload = {
                    "message": message,
                    "content": base64.b64encode(content.encode()).decode(),
                    "branch": branch,
                }
                self.request("PUT", suffix, statuses=(201, 409, 422), json=payload)
            else:
                payload = {"content": content, "commit_message": message, "branch": branch}
                self.request("POST", suffix, statuses=(201, 400, 409), json=payload)
            return
        _, blob_id, commit = state
        if github:
            payload = {"message": message, "sha": blob_id, "branch": branch}
            if content is None:
                self.request("DELETE", suffix, statuses=(200, 409, 422), json=payload)
            else:
                payload["content"] = base64.b64encode(content.encode()).decode()
                self.request("PUT", suffix, statuses=(200, 201, 409, 422), json=payload)
            return
        if commit is None:
            raise GitOpsError("Provider file response lacks a commit identity")
        payload = {"commit_message": message, "branch": branch, "last_commit_id": commit}
        if content is None:
            self.request("DELETE", suffix, statuses=(204, 400, 409), json=payload)
        else:
            payload["content"] = content
            self.request("PUT", suffix, statuses=(200, 400, 409), json=payload)

    def open_change(
        self, change_id: str, tenant_key: str, files, title: str, body: str, purpose: str = "change"
    ) -> PullRequest:
        """Open (or find) the draft review of a multi-file change or its revert.

        Same guards as ``create_pr``: bounded requests and time, a branch and file scope
        under ``<policy_prefix>/<tenant_key>/<change_id>/``, a marker binding the review to
        the change's content digest, never touching a review that does not match it, and
        retries that reuse what already exists. A change only creates files that do not
        exist; a revert rewrites (or removes) a file only when the base still holds exactly
        what the change wrote. Never merges, closes or force-pushes anything.
        """
        self.deadline, self.requests = time.monotonic() + DEADLINE_SECONDS, 0
        try:
            scope = self.change_scope(change_id, tenant_key, files, purpose)
            self.extra = REQUESTS_PER_FILE * len(files)
            self.deadline += SECONDS_PER_FILE * len(files)
            if not isinstance(title, str) or not isinstance(body, str) or len(body) > MAX_BODY_CHARS:
                raise GitOpsError("Review description exceeds supported size")
            title = " ".join(title.split())[:MAX_TITLE_CHARS] or "ZeroGraph least-privilege change"
            suffix_name = "" if purpose == "change" else "-revert"
            branch = f"zerograph/{tenant_key}/{change_id}{suffix_name}"
            root = f"{self.prefix}/{tenant_key}/{change_id}"
            if branch == self.base:
                raise GitOpsConflict("Review branch cannot be the configured base branch")
            digest = hashlib.sha256(
                json.dumps(scope, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            marker = f"<!-- zerograph:{change_id}:{purpose}:{tenant_key}:{digest} -->"
            description = body.replace("<!--", "&lt;!--") + "\n\n" + marker
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
            wrote = False
            for item in files:
                path = f"{root}/{item.path}"
                state = self.file_state(path, branch)
                current = state[0] if state is not None else None
                target = item.content.encode() if item.content is not None else None
                if current == target:
                    continue
                if review is not None:
                    raise GitOpsConflict("Existing review content differs; do not rewrite it")
                if item.expected is None:
                    if current is not None:
                        raise GitOpsConflict("Published proposal content differs; generate a fresh change")
                elif current is not None and current != item.expected.encode():
                    raise GitOpsConflict("The file changed since the change was merged; revert it manually")
                self.write_file(path, branch, item.content, state if current is not None else None, title)
                after = self.file_state(path, branch)
                if (after[0] if after is not None else None) != target:
                    raise GitOpsConflict("Proposal write conflicted; existing content was preserved")
                wrote = True
            head = self.ref(branch)
            if head is None:
                raise GitOpsError("Review branch disappeared")
            review = self.reviews(branch)
            if review is None:
                if not wrote and head == self.ref(self.base):
                    raise GitOpsConflict("Nothing to change on the base branch for this review")
                suffix = "/pulls" if self.provider == "github" else "/merge_requests"
                payload = (
                    {"title": title, "body": description, "head": branch, "base": self.base, "draft": True}
                    if self.provider == "github"
                    else {
                        "title": f"Draft: {title}",
                        "description": description,
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
