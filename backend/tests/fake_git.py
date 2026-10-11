"""In-memory GitHub/GitLab repository behind ``httpx.MockTransport`` (no network).

Implements the documented REST contracts the GitOps client uses: branches/refs, file
contents (create, compare-and-swap update and delete), draft reviews and, for
GitLab, the project identity. ``merge`` stands in for a person merging a review in
the customer's repository (three-way: the review's changes are applied onto the
base branch); a review that is never merged leaves the base untouched, so a revert of
an unmerged change can be exercised by simply not calling it. GitLab's
``last_commit_id`` is the last commit that changed the file (per file, as in GitLab's
Files API), not the branch head. Every request is recorded; any merge, close or
force-push attempt by the client fails the test.
"""

import base64
import hashlib
import json
from urllib.parse import unquote

import httpx

from app.core.config import Settings

OWNER, NAME = "acme", "policies"
REPOSITORY = f"{OWNER}/{NAME}"
PROJECT_ID = 100


def blob_sha(content: bytes) -> str:
    return hashlib.sha1(f"blob {len(content)}\0".encode() + content, usedforsecurity=False).hexdigest()


def settings(provider: str = "github", tenant: str = "tenant-a", **extra) -> Settings:
    return Settings(
        environment="test",
        demo_mode=False,
        git_provider=provider,
        git_repository=REPOSITORY,
        git_token="secret-token-value",
        git_tenant_id=tenant,
        **extra,
    )


class FakeRepository:
    def __init__(self, provider: str = "github"):
        self.provider = provider
        self.commits = 0
        self.branches: dict[str, dict] = {}  # name -> {"head", "tree", "fork", "last"}
        self.reviews: list[dict] = []
        self.requests: list[httpx.Request] = []
        self.branches["main"] = {"head": self._commit(), "tree": {}, "fork": {}, "last": {}}

    # -- helpers -------------------------------------------------------------

    def _commit(self) -> str:
        self.commits += 1
        return hashlib.sha1(f"commit-{self.commits}".encode(), usedforsecurity=False).hexdigest()

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)

    @property
    def writes(self) -> list[httpx.Request]:
        return [r for r in self.requests if r.method != "GET"]

    def file(self, path: str, branch: str = "main") -> bytes | None:
        return self.branches[branch]["tree"].get(path)

    def fork(self, name: str) -> dict:
        """Create branch ``name`` at the current base head (what the client's branch POST does)."""
        base = self.branches["main"]
        self.branches[name] = {
            "head": base["head"],
            "tree": dict(base["tree"]),
            "fork": dict(base["tree"]),
            "last": dict(base["last"]),
        }
        return self.branches[name]

    def last_commit(self, path: str, branch: str = "main") -> str:
        state = self.branches[branch]
        return state["last"].get(path, state["head"])

    def review(self, number: int) -> dict:
        return self.reviews[number - 1]

    def merge(self, number: int) -> None:
        """A person merges review ``number`` in the customer's repository."""
        review = self.review(number)
        branch = self.branches[review["_branch"]]
        base = self.branches["main"]
        for path in set(branch["fork"]) | set(branch["tree"]):
            before, after = branch["fork"].get(path), branch["tree"].get(path)
            if before == after:
                continue
            if after is None:
                base["tree"].pop(path, None)
            else:
                base["tree"][path] = after
        base["head"] = self._commit()
        for path in set(branch["fork"]) | set(branch["tree"]):
            if branch["fork"].get(path) != branch["tree"].get(path):
                base["last"][path] = base["head"]
        review["_merged"] = True

    def _review_json(self, review: dict) -> dict:
        branch = self.branches.get(review["_branch"])
        head = branch["head"] if branch else "0" * 40
        if self.provider == "github":
            return {
                "number": review["number"],
                "state": "closed" if review["_merged"] else "open",
                "draft": review["draft"],
                "merged_at": "2026-10-07T00:00:00Z" if review["_merged"] else None,
                "html_url": f"https://github.com/{REPOSITORY}/pull/{review['number']}",
                "head": {"ref": review["_branch"], "sha": head, "repo": {"full_name": REPOSITORY}},
                "base": {"ref": "main", "repo": {"full_name": REPOSITORY}},
                "body": review["body"],
                "title": review["title"],
            }
        return {
            "iid": review["number"],
            "state": "merged" if review["_merged"] else "opened",
            "draft": review["draft"],
            "merged_at": "2026-10-07T00:00:00Z" if review["_merged"] else None,
            "web_url": f"https://gitlab.com/{REPOSITORY}/-/merge_requests/{review['number']}",
            "source_branch": review["_branch"],
            "target_branch": "main",
            "source_project_id": PROJECT_ID,
            "target_project_id": PROJECT_ID,
            "sha": head,
            "description": review["body"],
            "title": review["title"],
        }

    def _file_json(self, path: str, branch: str) -> dict:
        content = self.branches[branch]["tree"][path]
        data = {"encoding": "base64", "size": len(content), "content": base64.encodebytes(content).decode()}
        if self.provider == "github":
            data.update({"type": "file", "path": path, "sha": blob_sha(content)})
        else:
            data.update(
                {
                    "file_path": path,
                    "ref": branch,
                    "blob_id": blob_sha(content),
                    "content_sha256": hashlib.sha256(content).hexdigest(),
                    "last_commit_id": self.last_commit(path, branch),
                }
            )
        return data

    def _set(self, branch: str, path: str, content: bytes | None) -> None:
        state = self.branches[branch]
        if content is None:
            state["tree"].pop(path, None)
        else:
            state["tree"][path] = content
        state["head"] = self._commit()
        state["last"][path] = state["head"]

    # -- transport -----------------------------------------------------------

    def __call__(self, request: httpx.Request) -> httpx.Response:  # noqa: C901 - one contract table
        self.requests.append(request)
        assert request.url.scheme == "https"
        assert request.headers["authorization"] == "Bearer secret-token-value"
        github = self.provider == "github"
        assert request.url.host == ("api.github.com" if github else "gitlab.com")
        raw = request.url.raw_path.decode().split("?", 1)[0]
        prefix = f"/repos/{REPOSITORY}" if github else f"/api/v4/projects/{OWNER}%2F{NAME}"
        assert raw.startswith(prefix), raw
        path, method = raw[len(prefix) :], request.method
        payload = json.loads(request.content) if request.content else {}
        assert not path.endswith("/merge") and "force" not in payload, "Client must never merge or force"
        if not github and path == "" and method == "GET":
            return httpx.Response(200, json={"id": PROJECT_ID, "path_with_namespace": REPOSITORY})
        # Branches.
        if method == "GET" and (
            path.startswith("/git/ref/heads/") or path.startswith("/repository/branches/")
        ):
            name = unquote(path.split("/heads/", 1)[1] if github else path.split("/branches/", 1)[1])
            branch = self.branches.get(name)
            if branch is None:
                return httpx.Response(404, json={"message": "Not Found"})
            return httpx.Response(
                200,
                json={"ref": f"refs/heads/{name}", "object": {"type": "commit", "sha": branch["head"]}}
                if github
                else {"name": name, "commit": {"id": branch["head"]}},
            )
        if method == "POST" and path in ("/git/refs", "/repository/branches"):
            name = payload["ref"].removeprefix("refs/heads/") if github else payload["branch"]
            sha = payload["sha"] if github else payload["ref"]
            if name in self.branches:
                return httpx.Response(422 if github else 400, json={"message": "exists"})
            assert sha == self.branches["main"]["head"], "Branches start from the current base head"
            self.fork(name)
            return httpx.Response(201, json={})
        # Files.
        if path.startswith("/contents/") or path.startswith("/repository/files/"):
            file_path = unquote(path.split("/contents/", 1)[1] if github else path.split("/files/", 1)[1])
            if method == "GET":
                ref = request.url.params["ref"]
                if ref not in self.branches or file_path not in self.branches[ref]["tree"]:
                    return httpx.Response(404, json={"message": "Not Found"})
                return httpx.Response(200, json=self._file_json(file_path, ref))
            ref = payload["branch"]
            assert ref != "main", "Never write to the base branch"
            assert ref in self.branches
            current = self.branches[ref]["tree"].get(file_path)
            if github:
                if method == "PUT":
                    if current is not None and payload.get("sha") != blob_sha(current):
                        return httpx.Response(409 if "sha" in payload else 422, json={"message": "sha"})
                    if current is None and "sha" in payload:
                        return httpx.Response(422, json={"message": "sha"})
                    self._set(ref, file_path, base64.b64decode(payload["content"]))
                    return httpx.Response(200 if current is not None else 201, json={})
                if method == "DELETE":
                    if current is None or payload.get("sha") != blob_sha(current):
                        return httpx.Response(409, json={"message": "sha"})
                    self._set(ref, file_path, None)
                    return httpx.Response(200, json={})
            else:
                last = self.last_commit(file_path, ref)
                if method == "POST":
                    if current is not None:
                        return httpx.Response(400, json={"message": "exists"})
                    self._set(ref, file_path, payload["content"].encode())
                    return httpx.Response(201, json={})
                if method in ("PUT", "DELETE"):
                    if current is None or payload.get("last_commit_id") != last:
                        return httpx.Response(400, json={"message": "stale"})
                    self._set(ref, file_path, payload["content"].encode() if method == "PUT" else None)
                    return httpx.Response(
                        200 if method == "PUT" else 204, json={} if method == "PUT" else None
                    )
        # Reviews.
        if path in ("/pulls", "/merge_requests"):
            if method == "GET":
                params = request.url.params
                assert params["state" if github else "scope"] == "all"
                branch = params["head"].split(":", 1)[1] if github else params["source_branch"]
                found = [self._review_json(r) for r in self.reviews if r["_branch"] == branch]
                return httpx.Response(200, json=found)
            if method == "POST":
                branch = payload["head"] if github else payload["source_branch"]
                if any(r["_branch"] == branch for r in self.reviews):
                    return httpx.Response(422 if github else 409, json={"message": "exists"})
                assert payload.get("draft") is True if github else payload["title"].startswith("Draft:")
                review = {
                    "number": len(self.reviews) + 1,
                    "_branch": branch,
                    "_merged": False,
                    "draft": True,
                    "title": payload["title"],
                    "body": payload["body"] if github else payload["description"],
                }
                self.reviews.append(review)
                return httpx.Response(201, json=self._review_json(review))
        raise AssertionError(f"Unexpected provider contract: {method} {path}")
