import base64
import re
from dataclasses import dataclass
from urllib.parse import quote

import httpx

from app.core.config import Settings


@dataclass(frozen=True)
class PullRequest:
    url: str
    branch: str


class GitOpsError(RuntimeError):
    pass


class GitOpsClient:
    """Writes only to an administrator-configured repository on a review branch."""

    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None):
        if not settings.git_repository or not settings.git_token.get_secret_value():
            raise GitOpsError("GitOps repository and token are not configured")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+", settings.git_repository):
            raise GitOpsError("Invalid repository path")
        prefix = settings.git_policy_prefix.strip("/")
        if not prefix or any(segment in {".", "..", ".git"} for segment in prefix.split("/")):
            raise GitOpsError("Invalid policy destination")
        self.settings = settings
        self.prefix = prefix
        self.client = httpx.Client(
            timeout=20,
            follow_redirects=False,
            transport=transport,
            headers={
                "Authorization": f"Bearer {settings.git_token.get_secret_value()}",
                "Accept": "application/vnd.github+json",
            },
        )

    def _request(self, method: str, url: str, **kwargs) -> dict:
        response = self.client.request(method, url, **kwargs)
        if response.status_code >= 400:
            # Do not expose provider responses, credentials, or policy contents in errors.
            raise GitOpsError(f"Git provider returned HTTP {response.status_code}")
        return response.json() if response.content else {}

    def create_pr(
        self, remediation_id: str, tenant_key: str, content: str, extension: str = "json"
    ) -> PullRequest:
        if not re.fullmatch(r"[a-f0-9-]{36}", remediation_id) or not re.fullmatch(
            r"[a-f0-9]{16}", tenant_key
        ):
            raise GitOpsError("Invalid remediation identifier")
        if extension not in {"json", "tf"}:
            raise GitOpsError("Invalid policy format")
        branch = f"zerograph/{tenant_key}/{remediation_id}"
        path = f"{self.prefix}/{tenant_key}/{remediation_id}.{extension}"
        title = f"ZeroGraph: review least-privilege policy {remediation_id[:8]}"
        body = (
            "Review-only least-privilege proposal based on the observation window recorded in ZeroGraph. "
            "Validate rare/seasonal workloads and resource scope before applying. "
            "This adds a proposal file; wire it into your IaC only after review."
        )
        try:
            if self.settings.git_provider == "github":
                api = f"https://api.github.com/repos/{self.settings.git_repository}"
                base = self._request(
                    "GET", f"{api}/git/ref/heads/{quote(self.settings.git_base_branch, safe='')}"
                )
                existing = self.client.get(f"{api}/git/ref/heads/{quote(branch, safe='')}")
                if existing.status_code == 404:
                    self._request(
                        "POST",
                        f"{api}/git/refs",
                        json={"ref": f"refs/heads/{branch}", "sha": base["object"]["sha"]},
                    )
                elif existing.status_code != 200:
                    raise GitOpsError("Could not check review branch")
                file_url = f"{api}/contents/{quote(path, safe='/')}"
                existing_file = self.client.get(file_url, params={"ref": branch})
                payload = {
                    "message": title,
                    "content": base64.b64encode(content.encode()).decode(),
                    "branch": branch,
                }
                if existing_file.status_code == 200:
                    payload["sha"] = existing_file.json()["sha"]
                elif existing_file.status_code != 404:
                    raise GitOpsError("Could not check proposal file")
                self._request("PUT", file_url, json=payload)
                opened = self._request(
                    "GET",
                    f"{api}/pulls",
                    params={
                        "state": "open",
                        "head": f"{self.settings.git_repository.split('/')[0]}:{branch}",
                    },
                )
                pr = (
                    opened[0]
                    if opened
                    else self._request(
                        "POST",
                        f"{api}/pulls",
                        json={
                            "title": title,
                            "body": body,
                            "head": branch,
                            "base": self.settings.git_base_branch,
                            "draft": True,
                        },
                    )
                )
                return PullRequest(pr["html_url"], branch)
            api = f"https://gitlab.com/api/v4/projects/{quote(self.settings.git_repository, safe='')}"
            existing = self.client.get(f"{api}/repository/branches/{quote(branch, safe='')}")
            if existing.status_code == 404:
                self._request(
                    "POST",
                    f"{api}/repository/branches",
                    json={"branch": branch, "ref": self.settings.git_base_branch},
                )
            elif existing.status_code != 200:
                raise GitOpsError("Could not check review branch")
            file_url = f"{api}/repository/files/{quote(path, safe='')}"
            exists = self.client.get(file_url, params={"ref": branch})
            if exists.status_code not in {200, 404}:
                raise GitOpsError("Could not check proposal file")
            self._request(
                "PUT" if exists.status_code == 200 else "POST",
                file_url,
                json={"branch": branch, "content": content, "commit_message": title},
            )
            opened = self._request(
                "GET", f"{api}/merge_requests", params={"state": "opened", "source_branch": branch}
            )
            pr = (
                opened[0]
                if opened
                else self._request(
                    "POST",
                    f"{api}/merge_requests",
                    json={
                        "source_branch": branch,
                        "target_branch": self.settings.git_base_branch,
                        "title": f"Draft: {title}",
                        "description": body,
                    },
                )
            )
            return PullRequest(pr["web_url"], branch)
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            raise GitOpsError("GitOps request failed; retry uses the same branch") from exc
        finally:
            self.client.close()
