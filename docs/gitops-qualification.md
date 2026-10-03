# GitOps proposal integrity and qualification

ZeroGraph creates review-only policy proposal files on `zerograph/<tenant-hash>/<remediation-id>` branches in the administrator-configured repository. It never merges, deletes resources, updates a proposal file, or writes to the configured base branch. A retry reuses verified existing resources and returns the matching draft review without another commit. Reviewers remain responsible for the final infrastructure integration and deployment.

The first API attempt durably records provider/repository/base/path/tenant/format and a SHA-256 digest of the exact proposal bytes in the existing remediation evidence. Tokens and raw policy contents are excluded from this fingerprint. It then reacquires the remediation row lock, refreshes database state, and revalidates destination, content and graph revision before provider effects. This covers accepted provider writes followed by a lost response or a failed SQL result commit. Concurrent requests for the same remediation serialize; PostgreSQL lock acquisition times out after five seconds with a retryable 503 and `Retry-After: 5`. Other database failures retain their existing failure behavior.

Changing destination or proposal bytes under an existing remediation ID returns 409 and requires a fresh preview. Existing different files, removed review files/branches, closed or non-draft reviews, ambiguous reviews, mismatched repository/base/head/project IDs, or missing proposal scope markers are also refused. Previously recorded successful PR URLs still return from application state; a legacy partial review without the new scope marker is not adopted automatically. Review it manually and generate a fresh preview rather than rewriting it.

Provider file creation uses create-only semantics: GitHub writes omit the existing blob SHA, and GitLab uses POST instead of PUT. Existing files are read as bounded base64 payloads and verified by size and blob digest before byte comparison. Create conflicts re-read the actual branch/file/review and only reuse matching state. These contracts follow the official [GitHub contents API](https://docs.github.com/en/rest/repos/contents?apiVersion=2022-11-28), [GitHub pull-request API](https://docs.github.com/en/rest/pulls/pulls?apiVersion=2022-11-28), [GitLab files API](https://docs.gitlab.com/api/repository_files/), and [GitLab merge-request API](https://docs.gitlab.com/api/merge_requests/).

HTTP traffic stays on the fixed official provider hosts. Redirects are refused, JSON responses are streamed with a one-megabyte limit, proposal contents are capped at 256 KB, each attempt has a 20-request budget and a 60-second deadline checked between operations and streamed chunks, with per-operation network timeouts capped at 20 seconds. An in-flight read can finish or time out after the attempt deadline; this is not a strict wall-clock cancellation guarantee. Returned review URLs must match the configured repository and review identifier. Provider response bodies, tokens and raw policy values do not appear in error messages. A remote service is not transactionally locked by PostgreSQL: a human/provider can still change a draft after verification, so Git branch protections, credential restrictions and reviewer controls remain necessary.

## Automated evidence

Run the fixture contract suite from the backend environment:

```sh
cd backend
.venv/bin/pytest tests/test_gitops.py tests/test_api.py --no-cov
```

Stateful GitHub/GitLab fixtures exercise fresh creation, immutable retries, branch/file/review accepted-write/lost-response recovery, create races, mismatched reviews, removed branches/files, redirects, malformed JSON and bounded streams. Actual HTTP API regressions verify durable scope binding and provider success followed by SQL result failure. A gated PostgreSQL regression uses `ZG_INGESTION_POSTGRES_URL` only for a disposable test database, creates a random private schema, proves a second request actually waits on a row lock, and verifies publisher-lock timeout/rollback. Standard backend CI provides that disposable database; no existing operator database or real GitOps repository is used.

These are protocol fixtures and real database concurrency evidence, not live GitHub/GitLab qualification. No remote policy proposal, provider sandbox credential use, merge or cloud IAM change was performed during this task.

## Remaining staging gate

Before enabling GitOps in an enterprise tenant, obtain explicit authorization for a dedicated private sandbox repository, a protected base branch and a narrowly scoped GitHub App installation/GitLab token. Configure the sandbox as that tenant's destination, create a synthetic preview, and repeat the Generate PR action. Verify one draft review and one proposal commit, matching file bytes, base/head/project, scope marker and URL. Test an accepted provider write followed by a client timeout and a disabled repository permission, then restore permission and retry the same preview. Confirm no default-branch writes or duplicate file commits. Exercise removed/modified/closed draft conflicts with a fresh preview for each scenario.

Record provider/version, exact release commit, tenant configuration, expected remote request counts and returned review identities without recording credentials or sensitive policy. Rotate sandbox credentials and perform cleanup only under separately authorized operator actions. No live execution shortcut is enabled by the fixture command above; live provider behavior and network/rate-limit handling must be qualified in that authorized environment.
