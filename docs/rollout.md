# Optimizer rollout: pull requests, canary and rollback

Optimizer Phase 4. Accepted least-privilege proposals ([proposals.md](proposals.md)) become
**draft pull requests** (GitLab: draft merge requests) in the policy repository configured
for GitOps (`ZG_GIT_*`). **Nothing is applied by ZeroGraph**: it never merges, closes or
force-pushes, never writes to the base branch, and never calls a cloud API. Merging (and
applying the policy through your IaC) happens in your repository. Code:
`app/remediation/rollout.py`, `policy_optimizer.scope_policy`, `gitops_sync.open_change`.

## From proposal to diff

A **change** covers one principal (a role, IAM user or service account: "one PR per role")
or, optionally, a topic bundle of up to 25 principals. It is built from the tenant's
*accepted* proposals of the current revision:

| Proposal | Change written | Never |
|---|---|---|
| `remove_grant`, `break_toxic_path` removing a grant | The principal's stored **inline** identity policy with the Resource entries naming the asset dropped (`arn` and `arn/...`); a statement left without Resource is removed | Widening anything; touching Deny, Condition, NotAction, NotResource, Principal |
| `disable_role`, `disable_identity` | An added inline policy `ZeroGraphDisable` (`Deny * on *`) | Deleting or detaching the principal |
| `merge_roles`, `split_role`, `scope_wildcard`, any `manual`-tier proposal, a toxic-path hop cut | A reviewed **draft text** only (`GET /proposals/{id}/draft`), no pull request | — |

A removal also stays draft-only (with the reason) when the grant comes from a managed or
group policy (shared), from no stored identity policy (resource policy), through a
wildcard or policy-variable Resource pattern, from a statement with Condition/NotAction/
NotResource/Principal, when an entry also covers another asset the principal keeps, or when
it would empty a policy (detaching is a manual review). A disable of a non-IAM principal
(agent, MCP server) is draft-only. Every diff is re-evaluated with
`app.collectors.iam_evaluator` before it is offered: each removed (asset, action) is no
longer allowed, every kept asset evaluates exactly as before, and no probed action is newly
allowed. A failed check makes the removal draft-only.

Each file of a change is stored as a `Remediation` (`status = rollout`) whose `original` is
the stored policy document (or `{}` for an added disable policy) and `optimized` the new
one. Files: `<policy_prefix>/<tenant_key>/<change_id>/<principal-key>/inline-<policy>.json`
or `.../ZeroGraphDisable.json`, rendered as `json.dumps(indent=2, sort_keys=True)`.

## Pull request

`POST /rollout/changes` (admin) stores a draft change; `POST /rollout/changes/{id}/pr`
(admin) opens its draft pull request with the existing GitOps guards: tenant-bound
destination, validated branch and paths, durable intent recorded (and audited) before any
provider call, a marker binding the review to the content digest, bounded requests, time
and response sizes, and retries that reuse what exists. A draft generated on an older
revision is regenerated against the current one (same proposals by ID) before the intent
is recorded; once recorded, the content is frozen. The body lists the proposals, the usage
evidence, excess privilege before and after (what-if), the principal's blast-radius
simulation, the canary plan, the files and revert instructions.

## Canary and states

Per topic, the first single-principal change to open its pull request is the **canary**.
Other changes of the topic, and any topic bundle, are refused (409, "Waiting for canary")
until the canary is marked merged (`POST .../merged`) and its watch window
(`ZG_ROLLOUT_WATCH_DAYS`, default 7) passes without an AccessDenied flag; it then becomes
`verified` (on the next `GET /rollout`, audited as `system:rollout`). A rolled-back canary no
longer counts: the next change of the topic becomes its canary.

```
draft -> pr_open -> merged (canary watch) -> verified
                         \-> revert_open -> rolled_back
```

State is per tenant (`rollout_changes`, migration 0012), so changes carry forward across
revisions; a proposal belongs to at most one active change. A draft whose pull request was
never requested can be discarded.

## Rollback and the AccessDenied watch

`POST /rollout/changes/{id}/revert` (admin) opens a draft revert pull request on
`zerograph/<tenant_key>/<change_id>-revert`: each rewritten file is restored **byte for byte**
to `render(Remediation.original)` (the stored document) and each added disable policy is
removed. It rewrites or removes a file only when the base branch still holds exactly what
the change wrote (GitHub blob SHA / GitLab last commit compare-and-swap); anything else is
a conflict and nothing is written. `POST .../reverted` records the merge (`rolled_back`).

CloudTrail uploads ([usage-evidence.md](usage-evidence.md)) now also aggregate denied
attempts (`errorCode`) per (principal, resource, service, error code) in `access_denials`
(never as use; at most 20,000 pairs per file). After each upload commit, a merged or
verified change with at least `ZG_ROLLOUT_DENIED_THRESHOLD` (default 1) denied attempts by a
principal it touched — on an asset it removed, or any asset for a disabled principal —
inside its watch window is **flagged** and its revert pull request is opened automatically
(never merged), audited as `system:access-denied-watch` (`rollout.flagged`,
`rollout.revert_requested`, `rollout.revert_opened`). A failure is recorded on the change
(`revert_error`) and never fails the upload; "Open revert PR" retries.

## API

| Endpoint | Role | |
|---|---|---|
| `GET /rollout` | viewer | Changes with state, canary, hold reason, PR links, watch countdown |
| `POST /rollout/plan` | analyst | Preview: files and diffs, draft-only proposals, canary note |
| `POST /rollout/changes` | admin | Store a draft change (`subject_id` or `topic_id`) |
| `GET /rollout/changes/{id}` | analyst | Change with diffs |
| `DELETE /rollout/changes/{id}` | admin | Discard a draft |
| `POST /rollout/changes/{id}/pr` | admin | Open the draft pull request (canary gated) |
| `POST /rollout/changes/{id}/merged` | admin | Record the merge; watch starts |
| `POST /rollout/changes/{id}/revert` | admin | Open the revert pull request |
| `POST /rollout/changes/{id}/reverted` | admin | Record the revert merge |
| `GET /proposals/{id}/draft` | viewer | Draft text and pull-request eligibility |

Plans and change details are analyst-only because diffs show policy documents (like
`GET /graph/policies`). The legacy `POST /remediations/{id}/pr` refuses rollout records.

## Console

Proposals > evidence panel: **Create PR** (this principal's accepted proposals) and
**Bundle topic**, enabled for administrators on accepted, eligible proposals; otherwise the
draft text and its reason. Proposals > **Rollout**: every change with its state, PR and
revert links, the canary countdown, AccessDenied flags, and Open PR / Mark merged / Open
revert PR / Mark reverted / Discard.

## Qualification

`scripts/qualify_rollout.py` (planted 100k on Memgraph and PostgreSQL, Git through the local
fake provider `tests/fake_git.py`; no network): diff correctness by re-evaluating every
grant edge of each touched principal, the canary flow, a byte-for-byte revert, an
AccessDenied-triggered revert, and a re-ingest round trip against the what-if model. The
accepted sample is deterministic for a seed (stable IDs only, never the run date) and is
topped up round-robin across topics until at least `--min-scopings` (500) resource
scopings are accepted.

## Limits

- Merges are recorded by an administrator (ZeroGraph does not read the provider's merge
  state). The watch only sees AccessDenied in CloudTrail that is uploaded.
- Only inline policies are rewritten; managed and group policies stay manual.
- Files are standalone review files under the policy prefix, not your IaC source.
