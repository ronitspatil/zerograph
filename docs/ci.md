# CI budget and release qualification

GitHub Actions are paused to preserve the account's remaining minutes. The owner authorized one bounded runtime campaign below; the primary operator controls any temporary enablement. These committed workflow controls do not themselves enable or run workflows.

When enabled, standard CI runs once per pull-request update and on pushes to `main`; task-branch pushes do not trigger a second copy. Three bounded jobs cover backend tests with dedicated PostgreSQL, lint, analysis qualification and Python dependency audit; frontend tests, build and full dependency audit; and Helm rendering plus deployment contract tests. Newer updates cancel obsolete standard runs, except on the explicitly authorized runtime campaign branch, where cancellation is disabled so running drills can clean up. Audits retain development dependencies and report failures; an earlier green run does not establish today's advisory status.

Compose, both graph databases, restore and production-mode OIDC qualification are separate workflows with `workflow_dispatch` and `workflow_call`. They have no direct automatic push, pull-request or schedule triggers. Outside the guarded campaign below, they require explicit manual invocation. Graph database jobs run one at a time. Manual drill runs are serialized globally per workflow without cancelling a running drill, so its cleanup can finish. GitHub may replace an older pending run with a newer pending run; avoid queueing repeated requests. Job timeouts cap runtime, but runner termination can prevent cleanup. Use only the disposable resources named by each workflow and inspect incomplete drills before declaring success.

For release, an authorized operator must manually run the Compose/persistence, Memgraph and Neo4j, fresh-volume restore and OIDC drills against the exact release commit and retain their successful results. Browser and Kubernetes qualifications are also required when their workflows land. Run on the release branch without advancing its head during qualification, and verify each run's head SHA. Missing, skipped, cancelled or failed qualifications are outstanding release gates. Workflow parsing, unit tests and builds provide local evidence; they do not prove runtime qualification or target staging readiness. AWS sandbox and GitOps provider qualifications still require their documented explicit operator setup.

Local checks do not spend Actions minutes:

```sh
python -m unittest deploy.tests.test_workflow_budget -v
ruff check --config backend/pyproject.toml deploy
helm lint deploy/helm/zerograph --strict
python -m unittest discover -s deploy/tests -v
```

Use the locked backend development environment and Helm for these commands. Frontend audit findings must be resolved or explicitly reviewed by the owner before release; disabling the audit or dropping development dependencies is not a budget control.

## One bounded runtime campaign

`ci.yml` has three ordinary jobs and six relative reusable calls. The calls run only for a pull request to `main` whose head is exactly `fm/zerograph-runtime-qualification` in this repository; fork branches and every ordinary PR skip them. Each called job independently enforces the same guard or an explicit manual dispatch. Relative references load the same commit as the caller, as described in [GitHub's reusable workflow documentation](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows). Fixtures are synthetic; calls inherit no secrets and use `contents: read` only.

The campaign waits for backend, frontend and Helm to pass, then runs Compose, both graph databases, restore, OIDC, Chromium and kind in sequence. A failed stage stops downstream qualification. Each drill has its own literal concurrency group, distinct from the caller and the other drills; called workflows inherit the caller's `github.workflow` context, so that expression must not identify their groups. No extra heavy jobs are copied into standard CI.

| Runner jobs | Timeout minutes per job | Maximum runner minutes |
| --- | ---: | ---: |
| Backend / frontend / Helm | 10 / 10 / 5 | 25 |
| Compose | 10 | 10 |
| Memgraph / Neo4j (serial matrix) | 5 / 5 | 10 |
| Restore | 10 | 10 |
| OIDC | 10 | 10 |
| Chromium | 10 | 10 |
| kind / Helm lifecycle | 20 | 20 |
| Total | | 95 |

These are timeout sums, not a billing guarantee: GitHub rounds each job's charged duration and setup/termination can add overhead. Prior timings suggest about 40–60 minutes for the initial campaign; kind remains unmeasured. The primary must track aggregate charged estimates, including targeted retries, stop at 150 minutes, and leave the owner's 200-minute limit unexceeded. No automatic retries, extra matrices or recursive workflow calls are configured. Do not push PR revisions while CI is enabled; an additional PR event could start another campaign.

The primary procedure is to push while workflows are disabled, temporarily enable only existing CI, open one PR to register one exact-head run, then disable CI again. Whether GitHub permits disabled child workflows to execute through `workflow_call` is unverified in this environment: inspect initial registration and report refusal rather than speculate or repeat runs. Do not enable or dispatch children unless the primary verifies necessity and remaining authorization/budget. Missing or rejected calls provide no qualification evidence. Preserve successful stage evidence at its exact commit and separately identify any correction requiring a targeted retry; remaining release and target staging gates still apply.
