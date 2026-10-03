# CI budget and release qualification

GitHub Actions are currently disabled to preserve the account's remaining minutes. These committed workflow controls do not enable workflows or run checks. Keep this pause until the owner explicitly authorizes resuming Actions.

When enabled, standard CI runs once per pull-request update and on pushes to `main`; task-branch pushes do not trigger a second copy. Three bounded jobs cover backend tests with dedicated PostgreSQL, lint, analysis qualification and Python dependency audit; frontend tests, build and full dependency audit; and Helm rendering plus deployment contract tests. Newer updates cancel obsolete standard runs. Audits retain development dependencies and report failures; an earlier green run does not establish today's advisory status.

Compose, both graph databases, restore and production-mode OIDC qualification are separate `workflow_dispatch` workflows. They have no automatic push, pull-request or schedule triggers. Graph database jobs run one at a time. Manual drill runs are serialized globally per workflow without cancelling a running drill, so its cleanup can finish. GitHub may replace an older pending run with a newer pending run; avoid queueing repeated requests. Job timeouts cap runtime, but runner termination can prevent cleanup. Use only the disposable resources named by each workflow and inspect incomplete drills before declaring success.

For release, an authorized operator must manually run the Compose/persistence, Memgraph and Neo4j, fresh-volume restore and OIDC drills against the exact release commit and retain their successful results. Browser and Kubernetes qualifications are also required when their workflows land. Run on the release branch without advancing its head during qualification, and verify each run's head SHA. Missing, skipped, cancelled or failed qualifications are outstanding release gates. Workflow parsing, unit tests and builds provide local evidence; they do not prove runtime qualification or target staging readiness. AWS sandbox and GitOps provider qualifications still require their documented explicit operator setup.

Local checks do not spend Actions minutes:

```sh
python -m unittest deploy.tests.test_workflow_budget -v
ruff check --config backend/pyproject.toml deploy
helm lint deploy/helm/zerograph --strict
python -m unittest discover -s deploy/tests -v
```

Use the locked backend development environment and Helm for these commands. Frontend audit findings must be resolved or explicitly reviewed by the owner before release; disabling the audit or dropping development dependencies is not a budget control.
