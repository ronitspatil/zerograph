# ZeroGraph

ZeroGraph builds a graph of non-human identities, AI agents, MCP servers and the data they
can reach across AWS: IAM roles, users and groups, S3, Organizations SCPs, and the Glue Data
Catalog, Lake Formation and Athena. It separates what each identity is granted from what
CloudTrail shows it actually using, scores the gap as an excess-privilege index (EPI),
proposes least-privilege changes with a what-if simulation, and turns accepted proposals
into draft pull requests (GitHub) or merge requests (GitLab) with a canary rollout and a
revert plan. ZeroGraph never merges, deploys or changes cloud IAM itself; its AWS collector
is read-only.

## Quick start

Requires Docker Compose. From the repository root:

```sh
python3 deploy/init_env.py   # writes .env with demo mode and random secrets; skip if .env exists
docker compose up --build -d
docker compose logs -f backend worker
```

Open http://localhost:3100. The demo opens directly on the overview dashboard with a
synthetic demo session; load the sample environment to run an ingestion through Celery and
explore the graph, blast radius and remediation views. Only the frontend is published, on
the loopback interface. `docker compose down` stops the stack and keeps its volumes.

`make init`, `make up`, `make down` and `make test` wrap the same commands.

## Architecture

- `backend/`: FastAPI API, collectors and graph analysis (Python 3.12).
- Celery worker for ingestion and analysis jobs, plus a singleton scheduler that recovers
  stalled jobs and upgrades revisions published by older releases.
- `frontend/`: Next.js console with PKCE sign-in and an encrypted HTTP-only session cookie.
- PostgreSQL for snapshots, jobs, audit and remediation records; Redis as the Celery broker.
- Memgraph (default) or Neo4j for immutable, tenant-scoped graph revisions.

## Production

[docs/operations.md](docs/operations.md) is the operator guide. In short:

- **Kubernetes:** deploy with the Helm chart in [deploy/helm/zerograph](deploy/helm/zerograph);
  provision PostgreSQL, Redis and the graph database separately. See
  [staging preflight](docs/staging.md) and [monitoring](docs/monitoring.md).
- **SSO:** set `ZG_DEMO_MODE=false` and configure OIDC. Access tokens must carry the tenant
  and roles claims (`ZG_TENANT_CLAIM`, `ZG_ROLE_CLAIM`); roles are `viewer`, `analyst` and
  `admin`.
- **AWS collection:** give the worker a read-only role based on
  [deploy/aws/collector-role-policy.example.json](deploy/aws/collector-role-policy.example.json)
  (trust: [collector-role-trust.example.json](deploy/aws/collector-role-trust.example.json)).
  See [AWS qualification](docs/aws-qualification.md).
- **Usage evidence:** administrators upload CloudTrail exports; see
  [docs/usage-evidence.md](docs/usage-evidence.md).
- **GitOps destination:** configure `ZG_GIT_*` for a GitHub or GitLab policy repository;
  see [proposals](docs/proposals.md) and [rollout](docs/rollout.md).
- **Backups:** back up PostgreSQL and the graph store together; see
  [docs/backup-restore.md](docs/backup-restore.md) and
  [graph retention](docs/graph-retention.md).

## Development

```sh
python3.12 -m venv backend/.venv
backend/.venv/bin/pip install -r backend/requirements-dev.lock -e backend
(cd backend && .venv/bin/ruff check app tests && .venv/bin/pytest)
(cd frontend && npm ci && npm run typecheck && npm test && npm run build)
helm lint deploy/helm/zerograph --strict
python3 -m unittest discover -s deploy/tests -v
```

Graph integration tests, the full-stack end-to-end test and CI budgets are described in
[docs/operations.md](docs/operations.md#validation) and [docs/ci.md](docs/ci.md).

## Security model

[docs/security-model.md](docs/security-model.md) covers tenant isolation, how permission
evidence is evaluated, what the collectors do and do not read, and the limits of the risk
and toxic-path analysis.
