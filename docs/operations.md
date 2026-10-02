# Running ZeroGraph

ZeroGraph includes an authenticated web console, asynchronous ingestion, tenant-scoped graph snapshots, access analysis, and reviewable GitOps proposals. The local Compose stack uses synthetic demo authentication. Configure OIDC and infrastructure controls before exposing a deployment outside localhost.

## Local stack

Run these commands from this project directory with Docker Compose installed:

```sh
python3 deploy/init_env.py  # Only if .env does not already exist
docker compose up --build -d
docker compose logs -f backend worker
```

Open `http://localhost:3100`, select **Explore the demo workspace**, then **Load sample environment**. An ingestion job goes through Redis and Celery; the completed snapshot appears in the graph. Select Support Copilot to simulate compromise. The remediation hub contains a synthetic sample policy and observation history. Complete audit coverage is unchecked by default.

Only the frontend is published, on the loopback interface. PostgreSQL, Redis, graph Bolt, and FastAPI are on the Compose network. `docker compose down` keeps named volumes. The scheduler recovers queued jobs if broker publication fails and resets workers stalled longer than 20 minutes.

## Authentication and authorization

Set `ZG_DEMO_MODE=false` and `ZG_ENVIRONMENT=production`. Configure the HTTPS OIDC issuer, JWKS URL, API audience, web client ID, client secret where required, and registered callback `${ZG_PUBLIC_URL}/api/auth/callback`. `ZG_OIDC_SCOPE` must request an access token for the API audience according to your provider's configuration.

Access tokens must be signed RS256 or ES256 JWTs containing `sub`, `iat`, `exp`, the configured tenant claim, and an array of roles. Roles are `viewer`, `analyst`, and `admin`; administrators can perform all actions. The tenant comes from the verified access token, never a request header. Analyst access permits simulations, audit normalization, and remediation previews. Ingestion, PR creation, and workspace audit inspection require administrator access.

The console uses PKCE and an encrypted HTTP-only session cookie. Configure `ZG_SESSION_SECRET` with at least 32 random characters, `ZG_COOKIE_SECURE=true`, and an HTTPS public URL. Sessions last at most one hour and require another sign-in after expiration; refresh tokens are not stored. Configure ingress request-size limits and rate limits for public authentication routes in addition to API rate limiting.

## AWS collection

Configure `ZG_AWS_TENANT_ID`, `ZG_AWS_ROLE_ARN`, region, and optional external ID on the backend and worker. Give the workload an AWS identity through the standard boto3 credential chain. No cloud credentials are accepted from the browser.

The assumed role needs read-only access to IAM authorization details and managed policy versions, S3 bucket listing, policies, tags and encryption configuration, and Organizations descriptions and SCP hierarchy. Scope these rights to the required accounts where AWS supports resource constraints. The collector never reads object contents or modifies cloud infrastructure. Missing required IAM inventory aborts the job; optional missing metadata is reported as incomplete coverage.

## GitOps destination

Configure `ZG_GIT_PROVIDER` (`github` or `gitlab`), `ZG_GIT_REPOSITORY`, `ZG_GIT_TENANT_ID`, `ZG_GIT_BASE_BRANCH`, `ZG_GIT_TOKEN`, and optionally `ZG_GIT_POLICY_PREFIX`. The destination is bound to the configured tenant; other tenants cannot use it. Use a dedicated GitHub App installation token or a narrowly scoped GitLab token. Rotate credentials outside this application.

PR generation writes a policy proposal to a dedicated branch and opens a draft PR or merge request. It adds a proposal file under `security/zerograph/<tenant-hash>/`; it does not rewrite your existing Terraform resources, merge, deploy, or change cloud IAM. Reviewers must connect the approved proposal to the actual infrastructure configuration. Retries reuse the same branch and proposal path. A changed graph revision requires a fresh preview.

## Graph database

Memgraph is the default. The graph driver also supports Neo4j. To use the optional Neo4j Compose override, set a strong `ZG_GRAPH_PASSWORD` and run:

```sh
docker compose -f docker-compose.yml -f deploy/docker-compose.neo4j.yml up --build -d
```

This override requires Compose 2.24.4 or later for `!override`. Neo4j includes the APOC plugin. Native shortest-path queries are used by the application, so APOC and MAGE algorithms are optional. The `002_optional_capabilities.cypher` files inspect available procedures; they are diagnostics rather than automatic extension installers.

The migration service runs versioned Alembic migrations and graph constraints before application startup. Every graph publication has an immutable revision; PostgreSQL advances the tenant pointer only after graph publication succeeds. Failed publication preserves the prior revision. Historical graph revisions are retained; establish a retention and backup policy before sustained production ingestion.

## Kubernetes deployment

The Helm chart deploys the API, frontend, worker, singleton scheduler, migration job, Services, and TLS ingress. Provision PostgreSQL, Redis, and Memgraph or Neo4j separately, with private networking, authentication and encrypted connections. Override their URLs using an existing Kubernetes Secret named by `secretName`; secret environment values override the chart's illustrative ConfigMap values.

Build and push the two images, set image names in your values file, configure OIDC and public URL, and provision the TLS secret. Supply `ZG_DATABASE_URL`, `ZG_REDIS_URL`, graph credentials, `ZG_SESSION_SECRET`, and optional connector secrets in the existing secret. Then run `helm upgrade --install zerograph deploy/helm/zerograph -f <your-values.yaml>`. Pin container images by digest for releases. The sample chart does not provision external databases or a cloud workload identity.

The service account disables automatic Kubernetes API tokens. If using workload identity, configure the provider's projected token mechanism and required egress policies. Apply ingress size/rate limits and namespace NetworkPolicies appropriate to your infrastructure. Back up both PostgreSQL and the graph store; their revision relationship is needed for recovery.

The migration hook applies the same non-root, read-only filesystem and capability restrictions as application containers. ConfigMap changes trigger a workload rollout through a pod-template checksum. Changes to an external Secret require an explicit rollout after rotation; secret contents are not rendered or hashed by the chart. Web startup probes allow initial startup before liveness checks begin. The migration ConfigMap is a retained pre-install/pre-upgrade hook resource and must be included in uninstall cleanup if no longer needed.

## Validation

Use Python 3.12 for the backend:

```sh
python3.12 -m venv backend/.venv
backend/.venv/bin/pip install -r backend/requirements-dev.lock -e backend
(cd backend && .venv/bin/ruff check app tests && .venv/bin/pytest)
(cd frontend && npm ci && npm run typecheck && npm test && npm run build)
```

Set `ZG_INTEGRATION_GRAPH=neo4j` or `memgraph` and `ZG_GRAPH_URI` to a disposable graph instance to run `backend/tests/test_graph_integration.py`. The test creates a unique namespace and removes only its own test nodes. CI runs the integration test against both database images.

CI also builds the Docker images and starts the complete Compose stack with disposable volumes. `test_stack_e2e.py` exercises the built frontend, cookie session, asynchronous demo ingestion through Celery/Redis, SQL/graph persistence, blast-radius analysis, and remediation review. CI then restarts PostgreSQL, Redis and Memgraph and verifies that the graph revision, remediation and audit records survive without re-ingestion. Failure logs are bounded, and stack cleanup runs even if checks fail. This proves the local demo deployment; it does not validate production OIDC, live cloud credentials, or Kubernetes installation.

To reproduce, generate a disposable `.env`, run `docker compose up --build --detach --wait --wait-timeout 240`, and run `ZG_E2E_URL=http://localhost:3100 backend/.venv/bin/pytest backend/tests/test_stack_e2e.py -v --no-cov`. Use a disposable Compose project; the test adds synthetic demo data. Run `docker compose down --volumes` only when its volumes are disposable. With Helm and PyYAML installed, run `helm lint deploy/helm/zerograph --strict` and `python3 -m unittest discover -s deploy/tests -v` to verify rendered resources and configuration rollouts without a cluster.

The console uses Next.js 15.5.24 and React 19 rather than the originally proposed Next.js 14 and React 18. The change avoids advisories without fixes in the older Next.js major. Dependency lockfiles pin the backend and frontend installations; frontend overrides select a patched PostCSS version.
