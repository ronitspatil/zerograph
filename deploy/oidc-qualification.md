# Disposable production-mode OIDC qualification

The dedicated CI workflow runs built ZeroGraph frontend/backend containers with demo mode disabled, production configuration and Secure cookies. It uses pinned Keycloak 26.8.0 with PostgreSQL, imported disposable accounts, an enforced S256 public authorization-code client and generated ephemeral TLS CA. Node, Python and the HTTP test client explicitly trust that CA; TLS verification is never disabled.

Nginx terminates HTTPS for fixture auth, console and API hostnames. Keycloak is started in production mode behind a trusted proxy with forwarded HTTPS metadata. The API TLS route exists only to qualify signed access tokens directly and is not a production exposure recommendation. No bootstrap administrator, customer identity provider or external credentials are used. Generated account passwords, imported realm JSON, private key and environment configuration stay in a private temporary directory; they are never committed or uploaded. The workflow disables ingress access logs and uploads only sanitized JUnit outcomes; diagnostics show service state rather than raw provider/application logs.

The HTTP form/callback drill verifies:

- Actual discovery, frontend authorization redirect, S256 PKCE, provider login form, code exchange, HTTPS JWKS signature verification and encrypted Secure/HttpOnly/SameSite=Lax cookies.
- Viewer/analyst/admin permitted and denied operations, real provider-signed missing-role/missing-tenant identities and existing-ID cross-tenant graph/job/remediation/simulation/audit denial.
- Wrong PKCE verifier, code/callback replay, OAuth state mismatch, modified signature and real provider-signed wrong audience rejection.
- Production demo login denial, same-origin logout, cross-origin logout denial, provider-token expiry including 30-second backend leeway, and replayed expired session rejection including JWE tolerance.

The fixture access/session lifetimes are intentionally short. The expiry wait is bounded at 75 seconds, ingestion completion at 30 seconds and provider readiness at 120 seconds. Docker cleanup targets only the dedicated Compose project and generated fixture path.

For a Docker-enabled disposable environment, install the backend locked development requirements, allocate a new `/tmp/zerograph-oidc-qualification.*` directory and run `python deploy/oidc-init.py --directory <path> --env-file .env` from a clean checkout without an existing `.env`. Map `auth.oidc.test`, `console.oidc.test` and `api.oidc.test` to loopback, then run Compose with `-f docker-compose.yml -f deploy/oidc-compose.yml` under a dedicated project name. Set `ZG_OIDC_E2E=true` and `ZG_OIDC_FIXTURE_DIR=<path>` for `pytest backend/tests/test_oidc_e2e.py --no-cov`. Stop that project with `down --volumes` and invoke `deploy/oidc-cleanup.py` with the same paths afterward. Do not run these fixture operations against an existing development or customer deployment.

This qualifies HTTP authorization/session behavior against a real disposable provider. It does not validate browser JavaScript, third-party cookie restrictions, SameSite navigation semantics, CSP rendering, provider MFA/conditional access, user provisioning/SCIM, customer claim mappings, IdP-specific client authentication or customer TLS/ingress configuration. Those remain target-environment acceptance work tied to the intended release and identity provider.
