# Staging configuration preflight

Run the offline check before installing the qualified chart into an authorized target. It uses local Helm only, without Kubernetes, cloud credentials or provider calls:

```sh
PATH=/path/to/pinned-helm:$PATH python deploy/staging_preflight.py --values /private/path/staging-values.yaml
```

Use Helm 3.17.3 and Python 3.12 with the repository's pinned PyYAML dependency. The command prints redacted JSON and exits zero only for `configuration_valid`. This means the rendered configuration passed local checks; it does not mean the deployment is ready or externally validated. The shipped chart defaults intentionally fail the preflight because their images are mutable and their public/provider endpoints are placeholders.

An operator values file should select backend/frontend images as `registry/repository@sha256:<64 lowercase hex characters>`, the name of a separately managed existing application Secret, and an origin-only HTTPS public URL without a trailing slash. Set production environment, demo disabled, secure cookies, an external graph vendor, OIDC issuer/JWKS URLs, audience/client ID and tenant/role claim names. Issuer and JWKS paths and distinct hosts are supported, including nondefault HTTPS ports and internal DNS. Credential-free JWKS query parameters and database TLS parameters such as `sslmode=verify-full` are supported. Localhost and reserved example/invalid domains are refused. Public URL paths, credentials, query strings and fragments are refused because authentication callbacks depend on the configured origin.

With chart ingress enabled, its host must match the public URL hostname and reference a named TLS Secret and ingress class. Alternatively disable chart ingress for a private/external routing target; its HTTPS public URL still needs external validation. No ingress controller is selected or qualified by this preflight.

Keep credentials outside values and ConfigMaps. The tool rejects known secret keys and URL passwords or recognized credential query parameters in rendered ConfigMaps. It verifies the application and migration hook reference the same existing Secret, without accessing its contents. Required keys are `ZG_SESSION_SECRET` (at least 32 characters), `ZG_DATABASE_URL` and `ZG_METRICS_TOKEN` (a separate printable ASCII secret of 32–4096 characters without whitespace). Conditional keys are `ZG_GRAPH_PASSWORD`, authenticated `ZG_REDIS_URL`, `ZG_OIDC_CLIENT_SECRET` for a confidential client, `ZG_GIT_TOKEN` when GitOps is enabled and `ZG_AWS_EXTERNAL_ID` when the role trust requires one. Secret credentials may override ConfigMap settings through `envFrom`; operators must ensure they do not override production/authentication controls. Presence, content, lengths and permissions are explicitly unchecked.

The renderer reads at most 1 MB of values, rejects YAML aliases/duplicate keys/deep nesting, uses private temporary files and isolated Helm directories, and enforces a 30-second render deadline and 4 MB output/error limits. It emits fixed failure/check labels and Secret key names, never input values, domains, image references, paths, rendered manifests or raw Helm errors. Do not place credentials in command arguments or share the original values file.

Before staging approval, validate the exact image digests in the registry, Secret contents/access, target cluster/storage/capacity, database/graph/Redis connectivity and authentication, DNS/routing/TLS/controller configuration, OIDC discovery/signatures/tenant and role claims, and installation/upgrade/backup/restore/load behavior. Disposable Kubernetes evidence from PR12 qualifies its synthetic fixture lifecycle only; it does not cover these customer-specific gates. This command creates no resources and authorizes no deployment.
