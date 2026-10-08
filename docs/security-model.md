# ZeroGraph security model and coverage

ZeroGraph models evidence about identity-to-data access. It preserves uncertainty so an incomplete inventory cannot silently become a confirmed grant or a safe-remediation claim. It is an analysis and review system; it does not replace cloud authorization enforcement.

## Tenant and snapshot isolation

Every API read and mutation is scoped to the tenant in a verified access token. PostgreSQL source snapshots, jobs, audit records, and remediation records contain tenant IDs. Graph nodes use an encoded tenant, revision, and resource ID as their unique key. Edges connect endpoints from the same tenant and revision. Traversal queries scope their starting node and validate traversal scope.

Source snapshots are published under a tenant row lock. Duplicate Celery delivery cannot process an already running or completed job. Queued job rows are the transactional outbox. Immutable graph publication precedes the PostgreSQL pointer update; orphan graph revisions can exist after a database failure, but readers continue using the last committed pointer. Conflicting definitions of the same node from different sources abort publication instead of silently overriding one another.

## Permission evidence

The finite-request IAM evaluator supports wildcard action/resource matching, NotAction, NotResource, explicit-deny precedence, supported conditions, permissions boundaries, session policies, SCP and RCP levels, cross-account grant intersection, and direct same-account IAM-user or STS-session grants. Policies within one Organizations level form a union; levels intersect. Unsupported condition operators, missing request context, unresolved policy variables, and NotPrincipal semantics remain conditional.

The live AWS collector initially inventories IAM roles and S3 metadata. It does not collect IAM-user grants, cross-account accounts, resource control policies, endpoint policies, ACLs, session policies, KMS grants, databases, or concrete S3 object-prefix inventories. Live edges are conditional because those controls can change the outcome. Supported AWS actions are a finite S3 read/write catalog and role assumption, rather than the complete AWS service authorization catalog.

MCP server definitions are configuration evidence. The collector never executes server commands, contacts supplied URLs, or infers backend access from a tool's `readOnlyHint`. Explicit tool bindings define intended operations and target assets; those edges remain declared until independently verified. Agent inventories accept LangGraph, CrewAI, AutoGen and custom framework labels in the normalized schema. Arbitrary framework Python code is not executed or automatically interpreted.

GCP, Azure, and Okta SDKs are available as optional dependencies; live collectors for those providers are not implemented in this release. Import normalized snapshots for additional data sources.

Literal same-account role trust grants can authorize AssumeRole without an identity Allow. Account-root delegation still requires an identity grant, and role permissions boundaries remain applicable.

## Sensitive data classification

Regex classification scans labels and schema metadata for PII, PCI, PHI, and credential indicators. Presidio can be supplied through the classifier adapter after installing the optional classifier dependencies and an appropriate local NLP model. Metadata matches are hypotheses; no raw sensitive values are emitted or logged. These classifications do not establish the presence or absence of sensitive object contents.

`STORES_PII` connects a data asset to a DataCategory annotation node. Annotation edges are excluded from access traversal so a shared category cannot create an artificial access path. Sensitivity labels affect prioritization and must be validated against authoritative data discovery before compliance reporting.

## Risk and toxic paths

Blast radius follows directed role assumptions, permission inheritance, tool invocations, and read/write grants for at most five hops. Confirmed-only analysis is the default; simulations can explicitly include conditional and declared edges. The risk score combines sensitivity-weighted reachable asset exposure (85%) with normalized outgoing-degree centrality (15%). It is a relative review heuristic, not a probability of compromise. Rankings can change when the collected asset inventory changes.

Toxic-path detection finds declared public, unauthenticated entry points reaching confidential or restricted data, or unencrypted assets. A privileged intermediate identity increases severity only on a confirmed path. Findings carry the path, evidence, and whether the path is conditional. The rules do not model every possible exploit or privilege escalation mechanism.

## Remediation evidence

Optimization removes only concrete, unconditioned Allow actions for services whose audit coverage is explicitly complete, with at least 90 days of evidence ending within the last seven days. It preserves Deny statements, wildcard actions, unsupported semantics, and conditional grants. If all statements would disappear, it preserves the policy and recommends a detach-policy review rather than creating an invalid empty policy.

CloudTrail event normalization matches identity ARNs or role session issuers and uses a verified operation-to-IAM-action catalog. Unknown mappings invalidate complete coverage. Access Advisor is supplementary evidence; activity summaries cannot prove complete resource-level non-use. An operator's completeness assertion is recorded as evidence, not independently attested by the platform.

Unused during an observation window does not imply unnecessary. Review seasonal work, disaster recovery, break-glass actions, and rare customer workflows before applying a proposal. Generated Terraform escapes IAM policy variables and does not attach or deploy a policy. GitOps destinations are administrator-configured; requests cannot choose arbitrary API hosts or repository paths. Optimizer rollout pull requests ([rollout.md](rollout.md)) use the same client and guards: draft reviews only, files only under `<policy_prefix>/<tenant_key>/<change_id>/`, never a merge, close or write to the base branch; a revert rewrites a file only when the base still holds exactly what the change wrote (compare-and-swap). Every pull request, merge record, revert and AccessDenied flag is audited.

## Release verification limits

Unit and API tests use SQLite and an explicit in-memory graph adapter. Real Neo4j round-trip and shortest-path tests are separately available and were run locally. Memgraph validation is included in CI and requires its Docker image. OIDC provider integration, live AWS accounts, real GitHub/GitLab PR creation, container orchestration, and Kubernetes installation require staging credentials and infrastructure. Do not treat passing isolated tests as certification of a production deployment.
