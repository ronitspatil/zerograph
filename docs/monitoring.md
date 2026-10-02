# Operational visibility

The backend exports protected Prometheus exposition at `/metrics`. Set a separate random `ZG_METRICS_TOKEN` of at least 32 printable ASCII characters without whitespace in the backend secret. Missing configuration returns 503, missing or invalid Bearer authentication returns 401. Application access tokens and demo tokens do not authorize scraping. Never put the scrape credential in a URL or frontend configuration. The backend service remains internal; scrape through a trusted private network or TLS endpoint.

With existing Prometheus Operator infrastructure, set Helm `monitoring.enabled=true`. The optional ServiceMonitor discovers each backend pod through the backend Service and references `ZG_METRICS_TOKEN` in the existing application Secret. No Prometheus, Grafana, Operator CRDs or outbound telemetry integration is installed. The default chart creates no ServiceMonitor and exports nothing to an external system. Configure Prometheus selectors and RBAC for the same namespace; restrict endpoint access using your cluster network policy.

One Uvicorn process per backend pod is required for these process-local HTTP counters/histograms. Scrape each pod separately, not a load-balanced public ingress. Counter resets on restart are normal. Worker outcomes and backlog gauges come from PostgreSQL and therefore remain valid across Celery processes/restarts. They describe retained records, not lifetime counters. Do not sum replicated SQL gauges across backend pods; use `max` after appropriate cluster/job selection.

The finite label sets are operation names, allowlisted HTTP methods, status classes, dependency names, and persisted ingestion statuses normalized to six values. Route paths, URLs, queries, tenants, identities, tokens, assets and exception messages are absent. An unknown route/method/status maps to `unmatched`/`OTHER`/`other`. No default runtime collectors or metric exemplars are registered.

| Signal | Meaning | Suggested initial alert |
| --- | --- | --- |
| `zg_http_requests_total` | Requests completed by operation, method and status class; scrapes excluded | API 5xx fraction >1% for 10m with adequate traffic |
| `zg_http_request_duration_seconds` | Request histogram including body read and response send | Analysis p95 >2s for 10m; qualify thresholds on staging workload |
| `zg_ingestion_jobs{status}` | Retained SQL job counts, including failed/completed | Failed count rising over an operational review window |
| `zg_ingestion_oldest_pending_seconds` | Oldest queued/retrying job age, including scheduled retries | Age >300s for 10m |
| `zg_ingestion_collection_success` | Latest cached SQL aggregate succeeded | 0 for 2m; missing gauges must not be read as zero backlog |
| `zg_dependency_health{dependency}` | Last readiness result for postgres, graph or redis | Any dependency observed unhealthy for 2m |
| `zg_dependency_health_checked_timestamp_seconds` | Last check time; later dependencies may be skipped after an earlier failure | Missing or >60s old while expecting readiness probes |
| Prometheus `up` | Scrape reachability/authentication | 0 for 2m |

SQL aggregation refreshes at most once per 15 seconds per pod. PostgreSQL collection uses separate, unpooled connections with a two-second connect timeout and a two-second timeout per aggregate statement; aggregation failures omit job/backlog samples and export collection success 0, while preserving HTTP metrics. Large retained SQL job tables need a measured retention/maintenance policy. Readiness evidence is observational and does not replace worker liveness, queue consumer health or database exporters.

Production Loguru output is JSON. Request logs carry generated request ID, HTTP method, status and duration; failures include bounded event/dependency and exception type, excluding raw exception text. Do not configure access logs that capture query strings or Authorization headers. Frontend and backend body reads have a total 30-second default deadline; the backend deadline is configurable with `ZG_BODY_TIMEOUT_SECONDS` (1–120). Oversized requests return 413 and stalled bodies return 408.

## Initial SLO review

Use an initial availability objective of 99.9% successful authenticated API operations over 30 days and a candidate latency objective of 95% of analysis requests completing within two seconds. These are proposed operational targets, not achieved production guarantees. Define which operation names count, how 4xx client failures are excluded, and the traffic floor before alerting. A starting error-ratio expression is:

```promql
sum(rate(zg_http_requests_total{status_class="5xx",operation!~"live|ready|unmatched"}[10m]))
/
clamp_min(sum(rate(zg_http_requests_total{operation!~"live|ready|unmatched"}[10m])), 0.001)
```

A histogram percentile should aggregate bucket counts, not per-pod percentiles:

```promql
histogram_quantile(0.95,
  sum by (le) (rate(zg_http_request_duration_seconds_bucket{operation=~"overview|findings|simulate"}[10m]))
)
```

Fleet-wide oldest pending age is `max(zg_ingestion_oldest_pending_seconds)` for one selected deployment/database. Neither retained completed/failed job counts nor their `rate()` represent event throughput; use job ledger/audit evidence for precise outcomes.

## Reproducible analysis qualification

From `backend/`, run `PYTHONPATH=. python scripts/qualify_analysis.py --output analysis-qualification.json`. The bounded fixture spans 500/2,000/5,000 nodes and up to 20,000 edges, includes role cycles, restricted data and five exposed agents, and measures the actual overview logic, findings, simulation, plus 12 simulations at concurrency four. CI saves its report as an artifact and enforces generous synthetic regression budgets (overview <10s, simulation p95 <5s, traced allocations <256MiB), alongside deterministic result counts. These budgets are qualification guards, not the proposed production SLO. The script uses temporary SQLite app state and in-memory graph snapshots, performs no connector calls, and sends no telemetry externally.

Qualification reports include Python/platform, wall times, peak traced Python allocations and deterministic output counts. Tracemalloc adds overhead and is not RSS. This establishes a repeatable regression signal, not capacity: real graph-database roundtrips, HTTP/TLS, multi-tenant concurrency, ingestion competition, deployment sizing and adversarial graph shapes still require staging load tests tied to a release commit.

The local Python 3.12/macOS qualification found the 5,000-node/20,000-edge overview rebuilding graph structures per identity: 114.47 seconds with allocation tracing. Reusing a request-local adjacency/evidence/weight index reduced the same overview to 0.48 seconds, with 35 reachable assets and 175 findings unchanged. The index is tied to one exact snapshot and certainty mode, has no process-wide cache, and preserves sorted shortest paths and confirmed evidence preference. These local results motivate the change; CI artifacts and target-environment measurements remain the evidence for their own hardware and release.
