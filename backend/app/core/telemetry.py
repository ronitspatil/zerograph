"""Process-local HTTP telemetry and database-backed, fleet-wide ingestion gauges.

All label values are allowlisted. The registry deliberately excludes default
process/runtime collectors and never exports identities, tenant IDs or URLs.
"""

import hmac
import threading
import time
from contextlib import contextmanager
from datetime import UTC, datetime

from fastapi import HTTPException, Request
from loguru import logger
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest
from prometheus_client.core import GaugeMetricFamily
from sqlalchemy import case, create_engine, func, select, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.core.config import Settings, get_settings
from app.db.models import IngestionJob
from app.db.session import session_factory

STATUSES = ("queued", "retrying", "running", "completed", "failed", "other")
METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
DEPENDENCIES = frozenset({"postgres", "graph", "redis"})


def authorize_scrape(request: Request, settings: Settings) -> None:
    secret = settings.metrics_token.get_secret_value()
    if not secret:
        raise HTTPException(503, "Metrics scraping is disabled")
    authorization = request.headers.get("authorization", "")
    parts = authorization.split(" ", 1)
    supplied = parts[1] if len(parts) == 2 and parts[0].lower() == "bearer" else ""
    if len(supplied) > 4096 or not supplied.isascii() or not hmac.compare_digest(supplied, secret):
        raise HTTPException(401, "Invalid scrape credentials", headers={"WWW-Authenticate": "Bearer"})


@contextmanager
def metrics_session():
    url = get_settings().database_url
    if url.startswith("postgresql"):
        # Do not queue behind the application pool or hang on an unreachable database.
        engine = create_engine(url, poolclass=NullPool, connect_args={"connect_timeout": 2})
        try:
            with Session(engine) as db:
                yield db
        finally:
            engine.dispose()
    else:
        with session_factory()() as db:
            yield db


class IngestionCollector:
    """SQL-authoritative current counts, not a monotonic lifetime outcome counter.

    Refresh at most once per 15 seconds per backend process. Query aggregation
    maps unknown persisted values into `other` before grouping. PostgreSQL
    statement timeout bounds database work; failures omit stale job gauges.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.refreshed_at = float("-inf")
        self.counts: dict[str, int] = {}
        self.oldest: datetime | None = None
        self.healthy = False

    def describe(self):
        return []

    def _refresh(self) -> None:
        with self.lock:
            now = time.monotonic()
            if now - self.refreshed_at < 15:
                return
            try:
                with metrics_session() as db:
                    if db.get_bind().dialect.name == "postgresql":
                        db.execute(text("SET LOCAL statement_timeout = '2000ms'"))
                    status = case(
                        (IngestionJob.status.in_(STATUSES[:-1]), IngestionJob.status), else_="other"
                    )
                    rows = db.execute(select(status, func.count()).group_by(status)).all()
                    oldest = db.scalar(
                        select(func.min(IngestionJob.created_at)).where(
                            IngestionJob.status.in_(["queued", "retrying"])
                        )
                    )
                self.counts = {label: count for label, count in rows}
                self.oldest = oldest.replace(tzinfo=UTC) if oldest and oldest.tzinfo is None else oldest
                self.healthy = True
            except Exception as exc:
                self.counts, self.oldest, self.healthy = {}, None, False
                logger.bind(
                    event="metrics_collection_failed",
                    dependency="postgres",
                    exception_type=type(exc).__name__,
                ).warning(
                    "Metrics collection failed dependency=postgres exception_type={}", type(exc).__name__
                )
            self.refreshed_at = now

    def collect(self):
        self._refresh()
        with self.lock:
            healthy, counts, oldest = self.healthy, self.counts.copy(), self.oldest
        yield GaugeMetricFamily(
            "zg_ingestion_collection_success",
            "Whether the cached SQL ingestion aggregation succeeded",
            value=int(healthy),
        )
        if not healthy:
            return
        jobs = GaugeMetricFamily(
            "zg_ingestion_jobs",
            "Current retained SQL jobs by status; not lifetime counters",
            labels=["status"],
        )
        for status in STATUSES:
            jobs.add_metric([status], counts.get(status, 0))
        yield jobs
        age = max(0, (datetime.now(UTC) - oldest).total_seconds()) if oldest else 0
        yield GaugeMetricFamily(
            "zg_ingestion_oldest_pending_seconds",
            "Age of oldest queued/retrying job; zero when none",
            value=age,
        )


class Telemetry:
    def __init__(self, operations: set[str]):
        self.operations = frozenset(operations)
        self.registry = CollectorRegistry(auto_describe=False)
        self.requests = Counter(
            "zg_http_requests_total",
            "Completed HTTP requests",
            ["operation", "method", "status_class"],
            registry=self.registry,
        )
        self.duration = Histogram(
            "zg_http_request_duration_seconds",
            "HTTP handling duration including response streaming",
            ["operation", "method", "status_class"],
            buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30),
            registry=self.registry,
        )
        self.health = Gauge(
            "zg_dependency_health",
            "Last readiness check result, unknown until first check",
            ["dependency"],
            registry=self.registry,
        )
        self.checked_at = Gauge(
            "zg_dependency_health_checked_timestamp_seconds",
            "Unix time of last readiness check",
            ["dependency"],
            registry=self.registry,
        )
        self.registry.register(IngestionCollector())

    def observe_http(self, operation: str, method: str, status: int, duration: float):
        if operation == "metrics":
            return  # Scrapes do not skew user request SLOs.
        operation = operation if operation in self.operations else "unmatched"
        method = method if method in METHODS else "OTHER"
        status_class = f"{status // 100}xx" if 100 <= status < 600 else "other"
        labels = (operation, method, status_class)
        self.requests.labels(*labels).inc()
        self.duration.labels(*labels).observe(max(0, duration))

    def observe_health(self, dependency: str, healthy: bool):
        if dependency not in DEPENDENCIES:
            raise ValueError("Unknown health dependency")
        self.health.labels(dependency).set(int(healthy))
        self.checked_at.labels(dependency).set(time.time())

    def render(self) -> bytes:
        return generate_latest(self.registry)


class MetricsMiddleware:
    def __init__(self, app, telemetry: Telemetry):
        self.app, self.telemetry = app, telemetry

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        start, status = time.monotonic(), 500

        async def measured_send(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, measured_send)
        finally:
            route = scope.get("route")
            self.telemetry.observe_http(
                getattr(route, "name", "unmatched"), scope["method"], status, time.monotonic() - start
            )
