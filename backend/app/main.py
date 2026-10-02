import asyncio
import sys
import time
from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from loguru import logger
from prometheus_client import CONTENT_TYPE_LATEST
from redis import Redis
from sqlalchemy import text

from app.api.routes import router
from app.core.config import get_settings
from app.core.telemetry import MetricsMiddleware, Telemetry, authorize_scrape
from app.db.session import session_factory
from app.graph.repository import get_graph_store


class BodyLimitMiddleware:
    def __init__(self, app, max_bytes: int, timeout_seconds: int):
        self.app, self.max_bytes, self.timeout_seconds = app, max_bytes, timeout_seconds

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        body = bytearray()
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            try:
                message = await asyncio.wait_for(receive(), max(0, deadline - time.monotonic()))
            except TimeoutError:
                return await JSONResponse({"detail": "Request body timed out"}, status_code=408)(
                    scope, receive, send
                )
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > self.max_bytes:
                response = JSONResponse({"detail": "Request body too large"}, status_code=413)
                return await response(scope, receive, send)
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    get_graph_store().close()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="ZeroGraph",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs" if settings.environment != "production" else None,
        redoc_url=None,
    )
    if settings.environment == "production":
        logger.configure(handlers=[{"sink": sys.stderr, "serialize": True}])
    app.add_middleware(
        BodyLimitMiddleware, max_bytes=settings.max_body_bytes, timeout_seconds=settings.body_timeout_seconds
    )

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        request_id = str(uuid4())
        start = time.monotonic()
        try:
            response = await call_next(request)
        except Exception as exc:
            logger.bind(
                event="http_request_failed", request_id=request_id, exception_type=type(exc).__name__
            ).error("Request failed")
            response = JSONResponse(
                {"detail": "Internal service error", "request_id": request_id}, status_code=500
            )
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        # Do not log URLs containing identity IDs, tokens, queries, or payloads.
        logger.bind(
            event="http_request",
            request_id=request_id,
            method=request.method,
            status=response.status_code,
            elapsed_ms=1000 * (time.monotonic() - start),
        ).info("HTTP request completed")
        return response

    @app.get("/health/live", include_in_schema=False)
    def live():
        return {"status": "ok"}

    @app.get("/health/ready", include_in_schema=False)
    def ready():
        component = "postgres"
        try:
            with session_factory()() as db:
                db.execute(text("SELECT 1"))
            telemetry.observe_health("postgres", True)
            component = "graph"
            store = get_graph_store()
            if hasattr(store, "driver"):
                store.driver.verify_connectivity()
            telemetry.observe_health("graph", True)
            component = "redis"
            with Redis.from_url(settings.redis_url, socket_timeout=2, socket_connect_timeout=2) as client:
                client.ping()
            telemetry.observe_health("redis", True)
            return {"status": "ready"}
        except Exception as exc:
            telemetry.observe_health(component, False)
            logger.bind(
                event="dependency_health_failed", dependency=component, exception_type=type(exc).__name__
            ).warning("Readiness failed dependency={} exception_type={}", component, type(exc).__name__)
            return JSONResponse({"status": "unavailable"}, status_code=503)

    @app.get("/metrics", include_in_schema=False)
    def metrics(request: Request):
        authorize_scrape(request, settings)
        return Response(telemetry.render(), headers={"Content-Type": CONTENT_TYPE_LATEST})

    app.include_router(router)
    telemetry = Telemetry(
        {route.name for route in router.routes}
        | {getattr(route, "name", "unmatched") for route in app.routes}
    )
    app.state.telemetry = telemetry
    app.add_middleware(MetricsMiddleware, telemetry=telemetry)
    return app


app = create_app()
