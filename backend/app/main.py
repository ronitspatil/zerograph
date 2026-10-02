import time
from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from loguru import logger
from redis import Redis
from sqlalchemy import text

from app.api.routes import router
from app.core.config import get_settings
from app.db.session import session_factory
from app.graph.repository import get_graph_store


class BodyLimitMiddleware:
    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        chunks, size = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            size += len(message.get("body", b""))
            if size > self.max_bytes:
                response = JSONResponse({"detail": "Request body too large"}, status_code=413)
                return await response(scope, receive, send)
            chunks.append(message)
            if not message.get("more_body", False):
                break

        async def replay():
            if chunks:
                return chunks.pop(0)
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
    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.max_body_bytes)

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        request_id = str(uuid4())
        start = time.monotonic()
        try:
            response = await call_next(request)
        except Exception as exc:
            logger.error("Request failed id={} exception_type={}", request_id, type(exc).__name__)
            response = JSONResponse(
                {"detail": "Internal service error", "request_id": request_id}, status_code=500
            )
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        # Do not log URLs containing identity IDs, tokens, queries, or payloads.
        logger.info(
            "request={} method={} status={} elapsed_ms={:.1f}",
            request_id,
            request.method,
            response.status_code,
            1000 * (time.monotonic() - start),
        )
        return response

    @app.get("/health/live", include_in_schema=False)
    def live():
        return {"status": "ok"}

    @app.get("/health/ready", include_in_schema=False)
    def ready():
        try:
            with session_factory()() as db:
                db.execute(text("SELECT 1"))
            store = get_graph_store()
            if hasattr(store, "driver"):
                store.driver.verify_connectivity()
            with Redis.from_url(settings.redis_url, socket_timeout=2) as client:
                client.ping()
            return {"status": "ready"}
        except Exception:
            return JSONResponse({"status": "unavailable"}, status_code=503)

    app.include_router(router)
    return app


app = create_app()
