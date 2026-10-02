import os

os.environ.update(
    ZG_ENVIRONMENT="test", ZG_GRAPH_VENDOR="memory", ZG_DEMO_MODE="true", ZG_DEMO_TOKEN="a" * 64
)

import pytest
from fastapi.testclient import TestClient

from app.core.auth import Actor, current_actor
from app.core.config import get_settings
from app.db.models import Base, TenantState
from app.db.session import session_factory
from app.graph.demo import demo_snapshot
from app.graph.repository import get_graph_store
from app.main import create_app


@pytest.fixture
def environment(tmp_path, monkeypatch):
    monkeypatch.setenv("ZG_DATABASE_URL", f"sqlite:///{tmp_path}/app.db")
    get_settings.cache_clear()
    session_factory.cache_clear()
    get_graph_store.cache_clear()
    factory = session_factory()
    Base.metadata.create_all(factory.kw["bind"])
    graph = get_graph_store()
    graph.publish("tenant-a", "revision-a", demo_snapshot())
    with factory() as db:
        db.add(TenantState(tenant_id="tenant-a", revision="revision-a"))
        db.commit()
    yield factory, graph
    factory.kw["bind"].dispose()
    session_factory.cache_clear()
    get_graph_store.cache_clear()
    get_settings.cache_clear()


@pytest.fixture
def client(environment):
    app = create_app()
    app.dependency_overrides[current_actor] = lambda: Actor(
        "alice", "tenant-a", frozenset({"admin", "analyst", "viewer"})
    )
    with TestClient(app) as client:
        yield client
