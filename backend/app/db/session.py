from functools import lru_cache
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.auth import Actor
from app.core.config import get_settings
from app.db.models import AuditEvent


@lru_cache
def session_factory() -> sessionmaker[Session]:
    url = get_settings().database_url
    kwargs = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {}
    engine = create_engine(url, pool_pre_ping=True, **kwargs)
    return sessionmaker(engine, expire_on_commit=False)


def get_db():
    with session_factory()() as session:
        yield session


def audit(db: Session, actor: Actor, action: str, detail: dict) -> None:
    db.add(
        AuditEvent(
            id=str(uuid4()), tenant_id=actor.tenant_id, actor=actor.subject, action=action, detail=detail
        )
    )
