"""Engine/session management and initialization."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from aeptf.core.config import Settings, get_settings
from aeptf.database.models import Base

_engine = None
_SessionLocal: sessionmaker | None = None


def get_engine(settings: Settings | None = None):
    global _engine
    if _engine is None:
        settings = settings or get_settings()
        connect_args = {}
        if settings.database.url.startswith("sqlite"):
            connect_args = {"check_same_thread": False}
        _engine = create_engine(settings.database.url, echo=settings.database.echo, connect_args=connect_args)
    return _engine


def get_session_factory(settings: Settings | None = None) -> sessionmaker:
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=get_engine(settings), autoflush=False, autocommit=False)
    return _SessionLocal


def init_db(settings: Settings | None = None) -> None:
    """Create all tables. Safe to call repeatedly."""
    Base.metadata.create_all(bind=get_engine(settings))


@contextmanager
def session_scope() -> Iterator[Session]:
    factory = get_session_factory()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
