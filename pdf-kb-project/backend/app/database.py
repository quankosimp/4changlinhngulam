from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from .settings import get_settings

Base = declarative_base()
engine: Engine
_session_factory: sessionmaker[Session]


def _connect_args(database_url: str) -> dict[str, object]:
    if database_url.startswith("sqlite"):
        return {"check_same_thread": False}
    return {}


def configure_database(database_url: str | None = None) -> None:
    global engine, _session_factory
    url = database_url or get_settings().database_url
    if url.startswith("sqlite"):
        db_path = url.removeprefix("sqlite:///")
        if db_path and db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(url, connect_args=_connect_args(url), future=True)
    _session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True, expire_on_commit=False)


def init_db() -> None:
    from . import models  # noqa: F401 - registers models with Base

    if engine.url.get_backend_name().startswith("sqlite"):
        Base.metadata.create_all(bind=engine)


def SessionLocal() -> Session:
    return _session_factory()


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


configure_database()
