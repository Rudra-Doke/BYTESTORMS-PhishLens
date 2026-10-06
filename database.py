from __future__ import annotations

import os
from pathlib import Path
from threading import Lock

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = BASE_DIR / "instance" / "phishlens.db"


class Base(DeclarativeBase):
    """Base class for all PhishLens SQLAlchemy models."""


_engine = None
_SessionLocal: sessionmaker[Session] | None = None
_init_lock = Lock()


def get_database_url() -> str:
    """
    Return the configured database URL.

    Supports SQLite, MySQL, and PostgreSQL.
    """
    configured = os.getenv("PHISHLENS_DATABASE_URL", "").strip()

    if configured:
        return configured

    return f"sqlite:///{DEFAULT_DB_PATH.as_posix()}"


def init_database():
    """
    Initialize the SQLAlchemy engine, session factory, and schema.

    Safe to call multiple times.
    """
    global _engine, _SessionLocal

    if _engine is not None:
        return _engine

    with _init_lock:
        if _engine is not None:
            return _engine

        database_url = get_database_url()

        if database_url.startswith("sqlite:///"):
            DEFAULT_DB_PATH.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

        connect_args = {}

        if database_url.startswith("sqlite:"):
            connect_args["check_same_thread"] = False

        _engine = create_engine(
            database_url,
            pool_pre_ping=True,
            future=True,
            connect_args=connect_args,
        )

        _SessionLocal = sessionmaker(
            bind=_engine,
            autoflush=False,
            autocommit=False,
            expire_on_commit=False,
        )

        # Import models after Base exists so SQLAlchemy sees every table.
        import models  # noqa: F401

        Base.metadata.create_all(_engine)

    return _engine


def get_session() -> Session:
    """Return a new database session."""
    if _SessionLocal is None:
        init_database()

    assert _SessionLocal is not None
    return _SessionLocal()


def database_healthcheck() -> bool:
    """Return True when the database can execute a basic query."""
    try:
        engine = init_database()

        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))

        return True

    except Exception:
        return False