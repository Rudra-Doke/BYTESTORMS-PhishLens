from __future__ import annotations

import os
from pathlib import Path
from threading import Lock

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = BASE_DIR / "instance" / "phishlens.db"


class Base(DeclarativeBase):
    """Base class for all PhishLens SQLAlchemy models."""


_engine = None
_SessionLocal: sessionmaker[Session] | None = None
_init_lock = Lock()


# Alembic is now the single source of truth for schema creation and changes.
# These tables must exist before the application can use persistence safely.
REQUIRED_TABLES = {
    "alembic_version",
    "domains",
    "scans",
    "redirects",
    "threat_events",
    "qr_scans",
}


def get_database_url() -> str:
    """
    Return the configured database URL.

    Examples:
        SQLite:
            sqlite:///C:/path/to/phishlens.db

        MySQL:
            mysql+pymysql://user:password@host/phishlens

        PostgreSQL:
            postgresql+psycopg://user:password@host/phishlens
    """
    configured = os.getenv(
        "PHISHLENS_DATABASE_URL",
        "",
    ).strip()

    if configured:
        return configured

    return f"sqlite:///{DEFAULT_DB_PATH.as_posix()}"


def init_database():
    """
    Initialize the SQLAlchemy engine and session factory.

    Schema creation and schema changes are intentionally NOT performed here.
    Alembic owns the schema lifecycle for the enterprise branch.
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

        # Import models after Base exists so all ORM metadata is registered.
        # Alembic imports this metadata when generating migrations.
        import models  # noqa: F401

    return _engine


def get_session() -> Session:
    """Return a new database session."""
    if _SessionLocal is None:
        init_database()

    assert _SessionLocal is not None
    return _SessionLocal()


def database_healthcheck() -> bool:
    """
    Return True when the database is reachable and the Alembic-managed schema
    is present.

    This deliberately does not create missing tables. Use:

        alembic upgrade head

    to apply schema changes.
    """
    try:
        engine = init_database()

        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))

            tables = set(
                inspect(connection).get_table_names()
            )

        return REQUIRED_TABLES.issubset(tables)

    except Exception:
        return False
