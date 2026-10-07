from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config
from sqlalchemy import pool

from database import Base, get_database_url
import models  # noqa: F401


# ============================================================
# ALEMBIC CONFIGURATION
# ============================================================

config = context.config


# Configure Python logging from alembic.ini.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)


# ============================================================
# SQLALCHEMY METADATA
# ============================================================

# Alembic uses this metadata to compare the current database
# schema with the SQLAlchemy models.
target_metadata = Base.metadata


# ============================================================
# DATABASE URL
# ============================================================

# Use the same database configuration as PhishLens itself.
#
# Priority:
#   1. PHISHLENS_DATABASE_URL environment variable
#   2. database.py default SQLite database
#
database_url = os.getenv(
    "PHISHLENS_DATABASE_URL",
    get_database_url(),
)

# ConfigParser treats '%' specially, so escape it when necessary.
config.set_main_option(
    "sqlalchemy.url",
    database_url.replace(
        "%",
        "%%",
    ),
)


# ============================================================
# OFFLINE MIGRATIONS
# ============================================================

def run_migrations_offline() -> None:
    """
    Run migrations without creating a live database connection.
    """

    url = config.get_main_option(
        "sqlalchemy.url"
    )

    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={
            "paramstyle": "named"
        },
    )

    with context.begin_transaction():
        context.run_migrations()


# ============================================================
# ONLINE MIGRATIONS
# ============================================================

def run_migrations_online() -> None:
    """
    Run migrations against a live database connection.
    """

    connectable = engine_from_config(
        config.get_section(
            config.config_ini_section,
            {},
        ),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:

        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


# ============================================================
# ENTRY POINT
# ============================================================

if context.is_offline_mode():

    run_migrations_offline()

else:

    run_migrations_online()