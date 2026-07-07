"""Alembic environment for DHRUVA.

Reads the Postgres DSN from the DATABASE_URL environment variable
(or, as a fallback, from `database.dsn` in config/config.yaml so
operators can drive `alembic upgrade head` from the same file the
app uses). No SQLAlchemy ORM models — DHRUVA uses raw SQL via
psycopg v3, so autogeneration is disabled.
"""

from __future__ import annotations

import os
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def _resolve_dsn() -> str:
    """Pick the connection string. DATABASE_URL wins; config/config.yaml
    is the fallback so the install path doesn't need an env var.

    Normalizes the URL so SQLAlchemy picks the psycopg v3 driver. Plain
    ``postgresql://...`` (libpq style, the form psycopg accepts) would
    otherwise default to psycopg2 — which isn't installed — and emit a
    cryptic ``ModuleNotFoundError: No module named 'psycopg2'``.
    """
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        config_path = Path(__file__).resolve().parents[3] / "config" / "config.yaml"
        if config_path.exists():
            try:
                import yaml
            except ImportError:
                yaml = None
            if yaml is not None:
                with config_path.open() as fh:
                    data = yaml.safe_load(fh) or {}
                dsn = (data.get("database") or {}).get("dsn")

    if not dsn:
        raise RuntimeError(
            "DATABASE_URL is not set and database.dsn is missing from "
            "config/config.yaml. Set one before running alembic. Example:\n"
            "  export DATABASE_URL='postgresql://user:pass@host:5432/dhruva'"
        )

    # Force the psycopg v3 dialect — SQLAlchemy's default ``postgresql://``
    # resolver picks psycopg2, which the project doesn't ship.
    if dsn.startswith("postgresql://"):
        dsn = "postgresql+psycopg://" + dsn[len("postgresql://"):]
    elif dsn.startswith("postgres://"):
        dsn = "postgresql+psycopg://" + dsn[len("postgres://"):]
    elif dsn.startswith("postgresql+psycopg2://"):
        # Older deployments may still carry the v2 hint; rewrite to v3.
        dsn = "postgresql+psycopg://" + dsn[len("postgresql+psycopg2://"):]
    return dsn


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting (alembic upgrade --sql)."""
    context.configure(
        url=_resolve_dsn(),
        target_metadata=None,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Connect to the live database and apply pending migrations."""
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = _resolve_dsn()

    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=None)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
