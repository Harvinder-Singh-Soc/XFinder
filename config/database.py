"""SQLAlchemy database engine and session management.

This module exposes:

* ``engine``  – a single shared SQLAlchemy engine.
* ``SessionLocal`` – a session factory used by the repository layer.
* ``Base`` – the declarative base shared by all ORM models.
* ``init_db()`` – creates all tables (used by the installer / first run).

The DSN is sourced from ``config.settings`` so changing ``.env`` immediately
propagates without code changes.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from config.settings import settings

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    """Declarative base shared by all ORM models."""


def _build_engine() -> Engine:
    """Create the SQLAlchemy engine with sensible production defaults."""
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,        # verify connection is alive before checkout
        pool_recycle=1800,         # recycle connections every 30 minutes
        pool_size=10,
        max_overflow=20,
        future=True,
    )


engine: Engine = _build_engine()
SessionLocal: sessionmaker = sessionmaker(
    bind=engine, autoflush=False, autocommit=False, expire_on_commit=False
)


@contextmanager
def session_scope() -> Iterator[Session]:
    """Context manager that yields a Session and handles commit/rollback.

    Usage::

        with session_scope() as s:
            s.add(obj)

    Commits automatically on clean exit; rolls back on exception.
    """
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        logger.error("Database error, rolling back: %s", exc, exc_info=True)
        raise
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db() -> None:
    """Create all tables defined on ``Base``.

    Should be called once during installation or first run. Safe to call
    repeatedly – SQLAlchemy ``create_all`` is idempotent.
    """
    # Import models so they are registered on Base.metadata before create_all.
    from database import models  # noqa: F401  (side-effect import)

    logger.info("Initializing database schema at %s", settings.database_url)
    Base.metadata.create_all(bind=engine)
    logger.info("Database schema initialized successfully")


def test_connection() -> bool:
    """Verify we can reach the database.

    Returns ``True`` on success, ``False`` on failure. Used by the installer
    and the CLI "Configuration" menu.
    """
    from sqlalchemy import text

    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except SQLAlchemyError as exc:
        logger.error("Database connection test failed: %s", exc)
        return False
