"""Pytest configuration: add project root to sys.path so `from config...`
works without installation.

Also sets up a single shared SQLite in-memory engine for all DB-touching
tests, avoiding cross-test engine reload issues.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Use a tmp output dir for tests so we never pollute the real output/
os.environ.setdefault("OUTPUT_DIR", "/tmp/xfinder_test_output")
os.environ.setdefault("LOG_LEVEL", "WARNING")


# ---------------------------------------------------------------------------
# Shared SQLite engine setup
#
# We patch `config.database` to use a single in-memory SQLite engine for the
# entire test session. This avoids each test module reloading the Repository
# with a different engine, which causes cross-test interference.

import config.database as _db_mod  # noqa: E402
import config.settings as _settings_mod  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

_settings_mod.settings.db_host = "localhost"
_settings_mod.settings.db_user = "test"
_settings_mod.settings.db_password = "test"
_settings_mod.settings.db_name = ":memory:"
_settings_mod.settings.output_dir = "/tmp/xfinder_test_output"

_TEST_ENGINE = create_engine("sqlite:///:memory:", future=True)
_db_mod.engine = _TEST_ENGINE
_db_mod.SessionLocal = sessionmaker(
    bind=_TEST_ENGINE, autoflush=False, autocommit=False, expire_on_commit=False
)


import pytest  # noqa: E402


@pytest.fixture(scope="function")
def fresh_db():
    """Recreate all tables before each test that uses the database."""
    from database import models  # noqa: F401 (register on metadata)
    models.Base.metadata.create_all(_TEST_ENGINE)
    yield
    models.Base.metadata.drop_all(_TEST_ENGINE)
