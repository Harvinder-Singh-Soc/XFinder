"""Unit tests for config/settings.py."""

from __future__ import annotations

import pytest

from config.settings import Settings, get_settings


class TestSettings:
    def test_defaults(self, monkeypatch) -> None:
        # Clear env vars so we test the actual defaults (not .env overrides)
        for var in ("DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD",
                    "DEFAULT_THREADS", "SCAN_INTERVAL_MINUTES", "LOG_LEVEL",
                    "OUTPUT_DIR", "LOG_DIR", "NUCLEI_SEVERITY"):
            monkeypatch.delenv(var, raising=False)
        s = Settings(_env_file=None)  # ignore .env file
        assert s.db_host == "localhost"
        assert s.db_port == 5432
        assert s.default_threads >= 1
        assert s.scan_interval_minutes >= 5

    def test_database_url(self) -> None:
        s = Settings(db_user="user", db_password="pass", db_host="h",
                     db_port=5432, db_name="x")
        assert s.database_url == "postgresql+psycopg2://user:pass@h:5432/x"

    def test_nuclei_severities(self) -> None:
        s = Settings(nuclei_severity="low,medium,high,critical")
        assert s.nuclei_severities == ["low", "medium", "high", "critical"]

    def test_invalid_log_level(self) -> None:
        with pytest.raises(Exception):
            Settings(log_level="BOGUS")


def test_get_settings_cached() -> None:
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2
