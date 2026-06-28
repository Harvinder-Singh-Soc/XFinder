"""Centralized configuration loader for XFinder.

Uses pydantic-settings to read environment variables (optionally from a .env
file) into a strongly-typed ``Settings`` instance. All modules import the
singleton ``settings`` object instead of re-reading the environment, which
keeps configuration consistent across the codebase.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import List

from dotenv import load_dotenv
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# Resolve project root: this file lives in <root>/config/settings.py
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent

# Load .env if present (silent if missing).
load_dotenv(PROJECT_ROOT / ".env")


class Settings(BaseSettings):
    """Strongly-typed application settings.

    Every field maps 1:1 to an environment variable. Sensible defaults are
    provided so the application can boot even when the user has not yet
    configured their environment.
    """

    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ----- PostgreSQL -----
    db_host: str = Field(default="localhost")
    db_port: int = Field(default=5432)
    db_name: str = Field(default="xfinder")
    db_user: str = Field(default="xfinder")
    db_password: str = Field(default="")

    # ----- API Keys -----
    shodan_api_key: str = Field(default="")
    virustotal_api_key: str = Field(default="")

    # ----- Performance -----
    default_threads: int = Field(default=20, ge=1, le=500)
    httpx_timeout: int = Field(default=15, ge=1)
    dnsx_timeout: int = Field(default=10, ge=1)
    naabu_timeout: int = Field(default=15, ge=1)
    nmap_timeout: int = Field(default=60, ge=1)
    katana_timeout: int = Field(default=120, ge=1)
    nuclei_timeout: int = Field(default=180, ge=1)
    scan_rate: int = Field(default=1000, ge=1)

    # ----- Scheduling -----
    scan_interval_minutes: int = Field(default=60, ge=5)

    # ----- Output / Logging -----
    output_dir: str = Field(default="./output")
    log_level: str = Field(default="INFO")
    log_dir: str = Field(default="./logs")

    # ----- Nuclei -----
    nuclei_severity: str = Field(default="low,medium,high,critical")

    # ----------------------------------------------------------------- properties

    @property
    def database_url(self) -> str:
        """Build a SQLAlchemy PostgreSQL connection URL."""
        return (
            f"postgresql+psycopg2://{self.db_user}:{self.db_password}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}"
        )

    @property
    def output_path(self) -> Path:
        """Resolved absolute output directory."""
        p = Path(self.output_dir)
        if not p.is_absolute():
            p = PROJECT_ROOT / p
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def log_path(self) -> Path:
        """Resolved absolute log directory."""
        p = Path(self.log_dir)
        if not p.is_absolute():
            p = PROJECT_ROOT / p
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def nuclei_severities(self) -> List[str]:
        """Nuclei severity list parsed from comma-separated string."""
        return [s.strip().lower() for s in self.nuclei_severity.split(",") if s.strip()]

    # ----------------------------------------------------------------- validators

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        v_upper = v.upper()
        if v_upper not in allowed:
            raise ValueError(f"log_level must be one of {allowed}, got '{v}'")
        return v_upper


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached ``Settings`` instance.

    Using ``lru_cache`` ensures we read the environment exactly once per
    process, while still allowing tests to override values via
    ``get_settings.cache_clear()``.
    """
    return Settings()


# Module-level singleton imported by the rest of the codebase.
settings: Settings = get_settings()


# Helpful project-level constants.
APP_NAME: str = "XFinder"
APP_VERSION: str = "1.0.0"
APP_DESCRIPTION: str = "External Attack Surface Management"

# Path to the optional persisted scheduler state file. APScheduler stores
# scheduled jobs here so they survive restarts.
SCHEDULER_STATE_FILE: Path = PROJECT_ROOT / "scheduler" / "scheduler_state.json"
