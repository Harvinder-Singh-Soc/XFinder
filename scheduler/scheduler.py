"""APScheduler-based scheduler for recurring XFinder scans.

Design notes
------------

* Uses ``BackgroundScheduler`` so scans run in a background thread without
  blocking the CLI.
* Persisted state is held in memory (jobs are re-registered from the
  in-process ``scheduled_jobs`` registry on each start). For a future
  release we may swap in a SQLAlchemy jobstore, but for now keeping it
  in-memory means no extra table is required and there is no risk of
  zombie jobs surviving a schema migration.
* The scheduler never uses ``while True`` – it relies on the scheduler's
  own event loop and exposes ``shutdown`` for clean teardown.

Public API::

    sched = ScanScheduler()
    sched.schedule(target="example.com", scan_type="full",
                   interval_minutes=60)
    sched.start()
    ...
    sched.shutdown(wait=True)
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from config.settings import settings
from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass(slots=True)
class ScheduledJob:
    """Bookkeeping for a scheduled recurring scan."""

    job_id: str            # APScheduler job ID
    target: str
    scan_type: str
    interval_minutes: int
    created_at: datetime
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None


def _job_id_for(target: str, scan_type: str) -> str:
    """Stable job ID derived from target + scan type."""
    safe_target = target.replace(".", "_").replace("/", "_")
    return f"xfinder_{safe_target}_{scan_type}"


class ScanScheduler:
    """Wraps APScheduler to provide recurring XFinder scans.

    The scheduler is intentionally simple: each (target, scan_type) pair
    maps to exactly one job. Re-scheduling the same pair replaces the
    existing job.
    """

    def __init__(self) -> None:
        self._scheduler = BackgroundScheduler(
            daemon=True,
            job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": 300},
        )
        self._jobs: Dict[str, ScheduledJob] = {}
        self._lock = threading.Lock()
        self._started = False

    # ----------------------------------------------------------------- lifecycle

    def start(self) -> None:
        """Start the background scheduler thread."""
        if self._started:
            return
        self._scheduler.start()
        self._started = True
        logger.info("ScanScheduler started")

    def shutdown(self, wait: bool = True) -> None:
        """Shut down the scheduler. Safe to call even if not started."""
        if not self._started:
            return
        try:
            self._scheduler.shutdown(wait=wait)
            logger.info("ScanScheduler shut down")
        finally:
            self._started = False

    # ----------------------------------------------------------------- scheduling

    def schedule(
        self,
        target: str,
        scan_type: str,
        interval_minutes: Optional[int] = None,
    ) -> ScheduledJob:
        """Schedule (or replace) a recurring scan.

        Parameters
        ----------
        target:
            Domain to scan (e.g. ``example.com``).
        scan_type:
            One of the scan types registered in ``scanners.registry``.
        interval_minutes:
            Recurrence interval. Defaults to ``settings.scan_interval_minutes``.

        Returns
        -------
        ScheduledJob
            Bookkeeping record for the scheduled job.
        """
        if interval_minutes is None:
            interval_minutes = settings.scan_interval_minutes
        if interval_minutes < 5:
            raise ValueError("Minimum scan interval is 5 minutes")

        job_id = _job_id_for(target, scan_type)
        with self._lock:
            # If a job with this ID exists, remove it (replace semantics)
            existing = self._scheduler.get_job(job_id)
            if existing is not None:
                self._scheduler.remove_job(job_id)
                logger.info("Replaced existing scheduled job %s", job_id)

            job = self._scheduler.add_job(
                func=_run_scan_job,
                args=[target, scan_type],
                trigger=IntervalTrigger(minutes=interval_minutes),
                id=job_id,
                name=f"XFinder {scan_type} scan of {target} every {interval_minutes}m",
                replace_existing=True,
            )
            record = ScheduledJob(
                job_id=job_id,
                target=target,
                scan_type=scan_type,
                interval_minutes=interval_minutes,
                created_at=datetime.utcnow(),
                next_run=job.next_run_time,
            )
            self._jobs[job_id] = record
            logger.info(
                "Scheduled %s scan for %s every %d minutes (next run: %s)",
                scan_type, target, interval_minutes, job.next_run_time,
            )
            return record

    def unschedule(self, target: str, scan_type: str) -> bool:
        """Remove a scheduled scan. Returns True if a job was removed."""
        job_id = _job_id_for(target, scan_type)
        with self._lock:
            if job_id not in self._jobs:
                return False
            try:
                self._scheduler.remove_job(job_id)
            except Exception:
                pass
            self._jobs.pop(job_id, None)
            logger.info("Unscheduled job %s", job_id)
            return True

    def list_jobs(self) -> List[ScheduledJob]:
        """Return all currently scheduled jobs (snapshot copy)."""
        with self._lock:
            return list(self._jobs.values())

    def is_started(self) -> bool:
        return self._started


# --------------------------------------------------------------------------- module-level singleton

#: Module-level singleton used by the CLI. The CLI calls ``scheduler.start()``
#: lazily when the user opts into a recurring scan.
_scheduler_singleton: Optional[ScanScheduler] = None
_singleton_lock = threading.Lock()


def get_scheduler() -> ScanScheduler:
    """Return the shared ``ScanScheduler`` instance, creating it on first use."""
    global _scheduler_singleton
    if _scheduler_singleton is None:
        with _singleton_lock:
            if _scheduler_singleton is None:
                _scheduler_singleton = ScanScheduler()
    return _scheduler_singleton


# --------------------------------------------------------------------------- job function

def _run_scan_job(target: str, scan_type: str) -> None:
    """Top-level job function invoked by APScheduler.

    Kept at module level (not as a method) so APScheduler can pickle it for
    its jobstore (future-proofing). Imports the engine lazily to avoid
    circular imports at module load time.
    """
    # Late import to avoid circular dependency at module load time
    from scanners.engine import ScanEngine

    logger.info("Scheduled scan triggered: target=%s type=%s", target, scan_type)
    try:
        outcome = ScanEngine().run(target=target, scan_type=scan_type)
        if outcome.success:
            logger.info(
                "Scheduled scan completed: target=%s type=%s duration=%.2fs",
                target, scan_type, outcome.duration_seconds,
            )
        else:
            logger.error(
                "Scheduled scan failed: target=%s type=%s error=%s",
                target, scan_type, outcome.error,
            )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Scheduled scan raised: %s", exc)
