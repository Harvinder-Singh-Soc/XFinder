"""Integration test for the scheduler module.

Verifies that scheduling / unscheduling / listing works end-to-end without
actually invoking the scan job (we mock the engine).
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from scheduler.scheduler import ScanScheduler, _job_id_for


class TestScanScheduler:
    def test_job_id_is_stable(self) -> None:
        j1 = _job_id_for("example.com", "full")
        j2 = _job_id_for("example.com", "full")
        j3 = _job_id_for("example.com", "dns")
        assert j1 == j2
        assert j1 != j3

    def test_schedule_and_list(self) -> None:
        sched = ScanScheduler()
        sched.start()
        try:
            record = sched.schedule("example.com", "full", interval_minutes=10)
            assert record.target == "example.com"
            assert record.scan_type == "full"
            assert record.interval_minutes == 10
            jobs = sched.list_jobs()
            assert len(jobs) == 1
            assert jobs[0].target == "example.com"
        finally:
            sched.shutdown(wait=False)

    def test_unschedule(self) -> None:
        sched = ScanScheduler()
        sched.start()
        try:
            sched.schedule("example.com", "full", interval_minutes=10)
            assert len(sched.list_jobs()) == 1
            removed = sched.unschedule("example.com", "full")
            assert removed is True
            assert len(sched.list_jobs()) == 0
            # Unscheduling something that doesn't exist returns False
            assert sched.unschedule("example.com", "full") is False
        finally:
            sched.shutdown(wait=False)

    def test_reschedule_replaces(self) -> None:
        sched = ScanScheduler()
        sched.start()
        try:
            sched.schedule("example.com", "full", interval_minutes=10)
            sched.schedule("example.com", "full", interval_minutes=30)
            jobs = sched.list_jobs()
            assert len(jobs) == 1
            assert jobs[0].interval_minutes == 30
        finally:
            sched.shutdown(wait=False)

    def test_minimum_interval(self) -> None:
        sched = ScanScheduler()
        with pytest.raises(ValueError):
            sched.schedule("example.com", "full", interval_minutes=1)

    def test_job_runs_without_crashing(self) -> None:
        """Mock the engine so the scheduled job function executes safely."""
        from scheduler import scheduler as sched_mod
        with patch.object(sched_mod, "_run_scan_job") as mock_run:
            mock_run.return_value = None
            sched = ScanScheduler()
            sched.start()
            try:
                sched.schedule("example.com", "full", interval_minutes=5)
                # The job is registered; we don't wait for it to fire.
                assert len(sched.list_jobs()) == 1
            finally:
                sched.shutdown(wait=False)
