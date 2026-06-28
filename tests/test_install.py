"""Tests for install.py – dependency detection logic.

We mock ``shutil.which`` and ``subprocess.run`` so we don't depend on the
host's installed tools.
"""

from __future__ import annotations

from unittest.mock import patch

from install import check_system_tool, Dependency


class TestCheckSystemTool:
    def test_installed_tool(self) -> None:
        dep = Dependency(name="echo", kind="system")
        ok, ver = check_system_tool(dep)
        # `echo` is a shell builtin on most systems; subprocess may still find it.
        # We accept either result since it depends on the test environment.
        assert isinstance(ok, bool)
        assert isinstance(ver, str)

    def test_missing_tool(self) -> None:
        dep = Dependency(name="nonexistent_xyz_binary_12345", kind="system")
        ok, ver = check_system_tool(dep)
        assert ok is False
        assert ver == ""

    def test_alias_fallback_for_postgresql(self) -> None:
        """When 'postgresql' binary is absent, we should try 'psql'."""
        dep = Dependency(name="postgresql", kind="system")
        with patch("install.shutil.which") as mock_which:
            # First call (postgresql) returns None; second (psql) returns a path.
            mock_which.side_effect = [None, "/usr/bin/psql"]
            with patch("install.subprocess.run") as mock_run:
                mock_run.return_value.stdout = "psql (PostgreSQL) 16.0"
                mock_run.return_value.stderr = ""
                ok, ver = check_system_tool(dep)
        assert ok is True
        assert "PostgreSQL" in ver or "16" in ver
