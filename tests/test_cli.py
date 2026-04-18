"""Smoke tests for CLI argument parsing + non-routing commands."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(REPO / "main.py"), *args],
        capture_output=True, text=True,
    )


def test_help_runs_clean():
    r = _run("--help")
    assert r.returncode == 0
    assert "tunnel_manager" in r.stdout
    assert "--dry-run" in r.stdout
    assert "--status" in r.stdout
    assert "--update-list" in r.stdout


def test_version_prints():
    r = _run("--version")
    assert r.returncode == 0
    assert "tunnel_manager" in r.stdout
    # PEP 440-ish version
    assert any(ch.isdigit() for ch in r.stdout)


def test_status_with_no_state_runs_clean(tmp_path, monkeypatch):
    # Force STATE_DIR to tmp_path so we don't pick up real state.
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    monkeypatch.setenv("APPDATA", str(tmp_path))
    r = _run("--status")
    assert r.returncode == 0
