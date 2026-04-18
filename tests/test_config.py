import json
import time
from pathlib import Path

import pytest

from tunnel_manager.config import Config


def test_load_creates_default_when_missing(tmp_path: Path):
    p = tmp_path / "config.json"
    cfg = Config.load(p)
    assert p.exists()
    assert cfg.list_url == "tunnel_list.txt"
    assert cfg.refresh_interval_hours == 24


def test_load_reads_existing(tmp_path: Path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"list_url": "remote.txt", "refresh_interval_hours": 6}))
    cfg = Config.load(p)
    assert cfg.list_url == "remote.txt"
    assert cfg.refresh_interval_hours == 6


def test_load_ignores_unknown_fields(tmp_path: Path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"list_url": "x.txt", "completely_unknown": 42}))
    cfg = Config.load(p)
    assert cfg.list_url == "x.txt"


def test_validation_rejects_bad_values(tmp_path: Path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"watchdog_interval_seconds": 1}))
    with pytest.raises(ValueError, match="watchdog"):
        Config.load(p)


def test_maybe_reload_returns_self_when_unchanged(tmp_path: Path):
    p = tmp_path / "config.json"
    cfg = Config.load(p)
    assert cfg.maybe_reload() is cfg


def test_maybe_reload_returns_fresh_when_mtime_advances(tmp_path: Path):
    p = tmp_path / "config.json"
    cfg = Config.load(p)
    # Bump mtime + content
    time.sleep(0.05)
    p.write_text(json.dumps({"list_url": "changed.txt"}))
    new_cfg = cfg.maybe_reload()
    assert new_cfg is not cfg
    assert new_cfg.list_url == "changed.txt"
