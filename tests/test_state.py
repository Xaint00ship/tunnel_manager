import os
import time
from pathlib import Path

from tunnel_manager.state import HEARTBEAT_TIMEOUT_SECONDS, StateFile


def test_save_then_reload_preserves_fields(tmp_path: Path):
    s = StateFile(tmp_path / "state.json")
    s.save(active_routes=["1.1.1.1", "2.2.2.2"], pid=12345)

    reopened = StateFile(tmp_path / "state.json")
    assert reopened.previous_routes() == ["1.1.1.1", "2.2.2.2"]
    assert reopened.data["pid"] == 12345


def test_clear_removes_file(tmp_path: Path):
    s = StateFile(tmp_path / "state.json")
    s.save(active_routes=["1.1.1.1"])
    s.clear()
    assert not (tmp_path / "state.json").exists()
    assert s.previous_routes() == []


def test_missing_file_returns_empty(tmp_path: Path):
    s = StateFile(tmp_path / "nonexistent.json")
    assert s.previous_routes() == []
    assert s.data == {}


def test_corrupt_file_returns_empty(tmp_path: Path):
    (tmp_path / "state.json").write_text("{not json")
    s = StateFile(tmp_path / "state.json")
    assert s.data == {}


def test_pid_alive_self():
    assert StateFile.is_pid_alive(os.getpid())


def test_pid_alive_rejects_zero_and_negative():
    assert not StateFile.is_pid_alive(0)
    assert not StateFile.is_pid_alive(-1)


def test_pid_alive_dead_pid():
    # 2^31 - 2 — extremely unlikely to be in use on any platform
    assert not StateFile.is_pid_alive(2_147_483_646)


def test_another_instance_requires_fresh_heartbeat(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(StateFile, "is_pid_alive", staticmethod(lambda _pid: True))
    s = StateFile(tmp_path / "state.json")

    s.save(pid=12345)
    assert not s.is_another_instance_alive()

    s.save(heartbeat=int(time.time()))
    assert s.is_another_instance_alive()

    s.save(heartbeat=int(time.time()) - HEARTBEAT_TIMEOUT_SECONDS - 1)
    assert not s.is_another_instance_alive()
