"""Persistent state — survives crashes so we can reconcile dangling routes."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

STATE_DIR = Path.home() / ".tunnel_manager"


class StateFile:
    def __init__(self, path: Optional[Path] = None):
        self.path = path or (STATE_DIR / "state.json")
        self.data: dict = self._load()

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}

    def save(self, **fields) -> None:
        self.data.update(fields)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(self.data, indent=2, default=str), encoding="utf-8"
        )

    def clear(self) -> None:
        if self.path.exists():
            try:
                self.path.unlink()
            except OSError:
                pass
        self.data = {}

    def previous_routes(self) -> list[str]:
        return list(self.data.get("active_routes", []))

    @staticmethod
    def is_pid_alive(pid: int) -> bool:
        if pid <= 0:
            return False
        if os.name == "nt":
            import ctypes

            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid)
            )
            if not handle:
                return False
            # Check exit code — STILL_ACTIVE (259) means process is alive.
            exit_code = ctypes.c_ulong()
            ok = kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
            kernel32.CloseHandle(handle)
            return bool(ok and exit_code.value == 259)
        try:
            os.kill(int(pid), 0)
            return True
        except (OSError, ProcessLookupError, PermissionError):
            return False
