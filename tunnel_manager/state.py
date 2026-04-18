"""Persistent state — survives crashes so we can reconcile dangling routes.

Liveness is decided by both PID and a periodically-updated heartbeat: a
stale PID file from a kill -9'd process won't block the next start once
the heartbeat ages out.
"""

from __future__ import annotations

import contextlib
import json
import os
import time
from pathlib import Path

from .paths import STATE_FILE

HEARTBEAT_TIMEOUT_SECONDS = 90


class StateFile:
    def __init__(self, path: Path | None = None):
        self.path = path or STATE_FILE
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

    def heartbeat(self) -> None:
        self.save(heartbeat=int(time.time()))

    def clear(self) -> None:
        if self.path.exists():
            with contextlib.suppress(OSError):
                self.path.unlink()
        self.data = {}

    def previous_routes(self) -> list[str]:
        return list(self.data.get("active_routes", []))

    def previous_interface(self) -> str | None:
        iface = self.data.get("vpn_interface")
        return str(iface) if iface else None

    def previous_gateway(self) -> str | None:
        gw = self.data.get("vpn_gateway")
        return str(gw) if gw else None

    def is_another_instance_alive(self) -> bool:
        """True only when both PID and heartbeat say a peer is alive."""
        pid = int(self.data.get("pid") or 0)
        if pid <= 0 or pid == os.getpid():
            return False
        if not self.is_pid_alive(pid):
            return False
        last = int(self.data.get("heartbeat") or 0)
        return not (last and (time.time() - last) > HEARTBEAT_TIMEOUT_SECONDS)

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
            exit_code = ctypes.c_ulong()
            ok = kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
            kernel32.CloseHandle(handle)
            return bool(ok and exit_code.value == 259)
        try:
            os.kill(int(pid), 0)
            return True
        except (OSError, ProcessLookupError, PermissionError):
            return False
