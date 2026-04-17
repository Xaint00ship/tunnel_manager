"""Platform-specific routing backends."""

from __future__ import annotations

import platform

from .base import AddResult, RouteBackend, VPNInfo


def get_backend() -> RouteBackend:
    system = platform.system()
    if system == "Windows":
        from .windows import WindowsBackend
        return WindowsBackend()
    if system == "Darwin":
        from .macos import MacOSBackend
        return MacOSBackend()
    if system == "Linux":
        from .linux import LinuxBackend
        return LinuxBackend()
    raise RuntimeError(f"Unsupported platform: {system}")


__all__ = ["AddResult", "RouteBackend", "VPNInfo", "get_backend"]
