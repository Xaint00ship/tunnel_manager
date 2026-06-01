"""Abstract route backend — each platform implements this."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass

SUBPROCESS_TIMEOUT = 30
BATCH_TIMEOUT = 60


@dataclass
class VPNInfo:
    interface: str  # iface name on *nix, ifIndex (as str) on Windows
    gateway: str | None  # None / "0.0.0.0" / link-layer → "no next hop"
    local_gateway: str | None = None
    local_interface: str | None = None
    persistent_routes: bool = False

    def describe(self) -> str:
        s = self.interface
        if self.gateway and self.gateway != "0.0.0.0":
            s += f" via {self.gateway}"
        return s


@dataclass
class AddResult:
    added: list[str]
    failed: list[tuple[str, str]]  # (entry, error message)

    @property
    def count(self) -> int:
        return len(self.added)

    @property
    def failure_count(self) -> int:
        return len(self.failed)


class RouteBackend(ABC):
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def is_privileged(self) -> bool: ...

    @abstractmethod
    def detect_vpn(self) -> VPNInfo | None: ...

    @abstractmethod
    def remove_default_vpn_route(self, info: VPNInfo) -> None: ...

    @abstractmethod
    def add_routes(self, entries: list[str], info: VPNInfo) -> AddResult: ...

    @abstractmethod
    def remove_routes(self, entries: list[str], info: VPNInfo) -> None: ...

    @abstractmethod
    def list_vpn_routes(self, info: VPNInfo) -> list[str]:
        """All routes on the VPN interface except the catch-all defaults."""

    def is_interface_up(self, iface: str) -> bool:
        """Return True if the named interface exists and is UP. Override per platform."""
        return False

    def health_check(self) -> tuple[bool, str]:
        """Return whether the backend is ready to modify system routes."""
        if not self.is_privileged():
            return False, "insufficient privileges"
        return True, "ok"

    def supports_persistent_routes(self) -> bool:
        """Whether add_routes can ask the OS to persist routes across reboots."""
        return False

    async def detect_vpn_async(self) -> VPNInfo | None:
        return await asyncio.to_thread(self.detect_vpn)

    async def remove_default_vpn_route_async(self, info: VPNInfo) -> None:
        await asyncio.to_thread(self.remove_default_vpn_route, info)

    async def add_routes_async(self, entries: list[str], info: VPNInfo) -> AddResult:
        return await asyncio.to_thread(self.add_routes, entries, info)

    async def remove_routes_async(self, entries: list[str], info: VPNInfo) -> None:
        await asyncio.to_thread(self.remove_routes, entries, info)

    def block_routes(self, entries: list[str]) -> None:
        """Install fail-closed blocks for routes that must not use the public default."""
        _ = entries

    def unblock_routes(self, entries: list[str]) -> None:
        """Remove fail-closed blocks installed by block_routes."""
        _ = entries

    def has_default_vpn_route(self, info: VPNInfo) -> bool:
        """Return True when a catch-all default currently points at the VPN."""
        _ = info
        return False

    async def block_routes_async(self, entries: list[str]) -> None:
        await asyncio.to_thread(self.block_routes, entries)

    async def unblock_routes_async(self, entries: list[str]) -> None:
        await asyncio.to_thread(self.unblock_routes, entries)

    async def list_vpn_routes_async(self, info: VPNInfo) -> list[str]:
        return await asyncio.to_thread(self.list_vpn_routes, info)

    async def is_interface_up_async(self, iface: str) -> bool:
        return await asyncio.to_thread(self.is_interface_up, iface)

    async def has_default_vpn_route_async(self, info: VPNInfo) -> bool:
        return await asyncio.to_thread(self.has_default_vpn_route, info)
