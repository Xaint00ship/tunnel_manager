"""Abstract route backend — each platform implements this."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class VPNInfo:
    interface: str                    # iface name on *nix, ifIndex (as str) on Windows
    gateway: str | None            # None / "0.0.0.0" / link-layer → "no next hop"
    local_gateway: str | None = None
    local_interface: str | None = None

    def describe(self) -> str:
        s = self.interface
        if self.gateway and self.gateway != "0.0.0.0":
            s += f" via {self.gateway}"
        return s


@dataclass
class AddResult:
    added: list[str]
    failed: list[tuple[str, str]]     # (entry, error message)

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
