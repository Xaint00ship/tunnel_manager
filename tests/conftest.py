"""Shared fixtures + a MockBackend for testing the orchestration layer."""

from __future__ import annotations

from pathlib import Path

import pytest

from tunnel_manager.backends.base import AddResult, RouteBackend, VPNInfo


class MockBackend(RouteBackend):
    """In-memory backend for testing — no system calls."""

    def __init__(
        self,
        vpn: VPNInfo | None = None,
        privileged: bool = True,
        existing: set[str] | None = None,
        add_failures: dict[str, str] | None = None,
    ):
        self._vpn = vpn
        self._privileged = privileged
        self.routes: set[str] = set(existing or set())
        self.add_failures = add_failures or {}
        self.calls: list[tuple[str, tuple]] = []

    def name(self) -> str:
        return "mock"

    def is_privileged(self) -> bool:
        return self._privileged

    def detect_vpn(self) -> VPNInfo | None:
        self.calls.append(("detect_vpn", ()))
        return self._vpn

    def set_vpn(self, info: VPNInfo | None) -> None:
        self._vpn = info

    def remove_default_vpn_route(self, info: VPNInfo) -> None:
        self.calls.append(("remove_default_vpn_route", (info.interface,)))

    def add_routes(self, entries: list[str], info: VPNInfo) -> AddResult:
        self.calls.append(("add_routes", (tuple(entries), info.interface)))
        added, failed = [], []
        for e in entries:
            err = self.add_failures.get(e)
            if err:
                failed.append((e, err))
            else:
                self.routes.add(e if "/" in e else f"{e}/32")
                added.append(e)
        return AddResult(added=added, failed=failed)

    def remove_routes(self, entries: list[str], info: VPNInfo) -> None:
        self.calls.append(("remove_routes", (tuple(entries), info.interface)))
        for e in entries:
            self.routes.discard(e if "/" in e else f"{e}/32")

    def list_vpn_routes(self, info: VPNInfo) -> list[str]:
        self.calls.append(("list_vpn_routes", (info.interface,)))
        return sorted(self.routes)


@pytest.fixture
def mock_vpn() -> VPNInfo:
    return VPNInfo(
        interface="50",
        gateway="0.0.0.0",
        local_gateway="192.168.0.1",
        local_interface="3",
    )


@pytest.fixture
def mock_backend(mock_vpn: VPNInfo) -> MockBackend:
    return MockBackend(vpn=mock_vpn)


@pytest.fixture
def list_file(tmp_path: Path) -> Path:
    p = tmp_path / "list.txt"
    p.write_bytes(
        b"Meta\n1.1.1.1\n2.2.2.2/24\nDiscord\n3.3.3.3\n"
    )
    return p
