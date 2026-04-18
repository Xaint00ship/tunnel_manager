"""Shared fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from tunnel_manager.backends.base import VPNInfo

from ._mocks import MockBackend


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
    # Use a properly-aligned /24 so the aggregator's CIDR normalization
    # leaves it in the same form (2.2.2.0/24 stays 2.2.2.0/24).
    p.write_bytes(
        b"Meta\n1.1.1.1\n2.2.2.0/24\nDiscord\n3.3.3.3\n"
    )
    return p
