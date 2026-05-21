import json

import pytest

from tunnel_manager.backends.base import VPNInfo
from tunnel_manager.backends.windows import WindowsBackend


def test_windows_detect_parser_scores_vpn_adapter():
    out = json.dumps(
        [
            {
                "InterfaceIndex": 3,
                "InterfaceAlias": "Ethernet",
                "NextHop": "192.168.0.1",
                "Metric": 25,
                "Description": "Intel Ethernet",
                "IsHardware": True,
            },
            {
                "InterfaceIndex": 50,
                "InterfaceAlias": "WireGuard Tunnel",
                "NextHop": "0.0.0.0",
                "Metric": 1,
                "Description": "WireGuard Tunnel",
                "IsHardware": False,
            },
        ]
    )

    info = WindowsBackend()._parse_detect_vpn_output(out)

    assert info is not None
    assert info.interface == "50"
    assert info.gateway == "0.0.0.0"
    assert info.local_gateway == "192.168.0.1"
    assert info.local_interface == "3"


def test_windows_detect_parser_accepts_single_object():
    out = json.dumps(
        {
            "InterfaceIndex": 42,
            "InterfaceAlias": "VPN",
            "NextHop": "0.0.0.0",
            "Metric": 1,
            "Description": "RAS VPN",
            "IsHardware": False,
        }
    )

    info = WindowsBackend()._parse_detect_vpn_output(out)

    assert info is not None
    assert info.interface == "42"


def test_windows_detect_parser_rejects_invalid_output():
    assert WindowsBackend()._parse_detect_vpn_output("") is None
    assert WindowsBackend()._parse_detect_vpn_output("{not json") is None
    assert WindowsBackend()._parse_detect_vpn_output("[]") is None


@pytest.mark.asyncio
async def test_windows_async_add_uses_persistent_store_when_requested(monkeypatch):
    backend = WindowsBackend()
    captured: list[list[str]] = []

    async def fake_netsh(args: list[str]):
        captured.append(args)
        import subprocess

        return subprocess.CompletedProcess(["netsh", *args], 0, "", "")

    monkeypatch.setattr(backend, "_async_netsh", fake_netsh)

    await backend.add_routes_async(
        ["1.2.3.4/32"],
        VPNInfo(interface="50", gateway="0.0.0.0", persistent_routes=True),
    )

    assert captured
    assert "store=persistent" in captured[0]
