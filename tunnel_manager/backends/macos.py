"""macOS route backend — `route` command via sudo."""

from __future__ import annotations

import os
import subprocess
from typing import Optional

from .base import AddResult, RouteBackend, VPNInfo


class MacOSBackend(RouteBackend):
    VPN_IFACE_PREFIXES = ("ipsec", "utun", "ppp")

    def name(self) -> str:
        return "macos"

    def is_privileged(self) -> bool:
        return hasattr(os, "geteuid") and os.geteuid() == 0

    def _sudo(self, argv: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["sudo", "-n"] + argv, capture_output=True, text=True
        )

    # ── detection ──────────────────────────────────────────────────────

    def detect_vpn(self) -> Optional[VPNInfo]:
        out = subprocess.check_output(["netstat", "-rn", "-f", "inet"], text=True)
        vpn_iface = vpn_gw = local_gw = local_iface = None
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            dest, gw, iface = parts[0], parts[1], parts[-1]
            if dest not in ("default", "0/1", "128.0/1"):
                continue
            if any(iface.startswith(p) for p in self.VPN_IFACE_PREFIXES):
                if vpn_iface is None or dest == "default":
                    vpn_iface = iface
                    vpn_gw = None if gw.startswith("link#") else gw
            elif iface.startswith(("en", "eth", "wlan")) and local_gw is None:
                if not gw.startswith("link#"):
                    local_gw = gw
                    local_iface = iface
        if not vpn_iface:
            return None
        return VPNInfo(
            interface=vpn_iface, gateway=vpn_gw,
            local_gateway=local_gw, local_interface=local_iface,
        )

    def _is_ipsec(self, info: VPNInfo) -> bool:
        return info.interface.startswith("ipsec")

    @staticmethod
    def _route_flag(entry: str) -> str:
        return "-net" if "/" in entry else "-host"

    # ── default route mgmt ─────────────────────────────────────────────

    def remove_default_vpn_route(self, info: VPNInfo) -> None:
        for dest in ("default", "0/1", "128.0/1"):
            self._sudo(["route", "delete", dest, "-interface", info.interface])
        if info.local_gateway and info.local_interface:
            # macOS scopes the restored ISP default to the interface (flag I); without
            # a global default sockets can't route outbound. Re-add as global.
            self._sudo(
                ["route", "delete", "default", "-ifscope",
                 info.local_interface, info.local_gateway]
            )
            r = self._sudo(["route", "add", "default", info.local_gateway])
            if r.returncode != 0:
                self._sudo(["route", "change", "default", info.local_gateway])

    # ── add/remove ─────────────────────────────────────────────────────

    def _add_argv(self, entry: str, info: VPNInfo) -> Optional[list[str]]:
        flag = self._route_flag(entry)
        if self._is_ipsec(info):
            return ["route", "add", flag, entry, "-interface", info.interface]
        if info.gateway:
            return ["route", "add", flag, entry, info.gateway]
        return None

    def add_routes(self, entries: list[str], info: VPNInfo) -> AddResult:
        added: list[str] = []
        failed: list[tuple[str, str]] = []
        for entry in entries:
            argv = self._add_argv(entry, info)
            if argv is None:
                failed.append((entry, "no VPN gateway available"))
                continue
            r = self._sudo(argv)
            if r.returncode == 0 or "File exists" in r.stderr:
                added.append(entry)
            else:
                failed.append((entry, (r.stderr or "route add failed").strip()))
        return AddResult(added=added, failed=failed)

    def remove_routes(self, entries: list[str], info: VPNInfo) -> None:
        for entry in entries:
            flag = self._route_flag(entry)
            self._sudo(["route", "delete", flag, entry, "-interface", info.interface])

    def list_vpn_routes(self, info: VPNInfo) -> list[str]:
        out = subprocess.check_output(["netstat", "-rn", "-f", "inet"], text=True)
        routes = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            dest, iface = parts[0], parts[-1]
            if iface != info.interface:
                continue
            if dest in ("default", "0/1", "128.0/1"):
                continue
            routes.append(dest)
        return routes
