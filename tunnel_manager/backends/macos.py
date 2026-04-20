"""macOS route backend — `route` command via sudo.

Handles IPv4 and IPv6 by dispatching `route ... -inet` / `-inet6`
based on each entry's address family.
"""

from __future__ import annotations

import ipaddress
import os
import subprocess

from ..parser import address_family
from .base import AddResult, RouteBackend, VPNInfo


class MacOSBackend(RouteBackend):
    VPN_IFACE_PREFIXES = ("ipsec", "utun", "ppp")

    def name(self) -> str:
        return "macos"

    def is_privileged(self) -> bool:
        return hasattr(os, "geteuid") and os.geteuid() == 0

    def _sudo(self, argv: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(["sudo", "-n", *argv], capture_output=True, text=True)

    @staticmethod
    def _family(entry: str) -> int:
        return address_family(entry.split("/")[0])

    @staticmethod
    def _route_flag(entry: str) -> str:
        return "-net" if "/" in entry else "-host"

    @staticmethod
    def _family_flag(entry: str) -> str:
        return "-inet6" if MacOSBackend._family(entry) == 6 else "-inet"

    # ── detection ──────────────────────────────────────────────────────

    def detect_vpn(self) -> VPNInfo | None:
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
            elif (
                iface.startswith(("en", "eth", "wlan"))
                and local_gw is None
                and not gw.startswith("link#")
            ):
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

    # ── default route mgmt ─────────────────────────────────────────────

    def remove_default_vpn_route(self, info: VPNInfo) -> None:
        for dest in ("default", "0/1", "128.0/1"):
            self._sudo(["route", "delete", dest, "-interface", info.interface])
        # Also try IPv6 default:
        self._sudo(["route", "delete", "-inet6", "default", "-interface", info.interface])
        if info.local_gateway and info.local_interface:
            self._sudo(
                ["route", "delete", "default", "-ifscope",
                 info.local_interface, info.local_gateway]
            )
            r = self._sudo(["route", "add", "default", info.local_gateway])
            if r.returncode != 0:
                self._sudo(["route", "change", "default", info.local_gateway])

    # ── add/remove ─────────────────────────────────────────────────────

    def _add_argv(self, entry: str, info: VPNInfo) -> list[str] | None:
        flag = self._route_flag(entry)
        family = self._family_flag(entry)
        if self._is_ipsec(info):
            return ["route", "add", family, flag, entry, "-interface", info.interface]
        if info.gateway and self._family(entry) == 4:
            return ["route", "add", family, flag, entry, info.gateway]
        # IPv6 or no gateway → fall back to interface routing
        return ["route", "add", family, flag, entry, "-interface", info.interface]

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
            try:
                flag = self._route_flag(entry)
                family = self._family_flag(entry)
            except ValueError:
                continue
            self._sudo(
                ["route", "delete", family, flag, entry, "-interface", info.interface]
            )

    def is_interface_up(self, iface: str) -> bool:
        try:
            out = subprocess.check_output(["ifconfig", iface], text=True, stderr=subprocess.DEVNULL)
            return "status: active" in out or "flags=" in out
        except subprocess.CalledProcessError:
            return False

    def list_vpn_routes(self, info: VPNInfo) -> list[str]:
        routes: list[str] = []
        for family_flag in ("inet", "inet6"):
            try:
                out = subprocess.check_output(
                    ["netstat", "-rn", "-f", family_flag], text=True
                )
            except subprocess.CalledProcessError:
                continue
            for line in out.splitlines():
                parts = line.split()
                if len(parts) < 4:
                    continue
                dest, iface = parts[0], parts[-1]
                if iface != info.interface:
                    continue
                if dest in ("default", "0/1", "128.0/1"):
                    continue
                try:
                    ipaddress.ip_network(dest, strict=False)
                except ValueError:
                    continue
                routes.append(dest)
        return routes
