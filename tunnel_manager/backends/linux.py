"""Linux route backend — `ip` command with `-batch` stdin for speed."""

from __future__ import annotations

import os
import re
import subprocess
from typing import Optional

from .base import AddResult, RouteBackend, VPNInfo


class LinuxBackend(RouteBackend):
    VPN_IFACE_RE = re.compile(r"^(utun|tun|wg|tap|xfrm|ppp|ipsec)\d*$")

    def name(self) -> str:
        return "linux"

    def is_privileged(self) -> bool:
        return hasattr(os, "geteuid") and os.geteuid() == 0

    def _sudo_ip(self, argv: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["sudo", "-n", "ip"] + argv, capture_output=True, text=True
        )

    def _sudo_ip_batch(self, cmds: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["sudo", "-n", "ip", "-force", "-batch", "-"],
            input="\n".join(cmds) + "\n",
            capture_output=True, text=True,
        )

    @staticmethod
    def _normalize(entry: str) -> str:
        return entry if "/" in entry else f"{entry}/32"

    # ── detection ──────────────────────────────────────────────────────

    def detect_vpn(self) -> Optional[VPNInfo]:
        out = subprocess.check_output(["ip", "route"], text=True)
        vpn: Optional[VPNInfo] = None
        isp_gw = isp_if = None
        for line in out.splitlines():
            parts = line.split()
            if not parts or parts[0] != "default":
                continue
            via = parts[parts.index("via") + 1] if "via" in parts else None
            dev = parts[parts.index("dev") + 1] if "dev" in parts else None
            if not dev:
                continue
            if self.VPN_IFACE_RE.match(dev):
                if vpn is None:
                    vpn = VPNInfo(interface=dev, gateway=via)
            elif isp_gw is None:
                isp_gw = via
                isp_if = dev
        if vpn:
            vpn.local_gateway = isp_gw
            vpn.local_interface = isp_if
            return vpn
        return None

    # ── default route mgmt ─────────────────────────────────────────────

    def remove_default_vpn_route(self, info: VPNInfo) -> None:
        self._sudo_ip(["route", "del", "default", "dev", info.interface])
        if info.local_gateway:
            self._sudo_ip(["route", "add", "default", "via", info.local_gateway])

    # ── add/remove ─────────────────────────────────────────────────────

    def add_routes(self, entries: list[str], info: VPNInfo) -> AddResult:
        if not entries:
            return AddResult(added=[], failed=[])
        cmds: list[str] = []
        for e in entries:
            dest = self._normalize(e)
            if info.gateway:
                cmds.append(f"route add {dest} dev {info.interface} via {info.gateway}")
            else:
                cmds.append(f"route add {dest} dev {info.interface}")
        r = self._sudo_ip_batch(cmds)
        if r.returncode == 0:
            return AddResult(added=list(entries), failed=[])
        # Batch failed somewhere — fall back to per-entry for accurate reporting.
        added: list[str] = []
        failed: list[tuple[str, str]] = []
        for e in entries:
            dest = self._normalize(e)
            args = ["route", "add", dest, "dev", info.interface]
            if info.gateway:
                args += ["via", info.gateway]
            res = self._sudo_ip(args)
            if res.returncode == 0 or "File exists" in res.stderr:
                added.append(e)
            else:
                failed.append((e, (res.stderr or "ip route add failed").strip()))
        return AddResult(added=added, failed=failed)

    def remove_routes(self, entries: list[str], info: VPNInfo) -> None:
        if not entries:
            return
        cmds = [f"route del {self._normalize(e)} dev {info.interface}" for e in entries]
        self._sudo_ip_batch(cmds)

    def list_vpn_routes(self, info: VPNInfo) -> list[str]:
        out = subprocess.check_output(
            ["ip", "route", "show", "dev", info.interface], text=True
        )
        routes = []
        for line in out.splitlines():
            parts = line.split()
            if not parts or parts[0] == "default":
                continue
            routes.append(parts[0])
        return routes
