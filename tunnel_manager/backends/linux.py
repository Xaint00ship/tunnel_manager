"""Linux route backend — `ip` command with `-batch` stdin for speed.

Handles IPv4 and IPv6 by inspecting each entry's address family and
dispatching to `ip -4` / `ip -6` accordingly.
"""

from __future__ import annotations

import os
import re
import subprocess

from ..parser import address_family
from .base import AddResult, RouteBackend, VPNInfo


class LinuxBackend(RouteBackend):
    VPN_IFACE_RE = re.compile(r"^(utun|tun|wg|tap|xfrm|ppp|ipsec)\d*$")

    def name(self) -> str:
        return "linux"

    def is_privileged(self) -> bool:
        return hasattr(os, "geteuid") and os.geteuid() == 0

    def _sudo_ip(self, family_flag: str, argv: list[str]) -> subprocess.CompletedProcess:
        cmd = ["sudo", "-n", "ip"]
        if family_flag:
            cmd.append(family_flag)
        cmd.extend(argv)
        return subprocess.run(cmd, capture_output=True, text=True)

    def _sudo_ip_batch(
        self, family_flag: str, cmds: list[str]
    ) -> subprocess.CompletedProcess:
        prefix = ["sudo", "-n", "ip"]
        if family_flag:
            prefix.append(family_flag)
        prefix.extend(["-force", "-batch", "-"])
        return subprocess.run(
            prefix, input="\n".join(cmds) + "\n", capture_output=True, text=True
        )

    @staticmethod
    def _normalize(entry: str) -> str:
        if "/" in entry:
            return entry
        return f"{entry}/32" if address_family(entry) == 4 else f"{entry}/128"

    @staticmethod
    def _family(entry: str) -> int:
        return address_family(entry.split("/")[0])

    # ── detection ──────────────────────────────────────────────────────

    def detect_vpn(self) -> VPNInfo | None:
        out = subprocess.check_output(["ip", "route"], text=True)
        vpn: VPNInfo | None = None
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
        for fam in ("-4", "-6"):
            self._sudo_ip(fam, ["route", "del", "default", "dev", info.interface])
        if info.local_gateway:
            self._sudo_ip("-4", ["route", "add", "default", "via", info.local_gateway])

    # ── add/remove ─────────────────────────────────────────────────────

    def _split_by_family(
        self, entries: list[str]
    ) -> tuple[list[str], list[str]]:
        v4: list[str] = []
        v6: list[str] = []
        for e in entries:
            (v6 if self._family(e) == 6 else v4).append(e)
        return v4, v6

    def add_routes(self, entries: list[str], info: VPNInfo) -> AddResult:
        if not entries:
            return AddResult(added=[], failed=[])
        added: list[str] = []
        failed: list[tuple[str, str]] = []
        v4, v6 = self._split_by_family(entries)
        for fam, group in (("-4", v4), ("-6", v6)):
            if not group:
                continue
            cmds = []
            for e in group:
                dest = self._normalize(e)
                if info.gateway and fam == "-4":
                    cmds.append(f"route add {dest} dev {info.interface} via {info.gateway}")
                else:
                    cmds.append(f"route add {dest} dev {info.interface}")
            r = self._sudo_ip_batch(fam, cmds)
            if r.returncode == 0:
                added.extend(group)
                continue
            for e in group:
                dest = self._normalize(e)
                args = ["route", "add", dest, "dev", info.interface]
                if info.gateway and fam == "-4":
                    args += ["via", info.gateway]
                res = self._sudo_ip(fam, args)
                if res.returncode == 0 or "File exists" in res.stderr:
                    added.append(e)
                else:
                    failed.append((e, (res.stderr or "ip route add failed").strip()))
        return AddResult(added=added, failed=failed)

    def remove_routes(self, entries: list[str], info: VPNInfo) -> None:
        if not entries:
            return
        v4, v6 = self._split_by_family(entries)
        for fam, group in (("-4", v4), ("-6", v6)):
            if not group:
                continue
            cmds = [f"route del {self._normalize(e)} dev {info.interface}" for e in group]
            self._sudo_ip_batch(fam, cmds)

    def list_vpn_routes(self, info: VPNInfo) -> list[str]:
        routes: list[str] = []
        for fam in ("-4", "-6"):
            try:
                out = subprocess.check_output(
                    ["ip", fam, "route", "show", "dev", info.interface], text=True
                )
            except subprocess.CalledProcessError:
                continue
            for line in out.splitlines():
                parts = line.split()
                if not parts or parts[0] == "default":
                    continue
                routes.append(parts[0])
        return routes
