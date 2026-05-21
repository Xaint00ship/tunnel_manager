"""Linux route backend — `ip` command with `-batch` stdin for speed.

Handles IPv4 and IPv6 by inspecting each entry's address family and
dispatching to `ip -4` / `ip -6` accordingly.
"""

from __future__ import annotations

import asyncio
import os
import re
import subprocess

from ..parser import address_family
from .base import BATCH_TIMEOUT, SUBPROCESS_TIMEOUT, AddResult, RouteBackend, VPNInfo


class LinuxBackend(RouteBackend):
    VPN_IFACE_RE = re.compile(r"^(utun|tun|wg|tap|xfrm|ppp|ipsec)\d*$")

    def name(self) -> str:
        return "linux"

    def is_privileged(self) -> bool:
        return hasattr(os, "geteuid") and os.geteuid() == 0

    def health_check(self) -> tuple[bool, str]:
        if not self.is_privileged():
            return False, "insufficient privileges"
        try:
            subprocess.run(
                ["ip", "-Version"],
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT,
                check=False,
            )
        except FileNotFoundError:
            return False, "`ip` command not found"
        except subprocess.TimeoutExpired:
            return False, "`ip` command timed out"
        return True, "ok"

    def _sudo_ip(self, family_flag: str, argv: list[str]) -> subprocess.CompletedProcess:
        cmd = ["sudo", "-n", "ip"]
        if family_flag:
            cmd.append(family_flag)
        cmd.extend(argv)
        return subprocess.run(cmd, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT)

    def _sudo_ip_batch(self, family_flag: str, cmds: list[str]) -> subprocess.CompletedProcess:
        prefix = ["sudo", "-n", "ip"]
        if family_flag:
            prefix.append(family_flag)
        prefix.extend(["-force", "-batch", "-"])
        return subprocess.run(
            prefix,
            input="\n".join(cmds) + "\n",
            capture_output=True,
            text=True,
            timeout=BATCH_TIMEOUT,
        )

    async def _run_async(
        self,
        cmd: list[str],
        *,
        input_text: str | None = None,
        timeout: int = SUBPROCESS_TIMEOUT,
    ) -> subprocess.CompletedProcess:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if input_text is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input_text.encode() if input_text is not None else None),
                timeout=timeout,
            )
        except TimeoutError:
            proc.kill()
            await proc.wait()
            raise RuntimeError(f"{cmd[0]} timeout after {timeout}s") from None
        return subprocess.CompletedProcess(
            cmd,
            proc.returncode or 0,
            stdout.decode(errors="replace") if stdout else "",
            stderr.decode(errors="replace") if stderr else "",
        )

    async def _sudo_ip_async(
        self, family_flag: str, argv: list[str]
    ) -> subprocess.CompletedProcess:
        cmd = ["sudo", "-n", "ip"]
        if family_flag:
            cmd.append(family_flag)
        cmd.extend(argv)
        return await self._run_async(cmd)

    async def _sudo_ip_batch_async(
        self, family_flag: str, cmds: list[str]
    ) -> subprocess.CompletedProcess:
        prefix = ["sudo", "-n", "ip"]
        if family_flag:
            prefix.append(family_flag)
        prefix.extend(["-force", "-batch", "-"])
        return await self._run_async(
            prefix, input_text="\n".join(cmds) + "\n", timeout=BATCH_TIMEOUT
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

    def _parse_default_routes(self, out: str) -> tuple[VPNInfo | None, str | None, str | None]:
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
        return vpn, isp_gw, isp_if

    def _vpn_from_links(self, links: str, isp_gw: str | None, isp_if: str | None) -> VPNInfo | None:
        for line in links.splitlines():
            m = re.search(r"^\d+: (\S+?)[@:]", line)
            if not m:
                continue
            iface = m.group(1)
            if self.VPN_IFACE_RE.match(iface) and ("UP" in line or "LOWER_UP" in line):
                return VPNInfo(
                    interface=iface, gateway=None, local_gateway=isp_gw, local_interface=isp_if
                )
        return None

    def detect_vpn(self) -> VPNInfo | None:
        out = subprocess.check_output(["ip", "route"], text=True, timeout=SUBPROCESS_TIMEOUT)
        vpn, isp_gw, isp_if = self._parse_default_routes(out)
        if vpn:
            return vpn

        # No default route via VPN: tunnel_manager may have already replaced it
        # with specific routes. Fall back to any UP VPN-like interface.
        try:
            links = subprocess.check_output(["ip", "link"], text=True, timeout=SUBPROCESS_TIMEOUT)
        except subprocess.CalledProcessError:
            return None
        return self._vpn_from_links(links, isp_gw, isp_if)

    async def detect_vpn_async(self) -> VPNInfo | None:
        r = await self._run_async(["ip", "route"])
        if r.returncode != 0:
            raise RuntimeError((r.stderr or "ip route failed").strip())
        vpn, isp_gw, isp_if = self._parse_default_routes(r.stdout)
        if vpn:
            return vpn
        links = await self._run_async(["ip", "link"])
        if links.returncode != 0:
            return None
        return self._vpn_from_links(links.stdout, isp_gw, isp_if)

    # ── default route mgmt ─────────────────────────────────────────────

    def remove_default_vpn_route(self, info: VPNInfo) -> None:
        for fam in ("-4", "-6"):
            self._sudo_ip(fam, ["route", "del", "default", "dev", info.interface])
        if info.local_gateway:
            self._sudo_ip("-4", ["route", "add", "default", "via", info.local_gateway])

    async def remove_default_vpn_route_async(self, info: VPNInfo) -> None:
        await asyncio.gather(
            *[
                self._sudo_ip_async(fam, ["route", "del", "default", "dev", info.interface])
                for fam in ("-4", "-6")
            ],
            return_exceptions=True,
        )
        if info.local_gateway:
            await self._sudo_ip_async("-4", ["route", "add", "default", "via", info.local_gateway])

    # ── add/remove ─────────────────────────────────────────────────────

    def _split_by_family(self, entries: list[str]) -> tuple[list[str], list[str]]:
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

    async def add_routes_async(self, entries: list[str], info: VPNInfo) -> AddResult:
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
            r = await self._sudo_ip_batch_async(fam, cmds)
            if r.returncode == 0:
                added.extend(group)
                continue
            for e in group:
                dest = self._normalize(e)
                args = ["route", "add", dest, "dev", info.interface]
                if info.gateway and fam == "-4":
                    args += ["via", info.gateway]
                res = await self._sudo_ip_async(fam, args)
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

    async def remove_routes_async(self, entries: list[str], info: VPNInfo) -> None:
        if not entries:
            return
        v4, v6 = self._split_by_family(entries)
        for fam, group in (("-4", v4), ("-6", v6)):
            if not group:
                continue
            cmds = [f"route del {self._normalize(e)} dev {info.interface}" for e in group]
            await self._sudo_ip_batch_async(fam, cmds)

    def is_interface_up(self, iface: str) -> bool:
        try:
            out = subprocess.check_output(
                ["ip", "link", "show", iface],
                text=True,
                timeout=SUBPROCESS_TIMEOUT,
            )
            return "state UP" in out or "LOWER_UP" in out
        except subprocess.CalledProcessError:
            return False

    async def is_interface_up_async(self, iface: str) -> bool:
        r = await self._run_async(["ip", "link", "show", iface])
        if r.returncode != 0:
            return False
        return "state UP" in r.stdout or "LOWER_UP" in r.stdout

    def list_vpn_routes(self, info: VPNInfo) -> list[str]:
        routes: list[str] = []
        for fam in ("-4", "-6"):
            try:
                out = subprocess.check_output(
                    ["ip", fam, "route", "show", "dev", info.interface],
                    text=True,
                    timeout=SUBPROCESS_TIMEOUT,
                )
            except subprocess.CalledProcessError:
                continue
            for line in out.splitlines():
                parts = line.split()
                if not parts or parts[0] == "default":
                    continue
                routes.append(parts[0])
        return routes

    async def list_vpn_routes_async(self, info: VPNInfo) -> list[str]:
        routes: list[str] = []
        for fam in ("-4", "-6"):
            r = await self._run_async(["ip", fam, "route", "show", "dev", info.interface])
            if r.returncode != 0:
                continue
            for line in r.stdout.splitlines():
                parts = line.split()
                if not parts or parts[0] == "default":
                    continue
                routes.append(parts[0])
        return routes
