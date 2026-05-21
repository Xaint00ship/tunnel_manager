"""macOS route backend - `route` command via sudo.

Handles IPv4 and IPv6 by dispatching `route ... -inet` / `-inet6`
based on each entry's address family.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import subprocess

from ..parser import address_family
from .base import SUBPROCESS_TIMEOUT, AddResult, RouteBackend, VPNInfo


class MacOSBackend(RouteBackend):
    VPN_IFACE_PREFIXES = ("ipsec", "utun", "ppp")

    def name(self) -> str:
        return "macos"

    def is_privileged(self) -> bool:
        return hasattr(os, "geteuid") and os.geteuid() == 0

    def health_check(self) -> tuple[bool, str]:
        if not self.is_privileged():
            return False, "insufficient privileges"
        try:
            subprocess.run(
                ["netstat", "-rn", "-f", "inet"],
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT,
                check=False,
            )
        except FileNotFoundError:
            return False, "`netstat` command not found"
        except subprocess.TimeoutExpired:
            return False, "`netstat` command timed out"
        return True, "ok"

    def _sudo(self, argv: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["sudo", "-n", *argv],
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
        )

    async def _run_async(
        self, cmd: list[str], *, timeout: int = SUBPROCESS_TIMEOUT
    ) -> subprocess.CompletedProcess:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
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

    async def _sudo_async(self, argv: list[str]) -> subprocess.CompletedProcess:
        return await self._run_async(["sudo", "-n", *argv])

    @staticmethod
    def _family(entry: str) -> int:
        return address_family(entry.split("/")[0])

    @staticmethod
    def _route_flag(entry: str) -> str:
        return "-net" if "/" in entry else "-host"

    @staticmethod
    def _family_flag(entry: str) -> str:
        return "-inet6" if MacOSBackend._family(entry) == 6 else "-inet"

    # -- detection -----------------------------------------------------

    def _parse_netstat_defaults(self, out: str) -> VPNInfo | None:
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
            interface=vpn_iface,
            gateway=vpn_gw,
            local_gateway=local_gw,
            local_interface=local_iface,
        )

    def detect_vpn(self) -> VPNInfo | None:
        out = subprocess.check_output(
            ["netstat", "-rn", "-f", "inet"],
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
        )
        return self._parse_netstat_defaults(out)

    async def detect_vpn_async(self) -> VPNInfo | None:
        r = await self._run_async(["netstat", "-rn", "-f", "inet"])
        if r.returncode != 0:
            raise RuntimeError((r.stderr or "netstat failed").strip())
        return self._parse_netstat_defaults(r.stdout)

    # -- default route mgmt -------------------------------------------

    def _is_ipsec(self, info: VPNInfo) -> bool:
        return info.interface.startswith("ipsec")

    def remove_default_vpn_route(self, info: VPNInfo) -> None:
        for dest in ("default", "0/1", "128.0/1"):
            self._sudo(["route", "delete", dest, "-interface", info.interface])
        self._sudo(["route", "delete", "-inet6", "default", "-interface", info.interface])
        if info.local_gateway and info.local_interface:
            self._sudo(
                [
                    "route",
                    "delete",
                    "default",
                    "-ifscope",
                    info.local_interface,
                    info.local_gateway,
                ]
            )
            r = self._sudo(["route", "add", "default", info.local_gateway])
            if r.returncode != 0:
                self._sudo(["route", "change", "default", info.local_gateway])

    async def remove_default_vpn_route_async(self, info: VPNInfo) -> None:
        await asyncio.gather(
            *[
                self._sudo_async(["route", "delete", dest, "-interface", info.interface])
                for dest in ("default", "0/1", "128.0/1")
            ],
            self._sudo_async(
                ["route", "delete", "-inet6", "default", "-interface", info.interface]
            ),
            return_exceptions=True,
        )
        if info.local_gateway and info.local_interface:
            await self._sudo_async(
                [
                    "route",
                    "delete",
                    "default",
                    "-ifscope",
                    info.local_interface,
                    info.local_gateway,
                ]
            )
            r = await self._sudo_async(["route", "add", "default", info.local_gateway])
            if r.returncode != 0:
                await self._sudo_async(["route", "change", "default", info.local_gateway])

    # -- add/remove ----------------------------------------------------

    def _add_argv(self, entry: str, info: VPNInfo) -> list[str] | None:
        flag = self._route_flag(entry)
        family = self._family_flag(entry)
        if self._is_ipsec(info):
            return ["route", "add", family, flag, entry, "-interface", info.interface]
        if info.gateway and self._family(entry) == 4:
            return ["route", "add", family, flag, entry, info.gateway]
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

    async def add_routes_async(self, entries: list[str], info: VPNInfo) -> AddResult:
        added: list[str] = []
        failed: list[tuple[str, str]] = []
        for entry in entries:
            argv = self._add_argv(entry, info)
            if argv is None:
                failed.append((entry, "no VPN gateway available"))
                continue
            r = await self._sudo_async(argv)
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
            self._sudo(["route", "delete", family, flag, entry, "-interface", info.interface])

    async def remove_routes_async(self, entries: list[str], info: VPNInfo) -> None:
        for entry in entries:
            try:
                flag = self._route_flag(entry)
                family = self._family_flag(entry)
            except ValueError:
                continue
            await self._sudo_async(
                ["route", "delete", family, flag, entry, "-interface", info.interface]
            )

    def is_interface_up(self, iface: str) -> bool:
        try:
            out = subprocess.check_output(
                ["ifconfig", iface],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=SUBPROCESS_TIMEOUT,
            )
            return "status: active" in out or "flags=" in out
        except subprocess.CalledProcessError:
            return False

    async def is_interface_up_async(self, iface: str) -> bool:
        r = await self._run_async(["ifconfig", iface])
        if r.returncode != 0:
            return False
        return "status: active" in r.stdout or "flags=" in r.stdout

    @staticmethod
    def _routes_from_netstat(out: str, iface: str) -> list[str]:
        routes: list[str] = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            dest, route_iface = parts[0], parts[-1]
            if route_iface != iface:
                continue
            if dest in ("default", "0/1", "128.0/1"):
                continue
            try:
                ipaddress.ip_network(dest, strict=False)
            except ValueError:
                continue
            routes.append(dest)
        return routes

    def list_vpn_routes(self, info: VPNInfo) -> list[str]:
        routes: list[str] = []
        for family_flag in ("inet", "inet6"):
            try:
                out = subprocess.check_output(
                    ["netstat", "-rn", "-f", family_flag],
                    text=True,
                    timeout=SUBPROCESS_TIMEOUT,
                )
            except subprocess.CalledProcessError:
                continue
            routes.extend(self._routes_from_netstat(out, info.interface))
        return routes

    async def list_vpn_routes_async(self, info: VPNInfo) -> list[str]:
        routes: list[str] = []
        for family_flag in ("inet", "inet6"):
            r = await self._run_async(["netstat", "-rn", "-f", family_flag])
            if r.returncode != 0:
                continue
            routes.extend(self._routes_from_netstat(r.stdout, info.interface))
        return routes
