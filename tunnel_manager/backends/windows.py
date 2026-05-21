"""Windows route backend — netsh for fast add/remove, PowerShell for detection.

Detects via Get-Net* (scored), adds/removes via netsh (much lighter than PS).
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import json
import os
import subprocess
import tempfile

from ..parser import address_family
from .base import BATCH_TIMEOUT, SUBPROCESS_TIMEOUT, AddResult, RouteBackend, VPNInfo

_CHUNK = 200

_DETECT_VPN_SCRIPT = (
    "$routes = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue; "
    "$out = foreach ($r in $routes) { "
    "  $a = Get-NetAdapter -InterfaceIndex $r.InterfaceIndex -ErrorAction SilentlyContinue; "
    "  [PSCustomObject]@{ "
    "    InterfaceIndex=[int]$r.InterfaceIndex; "
    "    InterfaceAlias=[string]$r.InterfaceAlias; "
    "    NextHop=[string]$r.NextHop; "
    "    Metric=[int]$r.RouteMetric; "
    "    Description=if ($a) { [string]$a.InterfaceDescription } else { '' }; "
    "    IsHardware=[bool]$a "
    "  } "
    "}; "
    "$out | ConvertTo-Json -Compress -Depth 2"
)


class WindowsBackend(RouteBackend):
    _VPN_KEYWORDS = (
        "ikev2",
        "vpn",
        "wireguard",
        "openvpn",
        "tap",
        "tun",
        "ppp",
        "l2tp",
        "sstp",
        "ras",
    )

    def name(self) -> str:
        return "windows"

    def is_privileged(self) -> bool:
        windll = getattr(ctypes, "windll", None)
        if windll is None:
            return False
        try:
            return bool(windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False

    def health_check(self) -> tuple[bool, str]:
        if not self.is_privileged():
            return False, "insufficient privileges"
        try:
            self._ps("$PSVersionTable.PSVersion.ToString()")
        except RuntimeError as e:
            return False, str(e)
        try:
            subprocess.run(
                ["netsh", "help"],
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT,
                check=False,
            )
        except FileNotFoundError:
            return False, "`netsh` command not found"
        except subprocess.TimeoutExpired:
            return False, "`netsh` command timed out"
        return True, "ok"

    def supports_persistent_routes(self) -> bool:
        return True

    # ── helpers ────────────────────────────────────────────────────────

    def _ps(self, script: str) -> str:
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("PowerShell timeout after 30s") from None
        if r.returncode != 0:
            raise RuntimeError(f"PowerShell error: {r.stderr.strip() or r.stdout.strip()}")
        return r.stdout.strip()

    async def _async_ps(self, script: str) -> str:
        proc = await asyncio.create_subprocess_exec(
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=SUBPROCESS_TIMEOUT)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            raise RuntimeError("PowerShell timeout after 30s") from None
        out = stdout.decode(errors="replace") if stdout else ""
        err = stderr.decode(errors="replace") if stderr else ""
        if proc.returncode != 0:
            raise RuntimeError(f"PowerShell error: {err.strip() or out.strip()}")
        return out.strip()

    def _netsh_batch(self, lines: list[str]) -> tuple[int, str]:
        if not lines:
            return 0, ""
        fd, path = tempfile.mkstemp(suffix=".netsh", text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
            r = subprocess.run(
                ["netsh", "-f", path], capture_output=True, text=True, timeout=BATCH_TIMEOUT
            )
            return r.returncode, (r.stderr or r.stdout).strip()
        finally:
            with contextlib.suppress(OSError):
                os.unlink(path)

    async def _async_netsh(self, args: list[str]) -> subprocess.CompletedProcess:
        proc = await asyncio.create_subprocess_exec(
            "netsh", *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=SUBPROCESS_TIMEOUT)
            return subprocess.CompletedProcess(
                ["netsh", *args],
                proc.returncode or 0,
                stdout.decode(errors="replace") if stdout else "",
                stderr.decode(errors="replace") if stderr else "",
            )
        except TimeoutError:
            proc.kill()
            await proc.wait()
            raise RuntimeError("netsh timeout") from None

    @staticmethod
    def _normalize(entry: str) -> str:
        if "/" in entry:
            return entry
        return f"{entry}/32" if address_family(entry) == 4 else f"{entry}/128"

    @staticmethod
    def _next_hop_for(entry: str, info: VPNInfo) -> str:
        if address_family(entry.split("/")[0]) == 6:
            return "::"
        return info.gateway or "0.0.0.0"

    # ── detection ──────────────────────────────────────────────────────

    def _parse_detect_vpn_output(self, out: str) -> VPNInfo | None:
        if not out:
            return None
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return None
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            return None
        routes = [r for r in data if isinstance(r, dict)]
        if not routes:
            return None

        def score(r: dict) -> int:
            s = 0
            if r.get("NextHop") == "0.0.0.0":
                s += 10
            if not r.get("IsHardware"):
                s += 5
            text = f"{r.get('Description', '')} {r.get('InterfaceAlias', '')}".lower()
            if any(k in text for k in self._VPN_KEYWORDS):
                s += 3
            return s

        ranked = sorted(routes, key=score, reverse=True)
        vpn = ranked[0] if score(ranked[0]) > 0 else None
        if vpn is None:
            return None
        isp = next(
            (r for r in routes if r.get("InterfaceIndex") != vpn.get("InterfaceIndex")),
            None,
        )
        return VPNInfo(
            interface=str(vpn.get("InterfaceIndex")),
            gateway=str(vpn.get("NextHop") or "0.0.0.0"),
            local_gateway=str(isp.get("NextHop")) if isp else None,
            local_interface=str(isp.get("InterfaceIndex")) if isp else None,
        )

    def detect_vpn(self) -> VPNInfo | None:
        return self._parse_detect_vpn_output(self._ps(_DETECT_VPN_SCRIPT))

    async def detect_vpn_async(self) -> VPNInfo | None:
        return self._parse_detect_vpn_output(await self._async_ps(_DETECT_VPN_SCRIPT))

    # ── default route mgmt ─────────────────────────────────────────────

    def remove_default_vpn_route(self, info: VPNInfo) -> None:
        for prefix, fam in (("0.0.0.0/0", "ipv4"), ("::/0", "ipv6")):
            args = [
                "interface",
                fam,
                "delete",
                "route",
                f"prefix={prefix}",
                f"interface={info.interface}",
            ]
            if info.persistent_routes:
                args += ["store=persistent"]
            with contextlib.suppress(Exception):
                subprocess.run(
                    ["netsh", *args], capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT
                )

    async def remove_default_vpn_route_async(self, info: VPNInfo) -> None:
        tasks = []
        for prefix, fam in (("0.0.0.0/0", "ipv4"), ("::/0", "ipv6")):
            args = [
                "interface",
                fam,
                "delete",
                "route",
                f"prefix={prefix}",
                f"interface={info.interface}",
            ]
            tasks.append(asyncio.create_task(self._async_netsh(args)))
        await asyncio.gather(*tasks, return_exceptions=True)

    # ── bulk add/remove ────────────────────────────────────────────────

    def add_routes(self, entries: list[str], info: VPNInfo) -> AddResult:
        added: list[str] = []
        failed: list[tuple[str, str]] = []
        for i in range(0, len(entries), _CHUNK):
            chunk = entries[i : i + _CHUNK]
            added_part, failed_part = self._add_chunk(chunk, info)
            added.extend(added_part)
            failed.extend(failed_part)
        return AddResult(added=added, failed=failed)

    def _add_chunk(
        self, chunk: list[str], info: VPNInfo
    ) -> tuple[list[str], list[tuple[str, str]]]:
        added: list[str] = []
        failed: list[tuple[str, str]] = []
        for e in chunk:
            prefix = self._normalize(e)
            nh = self._next_hop_for(prefix, info)
            fam = "ipv4" if address_family(prefix.split("/")[0]) == 4 else "ipv6"
            args = [
                "interface",
                fam,
                "add",
                "route",
                f"prefix={prefix}",
                f"interface={info.interface}",
            ]
            if nh not in ("0.0.0.0", "::"):
                args += [f"next-hop={nh}"]
            if info.persistent_routes:
                args += ["store=persistent"]
            r = subprocess.run(
                ["netsh", *args], capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT
            )
            out = (r.stderr or r.stdout or "").lower()
            if r.returncode == 0 or "already exists" in out:
                added.append(e)
            else:
                failed.append((e, (r.stderr or "netsh failed").strip()))
        return added, failed

    async def add_routes_async(self, entries: list[str], info: VPNInfo) -> AddResult:
        added: list[str] = []
        failed: list[tuple[str, str]] = []
        for e in entries:
            prefix = self._normalize(e)
            nh = self._next_hop_for(prefix, info)
            fam = "ipv4" if address_family(prefix.split("/")[0]) == 4 else "ipv6"
            args = [
                "interface",
                fam,
                "add",
                "route",
                f"prefix={prefix}",
                f"interface={info.interface}",
            ]
            if nh not in ("0.0.0.0", "::"):
                args += [f"next-hop={nh}"]
            if info.persistent_routes:
                args += ["store=persistent"]
            try:
                r = await self._async_netsh(args)
            except RuntimeError as exc:
                failed.append((e, str(exc)))
                continue
            out = (r.stderr or r.stdout or "").lower()
            if r.returncode == 0 or "already exists" in out:
                added.append(e)
            else:
                failed.append((e, (r.stderr or "netsh failed").strip()))
        return AddResult(added=added, failed=failed)

    def remove_routes(self, entries: list[str], info: VPNInfo) -> None:
        if not entries:
            return
        for e in entries:
            prefix = self._normalize(e)
            fam = "ipv4" if address_family(prefix.split("/")[0]) == 4 else "ipv6"
            args = [
                "interface",
                fam,
                "delete",
                "route",
                f"prefix={prefix}",
                f"interface={info.interface}",
            ]
            with contextlib.suppress(Exception):
                subprocess.run(
                    ["netsh", *args], capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT
                )

    async def remove_routes_async(self, entries: list[str], info: VPNInfo) -> None:
        if not entries:
            return
        for e in entries:
            prefix = self._normalize(e)
            fam = "ipv4" if address_family(prefix.split("/")[0]) == 4 else "ipv6"
            args = [
                "interface",
                fam,
                "delete",
                "route",
                f"prefix={prefix}",
                f"interface={info.interface}",
            ]
            if info.persistent_routes:
                args += ["store=persistent"]
            with contextlib.suppress(Exception):
                await self._async_netsh(args)

    def list_vpn_routes(self, info: VPNInfo) -> list[str]:
        script = (
            f"$r = Get-NetRoute -InterfaceIndex {info.interface} "
            f"-ErrorAction SilentlyContinue | "
            f"Where-Object {{ $_.DestinationPrefix -ne '0.0.0.0/0' "
            f"  -and $_.DestinationPrefix -ne '::/0' }}; "
            f'($r | ForEach-Object {{ $_.DestinationPrefix }}) -join "`n"'
        )
        try:
            out = self._ps(script)
        except RuntimeError:
            return []
        return [line.strip() for line in out.splitlines() if line.strip()]

    async def list_vpn_routes_async(self, info: VPNInfo) -> list[str]:
        script = (
            f"$r = Get-NetRoute -InterfaceIndex {info.interface} "
            f"-ErrorAction SilentlyContinue | "
            f"Where-Object {{ $_.DestinationPrefix -ne '0.0.0.0/0' "
            f"  -and $_.DestinationPrefix -ne '::/0' }}; "
            f'($r | ForEach-Object {{ $_.DestinationPrefix }}) -join "`n"'
        )
        try:
            out = await self._async_ps(script)
        except RuntimeError:
            return []
        return [line.strip() for line in out.splitlines() if line.strip()]

    def is_interface_up(self, iface: str) -> bool:
        try:
            out = self._ps(
                f"$a = Get-NetAdapter -InterfaceIndex {iface} -ErrorAction SilentlyContinue; "
                f"if ($a) {{ ($a.Status -eq 'Up') }} else {{ $false }}"
            )
            return out.strip().lower() == "true"
        except RuntimeError:
            return False

    async def is_interface_up_async(self, iface: str) -> bool:
        try:
            out = await self._async_ps(
                f"$a = Get-NetAdapter -InterfaceIndex {iface} -ErrorAction SilentlyContinue; "
                f"if ($a) {{ ($a.Status -eq 'Up') }} else {{ $false }}"
            )
            return out.strip().lower() == "true"
        except RuntimeError:
            return False
