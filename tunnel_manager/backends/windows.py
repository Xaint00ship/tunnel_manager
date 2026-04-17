"""Windows route backend — PowerShell with batched operations."""

from __future__ import annotations

import ctypes
import json
import subprocess
from typing import Optional

from .base import AddResult, RouteBackend, VPNInfo


# Chunk size keeps PowerShell command line under the ~32K process-creation limit.
_CHUNK = 200


class WindowsBackend(RouteBackend):
    _VPN_KEYWORDS = (
        "ikev2", "vpn", "wireguard", "openvpn", "tap", "tun",
        "ppp", "l2tp", "sstp", "ras",
    )

    def name(self) -> str:
        return "windows"

    def is_privileged(self) -> bool:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False

    # ── helpers ────────────────────────────────────────────────────────

    def _ps(self, script: str) -> str:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            raise RuntimeError(f"PowerShell error: {r.stderr.strip() or r.stdout.strip()}")
        return r.stdout.strip()

    @staticmethod
    def _normalize(entry: str) -> str:
        return entry if "/" in entry else f"{entry}/32"

    # ── detection ──────────────────────────────────────────────────────

    def detect_vpn(self) -> Optional[VPNInfo]:
        script = (
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
        out = self._ps(script)
        if not out:
            return None
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return None
        if isinstance(data, dict):
            data = [data]
        if not data:
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

        ranked = sorted(data, key=score, reverse=True)
        vpn = ranked[0] if score(ranked[0]) > 0 else None
        if vpn is None:
            return None
        isp = next(
            (r for r in data if r["InterfaceIndex"] != vpn["InterfaceIndex"]), None
        )
        return VPNInfo(
            interface=str(vpn["InterfaceIndex"]),
            gateway=vpn["NextHop"] or "0.0.0.0",
            local_gateway=isp["NextHop"] if isp else None,
            local_interface=str(isp["InterfaceIndex"]) if isp else None,
        )

    # ── default route mgmt ─────────────────────────────────────────────

    def remove_default_vpn_route(self, info: VPNInfo) -> None:
        self._ps(
            f"Remove-NetRoute -InterfaceIndex {info.interface} "
            f"-DestinationPrefix '0.0.0.0/0' -Confirm:$false "
            f"-ErrorAction SilentlyContinue"
        )

    # ── bulk add/remove ────────────────────────────────────────────────

    def add_routes(self, entries: list[str], info: VPNInfo) -> AddResult:
        added: list[str] = []
        failed: list[tuple[str, str]] = []
        gw = info.gateway or "0.0.0.0"
        for i in range(0, len(entries), _CHUNK):
            chunk = entries[i : i + _CHUNK]
            added_part, failed_part = self._add_chunk(chunk, info.interface, gw)
            added.extend(added_part)
            failed.extend(failed_part)
        return AddResult(added=added, failed=failed)

    def _add_chunk(
        self, chunk: list[str], iface: str, gateway: str
    ) -> tuple[list[str], list[tuple[str, str]]]:
        prefixes = [self._normalize(e) for e in chunk]
        ps_list = ",".join(f"'{p}'" for p in prefixes)
        script = (
            f"$prefixes = @({ps_list}); "
            f"$results = foreach ($p in $prefixes) {{ "
            f"  try {{ "
            f"    $null = New-NetRoute -DestinationPrefix $p "
            f"      -InterfaceIndex {iface} -NextHop '{gateway}' "
            f"      -PolicyStore ActiveStore -ErrorAction Stop; "
            f"    [PSCustomObject]@{{ Prefix=$p; Ok=$true; Error='' }} "
            f"  }} catch {{ "
            f"    $msg = $_.Exception.Message; "
            f"    $ok = $msg -match 'already exists'; "
            f"    [PSCustomObject]@{{ Prefix=$p; Ok=$ok; Error=$msg }} "
            f"  }} "
            f"}}; "
            f"$results | ConvertTo-Json -Compress -Depth 2"
        )
        try:
            out = self._ps(script)
        except RuntimeError as e:
            return [], [(orig, str(e)) for orig in chunk]
        if not out:
            return [], [(orig, "no output") for orig in chunk]
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        added, failed = [], []
        for r, orig in zip(data, chunk):
            if r.get("Ok"):
                added.append(orig)
            else:
                failed.append((orig, (r.get("Error") or "unknown").strip()))
        return added, failed

    def remove_routes(self, entries: list[str], info: VPNInfo) -> None:
        if not entries:
            return
        for i in range(0, len(entries), _CHUNK):
            chunk = entries[i : i + _CHUNK]
            prefixes = [self._normalize(e) for e in chunk]
            ps_list = ",".join(f"'{p}'" for p in prefixes)
            script = (
                f"$prefixes = @({ps_list}); "
                f"foreach ($p in $prefixes) {{ "
                f"  Remove-NetRoute -DestinationPrefix $p "
                f"    -InterfaceIndex {info.interface} "
                f"    -Confirm:$false -ErrorAction SilentlyContinue "
                f"}}"
            )
            try:
                self._ps(script)
            except RuntimeError:
                pass

    def list_vpn_routes(self, info: VPNInfo) -> list[str]:
        script = (
            f"$r = Get-NetRoute -InterfaceIndex {info.interface} "
            f"-AddressFamily IPv4 -ErrorAction SilentlyContinue | "
            f"Where-Object {{ $_.DestinationPrefix -ne '0.0.0.0/0' }}; "
            f"($r | ForEach-Object {{ $_.DestinationPrefix }}) -join \"`n\""
        )
        try:
            out = self._ps(script)
        except RuntimeError:
            return []
        return [line.strip() for line in out.splitlines() if line.strip()]
