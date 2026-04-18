"""Windows route backend — PowerShell with batched operations.

Detects the VPN by scoring 0.0.0.0/0 routes (point-to-point next hop, RAS
adapters, VPN-keyword interface descriptions). Adds/removes routes in
chunks of 200 per PowerShell invocation, both IPv4 and IPv6.
"""

from __future__ import annotations

import contextlib
import ctypes
import json
import subprocess

from ..parser import address_family
from .base import AddResult, RouteBackend, VPNInfo

_CHUNK = 200


class WindowsBackend(RouteBackend):
    _VPN_KEYWORDS = (
        "ikev2", "vpn", "wireguard", "openvpn", "tap", "tun",
        "ppp", "l2tp", "sstp", "ras",
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
        if "/" in entry:
            return entry
        return f"{entry}/32" if address_family(entry) == 4 else f"{entry}/128"

    @staticmethod
    def _next_hop_for(entry: str, info: VPNInfo) -> str:
        if address_family(entry.split("/")[0]) == 6:
            return "::"
        return info.gateway or "0.0.0.0"

    # ── detection ──────────────────────────────────────────────────────

    def detect_vpn(self) -> VPNInfo | None:
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
        for prefix in ("0.0.0.0/0", "::/0"):
            with contextlib.suppress(RuntimeError):
                self._ps(
                    f"Remove-NetRoute -InterfaceIndex {info.interface} "
                    f"-DestinationPrefix '{prefix}' -Confirm:$false "
                    f"-ErrorAction SilentlyContinue"
                )

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
        # Each entry carries its own NextHop because chunks may mix v4/v6.
        items = []
        for e in chunk:
            prefix = self._normalize(e)
            nh = self._next_hop_for(prefix, info)
            items.append(f"@{{Prefix='{prefix}'; NextHop='{nh}'}}")
        ps_list = ",".join(items)
        script = (
            f"$items = @({ps_list}); "
            f"$results = foreach ($it in $items) {{ "
            f"  try {{ "
            f"    $null = New-NetRoute -DestinationPrefix $it.Prefix "
            f"      -InterfaceIndex {info.interface} -NextHop $it.NextHop "
            f"      -PolicyStore ActiveStore -ErrorAction Stop; "
            f"    [PSCustomObject]@{{ Prefix=$it.Prefix; Ok=$true; Error='' }} "
            f"  }} catch {{ "
            f"    $msg = $_.Exception.Message; "
            f"    $ok = $msg -match 'already exists'; "
            f"    [PSCustomObject]@{{ Prefix=$it.Prefix; Ok=$ok; Error=$msg }} "
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
        for r, orig in zip(data, chunk, strict=False):
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
            with contextlib.suppress(RuntimeError):
                self._ps(script)

    def list_vpn_routes(self, info: VPNInfo) -> list[str]:
        script = (
            f"$r = Get-NetRoute -InterfaceIndex {info.interface} "
            f"-ErrorAction SilentlyContinue | "
            f"Where-Object {{ $_.DestinationPrefix -ne '0.0.0.0/0' "
            f"  -and $_.DestinationPrefix -ne '::/0' }}; "
            f"($r | ForEach-Object {{ $_.DestinationPrefix }}) -join \"`n\""
        )
        try:
            out = self._ps(script)
        except RuntimeError:
            return []
        return [line.strip() for line in out.splitlines() if line.strip()]
