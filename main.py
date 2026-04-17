#!/usr/bin/env python3
"""
VPN Split Tunnel Manager
Downloads a curated IP/CIDR list and routes only those through VPN.
Everything else goes direct via ISP.
"""

import asyncio
import json
import os
import platform
import re
import subprocess
import sys
import time
import urllib.request
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()

# ─────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────

CONFIG_FILE = "config.json"
DEFAULT_CONFIG = {
    "list_url": (
        "https://gist.githubusercontent.com/iamwildtuna/"
        "7772b7c84a11bf6e1385f23096a73a15/raw/gistfile2.txt"
    ),
    "refresh_interval_hours": 24,
}

OS = platform.system()

# ─────────────────────────────────────────────
#  PARSER
# ─────────────────────────────────────────────

IP_RE = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b')
ROUTE_ADD_RE = re.compile(
    r'route\s+ADD\s+(\d[\d.]+)\s+MASK\s+(\d[\d.]+)', re.IGNORECASE
)


def _mask_to_prefix(mask: str) -> int:
    return sum(bin(int(b)).count("1") for b in mask.split("."))


def fetch_list(url: str) -> str:
    with urllib.request.urlopen(url, timeout=15) as r:
        return r.read().decode()


def parse_route_list(text: str) -> dict[str, list[str]]:
    """
    Returns {section_name: [ip_or_cidr, ...]}
    Handles:
      - plain IPs / CIDRs
      - Windows 'route ADD x.x.x.x MASK y.y.y.y ...' (converts to CIDR)
    Deduplicates within sections.
    """
    sections: dict[str, list[str]] = {}
    seen: set[str] = set()
    current = "Other"

    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("//"):
            continue

        # Windows route command → convert to CIDR
        m = ROUTE_ADD_RE.search(s)
        if m:
            cidr = f"{m.group(1)}/{_mask_to_prefix(m.group(2))}"
            if cidr not in seen:
                seen.add(cidr)
                sections.setdefault(current, []).append(cidr)
            continue

        matches = IP_RE.findall(s)
        if not matches:
            current = s    # section header
            continue

        for entry in matches:
            if entry not in seen:
                seen.add(entry)
                sections.setdefault(current, []).append(entry)

    return sections


# ─────────────────────────────────────────────
#  DATA
# ─────────────────────────────────────────────

class LogEntry:
    def __init__(self, level: str, message: str):
        self.ts = datetime.now().strftime("%H:%M:%S")
        self.level = level
        self.message = message


# ─────────────────────────────────────────────
#  ROUTE MANAGER
# ─────────────────────────────────────────────

class RouteManager:
    """Manages OS-level routes for split tunneling."""

    VPN_IFACE_PREFIXES = ("ipsec", "utun", "ppp")

    def __init__(self):
        self.vpn_interface: Optional[str] = None
        self.vpn_gateway: Optional[str] = None
        self.local_gateway: Optional[str] = None
        self.local_interface: Optional[str] = None
        self.active_routes: set[str] = set()

    # ── Detection ──────────────────────────────

    def detect_vpn(self) -> bool:
        try:
            if OS == "Darwin":
                return self._detect_macos()
            elif OS == "Windows":
                return self._detect_windows()
            else:
                return self._detect_linux()
        except Exception:
            return False

    def _detect_macos(self) -> bool:
        routes = subprocess.check_output(["netstat", "-rn", "-f", "inet"], text=True)
        vpn_iface = vpn_gw = local_gw = local_iface = None
        for line in routes.splitlines():
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
        if vpn_iface:
            self.vpn_interface = vpn_iface
            self.vpn_gateway = vpn_gw
            self.local_gateway = local_gw
            self.local_interface = local_iface
            return True
        return False

    def _detect_windows(self) -> bool:
        out = subprocess.check_output(
            ["powershell", "-Command",
             "Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*IKEv2*' "
             "-or $_.InterfaceDescription -like '*VPN*' } | Select-Object -First 1 -ExpandProperty ifIndex"],
            text=True
        ).strip()
        if not out:
            return False
        gw = subprocess.check_output(
            ["powershell", "-Command",
             f"(Get-NetRoute -InterfaceIndex {out} -DestinationPrefix '0.0.0.0/0').NextHop"],
            text=True
        ).strip()
        self.vpn_interface = out
        self.vpn_gateway = gw
        return bool(gw)

    def _detect_linux(self) -> bool:
        out = subprocess.check_output(["ip", "route"], text=True)
        for line in out.splitlines():
            if "tun" in line or "ppp" in line or "xfrm" in line:
                parts = line.split()
                if "via" in parts:
                    self.vpn_gateway = parts[parts.index("via") + 1]
                if "dev" in parts:
                    self.vpn_interface = parts[parts.index("dev") + 1]
                for ln in out.splitlines():
                    if ln.startswith("default") and "via" in ln:
                        p = ln.split()
                        self.local_gateway = p[p.index("via") + 1]
                        break
                return bool(self.vpn_gateway)
        return False

    # ── Route CRUD ─────────────────────────────

    def _is_ipsec(self) -> bool:
        return self.vpn_interface is not None and self.vpn_interface.startswith("ipsec")

    def _is_cidr(self, entry: str) -> bool:
        return "/" in entry

    def add_route(self, entry: str) -> bool:
        """Add a host (/32) or network (CIDR) route via VPN interface."""
        if entry in self.active_routes:
            return True
        try:
            if OS == "Darwin":
                if self._is_cidr(entry):
                    flag = "-net"
                else:
                    flag = "-host"
                if self._is_ipsec():
                    subprocess.run(
                        ["sudo", "route", "add", flag, entry, "-interface", self.vpn_interface],
                        check=True, capture_output=True
                    )
                else:
                    subprocess.run(
                        ["sudo", "route", "add", flag, entry, self.vpn_gateway],
                        check=True, capture_output=True
                    )
            elif OS == "Windows":
                dest = entry if self._is_cidr(entry) else f"{entry}/32"
                subprocess.run(
                    ["powershell", "-Command",
                     f"New-NetRoute -DestinationPrefix '{dest}' "
                     f"-InterfaceIndex {self.vpn_interface} "
                     f"-NextHop {self.vpn_gateway} -ErrorAction SilentlyContinue"],
                    check=True, capture_output=True
                )
            else:
                dest = entry if self._is_cidr(entry) else f"{entry}/32"
                cmd = ["sudo", "ip", "route", "add", dest, "dev", self.vpn_interface]
                if self.vpn_gateway:
                    cmd += ["via", self.vpn_gateway]
                subprocess.run(cmd, check=True, capture_output=True)
            self.active_routes.add(entry)
            return True
        except subprocess.CalledProcessError:
            return False

    def remove_default_vpn_route(self) -> bool:
        """Remove the VPN catch-all default route and restore ISP default globally."""
        try:
            if OS == "Darwin":
                for dest in ("default", "0/1", "128.0/1"):
                    subprocess.run(
                        ["sudo", "route", "delete", dest, "-interface", self.vpn_interface],
                        capture_output=True
                    )
                if self.local_gateway and self.local_interface:
                    # macOS marks the ISP default IFSCOPE (flag I) — without a global
                    # default, sockets can't route outbound. Re-add it as global.
                    subprocess.run(
                        ["sudo", "route", "delete", "default",
                         "-ifscope", self.local_interface, self.local_gateway],
                        capture_output=True
                    )
                    r = subprocess.run(
                        ["sudo", "route", "add", "default", self.local_gateway],
                        capture_output=True, text=True
                    )
                    if r.returncode != 0:
                        subprocess.run(
                            ["sudo", "route", "change", "default", self.local_gateway],
                            capture_output=True
                        )
            elif OS == "Windows":
                subprocess.run(
                    ["powershell", "-Command",
                     f"Remove-NetRoute -InterfaceIndex {self.vpn_interface} "
                     f"-DestinationPrefix '0.0.0.0/0' -Confirm:$false -ErrorAction SilentlyContinue"],
                    capture_output=True
                )
            else:
                subprocess.run(
                    ["sudo", "ip", "route", "del", "default", "dev", self.vpn_interface],
                    capture_output=True
                )
                if self.local_gateway:
                    subprocess.run(
                        ["sudo", "ip", "route", "add", "default", "via", self.local_gateway],
                        capture_output=True
                    )
            return True
        except Exception:
            return False

    def flush_vpn_routes(self):
        """Remove all VPN-interface routes left from a previous run."""
        if OS == "Darwin":
            try:
                out = subprocess.check_output(["netstat", "-rn", "-f", "inet"], text=True)
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    dest, flags, iface = parts[0], parts[2], parts[-1]
                    if iface != self.vpn_interface:
                        continue
                    # Skip the default/tunnel endpoint routes managed by VPN client
                    if dest in ("default", "0/1", "128.0/1"):
                        continue
                    flag = "-host" if "H" in flags else "-net"
                    subprocess.run(
                        ["sudo", "route", "delete", flag, dest, "-interface", self.vpn_interface],
                        capture_output=True
                    )
            except Exception:
                pass
        elif OS == "Linux":
            try:
                out = subprocess.check_output(["ip", "route"], text=True)
                for line in out.splitlines():
                    if f"dev {self.vpn_interface}" in line:
                        dest = line.split()[0]
                        if dest not in ("default",):
                            subprocess.run(
                                ["sudo", "ip", "route", "del", dest], capture_output=True
                            )
            except Exception:
                pass
        self.active_routes.clear()


# ─────────────────────────────────────────────
#  TUNNEL APP
# ─────────────────────────────────────────────

class TunnelApp:
    def __init__(self, config: dict):
        self.config = config
        self.router = RouteManager()
        self.logs: list[LogEntry] = []
        self.running = False
        self.vpn_connected = False
        self.sections: dict[str, int] = {}   # section → route count
        self.total_routes = 0
        self.last_updated: Optional[float] = None
        self.status_line = "Initializing..."

    def _log(self, level: str, msg: str):
        self.logs.append(LogEntry(level, msg))
        if len(self.logs) > 300:
            self.logs.pop(0)

    # ── Startup ────────────────────────────────

    async def start(self):
        self._log("INFO", "Starting VPN Split Tunnel Manager...")
        loop = asyncio.get_event_loop()

        self._log("INFO", "Detecting VPN interface...")
        if not await loop.run_in_executor(None, self.router.detect_vpn):
            self._log("WARN", "VPN not detected. Connect IKEv2 VPN and restart.")
            self.vpn_connected = False
        else:
            self.vpn_connected = True
            iface = self.router.vpn_interface
            gw = self.router.vpn_gateway or "link-layer"
            self._log("OK", f"VPN: {iface}  gateway: {gw}  local ISP: {self.router.local_gateway}")
            await self._setup_tunnel()

        self.running = True

    async def _setup_tunnel(self):
        loop = asyncio.get_event_loop()

        self._log("INFO", "Removing catch-all VPN default route...")
        await loop.run_in_executor(None, self.router.remove_default_vpn_route)

        self._log("INFO", "Flushing stale routes from previous run...")
        await loop.run_in_executor(None, self.router.flush_vpn_routes)

        await self._load_and_apply_routes()

    async def _load_and_apply_routes(self):
        loop = asyncio.get_event_loop()
        url = self.config["list_url"]

        self._log("INFO", f"Fetching route list...")
        self.status_line = "Fetching list..."
        try:
            raw = await loop.run_in_executor(None, fetch_list, url)
        except Exception as e:
            self._log("ERROR", f"Failed to fetch list: {e}")
            self.status_line = "Fetch failed"
            return

        sections = parse_route_list(raw)
        total = sum(len(v) for v in sections.values())
        self._log("OK", f"Parsed {total} entries across {len(sections)} services")

        # Flush existing routes and re-add fresh
        await loop.run_in_executor(None, self.router.flush_vpn_routes)

        added = skipped = 0
        self.status_line = "Adding routes..."
        for section, entries in sections.items():
            count = 0
            # Add routes concurrently in batches of 40
            for i in range(0, len(entries), 40):
                batch = entries[i:i + 40]
                results = await asyncio.gather(*[
                    loop.run_in_executor(None, self.router.add_route, e)
                    for e in batch
                ])
                count += sum(results)
                added += sum(results)
                skipped += sum(1 for r in results if not r)
            self.sections[section] = count

        self.total_routes = added
        self.last_updated = time.time()
        self.status_line = "Active"
        self._log("OK", f"Done: {added} routes active, {skipped} skipped (already exist)")

    # ── Background Workers ─────────────────────

    async def worker_refresh(self):
        """Re-fetch and re-apply the route list every N hours."""
        interval = self.config["refresh_interval_hours"] * 3600
        while self.running:
            await asyncio.sleep(interval)
            if not self.vpn_connected:
                continue
            self._log("INFO", "Scheduled refresh: re-fetching route list...")
            await self._load_and_apply_routes()

    async def worker_vpn_watchdog(self):
        """Detect VPN connect / disconnect."""
        while self.running:
            await asyncio.sleep(15)
            loop = asyncio.get_event_loop()
            was = self.vpn_connected
            connected = await loop.run_in_executor(None, self.router.detect_vpn)
            if connected and not was:
                self.vpn_connected = True
                self._log("OK", "VPN reconnected — rebuilding tunnel...")
                await self._setup_tunnel()
            elif not connected and was:
                self.vpn_connected = False
                self.status_line = "VPN disconnected"
                self._log("WARN", "VPN disconnected. Waiting for reconnect...")

    # ── TUI ───────────────────────────────────

    def _make_layout(self):
        now = time.time()

        # ── Header ──────────────────────────────
        status_color = "green" if self.vpn_connected else "red"
        status_text = "● CONNECTED" if self.vpn_connected else "○ DISCONNECTED"
        vpn_info = ""
        if self.vpn_connected:
            vpn_info = f"  {self.router.vpn_interface}"
            if self.router.vpn_gateway:
                vpn_info += f" via {self.router.vpn_gateway}"
            if self.router.local_gateway:
                vpn_info += f"  •  ISP: {self.router.local_gateway}"

        header = Panel(
            Text.assemble(
                ("VPN SPLIT TUNNEL MANAGER", "bold white"),
                "   ",
                (status_text, f"bold {status_color}"),
                (vpn_info, "dim"),
            ),
            style="on #0d1117",
            padding=(0, 2),
        )

        # ── Stats ────────────────────────────────
        updated_str = (
            datetime.fromtimestamp(self.last_updated).strftime("%H:%M:%S")
            if self.last_updated else "—"
        )
        next_refresh = ""
        if self.last_updated:
            secs = int(self.config["refresh_interval_hours"] * 3600 - (now - self.last_updated))
            if secs > 3600:
                next_refresh = f"  next refresh in {secs // 3600}h {(secs % 3600) // 60}m"
            elif secs > 0:
                next_refresh = f"  next refresh in {secs // 60}m {secs % 60}s"

        stats_table = Table(box=None, show_header=False, padding=(0, 4))
        stats_table.add_column()
        stats_table.add_column()
        stats_table.add_column()
        stats_table.add_row(
            f"[cyan]Routes active[/]  [bold]{self.total_routes}[/]",
            f"[dim]Updated: {updated_str}{next_refresh}[/]",
            f"[yellow]{self.status_line}[/]",
        )
        stats_panel = Panel(stats_table, title="[dim]Stats[/]", style="dim", padding=(0, 1))

        # ── Services table ───────────────────────
        svc_table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold #58a6ff",
            row_styles=["", "dim"],
            padding=(0, 2),
        )
        svc_table.add_column("Service", min_width=30)
        svc_table.add_column("Routes", justify="right", min_width=8)

        for section, count in sorted(self.sections.items(), key=lambda x: -x[1]):
            svc_table.add_row(section, str(count))

        svc_panel = Panel(svc_table, title="[bold]Services via VPN[/]", padding=(0, 1))

        # ── Log ─────────────────────────────────
        log_table = Table(box=None, show_header=False, padding=(0, 1), expand=True)
        log_table.add_column("ts", style="dim", min_width=10)
        log_table.add_column("level", min_width=6)
        log_table.add_column("message")

        colors = {"INFO": "blue", "WARN": "yellow", "ERROR": "red", "OK": "green"}
        for entry in self.logs[-12:]:
            c = colors.get(entry.level, "white")
            log_table.add_row(entry.ts, f"[{c}]{entry.level}[/]", entry.message)

        log_panel = Panel(log_table, title="[bold]Log[/]", padding=(0, 1))

        from rich.console import Group
        return Group(header, stats_panel, svc_panel, log_panel)

    async def run_tui(self):
        with Live(self._make_layout(), refresh_per_second=2, screen=True) as live:
            while self.running:
                live.update(self._make_layout())
                await asyncio.sleep(0.5)

    async def run(self):
        await self.start()
        await asyncio.gather(
            self.run_tui(),
            self.worker_refresh(),
            self.worker_vpn_watchdog(),
        )


# ─────────────────────────────────────────────
#  CONFIG LOADER
# ─────────────────────────────────────────────

def load_config() -> dict:
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            user = json.load(f)
        return {**DEFAULT_CONFIG, **user}
    cfg = DEFAULT_CONFIG.copy()
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)
    console.print(f"[yellow]Created default config: {CONFIG_FILE}[/]")
    return cfg


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────

def main():
    console.print(Panel.fit(
        "[bold cyan]VPN Split Tunnel Manager[/]\n[dim]IKEv2 · Auto IP list · Split tunnel[/]",
        border_style="cyan"
    ))

    if OS not in ("Darwin", "Windows", "Linux"):
        console.print(f"[red]Unsupported OS: {OS}[/]")
        sys.exit(1)

    config = load_config()
    app = TunnelApp(config)

    try:
        asyncio.run(app.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutting down...[/]")
        console.print("[dim]Routes remain active until reboot or 'sudo route flush'[/]")


if __name__ == "__main__":
    main()
