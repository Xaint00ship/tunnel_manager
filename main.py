#!/usr/bin/env python3
"""
VPN Split Tunnel Manager
Manages split tunneling for IKEv2 VPN with smart DNS caching and route management.
"""

import asyncio
import json
import os
import platform
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import dns.resolver
from rich.columns import Columns
from rich.console import Console
from rich.layout import Layout
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
    "whitelist": [
        "netflix.com",
        "youtube.com",
        "github.com",
        "openai.com",
    ],
    "ping_interval_seconds": 1800,       # 30 minutes
    "active_check_interval_seconds": 60, # check active routes every 60s
    "top_n_to_ping": 10,                 # ping top-N most used domains
    "dns_servers": ["8.8.8.8", "1.1.1.1"],
    "dns_timeout": 5,
}

OS = platform.system()  # "Darwin" | "Windows" | "Linux"


# ─────────────────────────────────────────────
#  DATA CLASSES
# ─────────────────────────────────────────────

@dataclass
class DomainEntry:
    domain: str
    ips: set = field(default_factory=set)
    hit_count: int = 0
    last_resolved: float = 0.0
    last_ping: float = 0.0
    route_active: bool = False
    status: str = "pending"   # pending | active | error | updating


@dataclass
class LogEntry:
    ts: str
    level: str   # INFO | WARN | ERROR | OK
    message: str


# ─────────────────────────────────────────────
#  DNS CACHE
# ─────────────────────────────────────────────

class DNSCache:
    """In-memory DNS cache with hit-count tracking."""

    def __init__(self, dns_servers: list[str], timeout: int):
        self.entries: dict[str, DomainEntry] = {}
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = dns_servers
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def register(self, domain: str):
        if domain not in self.entries:
            self.entries[domain] = DomainEntry(domain=domain)

    def hit(self, domain: str) -> DomainEntry:
        """Record a usage hit and return entry."""
        if domain not in self.entries:
            self.register(domain)
        entry = self.entries[domain]
        entry.hit_count += 1
        return entry

    def top_domains(self, n: int) -> list[DomainEntry]:
        return sorted(self.entries.values(), key=lambda e: e.hit_count, reverse=True)[:n]

    async def resolve(self, domain: str) -> set[str]:
        """Resolve domain → set of IPv4 addresses."""
        loop = asyncio.get_event_loop()
        try:
            answers = await loop.run_in_executor(
                None, lambda: self.resolver.resolve(domain, "A")
            )
            return {r.address for r in answers}
        except Exception:
            return set()

    async def refresh(self, domain: str) -> tuple[set[str], set[str]]:
        """
        Resolve and compare with cached IPs.
        Returns (new_ips, removed_ips).
        """
        entry = self.entries.get(domain)
        if not entry:
            return set(), set()

        fresh = await self.resolve(domain)
        if not fresh:
            return set(), set()

        old = entry.ips.copy()
        new_ips = fresh - old
        removed_ips = old - fresh

        entry.ips = fresh
        entry.last_resolved = time.time()
        return new_ips, removed_ips


# ─────────────────────────────────────────────
#  ROUTE MANAGER
# ─────────────────────────────────────────────

class RouteManager:
    """Manages OS-level routes for split tunneling."""

    # macOS IKEv2 uses ipsec*, other VPNs use utun*, Linux uses tun*/ppp*/xfrm*
    VPN_IFACE_PREFIXES = ("ipsec", "utun", "ppp")

    def __init__(self):
        self.vpn_interface: Optional[str] = None
        self.vpn_gateway: Optional[str] = None   # None for ipsec (link-layer tunnel)
        self.local_gateway: Optional[str] = None  # ISP gateway to restore after VPN default removal
        self.local_interface: Optional[str] = None
        self.active_routes: set[str] = set()

    # ── Detection ──────────────────────────────

    def detect_vpn(self) -> bool:
        """Auto-detect VPN interface and gateway."""
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
        """
        Parse `netstat -rn -f inet` to find:
          - VPN default route (via ipsec*/utun*/ppp*)
          - Local default route (via en*/eth*) to restore after VPN removal
        macOS native IKEv2 creates ipsec0; other VPN clients use utun*.
        """
        routes = subprocess.check_output(["netstat", "-rn", "-f", "inet"], text=True)

        vpn_iface = vpn_gw = local_gw = local_iface = None

        for line in routes.splitlines():
            parts = line.split()
            # columns: Destination Gateway Flags [Refs Use] Netif [Expire]
            if len(parts) < 4:
                continue
            dest, gw, iface = parts[0], parts[1], parts[-1]

            if dest not in ("default", "0/1", "128.0/1"):
                continue

            if any(iface.startswith(p) for p in self.VPN_IFACE_PREFIXES):
                if vpn_iface is None or dest == "default":
                    vpn_iface = iface
                    # ipsec tunnels have link#N as gateway — store None (use -interface flag)
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
        idx = out
        gw = subprocess.check_output(
            ["powershell", "-Command",
             f"(Get-NetRoute -InterfaceIndex {idx} -DestinationPrefix '0.0.0.0/0').NextHop"],
            text=True
        ).strip()
        self.vpn_interface = idx
        self.vpn_gateway = gw
        return bool(gw)

    def _detect_linux(self) -> bool:
        out = subprocess.check_output(["ip", "route"], text=True)
        for line in out.splitlines():
            if "tun" in line or "ppp" in line or "xfrm" in line:
                parts = line.split()
                if "via" in parts:
                    idx = parts.index("via")
                    self.vpn_gateway = parts[idx + 1]
                if "dev" in parts:
                    idx = parts.index("dev")
                    self.vpn_interface = parts[idx + 1]
                if not self.local_gateway:
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

    def add_route(self, ip: str) -> bool:
        if ip in self.active_routes:
            return True
        try:
            if OS == "Darwin":
                if self._is_ipsec():
                    # ipsec tunnel has no IP gateway — route via interface
                    subprocess.run(
                        ["sudo", "route", "add", "-host", ip, "-interface", self.vpn_interface],
                        check=True, capture_output=True
                    )
                else:
                    subprocess.run(
                        ["sudo", "route", "add", ip, self.vpn_gateway],
                        check=True, capture_output=True
                    )
            elif OS == "Windows":
                subprocess.run(
                    ["powershell", "-Command",
                     f"New-NetRoute -DestinationPrefix '{ip}/32' "
                     f"-InterfaceIndex {self.vpn_interface} "
                     f"-NextHop {self.vpn_gateway} -ErrorAction SilentlyContinue"],
                    check=True, capture_output=True
                )
            else:
                subprocess.run(
                    ["sudo", "ip", "route", "add", f"{ip}/32",
                     "via", self.vpn_gateway, "dev", self.vpn_interface],
                    check=True, capture_output=True
                )
            self.active_routes.add(ip)
            return True
        except subprocess.CalledProcessError:
            return False

    def remove_route(self, ip: str) -> bool:
        if ip not in self.active_routes:
            return True
        try:
            if OS == "Darwin":
                if self._is_ipsec():
                    subprocess.run(
                        ["sudo", "route", "delete", "-host", ip, "-interface", self.vpn_interface],
                        check=True, capture_output=True
                    )
                else:
                    subprocess.run(
                        ["sudo", "route", "delete", ip],
                        check=True, capture_output=True
                    )
            elif OS == "Windows":
                subprocess.run(
                    ["powershell", "-Command",
                     f"Remove-NetRoute -DestinationPrefix '{ip}/32' "
                     f"-InterfaceIndex {self.vpn_interface} -Confirm:$false -ErrorAction SilentlyContinue"],
                    check=True, capture_output=True
                )
            else:
                subprocess.run(
                    ["sudo", "ip", "route", "del", f"{ip}/32"],
                    check=True, capture_output=True
                )
            self.active_routes.discard(ip)
            return True
        except subprocess.CalledProcessError:
            return False

    def remove_default_vpn_route(self) -> bool:
        """
        Remove the VPN catch-all default route, then ensure ISP default route
        exists as a global (non-scoped) route so regular traffic keeps working.
        """
        try:
            if OS == "Darwin":
                # Remove all default/catch-all patterns the VPN may have added
                for dest in ("default", "0/1", "128.0/1"):
                    subprocess.run(
                        ["sudo", "route", "delete", dest, "-interface", self.vpn_interface],
                        capture_output=True
                    )
                # Restore a global default via ISP gateway so non-VPN traffic works
                if self.local_gateway:
                    subprocess.run(
                        ["sudo", "route", "add", "default", self.local_gateway],
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
                    ["sudo", "ip", "route", "del", "default",
                     "dev", self.vpn_interface],
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

    def is_route_reachable(self, ip: str) -> bool:
        """Quick ping check for an IP."""
        try:
            if OS == "Windows":
                out = subprocess.run(
                    ["ping", "-n", "1", "-w", "2000", ip],
                    capture_output=True, timeout=5
                )
            else:
                out = subprocess.run(
                    ["ping", "-c", "1", "-W", "2", ip],
                    capture_output=True, timeout=5
                )
            return out.returncode == 0
        except Exception:
            return False


# ─────────────────────────────────────────────
#  TUNNEL APP
# ─────────────────────────────────────────────

class TunnelApp:
    def __init__(self, config: dict):
        self.config = config
        self.cache = DNSCache(config["dns_servers"], config["dns_timeout"])
        self.router = RouteManager()
        self.logs: list[LogEntry] = []
        self.running = False
        self.vpn_connected = False
        self.stats = {"routes_added": 0, "routes_removed": 0, "ip_changes": 0, "pings": 0}
        self._lock = asyncio.Lock()

        # Pre-register whitelist
        for domain in config["whitelist"]:
            self.cache.register(domain)

    def _log(self, level: str, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.logs.append(LogEntry(ts=ts, level=level, message=msg))
        if len(self.logs) > 200:
            self.logs.pop(0)

    # ── Startup ────────────────────────────────

    async def start(self):
        self._log("INFO", "Starting VPN Split Tunnel Manager...")

        # Detect VPN
        self._log("INFO", "Detecting VPN interface...")
        if not await asyncio.get_event_loop().run_in_executor(None, self.router.detect_vpn):
            self._log("WARN", "VPN not detected. Connect IKEv2 VPN first, then re-run.")
            self.vpn_connected = False
        else:
            self.vpn_connected = True
            self._log("OK", f"VPN detected: {self.router.vpn_interface} via {self.router.vpn_gateway}")
            await self._setup_tunnel()

        self.running = True

    async def _setup_tunnel(self):
        """Initial setup: remove default VPN route, resolve whitelist, add routes."""
        self._log("INFO", "Removing default VPN route (enabling split tunnel)...")
        self.router.remove_default_vpn_route()

        self._log("INFO", f"Resolving {len(self.config['whitelist'])} whitelisted domains...")
        tasks = [self._resolve_and_route(domain) for domain in self.config["whitelist"]]
        await asyncio.gather(*tasks)
        self._log("OK", "Split tunnel active. Only whitelisted domains go through VPN.")

    async def _resolve_and_route(self, domain: str):
        entry = self.cache.hit(domain)
        ips = await self.cache.resolve(domain)
        if not ips:
            self._log("WARN", f"Could not resolve {domain}")
            entry.status = "error"
            return

        entry.ips = ips
        entry.last_resolved = time.time()
        async with self._lock:
            for ip in ips:
                ok = await asyncio.get_event_loop().run_in_executor(None, self.router.add_route, ip)
                if ok:
                    self.stats["routes_added"] += 1
        entry.route_active = True
        entry.status = "active"
        self._log("OK", f"{domain} → {', '.join(ips)}")

    # ── Background Workers ─────────────────────

    async def worker_periodic_ping(self):
        """Every 30 min: ping top-N domains, update IPs if changed."""
        interval = self.config["ping_interval_seconds"]
        while self.running:
            await asyncio.sleep(interval)
            if not self.vpn_connected:
                continue
            top = self.cache.top_domains(self.config["top_n_to_ping"])
            self._log("INFO", f"Scheduled ping: checking {len(top)} top domains...")
            for entry in top:
                await self._ping_and_update(entry)

    async def _ping_and_update(self, entry: DomainEntry):
        self.stats["pings"] += 1
        entry.last_ping = time.time()
        new_ips, removed_ips = await self.cache.refresh(entry.domain)

        for ip in removed_ips:
            self._log("WARN", f"{entry.domain}: IP {ip} gone, removing route")
            async with self._lock:
                await asyncio.get_event_loop().run_in_executor(None, self.router.remove_route, ip)
            self.stats["routes_removed"] += 1
            self.stats["ip_changes"] += 1

        for ip in new_ips:
            self._log("OK", f"{entry.domain}: new IP {ip}, adding route")
            async with self._lock:
                ok = await asyncio.get_event_loop().run_in_executor(None, self.router.add_route, ip)
            if ok:
                self.stats["routes_added"] += 1
                self.stats["ip_changes"] += 1

        if new_ips or removed_ips:
            entry.status = "updating"
            await asyncio.sleep(1)
            entry.status = "active"

    async def worker_active_route_check(self):
        """Every 60s: check reachability of active routes, proactively refresh."""
        interval = self.config["active_check_interval_seconds"]
        while self.running:
            await asyncio.sleep(interval)
            if not self.vpn_connected:
                continue
            self._log("INFO", "Checking active route health...")
            for domain, entry in list(self.cache.entries.items()):
                if not entry.route_active:
                    continue
                # Check all IPs for this domain
                for ip in list(entry.ips):
                    ok = await asyncio.get_event_loop().run_in_executor(
                        None, self.router.is_route_reachable, ip
                    )
                    if not ok:
                        self._log("WARN", f"{domain} {ip} unreachable — refreshing routes proactively")
                        entry.status = "updating"
                        await self._ping_and_update(entry)
                        break

    async def worker_vpn_watchdog(self):
        """Watch for VPN connect/disconnect."""
        while self.running:
            await asyncio.sleep(15)
            was_connected = self.vpn_connected
            connected = await asyncio.get_event_loop().run_in_executor(None, self.router.detect_vpn)
            if connected and not was_connected:
                self.vpn_connected = True
                self._log("OK", "VPN connected! Setting up tunnel...")
                await self._setup_tunnel()
            elif not connected and was_connected:
                self.vpn_connected = False
                self._log("WARN", "VPN disconnected. Waiting for reconnect...")
                for entry in self.cache.entries.values():
                    entry.route_active = False
                    entry.status = "pending"

    # ── TUI ───────────────────────────────────

    def _make_layout(self) -> str:
        """Build Rich renderable for the live display."""
        # Header
        status_color = "green" if self.vpn_connected else "red"
        status_text = "● CONNECTED" if self.vpn_connected else "○ DISCONNECTED"
        vpn_info = f"  {self.router.vpn_interface} via {self.router.vpn_gateway}" if self.vpn_connected else ""

        local_info = f"  local gw: {self.router.local_gateway}" if self.router.local_gateway else ""
        header = Panel(
            Text.assemble(
                ("VPN SPLIT TUNNEL MANAGER", "bold white"),
                "   ",
                (status_text, f"bold {status_color}"),
                (vpn_info, "dim"),
                (local_info, "dim cyan"),
            ),
            style="on #0d1117",
            padding=(0, 2),
        )

        # Stats row
        stats_table = Table(box=None, show_header=False, padding=(0, 3))
        stats_table.add_column()
        stats_table.add_column()
        stats_table.add_column()
        stats_table.add_column()
        stats_table.add_row(
            f"[cyan]Routes added[/]  [bold]{self.stats['routes_added']}[/]",
            f"[yellow]Routes removed[/]  [bold]{self.stats['routes_removed']}[/]",
            f"[magenta]IP changes[/]  [bold]{self.stats['ip_changes']}[/]",
            f"[blue]Pings done[/]  [bold]{self.stats['pings']}[/]",
        )
        stats_panel = Panel(stats_table, title="[dim]Stats[/]", style="dim", padding=(0, 1))

        # Domain table
        domain_table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold #58a6ff",
            row_styles=["", "dim"],
            padding=(0, 1),
            expand=True,
        )
        domain_table.add_column("Domain", min_width=25)
        domain_table.add_column("IPs", min_width=35)
        domain_table.add_column("Hits", justify="right", min_width=6)
        domain_table.add_column("Status", min_width=10)
        domain_table.add_column("Last resolved", min_width=12)
        domain_table.add_column("Last ping", min_width=12)

        status_colors = {
            "active": "green",
            "error": "red",
            "pending": "yellow",
            "updating": "cyan",
        }

        for entry in sorted(self.cache.entries.values(), key=lambda e: e.hit_count, reverse=True):
            color = status_colors.get(entry.status, "white")
            lr = datetime.fromtimestamp(entry.last_resolved).strftime("%H:%M:%S") if entry.last_resolved else "—"
            lp = datetime.fromtimestamp(entry.last_ping).strftime("%H:%M:%S") if entry.last_ping else "—"
            domain_table.add_row(
                f"[bold]{entry.domain}[/]",
                ", ".join(sorted(entry.ips)) or "—",
                str(entry.hit_count),
                f"[{color}]{entry.status}[/]",
                lr,
                lp,
            )

        domains_panel = Panel(domain_table, title="[bold]Whitelisted Domains[/]", padding=(0, 1))

        # Log panel
        log_table = Table(box=None, show_header=False, padding=(0, 1), expand=True)
        log_table.add_column("ts", style="dim", min_width=10)
        log_table.add_column("level", min_width=6)
        log_table.add_column("message")

        level_colors = {"INFO": "blue", "WARN": "yellow", "ERROR": "red", "OK": "green"}
        for entry in self.logs[-15:]:
            color = level_colors.get(entry.level, "white")
            log_table.add_row(entry.ts, f"[{color}]{entry.level}[/]", entry.message)

        logs_panel = Panel(log_table, title="[bold]Log[/]", padding=(0, 1))

        from rich.console import Group
        return Group(header, stats_panel, domains_panel, logs_panel)

    async def run_tui(self):
        """Run the live TUI."""
        with Live(self._make_layout(), refresh_per_second=2, screen=True) as live:
            while self.running:
                live.update(self._make_layout())
                await asyncio.sleep(0.5)

    # ── Main entrypoint ────────────────────────

    async def run(self):
        await self.start()
        await asyncio.gather(
            self.run_tui(),
            self.worker_periodic_ping(),
            self.worker_active_route_check(),
            self.worker_vpn_watchdog(),
        )


# ─────────────────────────────────────────────
#  CONFIG LOADER
# ─────────────────────────────────────────────

def load_config() -> dict:
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            user = json.load(f)
        cfg = {**DEFAULT_CONFIG, **user}
    else:
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
        "[bold cyan]VPN Split Tunnel Manager[/]\n[dim]IKEv2 · Smart DNS Cache · Auto Route Updates[/]",
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
        console.print("[dim]Note: existing routes remain. Run 'sudo route flush' to clean up.[/]")


if __name__ == "__main__":
    main()
