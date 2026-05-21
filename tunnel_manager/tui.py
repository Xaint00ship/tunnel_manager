"""Rich TUI dashboard."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime

from rich import box
from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .log import InMemoryHandler

_LEVEL_COLORS = {
    "DEBUG": "dim",
    "INFO": "blue",
    "WARNING": "yellow",
    "ERROR": "red",
    "CRITICAL": "bold red",
}


def _render(app, log_handler: InMemoryHandler):
    now = time.time()
    info = app.vpn_info

    if app.vpn_connected and info:
        status_text, status_color = "● CONNECTED", "green"
        vpn_info_text = f"  {info.describe()}"
        if info.local_gateway:
            vpn_info_text += f"  •  ISP: {info.local_gateway}"
    else:
        status_text, status_color = "○ DISCONNECTED", "red"
        vpn_info_text = ""

    header = Panel(
        Text.assemble(
            ("VPN SPLIT TUNNEL MANAGER", "bold white"),
            "   ",
            (status_text, f"bold {status_color}"),
            (vpn_info_text, "dim"),
        ),
        style="on #0d1117",
        padding=(0, 2),
    )

    updated_str = (
        datetime.fromtimestamp(app.last_updated).strftime("%H:%M:%S") if app.last_updated else "—"
    )
    next_refresh = ""
    if app.last_updated:
        secs = int(app.config.refresh_interval_hours * 3600 - (now - app.last_updated))
        if secs > 3600:
            next_refresh = f"  next in {secs // 3600}h {(secs % 3600) // 60}m"
        elif secs > 0:
            next_refresh = f"  next in {secs // 60}m {secs % 60}s"

    stats_table = Table(box=None, show_header=False, padding=(0, 4))
    stats_table.add_column()
    stats_table.add_column()
    stats_table.add_column()
    stats_table.add_row(
        f"[cyan]Routes active[/]  [bold]{app.total_routes}[/]",
        f"[dim]Updated: {updated_str}{next_refresh}[/]",
        f"[yellow]{app.status_line}[/]",
    )
    if app.route_progress_total:
        stats_table.add_row(
            "[cyan]Route progress[/]",
            (
                f"[bold]{app.route_progress_done}/{app.route_progress_total}[/] "
                f"[dim]({app.route_progress_percent}%)[/]"
            ),
            "",
        )
    stats_panel = Panel(stats_table, title="[dim]Stats[/]", style="dim", padding=(0, 1))

    svc_table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold #58a6ff",
        row_styles=["", "dim"],
        padding=(0, 2),
    )
    svc_table.add_column("Service", min_width=30)
    svc_table.add_column("Routes", justify="right", min_width=8)
    for section, count in sorted(app.sections.items(), key=lambda x: -x[1]):
        svc_table.add_row(section, str(count))
    svc_panel = Panel(svc_table, title="[bold]Services via VPN[/]", padding=(0, 1))

    log_table = Table(box=None, show_header=False, padding=(0, 1), expand=True)
    log_table.add_column("ts", style="dim", min_width=10)
    log_table.add_column("level", min_width=8)
    log_table.add_column("message")
    for entry in list(log_handler.buffer)[-12:]:
        c = _LEVEL_COLORS.get(entry["level"], "white")
        log_table.add_row(entry["ts"], f"[{c}]{entry['level']}[/]", entry["message"])
    log_panel = Panel(log_table, title="[bold]Log[/]", padding=(0, 1))

    return Group(header, stats_panel, svc_panel, log_panel)


async def run_tui(app, log_handler: InMemoryHandler, persist: bool = False) -> None:
    with Live(
        _render(app, log_handler),
        refresh_per_second=2,
        screen=not persist,
    ) as live:
        while app.running:
            live.update(_render(app, log_handler))
            await asyncio.sleep(0.5)
