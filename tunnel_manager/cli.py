"""Command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

from . import __version__
from .app import TunnelApp
from .backends import RouteBackend, VPNInfo, get_backend
from .config import Config
from .fetcher import compute_sha256
from .log import get_logger, setup_logging
from .paths import LOG_FILE
from .state import StateFile
from .tui import run_tui

BASE_DIR = Path(__file__).resolve().parent.parent


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="tunnel_manager",
        description="VPN split-tunnel manager — routes a curated IP list through VPN.",
    )
    p.add_argument("--version", action="version", version=f"tunnel_manager {__version__}")
    p.add_argument("--no-tui", action="store_true",
                   help="Plain-text logging, no full-screen TUI.")
    p.add_argument("--persist-tui", action="store_true",
                   help="Keep TUI output in main terminal scrollback (no alt-screen).")
    p.add_argument("--dry-run", action="store_true",
                   help="Print planned changes; do not modify routing table.")
    p.add_argument("--cleanup", action="store_true",
                   help="Remove all routes from a previous run and exit.")
    p.add_argument("--status", action="store_true",
                   help="Print current state (active routes, VPN, log tail) and exit.")
    p.add_argument("--update-list", metavar="URL",
                   help="Download a fresh list from URL into bundled tunnel_list.txt and exit.")
    p.add_argument("--compute-sha", action="store_true",
                   help="Print SHA-256 of the configured list source and exit.")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging.")
    p.add_argument("--config", type=Path, default=BASE_DIR / "config.json",
                   help="Path to config.json (default: <repo>/config.json).")
    return p.parse_args()


def _print_status(state: StateFile) -> None:
    if not state.data:
        print("No state on disk — manager has never been run, or --cleanup wiped it.")
        return
    pid = state.data.get("pid", 0)
    pid_alive = StateFile.is_pid_alive(int(pid)) if pid else False
    print(f"PID:          {pid} ({'alive' if pid_alive else 'not running'})")
    started = state.data.get("started_at")
    if started:
        print(f"Started:      {datetime.fromtimestamp(int(started)).isoformat(timespec='seconds')}")
    hb = state.data.get("heartbeat")
    if hb:
        age = int(time.time() - int(hb))
        print(f"Heartbeat:    {age}s ago")
    print(f"Backend:      {state.data.get('vpn_backend', '?')}")
    print(f"VPN iface:    {state.data.get('vpn_interface', '?')}")
    print(f"VPN gateway:  {state.data.get('vpn_gateway') or '—'}")
    routes = state.previous_routes()
    print(f"Active routes: {len(routes)}")
    if LOG_FILE.exists():
        print(f"\nLast 10 log lines ({LOG_FILE}):")
        try:
            lines = LOG_FILE.read_text(encoding="utf-8").splitlines()[-10:]
            for line in lines:
                print(f"  {line}")
        except OSError:
            pass


def _update_list(url: str, dest: Path) -> int:
    log = get_logger("tunnel_manager.cli")
    log.info(f"Downloading list from {url}...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "tunnel_manager"})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read()
    except Exception as e:
        log.error(f"Download failed: {e}")
        return 1
    dest.write_bytes(data)
    log.info(f"Wrote {len(data)} bytes to {dest}")
    return 0


def _restore_vpn_info(state: StateFile) -> VPNInfo | None:
    """Rebuild a VPNInfo from saved state for cleanup-without-live-VPN."""
    iface = state.previous_interface()
    if not iface:
        return None
    return VPNInfo(interface=iface, gateway=state.previous_gateway() or None)


def main() -> int:
    args = _parse_args()
    use_tui = not args.no_tui and not args.cleanup and not args.status

    mem = setup_logging(verbose=args.verbose, use_tui=use_tui)
    log = get_logger("tunnel_manager.cli")

    if args.status:
        _print_status(StateFile())
        return 0

    if args.update_list:
        return _update_list(args.update_list, BASE_DIR / "tunnel_list.txt")

    try:
        backend = get_backend()
    except RuntimeError as e:
        log.error(str(e))
        return 1

    cfg = Config.load(args.config)

    if args.compute_sha:
        try:
            print(compute_sha256(cfg.list_url, BASE_DIR))
        except Exception as e:
            log.error(f"Could not compute SHA-256: {e}")
            return 1
        return 0

    if not args.dry_run and not backend.is_privileged():
        hint = (
            "Run PowerShell as Administrator"
            if backend.name() == "windows"
            else "Run as root (sudo -E)"
        )
        log.error(f"Insufficient privileges to modify routing table. {hint}.")
        return 2

    state = StateFile()
    if not args.cleanup and state.is_another_instance_alive():
        prev_pid = state.data.get("pid")
        log.error(f"Another instance is running (PID {prev_pid}). Exiting.")
        return 3

    state.save(pid=os.getpid(), started_at=int(time.time()))
    app = TunnelApp(backend, cfg, state, BASE_DIR, dry_run=args.dry_run)

    rc = 0
    try:
        asyncio.run(_run(app, backend, state, args, log, mem, use_tui))
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except Exception as e:
        log.exception(f"Fatal: {e}")
        rc = 1
    finally:
        state.save(pid=0)
    return rc


async def _run(
    app: TunnelApp,
    backend: RouteBackend,
    state: StateFile,
    args: argparse.Namespace,
    log,
    mem,
    use_tui: bool,
) -> None:
    if args.cleanup:
        info = backend.detect_vpn() or _restore_vpn_info(state)
        if info is None:
            log.error(
                "VPN not detected and no recorded interface in state — nothing to clean."
            )
            return
        app.vpn_info = info
        await app.cleanup()
        return

    extra = []
    if use_tui:
        extra.append(run_tui(app, mem, persist=args.persist_tui))
    await app.run(extra_tasks=extra)


if __name__ == "__main__":
    sys.exit(main())
