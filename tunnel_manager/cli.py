"""Command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from pathlib import Path

from .app import TunnelApp
from .backends import get_backend
from .config import Config
from .fetcher import compute_sha256
from .log import get_logger, setup_logging
from .state import StateFile
from .tui import run_tui

# Repo root = parent of the package dir. Used to resolve relative list_url paths
# and the default config.json location.
BASE_DIR = Path(__file__).resolve().parent.parent


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="tunnel_manager",
        description="VPN split-tunnel manager — routes a curated IP list through VPN.",
    )
    p.add_argument("--no-tui", action="store_true",
                   help="Plain-text logging, no full-screen TUI.")
    p.add_argument("--dry-run", action="store_true",
                   help="Print planned changes; do not modify routing table.")
    p.add_argument("--cleanup", action="store_true",
                   help="Remove all routes added by a previous run and exit.")
    p.add_argument("--compute-sha", action="store_true",
                   help="Print SHA-256 of the list source and exit (for pinning).")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging.")
    p.add_argument("--config", type=Path, default=BASE_DIR / "config.json",
                   help="Path to config.json (default: <repo>/config.json).")
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    mem = setup_logging(
        verbose=args.verbose,
        use_tui=not args.no_tui and not args.cleanup,
    )
    log = get_logger("tunnel_manager.cli")

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
    prev_pid = int(state.data.get("pid") or 0)
    if prev_pid and prev_pid != os.getpid() and StateFile.is_pid_alive(prev_pid):
        log.error(f"Another instance is running (PID {prev_pid}). Exiting.")
        return 3

    state.save(pid=os.getpid(), started_at=int(time.time()))
    app = TunnelApp(backend, cfg, state, BASE_DIR, dry_run=args.dry_run)

    rc = 0
    try:
        asyncio.run(_run(app, backend, state, args, log, mem))
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except Exception as e:
        log.exception(f"Fatal: {e}")
        rc = 1
    finally:
        # Drop our PID but keep active_routes so next run can reconcile.
        state.save(pid=0)
    return rc


async def _run(app: TunnelApp, backend, state: StateFile, args, log, mem) -> None:
    if args.cleanup:
        info = backend.detect_vpn()
        if info is None:
            log.error("VPN not detected — cannot target cleanup to an interface.")
            return
        app.vpn_info = info
        await app.cleanup()
        return

    extra = [run_tui(app, mem)] if not args.no_tui else []
    await app.run(extra_tasks=extra)


if __name__ == "__main__":
    sys.exit(main())
