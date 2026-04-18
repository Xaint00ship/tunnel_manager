"""Command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
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
from .fetcher import compute_sha256, load_list
from .log import get_logger, setup_logging
from .parser import parse_route_list
from .paths import (
    LOG_DIR,
    LOG_FILE,
    STATE_DIR,
    USER_DATA_DIR,
    default_config_path,
    list_search_dir,
)
from .state import StateFile
from .tui import run_tui


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
    p.add_argument("--self-test", action="store_true",
                   help="Run a diagnostic check (privs, paths, list, VPN) and exit.")
    p.add_argument("--update-list", metavar="URL",
                   help="Download a fresh list from URL into the user data dir, "
                        "update list_sha256 in config if pinned, and exit.")
    p.add_argument("--compute-sha", action="store_true",
                   help="Print SHA-256 of the configured list source and exit.")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging.")
    p.add_argument("--config", type=Path, default=None,
                   help="Path to config.json (default: <repo>/config.json or "
                        "user config dir).")
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
    print(f"List ETag:    {state.data.get('list_etag') or '—'}")
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


def _check(label: str, fn) -> bool:
    print(f"  {label:22}", end=" ")
    try:
        result = fn()
    except Exception as e:
        print(f"[FAIL] {type(e).__name__}: {e}")
        return False
    if result is True or result is None:
        print("[OK]")
        return True
    print(f"[OK] {result}")
    return True


def _self_test(config_path: Path) -> int:
    print(f"tunnel_manager {__version__}")
    print(f"Python {sys.version.split()[0]} on {sys.platform}\n")

    ok_count = 0
    total = 0

    def check(label, fn):
        nonlocal ok_count, total
        total += 1
        if _check(label, fn):
            ok_count += 1

    check("Backend factory", lambda: get_backend().name())

    backend = get_backend()
    check(
        "Privileged",
        lambda: "yes" if backend.is_privileged() else "NO (read-only checks only)",
    )

    def _writable(path: Path) -> str:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".write_probe"
        probe.write_text("ok")
        probe.unlink()
        return f"writable: {path}"

    check("State dir",  lambda: _writable(STATE_DIR))
    check("Log dir",    lambda: _writable(LOG_DIR))
    check("Data dir",   lambda: _writable(USER_DATA_DIR))

    cfg: Config | None = None

    def _load_cfg():
        nonlocal cfg
        cfg = Config.load(config_path)
        return f"loaded {config_path}"
    check("Config", _load_cfg)

    def _load_list():
        assert cfg is not None
        content, _ = load_list(cfg.list_url, list_search_dir(), cfg.list_sha256)
        if content is None:
            return "304 (cached)"
        sections = parse_route_list(content)
        n = sum(len(v) for v in sections.values())
        return f"{n} entries / {len(sections)} sections"
    check("Route list source", _load_list)

    def _detect_vpn():
        info = backend.detect_vpn()
        if info is None:
            return "no VPN detected (connect VPN before live run)"
        return f"iface={info.interface} gw={info.gateway or '—'} isp={info.local_gateway or '—'}"
    check("VPN detection", _detect_vpn)

    print(f"\n{ok_count}/{total} checks passed")
    return 0 if ok_count == total else 1


def _update_list(url: str, config_path: Path) -> int:
    log = get_logger("tunnel_manager.cli")
    USER_DATA_DIR.mkdir(parents=True, exist_ok=True)
    dest = USER_DATA_DIR / "tunnel_list.txt"
    log.info(f"Downloading list from {url}...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "tunnel_manager"})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read()
    except Exception as e:
        log.error(f"Download failed: {e}")
        return 1
    dest.write_bytes(data)
    new_sha = hashlib.sha256(data).hexdigest()
    log.info(f"Wrote {len(data)} bytes to {dest}  (sha256 {new_sha[:16]}...)")

    # If the user has a SHA pin configured, rotate it so the next run doesn't
    # fail with a mismatch.
    if config_path.exists():
        try:
            cfg_dict = json.loads(config_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            log.warning(f"Could not update list_sha256 in {config_path}: {e}")
            return 0
        if cfg_dict.get("list_sha256"):
            cfg_dict["list_sha256"] = new_sha
            config_path.write_text(
                json.dumps(cfg_dict, indent=2), encoding="utf-8"
            )
            log.info(f"Updated list_sha256 in {config_path}")
    return 0


def _restore_vpn_info(state: StateFile) -> VPNInfo | None:
    """Rebuild a VPNInfo from saved state for cleanup-without-live-VPN."""
    iface = state.previous_interface()
    if not iface:
        return None
    return VPNInfo(interface=iface, gateway=state.previous_gateway() or None)


def main() -> int:
    args = _parse_args()
    config_path = args.config or default_config_path()
    use_tui = (
        not args.no_tui
        and not args.cleanup
        and not args.status
        and not args.self_test
    )

    mem = setup_logging(verbose=args.verbose, use_tui=use_tui)
    log = get_logger("tunnel_manager.cli")

    if args.status:
        _print_status(StateFile())
        return 0

    if args.self_test:
        return _self_test(config_path)

    if args.update_list:
        return _update_list(args.update_list, config_path)

    try:
        backend = get_backend()
    except RuntimeError as e:
        log.error(str(e))
        return 1

    cfg = Config.load(config_path)

    if args.compute_sha:
        try:
            print(compute_sha256(cfg.list_url, list_search_dir()))
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
    app = TunnelApp(backend, cfg, state, list_search_dir(), dry_run=args.dry_run)

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
