"""Command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import platform
import plistlib
import shutil
import subprocess
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
    REPO_ROOT,
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
    p.add_argument("--no-tui", action="store_true", help="Plain-text logging, no full-screen TUI.")
    p.add_argument(
        "--persist-tui",
        action="store_true",
        help="Keep TUI output in main terminal scrollback (no alt-screen).",
    )
    p.add_argument(
        "--dry-run", action="store_true", help="Print planned changes; do not modify routing table."
    )
    p.add_argument(
        "--cleanup", action="store_true", help="Remove all routes from a previous run and exit."
    )
    p.add_argument(
        "--status",
        action="store_true",
        help="Print current state (active routes, VPN, log tail) and exit.",
    )
    p.add_argument(
        "--self-test",
        action="store_true",
        help="Run a diagnostic check (privs, paths, list, VPN) and exit.",
    )
    p.add_argument(
        "--install-service",
        action="store_true",
        help="Install and start a system service for tunnel-manager, then exit.",
    )
    p.add_argument(
        "--uninstall-service",
        action="store_true",
        help="Stop and remove the tunnel-manager system service, then exit.",
    )
    p.add_argument(
        "--service-name",
        default=None,
        help="Service name/label to install or remove.",
    )
    p.add_argument(
        "--service-repo",
        type=Path,
        default=REPO_ROOT,
        help="Repository/install path used by service templates.",
    )
    p.add_argument(
        "--service-python",
        type=Path,
        default=None,
        help="Python executable used by the installed service.",
    )
    p.add_argument(
        "--update-list",
        metavar="URL",
        help="Download a fresh list from URL into the user data dir, "
        "update list_sha256 in config if pinned, and exit.",
    )
    p.add_argument(
        "--compute-sha",
        action="store_true",
        help="Print SHA-256 of the configured list source and exit.",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging.")
    p.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to config.json (default: <repo>/config.json or user config dir).",
    )
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
    if isinstance(result, tuple) and len(result) == 2 and isinstance(result[0], bool):
        ok, detail = result
        print(f"[{'OK' if ok else 'FAIL'}] {detail}")
        return ok
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
    check(
        "Backend health",
        lambda: backend.health_check() if backend.is_privileged() else "skipped (not privileged)",
    )

    def _writable(path: Path) -> str:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".write_probe"
        probe.write_text("ok")
        probe.unlink()
        return f"writable: {path}"

    check("State dir", lambda: _writable(STATE_DIR))
    check("Log dir", lambda: _writable(LOG_DIR))
    check("Data dir", lambda: _writable(USER_DATA_DIR))

    cfg: Config | None = None

    def _load_cfg():
        nonlocal cfg
        cfg = Config.load(config_path)
        return f"loaded {config_path}"

    check("Config", _load_cfg)

    def _load_list():
        assert cfg is not None
        content, _ = load_list(
            cfg.effective_list_url(), list_search_dir(), cfg.list_sha256, api_key=cfg.list_api_key
        )
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
        req = urllib.request.Request(url, headers={"User-Agent": f"tunnel_manager/{__version__}"})
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
            config_path.write_text(json.dumps(cfg_dict, indent=2), encoding="utf-8")
            log.info(f"Updated list_sha256 in {config_path}")
    return 0


def _run_cmd(cmd: list[str], log) -> subprocess.CompletedProcess:
    log.debug("running: %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def _service_name(system: str, requested: str | None) -> str:
    if requested:
        return requested
    if system == "Windows":
        return "TunnelManager"
    if system == "Darwin":
        return "com.tunnel-manager"
    return "tunnel-manager"


def _service_python(repo_path: Path, explicit: Path | None, system: str) -> Path:
    if explicit is not None:
        return explicit
    venv_python = (
        repo_path / ".venv" / "Scripts" / "python.exe"
        if system == "Windows"
        else repo_path / ".venv" / "bin" / "python"
    )
    if venv_python.exists():
        return venv_python
    return Path(sys.executable)


def _systemd_arg(path: Path) -> str:
    text = str(path)
    if any(ch.isspace() for ch in text):
        return '"' + text.replace('"', '\\"') + '"'
    return text


def _install_linux_service(repo_path: Path, python_path: Path, service_name: str, log) -> int:
    template = REPO_ROOT / "packaging" / "systemd" / "tunnel-manager.service"
    unit_path = Path("/etc/systemd/system") / f"{service_name}.service"
    if template.exists():
        unit = template.read_text(encoding="utf-8")
        unit = unit.replace("WorkingDirectory=/opt/tunnel_manager", f"WorkingDirectory={repo_path}")
        unit = unit.replace(
            "ExecStart=/opt/tunnel_manager/.venv/bin/python /opt/tunnel_manager/main.py --no-tui",
            f"ExecStart={_systemd_arg(python_path)} {_systemd_arg(repo_path / 'main.py')} --no-tui",
        )
    else:
        unit = (
            "[Unit]\n"
            "Description=VPN Split Tunnel Manager\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n\n"
            "[Service]\n"
            "Type=simple\n"
            f"WorkingDirectory={repo_path}\n"
            f"ExecStart={_systemd_arg(python_path)} {_systemd_arg(repo_path / 'main.py')} --no-tui\n"
            "Restart=on-failure\n"
            "RestartSec=5\n"
            "User=root\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )
    unit_path.write_text(unit, encoding="utf-8")
    for cmd in (
        ["systemctl", "daemon-reload"],
        ["systemctl", "enable", "--now", unit_path.name],
    ):
        r = _run_cmd(cmd, log)
        if r.returncode != 0:
            log.error(r.stderr.strip() or r.stdout.strip() or f"{cmd[0]} failed")
            return r.returncode
    log.info(f"Installed systemd service {unit_path}")
    return 0


def _uninstall_linux_service(service_name: str, log) -> int:
    unit_path = Path("/etc/systemd/system") / f"{service_name}.service"
    for cmd in (
        ["systemctl", "disable", "--now", unit_path.name],
        ["systemctl", "daemon-reload"],
    ):
        r = _run_cmd(cmd, log)
        if r.returncode != 0 and cmd[1] != "disable":
            log.error(r.stderr.strip() or r.stdout.strip() or f"{cmd[0]} failed")
            return r.returncode
    if unit_path.exists():
        unit_path.unlink()
    _run_cmd(["systemctl", "daemon-reload"], log)
    log.info(f"Removed systemd service {unit_path}")
    return 0


def _install_macos_service(repo_path: Path, python_path: Path, service_name: str, log) -> int:
    plist_path = Path("/Library/LaunchDaemons") / f"{service_name}.plist"
    plist = {
        "Label": service_name,
        "ProgramArguments": [str(python_path), str(repo_path / "main.py"), "--no-tui"],
        "WorkingDirectory": str(repo_path),
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
        "StandardOutPath": f"/var/log/{service_name}.out.log",
        "StandardErrorPath": f"/var/log/{service_name}.err.log",
    }
    with plist_path.open("wb") as f:
        plistlib.dump(plist, f)
    _run_cmd(["chown", "root:wheel", str(plist_path)], log)
    r = _run_cmd(["launchctl", "load", "-w", str(plist_path)], log)
    if r.returncode != 0:
        log.error(r.stderr.strip() or r.stdout.strip() or "launchctl load failed")
        return r.returncode
    log.info(f"Installed launchd service {plist_path}")
    return 0


def _uninstall_macos_service(service_name: str, log) -> int:
    plist_path = Path("/Library/LaunchDaemons") / f"{service_name}.plist"
    if plist_path.exists():
        _run_cmd(["launchctl", "unload", "-w", str(plist_path)], log)
        plist_path.unlink()
    log.info(f"Removed launchd service {plist_path}")
    return 0


def _install_windows_service(repo_path: Path, python_path: Path, service_name: str, log) -> int:
    if shutil.which("nssm") is None:
        log.error("NSSM not found on PATH. Install from https://nssm.cc and retry.")
        return 1
    main_script = repo_path / "main.py"
    commands = [
        ["nssm", "install", service_name, str(python_path), str(main_script), "--no-tui"],
        ["nssm", "set", service_name, "AppDirectory", str(repo_path)],
        ["nssm", "set", service_name, "Start", "SERVICE_AUTO_START"],
        ["nssm", "set", service_name, "AppStdout", str(repo_path / "tunnel-manager.out.log")],
        ["nssm", "set", service_name, "AppStderr", str(repo_path / "tunnel-manager.err.log")],
        ["nssm", "set", service_name, "AppRotateFiles", "1"],
        ["nssm", "set", service_name, "AppRotateBytes", "1048576"],
        ["nssm", "start", service_name],
    ]
    for cmd in commands:
        r = _run_cmd(cmd, log)
        if r.returncode != 0:
            log.error(r.stderr.strip() or r.stdout.strip() or f"{cmd[0]} failed")
            return r.returncode
    log.info(f"Installed Windows service {service_name}")
    return 0


def _uninstall_windows_service(service_name: str, log) -> int:
    if shutil.which("nssm") is None:
        log.error("NSSM not found on PATH. Install from https://nssm.cc and retry.")
        return 1
    _run_cmd(["nssm", "stop", service_name], log)
    r = _run_cmd(["nssm", "remove", service_name, "confirm"], log)
    if r.returncode != 0:
        log.error(r.stderr.strip() or r.stdout.strip() or "nssm remove failed")
        return r.returncode
    log.info(f"Removed Windows service {service_name}")
    return 0


def _service_command(args: argparse.Namespace, backend: RouteBackend, log) -> int:
    if args.install_service and args.uninstall_service:
        log.error("Choose either --install-service or --uninstall-service, not both.")
        return 2
    if not backend.is_privileged():
        hint = (
            "Run PowerShell as Administrator"
            if backend.name() == "windows"
            else "Run as root (sudo -E)"
        )
        log.error(f"Insufficient privileges to manage system service. {hint}.")
        return 2

    repo_path = args.service_repo.resolve()
    python_path = _service_python(repo_path, args.service_python, platform.system()).resolve()
    main_script = repo_path / "main.py"
    if args.install_service and not main_script.exists():
        log.error(f"main.py not found at {main_script}")
        return 1

    system = platform.system()
    service_name = _service_name(system, args.service_name)
    if system == "Windows":
        return (
            _install_windows_service(repo_path, python_path, service_name, log)
            if args.install_service
            else _uninstall_windows_service(service_name, log)
        )
    if system == "Darwin":
        return (
            _install_macos_service(repo_path, python_path, service_name, log)
            if args.install_service
            else _uninstall_macos_service(service_name, log)
        )
    if system == "Linux":
        return (
            _install_linux_service(repo_path, python_path, service_name, log)
            if args.install_service
            else _uninstall_linux_service(service_name, log)
        )
    log.error(f"Unsupported platform: {system}")
    return 1


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
        and not args.install_service
        and not args.uninstall_service
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

    if args.install_service or args.uninstall_service:
        return _service_command(args, backend, log)

    cfg = Config.load(config_path)

    if args.compute_sha:
        try:
            print(compute_sha256(cfg.effective_list_url(), list_search_dir(), cfg.list_api_key))
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

    now = int(time.time())
    state.save(pid=os.getpid(), started_at=now, heartbeat=now)
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
            log.error("VPN not detected and no recorded interface in state — nothing to clean.")
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
