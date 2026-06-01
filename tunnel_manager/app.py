"""Tunnel orchestrator — startup order, diff-based refresh, cleanup."""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

from .aggregator import collapse_routes
from .backends import AddResult, RouteBackend, VPNInfo
from .config import Config
from .fetcher import load_list
from .log import get_logger
from .parser import parse_route_list
from .state import StateFile


def _http_probe(ip: str, timeout: int = 3) -> int:
    """Return HTTP status for http://ip/ or 0 on connection error."""
    try:
        with urllib.request.urlopen(f"http://{ip}/", timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def _report_grey(base_url: str | None, api_key: str | None, ip: str, reason: str) -> None:
    """POST ip to dashboard grey list report endpoint."""
    if base_url is None:
        return
    payload = json.dumps({"ip": ip, "reason": reason}).encode()
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/api/analytics/grey-list/report",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    if api_key:
        req.add_header("X-Api-Key", api_key)
    with contextlib.suppress(Exception):
        urllib.request.urlopen(req, timeout=5)


def _fetch_with_etag(
    source: str, base_dir, sha256, prev_etag, api_key=None
) -> tuple[str | None, str | None]:
    """Thin wrapper around load_list for thread offloading."""
    return load_list(source, base_dir, sha256=sha256, prev_etag=prev_etag, api_key=api_key)


class TunnelApp:
    CHUNK_SIZE = 200
    MAX_LOGGED_ERROR_KINDS = 5

    def __init__(
        self,
        backend: RouteBackend,
        config: Config,
        state: StateFile,
        base_dir: Path,
        dry_run: bool = False,
    ):
        self.backend = backend
        self.config = config
        self.state = state
        self.base_dir = base_dir
        self.dry_run = dry_run
        self.log = get_logger("tunnel_manager.app")

        self.vpn_info: VPNInfo | None = None
        self.vpn_connected = False
        self.sections: dict[str, int] = {}
        self.active_routes: set[str] = set()
        self.total_routes = 0
        self.route_progress_done = 0
        self.route_progress_total = 0
        self.route_progress_percent = 0
        self.last_updated: float | None = None
        self.status_line = "Initializing..."
        self.running = False
        self._cached_list_content: str | None = None
        self._bg_tasks: list = []
        self._last_detect: float = 0.0
        self._last_vpn_info: VPNInfo | None = None
        self._detect_failures: int = 0
        self._watchdog_circuit_until: float = 0.0
        self._persistent_warning_logged = False
        self._routes_blocked = False

    @staticmethod
    def _norm_route(entry: str) -> str:
        if "/" in entry:
            return entry
        return f"{entry}/32" if ":" not in entry else f"{entry}/128"

    async def _detect_vpn(self) -> VPNInfo | None:
        now = time.time()
        if now - self._last_detect < 5 and self._last_vpn_info is not None:
            self._apply_configured_vpn_options(self._last_vpn_info)
            return self._last_vpn_info
        info = await self.backend.detect_vpn_async()
        if info is not None:
            self._apply_configured_vpn_options(info)
        self._last_detect = now
        self._last_vpn_info = info
        return info

    def _apply_configured_vpn_options(self, info: VPNInfo) -> None:
        if self.config.vpn_interface and info.interface != self.config.vpn_interface:
            self.log.info(
                f"Using configured VPN interface {self.config.vpn_interface} "
                f"(detected {info.interface})"
            )
            info.interface = self.config.vpn_interface
        info.persistent_routes = self.config.persistent_routes
        if (
            info.persistent_routes
            and not self.backend.supports_persistent_routes()
            and not self._persistent_warning_logged
        ):
            self.log.warning(
                f"Persistent routes are not supported by {self.backend.name()} backend; "
                "routes will be active for this session only."
            )
            self._persistent_warning_logged = True

    async def start(self) -> None:
        self.log.info("Starting VPN Split Tunnel Manager...")
        self.log.info("Detecting VPN interface...")
        info = await self._detect_vpn()
        if info is None:
            self.log.warning("VPN not detected. Watchdog will pick it up on reconnect.")
            self.status_line = "VPN disconnected"
            self.vpn_connected = False
            await self._block_routes_fail_closed("startup without VPN")
        else:
            self.vpn_info = info
            self.vpn_connected = True
            self.log.info(f"VPN: {info.describe()}  |  ISP: {info.local_gateway or '—'}")
            await self._setup_tunnel(force_apply=True)
        self.running = True

    async def _setup_tunnel(self, force_apply: bool = False) -> None:
        """Rebuild the split tunnel: load list, compute diff, apply."""
        assert self.vpn_info is not None
        info = self.vpn_info

        # 1. Load list BEFORE touching routing — a failed fetch must not
        #    leave the user with a torn-down default route. ETag lets us
        #    skip the diff entirely when the source hasn't changed.
        self.status_line = "Loading list..."
        self.route_progress_done = 0
        self.route_progress_total = 0
        self.route_progress_percent = 0
        prev_etag = self.state.data.get("list_etag")
        try:
            raw, new_etag = await asyncio.to_thread(
                _fetch_with_etag,
                self.config.effective_list_url(),
                self.base_dir,
                self.config.list_sha256,
                prev_etag,
                self.config.list_api_key,
            )
        except Exception as e:
            self.log.error(f"Failed to load route list: {e}")
            self.status_line = "Load failed"
            return

        if raw is None and self._cached_list_content is not None:
            if not force_apply:
                self.log.info("Route list unchanged (304) — skipping diff.")
                self.status_line = "Active"
                return
            self.log.info("Route list unchanged (304) — reapplying cached list.")
            raw = self._cached_list_content
        if raw is None:
            # 304 but no in-memory cache (first run after restart) — refetch unconditionally.
            self.log.debug("304 with empty cache; refetching without ETag")
            try:
                raw, new_etag = await asyncio.to_thread(
                    _fetch_with_etag,
                    self.config.effective_list_url(),
                    self.base_dir,
                    self.config.list_sha256,
                    None,
                    self.config.list_api_key,
                )
            except Exception as e:
                self.log.error(f"Failed to refetch route list: {e}")
                return
        self._cached_list_content = raw

        sections = parse_route_list(raw or "")
        parsed: set[str] = set()
        for entries in sections.values():
            parsed.update(entries)
        self.log.info(f"Parsed {len(parsed)} entries across {len(sections)} services")

        # Aggregate: 700 entries → ~200 CIDRs, fewer route operations.
        desired: set[str] = set(collapse_routes(list(parsed)))
        if len(desired) < len(parsed):
            self.log.info(f"Aggregated {len(parsed)} entries → {len(desired)} CIDRs")

        # 2. Now snip the catch-all default.
        self.log.info("Removing catch-all VPN default route...")
        if not self.dry_run:
            await self.backend.remove_default_vpn_route_async(info)

        # 3. Diff against existing + previously-recorded routes.
        try:
            existing = set(await self.backend.list_vpn_routes_async(info))
        except Exception as e:
            self.log.debug(f"list_vpn_routes failed: {e}")
            existing = set()
        prev = set(self.state.previous_routes())

        existing_norm = {self._norm_route(e) for e in existing}
        prev_norm = {self._norm_route(e) for e in prev}
        desired_norm = {self._norm_route(e) for e in desired}

        stale = (existing_norm | prev_norm) - desired_norm
        new = {e for e in desired if self._norm_route(e) not in existing_norm}

        if stale:
            self.log.info(f"Removing {len(stale)} stale routes...")
            self.status_line = f"Removing stale routes... 0/{len(stale)} (0%)"
            if not self.dry_run:
                await self.backend.remove_routes_async(list(stale), info)
            self.status_line = f"Removing stale routes... {len(stale)}/{len(stale)} (100%)"

        added_total = failed_total = 0
        if new:
            await self._unblock_routes_fail_closed(new)
            self.log.info(f"Adding {len(new)} routes...")
            self.status_line = f"Adding routes... 0/{len(new)} (0%)"
            new_list = list(new)
            self.route_progress_total = len(new_list)
            failures: list[tuple[str, str]] = []
            for i in range(0, len(new_list), self.CHUNK_SIZE):
                chunk = new_list[i : i + self.CHUNK_SIZE]
                if self.dry_run:
                    added_total += len(chunk)
                else:
                    result: AddResult = await self.backend.add_routes_async(chunk, info)
                    added_total += result.count
                    failed_total += result.failure_count
                    failures.extend(result.failed)
                attempted = min(i + len(chunk), len(new_list))
                self.route_progress_done = attempted
                self.route_progress_percent = int(attempted * 100 / len(new_list))
                self.status_line = (
                    f"Adding routes... {attempted}/{len(new_list)} ({self.route_progress_percent}%)"
                )

            self._log_failure_summary(failures)
            self.log.info(
                f"Routes: +{added_total} -{len(stale)} "
                f"({failed_total} failed, "
                f"{len(desired) - added_total - failed_total} unchanged)"
            )
            if self.config.grey_api_url and new_list:
                self._bg_tasks.append(asyncio.create_task(self._probe_and_report(new_list)))
        else:
            self.log.info("No new routes to add (already synced)")

        self.active_routes = desired
        self.total_routes = len(desired)
        self.sections = {name: len(entries) for name, entries in sections.items()}
        self.last_updated = time.time()
        self.route_progress_done = 0
        self.route_progress_total = 0
        self.route_progress_percent = 0
        self.status_line = "Active" + (" (dry-run)" if self.dry_run else "")
        self.state.save(
            active_routes=sorted(desired),
            vpn_interface=info.interface,
            vpn_gateway=info.gateway or "",
            vpn_backend=self.backend.name(),
            list_etag=new_etag,
        )

    def _routes_for_fail_closed(self) -> list[str]:
        return sorted(self.active_routes or set(self.state.previous_routes()))

    async def _block_routes_fail_closed(self, reason: str) -> None:
        if not self.config.fail_closed_routes or self.dry_run:
            return
        routes = self._routes_for_fail_closed()
        if not routes:
            return
        self.log.warning(f"Fail-closed: blocking {len(routes)} routes ({reason}).")
        await self.backend.block_routes_async(routes)
        self._routes_blocked = True

    async def _unblock_routes_fail_closed(self, routes: set[str] | list[str] | None = None) -> None:
        if not self.config.fail_closed_routes or self.dry_run:
            return
        to_unblock = sorted(routes or self._routes_for_fail_closed())
        if not to_unblock:
            return
        await self.backend.unblock_routes_async(to_unblock)
        if self._routes_blocked:
            self.log.info(f"Fail-closed: unblocked {len(to_unblock)} routes.")
        self._routes_blocked = False

    async def _probe_and_report(self, routes: list[str]) -> None:
        """Probe newly added routes via HTTP; report non-200 to grey list."""
        sem = asyncio.Semaphore(10)

        async def probe_one(cidr: str) -> None:
            ip = cidr.split("/")[0]
            async with sem:
                code = await asyncio.to_thread(_http_probe, ip)
            if code != 200:
                reason = f"HTTP {code}" if code else "недоступен"
                await asyncio.to_thread(
                    _report_grey, self.config.grey_api_url, self.config.grey_api_key, cidr, reason
                )
                self.log.debug(f"grey list: {cidr} → {reason}")

        # Only probe host routes (/32) — probing subnets makes no sense
        host_routes = [r for r in routes if r.endswith("/32") or "/" not in r][:100]
        if not host_routes:
            return
        self.log.info(f"Probing {len(host_routes)} new routes for grey list...")
        await asyncio.gather(*[probe_one(r) for r in host_routes], return_exceptions=True)

    def _log_failure_summary(self, failures: list[tuple[str, str]]) -> None:
        if not failures:
            return
        # Group identical errors so 200x "File exists" shows as one line.
        groups = Counter(msg for _, msg in failures)
        for msg, count in groups.most_common(self.MAX_LOGGED_ERROR_KINDS):
            sample = next(entry for entry, m in failures if m == msg)
            self.log.warning(f"add failed [{count}x]: {sample} — {msg}")
        rest = sum(groups.values()) - sum(
            c for _, c in groups.most_common(self.MAX_LOGGED_ERROR_KINDS)
        )
        if rest > 0:
            self.log.warning(f"...and {rest} more failures of other kinds")

    # ── workers ─────────────────────────────────────────────────────────

    async def _repair_route_drift(self) -> bool:
        if self.vpn_info is None:
            return False
        desired = {self._norm_route(e) for e in (self.active_routes or set(self.state.previous_routes()))}
        if not desired:
            return False
        try:
            existing = {
                self._norm_route(e)
                for e in await self.backend.list_vpn_routes_async(self.vpn_info)
            }
            default_on_vpn = await self.backend.has_default_vpn_route_async(self.vpn_info)
        except Exception as e:
            self.log.debug(f"route drift check failed: {e}")
            return False
        missing = desired - existing
        if not missing and not default_on_vpn:
            return False
        reasons: list[str] = []
        if missing:
            reasons.append(f"{len(missing)} missing routes")
        if default_on_vpn:
            reasons.append("catch-all default route")
        self.log.warning(f"Route drift detected ({', '.join(reasons)}); repairing tunnel.")
        await self._setup_tunnel(force_apply=True)
        return True

    async def worker_refresh(self) -> None:
        while self.running:
            interval = max(60, self.config.refresh_interval_hours * 3600)
            await asyncio.sleep(interval)
            if not self.vpn_connected:
                continue
            self.log.info("Scheduled refresh...")
            await self._setup_tunnel()

    async def worker_watchdog(self) -> None:
        while self.running:
            interval = max(5, self.config.watchdog_interval_seconds)
            await asyncio.sleep(interval)
            if time.time() < self._watchdog_circuit_until:
                remaining = int(self._watchdog_circuit_until - time.time())
                self.status_line = f"VPN detect paused ({remaining}s)"
                continue
            was = self.vpn_connected
            try:
                info = await self._detect_vpn()
                self._detect_failures = 0
                self._watchdog_circuit_until = 0.0
            except Exception as e:
                self._detect_failures += 1
                backoff = min(60, 2**self._detect_failures)
                self.log.debug(f"watchdog detect failed: {e}, backoff {backoff}s")
                if self._detect_failures >= self.config.watchdog_failure_threshold:
                    cooldown = self.config.watchdog_circuit_breaker_seconds
                    if cooldown > 0:
                        self._watchdog_circuit_until = time.time() + cooldown
                        self.status_line = f"VPN detect paused ({cooldown}s)"
                        self.log.warning(
                            f"VPN detection failed {self._detect_failures} times; "
                            f"pausing detection for {cooldown}s."
                        )
                await asyncio.sleep(backoff)
                continue
            connected = info is not None
            if connected and not was:
                self.vpn_info = info
                self.vpn_connected = True
                self.log.info("VPN reconnected — rebuilding tunnel...")
                await self._unblock_routes_fail_closed()
                await self._setup_tunnel(force_apply=True)
            elif connected and was:
                self.vpn_info = info
                await self._repair_route_drift()
            elif not connected and was:
                if self.vpn_info:
                    iface = self.vpn_info.interface
                    if await self.backend.is_interface_up_async(iface):
                        continue
                self.vpn_connected = False
                self.status_line = "VPN disconnected"
                self.log.warning("VPN disconnected.")
                await self._block_routes_fail_closed("VPN disconnected")

    async def worker_heartbeat(self) -> None:
        while self.running:
            await asyncio.sleep(max(5, self.config.heartbeat_interval_seconds))
            try:
                self.state.heartbeat()
            except OSError as e:
                self.log.debug(f"heartbeat write failed: {e}")

    async def worker_config_reload(self) -> None:
        while self.running:
            await asyncio.sleep(10)
            new_cfg = self.config.maybe_reload()
            if new_cfg is not self.config:
                self.log.info("Config changed on disk — reloading.")
                self.config = new_cfg

    # ── cleanup ─────────────────────────────────────────────────────────

    async def cleanup(self) -> None:
        """Remove all routes we previously added through the VPN interface."""
        if self.vpn_info is None:
            self.log.warning("Cannot cleanup — VPN interface unknown.")
            return
        routes = list(self.active_routes) or self.state.previous_routes()
        if not routes:
            self.log.info("No routes to clean up.")
            return
        if self.dry_run:
            self.log.info(f"[dry-run] would remove {len(routes)} routes")
            return
        self.log.info(f"Removing {len(routes)} routes...")
        await self._unblock_routes_fail_closed(routes)
        await self.backend.remove_routes_async(routes, self.vpn_info)
        self.state.clear()
        self.log.info("Cleanup complete.")

    # ── run loop ────────────────────────────────────────────────────────

    async def run(self, extra_tasks: list | None = None) -> None:
        await self.start()
        tasks = [
            asyncio.create_task(self.worker_refresh()),
            asyncio.create_task(self.worker_watchdog()),
            asyncio.create_task(self.worker_heartbeat()),
            asyncio.create_task(self.worker_config_reload()),
        ]
        if extra_tasks:
            for coro in extra_tasks:
                tasks.append(asyncio.create_task(coro))
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            pass
        finally:
            self.running = False
            for t in tasks:
                if not t.done():
                    t.cancel()
