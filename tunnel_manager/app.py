"""Tunnel orchestrator — startup order, diff-based refresh, cleanup."""

from __future__ import annotations

import asyncio
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


def _report_grey(base_url: str, api_key: str | None, ip: str, reason: str) -> None:
    """POST ip to dashboard grey list report endpoint."""
    payload = json.dumps({"ip": ip, "reason": reason}).encode()
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/api/analytics/grey-list/report",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    if api_key:
        req.add_header("X-Api-Key", api_key)
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass


def _fetch_with_etag(
    source: str, base_dir, sha256, prev_etag, api_key=None
) -> tuple[str | None, str | None]:
    """Thin wrapper around load_list, kept module-level so it pickles cleanly
    for asyncio's run_in_executor (older 3.x quirks aside)."""
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
        self.last_updated: float | None = None
        self.status_line = "Initializing..."
        self.running = False
        self._cached_list_content: str | None = None

    # ── lifecycle ───────────────────────────────────────────────────────

    async def start(self) -> None:
        loop = asyncio.get_event_loop()
        self.log.info("Starting VPN Split Tunnel Manager...")
        self.log.info("Detecting VPN interface...")
        info = await loop.run_in_executor(None, self.backend.detect_vpn)
        if info is None:
            self.log.warning(
                "VPN not detected. Watchdog will pick it up on reconnect."
            )
            self.status_line = "VPN disconnected"
            self.vpn_connected = False
        else:
            self.vpn_info = info
            self.vpn_connected = True
            self.log.info(
                f"VPN: {info.describe()}  |  ISP: {info.local_gateway or '—'}"
            )
            await self._setup_tunnel()
        self.running = True

    async def _setup_tunnel(self) -> None:
        """Rebuild the split tunnel: load list, compute diff, apply."""
        loop = asyncio.get_event_loop()
        assert self.vpn_info is not None
        info = self.vpn_info

        # 1. Load list BEFORE touching routing — a failed fetch must not
        #    leave the user with a torn-down default route. ETag lets us
        #    skip the diff entirely when the source hasn't changed.
        self.status_line = "Loading list..."
        prev_etag = self.state.data.get("list_etag")
        try:
            raw, new_etag = await loop.run_in_executor(
                None,
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
            self.log.info("Route list unchanged (304) — skipping diff.")
            self.status_line = "Active"
            return
        if raw is None:
            # 304 but no in-memory cache (first run after restart) — refetch unconditionally.
            self.log.debug("304 with empty cache; refetching without ETag")
            try:
                raw, new_etag = await loop.run_in_executor(
                    None,
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
        self.log.info(
            f"Parsed {len(parsed)} entries across {len(sections)} services"
        )

        # Aggregate: 700 entries → ~200 CIDRs, fewer route operations.
        desired: set[str] = set(collapse_routes(list(parsed)))
        if len(desired) < len(parsed):
            self.log.info(
                f"Aggregated {len(parsed)} entries → {len(desired)} CIDRs"
            )

        # 2. Now snip the catch-all default.
        self.log.info("Removing catch-all VPN default route...")
        if not self.dry_run:
            await loop.run_in_executor(
                None, self.backend.remove_default_vpn_route, info
            )

        # 3. Diff against existing + previously-recorded routes.
        try:
            existing = set(
                await loop.run_in_executor(None, self.backend.list_vpn_routes, info)
            )
        except Exception as e:
            self.log.debug(f"list_vpn_routes failed: {e}")
            existing = set()
        prev = set(self.state.previous_routes())

        def norm(e: str) -> str:
            if "/" in e:
                return e
            return f"{e}/32" if ":" not in e else f"{e}/128"

        existing_norm = {norm(e) for e in existing}
        prev_norm = {norm(e) for e in prev}
        desired_norm = {norm(e) for e in desired}

        stale = (existing_norm | prev_norm) - desired_norm
        new = {e for e in desired if norm(e) not in existing_norm}

        if stale:
            self.log.info(f"Removing {len(stale)} stale routes...")
            if not self.dry_run:
                await loop.run_in_executor(
                    None, self.backend.remove_routes, list(stale), info
                )

        added_total = failed_total = 0
        if new:
            self.log.info(f"Adding {len(new)} routes...")
            self.status_line = "Adding routes..."
            new_list = list(new)
            failures: list[tuple[str, str]] = []
            for i in range(0, len(new_list), self.CHUNK_SIZE):
                chunk = new_list[i : i + self.CHUNK_SIZE]
                if self.dry_run:
                    added_total += len(chunk)
                    continue
                result: AddResult = await loop.run_in_executor(
                    None, self.backend.add_routes, chunk, info
                )
                added_total += result.count
                failed_total += result.failure_count
                failures.extend(result.failed)

            self._log_failure_summary(failures)
            self.log.info(
                f"Routes: +{added_total} -{len(stale)} "
                f"({failed_total} failed, "
                f"{len(desired) - added_total - failed_total} unchanged)"
            )
            if self.config.grey_api_url and new_list:
                asyncio.create_task(self._probe_and_report(new_list))
        else:
            self.log.info("No new routes to add (already synced)")

        self.active_routes = desired
        self.total_routes = len(desired)
        self.sections = {name: len(entries) for name, entries in sections.items()}
        self.last_updated = time.time()
        self.status_line = "Active" + (" (dry-run)" if self.dry_run else "")
        self.state.save(
            active_routes=sorted(desired),
            vpn_interface=info.interface,
            vpn_gateway=info.gateway or "",
            vpn_backend=self.backend.name(),
            list_etag=new_etag,
        )

    async def _probe_and_report(self, routes: list[str]) -> None:
        """Probe newly added routes via HTTP; report non-200 to grey list."""
        loop = asyncio.get_event_loop()
        sem = asyncio.Semaphore(10)

        async def probe_one(cidr: str) -> None:
            ip = cidr.split("/")[0]
            async with sem:
                code = await loop.run_in_executor(None, _http_probe, ip)
            if code != 200:
                reason = f"HTTP {code}" if code else "недоступен"
                await loop.run_in_executor(
                    None, _report_grey,
                    self.config.grey_api_url, self.config.grey_api_key, cidr, reason
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

    async def worker_refresh(self) -> None:
        while self.running:
            interval = max(60, self.config.refresh_interval_hours * 3600)
            await asyncio.sleep(interval)
            if not self.vpn_connected:
                continue
            self.log.info("Scheduled refresh...")
            await self._setup_tunnel()

    async def worker_watchdog(self) -> None:
        loop = asyncio.get_event_loop()
        while self.running:
            interval = max(5, self.config.watchdog_interval_seconds)
            await asyncio.sleep(interval)
            was = self.vpn_connected
            try:
                info = await loop.run_in_executor(None, self.backend.detect_vpn)
            except Exception as e:
                self.log.debug(f"watchdog detect failed: {e}")
                continue
            connected = info is not None
            if connected and not was:
                self.vpn_info = info
                self.vpn_connected = True
                self.log.info("VPN reconnected — rebuilding tunnel...")
                await self._setup_tunnel()
            elif not connected and was:
                # detect_vpn looks for a default route; after we replace it with
                # specific routes that route is gone — verify the interface itself
                # is still up before declaring the VPN disconnected.
                if self.vpn_info and await loop.run_in_executor(
                    None, self.backend.is_interface_up, self.vpn_info.interface
                ):
                    continue
                self.vpn_connected = False
                self.status_line = "VPN disconnected"
                self.log.warning("VPN disconnected.")

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
        loop = asyncio.get_event_loop()
        self.log.info(f"Removing {len(routes)} routes...")
        await loop.run_in_executor(
            None, self.backend.remove_routes, routes, self.vpn_info
        )
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
