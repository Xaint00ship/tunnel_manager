"""Tunnel orchestrator — startup order, diff-based refresh, cleanup."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Optional

from .backends import AddResult, RouteBackend, VPNInfo
from .config import Config
from .fetcher import load_list
from .log import get_logger
from .parser import parse_route_list
from .state import StateFile


class TunnelApp:
    CHUNK_SIZE = 200

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

        self.vpn_info: Optional[VPNInfo] = None
        self.vpn_connected = False
        self.sections: dict[str, int] = {}
        self.active_routes: set[str] = set()
        self.total_routes = 0
        self.last_updated: Optional[float] = None
        self.status_line = "Initializing..."
        self.running = False

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

        # 1. Load & parse list BEFORE touching routing. A failed fetch must not
        #    leave the user with a torn-down default route.
        self.status_line = "Loading list..."
        try:
            raw = await loop.run_in_executor(
                None, load_list, self.config.list_url,
                self.base_dir, self.config.list_sha256,
            )
        except Exception as e:
            self.log.error(f"Failed to load route list: {e}")
            self.status_line = "Load failed"
            return

        sections = parse_route_list(raw)
        desired: set[str] = set()
        for entries in sections.values():
            desired.update(entries)
        self.log.info(
            f"Parsed {len(desired)} entries across {len(sections)} services"
        )

        # 2. Only now remove the VPN catch-all default.
        self.log.info("Removing catch-all VPN default route...")
        if not self.dry_run:
            await loop.run_in_executor(
                None, self.backend.remove_default_vpn_route, info
            )

        # 3. Diff against what's already on the interface + what we recorded
        #    in state (covers dangling routes from a prior crash).
        try:
            existing = set(
                await loop.run_in_executor(None, self.backend.list_vpn_routes, info)
            )
        except Exception as e:
            self.log.debug(f"list_vpn_routes failed: {e}")
            existing = set()
        prev = set(self.state.previous_routes())

        # Normalize: previously added entries may or may not include /32.
        def norm(e: str) -> str:
            return e if "/" in e else f"{e}/32"

        existing_norm = {norm(e) for e in existing}
        prev_norm = {norm(e) for e in prev}
        desired_norm = {norm(e) for e in desired}

        stale = (existing_norm | prev_norm) - desired_norm
        new = desired - {e for e in desired if norm(e) in existing_norm}

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
                for entry, err in result.failed[:3]:
                    self.log.warning(f"add {entry}: {err}")
                if result.failure_count > 3:
                    self.log.warning(
                        f"...and {result.failure_count - 3} more add failures"
                    )
            self.log.info(
                f"Routes: +{added_total} -{len(stale)} "
                f"({failed_total} failed, {len(desired) - added_total - failed_total} unchanged)"
            )
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
        )

    # ── workers ─────────────────────────────────────────────────────────

    async def worker_refresh(self) -> None:
        interval = max(60, self.config.refresh_interval_hours * 3600)
        while self.running:
            await asyncio.sleep(interval)
            if not self.vpn_connected:
                continue
            self.log.info("Scheduled refresh...")
            await self._setup_tunnel()

    async def worker_watchdog(self) -> None:
        interval = max(5, self.config.watchdog_interval_seconds)
        loop = asyncio.get_event_loop()
        while self.running:
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
                self.vpn_connected = False
                self.status_line = "VPN disconnected"
                self.log.warning("VPN disconnected.")

    # ── cleanup ─────────────────────────────────────────────────────────

    async def cleanup(self) -> None:
        """Remove all routes we added through the VPN interface."""
        if self.vpn_info is None:
            self.log.warning("Can't cleanup — VPN interface unknown.")
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

    async def run(self, extra_tasks: list = None) -> None:
        await self.start()
        tasks = [
            asyncio.create_task(self.worker_refresh()),
            asyncio.create_task(self.worker_watchdog()),
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
