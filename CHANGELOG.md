# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- `list_api_key` for `list_source: "db"` now works (X-Api-Key header sent in fetcher).
- Windows: false "VPN disconnected" after default route removal (added real `is_interface_up` via Get-NetAdapter). This was the root cause of needing restarts to recover the split tunnel.
- PowerShell and netsh operations now have proper timeouts (SUBPROCESS_TIMEOUT / BATCH_TIMEOUT) to prevent the manager from hanging.

### Added
- TUI now shows live progress while adding routes (`Adding routes... 142/387`).
- Async netsh helper (`_async_netsh`) in Windows backend as foundation for full asyncio subprocess migration.

### Changed
- **Major Windows performance improvement**: route add/remove/default operations switched from PowerShell (`New-NetRoute` etc.) to native `netsh` (much lighter and faster process spawning).
- All HTTP requests now use dynamic `User-Agent: tunnel_manager/{version}`.
- `detect_vpn` results are cached for 5 seconds to reduce expensive system calls (Get-NetRoute / netstat / ip route).
- Watchdog now uses exponential backoff on repeated VPN detection failures.
- Advanced/internal parameters (`list_source`, `list_api_key`, `grey_api_*`) are now documented as dashboard-only features.
- Centralized timeout constants in `backends/base.py`.
- Import sorting and minor lint fixes applied across the codebase.

## [0.4.0] — 2026-04-18

### Added
- **PyPI distribution.** `pip install tunnel-manager` installs the `tunnel-manager` console script. Trusted Publishers wired into `.github/workflows/release.yml` — pushing a `v*` tag publishes both sdist and wheel.
- **CIDR aggregation.** `aggregator.collapse_routes()` merges adjacent prefixes via `ipaddress.collapse_addresses()`. The bundled list compresses from ~705 entries to ~200 CIDRs, cutting route-table writes proportionally.
- **ETag / If-Modified-Since support** in the fetcher. Scheduled refresh now sends `If-None-Match` and skips the diff entirely on `304 Not Modified`. ETag is persisted in state alongside `active_routes`.
- **`--self-test` command.** Diagnostic mode that checks: backend factory, privileges, writability of state/log/data dirs, config load, list reachability + parse, VPN detection. Useful for triaging install issues without committing to a real run.
- **`--update-list URL` now rotates `list_sha256`** in `config.json` if a pin is set, so a freshly downloaded list doesn't fail the next startup with a SHA mismatch.
- **`tunnel_list.txt` ships inside the package.** PyPI installs work out of the box. User-overridden lists (downloaded via `--update-list`) take priority over the bundled copy.
- **Repo hygiene:** `CHANGELOG.md`, `.github/dependabot.yml` (weekly pip + monthly Actions), `.pre-commit-config.yaml` (ruff + format + standard checks).

### Changed
- Default config path now follows OS conventions: prefers `<repo>/config.json` for git checkouts, falls back to the user config dir for `pip install` users (`~/.config/tunnel_manager/` on Linux, etc.).
- `fetcher.load_list` returns `(content, etag)` instead of a bare string. Callers updated.

## [0.3.0] — 2026-04-18

### Added
- IPv6 support throughout (parser via `ipaddress`, all three backends dispatch `-inet/-inet6`, `ip -4/-6`, IPv4/IPv6 NextHop).
- `--version`, `--status`, `--update-list URL`, `--persist-tui`, `--cleanup` (works without live VPN by reconstructing `VPNInfo` from state).
- State file gets a periodic heartbeat; single-instance guard requires both PID-alive AND fresh heartbeat.
- Config hot-reload via mtime watcher. Validation rejects out-of-range values.
- `add_routes` failures aggregate by message instead of dumping the first 3.
- Paths follow OS conventions via `platformdirs` (XDG, `%LOCALAPPDATA%`, `~/Library`).
- GitHub Actions CI: pytest + ruff + mypy across Ubuntu/macOS/Windows × Python 3.11/3.12.
- Packaging templates: systemd, launchd, NSSM/Windows.

## [0.2.0] — 2026-04-18

### Changed
- Refactor into a proper Python package (`tunnel_manager/`) with a thin `main.py` shim.
- Backends split into `RouteBackend` ABC + Windows/macOS/Linux implementations; Windows batches PowerShell calls (chunks of 200 → ~50× speedup), Linux uses `ip -force -batch -`.
- App orchestrator does diff-based refresh — only adds new and removes stale routes.
- 22 unit tests for parser, state, fetcher.

### Fixed
- Load and parse list **before** touching the routing table (failed fetch no longer leaves the user without a default route).
- Implemented `flush_vpn_routes` for Windows (was a no-op; stale routes accumulated).
- Tightened Linux VPN detection to a real interface regex.
- Privilege check at startup with a clear error message.
- `add_routes` returns per-entry errors instead of swallowing stderr.
- Single-instance guard via live-PID check on state file.

## [0.1.0] — 2026-04-18

Initial release. Single-file `main.py` with VPN detection, route list parsing, per-host route additions, basic Rich TUI.
