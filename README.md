# VPN Split Tunnel Manager

Routes only a curated list of IPs/subnets through your VPN — everything else goes direct via the ISP. No browser extensions, no proxy, no configuration on the VPN server side.

```
Curated IP list (Netflix, YouTube, ...)  ──►  VPN tunnel  ──►  your VPN server
Everything else                           ──►  direct ISP connection
```

## How it works

When you connect a VPN (IKEv2, WireGuard, OpenVPN, L2TP, …), the OS typically adds a catch-all default route that sends **all** traffic through the tunnel. This tool:

1. Detects the VPN interface by scanning `0.0.0.0/0` routes (IKEv2 `ipsec*`, `utun*`, `wg*`, `tun*`, `tap*`, `xfrm*`, `ppp*`, RAS adapters on Windows).
2. Loads a curated IP/CIDR list **first** (from a local file or URL with optional SHA-256 pinning) so a failed fetch never leaves you offline.
3. Removes the catch-all VPN default route, keeping the ISP default.
4. Diffs desired routes against what's already on the VPN interface + last-run state, then adds new routes / removes stale ones in batched platform-native calls.
5. Background workers refresh the list on a schedule and rebuild the tunnel on VPN reconnect.

```
┌──────────────────────────────────────────────────────────┐
│  Startup                                                 │
│  detect VPN → load+parse list → remove VPN default       │
│  diff vs. state+live → batch add new / remove stale      │
│  persist state to ~/.tunnel_manager/state.json           │
└──────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────┬──────────────────────────────┐
│  worker_refresh (24h)   │  worker_watchdog (15s)       │
│  Re-load list, diff-    │  VPN reconnect → rebuild.    │
│  apply changes only.    │  VPN gone → pause refresh.   │
└─────────────────────────┴──────────────────────────────┘
```

## Requirements

- Python 3.11+
- macOS, Windows, or Linux
- A VPN already connected via system settings (no third-party client needed)
- `sudo` access (macOS/Linux) or Administrator (Windows)

## Installation

### Via pip (recommended)

```bash
pip install tunnel-manager
```

This installs the `tunnel-manager` console script. The IP/CIDR list ships bundled inside the package.

### From source

```bash
git clone https://github.com/Xaint00ship/tunnel_manager.git
cd tunnel_manager

python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

pip install -e .
```

## Usage

**1. Connect your VPN** through system settings.

**2. Run a self-test** to confirm prerequisites:

```bash
tunnel-manager --self-test
```

**3. Run the manager:**

```bash
# macOS / Linux — sudo required to modify routing table
sudo tunnel-manager

# Windows — elevated PowerShell
tunnel-manager
```

Runs a full-screen Rich TUI dashboard. `Ctrl+C` to stop.

### CLI flags

| Flag | Description |
|------|-------------|
| `--version` | Print version and exit. |
| `--no-tui` | Plain-text logging instead of the TUI (good for systemd, debugging). |
| `--persist-tui` | Render the TUI in the main scrollback instead of the alt screen. |
| `--dry-run` | Print planned changes without touching the routing table. |
| `--cleanup` | Remove all routes from a previous run and exit. Works even if the VPN is no longer connected — uses the interface saved in state. |
| `--status` | Print last known state (PID liveness, routes, log tail) and exit. |
| `--update-list URL` | Download a fresh list into the user data dir; if `list_sha256` is pinned in config, rotate the pin to match. |
| `--compute-sha` | Print SHA-256 of the list source (for pinning), then exit. |
| `--self-test` | Run a diagnostic check (privs, paths, list, VPN) and exit. |
| `-v` / `--verbose` | Debug logging. |
| `--config PATH` | Use a different `config.json`. |

You can also run the package directly: `python -m tunnel_manager`.

### Logs

All logs go to a rotating file (1 MB × 3 backups) at the platform-native location:

| Platform | Path |
|----------|------|
| Linux | `~/.local/state/tunnel_manager/tunnel.log` (or `$XDG_STATE_HOME/tunnel_manager`) |
| macOS | `~/Library/Logs/tunnel_manager/tunnel.log` |
| Windows | `%LOCALAPPDATA%\tunnel_manager\Logs\tunnel.log` |

### State

State is persisted at the platform-native location (`~/.local/state/tunnel_manager/state.json` on Linux, etc.) with active routes, the VPN interface, and a heartbeat. If a previous run crashed, the next run reconciles stale routes automatically. The single-instance guard checks both PID liveness and heartbeat freshness — a stale state file from a `kill -9`'d process won't block subsequent runs.

## Configuration

`config.json` (created on first run):

```json
{
  "list_url": "tunnel_list.txt",
  "list_sha256": null,
  "refresh_interval_hours": 24,
  "watchdog_interval_seconds": 15,
  "heartbeat_interval_seconds": 30
}
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `list_url` | `tunnel_list.txt` | IP/CIDR list source — `http(s)://` URL or file path (absolute, or relative to `main.py`). |
| `list_sha256` | `null` | Optional SHA-256 hex digest; if set, a mismatch aborts the load. Use `--compute-sha` to generate. |
| `refresh_interval_hours` | `24` | How often to re-load the list and re-diff routes. |
| `watchdog_interval_seconds` | `15` | VPN reconnect polling interval. |
| `heartbeat_interval_seconds` | `30` | How often to update the state file's liveness marker. |

Advanced/internal parameters (`list_source`, `list_api_key`, `grey_api_*`) are for custom dashboard integrations and not recommended for general use.

The config is **hot-reloaded**: edit `config.json` while the manager is running and the new values take effect within ~10 seconds — no restart needed.

`tunnel_list.txt` ships inside the package so the tool works offline. Resolution priority for relative `list_url`:

1. User data dir (where `--update-list` writes — `~/.local/share/tunnel_manager/`, `~/Library/Application Support/tunnel_manager/`, `%LOCALAPPDATA%\tunnel_manager\`).
2. Bundled file inside the installed package.

To use a remote list instead, point `list_url` at a URL and optionally pin the hash:

```bash
tunnel-manager --compute-sha   # prints the current hash → set list_sha256 in config
tunnel-manager --update-list https://example.com/list.txt   # rotates pin automatically
```

The fetcher honors `If-None-Match` / `ETag` so scheduled refreshes that find an unchanged list skip the diff entirely (no route operations, zero downloaded bytes).

### List format

- IPv4: `142.250.1.1` and CIDR `142.250.0.0/16`
- IPv6: `2606:4700::1111` and CIDR `2606:4700::/32`
- Multiple on one line: `1.1.1.1, 2.2.2.2, 3.3.3.3`
- Windows commands: `ROUTE ADD 142.250.0.0 MASK 255.255.0.0 0.0.0.0` (converted to CIDR)
- `//`-prefixed lines are ignored as comments
- Any other non-IP line becomes a section header (leading `#`/`##` is stripped). Sections show up in the TUI with per-service route counts.

## Platform notes

| Platform | VPN detection | Route operations |
|----------|---------------|------------------|
| Windows | `Get-NetRoute` + adapter scoring (supports IKEv2, RAS/PPP, WireGuard, OpenVPN) | Batched `New-NetRoute` / `Remove-NetRoute` via PowerShell (chunks of 200) |
| macOS | `netstat -rn` — picks `ipsec*` / `utun*` / `ppp*` with a default route | `route add/delete` via `sudo -n`, `-interface` for IPsec |
| Linux | `ip route` — picks interface matching `^(utun|tun|wg|tap|xfrm|ppp|ipsec)\d*$` | `ip -force -batch -` from stdin (one syscall for all adds) |

## Development

```bash
pip install -e ".[dev]"
pytest          # 55 tests
ruff check .    # lint
mypy tunnel_manager
pre-commit install   # run ruff + format on every commit
```

CI runs the same on every push (Ubuntu / macOS / Windows × Python 3.11/3.12) — see [.github/workflows/ci.yml](.github/workflows/ci.yml). Releases publish to PyPI on `v*` tags via Trusted Publishers — see [.github/workflows/release.yml](.github/workflows/release.yml).

## Running as a service

Templates for systemd (Linux), launchd (macOS) and NSSM (Windows) live in [packaging/](packaging/). Each runs the manager with `--no-tui` so it logs to a file instead of taking over a terminal.

## Troubleshooting

**Insufficient privileges** — the tool fails fast if it can't modify routes. Re-run with `sudo` / elevated PowerShell.

**VPN not detected** — connect the VPN *before* starting. The watchdog will also pick up a VPN that connects after start. Run with `-v` to see what default routes were considered.

**`sudo` password prompt blocks routes** — add to `/etc/sudoers` (via `sudo visudo`):
```
your_user ALL=(ALL) NOPASSWD: /sbin/route, /sbin/ip
```

**Two instances at once** — refused with `Another instance is running (PID ...)`. The state file's PID is checked against live processes; if stale, remove `~/.tunnel_manager/state.json` manually.

**List fetch fails** — the list is loaded **before** the default route is touched, so a fetch failure leaves your normal connection untouched. Verify `list_url` is reachable; consider switching to the bundled `tunnel_list.txt`.
