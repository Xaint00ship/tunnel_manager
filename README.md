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

```bash
git clone https://github.com/Xaint00ship/tunnel_manager.git
cd tunnel_manager

python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

## Usage

**1. Connect your VPN** through system settings.

**2. Run the manager:**

```bash
# macOS / Linux — sudo required to modify routing table
sudo .venv/bin/python main.py

# Windows — run PowerShell as Administrator
.venv\Scripts\python main.py
```

Runs a full-screen Rich TUI dashboard. `Ctrl+C` to stop.

### CLI flags

| Flag | Description |
|------|-------------|
| `--no-tui` | Plain-text logging instead of the TUI (good for systemd, debugging). |
| `--dry-run` | Print planned changes without touching the routing table. |
| `--cleanup` | Remove all routes from a previous run and exit. |
| `--compute-sha` | Print SHA-256 of the list source (for pinning), then exit. |
| `-v` / `--verbose` | Debug logging. |
| `--config PATH` | Use a different `config.json`. |

You can also run the package directly: `python -m tunnel_manager`.

### Logs

All logs go to `~/.tunnel_manager/tunnel.log` (rotating, 1 MB × 3 backups) in addition to the TUI/stderr.

### State

`~/.tunnel_manager/state.json` records active routes and the PID of the running instance. If a previous run crashed, the next run reconciles stale routes automatically. Two instances cannot run concurrently.

## Configuration

`config.json` (created on first run):

```json
{
  "list_url": "tunnel_list.txt",
  "list_sha256": null,
  "refresh_interval_hours": 24,
  "watchdog_interval_seconds": 15
}
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `list_url` | `tunnel_list.txt` | IP/CIDR list source — `http(s)://` URL or file path (absolute, or relative to `main.py`). |
| `list_sha256` | `null` | Optional SHA-256 hex digest; if set, a mismatch aborts the load. Use `--compute-sha` to generate. |
| `refresh_interval_hours` | `24` | How often to re-load the list and re-diff routes. |
| `watchdog_interval_seconds` | `15` | VPN reconnect polling interval. |

A `tunnel_list.txt` ships with the repo so the tool works offline. To use a remote list instead, point `list_url` at a URL and optionally pin the hash:

```bash
python main.py --compute-sha   # prints the current hash
```

### List format

- Plain IPs: `142.250.1.1`
- CIDR blocks: `142.250.0.0/16`
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
pip install -r requirements-dev.txt
pytest
```

## Troubleshooting

**Insufficient privileges** — the tool fails fast if it can't modify routes. Re-run with `sudo` / elevated PowerShell.

**VPN not detected** — connect the VPN *before* starting. The watchdog will also pick up a VPN that connects after start. Run with `-v` to see what default routes were considered.

**`sudo` password prompt blocks routes** — add to `/etc/sudoers` (via `sudo visudo`):
```
your_user ALL=(ALL) NOPASSWD: /sbin/route, /sbin/ip
```

**Two instances at once** — refused with `Another instance is running (PID ...)`. The state file's PID is checked against live processes; if stale, remove `~/.tunnel_manager/state.json` manually.

**List fetch fails** — the list is loaded **before** the default route is touched, so a fetch failure leaves your normal connection untouched. Verify `list_url` is reachable; consider switching to the bundled `tunnel_list.txt`.
