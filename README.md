# VPN Split Tunnel Manager

Automatically routes only a curated list of IPs/subnets through your IKEv2 VPN — everything else goes direct. No browser extensions, no proxy, no configuration on the VPN server side.

```
Curated IP list (Netflix, YouTube, ...)  ──►  VPN tunnel  ──►  your VPN server
Everything else                           ──►  direct ISP connection
```

## How it works

When you connect IKEv2 VPN on macOS or Windows, the OS adds a catch-all default route that sends **all** traffic through the tunnel. This tool:

1. Detects the VPN interface (`ipsec0` on macOS, `utun*`, `ppp*`, `xfrm*`, or the IKEv2 adapter on Windows)
2. Removes the catch-all VPN default route
3. Restores the local ISP default route
4. Downloads a curated list of IPs/CIDRs and adds per-entry routes through the VPN
5. Keeps the list fresh and watches for VPN reconnects

```
┌──────────────────────────────────────────────────────────┐
│  Startup                                                 │
│  detect VPN interface → remove default VPN route         │
│  restore ISP default → fetch list → add routes           │
└──────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────┬──────────────────────────────┐
│  worker_refresh (24 h)  │  worker_vpn_watchdog (15 s)  │
│  Re-fetch list,         │  Detect VPN reconnect →      │
│  flush + re-apply       │  rebuild tunnel              │
│  routes.                │  automatically.              │
└─────────────────────────┴──────────────────────────────┘
```

## Requirements

- Python 3.11+
- macOS, Windows, or Linux
- IKEv2 VPN connected via system settings (no third-party client needed)
- `sudo` access (macOS/Linux) or Administrator (Windows)

## Installation

```bash
# Clone the repo
git clone https://github.com/Xaint00ship/tunnel_manager.git
cd tunnel_manager

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

**1. Connect your IKEv2 VPN** through system settings (macOS: System Settings → VPN, Windows: Settings → Network).

**2. Run the manager:**

```bash
# macOS / Linux — sudo required to modify routing table
sudo .venv/bin/python3 main.py

# Windows — run PowerShell as Administrator
.venv\Scripts\python main.py
```

The TUI dashboard launches automatically:

```
╭─ VPN SPLIT TUNNEL MANAGER ─ ● CONNECTED  ipsec0 via ...  •  ISP: 192.168.0.1 ─╮
│ Routes active  842     Updated: 17:42:01  next refresh in 23h 59m    Active   │
├───────────────────────────────────────────────────────────────────────────────┤
│ Services via VPN                                                               │
│ Service                          Routes                                        │
│ Netflix                             312                                        │
│ YouTube                             248                                        │
│ Discord                             102                                        │
├───────────────────────────────────────────────────────────────────────────────┤
│ Log                                                                            │
│ 17:42:00  INFO   Detecting VPN interface...                                    │
│ 17:42:00  OK     VPN: ipsec0  gateway: link-layer  local ISP: 192.168.0.1      │
│ 17:42:01  OK     Parsed 842 entries across 12 services                         │
│ 17:42:03  OK     Done: 842 routes active, 0 skipped (already exist)            │
╰───────────────────────────────────────────────────────────────────────────────╯
```

Stop with `Ctrl+C`. Routes remain active until the next reboot or manual flush (see below).

## Configuration

Edit `config.json` (created automatically on first run):

```json
{
  "list_url": "https://gist.githubusercontent.com/iamwildtuna/7772b7c84a11bf6e1385f23096a73a15/raw/gistfile2.txt",
  "refresh_interval_hours": 24
}
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `list_url` | curated gist | URL of the IP/CIDR list to route through VPN |
| `refresh_interval_hours` | `24` | How often to re-fetch the list and rebuild routes |

### List format

The parser accepts a mixed plain-text format:

- Plain IPs: `142.250.1.1`
- CIDR blocks: `142.250.0.0/16`
- Windows commands: `route ADD 142.250.0.0 MASK 255.255.0.0 ...` (auto-converted to CIDR)
- Lines starting with `//` are comments
- Lines with no IP are treated as **section headers** (e.g. `Netflix`, `YouTube`) and shown in the dashboard

You can point `list_url` at any URL serving this format — a GitHub gist, raw file, or your own endpoint.

## Platform notes

| Platform | VPN interface | Notes |
|----------|---------------|-------|
| macOS (IKEv2 native) | `ipsec0` | Routes added via `-interface` flag, no IP gateway |
| macOS (other clients) | `utun*` | Routes added via tunnel gateway IP |
| Windows | interface index | PowerShell `New-NetRoute` / `Remove-NetRoute` |
| Linux | `xfrm*` / `tun*` / `ppp*` | `ip route` commands |

## Cleaning up routes

On `Ctrl+C` the app exits cleanly but leaves routes in place (so traffic keeps working until you reconnect). To flush manually:

```bash
# macOS
sudo route flush

# Linux
sudo ip route flush table main

# Windows (PowerShell as Administrator)
Get-NetRoute | Where-Object { $_.InterfaceIndex -eq <VPN_INTERFACE_INDEX> } | Remove-NetRoute -Confirm:$false
```

## Troubleshooting

**VPN not detected**
Make sure the VPN is connected _before_ starting the manager. On macOS check `netstat -rn -f inet | grep default` — you should see a `default` route on `ipsec0` or `utun*`.

**`sudo` password prompt blocks routes**
Add this to `/etc/sudoers` (via `sudo visudo`) to allow passwordless execution:
```
your_user ALL=(ALL) NOPASSWD: /sbin/route, /sbin/ip
```

**Routes not removed after reboot**
That's expected — the OS routing table is reset on every boot and VPN reconnect. The manager rebuilds everything on startup.

**List fetch fails**
Check that `list_url` is reachable from your direct (non-VPN) connection. The fetch happens *after* the default route is restored to the ISP, so a broken ISP route will also break the fetch.
