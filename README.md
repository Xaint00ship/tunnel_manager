# VPN Split Tunnel Manager

Automatically routes only whitelisted domains through your IKEv2 VPN — everything else goes direct. No browser extensions, no proxy, no configuration on the VPN server side.

```
Netflix, YouTube, GitHub  ──►  VPN tunnel  ──►  your VPN server
Everything else           ──►  direct ISP connection
```

## How it works

When you connect IKEv2 VPN on macOS or Windows, the OS adds a catch-all default route that sends **all** traffic through the tunnel. This tool:

1. Detects the VPN interface (`ipsec0` on macOS, `utun*` for other protocols)
2. Removes the catch-all VPN default route
3. Restores the local ISP default route
4. Resolves whitelisted domains via DNS and adds per-IP host routes through the VPN
5. Keeps routes fresh with background workers

```
┌──────────────────────────────────────────────────────────┐
│  Startup                                                 │
│  detect VPN interface → remove default VPN route         │
│  restore ISP default → resolve whitelist → add /32 routes│
└──────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────┬──────────────────────────────┐
│  periodic_ping (30 min) │  active_route_check (60 s)   │
│  Re-resolve top-N       │  Ping every active IP        │
│  domains by usage.      │  If unreachable → refresh    │
│  Update IPs if changed. │  immediately (no lag).       │
└─────────────────────────┴──────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  vpn_watchdog (15 s)                                    │
│  Detect VPN reconnect → rebuild tunnel automatically    │
└─────────────────────────────────────────────────────────┘
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
╭─ VPN SPLIT TUNNEL MANAGER ─ ● CONNECTED  ipsec0 via ...  local gw: 192.168.0.1 ─╮
│ Stats: routes added  12   routes removed  0   IP changes  1   pings done  2      │
├──────────────────────────────────────────────────────────────────────────────────┤
│ Domain           IPs                    Hits  Status   Last resolved  Last ping  │
│ youtube.com      142.250.x.x, ...         8   active   17:42:01       —          │
│ netflix.com      54.237.x.x, ...          3   active   17:42:02       —          │
├──────────────────────────────────────────────────────────────────────────────────┤
│ Log                                                                               │
│ 17:42:00  INFO   Detecting VPN interface...                                      │
│ 17:42:00  OK     VPN detected: ipsec0                                            │
│ 17:42:01  OK     Split tunnel active. Only whitelisted domains go through VPN.   │
╰──────────────────────────────────────────────────────────────────────────────────╯
```

Stop with `Ctrl+C`. Routes remain active until the next reboot or manual flush (see below).

## Configuration

Edit `config.json` (created automatically on first run):

```json
{
  "whitelist": [
    "netflix.com",
    "youtube.com",
    "github.com",
    "openai.com"
  ],
  "ping_interval_seconds": 1800,
  "active_check_interval_seconds": 60,
  "top_n_to_ping": 10,
  "dns_servers": ["8.8.8.8", "1.1.1.1"],
  "dns_timeout": 5
}
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `whitelist` | — | Domains routed through VPN |
| `ping_interval_seconds` | `1800` | How often to re-resolve top-N domains (30 min) |
| `active_check_interval_seconds` | `60` | How often to ping active IPs for liveness |
| `top_n_to_ping` | `10` | Number of most-used domains to keep fresh |
| `dns_servers` | `["8.8.8.8", "1.1.1.1"]` | DNS servers used for resolving |
| `dns_timeout` | `5` | DNS query timeout in seconds |

Add or remove domains from `whitelist` and restart — changes take effect immediately on next run.

## Platform notes

| Platform | VPN interface | Notes |
|----------|---------------|-------|
| macOS (IKEv2 native) | `ipsec0` | Routes added via `-interface` flag, no IP gateway |
| macOS (other clients) | `utun*` | Routes added via tunnel gateway IP |
| Windows | interface index | PowerShell `New-NetRoute` / `Remove-NetRoute` |
| Linux | `xfrm*` / `tun*` | `ip route` commands |

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
Add these commands to `/etc/sudoers` (via `sudo visudo`) to allow passwordless execution:
```
your_user ALL=(ALL) NOPASSWD: /sbin/route
```

**Routes not removed after reboot**
That's expected — the OS routing table is reset on every boot and VPN reconnect. The manager rebuilds everything on startup.
