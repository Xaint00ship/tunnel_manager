# Packaging templates

Templates for running tunnel_manager as a system service.

The CLI can install or remove these service wrappers directly:

```bash
tunnel-manager --install-service
tunnel-manager --uninstall-service
```

Run from an elevated shell (`sudo` on Linux/macOS, Administrator PowerShell on Windows).

| File | Platform | Notes |
|------|----------|-------|
| `systemd/tunnel-manager.service` | Linux | Drop into `/etc/systemd/system/`, edit paths, then `systemctl enable --now tunnel-manager` |
| `launchd/com.tunnel-manager.plist` | macOS | Copy to `/Library/LaunchDaemons/`, set `root:wheel`, `launchctl load -w` |
| `windows/install-service.ps1` | Windows | Requires [NSSM](https://nssm.cc); run elevated, pass repo path |

All templates assume:
- Repo cloned to a fixed path (default `/opt/tunnel_manager` on *nix)
- Virtualenv at `<repo>/.venv` with deps installed (`pip install -r requirements.txt`)
- `config.json` in the repo root (or pass `--config /path` in the args)

The service runs the manager with `--no-tui` so it logs to file instead of trying to take over a terminal.
