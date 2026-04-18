"""Platform-aware paths for state and logs.

Uses XDG conventions on Linux, %APPDATA% on Windows, ~/Library on macOS.
Falls back to ~/.tunnel_manager when platformdirs is unavailable.
"""

from __future__ import annotations

from pathlib import Path

try:
    from platformdirs import user_log_dir, user_state_dir

    STATE_DIR = Path(user_state_dir("tunnel_manager", appauthor=False))
    LOG_DIR = Path(user_log_dir("tunnel_manager", appauthor=False))
except ImportError:  # pragma: no cover — fallback when platformdirs missing
    STATE_DIR = Path.home() / ".tunnel_manager"
    LOG_DIR = STATE_DIR

LOG_FILE = LOG_DIR / "tunnel.log"
STATE_FILE = STATE_DIR / "state.json"
