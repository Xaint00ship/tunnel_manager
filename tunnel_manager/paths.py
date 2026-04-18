"""Platform-aware paths for state, logs, config, and bundled assets.

Uses XDG conventions on Linux, %APPDATA% on Windows, ~/Library on macOS.
Falls back to ~/.tunnel_manager when platformdirs is unavailable.
"""

from __future__ import annotations

from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKAGE_DIR.parent

try:
    from platformdirs import (
        user_config_dir,
        user_data_dir,
        user_log_dir,
        user_state_dir,
    )

    STATE_DIR = Path(user_state_dir("tunnel_manager", appauthor=False))
    LOG_DIR = Path(user_log_dir("tunnel_manager", appauthor=False))
    USER_CONFIG_DIR = Path(user_config_dir("tunnel_manager", appauthor=False))
    USER_DATA_DIR = Path(user_data_dir("tunnel_manager", appauthor=False))
except ImportError:  # pragma: no cover — fallback when platformdirs missing
    STATE_DIR = Path.home() / ".tunnel_manager"
    LOG_DIR = STATE_DIR
    USER_CONFIG_DIR = STATE_DIR
    USER_DATA_DIR = STATE_DIR

LOG_FILE = LOG_DIR / "tunnel.log"
STATE_FILE = STATE_DIR / "state.json"


def default_config_path() -> Path:
    """Prefer a repo-root config.json (git checkout) over the user config dir."""
    repo_cfg = REPO_ROOT / "config.json"
    if repo_cfg.exists():
        return repo_cfg
    return USER_CONFIG_DIR / "config.json"


def list_search_dir() -> Path:
    """Where to look for a relative `list_url`.

    User-overridden lists (written by `--update-list`) take priority over
    the file bundled in the package.
    """
    if (USER_DATA_DIR / "tunnel_list.txt").exists():
        return USER_DATA_DIR
    return PACKAGE_DIR
