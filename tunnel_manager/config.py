"""Typed configuration loaded from config.json.

Supports hot-reload: `Config.maybe_reload()` re-reads from disk if the
file's mtime changed and returns a fresh instance, otherwise returns
the original.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path


DB_ROUTES_URL = "http://localhost/api/routes"


@dataclass
class Config:
    list_url: str = "tunnel_list.txt"
    list_source: str = "file"   # "file" or "db"
    list_api_key: str | None = None  # X-Api-Key header when list_source == "db"
    list_sha256: str | None = None
    refresh_interval_hours: int = 24
    watchdog_interval_seconds: int = 15
    heartbeat_interval_seconds: int = 30
    grey_api_url: str | None = None   # dashboard base URL for grey list reporting
    grey_api_key: str | None = None   # X-Api-Key for /api/analytics/grey-list/report

    def effective_list_url(self) -> str:
        """Return the URL/path to fetch the route list from."""
        if self.list_source == "db":
            return DB_ROUTES_URL
        return self.list_url

    _path: Path | None = field(default=None, repr=False, compare=False)
    _mtime: float = field(default=0.0, repr=False, compare=False)

    @classmethod
    def load(cls, path: Path) -> Config:
        if not path.exists():
            cfg = cls()
            cls._save(cfg, path)
            cfg._path = path
            cfg._mtime = path.stat().st_mtime
            return cfg
        data = json.loads(path.read_text(encoding="utf-8"))
        known = {
            k: v for k, v in data.items()
            if k in cls.__dataclass_fields__ and not k.startswith("_")
        }
        cfg = cls(**known)
        cfg._path = path
        cfg._mtime = path.stat().st_mtime
        cls._validate(cfg)
        return cfg

    def maybe_reload(self) -> Config:
        """Return a fresh Config if the source file changed, else self."""
        if self._path is None or not self._path.exists():
            return self
        try:
            mtime = self._path.stat().st_mtime
        except OSError:
            return self
        if mtime <= self._mtime:
            return self
        try:
            return Config.load(self._path)
        except (json.JSONDecodeError, ValueError):
            return self

    @staticmethod
    def _save(cfg: Config, path: Path) -> None:
        d = {
            k: v for k, v in asdict(cfg).items()
            if not k.startswith("_")
        }
        path.write_text(json.dumps(d, indent=2), encoding="utf-8")

    @staticmethod
    def _validate(cfg: Config) -> None:
        if cfg.refresh_interval_hours < 0:
            raise ValueError("refresh_interval_hours must be >= 0")
        if cfg.watchdog_interval_seconds < 5:
            raise ValueError("watchdog_interval_seconds must be >= 5")
        if cfg.heartbeat_interval_seconds < 5:
            raise ValueError("heartbeat_interval_seconds must be >= 5")
