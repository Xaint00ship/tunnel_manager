"""Typed configuration loaded from config.json."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional


@dataclass
class Config:
    list_url: str = "tunnel_list.txt"
    list_sha256: Optional[str] = None
    refresh_interval_hours: int = 24
    watchdog_interval_seconds: int = 15

    @classmethod
    def load(cls, path: Path) -> "Config":
        if not path.exists():
            cfg = cls()
            path.write_text(json.dumps(asdict(cfg), indent=2), encoding="utf-8")
            return cfg
        data = json.loads(path.read_text(encoding="utf-8"))
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**known)
