"""Logging setup — file (rotating) + in-memory buffer for TUI + optional stderr."""

from __future__ import annotations

import logging
from collections import deque
from datetime import datetime
from logging.handlers import RotatingFileHandler

from .paths import LOG_DIR, LOG_FILE


class InMemoryHandler(logging.Handler):
    def __init__(self, capacity: int = 300):
        super().__init__()
        self.buffer: deque[dict] = deque(maxlen=capacity)

    def emit(self, record: logging.LogRecord) -> None:
        self.buffer.append(
            {
                "ts": datetime.fromtimestamp(record.created).strftime("%H:%M:%S"),
                "level": record.levelname,
                "message": record.getMessage(),
            }
        )


def setup_logging(verbose: bool = False, use_tui: bool = True) -> InMemoryHandler:
    root = logging.getLogger("tunnel_manager")
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    file_fmt = logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")
    file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(file_fmt)
    root.addHandler(file_handler)

    mem = InMemoryHandler()
    root.addHandler(mem)

    if not use_tui:
        stream = logging.StreamHandler()
        stream.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-6s %(message)s", "%H:%M:%S")
        )
        root.addHandler(stream)

    return mem


def get_logger(name: str = "tunnel_manager") -> logging.Logger:
    return logging.getLogger(name)
