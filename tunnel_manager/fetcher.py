"""Route list loader — accepts HTTP(S) URLs or local file paths.

Optional SHA-256 pinning protects against compromise of a remote list source.
"""

from __future__ import annotations

import hashlib
import urllib.request
from pathlib import Path
from typing import Optional


def _is_url(source: str) -> bool:
    return source.startswith(("http://", "https://"))


def _resolve_path(source: str, base_dir: Path) -> Path:
    p = Path(source)
    return p if p.is_absolute() else base_dir / p


def load_list(
    source: str,
    base_dir: Path,
    sha256: Optional[str] = None,
    timeout: int = 15,
) -> str:
    if _is_url(source):
        req = urllib.request.Request(source, headers={"User-Agent": "tunnel_manager/0.2"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
    else:
        raw = _resolve_path(source, base_dir).read_bytes()

    if sha256:
        actual = hashlib.sha256(raw).hexdigest()
        if actual.lower() != sha256.lower():
            raise ValueError(
                f"SHA-256 mismatch for {source}: expected {sha256}, got {actual}"
            )
    return raw.decode("utf-8")


def compute_sha256(source: str, base_dir: Path) -> str:
    data = load_list(source, base_dir).encode("utf-8")
    return hashlib.sha256(data).hexdigest()
