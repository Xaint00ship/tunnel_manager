"""Route list loader — accepts HTTP(S) URLs or local file paths.

Supports:
  * Optional SHA-256 pinning to defend against compromise of a remote source.
  * ETag / If-Modified-Since caching to skip re-downloading unchanged lists.
"""

from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
from pathlib import Path


def _is_url(source: str) -> bool:
    return source.startswith(("http://", "https://"))


def _resolve_path(source: str, base_dir: Path) -> Path:
    p = Path(source)
    return p if p.is_absolute() else base_dir / p


def load_list(
    source: str,
    base_dir: Path,
    sha256: str | None = None,
    timeout: int = 15,
    prev_etag: str | None = None,
) -> tuple[str | None, str | None]:
    """Load the route list.

    Returns ``(content, new_etag)``:
      * ``content`` is the file body, or ``None`` when an HTTP source returns
        ``304 Not Modified`` — the caller should reuse its previous content.
      * ``new_etag`` is the freshly-observed ETag (or ``prev_etag`` on 304).
        Always ``None`` for local-file sources.

    Raises on network failure or SHA-256 mismatch.
    """
    new_etag: str | None = None

    if _is_url(source):
        req = urllib.request.Request(
            source, headers={"User-Agent": "tunnel_manager/0.4"}
        )
        if prev_etag:
            req.add_header("If-None-Match", prev_etag)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                new_etag = r.headers.get("ETag")
        except urllib.error.HTTPError as e:
            if e.code == 304:
                return None, prev_etag
            raise
    else:
        raw = _resolve_path(source, base_dir).read_bytes()

    if sha256:
        actual = hashlib.sha256(raw).hexdigest()
        if actual.lower() != sha256.lower():
            raise ValueError(
                f"SHA-256 mismatch for {source}: expected {sha256}, got {actual}"
            )
    return raw.decode("utf-8"), new_etag


def compute_sha256(source: str, base_dir: Path) -> str:
    content, _ = load_list(source, base_dir)
    if content is None:
        raise RuntimeError(f"Source {source} returned no content")
    return hashlib.sha256(content.encode("utf-8")).hexdigest()
