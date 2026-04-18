import hashlib
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError

import pytest

from tunnel_manager.fetcher import compute_sha256, load_list


def test_load_local_file(tmp_path: Path):
    (tmp_path / "list.txt").write_bytes(b"foo\n1.2.3.4\n")
    content, etag = load_list("list.txt", tmp_path)
    assert content == "foo\n1.2.3.4\n"
    assert etag is None


def test_load_absolute_path(tmp_path: Path):
    p = tmp_path / "abs.txt"
    p.write_bytes(b"hello")
    content, _ = load_list(str(p), tmp_path / "unrelated")
    assert content == "hello"


def test_sha256_pin_match(tmp_path: Path):
    content = b"pinned content\n"
    (tmp_path / "list.txt").write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    body, _ = load_list("list.txt", tmp_path, sha256=digest)
    assert body == content.decode()


def test_sha256_pin_mismatch_raises(tmp_path: Path):
    (tmp_path / "list.txt").write_bytes(b"content")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        load_list("list.txt", tmp_path, sha256="deadbeef" * 8)


def test_compute_sha256(tmp_path: Path):
    (tmp_path / "list.txt").write_bytes(b"abc")
    expected = hashlib.sha256(b"abc").hexdigest()
    assert compute_sha256("list.txt", tmp_path) == expected


class _FakeResp:
    def __init__(self, body: bytes, etag: str | None = None):
        self._body = body
        self.headers = {"ETag": etag} if etag else {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def read(self):
        return self._body


def test_etag_returned_from_url():
    fake = _FakeResp(b"content\n", etag='"abc123"')
    with mock.patch("urllib.request.urlopen", return_value=fake):
        body, etag = load_list("https://example.com/list", Path("/tmp"))
    assert body == "content\n"
    assert etag == '"abc123"'


def test_etag_304_returns_none_content():
    err = HTTPError("https://example.com/list", 304, "Not Modified", {}, None)
    with mock.patch("urllib.request.urlopen", side_effect=err):
        body, etag = load_list(
            "https://example.com/list", Path("/tmp"), prev_etag='"abc123"'
        )
    assert body is None
    assert etag == '"abc123"'


def test_etag_sent_as_if_none_match_header():
    fake = _FakeResp(b"x", etag=None)
    captured: dict = {}

    def _capture(req, *a, **kw):
        captured["headers"] = dict(req.headers)
        return fake

    with mock.patch("urllib.request.urlopen", side_effect=_capture):
        load_list("https://example.com/list", Path("/tmp"), prev_etag='"v1"')
    # urllib lower-cases header names in `Request.headers`
    assert captured["headers"].get("If-none-match") == '"v1"'
