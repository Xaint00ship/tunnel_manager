import hashlib
from pathlib import Path

import pytest

from tunnel_manager.fetcher import compute_sha256, load_list


def test_load_local_file(tmp_path: Path):
    (tmp_path / "list.txt").write_bytes(b"foo\n1.2.3.4\n")
    assert load_list("list.txt", tmp_path) == "foo\n1.2.3.4\n"


def test_load_absolute_path(tmp_path: Path):
    p = tmp_path / "abs.txt"
    p.write_bytes(b"hello")
    assert load_list(str(p), tmp_path / "unrelated") == "hello"


def test_sha256_pin_match(tmp_path: Path):
    content = b"pinned content\n"
    (tmp_path / "list.txt").write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    assert load_list("list.txt", tmp_path, sha256=digest) == content.decode()


def test_sha256_pin_mismatch_raises(tmp_path: Path):
    (tmp_path / "list.txt").write_bytes(b"content")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        load_list("list.txt", tmp_path, sha256="deadbeef" * 8)


def test_compute_sha256(tmp_path: Path):
    (tmp_path / "list.txt").write_bytes(b"abc")
    expected = hashlib.sha256(b"abc").hexdigest()
    assert compute_sha256("list.txt", tmp_path) == expected
