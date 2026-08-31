"""
Unit tests for upload part assembly and staging capacity preflight.

Assembly is data-path code: a bug here silently corrupts uploaded files, so the
byte-exactness of the chunked read loop is asserted directly.
"""

import os
import hashlib
from datetime import datetime
from pathlib import Path

import pytest

from app.db.sqlite import UploadPart, UploadSession, UploadState
from app.services.upload_manager import UploadManager


def _session(session_id: str, size: int) -> UploadSession:
    return UploadSession(
        id=session_id, token_id="t", user_id="u", path_dir="/d",
        filename="f.usd", size=size, sha256=None, part_size=8,
        received_bytes=0, created_at=datetime.now(),
        state=UploadState.ASSEMBLING, error=None, meta={},
    )


def _write_parts(staging: Path, session_id: str, blobs):
    d = staging / session_id
    d.mkdir(parents=True, exist_ok=True)
    parts = []
    for i, blob in enumerate(blobs):
        p = d / f"part_{i}"
        p.write_bytes(blob)
        parts.append(UploadPart(session_id=session_id, index=i, size=len(blob),
                                sha256=None, path_on_disk=str(p)))
    return d, parts


@pytest.fixture
def manager(tmp_path, monkeypatch):
    monkeypatch.setenv("STAGING_DIR", str(tmp_path / "staging"))
    from app.config import settings
    monkeypatch.setattr(settings, "staging_dir", str(tmp_path / "staging"))
    return UploadManager()


def test_assembly_is_byte_exact_across_chunk_boundaries(manager):
    """Parts larger than the read buffer must reassemble byte-for-byte."""
    manager.ASSEMBLY_CHUNK_SIZE = 1024  # force many iterations of the read loop
    blobs = [os.urandom(4096), os.urandom(1023), os.urandom(1025), os.urandom(1)]
    expected = b"".join(blobs)

    sid = "s-exact"
    d, parts = _write_parts(manager.staging_dir, sid, blobs)
    out = d / "assembled.bin"

    written = manager._assemble_parts_blocking(_session(sid, len(expected)), parts, out)

    assert written == len(expected)
    assert out.read_bytes() == expected
    assert hashlib.sha256(out.read_bytes()).hexdigest() == hashlib.sha256(expected).hexdigest()


def test_assembly_orders_by_supplied_sequence(manager):
    manager.ASSEMBLY_CHUNK_SIZE = 4
    blobs = [b"AAAA", b"BBBB", b"CC"]
    sid = "s-order"
    d, parts = _write_parts(manager.staging_dir, sid, blobs)
    out = d / "assembled.bin"

    manager._assemble_parts_blocking(_session(sid, 10), parts, out)
    assert out.read_bytes() == b"AAAABBBBCC"


def test_assembly_detects_part_size_mismatch(manager):
    """A part whose on-disk size disagrees with its record must fail, not truncate."""
    sid = "s-mismatch"
    d, parts = _write_parts(manager.staging_dir, sid, [b"12345"])
    parts[0].size = 99  # record disagrees with disk
    out = d / "assembled.bin"

    assert manager._assemble_parts_blocking(_session(sid, 99), parts, out) is None


def test_assembly_detects_missing_part(manager):
    sid = "s-missing"
    d, parts = _write_parts(manager.staging_dir, sid, [b"12345"])
    Path(parts[0].path_on_disk).unlink()
    out = d / "assembled.bin"

    assert manager._assemble_parts_blocking(_session(sid, 5), parts, out) is None


def test_capacity_preflight_rejects_when_disk_is_short(manager, monkeypatch):
    import shutil as _shutil
    monkeypatch.setattr(
        _shutil, "disk_usage",
        lambda _p: type("U", (), {"total": 0, "used": 0, "free": 1024})(),
    )
    err = manager._check_staging_capacity(10 * 1024 * 1024 * 1024)
    assert err is not None and "Insufficient server storage" in err


def test_capacity_preflight_allows_when_disk_is_ample(manager, monkeypatch):
    import shutil as _shutil
    huge = 500 * 1024 * 1024 * 1024
    monkeypatch.setattr(
        _shutil, "disk_usage",
        lambda _p: type("U", (), {"total": huge, "used": 0, "free": huge})(),
    )
    assert manager._check_staging_capacity(1024) is None


def test_capacity_preflight_fails_open_if_unmeasurable(manager, monkeypatch):
    """If free space can't be read the upload proceeds rather than hard-failing."""
    import shutil as _shutil

    def boom(_p):
        raise OSError("nope")

    monkeypatch.setattr(_shutil, "disk_usage", boom)
    assert manager._check_staging_capacity(1024) is None


def test_capacity_preflight_honours_configured_headroom(manager, monkeypatch):
    """Headroom is what keeps a big upload from starving Nucleus on the same disk."""
    import shutil as _shutil
    from app.config import settings

    GiB = 1024 ** 3
    # 10 GiB file needs 2x = 20 GiB, and the volume has 25 GiB free.
    monkeypatch.setattr(
        _shutil, "disk_usage",
        lambda _p: type("U", (), {"total": 100 * GiB, "used": 75 * GiB, "free": 25 * GiB})(),
    )

    monkeypatch.setattr(settings, "staging_headroom_bytes", 1 * GiB)
    assert manager._check_staging_capacity(10 * GiB) is None      # 20 + 1 <= 25

    monkeypatch.setattr(settings, "staging_headroom_bytes", 20 * GiB)
    assert manager._check_staging_capacity(10 * GiB) is not None   # 20 + 20 > 25
