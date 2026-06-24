"""Resource-exhaustion guards: zip-bomb / oversized / too-many-files aborted."""

import os

import pytest

from deskscanner.unpack import (
    ResourceLimitError,
    UnpackLimits,
    load_asar,
)
from helpers import frame_asar


def _write(tmp_path, header, data=b""):
    p = os.path.join(tmp_path, "big.asar")
    with open(p, "wb") as fp:
        fp.write(frame_asar(header, data))
    return p


def test_total_uncompressed_size_aborts(tmp_path):
    # Declare a huge total across files without actually storing the bytes —
    # the guard must abort before reading content.
    files = {f"f{i}.bin": {"size": 10_000_000, "offset": "0"} for i in range(100)}
    header = {"files": files}
    # The total guard must abort on declared sizes, before any data is read.
    limits = UnpackLimits(max_total_bytes=5_000_000, max_file_bytes=50_000_000,
                          max_files=10_000)
    with pytest.raises(ResourceLimitError):
        load_asar(_write(tmp_path, header), limits)


def test_per_file_size_aborts(tmp_path):
    header = {"files": {"huge.bin": {"size": 999_999_999, "offset": "0"}}}
    limits = UnpackLimits(max_file_bytes=1_000_000)
    with pytest.raises(ResourceLimitError):
        load_asar(_write(tmp_path, header), limits)


def test_too_many_files_aborts(tmp_path):
    files = {f"f{i}": {"size": 0, "offset": "0"} for i in range(5000)}
    header = {"files": files}
    limits = UnpackLimits(max_files=1000)
    with pytest.raises(ResourceLimitError):
        load_asar(_write(tmp_path, header), limits)


def test_within_limits_ok(tmp_path):
    header = {"files": {"a.js": {"size": 3, "offset": "0"}}}
    limits = UnpackLimits(max_total_bytes=1000, max_file_bytes=1000, max_files=10)
    bundle = load_asar(_write(tmp_path, header, b"abc"), limits)
    assert bundle.get("a.js").read_bytes() == b"abc"


def test_offset_outside_archive_rejected(tmp_path):
    # An entry pointing past the end of the file must be rejected, not read.
    header = {"files": {"a.js": {"size": 100, "offset": "9999"}}}
    from deskscanner.unpack import AsarFormatError
    with pytest.raises(AsarFormatError):
        load_asar(_write(tmp_path, header, b"abc"))
