"""Exhaustive asar-slip / absolute / symlink rejection tests."""

import os

import pytest

from deskscanner.unpack import (
    UnsafePathError,
    load_asar,
    load_directory,
    safe_extract,
    safe_join,
    safe_relpath,
)
from helpers import frame_asar


def _entry(size=1, offset="0"):
    return {"size": size, "offset": offset}


def _write(tmp_path, header, data=b"x"):
    p = os.path.join(tmp_path, "bad.asar")
    with open(p, "wb") as fp:
        fp.write(frame_asar(header, data))
    return p


@pytest.mark.parametrize("bad", [
    "../evil",
    "../../etc/passwd",
    "a/../../b",
    "foo/../../../bar",
    "..\\..\\windows\\system32",
])
def test_safe_relpath_rejects_traversal(bad):
    with pytest.raises(UnsafePathError):
        safe_relpath(bad)


@pytest.mark.parametrize("bad", ["/etc/passwd", "/abs/path", "\\\\server\\share"])
def test_safe_relpath_rejects_absolute(bad):
    with pytest.raises(UnsafePathError):
        safe_relpath(bad)


@pytest.mark.parametrize("bad", ["C:/Windows", "C:\\Windows\\system32", "D:/x"])
def test_safe_relpath_rejects_drive_letters(bad):
    with pytest.raises(UnsafePathError):
        safe_relpath(bad)


def test_safe_relpath_rejects_nul():
    with pytest.raises(UnsafePathError):
        safe_relpath("a\x00b")


def test_safe_relpath_accepts_clean():
    assert safe_relpath("a/b/c.js") == "a/b/c.js"
    assert safe_relpath("a\\b\\c.js") == "a/b/c.js"
    assert safe_relpath("./a/./b") == "a/b"


def test_load_asar_rejects_traversal_entry(tmp_path):
    header = {"files": {"../evil.txt": _entry()}}
    with pytest.raises(UnsafePathError):
        load_asar(_write(tmp_path, header))


def test_load_asar_rejects_nested_traversal(tmp_path):
    header = {"files": {"sub": {"files": {"..": {"files": {"x": _entry()}}}}}}
    with pytest.raises(UnsafePathError):
        load_asar(_write(tmp_path, header))


def test_load_asar_rejects_absolute_entry(tmp_path):
    header = {"files": {"/etc/shadow": _entry()}}
    with pytest.raises(UnsafePathError):
        load_asar(_write(tmp_path, header))


def test_load_asar_rejects_symlink_entry(tmp_path):
    header = {"files": {"link.txt": {"link": "/etc/passwd"}}}
    with pytest.raises(UnsafePathError):
        load_asar(_write(tmp_path, header))


def test_safe_join_blocks_escape(tmp_path):
    root = str(tmp_path)
    with pytest.raises(UnsafePathError):
        # even if a relpath slipped through, the realpath join must catch it
        safe_join(root, "../../etc/passwd")


def test_safe_extract_keeps_files_inside_root(tmp_path):
    # A clean archive extracts; every output path stays under dest.
    header = {"files": {"a": {"files": {"b.js": _entry(size=3, offset="0")}}}}
    src = os.path.join(tmp_path, "ok.asar")
    with open(src, "wb") as fp:
        fp.write(frame_asar(header, b"abc"))
    dest = os.path.join(tmp_path, "out")
    bundle = safe_extract(src, dest)
    for f in bundle.files:
        full = os.path.realpath(os.path.join(dest, f.relpath))
        assert full.startswith(os.path.realpath(dest) + os.sep)


def test_directory_walk_skips_symlinks(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "a.js").write_text("ok")
    outside = tmp_path / "secret.txt"
    outside.write_text("secret")
    link = real / "link.txt"
    try:
        os.symlink(str(outside), str(link))
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unsupported on this platform")
    bundle = load_directory(str(real))
    rels = {f.relpath for f in bundle.files}
    assert "a.js" in rels
    assert "link.txt" not in rels  # symlink never followed/included
