"""Locating targets, and graceful handling of non-Electron inputs."""

import os

import pytest

from deskscanner.engine import scan
from deskscanner.locate import TargetNotElectronError, locate
from helpers import write_secure_asar


def test_non_electron_directory_message(tmp_path):
    # A directory with no asar and no JS is not an Electron app.
    (tmp_path / "readme.txt").write_text("hello")
    with pytest.raises(TargetNotElectronError) as exc:
        locate(str(tmp_path))
    assert "Electron" in str(exc.value)


def test_native_binary_not_analysed(tmp_path):
    binpath = tmp_path / "app.bin"
    binpath.write_bytes(b"\x7fELF\x00\x00not a bundle")
    with pytest.raises(TargetNotElectronError):
        locate(str(binpath))


def test_missing_path(tmp_path):
    with pytest.raises(TargetNotElectronError):
        locate(str(tmp_path / "does-not-exist"))


def test_locate_asar_directly(tmp_path):
    p = os.path.join(tmp_path, "app.asar")
    write_secure_asar(p)
    located = locate(p)
    assert located.asar_path == p
    assert located.bundle.get("package.json") is not None


def test_locate_resources_dir_layout(tmp_path):
    resources = tmp_path / "resources"
    resources.mkdir()
    write_secure_asar(str(resources / "app.asar"))
    located = locate(str(tmp_path))
    assert located.asar_path.endswith(os.path.join("resources", "app.asar"))


def test_scan_raises_clear_error_on_non_electron(tmp_path):
    (tmp_path / "notes.md").write_text("not an app")
    with pytest.raises(TargetNotElectronError):
        scan(str(tmp_path), timestamp="FIXED")
