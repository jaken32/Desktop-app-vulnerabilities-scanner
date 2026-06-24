"""Safe, read-only Electron ``app.asar`` parsing and bundle abstraction.

This is the most safety-critical module in the project. The asar format is an
uncompressed archive with a JSON header (encoded in Chromium's Pickle wire
format) that lists ``{size, offset}`` for every file. A hostile bundle can try
to:

  * escape the extraction root via ``../`` path components ("asar-slip"),
  * use absolute paths or Windows drive letters,
  * smuggle symlinks that point outside the root,
  * exhaust memory/disk via a huge declared size or millions of entries
    (zip-bomb style — note asar is *not* compressed, but a crafted header can
    still declare absurd sizes or counts).

Every one of those is rejected here, *before* a single byte of file content is
read. We never execute anything and never follow symlinks.

The default mode is fully in-memory and writes nothing to disk (maximally
safe). ``safe_extract`` is also provided for callers who want files on disk;
it uses the same validation.
"""

from __future__ import annotations

import json
import os
import struct
import time
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Iterator, Optional


# ---------------------------------------------------------------------------
# Limits / errors
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UnpackLimits:
    """Resource-exhaustion bounds. A breach aborts the whole unpack."""

    max_total_bytes: int = 512 * 1024 * 1024   # 512 MiB uncompressed total
    max_file_bytes: int = 64 * 1024 * 1024      # 64 MiB per single file
    max_files: int = 200_000                    # entry count
    wall_clock_seconds: float = 120.0           # hard timeout

    @classmethod
    def from_env(cls) -> "UnpackLimits":
        def _int(name: str, default: int) -> int:
            try:
                return int(os.environ.get(name, default))
            except (TypeError, ValueError):
                return default

        return cls(
            max_total_bytes=_int("DESKSCANNER_MAX_TOTAL_BYTES", cls.max_total_bytes),
            max_file_bytes=_int("DESKSCANNER_MAX_FILE_BYTES", cls.max_file_bytes),
            max_files=_int("DESKSCANNER_MAX_FILES", cls.max_files),
            wall_clock_seconds=float(
                os.environ.get("DESKSCANNER_UNPACK_TIMEOUT", cls.wall_clock_seconds)
            ),
        )


class UnpackError(Exception):
    """Base class for all unpack failures (plain-language ``str``)."""


class ResourceLimitError(UnpackError):
    """A resource bound (size/count/time) was exceeded — abort."""


class UnsafePathError(UnpackError):
    """A path tried to escape the root, or a symlink was encountered."""


class AsarFormatError(UnpackError):
    """The file is not a parseable asar archive."""


# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------


def safe_relpath(*components: str) -> str:
    """Validate and normalise a sequence of path components into a *safe*
    POSIX-relative path.

    Rejects: absolute paths, ``..`` traversal, Windows drive letters,
    backslash separators that resolve upward, NUL bytes, and empty results.

    Returns a forward-slash relative path guaranteed to stay within a root.
    Raises :class:`UnsafePathError` otherwise.
    """
    parts: list[str] = []
    for raw in components:
        if raw is None:
            raise UnsafePathError("null path component")
        if "\x00" in raw:
            raise UnsafePathError("path contains NUL byte")
        # Normalise both separator styles so a Windows-style name can't slip a
        # backslash component past a POSIX check (or vice-versa).
        normalised = raw.replace("\\", "/")
        # A leading separator means an absolute path — reject outright rather
        # than silently relativising it.
        if normalised.startswith("/"):
            raise UnsafePathError(f"absolute path not allowed: {raw!r}")
        for segment in normalised.split("/"):
            if segment in ("", "."):
                continue
            if segment == "..":
                raise UnsafePathError(f"path traversal component in {raw!r}")
            # Windows drive / absolute markers, e.g. "C:" or device names.
            if len(segment) >= 2 and segment[1] == ":":
                raise UnsafePathError(f"drive-letter component in {raw!r}")
            parts.append(segment)

    if not parts:
        raise UnsafePathError("empty path after normalisation")

    rel = PurePosixPath(*parts)
    if rel.is_absolute():
        raise UnsafePathError("absolute path not allowed")
    # Defence in depth: re-check the joined string for any surviving ``..``.
    if ".." in rel.parts:
        raise UnsafePathError("traversal survived normalisation")
    return rel.as_posix()


def safe_join(root: str, relpath: str) -> str:
    """Join ``relpath`` (already validated) onto ``root`` and assert the result
    is still inside ``root`` after full realpath resolution."""
    root_abs = os.path.realpath(root)
    target = os.path.realpath(os.path.join(root_abs, relpath))
    if target != root_abs and not target.startswith(root_abs + os.sep):
        raise UnsafePathError(f"resolved path escapes root: {relpath!r}")
    return target


# ---------------------------------------------------------------------------
# Pickle / asar header parsing
# ---------------------------------------------------------------------------


def _u32(buf: bytes, offset: int) -> int:
    if offset + 4 > len(buf):
        raise AsarFormatError("truncated header while reading uint32")
    return struct.unpack_from("<I", buf, offset)[0]


def _read_asar_header(fp) -> tuple[dict, int]:
    """Return ``(header_dict, data_base_offset)`` for an open binary file.

    Layout (all little-endian):
        [0:4]   payload size of the "size" pickle (== 4)
        [4:8]   header_size  (size in bytes of the header pickle that follows)
        [8 :]   header pickle, within which:
            [+0:+4]  pickle payload length
            [+4:+8]  JSON string length
            [+8: ]   the JSON header string (4-byte aligned)
    File data begins at offset ``8 + header_size``.
    """
    prefix = fp.read(8)
    if len(prefix) < 8:
        raise AsarFormatError("file too small to be an asar archive")

    size_pickle_payload = _u32(prefix, 0)
    header_size = _u32(prefix, 4)
    if size_pickle_payload != 4:
        # Not fatal in every asar version, but a strong signal this isn't asar.
        raise AsarFormatError("unexpected asar size-pickle payload")
    # Sanity bound: header should never be wildly large.
    if header_size <= 0 or header_size > 256 * 1024 * 1024:
        raise AsarFormatError("implausible asar header size")

    header_buf = fp.read(header_size)
    if len(header_buf) < header_size:
        raise AsarFormatError("truncated asar header")

    json_len = _u32(header_buf, 4)
    if json_len <= 0 or 8 + json_len > len(header_buf):
        raise AsarFormatError("invalid asar header string length")
    json_bytes = header_buf[8 : 8 + json_len]
    try:
        header = json.loads(json_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AsarFormatError(f"asar header is not valid JSON: {exc}") from None
    if not isinstance(header, dict) or "files" not in header:
        raise AsarFormatError("asar header missing 'files' table")

    data_base = 8 + header_size
    return header, data_base


# ---------------------------------------------------------------------------
# Bundle abstraction
# ---------------------------------------------------------------------------


@dataclass
class BundleFile:
    """A single readable file inside a bundle. Reads lazily and safely."""

    relpath: str            # validated, posix, relative
    size: int
    _kind: str              # "asar" | "asar-unpacked" | "fs"
    _source: str            # asar path, unpacked file path, or fs path
    _offset: int = 0        # only for kind == "asar"
    _max_file_bytes: int = UnpackLimits.max_file_bytes

    def read_bytes(self) -> bytes:
        if self.size > self._max_file_bytes:
            raise ResourceLimitError(
                f"{self.relpath}: file size {self.size} exceeds per-file limit"
            )
        if self._kind == "asar":
            with open(self._source, "rb") as fp:
                fp.seek(self._offset)
                data = fp.read(self.size)
            return data
        # "asar-unpacked" and "fs" both read a real, pre-validated file path.
        with open(self._source, "rb") as fp:
            return fp.read(self._max_file_bytes + 1)[: self._max_file_bytes]

    def read_text(self, errors: str = "replace") -> str:
        return self.read_bytes().decode("utf-8", errors=errors)


@dataclass
class Bundle:
    """An unpacked Electron bundle: a flat, sorted list of safe files."""

    source_path: str
    source_kind: str        # "asar" | "directory"
    files: list[BundleFile]

    def get(self, relpath: str) -> Optional[BundleFile]:
        for f in self.files:
            if f.relpath == relpath:
                return f
        return None

    def find(self, *, suffix: Optional[str] = None,
             name: Optional[str] = None) -> list[BundleFile]:
        out = []
        for f in self.files:
            base = f.relpath.rsplit("/", 1)[-1]
            if suffix is not None and not f.relpath.endswith(suffix):
                continue
            if name is not None and base != name:
                continue
            out.append(f)
        return out


def _walk_asar_files(node: dict, prefix: str) -> Iterator[tuple[str, dict]]:
    """Yield ``(joined_raw_path, entry)`` for every *file* in the header tree.

    The raw path is intentionally *not* validated here — validation happens in
    :func:`load_asar` so a single bad entry produces a clear error tied to its
    full path.
    """
    files = node.get("files", {})
    if not isinstance(files, dict):
        raise AsarFormatError("malformed 'files' node in asar header")
    for name, entry in files.items():
        if not isinstance(entry, dict):
            raise AsarFormatError(f"malformed entry for {name!r}")
        path = f"{prefix}/{name}" if prefix else name
        if "files" in entry:
            yield from _walk_asar_files(entry, path)
        else:
            yield path, entry


def load_asar(asar_path: str, limits: Optional[UnpackLimits] = None) -> Bundle:
    """Parse an asar archive into a :class:`Bundle`, enforcing every guard.

    Raises a subclass of :class:`UnpackError` on any unsafe or oversized input.
    """
    limits = limits or UnpackLimits()
    started = time.monotonic()

    if not os.path.isfile(asar_path):
        raise AsarFormatError(f"not a file: {asar_path}")

    archive_size = os.path.getsize(asar_path)
    unpacked_dir = asar_path + ".unpacked"

    with open(asar_path, "rb") as fp:
        header, data_base = _read_asar_header(fp)

    files: list[BundleFile] = []
    total_bytes = 0
    count = 0

    for raw_path, entry in _walk_asar_files(header, ""):
        if time.monotonic() - started > limits.wall_clock_seconds:
            raise ResourceLimitError("unpack exceeded wall-clock timeout")

        # Symlinks are never followed — they are an escape vector. Record
        # nothing on disk; simply refuse the archive's link entries.
        if "link" in entry:
            raise UnsafePathError(
                f"symlink entry refused: {raw_path!r} -> {entry.get('link')!r}"
            )

        relpath = safe_relpath(raw_path)  # raises on traversal/absolute/drive

        count += 1
        if count > limits.max_files:
            raise ResourceLimitError(
                f"archive exceeds max file count ({limits.max_files})"
            )

        size = entry.get("size", 0)
        if not isinstance(size, int) or size < 0:
            raise AsarFormatError(f"invalid size for {raw_path!r}")
        if size > limits.max_file_bytes:
            raise ResourceLimitError(
                f"{relpath}: declared size {size} exceeds per-file limit "
                f"({limits.max_file_bytes})"
            )
        total_bytes += size
        if total_bytes > limits.max_total_bytes:
            raise ResourceLimitError(
                f"archive exceeds max total uncompressed size "
                f"({limits.max_total_bytes})"
            )

        if entry.get("unpacked"):
            # Content lives next to the asar in <name>.unpacked/<relpath>.
            real = safe_join(unpacked_dir, relpath) if os.path.isdir(unpacked_dir) else None
            if real and os.path.isfile(real) and not os.path.islink(real):
                files.append(BundleFile(relpath, size, "asar-unpacked", real,
                                        0, limits.max_file_bytes))
            # If the unpacked blob is missing we simply skip its content.
            continue

        try:
            offset = int(entry["offset"])
        except (KeyError, TypeError, ValueError):
            raise AsarFormatError(f"invalid offset for {raw_path!r}") from None
        abs_offset = data_base + offset
        if offset < 0 or abs_offset + size > archive_size:
            raise AsarFormatError(
                f"{relpath}: data range [{abs_offset}, {abs_offset + size}) "
                f"is outside the archive"
            )
        files.append(BundleFile(relpath, size, "asar", asar_path, abs_offset,
                                limits.max_file_bytes))

    files.sort(key=lambda f: f.relpath)
    return Bundle(source_path=asar_path, source_kind="asar", files=files)


def load_directory(dir_path: str, limits: Optional[UnpackLimits] = None) -> Bundle:
    """Build a :class:`Bundle` from an already-unpacked app directory.

    Used when an Electron app ships its resources unpacked (``app/`` instead of
    ``app.asar``). Symlinks are not followed; oversized trees abort.
    """
    limits = limits or UnpackLimits()
    started = time.monotonic()
    root = os.path.realpath(dir_path)
    if not os.path.isdir(root):
        raise AsarFormatError(f"not a directory: {dir_path}")

    files: list[BundleFile] = []
    total_bytes = 0
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Do not descend into symlinked directories.
        dirnames[:] = [d for d in dirnames
                       if not os.path.islink(os.path.join(dirpath, d))]
        for fname in filenames:
            if time.monotonic() - started > limits.wall_clock_seconds:
                raise ResourceLimitError("directory scan exceeded timeout")
            full = os.path.join(dirpath, fname)
            if os.path.islink(full):
                continue  # never read symlink targets
            rel = os.path.relpath(full, root)
            relpath = safe_relpath(rel)
            count += 1
            if count > limits.max_files:
                raise ResourceLimitError(
                    f"directory exceeds max file count ({limits.max_files})"
                )
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            if size > limits.max_file_bytes:
                # Skip individual oversized blobs (e.g. bundled binaries) rather
                # than aborting the whole scan; record nothing for them.
                continue
            total_bytes += size
            if total_bytes > limits.max_total_bytes:
                raise ResourceLimitError(
                    f"directory exceeds max total size ({limits.max_total_bytes})"
                )
            files.append(BundleFile(relpath, size, "fs", full, 0,
                                    limits.max_file_bytes))

    files.sort(key=lambda f: f.relpath)
    return Bundle(source_path=root, source_kind="directory", files=files)


def safe_extract(asar_path: str, dest_dir: str,
                 limits: Optional[UnpackLimits] = None) -> Bundle:
    """Extract an asar to ``dest_dir`` on disk, applying full path/size guards.

    Writes only regular files within ``dest_dir``; never creates symlinks.
    Returns a directory-backed :class:`Bundle` over the extracted tree.
    """
    bundle = load_asar(asar_path, limits)
    os.makedirs(dest_dir, exist_ok=True)
    for f in bundle.files:
        target = safe_join(dest_dir, f.relpath)  # re-validates against root
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as out:
            out.write(f.read_bytes())
    return load_directory(dest_dir, limits)
