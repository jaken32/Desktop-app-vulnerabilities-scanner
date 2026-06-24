"""Test helpers: a tiny pure-Python asar *writer* (mirroring deskscanner's
reader), low-level framing for crafting malicious/oversized headers, and
builders for the insecure/secure fixtures.

Placeholder secrets for the insecure fixture are assembled from fragments here
at build time so that no committed file contains a scannable secret (it can't
trip secret-scanners on push).
"""

from __future__ import annotations

import json
import os
import struct

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


# --- low-level asar framing -------------------------------------------------

def frame_asar(header_obj: dict, data: bytes = b"") -> bytes:
    """Frame an arbitrary header object + data section into asar bytes.

    Layout matches deskscanner.unpack._read_asar_header:
      prefix:    u32(4) | u32(header_size)
      header:    u32(payload_len) | u32(json_len) | json (4-byte aligned)
      data:      raw file bytes (file 'offset' values are relative to here)
    """
    json_bytes = json.dumps(header_obj).encode("utf-8")
    pad = (4 - (len(json_bytes) % 4)) % 4
    json_padded = json_bytes + b"\x00" * pad
    payload = struct.pack("<I", len(json_bytes)) + json_padded
    header_buf = struct.pack("<I", len(payload)) + payload
    header_size = len(header_buf)
    prefix = struct.pack("<I", 4) + struct.pack("<I", header_size)
    return prefix + header_buf + data


def pack_asar(files: dict[str, bytes]) -> bytes:
    """Pack ``{relpath: content}`` into a valid asar archive (bytes)."""
    data = bytearray()
    tree: dict = {"files": {}}
    for relpath, content in files.items():
        node = tree
        parts = relpath.split("/")
        for part in parts[:-1]:
            node = node["files"].setdefault(part, {"files": {}})
        offset = len(data)
        data.extend(content)
        node["files"][parts[-1]] = {"size": len(content), "offset": str(offset)}
    return frame_asar(tree, bytes(data))


def write_asar(path: str, files: dict[str, bytes]) -> str:
    with open(path, "wb") as fp:
        fp.write(pack_asar(files))
    return path


# --- fixture loading --------------------------------------------------------

def _read_dir(name: str) -> dict[str, bytes]:
    root = os.path.join(FIXTURES, name)
    out: dict[str, bytes] = {}
    for dirpath, _dirs, filenames in os.walk(root):
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            with open(full, "rb") as fp:
                out[rel] = fp.read()
    return out


def _assembled_secrets_file() -> bytes:
    # Each secret is assembled from fragments so the repo never stores a
    # complete, scannable credential. All values are fake.
    aws_key_id = "AK" + "IA" + "J5Z3QO2K" + "7NJ4XR9P"            # AKIA + 16
    private_key = (
        "-----BEGIN " + "RSA PRIVATE" + " KEY-----\\n"
        + "MIIB" + "fakefakefake" + "\\n-----END RSA PRIVATE KEY-----"
    )
    client_secret = "swh4kqp2" + "mfn8dlx0"                       # 16 chars
    payload = {
        "awsAccessKeyId": aws_key_id,
        "privateKey": private_key,
        "client_secret": client_secret,
        "comment": "fake values for testing only"
    }
    return json.dumps(payload, indent=2).encode("utf-8")


def insecure_files() -> dict[str, bytes]:
    files = _read_dir("insecure_app")
    files["config.json"] = _assembled_secrets_file()
    return files


def secure_files() -> dict[str, bytes]:
    return _read_dir("secure_app")


def write_insecure_asar(path: str) -> str:
    return write_asar(path, insecure_files())


def write_secure_asar(path: str) -> str:
    return write_asar(path, secure_files())
