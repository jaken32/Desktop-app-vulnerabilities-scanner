"""macOS code-signing / notarization tool layer.

The check logic is split from tool invocation so it is testable off-macOS: a
``Runner`` is any callable ``(argv: list[str]) -> (returncode, stdout, stderr)``.
The default runner shells out to the real tools; tests inject a fake runner that
returns captured ``codesign`` / ``spctl`` output, so parsing + findings are
verified deterministically without macOS.

We NEVER modify or re-sign the target — every command here is read-only
inspection (``codesign -d…``, ``spctl -a…``, ``stapler validate``).
"""

from __future__ import annotations

import plistlib
import re
import subprocess
from typing import Callable, Optional

# (returncode, stdout, stderr)
Runner = Callable[[list], tuple]


class ToolUnavailable(Exception):
    """The requested macOS tool is not on this host (e.g. running on Linux)."""


def default_runner(argv: list, timeout: float = 30.0) -> tuple:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError as exc:  # tool missing (non-macOS host)
        raise ToolUnavailable(argv[0]) from exc
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


# --------------------------------------------------------------------------- #
# Raw tool invocations (read-only). Each returns None when the tool is absent.
# --------------------------------------------------------------------------- #
def run_codesign_info(app_path: str, runner: Runner) -> Optional[str]:
    """`codesign -dvvv` — identity, flags (incl. hardened runtime), authorities.
    The detail is written to stderr; we return stdout+stderr combined."""
    try:
        rc, out, err = runner(["codesign", "-dvvv", app_path])
    except ToolUnavailable:
        return None
    return (out or "") + (err or "")


def run_entitlements(app_path: str, runner: Runner) -> Optional[str]:
    """`codesign -d --entitlements :- --xml` — the app's entitlements plist."""
    try:
        rc, out, err = runner(
            ["codesign", "-d", "--entitlements", ":-", "--xml", app_path])
    except ToolUnavailable:
        return None
    return out or err or ""


def run_spctl(app_path: str, runner: Runner) -> Optional[tuple]:
    """`spctl -a -vvv --type execute` — Gatekeeper assessment. Returns (rc, text)."""
    try:
        rc, out, err = runner(
            ["spctl", "-a", "-vvv", "--type", "execute", app_path])
    except ToolUnavailable:
        return None
    return rc, (out or "") + (err or "")


def run_stapler(app_path: str, runner: Runner) -> Optional[int]:
    """`stapler validate` — is a notarization ticket stapled? Returns rc."""
    try:
        rc, out, err = runner(["stapler", "validate", app_path])
    except ToolUnavailable:
        return None
    return rc


# --------------------------------------------------------------------------- #
# Pure parsers (no I/O) — the testable core.
# --------------------------------------------------------------------------- #
def parse_codesign(text: Optional[str]) -> dict:
    """Parse `codesign -dvvv` output into a structured dict."""
    info: dict = {
        "available": text is not None,
        "signed": False,
        "adhoc": False,
        "hardened_runtime": False,
        "identifier": None,
        "team_identifier": None,
        "authorities": [],
        "flags_raw": None,
    }
    if not text:
        return info

    if re.search(r"code object is not signed at all", text):
        info["signed"] = False
        return info
    # If we got any CodeDirectory / Identifier line, it is signed.
    info["signed"] = bool(re.search(r"^(Identifier|CodeDirectory)=", text, re.M)) \
        or "Authority=" in text

    m = re.search(r"^Identifier=(.+)$", text, re.M)
    if m:
        info["identifier"] = m.group(1).strip()
    m = re.search(r"^TeamIdentifier=(.+)$", text, re.M)
    if m:
        info["team_identifier"] = None if m.group(1).strip() == "not set" \
            else m.group(1).strip()
    info["authorities"] = [m.strip() for m in
                           re.findall(r"^Authority=(.+)$", text, re.M)]
    m = re.search(r"^(CodeDirectory .*?flags=.+)$", text, re.M)
    if m:
        info["flags_raw"] = m.group(1).strip()
    # Hardened runtime shows as the "runtime" flag in the CodeDirectory flags.
    info["hardened_runtime"] = bool(re.search(r"flags=[^\n]*runtime", text)) \
        or "(runtime)" in text
    # Ad-hoc signature.
    info["adhoc"] = bool(re.search(r"Signature=adhoc", text)) \
        or "linker-signed" in text
    if info["adhoc"]:
        info["signed"] = True
    return info


def parse_entitlements(text: Optional[str]) -> dict:
    """Parse entitlements (XML plist preferred; tolerant fallback)."""
    if not text:
        return {}
    stripped = text.strip()
    if "<plist" in stripped or stripped.startswith("<?xml"):
        try:
            start = stripped.index("<?xml") if "<?xml" in stripped else stripped.index("<plist")
            data = plistlib.loads(stripped[start:].encode("utf-8"))
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    # Fallback: `[Key] com.apple...` style or `key = value` lines.
    out: dict = {}
    for m in re.finditer(r'"?([A-Za-z0-9_.\-]+)"?\s*[=:]\s*(true|false|\d+|"[^"]*")',
                         stripped):
        key, val = m.group(1), m.group(2)
        if val in ("true", "false"):
            out[key] = (val == "true")
        elif val.isdigit():
            out[key] = int(val)
        else:
            out[key] = val.strip('"')
    return out


def parse_spctl(result: Optional[tuple]) -> dict:
    """Parse `spctl` result into {available, accepted, source, raw}."""
    if result is None:
        return {"available": False, "accepted": None, "source": None, "raw": ""}
    rc, text = result
    source = None
    m = re.search(r"source=(.+)$", text, re.M)
    if m:
        source = m.group(1).strip()
    accepted = (rc == 0) and ("accepted" in text or rc == 0)
    if "rejected" in text:
        accepted = False
    return {"available": True, "accepted": accepted, "source": source, "raw": text}
