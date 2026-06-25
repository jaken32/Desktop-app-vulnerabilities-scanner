"""Native / Flutter macOS checks.

Every finding cites the exact command run or the file path + the literal evidence
observed. Nothing is reported that wasn't directly observed on disk (or, for the
opt-in loopback probe, from 127.0.0.1). We never emit Electron-style findings
(nodeIntegration, contextIsolation, CSP-in-renderer …) — those concepts do not
exist in a native/Flutter app. Where a category can't be assessed (e.g. the
macOS signing tools aren't on this host) we say "Not assessed/applicable" rather
than invent a finding.

Confidence mapping used here (the project's enum -> the rubric's words):
  CONFIRMED = HIGH   (directly observed, unambiguous)
  LIKELY    = MEDIUM (observed but context-dependent)
  POSSIBLE  = LOW    (heuristic / inference)
"""

from __future__ import annotations

import math
import os
import re
import stat
from typing import Optional

from ..models import Confidence, Finding, Remediation, Severity, SourceLocator
from ..unpack import UnsafePathError
from .context import NativeContext

_DOC_HARDENING = "https://developer.apple.com/documentation/security/hardened_runtime"
_DOC_NOTARIZE = "https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution"
_DOC_ENT = "https://developer.apple.com/documentation/bundleresources/entitlements"
_DOC_ATS = "https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity"
_DOC_SPARKLE = "https://sparkle-project.org/documentation/"


def _na(category: str, title: str, reason: str, path: str = "<native>") -> Finding:
    return Finding(
        title=title, severity=Severity.INFO, confidence=Confidence.CONFIRMED,
        category=category, evidence=f"Not assessed — {reason}",
        source_locator=SourceLocator(path),
        remediation=Remediation("Re-run on macOS with the Xcode command-line "
                                "tools installed to assess this category."),
        why_it_matters="Honest scoping: this category could not be observed here.",
        discriminator=f"{category}:not-assessed")


# --------------------------------------------------------------------------- #
# 1. Code signing
# --------------------------------------------------------------------------- #
def check_code_signing(ctx: NativeContext) -> list:
    cs = ctx.codesign
    if not cs.get("available"):
        return [_na("signing", "Code signing not assessed",
                    "codesign is not available on this host")]
    out = []
    if not cs.get("signed"):
        out.append(Finding(
            title="Application is not code signed",
            severity=Severity.CRITICAL, confidence=Confidence.CONFIRMED,
            category="signing",
            evidence="`codesign -dvvv` reports the code object is not signed at all.",
            source_locator=SourceLocator("codesign -dvvv"),
            remediation=Remediation(
                "Sign the app with a Developer ID certificate before distribution.",
                code="codesign --force --options runtime --timestamp "
                     "--sign \"Developer ID Application: …\" YourApp.app"),
            references=[_DOC_NOTARIZE],
            why_it_matters="An unsigned app has no verifiable origin or integrity; "
                           "macOS Gatekeeper will block it and tampering is undetectable.",
            discriminator="signing:unsigned"))
        return out
    if cs.get("adhoc"):
        out.append(Finding(
            title="Application is ad-hoc signed (no Developer ID identity)",
            severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
            category="signing",
            evidence="`codesign -dvvv` shows an ad-hoc signature (Signature=adhoc); "
                     "there is no verifiable signing identity.",
            source_locator=SourceLocator("codesign -dvvv"),
            remediation=Remediation(
                "Re-sign with a Developer ID Application certificate and notarize.",
                code="codesign --force --options runtime --timestamp "
                     "--sign \"Developer ID Application: …\" YourApp.app"),
            references=[_DOC_NOTARIZE],
            why_it_matters="Ad-hoc signatures carry no identity, cannot be notarized, "
                           "and are rejected by Gatekeeper for distribution.",
            discriminator="signing:adhoc"))
    else:
        authority = "; ".join(cs.get("authorities") or []) or "unknown"
        out.append(Finding(
            title="Code signature present",
            severity=Severity.INFO, confidence=Confidence.CONFIRMED,
            category="signing",
            evidence=f"Signing authority chain: {authority}. "
                     f"Identifier: {cs.get('identifier')}. "
                     f"Team: {cs.get('team_identifier')}.",
            source_locator=SourceLocator("codesign -dvvv"),
            remediation=Remediation("No action — context for the report."),
            why_it_matters="Identity context for the signature.",
            discriminator="signing:present"))
    return out


# --------------------------------------------------------------------------- #
# 2. Notarization & Gatekeeper
# --------------------------------------------------------------------------- #
def check_notarization(ctx: NativeContext) -> list:
    sp = ctx.spctl
    if not sp.get("available") and ctx.stapled is None:
        return [_na("notarization", "Notarization / Gatekeeper not assessed",
                    "spctl/stapler are not available on this host")]
    out = []
    if sp.get("available") and sp.get("accepted") is False:
        out.append(Finding(
            title="Gatekeeper rejects the app (not notarized / not trusted)",
            severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
            category="notarization",
            evidence=f"`spctl -a -vvv --type execute` did not accept the app. "
                     f"source={sp.get('source')}. Output: {sp.get('raw','').strip()[:300]}",
            source_locator=SourceLocator("spctl -a -vvv --type execute"),
            remediation=Remediation(
                "Notarize the app and staple the ticket.",
                code="xcrun notarytool submit YourApp.zip --keychain-profile … --wait\n"
                     "xcrun stapler staple YourApp.app"),
            references=[_DOC_NOTARIZE],
            why_it_matters="Users will see a Gatekeeper block; the app's integrity "
                           "and notarization status cannot be confirmed by macOS.",
            discriminator="notarization:rejected"))
    if ctx.stapled is False:
        out.append(Finding(
            title="No stapled notarization ticket",
            severity=Severity.MEDIUM, confidence=Confidence.LIKELY,
            category="notarization",
            evidence="`stapler validate` did not find a stapled notarization ticket.",
            source_locator=SourceLocator("stapler validate"),
            remediation=Remediation("Staple the ticket so first launch works offline.",
                                    code="xcrun stapler staple YourApp.app"),
            references=[_DOC_NOTARIZE],
            why_it_matters="Without a stapled ticket, first launch requires online "
                           "verification and can fail offline.",
            discriminator="notarization:unstapled"))
    if sp.get("accepted") and ctx.stapled is not False:
        out.append(Finding(
            title="Gatekeeper accepts the app",
            severity=Severity.INFO, confidence=Confidence.CONFIRMED,
            category="notarization",
            evidence=f"`spctl` accepted the app. source={sp.get('source')}.",
            source_locator=SourceLocator("spctl -a -vvv --type execute"),
            remediation=Remediation("No action — context for the report."),
            why_it_matters="The app is accepted by Gatekeeper.",
            discriminator="notarization:accepted"))
    return out


# --------------------------------------------------------------------------- #
# 3. Hardened Runtime
# --------------------------------------------------------------------------- #
def check_hardened_runtime(ctx: NativeContext) -> list:
    cs = ctx.codesign
    if not cs.get("available"):
        return [_na("hardened-runtime", "Hardened Runtime not assessed",
                    "codesign is not available on this host")]
    if not cs.get("signed"):
        return []  # already covered by the unsigned finding
    if not cs.get("hardened_runtime"):
        return [Finding(
            title="Hardened Runtime is not enabled",
            severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
            category="hardened-runtime",
            evidence=f"The codesign flags do not include the runtime flag: "
                     f"{cs.get('flags_raw') or 'no runtime flag observed'}.",
            source_locator=SourceLocator("codesign -dvvv"),
            remediation=Remediation(
                "Re-sign with the Hardened Runtime enabled.",
                code="codesign --force --options runtime --sign \"Developer ID …\" YourApp.app"),
            references=[_DOC_HARDENING],
            why_it_matters="Hardened Runtime blocks code injection, unsigned memory "
                           "execution and dyld env attacks; without it those "
                           "protections are off. (Required for notarization.)",
            discriminator="hardened-runtime:absent")]
    return []


# --------------------------------------------------------------------------- #
# 4. App Sandbox
# --------------------------------------------------------------------------- #
def check_app_sandbox(ctx: NativeContext) -> list:
    if not ctx.codesign.get("available"):
        return [_na("sandbox", "App Sandbox not assessed",
                    "entitlements could not be read (codesign unavailable)")]
    if ctx.entitlements.get("com.apple.security.app-sandbox") is True:
        return []
    return [Finding(
        title="App Sandbox is not enabled",
        severity=Severity.MEDIUM, confidence=Confidence.LIKELY,
        category="sandbox",
        evidence="The entitlement `com.apple.security.app-sandbox` is absent from "
                 "the app's entitlements.",
        source_locator=SourceLocator("codesign -d --entitlements :-",
                                     config_key="com.apple.security.app-sandbox"),
        remediation=Remediation(
            "Adopt the App Sandbox and grant only the entitlements you need.",
            code="<key>com.apple.security.app-sandbox</key><true/>"),
        references=[_DOC_ENT],
        why_it_matters="Without the sandbox, a compromise of the app has the full "
                       "access of the user account rather than a constrained box. "
                       "(Note: many non-MAS apps ship unsandboxed by design.)",
        discriminator="sandbox:absent")]


# --------------------------------------------------------------------------- #
# 5 + 6. Dangerous entitlements (incl. library-validation)
# --------------------------------------------------------------------------- #
_DANGEROUS = [
    ("com.apple.security.get-task-allow", Severity.CRITICAL,
     "A debuggable build was shipped: any process can attach a debugger and read "
     "memory / inject code into the app.",
     "Remove get-task-allow from the distribution build (it is a debug-only "
     "entitlement)."),
    ("com.apple.security.cs.disable-library-validation", Severity.HIGH,
     "Library validation is disabled: unsigned or differently-signed dylibs can be "
     "loaded into the process (dylib injection).",
     "Remove this entitlement; sign all loaded libraries with the same Team ID."),
    ("com.apple.security.cs.allow-unsigned-executable-memory", Severity.HIGH,
     "Unsigned executable memory is allowed, weakening code-injection defences.",
     "Remove this entitlement unless a JIT genuinely requires it."),
    ("com.apple.security.cs.disable-executable-page-protection", Severity.HIGH,
     "Executable page protection is disabled, broadly weakening memory protections.",
     "Remove this entitlement."),
    ("com.apple.security.cs.allow-dyld-environment-variables", Severity.MEDIUM,
     "DYLD environment variables are allowed, enabling library-injection via the "
     "environment.",
     "Remove this entitlement unless absolutely required."),
]


def check_dangerous_entitlements(ctx: NativeContext) -> list:
    if not ctx.codesign.get("available"):
        return []  # sandbox check already emits the not-assessed note
    out = []
    for key, sev, risk, fix in _DANGEROUS:
        if ctx.entitlements.get(key) is True:
            out.append(Finding(
                title=f"Dangerous entitlement enabled: {key}",
                severity=sev, confidence=Confidence.CONFIRMED, category="entitlements",
                evidence=f"Entitlement `{key}` is set to true.",
                source_locator=SourceLocator("codesign -d --entitlements :-",
                                             config_key=key),
                remediation=Remediation(fix),
                references=[_DOC_ENT, _DOC_HARDENING],
                why_it_matters=risk,
                discriminator=f"entitlements:{key}"))
    return out


# --------------------------------------------------------------------------- #
# 7. Info.plist hygiene
# --------------------------------------------------------------------------- #
_SENSITIVE_USAGE_KEYS = [
    "NSCameraUsageDescription", "NSMicrophoneUsageDescription",
    "NSLocationUsageDescription", "NSLocationWhenInUseUsageDescription",
    "NSContactsUsageDescription", "NSCalendarsUsageDescription",
    "NSPhotoLibraryUsageDescription", "NSAppleEventsUsageDescription",
    "NSDesktopFolderUsageDescription", "NSDocumentsFolderUsageDescription",
    "NSDownloadsFolderUsageDescription",
]


def check_info_plist(ctx: NativeContext) -> list:
    info = ctx.info_plist
    if not info:
        return [_na("info-plist", "Info.plist not assessed",
                    "Contents/Info.plist could not be read",
                    "Contents/Info.plist")]
    out = []
    loc = SourceLocator("Contents/Info.plist")
    ats = info.get("NSAppTransportSecurity") or {}
    if isinstance(ats, dict) and ats.get("NSAllowsArbitraryLoads") is True:
        out.append(Finding(
            title="App Transport Security disabled (arbitrary cleartext allowed)",
            severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
            category="info-plist",
            evidence="Info.plist sets NSAppTransportSecurity → "
                     "NSAllowsArbitraryLoads = true, permitting plaintext HTTP to "
                     "any host.",
            source_locator=SourceLocator("Contents/Info.plist",
                                         config_key="NSAllowsArbitraryLoads"),
            remediation=Remediation(
                "Remove NSAllowsArbitraryLoads and use HTTPS; add narrow per-domain "
                "exceptions only if unavoidable."),
            references=[_DOC_ATS],
            why_it_matters="Cleartext traffic can be read or modified by a network "
                           "attacker (MITM).",
            discriminator="info-plist:ats"))
    # Custom URL schemes — a hijack surface (descriptive, low).
    schemes = []
    for entry in info.get("CFBundleURLTypes") or []:
        if isinstance(entry, dict):
            schemes += [str(s) for s in (entry.get("CFBundleURLSchemes") or [])]
    if schemes:
        out.append(Finding(
            title=f"Custom URL scheme(s) registered: {', '.join(sorted(set(schemes)))}",
            severity=Severity.LOW, confidence=Confidence.LIKELY,
            category="info-plist",
            evidence="Info.plist declares CFBundleURLTypes schemes: "
                     + ", ".join(sorted(set(schemes))),
            source_locator=SourceLocator("Contents/Info.plist",
                                         config_key="CFBundleURLTypes"),
            remediation=Remediation(
                "Treat all inbound URL payloads as untrusted: validate and "
                "authorise every deep-link action; never auto-execute on open."),
            references=["https://owasp.org/www-project-mobile-top-10/"],
            why_it_matters="Any app or web page can invoke a registered scheme; "
                           "unvalidated deep links are a common hijack/abuse surface.",
            discriminator="info-plist:url-schemes"))
    # Empty sensitive usage-description strings.
    for key in _SENSITIVE_USAGE_KEYS:
        if key in info and not str(info.get(key) or "").strip():
            out.append(Finding(
                title=f"Empty usage-description string: {key}",
                severity=Severity.LOW, confidence=Confidence.LIKELY,
                category="info-plist",
                evidence=f"Info.plist declares {key} but its value is empty.",
                source_locator=SourceLocator("Contents/Info.plist", config_key=key),
                remediation=Remediation(
                    f"Provide a clear, specific purpose string for {key}."),
                references=[],
                why_it_matters="An empty purpose string yields a confusing consent "
                               "prompt and may be rejected by App Review.",
                discriminator=f"info-plist:usage:{key}"))
    return out


# --------------------------------------------------------------------------- #
# 8. Storage at rest
# --------------------------------------------------------------------------- #
_SECRET_PATTERNS = [
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("generic secret assignment", re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password|passwd|client[_-]?secret|access[_-]?token)\b"
        r"\s*[:=]\s*[\"']?[A-Za-z0-9_\-\.]{12,}")),
]
_TEXTISH = (".json", ".yaml", ".yml", ".txt", ".ini", ".cfg", ".conf", ".env",
            ".log", ".plist", ".db", ".sqlite", ".sqlite3", ".properties")
_MAX_STORAGE_FILES = 5000


def _redact(s: str) -> str:
    s = s.strip()
    if len(s) <= 12:
        return s[:2] + "…"
    return s[:4] + "…" + s[-2:]


def check_storage(ctx: NativeContext) -> list:
    if not ctx.storage_paths:
        return [Finding(
            title="On-disk storage not scanned (no data dir provided)",
            severity=Severity.INFO, confidence=Confidence.CONFIRMED,
            category="storage",
            evidence="No storage path was supplied (--storage-path). For Pieces, "
                     "pass ~/Library/com.pieces.os and ~/Library/com.pieces.pfd.",
            source_locator=SourceLocator("<storage>"),
            remediation=Remediation("Re-run with --storage-path to assess data at rest."),
            why_it_matters="Storage-at-rest issues are only assessable when a data "
                           "directory is provided.",
            discriminator="storage:not-scanned")]
    out = []
    scanned = 0
    for root in ctx.storage_paths:
        if not os.path.isdir(root):
            continue
        for dirpath, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs
                       if not os.path.islink(os.path.join(dirpath, d))]
            for fname in sorted(files):
                if scanned >= _MAX_STORAGE_FILES:
                    break
                full = os.path.join(dirpath, fname)
                if os.path.islink(full):
                    continue
                scanned += 1
                try:
                    real = ctx.fs.resolve(full)
                except UnsafePathError:
                    continue
                out += _scan_storage_file(ctx, root, real, fname)
    if not out:
        out.append(Finding(
            title="No plaintext secrets or unsafe permissions found in storage",
            severity=Severity.INFO, confidence=Confidence.CONFIRMED,
            category="storage",
            evidence=f"Scanned {scanned} file(s) under the provided storage path(s); "
                     "no world-readable secrets or plaintext credentials matched.",
            source_locator=SourceLocator("<storage>"),
            remediation=Remediation("No action."),
            why_it_matters="Context: storage at rest looked clean for the patterns checked.",
            discriminator="storage:clean"))
    return out


def _scan_storage_file(ctx: NativeContext, root: str, real: str, fname: str) -> list:
    out = []
    rel = os.path.relpath(real, root)
    label = f"{os.path.basename(root)}/{rel}"
    try:
        st = os.stat(real)
    except OSError:
        return out
    mode = st.st_mode
    name_sensitive = bool(re.search(
        r"(?i)(token|secret|cred|password|key|auth|session|\.db$|\.sqlite)", fname))

    # Permission hygiene on sensitive files.
    if name_sensitive and (mode & stat.S_IROTH or mode & stat.S_IWOTH or mode & stat.S_IWGRP):
        bits = stat.filemode(mode)
        out.append(Finding(
            title=f"Sensitive file is world/group accessible: {label}",
            severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED,
            category="storage",
            evidence=f"{label} has permissions {bits} (octal {oct(mode & 0o777)}); "
                     "other users on the machine can read or modify it.",
            source_locator=SourceLocator(label),
            remediation=Remediation(
                "Restrict to the owner only.",
                code=f"chmod 600 \"{rel}\""),
            references=[],
            why_it_matters="On a shared machine, other local accounts can read "
                           "credentials or tamper with this file.",
            discriminator=f"storage:perm:{label}"))

    # Plaintext secret scan for text-ish files.
    if real.lower().endswith(_TEXTISH):
        try:
            data = ctx.fs.read_bytes(real, max_bytes=4 * 1024 * 1024)
        except (UnsafePathError, OSError):
            return out
        text = data.decode("utf-8", errors="replace")
        for kind, pat in _SECRET_PATTERNS:
            m = pat.search(text)
            if m:
                line = text.count("\n", 0, m.start()) + 1
                out.append(Finding(
                    title=f"Plaintext {kind} in stored data: {label}",
                    severity=Severity.HIGH, confidence=Confidence.LIKELY,
                    category="storage",
                    evidence=f"{label}:{line} contains a {kind} (redacted): "
                             f"{_redact(m.group(0))}",
                    source_locator=SourceLocator(label, line=line),
                    remediation=Remediation(
                        "Store secrets in the macOS Keychain, not in plaintext "
                        "config/log/db files."),
                    references=["https://developer.apple.com/documentation/security/keychain_services"],
                    why_it_matters="Plaintext credentials at rest can be stolen by "
                                   "any process or user with read access.",
                    discriminator=f"storage:secret:{kind}:{label}"))
                break  # one finding per file is enough
    return out


# --------------------------------------------------------------------------- #
# 9. Plugin / framework inventory (descriptive, INFO only)
# --------------------------------------------------------------------------- #
_KNOWN_PLUGINS = {
    "file_picker": "native file open/save dialogs",
    "share_plus": "system share sheet",
    "url_launcher": "open URLs / external apps",
    "path_provider": "platform directories",
    "package_info_plus": "app version/build info",
    "sqflite": "SQLite storage",
    "shared_preferences": "key-value preferences",
    "connectivity_plus": "network reachability",
    "screen_retriever": "display info",
    "window_manager": "window control",
    "Sparkle": "auto-update framework",
}


def check_inventory(ctx: NativeContext) -> list:
    items = list(ctx.frameworks) + list(ctx.bundles)
    if not items:
        return []
    lines = []
    for it in items:
        base = it.replace(".framework", "").replace(".bundle", "")
        desc = _KNOWN_PLUGINS.get(base)
        lines.append(f"{it}" + (f" — {desc}" if desc else ""))
    return [Finding(
        title=f"Bundled frameworks / plugins ({len(items)})",
        severity=Severity.INFO, confidence=Confidence.CONFIRMED,
        category="inventory",
        evidence="Contents/Frameworks + Contents/Resources inventory:\n  "
                 + "\n  ".join(lines),
        source_locator=SourceLocator("Contents/Frameworks"),
        remediation=Remediation("No action — descriptive inventory. Keep plugins "
                                "updated via your Flutter/pubspec toolchain."),
        why_it_matters="Knowing the native capability surface (file access, URL "
                       "launching, sharing, networking) frames the rest of the report. "
                       "Mere presence of a plugin is NOT a vulnerability and no "
                       "version-CVE is asserted.",
        discriminator="inventory:list")]


# --------------------------------------------------------------------------- #
# 10. Update mechanism (Sparkle)
# --------------------------------------------------------------------------- #
def check_update_mechanism(ctx: NativeContext) -> list:
    info = ctx.info_plist
    has_sparkle = any("Sparkle" in f for f in ctx.frameworks) or "SUFeedURL" in info
    if not has_sparkle:
        return []
    out = []
    feed = str(info.get("SUFeedURL") or "")
    if feed.startswith("http://"):
        out.append(Finding(
            title="Sparkle update feed served over HTTP (not HTTPS)",
            severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
            category="update",
            evidence=f"Info.plist SUFeedURL = {feed}",
            source_locator=SourceLocator("Contents/Info.plist", config_key="SUFeedURL"),
            remediation=Remediation("Serve the appcast over HTTPS."),
            references=[_DOC_SPARKLE],
            why_it_matters="An HTTP appcast lets a network attacker serve a malicious "
                           "update.",
            discriminator="update:http-feed"))
    if not (info.get("SUPublicEDKey") or info.get("SUPublicDSAKeyFile")):
        out.append(Finding(
            title="Sparkle appcast signing key not configured",
            severity=Severity.MEDIUM, confidence=Confidence.LIKELY,
            category="update",
            evidence="Sparkle is present but neither SUPublicEDKey (EdDSA) nor "
                     "SUPublicDSAKeyFile is set in Info.plist.",
            source_locator=SourceLocator("Contents/Info.plist", config_key="SUPublicEDKey"),
            remediation=Remediation(
                "Configure EdDSA appcast signing (SUPublicEDKey) so updates are "
                "verified before install."),
            references=[_DOC_SPARKLE],
            why_it_matters="Without signed appcasts, a tampered update can be "
                           "installed even over HTTPS if the server is compromised.",
            discriminator="update:no-signing-key"))
    return out


# --------------------------------------------------------------------------- #
# 11. Embedded-secret scan of NON-CODE artifacts + strings of the Mach-O
# --------------------------------------------------------------------------- #
def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _python_strings(data: bytes, minlen: int = 6) -> list:
    out, cur = [], []
    for b in data:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= minlen:
                out.append("".join(cur))
            cur = []
    if len(cur) >= minlen:
        out.append("".join(cur))
    return out


def check_embedded_secrets(ctx: NativeContext) -> list:
    out = []
    # (a) Non-code text artifacts in Resources / flutter_assets + Info.plist.
    text_roots = [ctx.resources_dir]
    scanned_files = 0
    for root in text_roots:
        if not os.path.isdir(root):
            continue
        for dirpath, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(dirpath, d))]
            for fname in sorted(files):
                if not fname.lower().endswith((".json", ".plist", ".yaml", ".yml",
                                               ".txt", ".cfg", ".env")):
                    continue
                if scanned_files >= 2000:
                    break
                full = os.path.join(dirpath, fname)
                if os.path.islink(full):
                    continue
                scanned_files += 1
                try:
                    text = ctx.fs.read_text(full, max_bytes=2 * 1024 * 1024)
                except (UnsafePathError, OSError):
                    continue
                rel = os.path.relpath(full, ctx.app_path)
                for kind, pat in _SECRET_PATTERNS:
                    m = pat.search(text)
                    if m:
                        line = text.count("\n", 0, m.start()) + 1
                        out.append(_secret_finding(kind, rel, line, m.group(0)))
                        break
    # (b) strings() of the Mach-O launcher and App.framework binary.
    macho = []
    if os.path.isdir(ctx.macos_dir):
        for n in sorted(os.listdir(ctx.macos_dir)):
            macho.append(os.path.join(ctx.macos_dir, n))
    app_bin = os.path.join(ctx.frameworks_dir, "App.framework", "App")
    if os.path.isfile(app_bin):
        macho.append(app_bin)
    for path in macho:
        if os.path.islink(path) or not os.path.isfile(path):
            continue
        try:
            data = ctx.fs.read_bytes(path, max_bytes=8 * 1024 * 1024)
        except (UnsafePathError, OSError):
            continue
        rel = os.path.relpath(path, ctx.app_path)
        for s in _python_strings(data):
            for kind, pat in _SECRET_PATTERNS:
                if pat.search(s):
                    out.append(_secret_finding(kind, rel, None, s, from_strings=True))
                    break
            if len(out) > 50:
                break

    note = Finding(
        title="Embedded-secret scan scope (compiled Dart NOT inspected)",
        severity=Severity.INFO, confidence=Confidence.CONFIRMED,
        category="secrets",
        evidence="Scanned: Info.plist, bundled json/plist/yaml/txt under "
                 "Contents/Resources, and printable strings of the Mach-O launcher "
                 "and App.framework/App. The AOT-compiled Dart logic itself is NOT "
                 "decompiled or scanned — only literal printable strings are read.",
        source_locator=SourceLocator("<native>"),
        remediation=Remediation("No action — scope statement for honesty."),
        why_it_matters="Static secret-scanning of a native app has low yield and "
                       "cannot see compiled logic; results here are literal strings only.",
        discriminator="secrets:scope")
    return out + [note]


def _secret_finding(kind: str, rel: str, line: Optional[int], match: str,
                    from_strings: bool = False) -> Finding:
    where = "printable strings of " if from_strings else ""
    return Finding(
        title=f"Possible embedded {kind} in {os.path.basename(rel)}",
        severity=Severity.MEDIUM, confidence=Confidence.POSSIBLE,
        category="secrets",
        evidence=f"{where}{rel}" + (f":{line}" if line else "")
                 + f" matched a {kind} (redacted): {_redact(match)}",
        source_locator=SourceLocator(rel, line=line),
        remediation=Remediation(
            "If this is a live secret, rotate it and load it at runtime from the "
            "Keychain or a server, not from a bundled artifact."),
        references=[],
        why_it_matters="Secrets shipped inside the app can be extracted by anyone "
                       "with the binary. Low confidence: may be a placeholder, public "
                       "key, or false positive — verify before acting.",
        false_positive_note="Heuristic match on a literal string; not confirmed to be "
                            "a live credential.",
        discriminator=f"secrets:{kind}:{rel}")


# Ordered registry — deterministic run order.
NATIVE_CHECKS = [
    check_code_signing,
    check_notarization,
    check_hardened_runtime,
    check_app_sandbox,
    check_dangerous_entitlements,
    check_info_plist,
    check_storage,
    check_inventory,
    check_update_mechanism,
    check_embedded_secrets,
]
