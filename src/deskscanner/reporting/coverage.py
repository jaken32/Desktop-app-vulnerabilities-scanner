"""The honest "what this does and doesn't cover" text, shared by all renderers
and the README. Single source of truth so the product and docs never drift."""

COVERS = [
    "Static inspection of the shipped Electron bundle (app.asar / unpacked app): "
    "JS, JSON and config, read without executing it.",
    "Per-window and per-<webview> Electron security configuration "
    "(nodeIntegration, contextIsolation, sandbox, webSecurity, CSP, preload, "
    "contextBridge exposure, remote content, shell.openExternal).",
    "Hardcoded secret scanning (provider patterns + Shannon entropy) with "
    "redaction and placeholder filtering.",
    "Dependency hygiene: outdated MAJOR versions (from version numbers) plus "
    "advisories from a dated, cited file only.",
    "Application metadata: Electron version + end-of-life status (dated data) "
    "and best-effort code-signing detection.",
    "On-disk data storage: plaintext secrets and world-/group-readable "
    "permissions on sensitive files.",
    "A SAFE, read-only loopback probe of the app's own detected port(s): "
    "security headers, CORS, unauthenticated root — GET/OPTIONS only.",
]

DOES_NOT_COVER = [
    "No dynamic/runtime analysis, debugging, hooking, or memory inspection.",
    "No reverse-engineering or disassembly of native binaries — if there is no "
    "readable JS bundle, the tool stops and says so.",
    "No logic flaws, memory-safety bugs, or anything requiring code execution.",
    "No CVE assertions from memory — CVE matching is limited to the dated "
    "advisory file; uncovered packages are 'not scanned for known CVEs'.",
    "No attacks on remote servers, no fuzzing, no mutation — the loopback probe "
    "is the only active behaviour and it is read-only.",
    "Confidence is reduced (never silently passed) on minified/packed bundles.",
]

DISCLAIMER = (
    "A good grade means the inspected configuration looks sound for the checks "
    "above — NOT that the application is secure. This is static analysis plus a "
    "safe loopback inspection, nothing more."
)
