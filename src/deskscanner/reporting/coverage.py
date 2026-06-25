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

# --- Native / Flutter engine coverage -------------------------------------- #
COVERS_NATIVE = [
    "Code-signing validity & identity (codesign -dvvv): unsigned / ad-hoc / "
    "authority chain.",
    "Notarization & Gatekeeper (spctl, stapler) and the Hardened Runtime flag.",
    "App Sandbox and dangerous entitlements (get-task-allow, "
    "disable-library-validation, allow-unsigned-executable-memory, "
    "allow-dyld-environment-variables, disable-executable-page-protection).",
    "Info.plist hygiene: App Transport Security, custom URL schemes, empty "
    "sensitive usage-description strings.",
    "On-disk storage at rest (with --storage-path): unsafe permissions and "
    "plaintext credentials/tokens.",
    "Framework / plugin inventory (descriptive, INFO only).",
    "Embedded-secret scan of NON-CODE artifacts (Info.plist, bundled "
    "json/plist/yaml/txt) and printable strings of the Mach-O launcher + "
    "App.framework binary.",
    "Update mechanism (Sparkle): HTTPS feed + appcast signing key.",
    "OPT-IN, loopback-only (127.0.0.1) read-only probe of the app's local HTTP "
    "service: auth, CORS, security headers, version disclosure.",
]

DOES_NOT_COVER_NATIVE = [
    "No decompilation or disassembly of native binaries — strings extraction "
    "only; decompilation is never performed.",
    "No runtime/dynamic analysis, debugging, hooking, or memory inspection.",
    "The loopback probe is the only active behaviour, is read-only (GET/OPTIONS), "
    "and only ever contacts 127.0.0.1.",
    "No CVEs or version vulnerabilities asserted for bundled plugins/frameworks.",
]

# Stated plainly in the report and README.
FLUTTER_VISIBILITY = (
    "What Flutter scanning can and cannot see: a release Flutter macOS app "
    "compiles its Dart logic to native machine code in Contents/Frameworks/"
    "App.framework/App. That compiled logic is NOT readable and is NOT scanned — "
    "there is no asar, no JavaScript, and no Electron webPreferences. This engine "
    "reports only what is directly observable on disk (signing, entitlements, "
    "Info.plist, bundled non-code assets, framework inventory, file permissions) "
    "and, with --probe, the app's own loopback HTTP service. It never fabricates "
    "Electron-style findings for a native app."
)
