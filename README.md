# deskscanner

[![tests](https://github.com/jaken32/Desktop-app-vulnerabilities-scanner/actions/workflows/tests.yml/badge.svg)](https://github.com/jaken32/Desktop-app-vulnerabilities-scanner/actions/workflows/tests.yml)

**Static security scanner for installed Electron desktop applications** (Pieces,
Slack, Discord, VS Code, …) plus a *safe, read-only* inspection of the app's own
loopback service. It locates and unpacks the shipped `app.asar` **without
executing it**, runs a battery of pluggable checks, and produces an in-depth,
graded report in the terminal and a local web UI.

> **A good grade means the inspected configuration looks sound for the checks
> below — not that the application is secure.** This is static analysis plus a
> safe loopback inspection. Nothing here runs, hooks, or reverse-engineers the
> target.

---

## What it checks

- **Electron misconfiguration (core value).** For *every* `BrowserWindow` and
  `<webview>` independently: `nodeIntegration`, `contextIsolation`, `sandbox`,
  `webSecurity`, `allowRunningInsecureContent`, `experimentalFeatures`, the
  remote module, `shell.openExternal` misuse, preload / `contextBridge`
  over-exposure, remote content loading, and missing/weak renderer CSP. One
  secure window does not make the app secure — findings are per-surface.
- **Secrets.** Provider regexes (AWS, GitHub, Slack, Google, Stripe, OpenAI,
  Anthropic, private keys, JWTs, …) plus a Shannon-entropy fallback, with
  redaction and placeholder filtering.
- **Dependencies.** Outdated **major** versions (from version numbers alone) and
  advisories from a *dated, cited* file only — **never invented CVEs** (see
  [No fabrication](#no-fabrication)).
- **Local API surface.** Detects a loopback HTTP listener statically, then
  *optionally* probes only that `127.0.0.1` service (security headers, CORS,
  unauthenticated root) with idempotent `GET`/`OPTIONS` and a timeout.
- **Local data storage.** Plaintext secrets and world-/group-readable
  permissions on sensitive files under the app's on-disk data directory.
- **App metadata.** Electron version + end-of-life status (from dated data) and
  best-effort code-signing detection.

## Quick start (clean clone)

Requires **Python 3.11+**. No secrets or network access are needed.

```bash
git clone https://github.com/jaken32/Desktop-app-vulnerabilities-scanner
cd Desktop-app-vulnerabilities-scanner

python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .                                     # installs pinned deps

# Scan an installed app (point at the app dir, .app bundle, or app.asar).
# By default this runs BOTH axes — security vulnerabilities AND efficiency —
# each with its own separate grade:
deskscanner scan /Applications/Slack.app
deskscanner scan "/opt/Pieces/resources/app.asar"
deskscanner scan ./my-electron-app

# Run just one axis when you want to:
deskscanner scan ./app --mode security      # security only
deskscanner scan ./app --mode efficiency    # efficiency only (same as `efficiency`)

# Save machine-readable + shareable reports:
deskscanner scan ./app --json report.json --html report.html

# Polished, branded PDF report:
deskscanner scan ./app --pdf report.pdf

# AI in-depth analysis + plain-English explanation (needs an API key):
pip install -e ".[report]"                  # one-time: installs anthropic + fpdf2
export ANTHROPIC_API_KEY=sk-ant-...
deskscanner scan ./app --analyze --pdf report.pdf

# Enable the SAFE loopback probe (read-only, 127.0.0.1 only):
deskscanner scan ./app --probe

# Diff against a previous run (ignores volatile fields):
deskscanner scan ./app --diff report.json

# EFFICIENCY only — grade the app's size/footprint (static; no profiling):
deskscanner efficiency ./app
deskscanner efficiency ./app --html efficiency.html --json efficiency.json
```

`deskscanner scan` runs **both** the security and efficiency axes by default,
each with its own independent A–F grade, shown as two clearly-separated sections.
Pass `--mode security` or `--mode efficiency` (or use the `efficiency`
subcommand) to run a single axis. The library API and web UI default to
security-only for backward compatibility — pass `mode="all"` to opt in.

The `--analyze` flag uses Claude to turn the deterministic findings into a
plain-English summary and a deeper technical analysis (key risks, recommended
fix order). It is optional and anchored to the scan's own evidence — the model
is instructed to explain only what the scanner found, never to invent issues.
The narrative appears in the CLI output, the PDF, and the JSON report.
`--pdf` and `--analyze` need the `report` extra (`pip install -e ".[report]"`);
the core scanner still runs with no extra packages and no secrets.

You'll be shown an **authorization notice** and asked to confirm before any
scan. Use `--yes` (or `DESKSCANNER_ASSUME_YES=1`) in CI.

CLI exit code is `1` when there is a confirmed/likely High or Critical finding,
`0` otherwise (and `2`/`3`/`4` for consent/target/unpack errors) — handy for CI
gates.

### Web UI

```bash
deskscanner serve            # http://127.0.0.1:8765
```

A single dense audit page: enter a target path, tick the authorization box,
optionally enable the probe, and run. Every control is wired to real behaviour
with explicit loading / success / empty / error states; the graded report can be
downloaded as a standalone HTML file.

### Configuration

Copy `.env.example` to `.env` (gitignored) to tune resource limits, the probe
timeout, and the web host/port. All have safe defaults.

## Efficiency mode (static footprint analysis)

A second analysis axis that helps developers make an Electron app **smaller and
leaner**. Run it with `deskscanner efficiency <app>`, or alongside security with
`deskscanner scan <app> --mode all`. It reuses the same safe asar unpacker,
`Finding`/`ScanResult` model, A–F grade, confidence model, and report renderers
— it is a new check category, not a new engine. Efficiency findings are graded
on their **own separate axis**, so they never change the security grade.

**What it analyses (static, structural):** total footprint + a size breakdown by
type and the largest files; oversized single assets; source maps shipped to
production; un-minified production JS; oversized/uncompressed images (with
dimensions); heavy dependencies that have lighter alternatives; duplicate
dependency versions; possibly-unused dependencies (import not found in readable
code); devDependencies packed into the shipped app; Electron main-process
anti-patterns (top-level synchronous `fs`, many `BrowserWindow`s); many startup
`<script>`s; duplicated file content; and an unpacked (no-asar) distribution.

**Impact summary.** Every efficiency report ends with an Impact Summary that
quantifies *only what static inspection can measure*:

- **Current vs. projected size** — the measured shipped size, the projected size
  if the flagged fixes are applied, the absolute saving, and the **% reduction in
  payload size** (always labelled "size", never "speed").
- **Per-fix measured savings (ranked "biggest wins")** — each fix with its
  `before → after` bytes, e.g. *"Minify renderer.js: 7.2 MB → ~2.5 MB (−4.7 MB)"*,
  *"Exclude source maps: −9.0 MB"*. Each is labelled `measured` (exact, e.g. a
  removal) or `estimate` with its stated assumption (e.g. *"assumes ~65%
  minification reduction"*).
- **Measured benefits** — numeric, traceable: total footprint reduction, files no
  longer shipped, devDependencies pruned (count + bytes), possibly-unused deps to
  remove.
- **Directional benefits** — real but *not* measured, and clearly labelled as
  such: *"smaller startup payload → generally faster launch and parse — verify
  with profiling."* No number is ever attached to these.
- **Honesty footer:** *"All figures are static size measurements and structural
  estimates. This tool does not run the app; actual runtime speed, memory, and
  smoothness must be confirmed by profiling the running application."*

If the app is already lean, the summary says so plainly (*"No significant
size-reduction opportunities found; shipped size is X MB"*) and fabricates no
savings. Every number traces to a counted file size; the summary reflects only
the findings actually present in this scan; identical bundles produce identical
numbers.

**What efficiency mode does NOT do (by design):**

- **No runtime profiling.** No CPU, memory, FPS, or startup-time measurement —
  it never runs, instruments, or executes the app.
- **No fabricated speed numbers.** It never claims "X% faster/smoother". Only
  measured *payload size* and structural signals are reported; speed effects are
  stated **directionally** ("a smaller payload generally reduces launch/parse
  time — verify with profiling"), never as measured figures.
- **No confident "unused" on code it couldn't read.** On a minified/obfuscated
  bundle, usage analysis is unreliable, so those findings drop to `possible` and
  say so. No "unused"/"heavy" claim is made without measured evidence.

### Efficiency severity rubric (hardcoded, applied identically to every app)

| Severity | Meaning (efficiency axis) |
|---|---|
| Critical | Ships something that severely bloats the app — e.g. an un-minified production bundle **and** shipped source maps, or a 100 MB+ avoidable payload. |
| High | Significant avoidable bloat or a clear startup-cost anti-pattern — an oversized single asset, devDependencies packed into production. |
| Medium | A meaningful optimization opportunity — un-minified JS, duplicate dependency versions, oversized images, a known-heavy library. |
| Low | Minor — top-level synchronous `fs` in main, many startup scripts, duplicated file content, an unpacked distribution. |
| Info | Advisory / summary context (footprint summary, analysis-reliability note). |

The grade uses the **same** severity×confidence decay math as the security axis
(see below); the two grades are computed independently.

## Native macOS / Flutter targets

deskscanner also scans **native macOS apps that ship no readable bundle** —
including Flutter apps (e.g. Pieces), whose logic is AOT-compiled Dart inside
`Contents/Frameworks/App.framework/App`. A **platform router** inspects the
target and picks the engine, reporting *which* engine ran and *why*:

| Artifact matched | Engine |
|---|---|
| `Contents/Resources/app.asar` (or an unpacked JS bundle) | **electron** (unchanged) |
| `Contents/Frameworks/FlutterMacOS.framework` | **flutter** |
| a valid `.app` with `Contents/Info.plist`, no asar/Flutter | **native** (generic) |

All engines share the same `Finding` schema, severity rubric, confidence model,
scoring, and report renderer. Force the choice with `--engine flutter|electron|native`.

```bash
# Auto-detected native scan (codesign/spctl/entitlements/Info.plist/inventory):
deskscanner scan /Applications/Pieces.app

# Include on-disk storage at rest:
deskscanner scan /Applications/Pieces.app \
  --storage-path ~/Library/com.pieces.os --storage-path ~/Library/com.pieces.pfd

# List which loopback ports the app is listening on (NO request sent):
deskscanner scan /Applications/Pieces.app --prospect

# OPT-IN, read-only loopback probe of the app's local HTTP API (127.0.0.1 only):
deskscanner scan /Applications/Pieces.app --probe

# `desksec` is an alias for `deskscanner`:
desksec scan /Applications/Pieces.app
```

The native engine checks: code-signing validity & identity, notarization &
Gatekeeper, Hardened Runtime, App Sandbox, dangerous entitlements
(`get-task-allow`, `disable-library-validation`,
`allow-unsigned-executable-memory`, `allow-dyld-environment-variables`,
`disable-executable-page-protection`), Info.plist hygiene (ATS / custom URL
schemes / empty usage strings), storage at rest, a descriptive framework/plugin
inventory, an embedded-secret scan of **non-code** artifacts, and the Sparkle
update mechanism — plus the opt-in loopback probe.

### What Flutter scanning can and cannot see

A release Flutter macOS app compiles its Dart to **native machine code** in
`Contents/Frameworks/App.framework/App`. **That compiled logic is not readable
and is not scanned** — there is no asar, no JavaScript, and no Electron
`webPreferences`. The native engine therefore:

- **reports only what is directly observable** on disk (`codesign`/`spctl`
  output, entitlements, Info.plist, bundled non-code assets, framework
  inventory, file permissions) and, with `--probe`, the app's own loopback HTTP
  service;
- **never decompiles or disassembles** native binaries — `strings` extraction is
  the only thing done to the Mach-O, and that is explicitly labelled;
- **never fabricates Electron-style findings** for a native app; categories that
  cannot be assessed (e.g. when `codesign`/`spctl` aren't on the host) are marked
  *"Not assessed / Not applicable"* rather than invented.

The macOS signing/notarization checks require the Xcode command-line tools
(`codesign`, `spctl`, `stapler`); off-macOS those categories report
*"not assessed on this host"*. The loopback probe **only ever contacts
127.0.0.1**, issues **GET/OPTIONS only**, and requires both the authorization
affirmation and the explicit `--probe` flag.

## How findings are scored

Every finding carries **two independent axes**: a **severity** (how bad it is if
real) and a **confidence** (how sure we are it's real and active). These are
never conflated.

### Severity rubric (hardcoded, applied identically to every app)

| Severity | Meaning | Example |
|----------|---------|---------|
| **Critical** | A remote-code-execution path, or a credential usable as-is | `nodeIntegration:true` + remote content; a live API key |
| **High** | A significant hardening failure with a known exploit class | `contextIsolation:false`, `webSecurity:false`, EOL Electron |
| **Medium** | A defence-in-depth gap | missing/weak CSP, missing security header on the local API |
| **Low** | Minor / cosmetic hardening | missing `Permissions-Policy`, unsigned app |
| **Info** | Advisory / context only | preload present, supported Electron version |

### Confidence model

| Confidence | Meaning |
|------------|---------|
| **confirmed** | The insecure setting is unambiguously present and active. |
| **likely** | Strong evidence, but a mitigation could exist elsewhere. |
| **possible** | Pattern present but plausibly intentional / a false positive. |

Where a finding is a common false positive, the finding text says so explicitly.

### Grade

The grade weights **severity × confidence**. The score starts at 100; each
finding's base penalty is `severity_weight × confidence_weight` (Info = 0), and
penalties are combined with a decay (`0.75ⁱ`, worst-first) so the single worst
issue counts in full and additional ones count progressively less. Because the
confidence weight multiplies in (confirmed 1.0 · likely 0.6 · possible 0.3), a
"possible" finding **cannot dominate** the grade the way a "confirmed" one can.

| Score | Grade |
|-------|-------|
| ≥ 90 | A |
| ≥ 80 | B |
| ≥ 70 | C |
| ≥ 60 | D |
| < 60 | F |

### Provenance & determinism

- **Every finding cites a verifiable source locator** — a file path inside the
  bundle plus a line number or the exact config key/value. No finding ships
  without one.
- **Determinism (scoped):** given the *same bundle*, the static findings, their
  order, and the grade are identical across runs. Each static finding has a
  stable id (`DS-…`). The scan timestamp and live local-API probe results are
  *volatile* — excluded from stable ids and from diffs.
- **Obfuscation honesty:** minified/packed files are detected and findings in
  them have **lowered confidence**; we never report a clean bill on code we
  couldn't meaningfully read.

## <a name="no-fabrication"></a>No fabrication of CVEs

deskscanner **never asserts a CVE, advisory, or version-specific vulnerability
from memory.** Only two modes exist:

1. **Outdated major version** — derived purely by comparing a dependency's
   resolved version against a dated `latest_major` snapshot
   (`src/deskscanner/data/dependency_advisories.json`).
2. **Named advisories** — emitted only for entries present in that dated, cited
   file (empty by default). Any package not covered is reported as
   *"not scanned for known CVEs"*.

Electron end-of-life is judged only against the dated
`src/deskscanner/data/electron_eol.json` snapshot. Versions newer than or absent
from it are reported as *unknown — not guessed*.

## Safety guarantees

- **Read-only.** Never modifies, patches, or repacks the target or its data.
- **Safe unpacking.** A pure-Python asar parser rejects path traversal
  (asar-slip), absolute paths, Windows drive letters, and symlink entries, and
  enforces resource bounds (max total size, per-file size, file count, wall-clock
  timeout) to defend against zip-bomb-style headers. Extraction is contained to a
  temp dir; the default mode reads in-memory and writes nothing.
- **The loopback probe is the only active behaviour.** It connects only to
  `127.0.0.1`/`::1` on the app's own detected port(s), issues idempotent
  `GET`/`OPTIONS` with a per-request timeout, and never fuzzes, mutates, or
  touches a non-loopback host. It is **opt-in** (`--probe`).
- **Consent gate** before every scan.
- All bundle- and API-derived strings are treated as hostile input and escaped in
  every report (XSS-safe).

## Limitations (please read)

- **Static analysis only**, plus the safe loopback inspection. No dynamic/runtime
  analysis, debugging, hooking, or memory inspection.
- **No native-binary reverse-engineering.** If the target has no `app.asar` and
  no readable JavaScript, the tool reports that and stops — it never analyses a
  native binary.
- Cannot find logic flaws, memory-safety bugs, or anything requiring code
  execution.
- Confidence is reduced (never silently passed) on minified/packed bundles.
- CVE matching is limited to the dated advisory file (see above).
- Code-signing detection is best-effort from on-disk artifacts; on Windows/Linux
  the signature lives in the native binary (out of scope), so status may be
  "unknown".
- **A good grade means the inspected configuration looks sound — not that the
  app is secure.**

## Authorization

Only scan software you own or are explicitly authorised to assess. The loopback
probe issues real (read-only) requests to a service running on your machine.

## Architecture

```
src/deskscanner/
  models.py            Severity, Confidence, SourceLocator, Remediation, Finding, ScanResult
  locate.py            find the bundle (app dir / .app / app.asar / unpacked)
  unpack.py            pure-Python asar parser; traversal + resource guards
  checks/              pluggable Check modules -> Finding objects
    base.py            Check ABC, shared CheckContext, text helpers
    electron_config.py per-window / per-webview misconfiguration
    secrets.py         provider regexes + entropy, redaction, placeholders
    dependencies.py    outdated majors + dated advisories (no fabrication)
    local_api.py       static listener detection + safe loopback probe
    storage.py         on-disk plaintext secrets + permissions
    app_meta.py        Electron version/EOL + code-signing
    efficiency.py      static footprint/efficiency analyzer (second axis)
  scoring.py           severity × confidence grade (diminishing returns); efficiency grade
  diff.py              fixed / new / unchanged, ignoring volatile fields
  native/              native/Flutter engine (macOS apps with no readable bundle)
    detect.py          platform router -> electron | flutter | native (+ why)
    macos.py           codesign/spctl/entitlements runner + pure parsers
    context.py         NativeContext + path-traversal-safe reader (SafeFS)
    checks.py          signing/notarization/runtime/sandbox/entitlements/plist/
                       storage/inventory/secrets/update checks
    probe.py           opt-in loopback-only (127.0.0.1) read-only probe
    engine.py          run_native: build context -> checks -> score -> ScanResult
  reporting/
    cli.py             dense terminal report
    html.py            standalone, escaped HTML report (design system)
    coverage.py        the honest "covers / does not cover" text
  data/                dated, cited advisory snapshots
  web/                 FastAPI backend + hand-written SPA (templates/, static/)
tests/                 pytest suite (offline, deterministic) + fixtures
```

A check is any subclass of `checks.base.Check` registered in
`checks/__init__.py`; it receives a `CheckContext` and returns `Finding`s.

## Development & tests

```bash
pip install -e ".[dev]"
python -m pytest          # fully offline & deterministic
```

CI runs the suite on Python 3.11 and 3.12 via GitHub Actions on every push and
PR (badge above). The test suite includes exhaustive asar path-traversal and
resource-limit tests, XSS-safety of the report, determinism, diff correctness,
and an end-to-end check that the deliberately-insecure fixture produces *exactly*
the documented findings while the secure fixture grades **A** (see
`tests/fixtures/EXPECTED.md`).

## License

MIT — see [LICENSE](LICENSE).