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

# Scan an installed app (point at the app dir, .app bundle, or app.asar):
deskscanner scan /Applications/Slack.app
deskscanner scan "/opt/Pieces/resources/app.asar"
deskscanner scan ./my-electron-app

# Save machine-readable + shareable reports:
deskscanner scan ./app --json report.json --html report.html

# Enable the SAFE loopback probe (read-only, 127.0.0.1 only):
deskscanner scan ./app --probe

# Diff against a previous run (ignores volatile fields):
deskscanner scan ./app --diff report.json
```

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
  scoring.py           severity × confidence grade (diminishing returns)
  diff.py              fixed / new / unchanged, ignoring volatile fields
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