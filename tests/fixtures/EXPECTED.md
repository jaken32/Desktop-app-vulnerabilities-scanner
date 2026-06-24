# Expected findings for the test fixtures

These are asserted exactly by `tests/test_fixture_expected.py`. If you change a
check or a fixture, update both together.

## Insecure fixture (`insecure_app/` + assembled `config.json`)

Scanned with the loopback probe **disabled**. Grade: **F** (contains a confirmed
RCE path and usable credentials).

| # | Category | Severity | Confidence | What |
|---|----------|----------|-----------|------|
| 1 | electron_config | Critical | confirmed | `nodeIntegration:true` **and** remote `loadURL` → RCE path (`main.js`) |
| 2 | electron_config | High | confirmed | `contextIsolation:false` (`main.js`) |
| 3 | electron_config | High | confirmed | `webSecurity:false` (`main.js`) |
| 4 | electron_config | High | confirmed | `allowRunningInsecureContent:true` (`main.js`) |
| 5 | electron_config | High | confirmed | `enableRemoteModule:true` (`main.js`) |
| 6 | electron_config | High | confirmed | `<webview nodeintegration>` (`index.html`) |
| 7 | electron_config | High | likely | `contextBridge.exposeInMainWorld('api', ipcRenderer)` broad exposure (`preload.js`) |
| 8 | electron_config | Medium | confirmed | `sandbox:false` (`main.js`) |
| 9 | electron_config | Medium | likely | No CSP on the renderer document (`index.html`) |
| 10 | electron_config | Medium | possible | `shell.openExternal(variable)` non-literal URL (`main.js`) |
| 11 | electron_config | Info | confirmed | Preload script configured (`main.js`) |
| 12 | secrets | Critical | confirmed | Hardcoded AWS Access Key ID (`config.json`) |
| 13 | secrets | Critical | confirmed | Hardcoded private key block (`config.json`) |
| 14 | secrets | High | possible | Generic assigned secret `client_secret` (`config.json`) |
| 15 | dependencies | Medium | likely | `electron` outdated major (22 vs 34) |
| 16 | dependencies | Low | likely | `lodash` outdated major (3 vs 4) |
| 17 | dependencies | Info | confirmed | CVE-matching scope note (no-fabrication policy) |
| 18 | app_meta | High | confirmed | End-of-life Electron 22 (per dated snapshot) |
| 19 | app_meta | Info | confirmed | Code-signing not determinable from a standalone asar |

The `config.json` secrets are assembled from fragments at test build time so the
repository never stores a complete, scannable credential. All values are fake.

## Secure fixture (`secure_app/`)

Grade: **A**, score **100**. Only informational findings:

- electron_config / Info: preload configured.
- app_meta / Info: Electron 34 is currently supported.
- app_meta / Info: code-signing not determinable from a standalone asar.
- dependencies / Info: CVE-matching scope note.

No findings above informational level — proving the tool does not just flag
everything.
