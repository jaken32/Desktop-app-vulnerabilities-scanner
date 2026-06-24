"""Electron security-misconfiguration checks — the core value of the tool.

We inspect *every* ``BrowserWindow``/``BrowserView`` ``webPreferences`` block
and *every* ``<webview>`` tag independently: one secure window does not make
the app secure, so each insecure surface gets its own finding with its own
source locator.

Detection is static and regex-driven. Crucially, Electron ``webPreferences``
key *names* are an API contract and survive minification unchanged (only their
*values* get rewritten, e.g. ``true`` -> ``!0``), which is why this still works
on packed bundles — we just lower confidence there.
"""

from __future__ import annotations

import re

from ..models import (
    Confidence,
    Finding,
    Remediation,
    Severity,
    SourceLocator,
)
from .base import Check, CheckContext, line_of, snippet_around

CATEGORY = "electron_config"

ELECTRON_DOCS = "https://www.electronjs.org/docs/latest/tutorial/security"

# True/false token normalisation, including minifier forms.
_TRUE_TOKENS = {"true", "!0", "1"}
_FALSE_TOKENS = {"false", "!1", "0"}


def _norm_bool(token: str):
    t = token.strip()
    if t in _TRUE_TOKENS:
        return True
    if t in _FALSE_TOKENS:
        return False
    return None


def _find_balanced_object(text: str, open_index: int) -> tuple[int, int]:
    """Given the index of a ``{``, return ``(start, end)`` of the balanced
    object, ignoring braces inside string/template literals. ``end`` is the
    index just past the closing ``}``."""
    depth = 0
    i = open_index
    n = len(text)
    quote = None
    while i < n:
        c = text[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        else:
            if c in "\"'`":
                quote = c
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return open_index, i + 1
        i += 1
    return open_index, n  # unbalanced; take the rest


# A webPreferences key and its (severity, confidence-when-set, message) for the
# *insecure* value. ``insecure_value`` is the boolean that is dangerous.
_BOOL_KEYS = {
    "nodeIntegration": {
        "insecure": True,
        "severity": Severity.HIGH,
        "title": "nodeIntegration enabled in a renderer",
        "why": "Renderer JS gets full Node.js access, so any successful XSS or "
               "loaded remote content becomes arbitrary code execution on the host.",
        "fp": None,
        "remediation": Remediation(
            "Disable nodeIntegration and use a contextBridge preload to expose "
            "only the specific IPC calls the renderer needs.",
            "new BrowserWindow({\n"
            "  webPreferences: {\n"
            "    nodeIntegration: false,   // default since Electron 5\n"
            "    contextIsolation: true,   // default since Electron 12\n"
            "    sandbox: true,\n"
            "    preload: path.join(__dirname, 'preload.js'),\n"
            "  },\n"
            "})",
        ),
    },
    "contextIsolation": {
        "insecure": False,
        "severity": Severity.HIGH,
        "title": "contextIsolation disabled in a renderer",
        "why": "Without context isolation, preload and page scripts share one "
               "world, so a compromised page can reach into privileged objects "
               "and prototype-pollute the bridge.",
        "fp": None,
        "remediation": Remediation(
            "Set contextIsolation: true (the default since Electron 12) and "
            "expose APIs only via contextBridge.",
            "webPreferences: { contextIsolation: true }",
        ),
    },
    "sandbox": {
        "insecure": False,
        "severity": Severity.MEDIUM,
        "title": "Renderer sandbox disabled",
        "why": "A disabled sandbox removes the OS-level process isolation that "
               "contains a compromised renderer.",
        "fp": "Some apps legitimately disable the sandbox for a preload that "
              "needs Node built-ins; pair this with the nodeIntegration/"
              "contextIsolation findings to judge real risk.",
        "remediation": Remediation(
            "Keep sandbox: true (default since Electron 20). If a preload needs "
            "Node, use a sandboxed preload with @electron/remote-free IPC.",
            "webPreferences: { sandbox: true }",
        ),
    },
    "webSecurity": {
        "insecure": False,
        "severity": Severity.HIGH,
        "title": "webSecurity disabled",
        "why": "Disabling webSecurity turns off the same-origin policy, allowing "
               "remote pages to read local files and cross-origin resources.",
        "fp": None,
        "remediation": Remediation(
            "Never ship with webSecurity: false. Use a custom protocol or "
            "explicit CORS handling instead of disabling the SOP.",
            "webPreferences: { webSecurity: true }",
        ),
    },
    "allowRunningInsecureContent": {
        "insecure": True,
        "severity": Severity.HIGH,
        "title": "allowRunningInsecureContent enabled",
        "why": "Permits HTTP scripts on HTTPS pages, opening a mixed-content "
               "injection path for a network attacker.",
        "fp": None,
        "remediation": Remediation(
            "Remove allowRunningInsecureContent and serve all content over a "
            "secure origin.",
            "webPreferences: { allowRunningInsecureContent: false }",
        ),
    },
    "experimentalFeatures": {
        "insecure": True,
        "severity": Severity.MEDIUM,
        "title": "experimentalFeatures enabled",
        "why": "Enables unstable Chromium features that have not been hardened "
               "and expand the renderer attack surface.",
        "fp": None,
        "remediation": Remediation(
            "Disable experimentalFeatures in production builds.",
            "webPreferences: { experimentalFeatures: false }",
        ),
    },
    "enableRemoteModule": {
        "insecure": True,
        "severity": Severity.HIGH,
        "title": "Electron remote module enabled",
        "why": "The remote module lets a renderer drive main-process objects, a "
               "well-known privilege-escalation path; it is removed in modern "
               "Electron for this reason.",
        "fp": None,
        "remediation": Remediation(
            "Remove enableRemoteModule and replace remote calls with explicit, "
            "validated ipcMain handlers.",
            "// drop enableRemoteModule; use ipcMain.handle('op', ...)",
        ),
    },
    "nodeIntegrationInWorker": {
        "insecure": True,
        "severity": Severity.HIGH,
        "title": "nodeIntegrationInWorker enabled",
        "why": "Grants Node access inside web workers, extending the RCE surface "
               "beyond the main renderer thread.",
        "fp": None,
        "remediation": Remediation(
            "Disable nodeIntegrationInWorker.",
            "webPreferences: { nodeIntegrationInWorker: false }",
        ),
    },
    "nodeIntegrationInSubFrames": {
        "insecure": True,
        "severity": Severity.MEDIUM,
        "title": "nodeIntegrationInSubFrames enabled",
        "why": "Extends Node integration to iframes, so a framed third-party page "
               "can reach Node.",
        "fp": None,
        "remediation": Remediation(
            "Disable nodeIntegrationInSubFrames.",
            "webPreferences: { nodeIntegrationInSubFrames: false }",
        ),
    },
}


class ElectronConfigCheck(Check):
    id = "electron_config"
    name = "Electron BrowserWindow / webview configuration"
    category = CATEGORY

    def run(self, ctx: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        for f in ctx.js_files():
            text = ctx.read_text(f)
            if not text:
                continue
            minified = ctx.file_is_minified(f)
            remote_content = self._loads_remote_content(text)
            findings += self._scan_webpreferences(
                ctx, f.relpath, text, minified, remote_content
            )
            if f.relpath.endswith(".html"):
                findings += self._scan_webview_tags(f.relpath, text)
                findings += self._scan_csp(f.relpath, text)
            findings += self._scan_open_external(f.relpath, text, minified)
            findings += self._scan_context_bridge(ctx, f.relpath, text, minified)
        return findings

    # -- webPreferences --------------------------------------------------
    @staticmethod
    def _loads_remote_content(text: str) -> bool:
        return bool(
            re.search(
                r"""load(?:URL|File)\s*\(\s*[`'"]https?://(?!localhost|127\.0\.0\.1|\[?::1)""",
                text,
            )
        )

    def _scan_webpreferences(self, ctx, relpath, text, minified, remote_content):
        findings: list[Finding] = []
        for m in re.finditer(r"webPreferences\s*:", text):
            brace = text.find("{", m.end())
            if brace == -1 or brace - m.end() > 40:
                continue
            start, end = _find_balanced_object(text, brace)
            block = text[start:end]
            block_line = line_of(text, m.start())
            findings += self._eval_block(
                ctx, relpath, text, block, start, block_line, minified,
                remote_content, surface="BrowserWindow",
            )
        return findings

    def _eval_block(self, ctx, relpath, text, block, block_start, block_line,
                    minified, remote_content, surface):
        findings: list[Finding] = []
        node_integration_on = False
        for key, spec in _BOOL_KEYS.items():
            km = re.search(rf"\b{key}\s*:\s*(true|false|!0|!1|0|1)\b", block)
            if not km:
                continue
            value = _norm_bool(km.group(1))
            if value is None or value != spec["insecure"]:
                continue
            if key == "nodeIntegration":
                node_integration_on = True
            abs_idx = block_start + km.start()
            line = line_of(text, abs_idx)
            severity = spec["severity"]
            confidence = Confidence.CONFIRMED
            title = spec["title"]
            why = spec["why"]
            # Escalate nodeIntegration:true to CRITICAL when the same file also
            # loads remote http(s) content — that's the classic RCE path.
            if key == "nodeIntegration" and remote_content:
                severity = Severity.CRITICAL
                title = "nodeIntegration enabled with remote content (RCE path)"
                why = ("nodeIntegration is on AND this file loads remote "
                       "http(s) content, so a malicious or MITM'd page runs "
                       "arbitrary Node code on the user's machine.")
            if minified:
                confidence = _downgrade(confidence)
            findings.append(
                Finding(
                    title=title,
                    severity=severity,
                    confidence=confidence,
                    category=self.category,
                    evidence=snippet_around(text, abs_idx, len(km.group(0))),
                    source_locator=SourceLocator(relpath, line=line, config_key=key),
                    remediation=spec["remediation"],
                    references=[ELECTRON_DOCS],
                    why_it_matters=why,
                    false_positive_note=_minified_note(spec["fp"], minified),
                    discriminator=f"{relpath}:{block_line}:{key}",
                )
            )
        # preload presence is informational context for the window.
        pm = re.search(r"\bpreload\s*:", block)
        if pm:
            abs_idx = block_start + pm.start()
            findings.append(
                Finding(
                    title="Preload script configured for a renderer",
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED if not minified else Confidence.LIKELY,
                    category=self.category,
                    evidence=snippet_around(text, abs_idx, 30),
                    source_locator=SourceLocator(relpath, line=line_of(text, abs_idx),
                                                 config_key="preload"),
                    remediation=Remediation(
                        "Ensure the preload uses contextBridge to expose a minimal, "
                        "explicit API rather than whole modules.",
                    ),
                    references=[ELECTRON_DOCS],
                    why_it_matters="A preload is the right place to bridge IPC — "
                                   "this is context, not a vulnerability by itself.",
                    discriminator=f"{relpath}:{block_line}:preload",
                )
            )
        return findings

    # -- <webview> -------------------------------------------------------
    def _scan_webview_tags(self, relpath, text):
        findings: list[Finding] = []
        for m in re.finditer(r"<webview\b[^>]*>", text, re.IGNORECASE | re.DOTALL):
            tag = m.group(0)
            line = line_of(text, m.start())
            checks = [
                ("nodeintegration", Severity.HIGH,
                 "nodeintegration enabled on a <webview>",
                 "A webview with nodeintegration grants embedded (often remote) "
                 "content Node access — direct RCE if that content is hostile."),
                ("disablewebsecurity", Severity.HIGH,
                 "disablewebsecurity set on a <webview>",
                 "Disables the same-origin policy for embedded content."),
            ]
            for attr, sev, title, why in checks:
                if re.search(rf"\b{attr}\b", tag, re.IGNORECASE):
                    findings.append(
                        Finding(
                            title=title,
                            severity=sev,
                            confidence=Confidence.CONFIRMED,
                            category=self.category,
                            evidence=tag.strip()[:160],
                            source_locator=SourceLocator(relpath, line=line,
                                                         config_key=attr),
                            remediation=Remediation(
                                "Remove the attribute. Prefer not using <webview> at "
                                "all; if required, keep nodeintegration off and "
                                "webSecurity on, and set a strict preload.",
                            ),
                            references=[ELECTRON_DOCS],
                            why_it_matters=why,
                            discriminator=f"{relpath}:{line}:webview:{attr}",
                        )
                    )
            if re.search(r"\ballowpopups\b", tag, re.IGNORECASE):
                findings.append(
                    Finding(
                        title="allowpopups enabled on a <webview>",
                        severity=Severity.LOW,
                        confidence=Confidence.CONFIRMED,
                        category=self.category,
                        evidence=tag.strip()[:160],
                        source_locator=SourceLocator(relpath, line=line,
                                                     config_key="allowpopups"),
                        remediation=Remediation(
                            "Remove allowpopups unless the embedded content "
                            "genuinely needs window.open, and validate any opened "
                            "URLs."),
                        references=[ELECTRON_DOCS],
                        why_it_matters="Lets embedded content spawn new windows, "
                                       "widening the navigation attack surface.",
                        discriminator=f"{relpath}:{line}:webview:allowpopups",
                    )
                )
        return findings

    # -- CSP -------------------------------------------------------------
    def _scan_csp(self, relpath, text):
        findings: list[Finding] = []
        # Only treat documents that actually render markup as renderers.
        if "<html" not in text.lower() and "<head" not in text.lower():
            return findings
        csp_match = re.search(
            r"""<meta[^>]+http-equiv\s*=\s*[`'"]Content-Security-Policy[`'"][^>]*>""",
            text, re.IGNORECASE,
        )
        if not csp_match:
            findings.append(
                Finding(
                    title="No Content-Security-Policy on a renderer document",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LIKELY,
                    category=self.category,
                    evidence="No <meta http-equiv=\"Content-Security-Policy\"> "
                             "found in this document.",
                    source_locator=SourceLocator(relpath, line=1,
                                                 config_key="Content-Security-Policy"),
                    remediation=Remediation(
                        "Add a strict CSP via a <meta> tag or the session's "
                        "onHeadersReceived, disallowing inline/eval script.",
                        "<meta http-equiv=\"Content-Security-Policy\"\n"
                        "  content=\"default-src 'self'; script-src 'self'; "
                        "object-src 'none'\">",
                    ),
                    references=[ELECTRON_DOCS,
                                "https://owasp.org/www-community/controls/Content_Security_Policy"],
                    why_it_matters="A CSP is the primary defence-in-depth against "
                                   "XSS turning into code execution in Electron.",
                    false_positive_note="The CSP may instead be set on HTTP "
                                        "response headers in the main process; if so "
                                        "this is a false positive.",
                    discriminator=f"{relpath}:csp:missing",
                )
            )
            return findings
        tag = csp_match.group(0)
        line = line_of(text, csp_match.start())
        weak_tokens = [t for t in ("unsafe-inline", "unsafe-eval") if t in tag.lower()]
        if "default-src *" in tag.lower() or "default-src 'unsafe" in tag.lower():
            weak_tokens.append("overly-broad default-src")
        if weak_tokens:
            findings.append(
                Finding(
                    title="Weak Content-Security-Policy on a renderer",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LIKELY,
                    category=self.category,
                    evidence=tag.strip()[:200],
                    source_locator=SourceLocator(relpath, line=line,
                                                 config_key="Content-Security-Policy"),
                    remediation=Remediation(
                        "Remove unsafe-inline / unsafe-eval and broad wildcards; "
                        "pin sources explicitly.",
                        "content=\"default-src 'self'; script-src 'self'\"",
                    ),
                    references=[ELECTRON_DOCS],
                    why_it_matters=f"CSP weakened by: {', '.join(weak_tokens)} — "
                                   "this largely defeats the policy's XSS protection.",
                    discriminator=f"{relpath}:{line}:csp:weak",
                )
            )
        return findings

    # -- shell.openExternal ---------------------------------------------
    def _scan_open_external(self, relpath, text, minified):
        findings: list[Finding] = []
        for m in re.finditer(r"(?:shell\.)?openExternal\s*\(\s*([^)]*)", text):
            arg = m.group(1).strip()
            line = line_of(text, m.start())
            # A hardcoded https literal is fine; a variable is the risky case.
            if re.match(r"""[`'"]https?://""", arg):
                continue
            findings.append(
                Finding(
                    title="shell.openExternal called with a non-literal URL",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.POSSIBLE,
                    category=self.category,
                    evidence=snippet_around(text, m.start(), len(m.group(0))),
                    source_locator=SourceLocator(relpath, line=line,
                                                 config_key="shell.openExternal"),
                    remediation=Remediation(
                        "Validate the URL against an allowlist of https/mailto "
                        "schemes before opening it externally.",
                        "if (/^https:\\/\\//.test(url)) shell.openExternal(url)",
                    ),
                    references=[ELECTRON_DOCS],
                    why_it_matters="If an attacker controls the argument, non-http "
                                   "URI schemes (e.g. file:, smb:) can be abused to "
                                   "run local handlers.",
                    false_positive_note="Very commonly a false positive — the URL is "
                                        "often already validated or trusted. Verify "
                                        "the call site before acting.",
                    discriminator=f"{relpath}:{line}:openExternal",
                )
            )
        return findings

    # -- contextBridge over-exposure ------------------------------------
    def _scan_context_bridge(self, ctx, relpath, text, minified):
        findings: list[Finding] = []
        for m in re.finditer(
            r"contextBridge\.exposeInMainWorld\s*\(\s*[^,]+,\s*([A-Za-z_$][\w$]*)",
            text,
        ):
            exposed = m.group(1)
            line = line_of(text, m.start())
            # Exposing the raw ipcRenderer or `require` is the dangerous pattern.
            if exposed in ("ipcRenderer", "require", "process") or \
               re.search(rf"{exposed}\s*[:=]\s*require\(", text):
                findings.append(
                    Finding(
                        title="contextBridge exposes a broad/privileged object",
                        severity=Severity.HIGH,
                        confidence=Confidence.LIKELY if not minified else Confidence.POSSIBLE,
                        category=self.category,
                        evidence=snippet_around(text, m.start(), len(m.group(0))),
                        source_locator=SourceLocator(relpath, line=line,
                                                     config_key="exposeInMainWorld"),
                        remediation=Remediation(
                            "Expose only specific, validated functions — never the "
                            "raw ipcRenderer, require, or process.",
                            "contextBridge.exposeInMainWorld('api', {\n"
                            "  ping: () => ipcRenderer.invoke('ping'),\n"
                            "})",
                        ),
                        references=[ELECTRON_DOCS],
                        why_it_matters="Exposing ipcRenderer/require wholesale lets a "
                                       "compromised renderer call any IPC channel or "
                                       "load Node modules, defeating context isolation.",
                        false_positive_note="If the exposed object is a small, "
                                            "hand-written wrapper this is fine.",
                        discriminator=f"{relpath}:{line}:exposeInMainWorld:{exposed}",
                    )
                )
        return findings


def _downgrade(c: Confidence) -> Confidence:
    return {
        Confidence.CONFIRMED: Confidence.LIKELY,
        Confidence.LIKELY: Confidence.POSSIBLE,
        Confidence.POSSIBLE: Confidence.POSSIBLE,
    }[c]


def _minified_note(base, minified):
    if minified:
        extra = ("Detected in a minified/packed file, so confidence is reduced; "
                 "verify against source if available.")
        return f"{base} {extra}" if base else extra
    return base
