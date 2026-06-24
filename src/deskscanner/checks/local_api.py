"""Local API surface — static detection + a SAFE, read-only loopback probe.

Two stages:

1. STATIC (deterministic, from the bundle): find loopback HTTP listeners and
   whether any binds to ``0.0.0.0`` (network-exposed) versus ``127.0.0.1``.

2. PROBE (opt-in, the only active behaviour in the whole tool): connect ONLY to
   ``127.0.0.1`` / ``::1`` on the app's own detected port(s), issue idempotent
   ``GET``/``OPTIONS`` with a short timeout, and inspect headers + CORS. We
   never fuzz, never mutate, never touch a non-loopback host. Probe-derived
   findings are marked ``volatile`` so they are excluded from diffs.
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

CATEGORY = "local_api"
OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}

# Security headers we expect on a local API, with the severity of their absence.
_EXPECTED_HEADERS = [
    ("x-content-type-options", Severity.LOW, "nosniff"),
    ("x-frame-options", Severity.LOW, "DENY"),
    ("content-security-policy", Severity.MEDIUM, "default-src 'none'"),
    ("permissions-policy", Severity.LOW, "interest-cohort=()"),
]


def _is_loopback(host: str) -> bool:
    return host.strip("[]") in _LOOPBACK_HOSTS


class LocalApiCheck(Check):
    id = "local_api"
    name = "Local API surface (loopback)"
    category = CATEGORY

    def run(self, ctx: CheckContext) -> list[Finding]:
        ports, binds_all, locators = self._detect_listeners(ctx)
        findings: list[Finding] = []

        # --- static finding: 0.0.0.0 bind -------------------------------
        for port, loc, ev in binds_all:
            findings.append(Finding(
                title="Local service binds to 0.0.0.0 (all interfaces)",
                severity=Severity.MEDIUM,
                confidence=Confidence.LIKELY,
                category=self.category,
                evidence=ev,
                source_locator=loc,
                remediation=Remediation(
                    "Bind the local helper to 127.0.0.1 so it is not reachable "
                    "from other hosts on the network.",
                    "server.listen(port, '127.0.0.1')"),
                references=[OWASP_HEADERS],
                why_it_matters="Binding to 0.0.0.0 exposes a service meant for the "
                               "local app to the whole network.",
                false_positive_note="The host may be overridden at runtime via "
                                    "config/env; confirm the effective bind address.",
                discriminator=f"local_api:bind0000:{port}",
            ))

        if not ctx.probe_enabled:
            if ports:
                ctx.notes.append(
                    f"Detected candidate local API port(s) {sorted(ports)} but the "
                    "live probe is disabled (pass --probe to enable, loopback-only).")
            return findings

        # --- live probe (volatile) --------------------------------------
        findings += self._probe(ctx, ports)
        return findings

    # -- static detection ------------------------------------------------
    def _detect_listeners(self, ctx: CheckContext):
        ports: set[int] = set()
        binds_all: list = []
        locators: list = []
        for f in ctx.js_files():
            text = ctx.read_text(f)
            if not text:
                continue
            for m in re.finditer(r"\.listen\s*\(\s*([^)]*)", text):
                args = m.group(1)
                pm = re.search(r"\b(\d{2,5})\b", args)
                if pm:
                    ports.add(int(pm.group(1)))
                if re.search(r"""['"]0\.0\.0\.0['"]""", args):
                    line = line_of(text, m.start())
                    port = int(pm.group(1)) if pm else 0
                    binds_all.append((
                        port,
                        SourceLocator(f.relpath, line=line, config_key="listen"),
                        snippet_around(text, m.start(), len(m.group(0))),
                    ))
            for m in re.finditer(
                r"""(?:127\.0\.0\.1|localhost)[:/](\d{2,5})""", text):
                ports.add(int(m.group(1)))
        # Keep ports in a sane range.
        ports = {p for p in ports if 1 <= p <= 65535}
        return ports, binds_all, locators

    # -- live loopback probe ---------------------------------------------
    def _probe(self, ctx: CheckContext, ports: set[int]) -> list[Finding]:
        findings: list[Finding] = []
        try:
            import httpx
        except ImportError:  # pragma: no cover
            ctx.notes.append("httpx not available; skipping local API probe.")
            return findings

        if not ports:
            ctx.notes.append("No local API port detected; nothing to probe.")
            return findings

        any_reachable = False
        with httpx.Client(timeout=ctx.probe_timeout, follow_redirects=False) as client:
            for port in sorted(ports):
                base = f"http://127.0.0.1:{port}"
                if not _is_loopback("127.0.0.1"):  # invariant guard
                    continue
                resp = self._safe_get(client, base + "/")
                if resp is None:
                    continue
                any_reachable = True
                loc = SourceLocator(f"<local-api 127.0.0.1:{port}>")
                findings += self._header_findings(resp, port, loc)
                findings += self._cors_findings(client, base, port, loc)
                findings += self._auth_findings(resp, port, loc)

        if any_reachable:
            ctx.notes.append("Local API probe reached a loopback service "
                             "(read-only GET/OPTIONS).")
        else:
            ctx.notes.append("Local API probe attempted; no loopback service "
                             "responded on detected ports.")
        return findings

    @staticmethod
    def _safe_get(client, url, headers=None):
        try:
            return client.get(url, headers=headers or {})
        except Exception:
            return None

    def _header_findings(self, resp, port, loc) -> list[Finding]:
        out: list[Finding] = []
        headers = {k.lower(): v for k, v in resp.headers.items()}
        for name, severity, recommended in _EXPECTED_HEADERS:
            if name not in headers:
                out.append(Finding(
                    title=f"Local API missing security header: {name}",
                    severity=severity,
                    confidence=Confidence.CONFIRMED,
                    category=self.category,
                    evidence=f"GET / on 127.0.0.1:{port} returned no '{name}' header "
                             f"(status {resp.status_code}).",
                    source_locator=loc,
                    remediation=Remediation(
                        f"Send '{name}: {recommended}' on local API responses.",
                        f"res.setHeader('{name}', '{recommended}')"),
                    references=[OWASP_HEADERS],
                    why_it_matters="Missing response-hardening headers weaken "
                                   "defence-in-depth for the local service.",
                    discriminator=f"local_api:hdr:{port}:{name}",
                    volatile=True,
                ))
        return out

    def _cors_findings(self, client, base, port, loc) -> list[Finding]:
        out: list[Finding] = []
        evil = "http://attacker.example"
        resp = self._safe_get(client, base + "/", headers={"Origin": evil})
        if resp is None:
            return out
        acao = resp.headers.get("access-control-allow-origin")
        acac = resp.headers.get("access-control-allow-credentials", "").lower()
        if acao == "*" or acao == evil:
            reflected = acao == evil
            severity = Severity.HIGH if (reflected and acac == "true") else Severity.MEDIUM
            out.append(Finding(
                title="Local API has permissive/reflected CORS",
                severity=severity,
                confidence=Confidence.CONFIRMED,
                category=self.category,
                evidence=f"Origin '{evil}' -> Access-Control-Allow-Origin: '{acao}'"
                         + (f", Allow-Credentials: {acac}" if acac else ""),
                source_locator=loc,
                remediation=Remediation(
                    "Restrict Access-Control-Allow-Origin to an explicit allowlist; "
                    "never reflect arbitrary origins, especially with credentials."),
                references=["https://owasp.org/www-community/attacks/CSRF",
                            OWASP_HEADERS],
                why_it_matters="A web page the user visits could script the local "
                               "service cross-origin, exfiltrating data or issuing "
                               "privileged actions.",
                discriminator=f"local_api:cors:{port}",
                volatile=True,
            ))
        return out

    def _auth_findings(self, resp, port, loc) -> list[Finding]:
        # Only the root path is probed (idempotent GET). A 200 with a body and no
        # auth challenge is reported at POSSIBLE confidence — it may be a benign
        # health endpoint, hence the false-positive note.
        if resp.status_code != 200:
            return []
        body = resp.text[:400]
        looks_jsonish = body.strip().startswith(("{", "[")) and len(body.strip()) > 2
        if not looks_jsonish:
            return []
        return [Finding(
            title="Local API root returns data without authentication",
            severity=Severity.MEDIUM,
            confidence=Confidence.POSSIBLE,
            category=self.category,
            evidence=f"GET / on 127.0.0.1:{port} -> 200 with a JSON-like body "
                     f"({len(resp.text)} bytes) and no auth challenge.",
            source_locator=loc,
            remediation=Remediation(
                "Require a per-session token for local API requests (Electron apps "
                "commonly pass a nonce to the renderer) and reject unauthenticated "
                "calls."),
            references=[OWASP_HEADERS],
            why_it_matters="Unauthenticated local endpoints can be driven by any "
                           "local process or, combined with CORS issues, a web page.",
            false_positive_note="Frequently a benign health/status endpoint. Verify "
                                "the endpoint actually exposes sensitive data.",
            discriminator=f"local_api:noauth:{port}",
            volatile=True,
        )]
