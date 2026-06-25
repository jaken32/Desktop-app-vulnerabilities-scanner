"""Opt-in loopback service probe — the highest-value native check.

Flutter desktop tools (Pieces included) commonly run a local HTTP service. This
probe — ONLY when the user passes ``--probe`` and affirms authorization —
discovers ports the app is listening on (loopback only) and issues READ-ONLY
``GET`` / ``OPTIONS`` to ``127.0.0.1``. It NEVER issues POST/PUT/DELETE and
NEVER touches a non-loopback address (enforced by :func:`assert_loopback`,
covered by a test).
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Callable, Optional

from ..models import Confidence, Finding, Remediation, Severity, SourceLocator

# getter(url, method) -> (status:int, headers:dict[str,str], body:str)
Getter = Callable[[str, str], tuple]

# Bounded candidate set used only to *test* whether something is listening on
# loopback (a TCP connect is a read-only observation, not a request).
_CANDIDATE_PORTS = [80, 443, 1234, 3000, 3030, 5000, 5025, 8000, 8080, 8081,
                    8443, 8765, 9000, 9090, 9100, 38300, 39300, 39400, 5323]


class LoopbackViolation(Exception):
    """Raised if any non-loopback host is ever targeted by the probe."""


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def assert_loopback(host: str) -> None:
    """Hard gate: refuse anything that is not a loopback address."""
    if not is_loopback(host):
        raise LoopbackViolation(
            f"refusing to probe non-loopback host {host!r}; the probe only ever "
            "contacts 127.0.0.1")


def _listening(port: int, host: str = "127.0.0.1", timeout: float = 0.2) -> bool:
    assert_loopback(host)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def discover_ports(candidates: Optional[list] = None,
                   *, connect: Callable[[int], bool] = _listening) -> list:
    """Return loopback ports that currently accept a TCP connection.

    Pure observation (a connect, no request). ``connect`` is injectable for tests.
    """
    ports = candidates if candidates is not None else _CANDIDATE_PORTS
    return [p for p in ports if connect(p)]


def _default_getter(url: str, method: str, timeout: float = 4.0) -> tuple:
    import urllib.request

    host = re.sub(r"^https?://", "", url).split(":")[0].split("/")[0]
    assert_loopback(host)
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (loopback only)
            body = resp.read(65536).decode("utf-8", errors="replace")
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, body
    except Exception as exc:  # connection refused / non-HTTP / error status
        code = getattr(exc, "code", 0)
        hdrs = {}
        h = getattr(exc, "headers", None)
        if h:
            hdrs = {k.lower(): v for k, v in h.items()}
        return code or 0, hdrs, ""


def probe(ctx, *, ports: Optional[list] = None, getter: Getter = _default_getter,
          discover: Callable[[], list] = None) -> list:
    """Run the loopback probe; return live (volatile) findings."""
    found_ports = ports if ports is not None else (
        discover() if discover else discover_ports())
    out: list = []
    if not found_ports:
        out.append(Finding(
            title="No loopback HTTP service detected",
            severity=Severity.INFO, confidence=Confidence.CONFIRMED,
            category="local-api",
            evidence="No candidate loopback port accepted a TCP connection at scan "
                     "time. (The service may be stopped, or on a port not probed.)",
            source_locator=SourceLocator("<local-api>"),
            remediation=Remediation("No action."),
            why_it_matters="Nothing was listening to assess.",
            discriminator="local-api:none", volatile=True))
        return out

    for port in found_ports:
        base = f"http://127.0.0.1:{port}"
        assert_loopback("127.0.0.1")
        try:
            status, headers, body = getter(base + "/", "GET")
        except LoopbackViolation:
            raise
        except Exception:
            continue
        if status == 0:
            continue
        loc = SourceLocator(f"<local-api>:{port}")

        # Unauthenticated root.
        if status == 200:
            out.append(Finding(
                title=f"Local API responds 200 to unauthenticated GET / (port {port})",
                severity=Severity.MEDIUM, confidence=Confidence.LIKELY,
                category="local-api",
                evidence=f"GET {base}/ returned HTTP 200 with no authentication.",
                source_locator=loc,
                remediation=Remediation(
                    "Require a local auth token / per-origin handshake for the local "
                    "API, even on loopback (other local apps and web pages can reach it)."),
                references=["https://owasp.org/www-community/attacks/CSRF"],
                why_it_matters="Any local process — or a web page via the browser — "
                               "can call an unauthenticated loopback API.",
                discriminator=f"local-api:noauth:{port}", volatile=True))

        # Permissive CORS.
        acao = headers.get("access-control-allow-origin")
        acac = (headers.get("access-control-allow-credentials") or "").lower()
        if acao == "*" or (acao and acac == "true"):
            sev = Severity.HIGH if acac == "true" else Severity.MEDIUM
            out.append(Finding(
                title=f"Permissive CORS on local API (port {port})",
                severity=sev, confidence=Confidence.CONFIRMED,
                category="local-api",
                evidence=f"Access-Control-Allow-Origin: {acao}"
                         + (f"; Access-Control-Allow-Credentials: {acac}" if acac else ""),
                source_locator=loc,
                remediation=Remediation(
                    "Restrict Access-Control-Allow-Origin to a specific trusted "
                    "origin; never combine '*' with credentials."),
                references=["https://developer.mozilla.org/docs/Web/HTTP/CORS"],
                why_it_matters="Permissive CORS lets arbitrary web origins read "
                               "responses from the local API in the user's browser.",
                discriminator=f"local-api:cors:{port}", volatile=True))

        # Missing security headers.
        missing = [h for h in ("x-content-type-options", "x-frame-options")
                   if h not in headers]
        if status == 200 and missing:
            out.append(Finding(
                title=f"Local API missing security headers (port {port})",
                severity=Severity.LOW, confidence=Confidence.LIKELY,
                category="local-api",
                evidence=f"Response is missing: {', '.join(missing)}.",
                source_locator=loc,
                remediation=Remediation(
                    "Add X-Content-Type-Options: nosniff and X-Frame-Options: DENY "
                    "to local API responses."),
                references=[],
                why_it_matters="Missing hardening headers ease content-sniffing and "
                               "framing attacks against any served content.",
                discriminator=f"local-api:headers:{port}", volatile=True))

        # Version / server disclosure.
        server = headers.get("server")
        if server:
            out.append(Finding(
                title=f"Local API discloses server/version banner (port {port})",
                severity=Severity.LOW, confidence=Confidence.LIKELY,
                category="local-api",
                evidence=f"Server: {server}",
                source_locator=loc,
                remediation=Remediation("Suppress or genericise the Server header."),
                references=[],
                why_it_matters="Version banners help an attacker target known issues.",
                discriminator=f"local-api:banner:{port}", volatile=True))
    return out


def prospect(ctx, *, discover: Callable[[], list] = None) -> list:
    """--prospect: passively report which loopback ports are listening. No HTTP."""
    found = discover() if discover else discover_ports()
    return [Finding(
        title=("Loopback ports accepting connections: "
               + (", ".join(str(p) for p in found) if found else "none detected")),
        severity=Severity.INFO, confidence=Confidence.CONFIRMED,
        category="local-api",
        evidence=("A read-only TCP connect found these loopback (127.0.0.1) ports "
                  f"listening: {found}. No HTTP request was sent (prospect mode). "
                  "Use --probe to assess them." if found else
                  "No candidate loopback port accepted a connection."),
        source_locator=SourceLocator("<local-api>"),
        remediation=Remediation("Run with --probe (and the authorization "
                                "affirmation) to assess any listed port."),
        why_it_matters="Shows the local attack surface without sending any request.",
        discriminator="local-api:prospect", volatile=True)]
