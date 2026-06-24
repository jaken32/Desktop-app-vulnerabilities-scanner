"""Hardcoded-secret scanning: provider regexes + Shannon-entropy fallback.

Findings are always *redacted* in the report (we show a short prefix and a
mask, never the full secret). We filter common placeholders ("YOUR_API_KEY",
"changeme", "xxxx...") and obvious example values to keep the false-positive
rate sane, and we drop the confidence of pure-entropy matches because those
are the noisy ones.
"""

from __future__ import annotations

import math
import re

from ..models import (
    Confidence,
    Finding,
    Remediation,
    Severity,
    SourceLocator,
)
from .base import Check, CheckContext, line_of

CATEGORY = "secrets"

OWASP_SECRETS = "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"


# (name, severity, regex, confidence). Severity CRITICAL only for credentials
# that are usable as-is (private keys, provider live keys).
_PROVIDER_PATTERNS = [
    ("AWS Access Key ID", Severity.CRITICAL,
     re.compile(r"\bAKIA[0-9A-Z]{16}\b"), Confidence.CONFIRMED),
    ("AWS Secret Access Key (contextual)", Severity.CRITICAL,
     re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
     Confidence.LIKELY),
    ("GitHub personal access token", Severity.CRITICAL,
     re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), Confidence.CONFIRMED),
    ("GitHub fine-grained token", Severity.CRITICAL,
     re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"), Confidence.CONFIRMED),
    ("Slack token", Severity.CRITICAL,
     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), Confidence.CONFIRMED),
    ("Google API key", Severity.HIGH,
     re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), Confidence.LIKELY),
    ("Stripe live secret key", Severity.CRITICAL,
     re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), Confidence.CONFIRMED),
    ("Stripe test secret key", Severity.MEDIUM,
     re.compile(r"\bsk_test_[0-9a-zA-Z]{24,}\b"), Confidence.CONFIRMED),
    ("OpenAI API key", Severity.CRITICAL,
     re.compile(r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"), Confidence.CONFIRMED),
    ("Anthropic API key", Severity.CRITICAL,
     re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"), Confidence.CONFIRMED),
    ("Google OAuth client secret", Severity.HIGH,
     re.compile(r"\bGOCSPX-[A-Za-z0-9_\-]{20,}\b"), Confidence.LIKELY),
    ("JSON Web Token", Severity.MEDIUM,
     re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
     Confidence.LIKELY),
    ("Private key block", Severity.CRITICAL,
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
     Confidence.CONFIRMED),
    ("Generic assigned secret", Severity.HIGH,
     re.compile(r"(?i)\b(?:api[_-]?key|secret|passwd|password|access[_-]?token|"
                r"auth[_-]?token|client[_-]?secret)\b['\"]?\s*[:=]\s*"
                r"['\"]([^'\"]{12,120})['\"]"),
     Confidence.POSSIBLE),
]

# Values that look like secrets but are clearly placeholders / examples.
_PLACEHOLDER_RE = re.compile(
    r"(?i)(your[_-]?|example|sample|placeholder|dummy|test[_-]?key|changeme|"
    r"replace[_-]?me|xxxx+|0000+|1234567|abcdef|<.*?>|\{\{.*?\}\}|\$\{.*?\})"
)
# Things that match generic patterns but are not secrets (URLs, hashes of code).
_LOW_VALUE_RE = re.compile(r"(?i)(localhost|127\.0\.0\.1|sha256-|sha512-|integrity)")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _redact(secret: str) -> str:
    secret = secret.strip()
    if len(secret) <= 8:
        return secret[:2] + "…"
    return f"{secret[:4]}…{secret[-2:]} ({len(secret)} chars, redacted)"


def _is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER_RE.search(value)) or bool(_LOW_VALUE_RE.search(value))


# High-entropy token candidates for the entropy fallback.
_TOKEN_RE = re.compile(r"['\"]([A-Za-z0-9+/=_\-]{24,80})['\"]")


class SecretsCheck(Check):
    id = "secrets"
    name = "Hardcoded secrets / credentials"
    category = CATEGORY

    def run(self, ctx: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for f in ctx.bundle.files:
            if not f.relpath.endswith((".js", ".mjs", ".cjs", ".json", ".env",
                                       ".txt", ".html", ".yml", ".yaml", ".pem",
                                       ".key", ".config")):
                continue
            text = ctx.read_text(f)
            if not text:
                continue
            minified = ctx.file_is_minified(f)
            findings += self._provider_scan(ctx, f.relpath, text, minified, seen)
            findings += self._entropy_scan(f.relpath, text, minified, seen)
        return findings

    def _provider_scan(self, ctx, relpath, text, minified, seen):
        out: list[Finding] = []
        for name, severity, pattern, base_conf in _PROVIDER_PATTERNS:
            for m in pattern.finditer(text):
                captured = m.group(len(m.groups())) if m.groups() else m.group(0)
                if _is_placeholder(captured):
                    continue
                line = line_of(text, m.start())
                key = f"{relpath}:{name}:{captured[:8]}:{line}"
                if key in seen:
                    continue
                seen.add(key)
                confidence = base_conf
                if minified and confidence != Confidence.CONFIRMED:
                    confidence = _downgrade(confidence)
                fp_note = None
                if base_conf == Confidence.POSSIBLE:
                    fp_note = ("Generic key/value match — may be a non-sensitive "
                               "config value or already-public identifier; verify "
                               "before treating as a leak.")
                out.append(
                    Finding(
                        title=f"Possible hardcoded {name}",
                        severity=severity,
                        confidence=confidence,
                        category=self.category,
                        evidence=f"{name}: {_redact(captured)}",
                        source_locator=SourceLocator(relpath, line=line),
                        remediation=Remediation(
                            "Remove the secret from the shipped bundle. Load "
                            "credentials at runtime from the OS keychain or a "
                            "user-supplied config, and rotate this value now that "
                            "it has shipped to disk.",
                        ),
                        references=[OWASP_SECRETS],
                        why_it_matters="Anything in the bundle is readable by anyone "
                                       "with the installed app; a usable credential "
                                       "here is effectively public.",
                        false_positive_note=fp_note,
                        discriminator=f"{relpath}:{line}:{name}",
                    )
                )
        return out

    def _entropy_scan(self, relpath, text, minified, seen):
        out: list[Finding] = []
        for m in _TOKEN_RE.finditer(text):
            token = m.group(1)
            if _is_placeholder(token) or _LOW_VALUE_RE.search(token):
                continue
            ent = shannon_entropy(token)
            # Require genuinely high entropy AND a mix of character classes to
            # avoid flagging long hex hashes, base64 asset data, etc.
            if ent < 4.0:
                continue
            classes = sum(bool(re.search(p, token)) for p in
                          (r"[a-z]", r"[A-Z]", r"[0-9]", r"[+/=_\-]"))
            if classes < 3:
                continue
            line = line_of(text, m.start())
            key = f"{relpath}:entropy:{token[:8]}:{line}"
            if key in seen:
                continue
            seen.add(key)
            # Entropy-only matches are the noisy class -> at most POSSIBLE.
            confidence = Confidence.POSSIBLE
            out.append(
                Finding(
                    title="High-entropy string (possible secret)",
                    severity=Severity.MEDIUM,
                    confidence=confidence,
                    category=self.category,
                    evidence=f"entropy={ent:.2f} bits/char: {_redact(token)}",
                    source_locator=SourceLocator(relpath, line=line),
                    remediation=Remediation(
                        "Confirm whether this string is a credential. If so, remove "
                        "and rotate it; if it is an asset hash or public id, ignore."),
                    references=[OWASP_SECRETS],
                    why_it_matters="High-entropy literals are sometimes embedded "
                                   "secrets, but are also often hashes or asset data.",
                    false_positive_note="Entropy-only detection is intentionally "
                                        "low-confidence and frequently a false "
                                        "positive (hashes, minified identifiers, "
                                        "base64 assets).",
                    discriminator=f"{relpath}:{line}:entropy",
                )
            )
        return out


def _downgrade(c: Confidence) -> Confidence:
    return {
        Confidence.CONFIRMED: Confidence.LIKELY,
        Confidence.LIKELY: Confidence.POSSIBLE,
        Confidence.POSSIBLE: Confidence.POSSIBLE,
    }[c]
