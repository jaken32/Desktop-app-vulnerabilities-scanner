"""Standalone, self-contained HTML report.

All bundle-derived strings (titles, evidence, locators, remediation) are
rendered through Jinja2 with autoescaping ON, so hostile content from the
scanned app cannot inject markup or script into the report. The design system
is hand-written CSS custom properties — a dense audit layout, not a template.

The report renders the security axis, the efficiency axis, or both, depending on
``result.mode`` — each with its own grade card and findings, clearly separated.
"""

from __future__ import annotations

from typing import Optional

from jinja2 import Environment

from ..diff import DiffResult
from ..models import ScanResult, Severity
from . import coverage

_ENV = Environment(autoescape=True, trim_blocks=True, lstrip_blocks=True)

# What static efficiency analysis explicitly does NOT do (honesty section).
_EFF_LIMITS = [
    "No runtime profiling — no CPU, memory, FPS, or startup-time measurement.",
    "No executing, instrumenting, or running the app.",
    "No claims like 'X% faster/smoother'. Only measured payload SIZE and "
    "structural signals are reported; speed effects are directional, not measured.",
    "Usage/dead-code detection is unreliable on minified/obfuscated bundles and "
    "is reported at lower confidence there.",
]

# Colourblind-safe severity hues; always paired with a glyph + text label.
_CSS = """
:root {
  --bg: #0f1115; --surface: #171a21; --surface-2: #1e222b; --border: #2a2f3a;
  --text: #e6e9ef; --muted: #9aa3b2; --accent: #5ea0ef;
  --sev-critical: #ff5c7a; --sev-high: #ff9d57; --sev-medium: #ffd45e;
  --sev-low: #5fd0c5; --sev-info: #9aa3b2;
  --ok: #69d28a;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  --sans: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
  --sp-1: 4px; --sp-2: 8px; --sp-3: 12px; --sp-4: 16px; --sp-5: 24px; --sp-6: 40px;
  --radius: 10px; --shadow: 0 1px 0 rgba(255,255,255,.03), 0 8px 24px rgba(0,0,0,.35);
  --fs-0: 12px; --fs-1: 14px; --fs-2: 16px; --fs-3: 20px; --fs-4: 28px; --fs-5: 44px;
}
@media (prefers-color-scheme: light) {
  :root { --bg:#f6f7f9; --surface:#fff; --surface-2:#f0f2f5; --border:#dfe3ea;
    --text:#1a1d23; --muted:#5b6470; --accent:#1f6feb;
    --sev-critical:#b00020; --sev-high:#c05621; --sev-medium:#8a6d00;
    --sev-low:#0b6e99; --sev-info:#5b6470; --ok:#1a7f37; }
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text); font-family:var(--sans);
  font-size:var(--fs-1); line-height:1.5; }
a { color:var(--accent); }
.wrap { max-width: 980px; margin: 0 auto; padding: var(--sp-5) var(--sp-4) var(--sp-6); }
.masthead { display:flex; align-items:baseline; gap:var(--sp-3); flex-wrap:wrap;
  border-bottom:1px solid var(--border); padding-bottom:var(--sp-3); }
.masthead h1 { font-size:var(--fs-3); margin:0; letter-spacing:-.01em; }
.masthead .sub { color:var(--muted); font-size:var(--fs-0); }
.card { background:var(--surface); border:1px solid var(--border);
  border-radius:var(--radius); box-shadow:var(--shadow); }
.summary { display:grid; grid-template-columns: 200px 1fr; gap:var(--sp-5);
  padding:var(--sp-5); margin-top:var(--sp-5); align-items:center; }
.grade { display:flex; flex-direction:column; align-items:center; justify-content:center;
  border-radius:var(--radius); padding:var(--sp-4); background:var(--surface-2);
  border:1px solid var(--border); }
.grade .letter { font-size:var(--fs-5); font-weight:800; line-height:1;
  font-family:var(--mono); }
.grade .score { color:var(--muted); font-size:var(--fs-1); margin-top:var(--sp-2); }
.grade .axis { color:var(--muted); font-size:var(--fs-0); text-transform:uppercase;
  letter-spacing:.06em; margin-bottom:var(--sp-2); }
.grade[data-grade="A"] .letter { color:var(--ok); }
.grade[data-grade="B"] .letter { color:var(--sev-low); }
.grade[data-grade="C"] .letter,.grade[data-grade="D"] .letter { color:var(--sev-medium); }
.grade[data-grade="F"] .letter { color:var(--sev-critical); }
.meta dl { display:grid; grid-template-columns:auto 1fr; gap:var(--sp-1) var(--sp-4);
  margin:0; }
.meta dt { color:var(--muted); font-size:var(--fs-0); }
.meta dd { margin:0; font-variant-numeric: tabular-nums; }
.badge { display:inline-flex; align-items:center; gap:6px; padding:1px 8px;
  border-radius:999px; font-size:var(--fs-0); border:1px solid var(--border);
  background:var(--surface-2); }
.badge.eol { color:var(--sev-high); border-color:var(--sev-high); }
.confnote { color:var(--muted); font-size:var(--fs-0); margin-top:var(--sp-3); }
.rollup { display:flex; gap:var(--sp-2); flex-wrap:wrap; margin:var(--sp-5) 0 0; }
.pill { display:flex; align-items:center; gap:var(--sp-2); padding:var(--sp-2) var(--sp-3);
  border-radius:var(--radius); border:1px solid var(--border); background:var(--surface);
  font-variant-numeric:tabular-nums; }
.pill .g { font-family:var(--mono); font-weight:700; }
.pill .n { font-weight:700; }
.sizes { display:flex; gap:var(--sp-2); flex-wrap:wrap; margin:var(--sp-3) 0; }
.wins { list-style:none; padding:0; margin:var(--sp-3) 0; }
.wins li { display:flex; justify-content:space-between; gap:var(--sp-3);
  border-bottom:1px solid var(--border); padding:var(--sp-2) 0;
  font-variant-numeric:tabular-nums; }
.wins .amt { font-family:var(--mono); font-weight:700; white-space:nowrap; }
.tag { font-size:var(--fs-0); color:var(--muted); border:1px solid var(--border);
  border-radius:999px; padding:0 6px; margin-left:var(--sp-2); }
.impact { margin:var(--sp-4) 0; }
.impact .headline { font-size:var(--fs-2); }
section.findings { margin-top:var(--sp-5); }
h2 { font-size:var(--fs-2); border-bottom:1px solid var(--border);
  padding-bottom:var(--sp-2); margin:var(--sp-6) 0 var(--sp-4); }
h2.axis-sec { border-bottom:2px solid var(--accent); }
h2.axis-eff { border-bottom:2px solid var(--ok); }
.finding { border:1px solid var(--border); border-left:4px solid var(--border);
  border-radius:var(--radius); background:var(--surface); margin:var(--sp-3) 0;
  padding:var(--sp-4); }
.finding[data-sev="critical"] { border-left-color:var(--sev-critical); }
.finding[data-sev="high"] { border-left-color:var(--sev-high); }
.finding[data-sev="medium"] { border-left-color:var(--sev-medium); }
.finding[data-sev="low"] { border-left-color:var(--sev-low); }
.finding[data-sev="info"] { border-left-color:var(--sev-info); }
.finding > summary { cursor:pointer; list-style:none; display:flex; gap:var(--sp-3);
  align-items:flex-start; }
.finding > summary::-webkit-details-marker { display:none; }
.sevtag { font-family:var(--mono); font-size:var(--fs-0); font-weight:700;
  padding:2px 8px; border-radius:6px; white-space:nowrap; border:1px solid; }
.sevtag[data-sev="critical"] { color:var(--sev-critical); border-color:var(--sev-critical); }
.sevtag[data-sev="high"] { color:var(--sev-high); border-color:var(--sev-high); }
.sevtag[data-sev="medium"] { color:var(--sev-medium); border-color:var(--sev-medium); }
.sevtag[data-sev="low"] { color:var(--sev-low); border-color:var(--sev-low); }
.sevtag[data-sev="info"] { color:var(--sev-info); border-color:var(--sev-info); }
.ftitle { font-weight:600; }
.fmeta { color:var(--muted); font-size:var(--fs-0); font-family:var(--mono);
  margin-top:2px; }
.conf { font-size:var(--fs-0); color:var(--muted); }
.fbody { margin-top:var(--sp-3); display:grid; gap:var(--sp-2); }
.kv { display:grid; grid-template-columns:90px 1fr; gap:var(--sp-3); align-items:start; }
.kv .k { color:var(--muted); font-size:var(--fs-0); text-transform:uppercase;
  letter-spacing:.04em; }
.loc, code, pre { font-family:var(--mono); }
.evidence, pre { background:var(--surface-2); border:1px solid var(--border);
  border-radius:8px; padding:var(--sp-3); overflow-x:auto; font-size:var(--fs-0);
  white-space:pre-wrap; word-break:break-word; }
pre { white-space:pre; }
.fpnote { color:var(--sev-medium); }
.volatile { font-size:var(--fs-0); color:var(--muted); font-style:italic; }
ul.cov { margin:var(--sp-2) 0; padding-left:var(--sp-5); }
ul.cov li { margin:var(--sp-1) 0; }
.disclaimer { color:var(--muted); font-style:italic; margin-top:var(--sp-3); }
.diffrow { font-family:var(--mono); font-size:var(--fs-0); padding:2px 0; }
footer { color:var(--muted); font-size:var(--fs-0); margin-top:var(--sp-6);
  border-top:1px solid var(--border); padding-top:var(--sp-3); }
:focus-visible { outline:2px solid var(--accent); outline-offset:2px; border-radius:4px; }
@media (prefers-reduced-motion: reduce) { * { animation:none!important; transition:none!important; } }
@media (max-width: 640px) { .summary { grid-template-columns:1fr; } .kv { grid-template-columns:1fr; } }
"""

_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>deskscanner report — {{ app.name }}</title>
<style>{{ css }}</style>
</head>
<body>
<a class="badge" href="#findings" style="position:absolute;left:-999px"
   onfocus="this.style.left='8px'">Skip to findings</a>
<div class="wrap">
  <header class="masthead">
    <h1>deskscanner</h1>
    <span class="sub">{{ subtitle }}</span>
  </header>

  {% if ran_security %}
  <section class="card summary" aria-label="Security summary">
    <div class="grade" data-grade="{{ grade }}" role="img"
         aria-label="Security grade {{ grade }}, score {{ score }} out of 100">
      <div class="axis">Security</div>
      <div class="letter">{{ grade }}</div>
      <div class="score">{{ score }}/100</div>
    </div>
    <div class="meta">
      <dl>
        <dt>Application</dt><dd>{{ app.name }} <span class="conf">v{{ app.version }}</span></dd>
        <dt>Bundle</dt><dd class="loc">{{ app.bundle_path }}</dd>
        <dt>Engine</dt><dd>{{ engine }} <span class="conf">{{ engine_reason }}</span></dd>
        {% if not native %}
        <dt>Electron</dt>
        <dd>{{ app.electron_version or "unknown" }}
          {% if app.electron_eol %}<span class="badge eol">▲ end-of-life</span>{% endif %}
        </dd>
        {% if app.electron_eol_note %}<dt></dt><dd class="conf">{{ app.electron_eol_note }}</dd>{% endif %}
        {% endif %}
        <dt>Signing</dt><dd>{{ signing }}</dd>
        <dt>Scanned</dt><dd>{{ timestamp }}</dd>
      </dl>
      <p class="confnote"><strong>Security confidence:</strong> {{ confidence_note }}</p>
    </div>
  </section>

  <div class="rollup" aria-label="Severity rollup">
    {% for sev in severities %}
    <div class="pill" title="{{ sev.label }}">
      <span class="g" style="color:var(--sev-{{ sev.value }})">{{ sev.glyph }}</span>
      <span>{{ sev.label }}</span>
      <span class="n">{{ rollup[sev.value] }}</span>
    </div>
    {% endfor %}
  </div>

  <section class="findings" id="findings">
    <h2 class="axis-sec">Security findings</h2>
    {% if not scored %}
      <p>No issues above informational level for the checks run.</p>
    {% endif %}
    {% for f in scored %}
      {{ render_finding(f) }}
    {% endfor %}
    {% if info %}
    <h2>Informational / context</h2>
    {% for f in info %}
      {{ render_finding(f) }}
    {% endfor %}
    {% endif %}
  </section>

  {% if diff %}
  <section>
    <h2>Diff vs previous report <span class="conf">(static findings only)</span></h2>
    <p class="conf">fixed={{ diff.fixed|length }} · new={{ diff.new|length }} · unchanged={{ diff.unchanged|length }}</p>
    {% for f in diff.new %}
      <div class="diffrow" style="color:var(--sev-{{ f.severity }})">NEW &nbsp; [{{ f.severity }}] {{ f.title }} ({{ f.stable_id }})</div>
    {% endfor %}
    {% for f in diff.fixed %}
      <div class="diffrow" style="color:var(--ok)">FIXED [{{ f.severity }}] {{ f.title }} ({{ f.stable_id }})</div>
    {% endfor %}
  </section>
  {% endif %}

  <section>
    <h2>What the security scan does &amp; doesn't cover</h2>
    <h3 style="font-size:var(--fs-1)">Covers</h3>
    <ul class="cov">{% for c in covers %}<li>{{ c }}</li>{% endfor %}</ul>
    <h3 style="font-size:var(--fs-1)">Does NOT cover</h3>
    <ul class="cov">{% for c in not_covers %}<li>{{ c }}</li>{% endfor %}</ul>
    {% if flutter_visibility %}<p class="disclaimer">{{ flutter_visibility }}</p>{% endif %}
    <p class="disclaimer">{{ disclaimer }}</p>
  </section>
  {% endif %}

  {% if ran_efficiency %}
  <section class="card summary" id="efficiency" aria-label="Efficiency summary">
    <div class="grade" data-grade="{{ eff_grade }}" role="img"
         aria-label="Efficiency grade {{ eff_grade }}, score {{ eff_score }} out of 100">
      <div class="axis">Efficiency</div>
      <div class="letter">{{ eff_grade }}</div>
      <div class="score">{{ eff_score }}/100</div>
    </div>
    <div class="meta">
      <dl>
        <dt>Footprint</dt><dd>{{ size.total_human }} · {{ size.file_count }} files</dd>
        {% for k, v in size.by_type_human.items() %}
        <dt>{{ k }}</dt><dd>{{ v }}</dd>
        {% endfor %}
      </dl>
      <p class="confnote"><strong>Efficiency confidence:</strong> {{ eff_note }}</p>
    </div>
  </section>

  {% if size.largest %}
  <section>
    <h3 style="font-size:var(--fs-1)">Largest files</h3>
    <ul class="wins">
      {% for f in size.largest %}
      <li><span class="loc">{{ f.path }}</span><span class="amt">{{ f.human }}</span></li>
      {% endfor %}
    </ul>
  </section>
  {% endif %}

  <section class="findings">
    <h2 class="axis-eff">Efficiency findings</h2>
    {% if not eff_scored %}
      <p>No significant efficiency issues found.</p>
    {% endif %}
    {% for f in eff_scored %}
      {{ render_finding(f) }}
    {% endfor %}
    {% if eff_info %}
    <h2>Informational / context</h2>
    {% for f in eff_info %}
      {{ render_finding(f) }}
    {% endfor %}
    {% endif %}
  </section>

  {% if impact %}
  <section class="impact card" style="padding:var(--sp-5)">
    <h2>Impact summary <span class="conf">(measured payload size — not runtime speed)</span></h2>
    <p class="headline">{{ impact.headline }}</p>
    {% if impact.biggest_wins %}
    <h3 style="font-size:var(--fs-1)">Biggest wins (per-fix measured savings, ranked)</h3>
    <ul class="wins">
      {% for w in impact.biggest_wins %}
      <li>
        <span>{{ w.label }} <span class="conf">({{ w.before_human }} → ~{{ w.after_human }})</span>
          <span class="tag">{{ w.kind }}</span>
          {% if w.assumption %}<span class="conf"> · {{ w.assumption }}</span>{% endif %}</span>
        <span class="amt">−{{ w.human }}</span>
      </li>
      {% endfor %}
    </ul>
    {% endif %}
    {% if impact.measured_benefits %}
    <h3 style="font-size:var(--fs-1)">Measured benefits</h3>
    <ul class="cov">{% for b in impact.measured_benefits %}<li>{{ b }}</li>{% endfor %}</ul>
    {% endif %}
    {% if impact.directional_benefits %}
    <h3 style="font-size:var(--fs-1)">Directional benefits <span class="conf">(expected, not measured — verify with profiling)</span></h3>
    <ul class="cov">{% for b in impact.directional_benefits %}<li>{{ b }}</li>{% endfor %}</ul>
    {% endif %}
    <p class="disclaimer">{{ impact.directional }}</p>
    <p class="disclaimer">{{ impact.disclaimer }}</p>
  </section>
  {% endif %}

  <section>
    <h2>What static efficiency analysis does NOT cover</h2>
    <ul class="cov">{% for c in eff_limits %}<li>{{ c }}</li>{% endfor %}</ul>
  </section>
  {% endif %}

  {% if notes %}
  <section><h2>Notes</h2><ul class="cov">{% for n in notes %}<li>{{ n }}</li>{% endfor %}</ul></section>
  {% endif %}

  <footer>
    Generated by deskscanner. Severity is shown by glyph + label + colour.
    A good security grade means the inspected configuration looks sound — not that
    the app is secure. Efficiency figures are static size measurements, not runtime speed.
  </footer>
</div>
</body>
</html>"""

_FINDING_MACRO = """
{% macro render_finding(f) %}
<details class="finding" data-sev="{{ f.severity }}" {% if f.severity in ('critical','high') %}open{% endif %}>
  <summary>
    <span class="sevtag" data-sev="{{ f.severity }}">{{ f.glyph }} {{ f.severity|upper }}</span>
    <span>
      <span class="ftitle">{{ f.title }}</span>
      <span class="conf">· {{ f.confidence }}</span>
      <div class="fmeta">{{ f.stable_id }} · {{ f.category }} · {{ f.locator }}{% if f.volatile %} · live probe{% endif %}</div>
    </span>
  </summary>
  <div class="fbody">
    {% if f.volatile %}<div class="volatile">Live probe result — excluded from diffs.</div>{% endif %}
    <div class="kv"><span class="k">Evidence</span><div class="evidence">{{ f.evidence }}</div></div>
    {% if f.why %}<div class="kv"><span class="k">Why</span><div>{{ f.why }}</div></div>{% endif %}
    {% if f.fpnote %}<div class="kv"><span class="k">FP note</span><div class="fpnote">{{ f.fpnote }}</div></div>{% endif %}
    <div class="kv"><span class="k">Fix</span><div>{{ f.fix }}</div></div>
    {% if f.code %}<div class="kv"><span class="k"></span><pre>{{ f.code }}</pre></div>{% endif %}
    {% if f.references %}<div class="kv"><span class="k">Refs</span><div>
      {% for r in f.references %}<a href="{{ r }}" rel="noopener noreferrer">{{ r }}</a><br>{% endfor %}
    </div></div>{% endif %}
  </div>
</details>
{% endmacro %}
"""

_SUBTITLE = {
    "security": "static Electron analysis + safe loopback inspection",
    "efficiency": "static efficiency / footprint analysis — no runtime profiling",
    "all": "security + efficiency — two independent grades",
}


def _finding_view(f) -> dict:
    return {
        "severity": f.severity.value,
        "glyph": f.severity.glyph,
        "confidence": f.confidence.label,
        "title": f.title,
        "stable_id": f.stable_id,
        "category": f.category,
        "locator": f.source_locator.render(),
        "evidence": f.evidence,
        "why": f.why_it_matters,
        "fpnote": f.false_positive_note,
        "fix": f.remediation.summary,
        "code": f.remediation.code,
        "references": list(f.references),
        "volatile": f.volatile,
    }


def render_html(result: ScanResult, *, diff: Optional[DiffResult] = None) -> str:
    macro_tmpl = _ENV.from_string(_FINDING_MACRO)
    render_finding = macro_tmpl.module.render_finding  # type: ignore[attr-defined]

    scored = [_finding_view(f) for f in result.findings if f.severity is not Severity.INFO]
    info = [_finding_view(f) for f in result.findings if f.severity is Severity.INFO]
    eff_scored = [_finding_view(f) for f in result.efficiency_findings
                  if f.severity is not Severity.INFO]
    eff_info = [_finding_view(f) for f in result.efficiency_findings
                if f.severity is Severity.INFO]

    native = result.engine in ("flutter", "native")
    if native:
        signing = {True: "code-signed", False: "NOT signed",
                   None: "not assessed on this host"}[result.app.code_signed]
    else:
        signing = {True: "code-signed (artifacts present)",
                   False: "no signature artifacts found",
                   None: "unknown (not determinable from bundle)"}[result.app.code_signed]

    tmpl = _ENV.from_string(_TEMPLATE)
    tmpl.globals["render_finding"] = render_finding
    _subtitle = ("static native analysis (signing · entitlements · Info.plist · "
                 "storage) + opt-in loopback probe" if native
                 else _SUBTITLE.get(result.mode, "static analysis"))
    return tmpl.render(
        css=_CSS,
        subtitle=_subtitle,
        app=result.app,
        engine=result.engine,
        engine_reason=result.engine_reason,
        native=native,
        ran_security=result.ran_security,
        ran_efficiency=result.ran_efficiency,
        grade=result.grade,
        score=result.score,
        confidence_note=result.confidence_note,
        timestamp=result.scan_timestamp,
        signing=signing,
        severities=list(Severity),
        rollup={s.value: sum(1 for f in result.findings if f.severity is s)
                for s in Severity},
        scored=scored,
        info=info,
        diff=diff.to_dict() if diff else None,
        covers=coverage.COVERS_NATIVE if native else coverage.COVERS,
        not_covers=coverage.DOES_NOT_COVER_NATIVE if native else coverage.DOES_NOT_COVER,
        flutter_visibility=coverage.FLUTTER_VISIBILITY if native else None,
        disclaimer=coverage.DISCLAIMER,
        # efficiency axis
        eff_grade=result.efficiency_grade,
        eff_score=result.efficiency_score,
        eff_note=result.efficiency_note,
        size=result.size_summary or {"total_human": "?", "file_count": 0,
                                     "by_type_human": {}, "largest": []},
        impact=result.impact_summary or None,
        eff_scored=eff_scored,
        eff_info=eff_info,
        eff_limits=_EFF_LIMITS,
        notes=result.notes,
    )
