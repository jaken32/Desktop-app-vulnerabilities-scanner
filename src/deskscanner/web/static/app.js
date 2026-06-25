"use strict";
// deskscanner SPA. All app/bundle-derived strings are inserted with
// textContent (never innerHTML), so hostile content cannot inject markup.

const $ = (sel) => document.querySelector(sel);
const SEV_GLYPH = { critical: "✖", high: "▲", medium: "●", low: "○", info: "·" };
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

let lastHtmlReport = null;

function el(tag, opts = {}, ...children) {
  const node = document.createElement(tag);
  if (opts.class) node.className = opts.class;
  if (opts.text != null) node.textContent = opts.text;
  for (const [k, v] of Object.entries(opts.attrs || {})) node.setAttribute(k, v);
  for (const c of children) if (c) node.appendChild(c);
  return node;
}

function setStatus(msg, isError) {
  const s = $("#status");
  s.textContent = msg || "";
  s.classList.toggle("error", !!isError);
}

function showLoading() {
  const main = $("#results");
  main.replaceChildren(
    el("div", { class: "loading" },
      el("span", { class: "spinner", attrs: { "aria-hidden": "true" } }),
      el("span", { text: "Scanning bundle and scoring findings…" }))
  );
}

function showError(message) {
  const main = $("#results");
  main.replaceChildren(
    el("div", { class: "banner error", attrs: { role: "alert" }, text: message })
  );
}

function kv(key, valueNode) {
  const wrap = el("div", { class: "kv" });
  wrap.appendChild(el("span", { class: "k", text: key }));
  wrap.appendChild(valueNode);
  return wrap;
}

function findingNode(f) {
  const details = el("details", { class: "finding", attrs: { "data-sev": f.severity } });
  if (f.severity === "critical" || f.severity === "high") details.open = true;

  const summary = el("summary");
  summary.appendChild(el("span", {
    class: "sevtag", attrs: { "data-sev": f.severity },
    text: `${SEV_GLYPH[f.severity]} ${f.severity.toUpperCase()}`,
  }));
  const titleWrap = el("span");
  titleWrap.appendChild(el("span", { class: "ftitle", text: f.title }));
  titleWrap.appendChild(document.createTextNode(`  ·  ${f.confidence}`));
  const meta = `${f.stable_id} · ${f.category} · ${f.source_locator.rendered}` +
    (f.volatile ? " · live probe" : "");
  titleWrap.appendChild(el("div", { class: "fmeta", text: meta }));
  summary.appendChild(titleWrap);
  details.appendChild(summary);

  const body = el("div", { class: "fbody" });
  body.appendChild(kv("Evidence", el("div", { class: "evidence", text: f.evidence })));
  if (f.why_it_matters) body.appendChild(kv("Why", el("div", { text: f.why_it_matters })));
  if (f.false_positive_note)
    body.appendChild(kv("FP note", el("div", { class: "fpnote", text: f.false_positive_note })));
  body.appendChild(kv("Fix", el("div", { text: f.remediation.summary })));
  if (f.remediation.code)
    body.appendChild(kv("", el("pre", { text: f.remediation.code })));
  if (f.references && f.references.length) {
    const refs = el("div");
    f.references.forEach((r) => {
      const a = el("a", { text: r, attrs: { href: r, rel: "noopener noreferrer" } });
      refs.appendChild(a);
      refs.appendChild(el("br"));
    });
    body.appendChild(kv("Refs", refs));
  }
  details.appendChild(body);
  return details;
}

function summaryCard(data) {
  const card = el("section", { class: "card summary", attrs: { "aria-label": "Summary" } });
  const grade = el("div", {
    class: "grade", attrs: { "data-grade": data.grade, role: "img",
      "aria-label": `Overall grade ${data.grade}, score ${data.score} of 100` },
  });
  grade.appendChild(el("div", { class: "letter", text: data.grade }));
  grade.appendChild(el("div", { class: "score", text: `${data.score}/100` }));
  card.appendChild(grade);

  const metaWrap = el("div", { class: "meta" });
  const dl = el("dl");
  const addRow = (dt, dd) => {
    dl.appendChild(el("dt", { text: dt }));
    dl.appendChild(el("dd", { text: dd }));
  };
  const a = data.app;
  const nativeEngine = data.engine === "flutter" || data.engine === "native";
  addRow("Application", `${a.name}  v${a.version}`);
  addRow("Bundle", a.bundle_path);
  addRow("Engine", `${data.engine}  (${data.engine_reason || ""})`);
  if (!nativeEngine) {
    addRow("Electron", (a.electron_version || "unknown") + (a.electron_eol ? "  [END-OF-LIFE]" : ""));
  }
  const signing = a.code_signed === true ? "code-signed"
    : a.code_signed === false ? (nativeEngine ? "NOT signed" : "no signature artifacts")
    : (nativeEngine ? "not assessed on this host" : "unknown");
  addRow("Signing", signing);
  addRow("Scanned", data.scan_timestamp);
  metaWrap.appendChild(dl);
  metaWrap.appendChild(el("p", { class: "confnote", text: "Overall confidence: " + data.confidence_note }));
  card.appendChild(metaWrap);
  return card;
}

function rollupRow(data) {
  const wrap = el("div", { class: "rollup", attrs: { "aria-label": "Severity rollup" } });
  const counts = {};
  SEV_ORDER.forEach((s) => (counts[s] = 0));
  data.findings.forEach((f) => (counts[f.severity] += 1));
  SEV_ORDER.forEach((s) => {
    const pill = el("div", { class: "pill", attrs: { title: s } });
    const g = el("span", { class: "g", text: SEV_GLYPH[s] });
    g.style.color = `var(--sev-${s})`;
    pill.appendChild(g);
    pill.appendChild(el("span", { text: s[0].toUpperCase() + s.slice(1) }));
    pill.appendChild(el("span", { class: "n", text: String(counts[s]) }));
    wrap.appendChild(pill);
  });
  return wrap;
}

function gradeCard(axis, grade, score, rows, note) {
  const card = el("section", { class: "card summary", attrs: { "aria-label": axis + " summary" } });
  const g = el("div", {
    class: "grade", attrs: { "data-grade": grade, role: "img",
      "aria-label": `${axis} grade ${grade}, score ${score} of 100` },
  });
  g.appendChild(el("div", { class: "axis", text: axis }));
  g.appendChild(el("div", { class: "letter", text: grade }));
  g.appendChild(el("div", { class: "score", text: `${score}/100` }));
  card.appendChild(g);
  const metaWrap = el("div", { class: "meta" });
  const dl = el("dl");
  rows.forEach(([dt, dd]) => {
    dl.appendChild(el("dt", { text: dt }));
    dl.appendChild(el("dd", { text: dd }));
  });
  metaWrap.appendChild(dl);
  if (note) metaWrap.appendChild(el("p", { class: "confnote", text: note }));
  card.appendChild(metaWrap);
  return card;
}

function renderEfficiency(main, eff) {
  const size = eff.size_summary || {};
  const rows = [["Footprint", `${size.total_human || "?"} · ${size.file_count || 0} files`]];
  Object.entries(size.by_type_human || {}).forEach(([k, v]) => rows.push([k, v]));
  main.appendChild(gradeCard("Efficiency", eff.grade, eff.score, rows,
    "Efficiency confidence: " + (eff.note || "")));

  main.appendChild(el("h2", { class: "axis-eff", text: "Efficiency findings" }));
  const scored = (eff.findings || []).filter((f) => f.severity !== "info");
  const info = (eff.findings || []).filter((f) => f.severity === "info");
  if (scored.length === 0) {
    main.appendChild(el("div", { class: "banner empty",
      text: "No significant efficiency issues found." }));
  } else {
    scored.forEach((f) => main.appendChild(findingNode(f)));
  }

  const im = eff.impact_summary;
  if (im) {
    main.appendChild(el("h2", { text: "Impact summary (measured payload size — not runtime speed)" }));
    main.appendChild(el("p", { text: im.headline || "" }));
    if (im.biggest_wins && im.biggest_wins.length) {
      main.appendChild(el("h3", { text: "Biggest wins (per-fix measured savings, ranked)" }));
      const ul = el("ul", { class: "wins" });
      im.biggest_wins.forEach((w) => {
        const li = el("li");
        const desc = `${w.label} (${w.before_human} → ~${w.after_human}) [${w.kind}]` +
          (w.assumption ? ` · ${w.assumption}` : "");
        li.appendChild(el("span", { text: desc }));
        li.appendChild(el("span", { class: "amt", text: `−${w.human}` }));
        ul.appendChild(li);
      });
      main.appendChild(ul);
    }
    const bullets = (title, arr) => {
      if (!arr || !arr.length) return;
      main.appendChild(el("h3", { text: title }));
      const ul = el("ul", { class: "cov" });
      arr.forEach((b) => ul.appendChild(el("li", { text: b })));
      main.appendChild(ul);
    };
    bullets("Measured benefits", im.measured_benefits);
    bullets("Directional benefits (expected, not measured — verify with profiling)",
            im.directional_benefits);
    if (im.disclaimer) main.appendChild(el("p", { class: "confnote", text: im.disclaimer }));
  }

  if (info.length) {
    main.appendChild(el("h2", { text: "Efficiency — informational" }));
    info.forEach((f) => main.appendChild(findingNode(f)));
  }
}

function renderReport(data) {
  const main = $("#results");
  main.replaceChildren();

  const ranSecurity = data.mode === "security" || data.mode === "all";
  if (ranSecurity) {
    main.appendChild(summaryCard(data));
    main.appendChild(rollupRow(data));

    const scored = data.findings.filter((f) => f.severity !== "info");
    const info = data.findings.filter((f) => f.severity === "info");

    main.appendChild(el("h2", { class: "axis-sec", text: "Security findings" }));
    if (scored.length === 0) {
      main.appendChild(el("div", { class: "banner empty",
        text: "No issues above informational level for the checks run. " +
              "A good grade means the inspected config looks sound — not that the app is secure." }));
    } else {
      scored.forEach((f) => main.appendChild(findingNode(f)));
    }
    if (info.length) {
      main.appendChild(el("h2", { text: "Informational / context" }));
      info.forEach((f) => main.appendChild(findingNode(f)));
    }
  }

  if (data.efficiency) renderEfficiency(main, data.efficiency);

  if (data.diff) {
    main.appendChild(el("h2", { text: "Diff vs previous report (static findings only)" }));
    const sum = el("p", { class: "confnote",
      text: `fixed=${data.diff.summary.fixed} · new=${data.diff.summary.new} · unchanged=${data.diff.summary.unchanged}` });
    main.appendChild(sum);
    data.diff.new.forEach((f) =>
      main.appendChild(el("div", { class: "fmeta", text: `NEW   [${f.severity}] ${f.title} (${f.stable_id})` })));
    data.diff.fixed.forEach((f) =>
      main.appendChild(el("div", { class: "fmeta", text: `FIXED [${f.severity}] ${f.title} (${f.stable_id})` })));
  }

  if (data.notes && data.notes.length) {
    main.appendChild(el("h2", { text: "Notes" }));
    const ul = el("ul", { class: "cov" });
    data.notes.forEach((n) => ul.appendChild(el("li", { text: n })));
    main.appendChild(ul);
  }
}

function showProgress(phase, i, total) {
  const main = $("#results");
  let bar = $("#progress");
  if (!bar) {
    main.replaceChildren();
    bar = el("div", { class: "loading", attrs: { id: "progress" } });
    bar.appendChild(el("span", { class: "spinner", attrs: { "aria-hidden": "true" } }));
    bar.appendChild(el("span", { attrs: { id: "progress-text" } }));
    main.appendChild(bar);
  }
  const pct = total ? Math.round((i / total) * 100) : 0;
  $("#progress-text").textContent = `Running ${phase}… (${pct}%)`;
}

function doneStatus(data) {
  const bits = [];
  if (data.mode === "security" || data.mode === "all")
    bits.push(`${data.engine} ${data.grade} (${data.findings.length} findings)`);
  if (data.efficiency)
    bits.push(`efficiency ${data.efficiency.grade} (${data.efficiency.findings.length})`);
  setStatus("Done — " + bits.join(" · ") + ".");
}

function runScan(ev) {
  ev.preventDefault();
  const target = $("#target").value.trim();
  const probe = $("#probe").checked;
  const prospect = $("#prospect") ? $("#prospect").checked : false;
  const consent = $("#consent").checked;
  const modeEl = document.querySelector('input[name="mode"]:checked');
  const mode = modeEl ? modeEl.value : "security";

  if (!consent) { setStatus("Tick the authorization box to continue.", true); return; }
  if (!target) { setStatus("Enter a target path.", true); return; }

  const btn = $("#scan-btn");
  btn.disabled = true;
  setStatus("Scanning…");
  $("#download-btn").hidden = true;
  showLoading();

  // Live progress via Server-Sent Events.
  const qs = new URLSearchParams({
    target, mode, probe: probe ? "1" : "", prospect: prospect ? "1" : "",
    consent: "1",
  });
  let settled = false;
  let es;
  try {
    es = new EventSource("/api/scan/stream?" + qs.toString());
  } catch (err) {
    showError("Could not start the scan stream.");
    setStatus("Failed.", true);
    btn.disabled = false;
    return;
  }
  es.addEventListener("progress", (e) => {
    const d = JSON.parse(e.data);
    showProgress(d.phase, d.i, d.total);
  });
  es.addEventListener("result", (e) => {
    settled = true;
    const data = JSON.parse(e.data);
    lastHtmlReport = data.html || null;
    renderReport(data);
    doneStatus(data);
    $("#download-btn").hidden = !lastHtmlReport;
    es.close();
    btn.disabled = false;
  });
  es.addEventListener("error", (e) => {
    if (settled) return;
    let msg = "Scan failed.";
    try { msg = JSON.parse(e.data).error || msg; } catch (_) {
      msg = "Lost connection to the scanner backend.";
    }
    showError(msg);
    setStatus("Failed.", true);
    es.close();
    btn.disabled = false;
  });
}

function downloadReport() {
  if (!lastHtmlReport) return;
  const blob = new Blob([lastHtmlReport], { type: "text/html" });
  const url = URL.createObjectURL(blob);
  const a = el("a", { attrs: { href: url, download: "deskscanner-report.html" } });
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

document.addEventListener("DOMContentLoaded", () => {
  $("#scan-form").addEventListener("submit", runScan);
  $("#download-btn").addEventListener("click", downloadReport);
});
