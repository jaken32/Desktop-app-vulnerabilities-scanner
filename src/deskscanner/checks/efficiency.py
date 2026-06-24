"""Static efficiency / footprint analyzer — the second analysis mode.

Where the security checks ask "is this app safe?", the efficiency analyzer asks
"is this app *lean*?" — purely from the shipped, static bundle. It measures the
delivered payload and flags structural bloat with concrete, evidence-backed
remediations a developer can act on.

HONESTY CONTRACT (mirrors the project's security discipline):
- Static only. We never run, instrument, or profile the app. We do NOT emit
  runtime speed/FPS/startup-millisecond claims — only measured *size* and
  structural signals. Directional effects (parse time, memory) are labelled as
  such, never as measured numbers.
- No fabrication. "Heavy"/"unused"/"duplicate" claims cite measured evidence
  (file sizes, an import not found in readable code, two resolved versions). On
  a minified/obfuscated bundle, usage analysis is unreliable — such findings
  drop to ``possible`` and say so. We never assert a confident "unused" on code
  we could not read.
- Deterministic. Same bundle -> same findings, grade, and impact numbers.

Severity rubric (efficiency) — documented here and in the README:
  Critical  ships something that severely bloats the app (un-minified prod
            bundle *and* shipped source maps; a 100MB+ avoidable payload).
  High      significant avoidable bloat or a clear startup-cost anti-pattern
            (an oversized single asset, devDependencies packed into prod).
  Medium    a meaningful optimization opportunity (un-minified JS, duplicate
            dependency versions, oversized images, known-heavy libraries).
  Low       minor (top-level synchronous fs in main, many startup scripts,
            duplicated file content, an unpacked distribution).
  Info      advisory / summary context.
"""

from __future__ import annotations

import hashlib
import posixpath
import re
from dataclasses import dataclass, field
from typing import Optional

from ..models import (
    Confidence,
    Finding,
    Remediation,
    Severity,
    SourceLocator,
)
from ..unpack import Bundle, BundleFile
from .base import Check, CheckContext, line_of

CATEGORY = "efficiency"

# --- thresholds (documented, deterministic) -------------------------------- #
MB = 1024 * 1024
TOTAL_HIGH = 200 * MB
TOTAL_MED = 80 * MB
TOTAL_LOW = 30 * MB
HUGE_PAYLOAD = 100 * MB         # the "critical avoidable payload" line
FILE_HIGH = 20 * MB
FILE_MED = 8 * MB
UNMIN_JS_BYTES = 50 * 1024      # a "large" un-minified script worth flagging
IMG_BYTES = 1_500 * 1024        # image worth a second look
IMG_DIM = 4000                  # px on the long edge
DUP_CONTENT_BYTES = 256 * 1024  # identical-content duplication worth flagging

# Estimated reduction factors for the (clearly-labelled) impact projection.
MINIFY_REDUCTION = 0.65         # typical min+gzip-agnostic minify saving on src
IMAGE_REDUCTION = 0.60         # typical recompress/WebP saving on bloated images

# Known-heavy libraries with a lighter, widely-recommended alternative. Only
# ever surfaced when the dependency is actually declared/present — never asserted
# from memory about an app we didn't see.
HEAVY_LIBS = {
    "moment": ("date-fns or dayjs", "~290 KB; modern date libs are a fraction of the size"),
    "lodash": ("lodash-es with tree-shaking, or per-method imports", "the full build ships every method"),
    "jquery": ("native DOM APIs", "rarely needed in a modern Electron renderer"),
    "rxjs": ("only the operators you use (tree-shaken)", "the full import pulls a large operator set"),
    "underscore": ("native array/object methods", "mostly superseded by the standard library"),
    "core-js": ("a targeted browserslist polyfill set", "the full polyfill set is large and often unneeded in Electron"),
}

_CODE_SUFFIXES = (".js", ".mjs", ".cjs")
_TEXT_SUFFIXES = (".js", ".mjs", ".cjs", ".html", ".htm", ".css")
_IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".webp")
_FONT_SUFFIXES = (".woff", ".woff2", ".ttf", ".otf", ".eot")
_MEDIA_SUFFIXES = (".mp4", ".mov", ".webm", ".avi", ".mp3", ".wav", ".flac")


def _human(n: int) -> str:
    if n >= MB:
        return f"{n / MB:.1f} MB"
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} B"


def _kind_of(relpath: str) -> str:
    low = relpath.lower()
    if low.endswith(".map"):
        return "sourcemap"
    if low.endswith(_CODE_SUFFIXES):
        return "js"
    if low.endswith(".css"):
        return "css"
    if low.endswith(_IMAGE_SUFFIXES):
        return "image"
    if low.endswith(_FONT_SUFFIXES):
        return "font"
    if low.endswith(_MEDIA_SUFFIXES):
        return "media"
    if low.endswith((".html", ".htm")):
        return "html"
    if low.endswith(".json"):
        return "json"
    return "other"


def _image_dims(data: bytes) -> Optional[tuple[int, int]]:
    """Best-effort (width, height) from common image headers; None if unknown."""
    try:
        if data[:8] == b"\x89PNG\r\n\x1a\n" and len(data) >= 24:
            w = int.from_bytes(data[16:20], "big")
            h = int.from_bytes(data[20:24], "big")
            return w, h
        if data[:6] in (b"GIF87a", b"GIF89a") and len(data) >= 10:
            w = int.from_bytes(data[6:8], "little")
            h = int.from_bytes(data[8:10], "little")
            return w, h
        if data[:2] == b"\xff\xd8":  # JPEG: walk segments to a SOF marker
            i = 2
            n = len(data)
            while i + 9 < n and data[i] == 0xFF:
                marker = data[i + 1]
                if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
                    h = int.from_bytes(data[i + 5:i + 7], "big")
                    w = int.from_bytes(data[i + 7:i + 9], "big")
                    return w, h
                seg = int.from_bytes(data[i + 2:i + 4], "big")
                if seg <= 0:
                    break
                i += 2 + seg
    except Exception:  # pragma: no cover - defensive; malformed image
        return None
    return None


@dataclass
class _ImpactItem:
    label: str
    bytes_saved: int
    kind: str        # "measured" | "estimate"
    severity: str


@dataclass
class EfficiencyResult:
    findings: list[Finding] = field(default_factory=list)
    size_summary: dict = field(default_factory=dict)
    impact_summary: dict = field(default_factory=dict)


def analyze(ctx: CheckContext) -> EfficiencyResult:
    """Run the full static efficiency analysis over a bundle."""
    bundle = ctx.bundle
    files = bundle.files
    findings: list[Finding] = []
    impact: list[_ImpactItem] = []

    total = sum(f.size for f in files)
    minified_ratio = ctx.app.minified_ratio
    obfuscated = minified_ratio >= 0.6

    size_summary = _size_summary(files, total)

    findings += _check_total_footprint(total, len(files))
    findings += _check_oversized_assets(files, impact)
    findings += _check_source_maps(files, impact)
    findings += _check_unminified(ctx, files, impact)
    findings += _check_combined_unoptimized(files)
    findings += _check_images(ctx, files, impact)
    findings += _check_dependencies(ctx, impact, obfuscated)
    findings += _check_main_process(ctx)
    findings += _check_startup_scripts(ctx)
    findings += _check_duplicate_content(files, impact)
    findings += _check_packaging(bundle)
    findings.append(_obfuscation_note(minified_ratio))

    impact_summary = _impact_summary(total, impact, obfuscated)
    return EfficiencyResult(findings=findings, size_summary=size_summary,
                            impact_summary=impact_summary)


# --------------------------------------------------------------------------- #
# Size summary
# --------------------------------------------------------------------------- #
def _size_summary(files: list[BundleFile], total: int) -> dict:
    by_type: dict[str, int] = {}
    for f in files:
        by_type[_kind_of(f.relpath)] = by_type.get(_kind_of(f.relpath), 0) + f.size
    largest = sorted(files, key=lambda f: (-f.size, f.relpath))[:10]
    return {
        "total_bytes": total,
        "total_human": _human(total),
        "file_count": len(files),
        "by_type": {k: v for k, v in sorted(by_type.items(), key=lambda kv: -kv[1])},
        "by_type_human": {k: _human(v) for k, v in
                          sorted(by_type.items(), key=lambda kv: -kv[1])},
        "largest": [{"path": f.relpath, "bytes": f.size, "human": _human(f.size)}
                    for f in largest],
    }


# --------------------------------------------------------------------------- #
# Individual checks
# --------------------------------------------------------------------------- #
def _check_total_footprint(total: int, count: int) -> list[Finding]:
    if total >= TOTAL_HIGH:
        sev = Severity.HIGH
    elif total >= TOTAL_MED:
        sev = Severity.MEDIUM
    elif total >= TOTAL_LOW:
        sev = Severity.LOW
    else:
        sev = Severity.INFO
    return [Finding(
        title=f"Shipped bundle footprint: {_human(total)} across {count} files",
        severity=sev,
        confidence=Confidence.CONFIRMED,
        category=CATEGORY,
        evidence=f"Total uncompressed payload measured from the bundle file table: "
                 f"{_human(total)} ({total} bytes) in {count} files.",
        source_locator=SourceLocator("<bundle>"),
        remediation=Remediation(
            "Trim the delivered payload: enable production minification + "
            "tree-shaking, exclude source maps and devDependencies from the "
            "packaged app, and compress large media/images. The findings below "
            "itemise the biggest wins."),
        references=["https://www.electronjs.org/docs/latest/tutorial/performance",
                    "https://web.dev/articles/reduce-javascript-payloads-with-tree-shaking"],
        why_it_matters="A larger shipped payload means a bigger download/update "
                       "and more to read from disk at launch (a directional effect, "
                       "not a measured speed number).",
        discriminator="eff:footprint",
    )]


def _check_oversized_assets(files: list[BundleFile], impact: list[_ImpactItem]) -> list[Finding]:
    out: list[Finding] = []
    for f in files:
        if f.size >= FILE_HIGH:
            sev = Severity.HIGH
        elif f.size >= FILE_MED:
            sev = Severity.MEDIUM
        else:
            continue
        kind = _kind_of(f.relpath)
        out.append(Finding(
            title=f"Oversized asset: {f.relpath} ({_human(f.size)})",
            severity=sev,
            confidence=Confidence.CONFIRMED,
            category=CATEGORY,
            evidence=f"Single file {f.relpath} is {_human(f.size)} ({f.size} bytes), "
                     f"kind={kind}.",
            source_locator=SourceLocator(f.relpath),
            remediation=Remediation(_oversized_fix(kind)),
            references=["https://www.electronjs.org/docs/latest/tutorial/performance"],
            why_it_matters="Large single assets dominate the download and the "
                           "on-disk footprint of the app.",
            discriminator=f"eff:oversized:{f.relpath}",
        ))
        if kind in ("image", "media"):
            impact.append(_ImpactItem(
                f"Compress/transcode {f.relpath}",
                int(f.size * IMAGE_REDUCTION), "estimate", sev.value))
    return out


def _oversized_fix(kind: str) -> str:
    if kind == "image":
        return ("Compress this image or convert to a modern format (WebP/AVIF); "
                "ship pre-sized variants instead of one huge source.")
    if kind == "media":
        return ("Avoid packaging large media in the app — stream or download it on "
                "demand, or compress with a modern codec.")
    if kind == "js":
        return ("Minify and code-split this script; lazy-load it with a dynamic "
                "import() instead of shipping it whole.")
    return ("Move this large asset out of the shipped bundle or compress it; "
            "fetch it on demand if it isn't needed at launch.")


def _check_source_maps(files: list[BundleFile], impact: list[_ImpactItem]) -> list[Finding]:
    maps = [f for f in files if f.relpath.lower().endswith(".map")]
    if not maps:
        return []
    total_map = sum(f.size for f in maps)
    sev = Severity.HIGH if total_map >= 8 * MB else Severity.MEDIUM
    sample = ", ".join(f.relpath for f in sorted(maps, key=lambda x: x.relpath)[:5])
    impact.append(_ImpactItem("Exclude source maps from the packaged build",
                              total_map, "measured", sev.value))
    return [Finding(
        title=f"Source maps shipped to production: {len(maps)} file(s), {_human(total_map)}",
        severity=sev,
        confidence=Confidence.CONFIRMED,
        category=CATEGORY,
        evidence=f"{len(maps)} .map file(s) totalling {_human(total_map)} are present "
                 f"in the shipped bundle (e.g. {sample}).",
        source_locator=SourceLocator(sorted(maps, key=lambda x: x.relpath)[0].relpath),
        remediation=Remediation(
            "Exclude source maps from the packaged app. In your bundler set "
            "production devtool to false (webpack) or sourcemap:false (Vite/"
            "Rollup), or strip *.map in the electron-builder/forge files glob.",
            code='// webpack.config.js (production)\nmodule.exports = { devtool: false };\n'
                 '// vite.config.js\nexport default { build: { sourcemap: false } };'),
        references=["https://webpack.js.org/configuration/devtool/",
                    "https://www.electron.build/configuration/contents"],
        why_it_matters="Source maps are a debugging artifact; shipping them bloats "
                       "the payload and exposes your original source.",
        discriminator="eff:sourcemaps",
    )]


def _check_unminified(ctx: CheckContext, files: list[BundleFile],
                      impact: list[_ImpactItem]) -> list[Finding]:
    out: list[Finding] = []
    saved = 0
    flagged = 0
    for f in files:
        if not f.relpath.endswith(_CODE_SUFFIXES):
            continue
        if f.size < UNMIN_JS_BYTES:
            continue
        if "node_modules/" in f.relpath:
            continue  # dependency code; covered by dep/dedup checks
        if ctx.file_is_minified(f):
            continue
        flagged += 1
        saved += int(f.size * MINIFY_REDUCTION)
        out.append(Finding(
            title=f"Un-minified production script: {f.relpath} ({_human(f.size)})",
            severity=Severity.MEDIUM,
            confidence=Confidence.LIKELY,
            category=CATEGORY,
            evidence=f"{f.relpath} is {_human(f.size)} and reads as un-minified "
                     "(long lines/whitespace not collapsed).",
            source_locator=SourceLocator(f.relpath),
            remediation=Remediation(
                "Enable production minification in your bundler (Terser/esbuild). "
                "Estimated ~65% size reduction on this file.",
                code='// vite.config.js\nexport default { build: { minify: "esbuild" } };'),
            references=["https://web.dev/articles/reduce-javascript-payloads-with-tree-shaking"],
            why_it_matters="Un-minified JS increases download size and startup "
                           "parse work (a directional effect, not a measured speedup).",
            false_positive_note="Readable code is what the SECURITY scanner wants; "
                                "this is purely an efficiency trade-off, and minifying "
                                "is the right call for a production build.",
            discriminator=f"eff:unminified:{f.relpath}",
        ))
    if saved:
        impact.append(_ImpactItem(
            f"Minify {flagged} un-minified script(s)", saved, "estimate", "medium"))
    return out


def _check_combined_unoptimized(files: list[BundleFile]) -> list[Finding]:
    """Critical signal: shipping source maps AND a large un-minified bundle =
    the production build was clearly never optimised."""
    has_maps = any(f.relpath.lower().endswith(".map") for f in files)
    big_src = any(f.relpath.endswith(_CODE_SUFFIXES) and f.size >= 5 * MB
                  and "node_modules/" not in f.relpath for f in files)
    if not (has_maps and big_src):
        return []
    return [Finding(
        title="Production build is not optimised (source maps + large raw bundle)",
        severity=Severity.CRITICAL,
        confidence=Confidence.LIKELY,
        category=CATEGORY,
        evidence="The bundle ships source maps alongside a multi-megabyte "
                 "un-minified script — together a strong signal that no production "
                 "optimisation (minify/strip) ran.",
        source_locator=SourceLocator("<bundle>"),
        remediation=Remediation(
            "Run a real production build: enable minification, disable source-map "
            "emission for the packaged app, and tree-shake. See the individual "
            "source-map and un-minified findings for the per-file fixes."),
        references=["https://www.electronjs.org/docs/latest/tutorial/performance"],
        why_it_matters="Shipping a debug-shaped build is the single biggest "
                       "avoidable contributor to app bloat.",
        false_positive_note="If this is intentionally a debug/development package, "
                            "this finding does not apply to your production artifact.",
        discriminator="eff:unoptimized-build",
    )]


def _check_images(ctx: CheckContext, files: list[BundleFile],
                  impact: list[_ImpactItem]) -> list[Finding]:
    out: list[Finding] = []
    for f in files:
        if not f.relpath.lower().endswith(_IMAGE_SUFFIXES):
            continue
        uncompressed = f.relpath.lower().endswith((".bmp", ".tiff"))
        big = f.size >= IMG_BYTES
        if not (big or uncompressed):
            continue
        dims = None
        if f.size <= 8 * MB:  # only read headers for reasonable files
            try:
                dims = _image_dims(f.read_bytes()[:64])
            except Exception:
                dims = None
        huge_dim = bool(dims and max(dims) >= IMG_DIM)
        if not (big or uncompressed or huge_dim):
            continue
        dim_str = f", {dims[0]}x{dims[1]}px" if dims else ""
        out.append(Finding(
            title=f"Bloated image: {f.relpath} ({_human(f.size)}{dim_str})",
            severity=Severity.MEDIUM if big or huge_dim else Severity.LOW,
            confidence=Confidence.LIKELY,
            category=CATEGORY,
            evidence=f"{f.relpath} is {_human(f.size)}{dim_str}"
                     + (" in an uncompressed format" if uncompressed else "") + ".",
            source_locator=SourceLocator(f.relpath),
            remediation=Remediation(
                "Compress and right-size this image: convert to WebP/AVIF, strip "
                "metadata, and export at the dimensions actually displayed.",
                code="# example\ncwebp -q 80 input.png -o output.webp"),
            references=["https://web.dev/articles/serve-images-webp"],
            why_it_matters="Oversized images inflate the package with no visible "
                           "quality benefit at display size.",
            false_positive_note="A genuinely high-resolution asset (e.g. a retina "
                                "splash) may need its size; verify before converting.",
            discriminator=f"eff:image:{f.relpath}",
        ))
        impact.append(_ImpactItem(f"Recompress {f.relpath}",
                                  int(f.size * IMAGE_REDUCTION), "estimate",
                                  "medium" if big or huge_dim else "low"))
    return out


def _gather_imports(ctx: CheckContext, files: list[BundleFile]) -> set[str]:
    """Top-level package names referenced by require()/import across readable JS."""
    names: set[str] = set()
    pat = re.compile(
        r"""(?:require\(\s*|\bfrom\s+|\bimport\(\s*)['"]([^'"./][^'"]*)['"]""")
    for f in files:
        if not f.relpath.endswith(_TEXT_SUFFIXES):
            continue
        if f.size > 2 * MB:
            continue
        try:
            text = ctx.read_text(f)
        except Exception:
            continue
        for m in pat.finditer(text):
            spec = m.group(1)
            # Normalise scoped (@scope/pkg) and sub-path (pkg/x) specifiers.
            if spec.startswith("@"):
                names.add("/".join(spec.split("/")[:2]))
            else:
                names.add(spec.split("/")[0])
    return names


def _check_dependencies(ctx: CheckContext, impact: list[_ImpactItem],
                        obfuscated: bool) -> list[Finding]:
    import json

    pkg = ctx.bundle.get("package.json")
    if not pkg:
        return []
    try:
        data = json.loads(ctx.read_text(pkg))
    except Exception:
        return []
    deps = {str(k): str(v) for k, v in (data.get("dependencies") or {}).items()}
    dev = {str(k): str(v) for k, v in (data.get("devDependencies") or {}).items()}
    pkg_text = ctx.read_text(pkg)
    out: list[Finding] = []

    # node_modules sizes inside the bundle (measured), by top-level package.
    nm_sizes, nm_versions = _node_modules_index(ctx.bundle)

    # (1) Heavy libraries with lighter alternatives.
    for name, (alt, why) in HEAVY_LIBS.items():
        if name not in deps:
            continue
        measured = nm_sizes.get(name)
        size_note = f" (~{_human(measured)} on disk)" if measured else ""
        idx = pkg_text.find(f'"{name}"')
        out.append(Finding(
            title=f"Heavy dependency with a lighter alternative: {name}{size_note}",
            severity=Severity.MEDIUM,
            confidence=Confidence.POSSIBLE,
            category=CATEGORY,
            evidence=f"{name} is declared in dependencies{size_note}. {why}.",
            source_locator=SourceLocator("package.json",
                                         line=line_of(pkg_text, idx) if idx >= 0 else 1,
                                         config_key=name),
            remediation=Remediation(
                f"Consider replacing {name} with {alt} if you only use a subset of "
                "its API. Measure before/after; some apps genuinely need the full "
                "library."),
            references=["https://bundlephobia.com/"],
            why_it_matters="Smaller dependencies mean a smaller bundle and less to "
                           "parse at startup.",
            false_positive_note="This is a judgement call ('possible'): the library "
                                "may be required for your use case. Not asserted as fact.",
            discriminator=f"eff:heavy:{name}",
        ))
        if measured:
            impact.append(_ImpactItem(f"Replace {name} with {alt}",
                                      int(measured * 0.8), "estimate", "medium"))

    # (2) Duplicate / multiple versions of the same package.
    for name, versions in sorted(nm_versions.items()):
        if len(versions) > 1:
            redundant = nm_sizes.get(name, 0)
            out.append(Finding(
                title=f"Duplicate dependency versions: {name} ({', '.join(sorted(versions))})",
                severity=Severity.MEDIUM,
                confidence=Confidence.LIKELY,
                category=CATEGORY,
                evidence=f"{name} is present at {len(versions)} different versions "
                         f"({', '.join(sorted(versions))}) in node_modules"
                         + (f"; ~{_human(redundant)} total on disk" if redundant else "")
                         + ".",
                source_locator=SourceLocator(f"node_modules/{name}"),
                remediation=Remediation(
                    "De-duplicate with `npm dedupe` / a single resolved version, or "
                    "align the version ranges of the packages that depend on it."),
                references=["https://docs.npmjs.com/cli/v10/commands/npm-dedupe"],
                why_it_matters="Multiple copies of the same library ship redundant "
                               "code and enlarge the bundle.",
                discriminator=f"eff:dupe:{name}",
            ))

    # (3) Un-used declared dependencies (import not found in readable code).
    imported = _gather_imports(ctx, ctx.bundle.files)
    for name in sorted(deps):
        if name in imported:
            continue
        # Only flag deps whose code we could actually search.
        conf = Confidence.POSSIBLE if obfuscated else Confidence.LIKELY
        note = ("The bundle is largely minified/obfuscated, so import detection is "
                "unreliable — this is 'possible', not a confident 'unused'."
                if obfuscated else
                "No static import was found, but a dynamic import or runtime "
                "require could still use it — verify before removing.")
        idx = pkg_text.find(f'"{name}"')
        out.append(Finding(
            title=f"Possibly-unused dependency: {name}",
            severity=Severity.LOW,
            confidence=conf,
            category=CATEGORY,
            evidence=f"{name} is declared in dependencies but no static "
                     f"require()/import of it was found in the readable bundle code.",
            source_locator=SourceLocator("package.json",
                                         line=line_of(pkg_text, idx) if idx >= 0 else 1,
                                         config_key=name),
            remediation=Remediation(
                f"Confirm {name} is unused (check for dynamic imports / runtime "
                "requires), then remove it from dependencies to shrink the install."),
            references=["https://github.com/depcheck/depcheck"],
            why_it_matters="Unused dependencies add install weight and supply-area "
                           "for no benefit.",
            false_positive_note=note,
            discriminator=f"eff:unused:{name}",
        ))

    # (4) devDependencies shipped inside the bundle.
    shipped_dev = sorted(d for d in dev if d in nm_sizes)
    if shipped_dev:
        dev_bytes = sum(nm_sizes.get(d, 0) for d in shipped_dev)
        sev = Severity.HIGH if dev_bytes >= 10 * MB else Severity.MEDIUM
        impact.append(_ImpactItem("Prune devDependencies from the packaged app",
                                  dev_bytes, "measured", sev.value))
        out.append(Finding(
            title=f"devDependencies packed into production: {len(shipped_dev)} package(s), {_human(dev_bytes)}",
            severity=sev,
            confidence=Confidence.CONFIRMED,
            category=CATEGORY,
            evidence=f"node_modules in the bundle contains devDependencies "
                     f"({', '.join(shipped_dev[:8])}{'…' if len(shipped_dev) > 8 else ''}) "
                     f"totalling ~{_human(dev_bytes)}.",
            source_locator=SourceLocator("node_modules"),
            remediation=Remediation(
                "Install production deps only when packaging (`npm ci --omit=dev`) "
                "or let electron-builder prune devDependencies; never ship build "
                "tools (typescript, webpack, eslint…) in the app."),
            references=["https://www.electron.build/configuration/contents"],
            why_it_matters="Build-time tooling has no place in the shipped app and "
                           "can be a large fraction of node_modules.",
            discriminator="eff:devdeps",
        ))
    return out


def _node_modules_index(bundle: Bundle):
    """Measure on-disk size and resolved versions per top-level node_modules pkg.

    Sizes are summed from the bundle file table (measured). Versions are read
    from each package's package.json 'version' field when present.
    """
    import json

    sizes: dict[str, int] = {}
    versions: dict[str, set] = {}
    for f in bundle.files:
        if "node_modules/" not in f.relpath:
            continue
        after = f.relpath.split("node_modules/")[-1]
        parts = after.split("/")
        if not parts:
            continue
        name = "/".join(parts[:2]) if parts[0].startswith("@") and len(parts) > 1 else parts[0]
        sizes[name] = sizes.get(name, 0) + f.size
        if f.relpath.endswith(f"node_modules/{name}/package.json"):
            try:
                v = json.loads(f.read_text()).get("version")
                if v:
                    versions.setdefault(name, set()).add(str(v))
            except Exception:
                pass
    return sizes, versions


def _main_entry(ctx: CheckContext) -> Optional[BundleFile]:
    import json

    pkg = ctx.bundle.get("package.json")
    main = "index.js"
    if pkg:
        try:
            main = json.loads(ctx.read_text(pkg)).get("main") or "index.js"
        except Exception:
            pass
    main = posixpath.normpath(main.lstrip("./"))
    return ctx.bundle.get(main) or ctx.bundle.get(main + ".js")


def _check_main_process(ctx: CheckContext) -> list[Finding]:
    main = _main_entry(ctx)
    if main is None or not main.relpath.endswith(_CODE_SUFFIXES):
        return []
    try:
        text = ctx.read_text(main)
    except Exception:
        return []
    out: list[Finding] = []

    sync_pat = re.compile(r"\b(readFileSync|writeFileSync|execSync|spawnSync|"
                          r"readdirSync|existsSync)\b")
    hits = list(sync_pat.finditer(text))
    # Only count top-of-file (module-init) synchronous calls — the ones that
    # block the main process at startup.
    early = [m for m in hits if line_of(text, m.start()) <= 60]
    if early:
        first = early[0]
        out.append(Finding(
            title=f"Synchronous fs/IPC at main-process startup ({len(early)} call(s))",
            severity=Severity.LOW,
            confidence=Confidence.POSSIBLE,
            category=CATEGORY,
            evidence=f"{main.relpath} calls {first.group(1)} near the top of the "
                     f"main process ({len(early)} synchronous call(s) in the first "
                     "60 lines).",
            source_locator=SourceLocator(main.relpath, line=line_of(text, first.start())),
            remediation=Remediation(
                "Defer or make these asynchronous (await fs.promises.*) so the main "
                "process doesn't block while the first window is being created."),
            references=["https://www.electronjs.org/docs/latest/tutorial/performance"],
            why_it_matters="Top-level synchronous fs blocks the main process during "
                           "launch (a directional effect — not a measured delay).",
            false_positive_note="A couple of small synchronous reads at startup are "
                                "often fine; this is advisory ('possible').",
            discriminator="eff:main-sync-fs",
        ))

    windows = len(re.findall(r"new\s+BrowserWindow\s*\(", text))
    if windows >= 3:
        out.append(Finding(
            title=f"Multiple BrowserWindows created ({windows})",
            severity=Severity.INFO,
            confidence=Confidence.POSSIBLE,
            category=CATEGORY,
            evidence=f"{windows} `new BrowserWindow(` sites in {main.relpath}. Each "
                     "window loads its own renderer + framework.",
            source_locator=SourceLocator(main.relpath),
            remediation=Remediation(
                "Reuse a single window where possible, or share a preload and lazy-"
                "load renderer code so each window doesn't re-pay the framework cost."),
            references=["https://www.electronjs.org/docs/latest/tutorial/performance"],
            why_it_matters="Several full renderer windows multiply memory and load "
                           "cost (directional; not measured here).",
            discriminator="eff:multi-window",
        ))
    return out


def _check_startup_scripts(ctx: CheckContext) -> list[Finding]:
    htmls = [f for f in ctx.bundle.files if f.relpath.lower().endswith((".html", ".htm"))
             and "node_modules/" not in f.relpath]
    out: list[Finding] = []
    for f in sorted(htmls, key=lambda x: x.relpath)[:5]:
        try:
            text = ctx.read_text(f)
        except Exception:
            continue
        scripts = re.findall(r"<script\b[^>]*\bsrc=", text, re.IGNORECASE)
        if len(scripts) >= 8:
            out.append(Finding(
                title=f"Many scripts loaded at startup: {f.relpath} ({len(scripts)} <script src>)",
                severity=Severity.LOW,
                confidence=Confidence.LIKELY,
                category=CATEGORY,
                evidence=f"{f.relpath} references {len(scripts)} external scripts; "
                         "all are fetched/parsed before the renderer is interactive.",
                source_locator=SourceLocator(f.relpath),
                remediation=Remediation(
                    "Bundle and code-split: ship one entry chunk and lazy-load the "
                    "rest with dynamic import() after first paint."),
                references=["https://web.dev/articles/reduce-javascript-payloads-with-code-splitting"],
                why_it_matters="Many synchronous startup scripts increase the work "
                               "before the UI is ready (directional, not measured).",
                discriminator=f"eff:startup-scripts:{f.relpath}",
            ))
    return out


def _check_duplicate_content(files: list[BundleFile], impact: list[_ImpactItem]) -> list[Finding]:
    by_hash: dict[str, list[BundleFile]] = {}
    for f in files:
        if f.size < DUP_CONTENT_BYTES or "node_modules/" in f.relpath:
            continue
        try:
            by_hash.setdefault(hashlib.sha256(f.read_bytes()).hexdigest(), []).append(f)
        except Exception:
            continue
    out: list[Finding] = []
    saved = 0
    for digest, group in sorted(by_hash.items()):
        if len(group) < 2:
            continue
        group = sorted(group, key=lambda x: x.relpath)
        redundant = group[0].size * (len(group) - 1)
        saved += redundant
        out.append(Finding(
            title=f"Duplicated file content: {len(group)} identical copies ({_human(group[0].size)} each)",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            category=CATEGORY,
            evidence=f"{len(group)} files share identical content "
                     f"({', '.join(g.relpath for g in group[:4])}"
                     f"{'…' if len(group) > 4 else ''}); ~{_human(redundant)} redundant.",
            source_locator=SourceLocator(group[0].relpath),
            remediation=Remediation(
                "Reference a single shared copy instead of duplicating the asset "
                "across directories."),
            references=[],
            why_it_matters="Identical duplicated files are pure dead weight in the "
                           "package.",
            discriminator=f"eff:dup-content:{digest[:12]}",
        ))
    if saved:
        impact.append(_ImpactItem("De-duplicate identical files", saved, "measured", "low"))
    return out


def _check_packaging(bundle: Bundle) -> list[Finding]:
    if bundle.source_kind != "directory":
        return []
    return [Finding(
        title="App ships unpacked (no app.asar)",
        severity=Severity.LOW,
        confidence=Confidence.LIKELY,
        category=CATEGORY,
        evidence="The application resources are shipped as a loose directory rather "
                 "than packed into an app.asar archive.",
        source_locator=SourceLocator("<bundle>"),
        remediation=Remediation(
            "Package resources into app.asar (the default for electron-builder/"
            "forge). It reduces file-count overhead and slightly speeds module "
            "resolution at launch."),
        references=["https://www.electronjs.org/docs/latest/tutorial/application-packaging"],
        why_it_matters="Thousands of loose files cost more filesystem overhead than "
                       "a single archive (directional, not measured here).",
        false_positive_note="Some apps intentionally stay unpacked (e.g. to patch "
                            "files post-install); this is advisory.",
        discriminator="eff:unpacked",
    )]


def _obfuscation_note(minified_ratio: float) -> Finding:
    if minified_ratio >= 0.6:
        state = (f"largely minified/obfuscated ({minified_ratio:.0%} of JS). "
                 "Dead-code and unused-dependency detection is unreliable here and "
                 "those findings are reported at lower confidence.")
    elif minified_ratio >= 0.25:
        state = (f"partially minified ({minified_ratio:.0%} of JS); some usage "
                 "analysis is less reliable.")
    else:
        state = (f"largely readable ({minified_ratio:.0%} minified); usage analysis "
                 "is reliable.")
    return Finding(
        title="Analysis reliability (minification)",
        severity=Severity.INFO,
        confidence=Confidence.CONFIRMED,
        category=CATEGORY,
        evidence=f"Bundle is {state}",
        source_locator=SourceLocator("<bundle>"),
        remediation=Remediation(
            "No action — this explains the confidence on usage-based findings."),
        references=[],
        why_it_matters="Honest scoping: we never assert a confident 'unused' on code "
                       "we couldn't read.",
        discriminator="eff:reliability",
    )


# --------------------------------------------------------------------------- #
# Impact summary (measured size; directional effects clearly labelled)
# --------------------------------------------------------------------------- #
def _impact_summary(total: int, impact: list[_ImpactItem], obfuscated: bool) -> dict:
    # Deterministic order: biggest measured/estimated saving first.
    items = sorted(impact, key=lambda it: (-it.bytes_saved, it.label))
    saved = sum(it.bytes_saved for it in items)
    saved = min(saved, total)  # never project below zero
    projected = max(0, total - saved)
    pct = round(100.0 * saved / total, 1) if total else 0.0
    return {
        "current_bytes": total,
        "current_human": _human(total),
        "projected_bytes": projected,
        "projected_human": _human(projected),
        "bytes_saved": saved,
        "saved_human": _human(saved),
        "pct_reduction": pct,
        "biggest_wins": [
            {"label": it.label, "bytes_saved": it.bytes_saved,
             "human": _human(it.bytes_saved), "kind": it.kind, "severity": it.severity}
            for it in items
        ],
        "directional": (
            "Likely effect (NOT measured): a smaller startup payload generally "
            "reduces launch and parse time, and fewer top-level synchronous "
            "requires reduce main-process blocking. These are directional "
            "expectations, not measured speedups — confirm with runtime profiling."),
        "disclaimer": (
            "These figures are static size measurements and structural estimates. "
            "Actual runtime speed/smoothness must be confirmed by profiling the "
            "running app; this tool does not measure them."),
    }


class EfficiencyCheck(Check):
    """Adapter so the analyzer can also be driven like any other Check."""

    id = "efficiency"
    name = "Efficiency / footprint analysis (static)"
    category = CATEGORY

    def run(self, ctx: CheckContext) -> list[Finding]:
        return analyze(ctx).findings


__all__ = ["analyze", "EfficiencyResult", "EfficiencyCheck", "CATEGORY"]
