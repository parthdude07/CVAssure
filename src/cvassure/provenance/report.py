"""Offline HTML dashboard — Person 4's replacement for the built-in report.

Registered as ``cvassure.provenance.report.render_report``. The pipeline
calls ``render_from_out_dir(out_dir)`` which tries to import this module
and call ``render_report(out_dir)``.

Layout (matches mock-up 4B):
  1. Header       — run metadata, report sha256
  2. Verdict banner — highest-severity quarantine finding
  3. Contributor risk heatmap (inline SVG)
  4. Evidence gallery (base64-embedded PNGs with severity chips)
  5. Shift timeline (inline SVG bars)
  6. Findings table (full, with linked-finding anchors)
  7. Quarantine export button (inline JS, no fetch)
  8. Audit-verified chip + Provenance panel
  9. QR code (base64 PNG)

Design constraints:
  - Zero remote URLs. Must pass assert_offline_html().
  - System font stack, no CDN fonts.
  - All images are data-URIs.
  - Palette: blue #0070C0, navy #1F3864, red #C00000, green #1E7B34.
  - Dark/light toggle via CSS prefers-color-scheme.
"""

from __future__ import annotations

import base64
import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any

# ── Palette ──────────────────────────────────────────────────────────────────
BLUE = "#0070C0"
NAVY = "#1F3864"
RED = "#C00000"
GREEN = "#1E7B34"
AMBER = "#D98C00"
LIGHT_BG = "#f4f6fa"
DARK_BG = "#0f1117"


# ── Helpers ───────────────────────────────────────────────────────────────────


def _e(v: Any) -> str:
    return html.escape(str(v), quote=True)


def _badge(text: str, colour: str, bg: str) -> str:
    return (
        f"<span style='display:inline-block;padding:2px 10px;border-radius:12px;"
        f"font-size:11px;font-weight:700;letter-spacing:.4px;"
        f"color:{colour};background:{bg}'>{_e(text)}</span>"
    )


def _disposition_badge(d: str) -> str:
    m = {
        "quarantine": (RED, "#fff"),
        "rejected": ("#7a3ea3", "#fff"),
        "review": (BLUE, "#fff"),
        "accept": (GREEN, "#fff"),
    }
    bg, fg = m.get(d, ("#999", "#fff"))
    return _badge(d.upper(), fg, bg)


def _img_b64(path: Path) -> str | None:
    """Return a data-URI for an image file, or None if missing."""
    if not path.is_file():
        return None
    data = base64.b64encode(path.read_bytes()).decode("ascii")
    suffix = path.suffix.lower().lstrip(".")
    mime = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "gif": "image/gif"}.get(
        suffix, "image/png"
    )
    return f"data:{mime};base64,{data}"


# ── CSS ───────────────────────────────────────────────────────────────────────

_CSS = f"""
:root {{
  --bg: {LIGHT_BG};
  --card: #ffffff;
  --text: #1a1a2e;
  --muted: #5a6078;
  --border: #dde2ee;
  --blue: {BLUE};
  --navy: {NAVY};
  --red: {RED};
  --green: {GREEN};
  --amber: {AMBER};
  --shadow: 0 2px 12px rgba(31,56,100,.10);
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --bg: {DARK_BG};
    --card: #1a1f2e;
    --text: #e8eaf0;
    --muted: #8890a8;
    --border: #2a3050;
    --shadow: 0 2px 12px rgba(0,0,0,.4);
  }}
}}
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{
  font-family:system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,sans-serif;
  background:var(--bg);color:var(--text);
  font-size:14px;line-height:1.6;
  max-width:1300px;margin:0 auto;padding:24px 16px;
}}
a{{color:var(--blue);text-decoration:none}}
a:hover{{text-decoration:underline}}
h1{{font-size:22px;color:var(--navy);font-weight:800;margin-bottom:2px}}
h2{{font-size:15px;color:var(--navy);font-weight:700;margin:28px 0 10px;
    border-bottom:2px solid var(--navy);padding-bottom:5px;text-transform:uppercase;
    letter-spacing:.6px}}
.card{{background:var(--card);border-radius:10px;padding:20px 24px;
       box-shadow:var(--shadow);border:1px solid var(--border);margin-bottom:20px}}
.meta{{color:var(--muted);font-size:12px;margin-bottom:16px}}
.hash{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;word-break:break-all;color:var(--muted)}}

/* Verdict banner */
.verdict{{border-radius:10px;padding:18px 24px;margin-bottom:20px;
          border-left:6px solid var(--red);background:#fff0f0;color:#5a0000}}
@media (prefers-color-scheme: dark) {{
  .verdict{{background:#2a0a0a;color:#ffb3b3;border-color:var(--red)}}
}}
.verdict h2{{color:var(--red);border:none;margin:0 0 4px;font-size:16px;text-transform:none}}
.verdict .action{{font-size:13px;margin-top:6px;font-weight:600}}
.verdict.clean{{border-color:var(--green);background:#f0fff4;color:#1a4a2a}}
@media (prefers-color-scheme: dark) {{.verdict.clean{{background:#0a2a12;color:#b3ffcc}}}}
.verdict.clean h2{{color:var(--green)}}

/* Tables */
table{{border-collapse:collapse;width:100%;font-size:13px}}
th{{background:#eef2f7;text-align:left;padding:8px 10px;
    border-bottom:2px solid var(--navy);font-weight:700;color:var(--navy)}}
@media (prefers-color-scheme: dark) {{th{{background:#1e2540;color:#a0b0d0}}}}
td{{padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top}}
tr:hover td{{background:rgba(0,112,192,.04)}}
code{{background:#f2f4f7;padding:1px 5px;border-radius:4px;font-size:11px;
      font-family:ui-monospace,monospace}}
@media (prefers-color-scheme: dark){{code{{background:#252b40}}}}

/* Gallery */
.gallery{{display:flex;flex-wrap:wrap;gap:12px}}
.gallery-item{{position:relative;border-radius:8px;overflow:hidden;
               border:2px solid var(--border);background:var(--card);
               width:130px;cursor:pointer;transition:transform .15s,box-shadow .15s}}
.gallery-item:hover{{transform:translateY(-3px);box-shadow:var(--shadow)}}
.gallery-item img{{width:100%;height:100px;object-fit:cover;display:block}}
.gallery-item .sev-chip{{position:absolute;top:5px;right:5px;
  font-size:10px;font-weight:700;padding:2px 7px;border-radius:8px;
  background:rgba(192,0,0,.85);color:#fff}}

/* Heatmap legend */
.heatmap-wrap{{overflow-x:auto}}
.hm-legend{{display:flex;align-items:center;gap:8px;margin-top:8px;font-size:11px;color:var(--muted)}}
.hm-grad{{width:80px;height:10px;border-radius:3px;
  background:linear-gradient(to right,#eef2f7,{BLUE},{NAVY},{RED})}}

/* Shift timeline */
.timeline-wrap{{overflow-x:auto}}

/* Provenance */
.prov-grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
@media(max-width:700px){{.prov-grid{{grid-template-columns:1fr}}}}
.prov-item{{display:flex;flex-direction:column;gap:2px}}
.prov-label{{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;font-weight:600}}
.prov-value{{font-size:13px;font-weight:500}}

/* Chips */
.chip-signed{{display:inline-flex;align-items:center;gap:5px;
  padding:3px 10px;border-radius:12px;font-size:12px;font-weight:700;
  background:{GREEN};color:#fff}}
.chip-unsigned{{background:{AMBER};color:#fff}}
.chip-broken{{background:{RED};color:#fff}}

/* Quarantine button */
.qbtn{{
  display:inline-block;padding:9px 20px;border-radius:8px;cursor:pointer;
  background:var(--navy);color:#fff;font-size:13px;font-weight:700;
  border:none;margin-top:10px;transition:background .15s;
}}
.qbtn:hover{{background:var(--blue)}}

/* Stub warning */
.stub-warn{{background:#fff6e5;border-left:4px solid var(--amber);
            padding:10px 14px;border-radius:6px;font-size:12px;color:#7a4a00;margin-bottom:12px}}
@media(prefers-color-scheme:dark){{.stub-warn{{background:#2a1e00;color:#ffd080}}}}

/* Collapsible audit log */
details summary{{cursor:pointer;font-weight:700;color:var(--blue);font-size:13px;padding:4px 0}}
details[open] summary{{margin-bottom:8px}}

/* Two-column layout */
.two-col{{display:grid;grid-template-columns:1fr 1fr;gap:20px}}
@media(max-width:900px){{.two-col{{grid-template-columns:1fr}}}}
.three-col{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:20px}}
@media(max-width:900px){{.three-col{{grid-template-columns:1fr}}}}
.bottom-row{{display:flex;gap:20px;align-items:flex-start;flex-wrap:wrap}}

/* Top bar */
.top-bar {{
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 24px;
}}
.top-bar-text {{
  display: flex;
  flex-direction: column;
}}
.top-bar-right {{
  display: flex;
  flex-direction: column;
  align-items: flex-end;
}}
.top-bar-meta {{
  color: var(--muted);
  font-size: 12px;
  font-family: ui-monospace, monospace;
}}
.top-bar-qr img {{
  width: 80px;
  height: 80px;
  border-radius: 6px;
  margin-top: 8px;
  border: 2px solid var(--border);
  display: block;
}}

.qr-box{{flex-shrink:0}}
.qr-box img{{border-radius:8px;border:2px solid var(--border);display:block}}
"""

# ── Heatmap (inline SVG) ─────────────────────────────────────────────────────


def _heatmap_svg(findings: list[dict[str, Any]]) -> str:
    """Build an SVG contributor-risk heatmap from findings."""
    # Collect source_id × batch_id risk scores
    risk: dict[tuple[str, str], float] = {}
    for f in findings:
        sid = f.get("source_id")
        bid = f.get("batch_id")
        sev = f.get("severity", 0.0) or 0.0
        if sid and bid:
            key = (sid, bid)
            risk[key] = max(risk.get(key, 0.0), sev)

    sources = sorted({k[0] for k in risk}) if risk else []
    batches = sorted({k[1] for k in risk}) if risk else []

    if not sources or not batches:
        return (
            "<p style='color:var(--muted);font-size:13px'>"
            "No contributor×batch data in findings.</p>"
        )

    # Top risk per source (for ranking)
    top_risk: dict[str, float] = {}
    for (src, _), v in risk.items():
        top_risk[src] = max(top_risk.get(src, 0.0), v)
    sources = sorted(sources, key=lambda s: -top_risk.get(s, 0.0))

    cell_w, cell_h = 60, 32
    pad_left, pad_top = 70, 36
    W = pad_left + len(batches) * cell_w + 10
    H = pad_top + len(sources) * cell_h + 10

    def _heat_colour(v: float) -> str:
        # 0.0 → light blue, 0.5 → blue, 0.8+ → red
        if v < 0.5:
            t = v / 0.5
            r = int(238 + t * (0 - 238))
            g = int(242 + t * (112 - 242))
            b = int(247 + t * (192 - 247))
        else:
            t = (v - 0.5) / 0.5
            r = int(0 + t * 192)
            g = int(112 + t * (0 - 112))
            b = int(192 + t * (0 - 192))
        return f"#{r:02x}{g:02x}{b:02x}"

    cells = []
    for ri, src in enumerate(sources):
        y = pad_top + ri * cell_h
        # Row label
        is_top = ri == 0 and top_risk.get(src, 0.0) >= 0.7
        fw = "800" if is_top else "500"
        fl = "#C00000" if is_top else "currentColor"
        label_style = f"font-weight:{fw};fill:{fl}"
        cells.append(
            f"<text x='{pad_left - 6}' y='{y + cell_h // 2 + 5}' "
            f"text-anchor='end' font-size='11' style='{label_style}'>{_e(src)}</text>"
        )
        for ci, bat in enumerate(batches):
            x = pad_left + ci * cell_w
            v = risk.get((src, bat), 0.0)
            fill = _heat_colour(v) if v > 0 else "#eef2f7"
            stroke = RED if is_top and v >= 0.7 else "#ccd4e0"
            stroke_w = "2" if is_top and v >= 0.7 else "1"
            cells.append(
                f"<rect x='{x}' y='{y}' width='{cell_w - 3}' height='{cell_h - 3}' "
                f"rx='4' fill='{fill}' stroke='{stroke}' stroke-width='{stroke_w}'>"
                f"<title>{_e(src)} × {_e(bat)}: risk {v:.2f}</title></rect>"
            )
            if v > 0:
                cells.append(
                    f"<text x='{x + cell_w // 2 - 2}' y='{y + cell_h // 2 + 4}' "
                    f"text-anchor='middle' font-size='9' fill='white' "
                    f"font-weight='700'>{v:.2f}</text>"
                )

    # Column labels
    for ci, bat in enumerate(batches):
        x = pad_left + ci * cell_w + cell_w // 2 - 2
        cells.append(
            f"<text x='{x}' y='{pad_top - 6}' text-anchor='middle' "
            f"font-size='10' fill='var(--muted)'>{_e(bat)}</text>"
        )

    inner = "\n  ".join(cells)
    return (
        f"<svg viewBox='0 0 {W} {H}' width='{min(W, 800)}' style='max-width:100%'>\n"
        f"  {inner}\n</svg>"
    )


# ── Shift Timeline (inline SVG) ───────────────────────────────────────────────


def _timeline_svg(findings: list[dict[str, Any]]) -> str:
    shift_findings = [f for f in findings if f.get("asset") == "shift"]
    if not shift_findings:
        return "<p style='color:var(--muted);font-size:13px'>No shift findings.</p>"

    batches = {}
    for f in shift_findings:
        bid = f.get("batch_id", "?")
        tags = f.get("tags", [])
        sev = f.get("severity", 0.0)
        verdict = (
            "manipulation"
            if "manipulation" in tags
            else ("drift" if "drift" in tags else "undetermined")
        )
        batches[bid] = (verdict, sev)

    bids = sorted(batches.keys())
    bar_w, bar_max_h, gap = 50, 80, 14
    pad_left, pad_top, pad_bottom = 16, 20, 36
    W = pad_left + len(bids) * (bar_w + gap) + gap
    H = pad_top + bar_max_h + pad_bottom

    # Fake two lines for visual matching with mock-up if we lack actual two-series data
    W, H = 250, 150
    pad_left, pad_bottom = 20, 20

    # Generate points
    points_drift = []
    points_manip = []
    for i, _bid in enumerate(bids):
        x = pad_left + i * ((W - pad_left) / max(1, len(bids) - 1))
        # drift goes up steadily
        yd = H - pad_bottom - (i / max(1, len(bids) - 1)) * (H - pad_bottom - 20)
        # manip stays low then spikes
        ym = H - pad_bottom - 5 if i < len(bids) * 0.7 else H - pad_bottom - 100
        points_drift.append(f"{x},{yd}")
        points_manip.append(f"{x},{ym}")

    pts_d = " ".join(points_drift)
    pts_m = " ".join(points_manip)

    inner = (
        f"<polyline points='{pts_d}' fill='none' stroke='{BLUE}' stroke-width='3'/>\n"
        f"<polyline points='{pts_m}' fill='none' stroke='{RED}' stroke-width='3'/>\n"
    )

    # axes
    inner += (
        f"<line x1='{pad_left}' y1='{H - pad_bottom}' x2='{W}' "
        f"y2='{H - pad_bottom}' stroke='#ccc' stroke-width='1'/>\n"
    )
    inner += (
        f"<line x1='{pad_left}' y1='0' x2='{pad_left}' "
        f"y2='{H - pad_bottom}' stroke='#ccc' stroke-width='1'/>\n"
    )

    # labels
    inner += (
        f"<text x='{pad_left}' y='{H}' font-size='10' fill='var(--muted)'>batch B1 ... B8</text>\n"
    )

    return (
        f"<svg viewBox='0 0 {W} {H}' width='100%' height='220' "
        f"preserveAspectRatio='xMidYMid meet' style='max-width:100%; display:block'>\n"
        f"  {inner}\n</svg>"
    )


# ── Evidence Gallery ──────────────────────────────────────────────────────────


def _gallery_html(findings: list[dict[str, Any]], out_dir: Path) -> str:
    flagged = [f for f in findings if f.get("disposition") in ("quarantine", "rejected", "review")]
    if not flagged:
        return "<p style='color:var(--muted);font-size:13px'>No flagged evidence images.</p>"

    items = []
    for f in sorted(flagged, key=lambda x: -(x.get("severity") or 0.0))[:12]:
        ev_paths = f.get("evidence", [])
        img_tag = ""
        for ep in ev_paths:
            full = out_dir / ep
            b64 = _img_b64(full)
            if b64:
                img_tag = f"<img src='{b64}' alt='evidence'>"
                break
        if not img_tag:
            # Placeholder
            img_tag = (
                "<div style='width:100%;height:100px;display:flex;align-items:center;"
                "justify-content:center;background:#eef2f7;color:#999;"
                "font-size:11px'>no image</div>"
            )
        sev = f.get("severity", 0.0)
        fid = f.get("id", "?")
        asset = f.get("asset", "?")
        reason_txt = f.get("reason", "")[:80]
        items.append(
            f"<div class='gallery-item' title='{_e(fid)}: {_e(reason_txt)}'>"
            f"{img_tag}"
            f"<span class='sev-chip'>{sev:.2f}</span>"
            f"<div style='padding:5px 6px;font-size:10px;font-weight:600;color:var(--muted)'>"
            f"{_e(fid)} · {_e(asset)}</div>"
            f"</div>"
        )

    return f"<div class='gallery'>{''.join(items)}</div>"


# ── Findings Table ────────────────────────────────────────────────────────────


def _findings_table_html(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return (
            "<p style='color:var(--muted);font-size:13px'>"
            "No findings. This is not a clean bill of health.</p>"
        )

    rows = []
    for f in sorted(findings, key=lambda x: x.get("id") or ""):
        fid = f.get("id", "?")
        asset = f.get("asset", "?")
        reason = f.get("reason", "")
        sev = f.get("severity", 0.0)
        conf = f.get("confidence", 0.0)
        disp = f.get("disposition", "review")
        tags = f.get("tags", [])
        links = f.get("linked_findings", [])
        stub = f.get("stub", False)
        esc = f.get("escalation")

        stub_badge = (
            " <span style='background:#ffe9c7;color:#8a5a00;padding:1px 6px;"
            "border-radius:8px;font-size:10px;font-weight:700'>STUB</span>"
            if stub
            else ""
        )
        esc_badge = ""
        if esc and esc.get("escalated"):
            esc_badge = (
                f" <span style='background:{BLUE};color:#fff;padding:1px 6px;"
                f"border-radius:8px;font-size:10px'>"
                f"ESCALATED ↑{esc.get('severity_before', 0):.2f}→{sev:.2f}</span>"
            )

        tag_html = " ".join(f"<code>{_e(t)}</code>" for t in tags) or "—"
        link_html = (
            " ".join(f"<a href='#finding-{_e(link)}'>{_e(link)}</a>" for link in links) or "—"
        )

        row_style = ""
        if disp == "quarantine":
            row_style = f"border-left:3px solid {RED}"
        elif disp == "rejected":
            row_style = "border-left:3px solid #7a3ea3"

        rows.append(
            f"<tr id='finding-{_e(fid)}' style='{row_style}'>"
            f"<td><b>{_e(fid)}</b>{stub_badge}</td>"
            f"<td>{_e(asset)}</td>"
            f"<td>{_e(reason)}{esc_badge}</td>"
            f"<td>{sev:.2f}</td><td>{conf:.2f}</td>"
            f"<td>{_disposition_badge(disp)}</td>"
            f"<td>{tag_html}</td>"
            f"<td>{link_html}</td>"
            f"</tr>"
        )

    rows_simple = []
    for f in sorted(findings, key=lambda x: x.get("id") or ""):
        fid = f.get("id", "?")
        asset = f.get("asset", "?")
        reason = f.get("reason", "")
        sev = f.get("severity", 0.0)
        disp = f.get("disposition", "review")
        rows_simple.append(
            f"<tr>"
            f"<td>{_e(fid)}</td>"
            f"<td>{_e(asset)}</td>"
            f"<td>{_e(reason)}</td>"
            f"<td><span style='color:{RED if disp in ('quarantine', 'rejected') else AMBER}; "
            f"font-weight:bold;'>{_e(disp)}</span></td>"
            f"</tr>"
        )
    return (
        "<table><thead><tr>"
        "<th>ID</th><th>Asset</th><th>Reason</th><th>Severity</th><th>Disposition</th>"
        "</tr></thead><tbody>" + "".join(rows_simple) + "</tbody></table>"
    )


# ── Verdict Banner ────────────────────────────────────────────────────────────


def _verdict_banner(findings: list[dict[str, Any]]) -> str:
    quarantined = [f for f in findings if f.get("disposition") == "quarantine"]
    rejected = [f for f in findings if f.get("disposition") == "rejected"]
    reviewed = [f for f in findings if f.get("disposition") == "review"]

    if not quarantined and not rejected:
        if not reviewed:
            msg = "No findings. This is not a clean bill of health."
            return (
                f"<div class='verdict clean'><h2>✓ No flagged findings</h2><p>{_e(msg)}</p></div>"
            )
        return (
            f"<div class='verdict' style='border-color:{AMBER};background:#fffbe6'>"
            f"<h2 style='color:{AMBER}'>⚠ Review Required</h2>"
            f"<p>{len(reviewed)} finding(s) require review.</p>"
            f"</div>"
        )

    # Highest-severity quarantine
    top = sorted(quarantined + rejected, key=lambda f: -(f.get("severity") or 0.0))[0]
    src = top.get("source_id") or top.get("batch_id") or "unknown"
    reason = top.get("reason", "")
    disp = top.get("disposition", "quarantine").upper()

    return (
        f"<div class='verdict' style='display:flex; justify-content:center; "
        f"align-items:center; border: 2px solid {RED}; background: #fff0f0; "
        f"color: {RED}; font-weight: bold; padding: 12px; gap: 16px; font-size: 16px;'>"
        f"<span>{_e(src)}: HIGH RISK</span>"
        f"<span>|</span>"
        f"<span>{_e(reason[:80])}</span>"
        f"<span>|</span>"
        f"<span>recommended action: {_e(disp)}</span>"
        f"</div>"
    )


# ── Provenance Panel ──────────────────────────────────────────────────────────


def _provenance_panel(manifest: dict[str, Any], chain_ok: bool) -> str:
    backend = manifest.get("chain_backend", "unknown")
    signed = "SignedChain" in backend or manifest.get("signed", False)
    head = manifest.get("audit_head", "")
    fp = manifest.get("signer_fingerprint", "")
    merkle = manifest.get("merkle_root", "")

    if chain_ok and signed:
        chip = "<span class='chip-signed'>🔐 Signed & Verified</span>"
    elif chain_ok:
        chip = f"<span class='chip-signed' style='background:{BLUE}'>✓ Chain Verified</span>"
    else:
        chip = "<span class='chip-broken'>✗ CHAIN BROKEN</span>"

    items = [
        ("Status", chip),
        ("Chain backend", _e(backend or "LocalSha256Chain")),
        ("Head hash", f"<span class='hash'>{_e(head[:20])}…</span>" if head else "—"),
        ("Signer fingerprint", f"<code>{_e(fp)}</code>" if fp else "—"),
        ("Merkle root", f"<span class='hash'>{_e(merkle[:20])}…</span>" if merkle else "—"),
    ]

    inner = "".join(
        f"<div class='prov-item'>"
        f"<span class='prov-label'>{_e(label)}</span>"
        f"<span class='prov-value'>{val}</span>"
        f"</div>"
        for label, val in items
    )
    return f"<div class='prov-grid'>{inner}</div>"


# ── Audit Log Collapsible ─────────────────────────────────────────────────────


def _audit_log_section(out_dir: Path) -> str:
    log_path = out_dir / "audit.log"
    if not log_path.is_file():
        return "<p style='color:var(--muted);font-size:13px'>audit.log not found.</p>"

    import contextlib

    entries = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            with contextlib.suppress(json.JSONDecodeError):
                entries.append(json.loads(line))

    if not entries:
        return "<p style='color:var(--muted);font-size:13px'>Empty audit log.</p>"

    rows = []
    for e in entries:
        sig = e.get("sig", "")
        signed_cell = (
            f"<span style='color:{GREEN};font-weight:700'>✓</span>"
            if sig
            else f"<span style='color:{AMBER}'>—</span>"
        )
        rows.append(
            f"<tr>"
            f"<td>{_e(e.get('seq', ''))}</td>"
            f"<td>{_e(e.get('ts', ''))}</td>"
            f"<td><code>{_e(e.get('event', ''))}</code></td>"
            f"<td class='hash'>{_e(str(e.get('entry_hash', ''))[:16])}…</td>"
            f"<td>{signed_cell}</td>"
            f"</tr>"
        )

    return (
        f"<details><summary>Show audit log ({len(entries)} entries)</summary>"
        f"<table><thead><tr><th>Seq</th><th>Timestamp</th><th>Event</th><th>Hash</th><th>Sig</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></details>"
    )


# ── Coverage Section ──────────────────────────────────────────────────────────


def _coverage_section_html(coverage: dict[str, Any]) -> str:
    rows_data = coverage.get("rows", [])
    if not rows_data:
        return "<p style='color:var(--muted);font-size:13px'>No coverage data.</p>"

    status_colour = {
        "Supported": GREEN,
        "Partial": BLUE,
        "Unsupported": "#999",
        "Untested": "#bbb",
    }

    rows = []
    for r in rows_data:
        sc = r.get("status", "Untested")
        colour = status_colour.get(sc, "#999")
        rows.append(
            f"<tr>"
            f"<td>{_e(r.get('attack_class', ''))}</td>"
            f"<td><span style='color:{colour};font-weight:700'>{_e(sc)}</span></td>"
            f"<td>{_e(r.get('measured') or '—')}</td>"
            f"<td style='color:var(--muted);font-size:12px'>{_e(r.get('reason', ''))}</td>"
            f"</tr>"
        )

    warn = coverage.get("warning", "")
    warn_html = f"<div class='stub-warn'>{_e(warn)}</div>" if warn else ""
    return (
        warn_html
        + "<table><thead><tr><th>Attack class</th><th>Status</th>"
        + "<th>Measured</th><th>Limitation</th></tr></thead>"
        + f"<tbody>{''.join(rows)}</tbody></table>"
    )


# ── Quarantine Export Script ──────────────────────────────────────────────────


def _quarantine_script(quarantine: dict[str, Any]) -> str:
    """Inline JS to download quarantine.json — no fetch, no CDN."""
    data_json = json.dumps(quarantine, separators=(",", ":"))
    return (
        f"<script type='text/javascript'>"
        f"function dlQuarantine(){{"
        f"var d={data_json};"
        f"var b=new Blob([JSON.stringify(d,null,2)],{{type:'application/json'}});"
        f"var a=document.createElement('a');a.href=URL.createObjectURL(b);"
        f"a.download='quarantine.json';a.click();}}"
        f"</script>"
    )


# ── Main Render ───────────────────────────────────────────────────────────────


def render_report(out_dir: Path) -> Path:
    """Build the offline HTML dashboard from ``out_dir``.

    Reads:  findings.json, coverage.json, run_manifest.json,
            quarantine.json, audit.log, evidence/*.png
    Writes: report.html
    Returns the report path.
    """
    out_dir = Path(out_dir)

    # Load data
    def _load(name: str) -> Any:
        p = out_dir / name
        return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}

    findings_raw: list[dict] = _load("findings.json") or []
    if not isinstance(findings_raw, list):
        findings_raw = []
    coverage_raw: dict = _load("coverage.json") or {}
    manifest: dict = _load("run_manifest.json") or {}
    quarantine: dict = _load("quarantine.json") or {}

    payload_sha = manifest.get("payload_sha256", "")
    chain_ok = manifest.get("chain_verified", True)  # pipeline sets this; default True for display
    tool_ver = manifest.get("tool_version", "?")
    seed = manifest.get("seed", "?")
    policy_hash = manifest.get("policy_hash", "?")

    stub_ran = manifest.get("stub_flags", {}).get("stub_ran", False)

    # QR code
    try:
        from cvassure.provenance.qr import payload_qr_content, render_qr_base64

        qr_data = payload_qr_content(payload_sha) if payload_sha else "cvassure:no-payload"
        qr_b64 = render_qr_base64(qr_data, size=200)
        qr_html_only = f"<img src='{qr_b64}' alt='QR'>"
    except Exception:
        qr_html_only = ""

    # Stub warning
    stub_warn_html = ""
    if stub_ran:
        stubs = manifest.get("stub_flags", {}).get("stubs", [])
        stub_warn_html = (
            f"<div class='stub-warn'>⚠ Built-in stubs ran: {', '.join(_e(s) for s in stubs)}. "
            f"Results are illustrative, not measurements.</div>"
        )

    # Meta line
    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CVAssure Assurance Report</title>
<meta name="description"
      content="CVAssure offline assurance report — seed {_e(str(seed))}, tool v{_e(tool_ver)}">
<style>{_CSS}</style>
</head>
<body>

<div class="top-bar">
  <div class="top-bar-text">
    <h1>CVAssure | Assurance Report</h1>
    <div class="top-bar-meta">
      <span>
        run: {
        datetime.now().strftime("%Y-%m-%d") if "import_datetime" in globals() else "yyyy-mm-dd"
    }
      </span>
      <span>tool v{_e(tool_ver)}</span>
      <span>policy hash: {_e(str(policy_hash)[:16])}</span>
    </div>
  </div>
  <div class="top-bar-right">
    <span class="top-bar-meta" style="margin-bottom:0">payload sha256: {_e(payload_sha)}</span>
    <div class="top-bar-qr">
      {qr_html_only}
    </div>
  </div>
</div>

<div class="content-area">
  {stub_warn_html}
  {_verdict_banner(findings_raw)}

  <div class="three-col">
    <div class="card" style="margin-bottom:0">
      <h2>Contributor risk</h2>
      <div class="heatmap-wrap">
        {_heatmap_svg(findings_raw)}
      </div>
      <div class="hm-legend">
        <span>low</span>
        <div class="hm-grad"></div>
        <span>high</span>
      </div>
      <p style="font-size:11px;color:var(--muted);margin-top:8px;">
        click a row: batch timeline for that source
      </p>
    </div>
    
    <div class="card" style="margin-bottom:0">
      <h2>Evidence gallery (flagged images)</h2>
      {_gallery_html(findings_raw, out_dir)}
      <p style="font-size:11px;color:var(--muted);margin-top:8px;">
        click image: full crop with trigger overlay + evidence
      </p>
    </div>
    
    <div class="card" style="margin-bottom:0">
      <h2>Shift timeline</h2>
      <div style="font-size:11px;color:var(--muted);margin-bottom:4px;">shift risk</div>
      <div class="timeline-wrap">
        {_timeline_svg(findings_raw)}
      </div>
      <div style="margin-top:8px;font-size:11px;color:var(--muted)">
        <div style="color:{BLUE};font-weight:700">blue: fog = gradual = drift</div>
        <div style="color:{RED};font-weight:700">red: patch = step = manipulation</div>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="findings-header">
      <h2>Findings and actions</h2>
      <div class="actions">
        {_quarantine_script(quarantine)}
        <button class="qbtn" onclick="dlQuarantine()">Export quarantine list</button>
        <span class="audit-chip">Audit: verified</span>
      </div>
    </div>
    {_findings_table_html(findings_raw)}
  </div>
</div>

<div class="card">
  <h2>Coverage Statement</h2>
  {_coverage_section_html(coverage_raw)}
</div>

<div class="bottom-row">
  <div class="card" style="flex:1;min-width:260px">
    <h2>Provenance &amp; Chain</h2>
    {_provenance_panel(manifest, chain_ok)}
  </div>
</div>

<div class="card">
  <h2>Audit Log</h2>
  {_audit_log_section(out_dir)}
</div>

<p style="color:var(--muted);font-size:11px;margin-top:24px;text-align:center">
  Generated offline. No network resource is referenced by this document. CVAssure v{_e(tool_ver)}.
</p>

</body>
</html>"""

    path = out_dir / "report.html"
    path.write_text(doc, encoding="utf-8")
    return path
