#!/usr/bin/env python3
"""
tools/surface_report.py. The automated attack-surface monitoring report.

WHAT THIS IS
------------
A deterministic report of what Continuous EAS has discovered for one client,
built straight from the signal files, in two formats:

  - Word (.docx), the editable draft, via python-docx.
  - PDF, the read-only copy, rendered from the same content with WeasyPrint.

    python tools/surface_report.py --slug security-joes

It is NOT a penetration test report. It is a monitoring snapshot: the surface
inventory (subdomains, lookalikes), the automated findings by severity, and the
hosts that need attention. Every number comes from the signals on disk, nothing
is inferred and no language model is involved, so the document is auditable and
cannot invent a finding. A full SJ pentest deliverable stays a human workflow
built from the SJ template, this is the contactless monitoring export.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

DATA = Path(os.environ.get("SURFACESCANNER_DATA", Path.home() / "surfacescanner-data"))

# The curated Word template a Vuln DB early alert is rendered from. The generator
# deep-copies it and fills the {{TOKEN}} placeholders, rather than building a
# plain body from scratch. The template is bundled with the code (tools/templates)
# so generation does not depend on any one machine's layout. Resolution order:
#   1. SURFACESCANNER_ALERT_TEMPLATE (explicit override)
#   2. DATA/templates/early-alert-template.docx (a per-install customised copy)
#   3. the repo-bundled template next to this module (the default)
_BUNDLED_TEMPLATE = Path(__file__).resolve().parent / "templates" / "early-alert-template.docx"
_DATA_TEMPLATE = DATA / "templates" / "early-alert-template.docx"


def _resolve_alert_template() -> Path:
    env = os.environ.get("SURFACESCANNER_ALERT_TEMPLATE")
    if env:
        return Path(env)
    if _DATA_TEMPLATE.is_file():
        return _DATA_TEMPLATE
    return _BUNDLED_TEMPLATE


ALERT_TEMPLATE = _resolve_alert_template()
ENGAGEMENTS = DATA / "engagements"

# Severity palette and labels, matching the console.
SEV = {
    "SEV1": ("Critical", "#C00000", "#ffffff"),
    "SEV2": ("High",     "#EE0000", "#ffffff"),
    "SEV3": ("Medium",   "#ED7D31", "#111820"),
    "SEV4": ("Low",      "#3BBBF8", "#111820"),
    "SEV5": ("Info",     "#607085", "#ffffff"),
}
SEV_ORDER = ["SEV1", "SEV2", "SEV3", "SEV4", "SEV5"]


def _rank(sev: str) -> int:
    return SEV_ORDER.index(sev) if sev in SEV_ORDER else len(SEV_ORDER)


def _pretty(slug: str) -> str:
    return " ".join(w.capitalize() for w in slug.replace("-", " ").split())


# A signal is a leak when its class or source names a breach, credential, or
# paste exposure. The HIBP automation is the breach_lookup module, so a leak is
# treated as corroborated by HIBP when any signal for the same subject comes from
# it. Non-HIBP leak sources are never named in the deliverable (see the reporting
# rule), they appear under the generic "Credential exposure monitoring" label.
_LEAK_HINTS = ("breach", "leak", "credential", "infostealer", "stealer",
               "paste", "password_exposure", "exposed_credential", "combolist")


def _is_leak(cls: str, source: str, title: str) -> bool:
    # Match on the signal class and the producing module only, never the title,
    # so an inventory item that merely mentions "breach" or "pastebin" in its URL
    # (a wayback entry, say) is not mistaken for a credential leak.
    blob = f"{cls} {source}".lower()
    return any(h in blob for h in _LEAK_HINTS)


def _is_hibp(cls: str, source: str, title: str) -> bool:
    blob = f"{cls} {source}".lower()
    return ("hibp" in blob or "have i been pwned" in blob
            or "haveibeenpwned" in blob or cls == "breach_lookup")


def _load_lookalike_candidates(base: Path) -> list[dict]:
    """The full lookalike candidate set, read from the brand_protection export
    (reports/<slug>-lookalike-domains.xlsx, the "All Candidates" sheet). This is
    every permutation dnstwist generated, not only the handful that registered
    and became signals. Merges every such export in the reports directory and
    deduplicates by registrable name. Empty list if no export is present."""
    rdir = base / "reports"
    if not rdir.is_dir():
        return []
    try:
        from openpyxl import load_workbook
    except Exception:
        return []
    seen: dict[str, dict] = {}
    for f in sorted(rdir.glob("*-lookalike-domains.xlsx")):
        try:
            wb = load_workbook(str(f), read_only=True, data_only=True)
        except Exception:
            continue
        ws = None
        for cand in ("All Candidates", "all candidates"):
            if cand in wb.sheetnames:
                ws = wb[cand]
                break
        if ws is None:
            wb.close()
            continue
        rows = ws.iter_rows(min_row=2, values_only=True)
        for r in rows:
            if not r or not r[0]:
                continue
            cand = str(r[0])
            name = str(r[1]) if len(r) > 1 and r[1] else cand
            key = name.lower()
            rec = {"candidate": cand, "name": name,
                   "technique": str(r[2]) if len(r) > 2 and r[2] else "",
                   "status": str(r[3]) if len(r) > 3 and r[3] else "",
                   "sev": str(r[4]) if len(r) > 4 and r[4] else "",
                   "ip": str(r[5]) if len(r) > 5 and r[5] else "",
                   "mail": str(r[6]) if len(r) > 6 and r[6] else ""}
            # Prefer the richer row (a registered one over an unregistered dup).
            if key not in seen or (rec["status"].lower() == "registered"
                                   and seen[key]["status"].lower() != "registered"):
                seen[key] = rec
        wb.close()
    reg_first = {"registered": 0}
    return sorted(seen.values(),
                  key=lambda c: (reg_first.get(c["status"].lower(), 1), c["name"]))


def collect(base: Path) -> dict:
    """Read every signal file once and reduce it to what the report shows:
    severity counts, the subdomain and lookalike inventory, the actionable
    findings (SEV1 to SEV3), the full host inventory with IPs (even hosts that do
    not resolve), and discovered leaks contrasted against the HIBP automation."""
    sdir = base / "signals"
    counts = {s: 0 for s in SEV_ORDER}
    subs: set[str] = set()
    looks: dict[str, str] = {}
    findings: list[dict] = []
    hosts: dict[str, dict] = {}
    leaks: dict[str, dict] = {}
    seen_dedup: set[str] = set()
    last = 0.0
    if sdir.is_dir():
        for f in sdir.glob("*.jsonl"):
            try:
                text = f.read_text(errors="ignore")
            except Exception:
                continue
            try:
                last = max(last, f.stat().st_mtime)
            except Exception:
                pass
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except Exception:
                    continue
                did = d.get("dedup_id") or line
                if did in seen_dedup:
                    continue
                seen_dedup.add(did)
                sev = str(d.get("severity", "")).upper()
                if sev not in SEV_ORDER:
                    sev = "SEV5"
                counts[sev] += 1
                cls = str(d.get("source_class") or "")
                source = str(d.get("source") or "")
                title = str(d.get("title") or "")
                ents = d.get("entities") or []
                doms = [str(x.get("value", "")).lower().rstrip(".")
                        for x in ents if x.get("type") == "domain" and x.get("value")]
                ips = [str(x.get("value", "")) for x in ents
                       if x.get("type") == "ip" and x.get("value")]
                ev = d.get("evidence") or {}
                if cls == "subdomain":
                    subs.update(doms)
                    # Full host inventory, including hosts that do not resolve.
                    rec_ips = [str(x) for x in (ev.get("records") or [])] or ips
                    up = bool(ev.get("resolves")) if "resolves" in ev else bool(rec_ips)
                    for dom in doms:
                        h = hosts.setdefault(dom, {"host": dom, "up": up, "ips": [],
                                                   "takeover": ev.get("takeover")})
                        h["up"] = h["up"] or up
                        for ip in rec_ips:
                            if ip not in h["ips"]:
                                h["ips"].append(ip)
                        if ev.get("takeover") and not h["takeover"]:
                            h["takeover"] = ev.get("takeover")
                elif cls == "lookalike_domain":
                    for dom in doms:
                        if dom not in looks or _rank(sev) < _rank(looks[dom]):
                            looks[dom] = sev
                elif _is_leak(cls, source, title):
                    # Subject of the leak: an email if present, else a domain, else
                    # the title. Contrast each subject against the HIBP automation.
                    emails = [str(x.get("value", "")).lower() for x in ents
                              if x.get("type") == "email" and x.get("value")]
                    subject = (emails[0] if emails else doms[0] if doms else title) or "unknown"
                    hibp = _is_hibp(cls, source, title)
                    lk = leaks.setdefault(subject, {"subject": subject, "sev": sev,
                                                    "hibp": False, "other": False,
                                                    "title": title})
                    if _rank(sev) < _rank(lk["sev"]):
                        lk["sev"] = sev
                    if hibp:
                        lk["hibp"] = True
                    else:
                        lk["other"] = True
                elif _rank(sev) <= 2:
                    findings.append({"title": title or cls or "Finding",
                                     "sev": sev, "host": doms[0] if doms else ""})
    findings.sort(key=lambda x: (_rank(x["sev"]), x["host"]))
    host_list = sorted(hosts.values(), key=lambda h: (not h["up"], h["host"]))
    leak_list = sorted(leaks.values(), key=lambda l: (_rank(l["sev"]), l["subject"]))
    total = sum(counts.values())
    return {"counts": counts, "total": total, "subs": sorted(subs),
            "looks": sorted(looks.items(), key=lambda kv: (_rank(kv[1]), kv[0])),
            "look_candidates": _load_lookalike_candidates(base),
            "findings": findings, "hosts": host_list, "leaks": leak_list,
            "last": last}


# --------------------------------------------------------------------------
# HTML for the PDF (WeasyPrint renders this).
# --------------------------------------------------------------------------
def _esc(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def build_html(name: str, data: dict, when: str) -> str:
    c = data["counts"]
    sev_rows = "".join(
        f'<tr><td><span class="sev" style="background:{SEV[s][1]};color:{SEV[s][2]}">'
        f'{SEV[s][0]}</span></td><td class="num">{c[s]}</td></tr>'
        for s in SEV_ORDER)
    attn = [f for f in data["findings"] if f["sev"] in ("SEV1", "SEV2")]

    def find_rows(items):
        if not items:
            return '<tr><td colspan="3" class="muted">None.</td></tr>'
        return "".join(
            f'<tr><td><span class="sev" style="background:{SEV[f["sev"]][1]};'
            f'color:{SEV[f["sev"]][2]}">{SEV[f["sev"]][0]}</span></td>'
            f'<td>{_esc(f["title"])}</td><td class="mono">{_esc(f["host"]) or "-"}</td></tr>'
            for f in items)

    subs_html = ("<br>".join(_esc(s) for s in data["subs"])
                 if data["subs"] else '<span class="muted">None discovered.</span>')
    looks_html = ("".join(
        f'<tr><td class="mono">{_esc(dom)}</td><td><span class="sev" '
        f'style="background:{SEV[sev][1]};color:{SEV[sev][2]}">{SEV[sev][0]}</span></td></tr>'
        for dom, sev in data["looks"]) if data["looks"]
        else '<tr><td colspan="2" class="muted">None discovered.</td></tr>')

    return f"""<!doctype html><html><head><meta charset="utf-8"><style>
@page {{ size: A4; margin: 20mm 18mm; @bottom-center {{ content: "{_esc(name)} · External Attack Surface Assessment · page " counter(page); font-size:9px; color:#888; }} }}
body {{ font-family: 'Helvetica Neue', Arial, sans-serif; color:#1a1f26; font-size:11px; line-height:1.5; }}
h1 {{ font-size:26px; margin:0 0 4px; }}
h2 {{ font-size:15px; margin:26px 0 8px; border-bottom:2px solid #e3e7ec; padding-bottom:4px; }}
.cover {{ page-break-after: always; padding-top:120px; text-align:center; }}
.cover .sub {{ font-size:15px; color:#555; margin-top:6px; }}
.cover .note {{ margin-top:28px; font-size:11px; color:#777; }}
table {{ border-collapse:collapse; width:100%; margin:6px 0; }}
td, th {{ border:1px solid #d9dee4; padding:5px 8px; text-align:left; vertical-align:top; }}
th {{ background:#f2f4f7; }}
td.num {{ text-align:right; width:70px; font-weight:bold; }}
.sev {{ display:inline-block; padding:1px 8px; border-radius:3px; font-size:10px; font-weight:bold; }}
.mono {{ font-family:'Courier New',monospace; font-size:10px; }}
.muted {{ color:#888; }}
.subs {{ font-family:'Courier New',monospace; font-size:10px; line-height:1.7; }}
.lead {{ color:#444; }}
</style></head><body>
<div class="cover">
  <h1>External Attack Surface Assessment</h1>
  <div class="sub">{_esc(name)}</div>
  <div class="sub">{_esc(when)}</div>
  <div class="note">Automated continuous monitoring export generated by Continuous EAS.<br>
  This is a surface snapshot, not a penetration test. Findings are produced by
  automated checks and have not been manually validated.</div>
</div>

<h2>Summary</h2>
<p class="lead">As of {_esc(when)}, Continuous EAS tracks {data['total']} signal(s) for
{_esc(name)}: {len(data['subs'])} enumerated subdomain(s), {len(data['looks'])} lookalike
domain(s), and {len(attn)} finding(s) that need attention. The severity breakdown is below.</p>
<table><tr><th>Severity</th><th class="num">Count</th></tr>{sev_rows}</table>

<h2>Needs attention (Critical and High)</h2>
<table><tr><th>Severity</th><th>Finding</th><th>Host</th></tr>{find_rows(attn)}</table>

<h2>All actionable findings (Critical, High, Medium)</h2>
<table><tr><th>Severity</th><th>Finding</th><th>Host</th></tr>{find_rows(data['findings'])}</table>

<h2>Lookalike domains</h2>
<table><tr><th>Domain</th><th>Severity</th></tr>{looks_html}</table>

<h2>Enumerated subdomains ({len(data['subs'])})</h2>
<div class="subs">{subs_html}</div>
</body></html>"""


def write_pdf(html: str, out: Path) -> bool:
    try:
        from weasyprint import HTML
    except Exception as exc:
        print(f"[!] PDF skipped, WeasyPrint not available: {exc}", file=sys.stderr)
        return False
    HTML(string=html).write_pdf(str(out))
    return True


# --------------------------------------------------------------------------
# Word (.docx) via python-docx, the editable draft.
# --------------------------------------------------------------------------
def write_docx(name: str, data: dict, when: str, out: Path) -> bool:
    try:
        from docx import Document
        from docx.shared import Pt, RGBColor
        from docx.enum.text import WD_ALIGN_PARAGRAPH
    except Exception as exc:
        print(f"[!] Word skipped, python-docx not available: {exc}", file=sys.stderr)
        return False

    doc = Document()
    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = title.add_run("External Attack Surface Assessment")
    run.bold = True
    run.font.size = Pt(24)
    for text, sz in ((name, 15), (when, 12)):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.add_run(text).font.size = Pt(sz)
    note = doc.add_paragraph()
    note.alignment = WD_ALIGN_PARAGRAPH.CENTER
    nr = note.add_run("Automated continuous monitoring export generated by Continuous EAS. "
                      "This is a surface snapshot, not a penetration test. Findings are "
                      "produced by automated checks and have not been manually validated.")
    nr.italic = True
    nr.font.size = Pt(9)
    nr.font.color.rgb = RGBColor(0x77, 0x77, 0x77)
    doc.add_page_break()

    c = data["counts"]
    attn = [f for f in data["findings"] if f["sev"] in ("SEV1", "SEV2")]

    doc.add_heading("Summary", level=1)
    doc.add_paragraph(
        f"As of {when}, Continuous EAS tracks {data['total']} signal(s) for {name}: "
        f"{len(data['subs'])} enumerated subdomain(s), {len(data['looks'])} lookalike "
        f"domain(s), and {len(attn)} finding(s) that need attention. The severity "
        f"breakdown is below.")
    t = doc.add_table(rows=1, cols=2)
    t.style = "Light Grid Accent 1"
    t.rows[0].cells[0].text = "Severity"
    t.rows[0].cells[1].text = "Count"
    for s in SEV_ORDER:
        cells = t.add_row().cells
        cells[0].text = SEV[s][0]
        cells[1].text = str(c[s])

    def finding_table(items):
        tb = doc.add_table(rows=1, cols=3)
        tb.style = "Light Grid Accent 1"
        hdr = tb.rows[0].cells
        hdr[0].text, hdr[1].text, hdr[2].text = "Severity", "Finding", "Host"
        if not items:
            r = tb.add_row().cells
            r[0].text = "None."
            return
        for f in items:
            r = tb.add_row().cells
            r[0].text = SEV[f["sev"]][0]
            r[1].text = f["title"]
            r[2].text = f["host"] or "-"

    doc.add_heading("Needs attention (Critical and High)", level=1)
    finding_table(attn)
    doc.add_heading("All actionable findings (Critical, High, Medium)", level=1)
    finding_table(data["findings"])

    doc.add_heading("Lookalike domains", level=1)
    if data["looks"]:
        lt = doc.add_table(rows=1, cols=2)
        lt.style = "Light Grid Accent 1"
        lt.rows[0].cells[0].text = "Domain"
        lt.rows[0].cells[1].text = "Severity"
        for dom, sev in data["looks"]:
            r = lt.add_row().cells
            r[0].text = dom
            r[1].text = SEV[sev][0]
    else:
        doc.add_paragraph("None discovered.")

    doc.add_heading(f"Enumerated subdomains ({len(data['subs'])})", level=1)
    if data["subs"]:
        for s in data["subs"]:
            doc.add_paragraph(s)
    else:
        doc.add_paragraph("None discovered.")

    out.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(out))
    return True


# --------------------------------------------------------------------------
# XLSX appendix via openpyxl. The long tables that do not belong in the body.
# --------------------------------------------------------------------------
def write_xlsx(name: str, data: dict, when: str, out: Path) -> bool:
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment
        from openpyxl.utils import get_column_letter
    except Exception as exc:
        print(f"[!] Appendix skipped, openpyxl not available: {exc}", file=sys.stderr)
        return False

    # House style taken from the SJ asset-inventory workbook: Abadi 11, the header
    # row bold white on red, the data rows plain, panes frozen below the header.
    FONT = "Abadi"
    hdr_fill = PatternFill("solid", fgColor="FFFF5D5D")
    hdr_font = Font(name=FONT, size=11, bold=True, color="FFFFFFFF")
    hdr_align = Alignment(vertical="center")
    body_font = Font(name=FONT, size=11)

    wb = Workbook()
    wb.remove(wb.active)

    def sheet(title: str, headers: list[str], rows: list[list], widths: list[int]):
        ws = wb.create_sheet(title[:31])
        ws.append(headers)
        for ci, _ in enumerate(headers, 1):
            cell = ws.cell(row=1, column=ci)
            cell.fill = hdr_fill
            cell.font = hdr_font
            cell.alignment = hdr_align
        for r in rows:
            ws.append(r)
        for ci, w in enumerate(widths, 1):
            ws.column_dimensions[get_column_letter(ci)].width = w
        for row in ws.iter_rows(min_row=2):
            for cell in row:
                cell.font = body_font
        ws.freeze_panes = "A2"
        # Filter dropdowns on the header row, across the full used range.
        ws.auto_filter.ref = f"A1:{get_column_letter(len(headers))}{ws.max_row}"
        return ws

    # Lookalike domains, the full candidate set (every permutation generated,
    # not only the ones that registered). Falls back to the signal-based
    # registered set if the brand_protection export is not present.
    cands = data.get("look_candidates") or []
    if cands:
        def _sevlabel(code):
            code = (code or "").upper()
            return SEV[code][0] if code in SEV else (code or "-")
        look_rows = [[c["candidate"], c["technique"] or "-", c["status"] or "-",
                      _sevlabel(c["sev"]), c["ip"] or "-", c["mail"] or "-"]
                     for c in cands]
        sheet("Lookalike Domains",
              ["Candidate", "Technique", "Status", "Severity if registered",
               "Resolved IP", "Mail"],
              look_rows, [46, 18, 16, 20, 20, 8])
    else:
        sheet("Lookalike Domains", ["Domain", "Severity"],
              [[dom, SEV[sev][0]] for dom, sev in data["looks"]]
              or [["None discovered", ""]], [46, 14])

    # Discovered leaks contrasted with the HIBP automation. Non-HIBP sources stay
    # generic, HIBP is named because it is the automation we run against them.
    leak_rows = []
    for l in data["leaks"]:
        if l["hibp"] and l["other"]:
            disc = "HIBP and credential exposure monitoring"
        elif l["hibp"]:
            disc = "HIBP"
        else:
            disc = "Credential exposure monitoring"
        leak_rows.append([l["subject"], SEV[l["sev"]][0], disc,
                          "Yes" if l["hibp"] else "No"])
    sheet("Breach Exposure", ["Subject", "Severity", "Discovered by", "In HIBP"],
          leak_rows or [["None discovered", "", "", ""]], [40, 14, 36, 10])

    # Full host inventory, every host found during the analysis, including the
    # ones that do not resolve, with their IPs.
    host_rows = [[h["host"], ", ".join(h["ips"]) or "none",
                  "Live" if h["up"] else "Does not resolve",
                  "Possible takeover" if h.get("takeover") else ""]
                 for h in data["hosts"]]
    sheet("Hosts and Services", ["Host", "IP address", "Reachability", "Notes"],
          host_rows or [["None discovered", "", "", ""]], [36, 34, 20, 40])

    out.parent.mkdir(parents=True, exist_ok=True)
    wb.save(str(out))
    return True


# --------------------------------------------------------------------------
# Early alert. A short, editable Word note for the Critical and High findings
# only, so an operator can fix a few details and push it into AIR fast. This is
# a placeholder layout, a client template will replace the body later.
# --------------------------------------------------------------------------
# A finding's source class maps to the Vuln DB template that describes it, so the
# early alert is phrased from the curated template (name, severity, CVSS, CWE,
# description, mitigation, references) rather than the raw signal title. Mirrors
# panel._CLASS_TO_VDB.
_CLASS_TO_VDB = {
    "lookalike_domain": "Active Brand Impersonation Domain",
    "email_auth_posture": "Missing or Weak DMARC Policy",
    "dmarc_record": "Missing or Weak DMARC Policy",
}

_CVSS31_RE = re.compile(r"CVSS:3\.[01]/[A-Z]{1,2}:[A-Z](?:/[A-Z]{1,2}:[A-Z])+")


def _cvss_vector(s: str) -> str:
    m = _CVSS31_RE.search((s or "").strip())
    return m.group(0) if m else ""


def _cvss31_score(vector: str):
    """CVSS 3.1 base score for a vector, or None. Mirrors panel._cvss31_score."""
    vec = _cvss_vector(vector)
    if not vec:
        return None
    m = {}
    for part in vec.split("/")[1:]:
        if ":" in part:
            k, v = part.split(":", 1)
            m[k] = v
    if any(k not in m for k in ("AV", "AC", "PR", "UI", "S", "C", "I", "A")):
        return None
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
        ac = {"L": 0.77, "H": 0.44}[m["AC"]]
        ui = {"N": 0.85, "R": 0.62}[m["UI"]]
        changed = m["S"] == "C"
        pr = ({"N": 0.85, "L": 0.68, "H": 0.5} if changed
              else {"N": 0.85, "L": 0.62, "H": 0.27})[m["PR"]]
        cia = {"N": 0, "L": 0.22, "H": 0.56}
        c, i, a = cia[m["C"]], cia[m["I"]], cia[m["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15) if changed else 6.42 * iss
    expl = 8.22 * av * ac * pr * ui

    def roundup(x):
        n = round(x * 100000)
        return n / 100000 if n % 10000 == 0 else (math.floor(n / 10000) + 1) / 10
    if impact <= 0:
        return 0.0
    return roundup(min((1.08 if changed else 1.0) * (impact + expl), 10))


def _vdb_templates() -> dict:
    """Vuln DB templates keyed by name, read straight from DATA/vuln_db.json.
    Empty if the file is absent, so the alert falls back to the signal fields."""
    f = DATA / "vuln_db.json"
    try:
        d = json.loads(f.read_text())
        return {t.get("name"): t for t in d.get("templates", []) if t.get("name")}
    except Exception:
        return {}


def _resolve_vuln(item: dict, templates: dict) -> dict | None:
    """The Vuln DB template describing this finding, by its source class."""
    return templates.get(_CLASS_TO_VDB.get(item.get("source_class", ""), ""))


def _alert_findings(base: Path) -> list[dict]:
    """Every Critical (SEV1) and High (SEV2) signal, deduped, with the title,
    description and affected host. Mirrors the console's Needs attention section
    so the alert covers exactly what the operator sees flagged there."""
    sdir = base / "signals"
    items: list[dict] = []
    seen: set[str] = set()
    # Active lookalikes for the same origin brand collapse into one finding,
    # keyed by origin, with every domain as a location. Matches the console.
    lookalikes: dict[str, dict] = {}
    if not sdir.is_dir():
        return items
    for f in sorted(sdir.glob("*.jsonl")):
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            sev = str(d.get("severity", "")).upper()
            cls = str(d.get("source_class") or "")
            did = d.get("dedup_id") or f"{cls}|{d.get('title', '')}"
            if did in seen:
                continue
            seen.add(did)
            ents = d.get("entities") or []
            doms = [str(x.get("value", "")).lower().rstrip(".")
                    for x in ents if x.get("type") == "domain" and x.get("value")]
            # Non-lookalike findings only enter the alert at Critical/High.
            # Active lookalikes group regardless of per-domain severity, since
            # the whole group is one High finding (matches the console).
            # Email-auth posture also enters at any severity: the operator
            # generates this alert explicitly by key, so it must stay available
            # even when the posture scores Medium (for example no DMARC record
            # but SPF -all and DKIM present). Its label still reflects the real
            # posture, computed below.
            # Accept both vocabularies: SEVn tokens (subdomain, lookalike feeds)
            # and named levels (email_auth_posture / dmarc_watch emits a word).
            if cls not in ("lookalike_domain", "email_auth_posture") and sev not in (
                    "SEV1", "SEV2", "CRITICAL", "HIGH"):
                continue
            if cls == "lookalike_domain":
                ev = d.get("evidence", {}) or {}
                origin = (ev.get("origin_domain") or "").lower().rstrip(".") or "lookalike"
                grp = lookalikes.setdefault(origin, {
                    "sev": sev, "hosts": [], "title": "", "description": "", "origin": origin})
                if _rank(sev) < _rank(grp["sev"]):
                    grp["sev"] = sev
                for dm in (doms or [str(d.get("title", ""))]):
                    if dm and dm not in grp["hosts"]:
                        grp["hosts"].append(dm)
                if not grp["title"]:
                    grp["title"] = str(d.get("title") or "Active brand impersonation domain")
                if not grp["description"]:
                    grp["description"] = str(d.get("description") or "")
                continue
            items.append({
                "sev": sev,
                "key": did,
                "title": str(d.get("title") or cls or "Finding"),
                "description": str(d.get("description") or ""),
                "host": doms[0] if doms else "",
                "hosts": doms,
                "source_class": cls,
                "evidence": d.get("evidence") or {},
            })
    # Emit one grouped item per origin brand.
    for origin, grp in lookalikes.items():
        hosts = sorted(grp["hosts"])
        n = len(hosts)
        title = (grp["title"] if n <= 1
                 else f"Active brand impersonation domains ({n}) impersonating {origin}")
        items.append({
            "sev": grp["sev"],
            "key": f"lookalike_domain|{origin}",
            "title": title,
            "description": grp["description"],
            "host": hosts[0] if hosts else "",
            "hosts": hosts,
            "source_class": "lookalike_domain",
        })
    # Attach the curated Vuln DB content so the early alert reads from the
    # template (description, mitigation, references, CVSS), not the raw signal.
    templates = _vdb_templates()
    for it in items:
        tpl = _resolve_vuln(it, templates)
        if tpl:
            vec = _cvss_vector(tpl.get("cvss_vector", ""))
            it["vuln_name"] = tpl.get("name") or it["title"]
            it["cvss_vector"] = vec
            score = _cvss31_score(vec)
            it["cvss_score"] = "" if score is None else f"{score:.1f}"
            it["vuln_description"] = tpl.get("description") or it["description"]
            it["mitigation"] = tpl.get("mitigation") or ""
            it["references"] = tpl.get("references") or ""
            it["evidence_steps"] = tpl.get("evidence_steps") or ""
            it["evidence_figures"] = tpl.get("evidence_figures") or []
            it["sev"] = tpl.get("severity") or it["sev"]
            if it.get("source_class") == "lookalike_domain":
                it["vuln_description"] = _shape_lookalike_desc(
                    it["vuln_description"], it.get("hosts") or [], it.get("key", ""))
            elif it.get("source_class") == "email_auth_posture":
                ev = it.get("evidence") or {}
                it["vuln_description"] = _shape_dmarc_desc(
                    it["vuln_description"], ev, it.get("host", ""))
                # Severity comes from the real posture, not the template's
                # worst-case label, so a domain that still hard-fails SPF and
                # signs with DKIM is not reported as High.
                it["sev"] = _dmarc_severity(ev)
                # The template vector computes to 4.3 (Medium). For the
                # Informational case (enforcing policy, only a cosmetic gap) a
                # 4.3 score would contradict the label, so drop the numeric CVSS
                # and let the finding stand as Informational with no score.
                if it["sev"] == "SEV5":
                    it["cvss_vector"] = ""
                    it["cvss_score"] = ""
                it["evidence_steps"] = (it.get("evidence_steps")
                                        or "\n".join(_dmarc_evidence_steps(it.get("host", ""), ev)))
        else:
            it["vuln_name"] = it["title"]
            it["cvss_vector"] = ""
            it["cvss_score"] = ""
            it["vuln_description"] = it["description"]
            it["mitigation"] = ""
            it["references"] = ""
            it["evidence_steps"] = ""
            it["evidence_figures"] = []
    items.sort(key=lambda a: (_rank(a["sev"]), a["host"], a["title"]))
    return items


def _shape_lookalike_desc(desc: str, hosts: list, key: str) -> str:
    """Make the brand-impersonation description match the actual finding: a
    concrete opening that names every confirmed domain, and singular template
    wording switched to plural when more than one domain was confirmed. The Vuln
    DB description is a generic explanation with a 'State here ...' author
    placeholder; we fill that placeholder with the real domains."""
    desc = desc or ""
    hosts = [h for h in hosts if h]
    n = len(hosts)
    origin = key.split("|", 1)[1] if "|" in key else ""
    # Fill the author-placeholder sentence with the concrete confirmed domains.
    placeholder = ("State here the confirmed domain, what it was serving "
                   "(resolving IP, login clone, mail), and the discovery date.")
    if n == 1:
        concrete = f"The confirmed domain is {hosts[0]}."
    elif n > 1:
        concrete = (f"The {n} confirmed domains are: " + ", ".join(hosts) + ".")
    else:
        concrete = ""
    if concrete and placeholder in desc:
        desc = desc.replace(placeholder, concrete)
    elif concrete:
        desc = desc.rstrip() + "\n\n" + concrete
    if n > 1:
        # Switch the singular template phrasing to plural.
        desc = desc.replace(
            "This finding is one confirmed domain, registered and actively "
            "running when it was discovered.",
            f"This finding groups {n} confirmed domains, each registered and "
            f"actively running when it was discovered.")
        # Concrete lead paragraph so the reader sees the scope immediately.
        lead = (f"{n} domains impersonating {origin or 'the client brand'} were found "
                f"registered and actively running, not merely parked.")
        desc = lead + "\n\n" + desc
    return desc


def _dmarc_severity(ev: dict) -> str:
    """Lowest defensible severity for the actual email-auth posture, returned as
    a SEVn token so it ranks and renders like every other finding. DMARC is one
    control in a set of three. The gap that matters is whether forged mail can
    reach an inbox, which depends on all three together, so a missing DMARC
    record on a domain that still hard-fails SPF and signs with DKIM is not the
    same risk as a domain with no protection at all.

    The label must match the CVSS band (house rule). The computable vector for
    email spoofing is CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N = 4.3, which
    is Medium: the recipient must act on the forged mail (UI:R) and only
    integrity is affected at a low level (I:L), so this class cannot compute to
    High no matter how many of the three controls are missing. Medium is
    therefore the ceiling, and a merely cosmetic gap drops to Informational.

      SEV3 Medium      spoofable: no DMARC, or p=none, or p=quarantine, or pct<100
      SEV5 Info        enforcing policy (p=reject): any remaining gap is cosmetic
    """
    dmarc_found = bool(ev.get("dmarc_found"))
    policy      = (ev.get("dmarc_policy") or "").lower()
    pct         = ev.get("dmarc_pct", 100)

    if policy == "reject" and (pct is None or pct == 100):
        # Enforcing policy in place. A missing rua tag is operational, not a
        # delivery risk, so it is Informational, never Medium or above.
        return "SEV5"
    # No DMARC, p=none, p=quarantine, or partial coverage: forged mail is not
    # blocked by an owner policy. Medium, matching the 4.3 vector.
    return "SEV3"


def _shape_dmarc_desc(base: str, ev: dict, host: str) -> str:
    """Turn the Vuln DB base paragraph into a concrete finding for THIS domain.

    The DB entry carries the stable explanation of DMARC and the mitigation. The
    per-domain facts (which of the three controls are present, the policy, the
    pct, whether aggregate reporting is on) come from the dmarc_watch signal
    evidence, never from an author menu. This replaces the old {one or two
    author-choose menus} in the template, which were shipping to the client
    verbatim because nothing filled them."""
    dmarc_found = bool(ev.get("dmarc_found"))
    policy      = (ev.get("dmarc_policy") or "").lower()
    pct         = ev.get("dmarc_pct", 100)
    rua         = bool(ev.get("dmarc_rua"))
    spf_found   = bool(ev.get("spf_found"))
    spf_q       = (ev.get("spf_qualifier") or "").lower()
    dkim_found  = bool(ev.get("dkim_found"))
    spf_hard    = spf_found and spf_q == "-all"
    dom         = host or "this domain"

    # Sentence 1: the DMARC state.
    if not dmarc_found:
        s_dmarc = (f"{dom} publishes no DMARC record, so a receiving mail server "
                   "is given no owner-stated instruction for mail that fails "
                   "authentication while claiming to come from this domain.")
    elif policy == "none":
        extra = "" if pct == 100 else f" and applies to only {pct} percent of mail"
        s_dmarc = (f"{dom} publishes a DMARC record at policy p=none{extra}, which "
                   "only monitors and does not tell a receiving server to reject "
                   "or quarantine forged mail.")
    elif policy == "quarantine":
        s_dmarc = (f"{dom} publishes a DMARC record at policy p=quarantine, which "
                   "sends suspected forgeries to spam rather than rejecting them.")
    elif policy == "reject":
        s_dmarc = (f"{dom} publishes an enforcing DMARC record at policy p=reject.")
    else:
        s_dmarc = f"{dom} publishes a DMARC record with policy p={policy or 'unknown'}."

    # Sentence 2: the supporting controls, SPF and DKIM.
    spf_txt = ("SPF is set to a hard fail (-all)" if spf_hard
               else f"SPF is set to {spf_q}, which does not hard-fail unlisted senders"
               if spf_found and spf_q
               else "SPF is published" if spf_found
               else "no SPF record is published")
    dkim_txt = "DKIM signing is present" if dkim_found else "no DKIM signing was found"
    s_support = f"For the supporting controls, {spf_txt} and {dkim_txt}."

    # Sentence 3: the resulting exposure, honest about the real state.
    if not dmarc_found and spf_hard and dkim_found:
        s_impact = ("Because SPF hard-fails and DKIM is in place, most receivers "
                    "will already reject or flag forged mail, but with no DMARC "
                    "record the owner states no policy and receives no aggregate "
                    "reports, so abuse of the name goes unseen.")
    elif not dmarc_found or policy == "none":
        s_impact = ("An attacker can send email that appears to come from an "
                    "address at this domain with little technical barrier, which "
                    "is a common first step of phishing and business email "
                    "compromise against staff, customers and partners.")
    elif policy == "quarantine":
        s_impact = ("Forged mail is sent to spam rather than blocked, so a "
                    "determined phishing attempt can still reach a recipient who "
                    "checks the spam folder.")
    else:
        s_impact = ("The enforcing policy blocks forged mail at the receiver. The "
                    "remaining gap is operational visibility rather than delivery.")

    if not rua and dmarc_found:
        s_impact += (" No rua tag is set, so the owner receives no aggregate "
                     "reports and is blind to spoofing attempts.")

    concrete = " ".join([s_dmarc, s_support, s_impact])
    base = (base or "").strip()
    # Drop any stale author menus the base might still carry, then prepend the
    # concrete per-domain paragraph so the reader sees the real posture first.
    base = re.sub(r"\{[^}]*\}", "", base)
    base = re.sub(r"[ ]{2,}", " ", base).strip()
    return concrete + ("\n\n" + base if base else "")


def _dig_short(args: list[str]) -> str | None:
    """Run `dig +short <args>` against a public resolver and return the trimmed
    output, or None if dig is unavailable or the lookup failed. Passive,
    contactless public-DNS read only: it never touches the client's hosts."""
    import shutil
    import subprocess
    if not shutil.which("dig"):
        return None
    try:
        r = subprocess.run(
            ["dig", "+short", "@1.1.1.1", *args],
            capture_output=True, text=True, timeout=12)
    except Exception:
        return None
    if r.returncode != 0:
        return None
    return r.stdout.strip()


def _dmarc_evidence_steps(host: str, ev: dict | None = None) -> list[str]:
    """Reproduction steps for an email-auth finding: the exact public DNS lookups
    that show the posture, each paired with the output observed when the finding
    was raised, so a reader can both rerun the command and see the result it is
    expected to return. The outputs are read live from public DNS at build time
    (passive). If dig is unavailable the step still carries the command, and the
    observed line falls back to the posture recorded in the signal evidence."""
    h = host or "the affected domain"
    ev = ev or {}

    def _oneline(out: str, kind: str) -> str:
        """Collapse a dig result to one readable line. A domain's root TXT set
        and a DKIM key both come back as several quoted lines, which would
        otherwise split one step into many and dump a full public key. Pick the
        record that matters and keep it to a single line."""
        lines = [ln.strip().strip('"') for ln in out.splitlines() if ln.strip()]
        joined = " ".join(lines)
        if kind == "spf":
            spf = next((ln for ln in lines if ln.lower().startswith("v=spf1")), "")
            return spf or (joined[:120] if joined else "(no SPF record)")
        if kind == "dkim":
            # Never echo the key material itself. A DKIM TXT record is a public
            # key, not a secret, but a long p= blob reads like a credential dump
            # in a client report and adds no evidentiary value, so report only
            # that a DKIM record is published.
            if "v=dkim1" in joined.replace(" ", "").lower():
                return "v=DKIM1 record published (DKIM signing is configured)"
            return "(no DKIM record)"
        if kind == "dmarc":
            dm = next((ln for ln in lines if ln.lower().startswith("v=dmarc1")), "")
            return dm or "(no record returned)"
        return (joined[:120] + " (truncated)") if len(joined) > 120 else joined

    def _obs(cmd_args: list[str], kind: str, fallback: str) -> str:
        out = _dig_short(cmd_args) if host else None
        if out is None:
            return fallback
        return _oneline(out, kind) if out else "(no record returned)"

    # Fallbacks derived from the stored posture, used only when dig cannot run.
    spf_fb = ("no SPF record" if not ev.get("spf_found")
              else f"v=spf1 ... {ev.get('spf_qualifier') or 'all'}")
    dmarc_fb = ("(no record returned)" if not ev.get("dmarc_found")
                else f"v=DMARC1; p={ev.get('dmarc_policy') or 'none'}")
    dkim_fb = ("(no record returned)" if not ev.get("dkim_found") else "v=DKIM1; ...")

    steps = [
        f"Query the DMARC record over public DNS, which returns the policy or "
        f"nothing: dig +short TXT _dmarc.{h}  ->  "
        + _obs(["TXT", f"_dmarc.{h}"], "dmarc", dmarc_fb),
        f"Query the SPF record and read the 'all' qualifier: dig +short TXT {h}  ->  "
        + _obs(["TXT", h], "spf", spf_fb),
        f"Query a DKIM selector (google shown, try the ones the sending platform "
        f"uses): dig +short TXT google._domainkey.{h}  ->  "
        + _obs(["TXT", f"google._domainkey.{h}"], "dkim", dkim_fb),
    ]
    steps.append(
        "Compare the published records against an enforcing posture: DMARC "
        "p=reject with a rua tag, SPF set to -all, and DKIM signing on every sender.")
    return steps


def _evidence_steps(item: dict) -> list[str]:
    """Reproduction steps for the finding's Evidence section. Prefers curated
    steps carried on the Vuln DB entry (one per line); otherwise derives a
    concrete, host-specific default from the finding class, so the early alert
    never ships an empty Evidence. The steps read as instructions a reader can
    follow, consistent with the sj-report evidence style."""
    curated = [s.strip() for s in (item.get("evidence_steps") or "").splitlines() if s.strip()]
    if curated:
        return curated
    hosts = item.get("hosts") or ([item["host"]] if item.get("host") else [])
    cls = (item.get("source_class") or "").lower()
    key = item.get("key", "")
    origin = key.split("|", 1)[1] if "|" in key else ""
    brand = origin or "the client brand"
    is_lookalike = any(w in cls for w in ("lookalike", "impersonation", "typosquat", "brand"))
    # The Evidence section is how a reader reproduces the finding, not how we
    # collected it, so it holds no screenshot-capture or registrar-lookup steps:
    # those are evidence gathering, not reproduction. For an impersonation
    # finding, reproducing it is simply visiting each confirmed domain and seeing
    # it stand in for the brand.
    if is_lookalike and len(hosts) > 1:
        joined = ", ".join(hosts)
        return [
            f"Browse over HTTPS to each of the {len(hosts)} confirmed domains: {joined}.",
            f"Observe that each domain serves a page standing in for {brand}, "
            "reproducing its name, layout and branding.",
            "Where a domain presents a login form, confirm it solicits the "
            "visitor's credentials under the impersonated brand.",
        ]
    host = hosts[0] if hosts else "the affected domain"
    if is_lookalike:
        return [
            f"Browse over HTTPS to https://{host}.",
            f"Observe that the page stands in for {brand}, reproducing its "
            "name, layout and branding.",
            "Where the page presents a login form, confirm it solicits the "
            "visitor's credentials under the impersonated brand.",
        ]
    return [
        f"Send the request shown below to {host}.",
        "Observe the response that confirms the issue.",
    ]


def _hex_to_rgb(h: str):
    from docx.shared import RGBColor
    h = (h or "").lstrip("#")
    if len(h) != 6:
        return None
    return RGBColor(int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))


def _all_paragraphs(doc):
    """Every unique paragraph in the document: body, table cells, and the header
    and footer of every section (so tokens in the running header/footer are
    filled too). Merged cells share one paragraph set, so each is yielded once by
    XML id."""
    seen = set()

    def _walk(container):
        for par in container.paragraphs:
            if id(par._p) not in seen:
                seen.add(id(par._p))
                yield par
        for tbl in container.tables:
            for row in tbl.rows:
                for cell in row.cells:
                    yield from _walk(cell)

    yield from _walk(doc)
    for sec in doc.sections:
        for hf in (sec.header, sec.first_page_header, sec.even_page_header,
                   sec.footer, sec.first_page_footer, sec.even_page_footer):
            if hf is not None:
                yield from _walk(hf)


def _inline_replace(par, token: str, value: str, color=None) -> bool:
    """Replace a token inside a paragraph, editing only the run(s) that carry the
    token text and leaving every other run untouched. This preserves inline
    images (a logo lives in its own empty-text run, so folding the whole
    paragraph into run 0 would destroy it) and the surrounding formatting."""
    runs = par.runs
    if not runs:
        return False
    full = "".join(r.text for r in runs)
    if token not in full:
        return False

    # Fast path: the token lies wholly within one run.
    for r in runs:
        if token in r.text:
            r.text = r.text.replace(token, value)
            if color is not None and value:
                r.font.color.rgb = color
            return True

    # Split path: the token spans consecutive runs. Edit only the spanning runs;
    # runs entirely outside the token's character span (including image runs)
    # are left exactly as they are.
    starts, pos = [], 0
    for r in runs:
        starts.append(pos)
        pos += len(r.text)
    idx = full.index(token)
    end = idx + len(token)
    first = True
    for i, r in enumerate(runs):
        rs, re_ = starts[i], starts[i] + len(r.text)
        if re_ <= idx or rs >= end:
            continue  # untouched: keeps logos and unrelated text intact
        before = r.text[:idx - rs] if rs < idx else ""
        after = r.text[end - rs:] if re_ > end else ""
        if first:
            r.text = before + value + after
            if color is not None and value:
                r.font.color.rgb = color
            first = False
        else:
            r.text = after
    return True


def _clone_paragraph_after(anchor):
    """Deep-copy a paragraph and insert the copy right after it. Returns the new
    Paragraph, carrying the same style and run formatting."""
    import copy
    from docx.text.paragraph import Paragraph
    new_p = copy.deepcopy(anchor._p)
    anchor._p.addnext(new_p)
    return Paragraph(new_p, anchor._parent)


def _set_text_keep_style(par, text: str):
    """Set a paragraph's text to a single run, keeping the first run's formatting
    and the paragraph style (used when expanding a cloned paragraph)."""
    if par.runs:
        par.runs[0].text = text
        for r in par.runs[1:]:
            r.text = ""
    else:
        par.add_run(text)


def _expand_token_paragraph(par, token: str, chunks: list[str], bullet: bool = False) -> None:
    """Replace a single-token paragraph with one paragraph per chunk, cloning the
    host paragraph so every line keeps its style. Optionally force a bullet style."""
    chunks = [c for c in (chunks or []) if c.strip()] or [""]

    def _has_num(p):
        from docx.oxml.ns import qn
        pPr = p._p.find(qn("w:pPr"))
        return pPr is not None and pPr.find(qn("w:numPr")) is not None

    # First chunk reuses the host paragraph. When the template paragraph already
    # carries list numbering (a bullet or a decimal numPr), keep it: cloning the
    # host preserves that numbering on every line, so a bullet or numbered list
    # renders exactly as the template defines it. Only fall back to the built-in
    # List Bullet style when a bullet was asked for and the host has no numbering.
    _inline_replace(par, token, chunks[0])
    if bullet and not _has_num(par):
        try:
            par.style = par.part.document.styles["List Bullet"]
        except Exception:
            _set_text_keep_style(par, "• " + chunks[0])
    anchor = par
    for chunk in chunks[1:]:
        new = _clone_paragraph_after(anchor)
        _set_text_keep_style(new, chunk)
        if bullet and not _has_num(new):
            try:
                new.style = new.part.document.styles["List Bullet"]
            except Exception:
                _set_text_keep_style(new, "• " + chunk)
        anchor = new


def _expand_figures(fig_par, cap_par, figures, max_width) -> None:
    """Fill the evidence figure block from a list of figures. Each figure is a
    dict with an 'image' (a file path) and a 'caption', or a bare path string.
    The {{EVIDENCE_FIGURES}} paragraph (centred) holds each image and the
    {{FIGURE_CAPTION}} paragraph is the caption prototype. Image and caption
    paragraphs are cloned per figure so one finding can carry many screenshots,
    each with its own 'Figure N.' caption. A missing image file falls back to
    the house-style hand-capture marker so the operator knows to drop one in."""
    marker = "[ Here goes the screenshot - description of what it shows ]"

    def _path_of(fig):
        if isinstance(fig, dict):
            return fig.get("image") or fig.get("path") or ""
        return str(fig or "")

    def _caption_of(fig):
        if isinstance(fig, dict):
            return (fig.get("caption") or "").strip()
        return ""

    def fill_image(p, fig):
        for r in list(p.runs):
            r.text = ""
        path = _path_of(fig)
        if path and os.path.isfile(str(path)):
            try:
                p.add_run().add_picture(str(path), width=max_width)
                return
            except Exception:
                pass
        _set_text_keep_style(p, marker)

    def fill_caption(p, fig, n):
        cap = _caption_of(fig) or "Evidence of the finding"
        _set_text_keep_style(p, f"Figure {n}. {cap}")

    fill_image(fig_par, figures[0])
    fill_caption(cap_par, figures[0], 1)
    anchor = cap_par
    for n, fig in enumerate(figures[1:], start=2):
        img = _clone_paragraph_after(anchor)
        fill_image(img, fig)
        cap = _clone_paragraph_after(img)
        fill_caption(cap, fig, n)
        anchor = cap


def _add_hyperlink(par, url: str, text: str):
    """Append a real hyperlink run to a paragraph."""
    from docx.oxml.shared import OxmlElement, qn
    part = par.part
    r_id = part.relate_to(
        url,
        "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
        is_external=True)
    link = OxmlElement("w:hyperlink")
    link.set(qn("r:id"), r_id)
    run = OxmlElement("w:r")
    rpr = OxmlElement("w:rPr")
    style = OxmlElement("w:rStyle")
    style.set(qn("w:val"), "Hyperlink")
    rpr.append(style)
    run.append(rpr)
    t = OxmlElement("w:t")
    t.text = text
    run.append(t)
    link.append(run)
    par._p.append(link)


def _expand_references(par, token: str, refs: str) -> None:
    """Replace the references token with one paragraph per reference line. Each
    line is 'Label | URL': the label becomes a hyperlink to the URL."""
    import copy
    from docx.oxml.shared import qn
    lines = [ln.strip() for ln in (refs or "").splitlines() if ln.strip()]
    if not lines:
        _inline_replace(par, token, "")
        return
    # Keep a pristine copy of the host paragraph (style, no hyperlinks) to clone
    # each extra reference from, so hyperlinks added to one line never carry into
    # the next.
    pristine = copy.deepcopy(par._p)

    def _clear(target):
        for hl in target._p.findall(qn("w:hyperlink")):
            target._p.remove(hl)
        if target.runs:
            target.runs[0].text = ""
            for r in target.runs[1:]:
                r.text = ""

    from docx.text.paragraph import Paragraph
    anchor = par
    for i, line in enumerate(lines):
        label, _, url = line.partition("|")
        label, url = label.strip(), url.strip()
        if i == 0:
            target = par
        else:
            new_p = copy.deepcopy(pristine)
            anchor._p.addnext(new_p)
            target = Paragraph(new_p, anchor._parent)
        _clear(target)
        if url:
            _add_hyperlink(target, url, label or url)
        else:
            _set_text_keep_style(target, label)
        anchor = target


def write_alert_docx(name: str, item: dict, when: str, out: Path) -> bool:
    """Render one Critical or High early-alert finding into the house-style Word
    template. The template carries {{TOKEN}} placeholders and the SJ styling,
    cover on page 1 and the finding on page 2; we deep-copy it and fill the
    tokens from the finding and its Vuln DB entry. The evidence stays a
    placeholder on purpose, for the operator to drop the screenshot in."""
    try:
        from docx import Document
    except Exception as exc:
        print(f"[!] Early alert skipped, python-docx not available: {exc}", file=sys.stderr)
        return False
    if not ALERT_TEMPLATE.is_file():
        print(f"[!] Early alert template not found: {ALERT_TEMPLATE}", file=sys.stderr)
        return False

    doc = Document(str(ALERT_TEMPLATE))

    hosts = item.get("hosts") or ([item["host"]] if item.get("host") else [])
    host = hosts[0] if hosts else ""

    # Backstop against placeholder leakage. A Vuln DB template can carry author
    # tokens ({domain}, <domain>, <selector>) that a per-class shaper is meant to
    # fill. If any shaper is skipped or a token is missed, the raw token would
    # otherwise ship to the client. Fill them here from the real host as a final
    # guard, across every rendered text field, so no placeholder can reach the
    # document. <selector> has no single value, so it reads as a worked example.
    def _fill_tokens(s: str) -> str:
        if not s:
            return s
        h = host or "the affected domain"
        s = s.replace("{domain}", h).replace("<domain>", h)
        s = s.replace("<selector>", "google (or another published selector)")
        return s

    for _f in ("vuln_description", "mitigation", "evidence_steps", "description"):
        if isinstance(item.get(_f), str):
            item[_f] = _fill_tokens(item[_f])

    sev = item.get("sev", "SEV3")
    sev_label = SEV.get(sev, ("Informational", "#607085", "#fff"))[0]
    sev_color = _hex_to_rgb(SEV.get(sev, ("", "#607085"))[1])
    if len(hosts) > 1:
        caption = "the confirmed active brand impersonation domains listed above"
    elif host:
        caption = f"the confirmed active brand impersonation domain {host}"
    else:
        caption = f"the confirmed {item.get('vuln_name', 'finding')}"
    # The caption follows "Figure 1. ", so its first word is sentence-capitalised.
    caption = caption[:1].upper() + caption[1:]

    inline = {
        "{{CLIENT_NAME}}": name,
        "{{REPORT_DATE}}": when,
        "{{VULN_NAME}}": item.get("vuln_name") or item.get("title") or "Finding",
        "{{CVSS_SCORE}}": item.get("cvss_score") or "",
        "{{CVSS_VECTOR}}": item.get("cvss_vector") or "",
        "{{FIGURE_CAPTION}}": caption,
    }

    # Materialise the full paragraph set before any edit: expanding a token
    # inserts new paragraphs, and iterating the generator lazily while mutating
    # would skip the table cells that come last.
    paras = list(_all_paragraphs(doc))
    # Usable text width (page minus margins) so an inserted screenshot never
    # overruns the template's margins.
    _sec = doc.sections[0]
    _usable_width = _sec.page_width - _sec.left_margin - _sec.right_margin
    for par in paras:
        text = "".join(r.text for r in par.runs)
        if "{{EVIDENCE_FIGURES}}" in text:
            figures = item.get("evidence_figures") or []
            if not figures:
                # No screenshots on this finding, leave the hand-capture marker
                # and let the single {{FIGURE_CAPTION}} below fill normally.
                _inline_replace(
                    par, "{{EVIDENCE_FIGURES}}",
                    "[ Here goes the screenshot - description of what it shows ]")
                continue
            cap_proto = next(
                (p for p in paras
                 if "{{FIGURE_CAPTION}}" in "".join(r.text for r in p.runs)),
                None)
            if cap_proto is None:
                _inline_replace(par, "{{EVIDENCE_FIGURES}}", "")
                continue
            _expand_figures(par, cap_proto, figures, _usable_width)
            continue
        if "{{SEVERITY}}" in text:
            _inline_replace(par, "{{SEVERITY}}", sev_label, color=sev_color)
            continue
        if "{{AFFECTED_HOST}}" in text:
            # One location per domain, so a grouped lookalike finding lists every
            # confirmed domain in the Locations cell.
            _expand_token_paragraph(
                par, "{{AFFECTED_HOST}}",
                hosts or ["No single host; see description"])
            continue
        if "{{DESCRIPTION}}" in text:
            _expand_token_paragraph(
                par, "{{DESCRIPTION}}",
                (item.get("vuln_description") or "").split("\n\n"))
            continue
        if "{{REMEDIATION_BULLETS}}" in text:
            # The host paragraph already carries the template's list numPr, so
            # cloning it per line keeps the list style the template defines
            # (numbered in the current template) rather than forcing bullets.
            _expand_token_paragraph(
                par, "{{REMEDIATION_BULLETS}}",
                (item.get("mitigation") or "").splitlines())
            continue
        if "{{EVIDENCE_STEPS}}" in text:
            # The host paragraph already carries the template's numbered-list
            # numPr, so cloning it per step gives a 1,2,3 list in the body font.
            _expand_token_paragraph(par, "{{EVIDENCE_STEPS}}", _evidence_steps(item))
            continue
        if "{{REFERENCES}}" in text:
            _expand_references(par, "{{REFERENCES}}", item.get("references") or "")
            continue
        for tok, val in inline.items():
            if tok in text:
                _inline_replace(par, tok, val)

    out.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(out))
    return True


def _safe_token(text: str) -> str:
    """A short filesystem-safe token from a finding title, for the file name."""
    tok = re.sub(r"[^A-Za-z0-9]+", "-", (text or "").strip()).strip("-")
    return (tok[:48] or "finding")


def _file_safe(text: str) -> str:
    """A readable, filesystem-safe name fragment: keeps spaces, drops only the
    characters a path cannot hold, collapses whitespace."""
    tok = re.sub(r"[\\/:*?\"<>|]+", " ", (text or "").strip())
    tok = re.sub(r"\s+", " ", tok).strip()
    return (tok[:80] or "Finding")


def _vmeta_figures(base: Path, key: str) -> list[dict]:
    """The figures the operator attached to this finding on the console, resolved
    to on-disk image paths with their captions, ready for the report. Figures are
    the `figures` lines in vuln_meta.json (one `filename | caption` per line),
    matched against the uploaded/captured evidence files recorded for the same
    finding under engagements/<slug>/evidence/<vid>/. When figures lines name no
    captions but files exist, the files are used in order. Returns [] when the
    finding has no attached evidence, so the Vuln DB default still applies."""
    mf = base / "state" / "vuln_meta.json"
    try:
        meta = json.loads(mf.read_text())
        entry = meta.get(key) or {}
    except Exception:
        return []
    files = entry.get("files") or []
    evroot = base / "evidence"

    def _locate(stored: str) -> str:
        if not stored:
            return ""
        hits = list(evroot.glob(f"*/{stored}"))
        return str(hits[0]) if hits else ""

    # Index both the stored (safe) name and the original upload name to a path.
    index: dict[str, str] = {}
    for f in files:
        stored = f.get("stored") or ""
        path = _locate(stored)
        if stored:
            index[stored.lower()] = path
        orig = (f.get("orig") or "").lower()
        if orig:
            index.setdefault(orig, path)

    out: list[dict] = []
    for ln in (entry.get("figures") or "").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        fn, _, cap = ln.partition("|")
        fn, cap = fn.strip(), cap.strip()
        path = index.get(fn.lower()) or _locate(fn)
        out.append({"image": path, "caption": cap})
    if not out:
        # No figure lines: fall back to every attached file, in upload order.
        for f in files:
            path = _locate(f.get("stored") or "")
            if path:
                out.append({"image": path, "caption": ""})
    return out


def build_early_alert(slug: str, base: Path | None = None, key: str | None = None) -> dict:
    """Build the editable early-alert Word document for one Critical or High
    finding, identified by its dedup key. Returns
    {"docx": path|None, "count": int, "stamp": str}."""
    base = base or (ENGAGEMENTS / slug)
    name = _pretty(slug)
    now = datetime.now(timezone.utc)
    when = now.strftime("%d %B %Y")
    stamp = now.strftime("%Y%m%d-%H%M%S")
    rdir = base / "reports"
    rdir.mkdir(parents=True, exist_ok=True)
    items = _alert_findings(base)
    item = next((i for i in items if i["key"] == key), None) if key else (items[0] if items else None)
    if item is None:
        return {"docx": None, "count": 0, "stamp": stamp}
    # Figures the operator captured or uploaded for this finding on the console
    # take precedence over the Vuln DB default list, so the browser-UI evidence
    # of the impersonating domains lands in the document.
    figs = _vmeta_figures(base, item.get("key", ""))
    if figs:
        item["evidence_figures"] = figs
    vuln_name = item.get("vuln_name") or item.get("title") or "Finding"
    out = rdir / f"{name} -Early Alert- {_file_safe(vuln_name)} - {when}_DRAFT.docx"
    ok = write_alert_docx(name, item, when, out)
    return {"docx": str(out) if ok else None, "count": 1, "stamp": stamp}


def build(slug: str, base: Path | None = None) -> dict:
    """Generate both reports plus the appendix for a client. Returns
    {"docx": path|None, "pdf": path|None, "xlsx": path|None, "stamp": str}."""
    base = base or (ENGAGEMENTS / slug)
    data = collect(base)
    name = _pretty(slug)
    now = datetime.now(timezone.utc)
    when = now.strftime("%d %B %Y")
    stamp = now.strftime("%Y%m%d-%H%M%S")
    rdir = base / "reports"
    rdir.mkdir(parents=True, exist_ok=True)
    # SJ report naming convention: "Client Name - Project Name - Date", with the
    # editable Word carrying _DRAFT until it is exported, and the PDF (the export)
    # dropping DRAFT. See the sj-report guidelines.
    project = "External Attack Surface Assessment"
    base_name = f"{name} - {project} - {when}"
    docx_out = rdir / f"{base_name}_DRAFT.docx"
    pdf_out = rdir / f"{base_name}.pdf"
    xlsx_out = rdir / f"{base_name} - Appendix.xlsx"
    ok_docx = write_docx(name, data, when, docx_out)
    ok_pdf = write_pdf(build_html(name, data, when), pdf_out)
    ok_xlsx = write_xlsx(name, data, when, xlsx_out)
    return {"docx": str(docx_out) if ok_docx else None,
            "pdf": str(pdf_out) if ok_pdf else None,
            "xlsx": str(xlsx_out) if ok_xlsx else None, "stamp": stamp}


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate the attack-surface monitoring report")
    ap.add_argument("--slug", required=True, help="client slug (engagement directory name)")
    args = ap.parse_args()
    base = ENGAGEMENTS / args.slug
    if not base.is_dir():
        print(f"[!] no engagement at {base}", file=sys.stderr)
        return 1
    res = build(args.slug, base)
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
