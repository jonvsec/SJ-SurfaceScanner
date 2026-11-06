#!/usr/bin/env python3
"""
tools/lookalike_report.py — the first-report lookalike deliverable, as an Excel file.

WHAT THIS IS
------------
The lookalike pipeline keeps a big pool of every name an attacker could register
against a client brand. This tool exports that whole pool to an Excel workbook,
which is the spreadsheet half of the first EAS report. The ongoing watcher
(tools/lookalike_watch.py) is separate: it only reports a domain to JOES AIR when
one of these candidates actually triggers.

    python tools/lookalike_report.py --scope scopes/acme.yaml
    python tools/lookalike_report.py --scope scopes/acme.yaml --mode semi \
        --out outputs/acme-lookalike-domains.xlsx

Sheets:
  All Candidates        every name in the monitored pool, with registration
                        status and, where registered, the risk.
  Registered Lookalikes the names that exist today, scored and sorted.
  Summary               counts by severity and by technique.

Pure scripting, no AI. The candidate pool is dnstwist's full generation plus the
Cyrillic/Greek homoglyphs and domain-hack forms dnstwist does not emit.
"""
from __future__ import annotations

import argparse
import asyncio
import csv as csvmod
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import load_config                                   # noqa: E402
from layer1 import brand_protection, newly_registered_domains          # noqa: E402
from layer1 import _lookalike_common as lc                             # noqa: E402
from scope_parser import load_scope                                    # noqa: E402

try:
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter
except ImportError:
    openpyxl = None

# House style for the asset-inventory workbook deliverable.
FONT_NAME = "Abadi"
FONT_SIZE = 11
HEADER_FILL = "FF5D5D"          # the salmon-red header band used across that workbook
HEADER_TEXT = "FFFFFF"

# Severity fills sampled from the JOES AIR portal severity palette so the sheet
# reads the same as the platform. SEV1 Critical, SEV2 High, SEV3 Medium,
# SEV4 Low, SEV5 Info.
SEV_FILL = {"SEV1": "F3415E", "SEV2": "FB913E", "SEV3": "FBBE29",
            "SEV4": "3BBBF8", "SEV5": "607085"}
SEV_TEXT = {"SEV1": "FFFFFF", "SEV2": "000000", "SEV3": "000000",
            "SEV4": "000000", "SEV5": "FFFFFF"}


def _clean(v):
    """Strip em dashes and semicolons from any string written to the workbook."""
    if isinstance(v, str):
        v = v.replace(" — ", ", ").replace(" – ", ", ").replace("—", ", ").replace("–", "-")
        v = v.replace("; ", ". ").replace(";", ".")
    return v


def _base_font(**kw):
    return Font(name=FONT_NAME, size=FONT_SIZE, **kw)


def _note(d: dict) -> str:
    """A plain-English assessment of one registered lookalike, senior-researcher tone."""
    s: list[str] = []
    if d.get("mail_capable"):
        s.append("Carries live MX records, so it could send and receive mail as the brand "
                 "and sits one step from an email phishing campaign.")
    if d.get("serves_login"):
        s.append("Serves a login form, which is consistent with credential harvesting.")
    if d.get("visual_match"):
        s.append("The served page is a close visual match to the genuine site.")
    if d.get("favicon_match"):
        s.append("Reuses the brand favicon.")
    if d.get("dns_a"):
        s.append("Resolves to a live host at " + ", ".join(d["dns_a"]) + ".")
    else:
        s.append("Registered but does not resolve at this time.")
    ns = d.get("dns_ns") or []
    if ns:
        s.append("Nameservers sit outside the organisation estate (" + ", ".join(ns[:3]) + ").")
    reg, created = d.get("registrar"), d.get("created")
    if reg or created:
        line = "Registered"
        if reg:
            line += " through " + str(reg)
        if created:
            line += " on " + str(created)[:10]
        s.append(line + ".")
    if d.get("severity") == "info" and d.get("age_days") is not None:
        s.append("The registration is aged and shows no mail and no active content, so it is "
                 "treated as dormant and monitored for change rather than raised as a live threat.")
    return _clean(" ".join(s))


def _decode_idn(host: str) -> str:
    try:
        return ".".join(
            p.encode("ascii").decode("idna") if p.startswith("xn--") else p
            for p in host.split(".")
        )
    except Exception:
        return host


def _candidate_pool(domains: list[str], timeout: int) -> dict[str, dict]:
    """The full monitored pool: dnstwist generation + our IDN and domain-hack forms."""
    pool: dict[str, dict] = {}
    for d in domains:
        try:
            raw = subprocess.run(
                ["dnstwist", "--format", "csv", d],
                capture_output=True, text=True, timeout=timeout,
            ).stdout
        except Exception as exc:
            print(f"[!] dnstwist generation failed for {d}: {exc}", file=sys.stderr)
            raw = ""
        for row in csvmod.reader(raw.splitlines()):
            if len(row) < 2 or row[0] in ("fuzzer", "*original"):
                continue
            host = row[1].strip().lower()
            if host:
                pool.setdefault(host, {"technique": row[0], "unicode": _decode_idn(host)})
    for d in domains:
        for v in lc.homoglyph_idn_variants(d):
            pool.setdefault(v["punycode"],
                            {"technique": "homoglyph-cyrillic/greek", "unicode": v["unicode"]})
    for h in lc.domain_hack_variants(domains):
        pool.setdefault(h, {"technique": "domain-hack", "unicode": h})
    for c in lc.combosquat_variants(domains):
        pool.setdefault(c, {"technique": "combosquatting", "unicode": c})
    for t in lc.tld_substitution_variants(domains):
        pool.setdefault(t, {"technique": "tld-substitution", "unicode": t})
    return pool


async def _registered(scope, cfg) -> list[dict]:
    findings = []
    for mod in (brand_protection, newly_registered_domains):
        r = await mod.run(scope, cfg, db=None)
        findings += r.get("findings", [])
    return findings


def _header(ws, labels, Font, PatternFill, Alignment, Border, Side):
    fill = PatternFill("solid", fgColor=HEADER_FILL)
    font = _base_font(bold=True, color=HEADER_TEXT)
    thin = Side(style="thin", color="D9D9D9")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    for c, label in enumerate(labels, 1):
        cell = ws.cell(1, c, label)
        cell.fill = fill
        cell.font = font
        cell.alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
        cell.border = border
    return border


def _build_workbook(scope, pool: dict, findings: list, out: Path) -> dict:
    registered = {f["value"].lower(): f["data"] for f in findings}
    thin = Side(style="thin", color="D9D9D9")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    reg_fill = PatternFill("solid", fgColor="C6EFCE")

    wb = openpyxl.Workbook()

    # Sheet 1: All Candidates
    ws = wb.active
    ws.title = "All Candidates"
    cols1 = ["Candidate (as shown)", "Registrable name", "Technique", "Status",
             "Severity if registered", "Resolved IP", "Mail"]
    _header(ws, cols1, Font, PatternFill, Alignment, Border, Side)
    items = sorted(pool.items(), key=lambda kv: (kv[0] not in registered, kv[1]["unicode"]))
    r = 2
    for host, meta in items:
        reg = registered.get(host)
        sev = reg.get("sev_platform") if reg else ""
        vals = [meta["unicode"], host, meta["technique"],
                "Registered" if reg else "Not registered", sev,
                ", ".join(reg.get("dns_a") or []) if reg else "",
                ("Yes" if reg.get("mail_capable") else "No") if reg else ""]
        for c, v in enumerate(vals, 1):
            cell = ws.cell(r, c, _clean(v))
            cell.font = _base_font()
            cell.border = border
        if reg:
            ws.cell(r, 4).fill = reg_fill
            if sev in SEV_FILL:
                sc = ws.cell(r, 5)
                sc.fill = PatternFill("solid", fgColor=SEV_FILL[sev])
                sc.font = _base_font(bold=True, color=SEV_TEXT[sev])
                sc.alignment = Alignment(horizontal="center")
        r += 1
    for c, w in enumerate([34, 36, 26, 15, 20, 18, 7], 1):
        ws.column_dimensions[get_column_letter(c)].width = w
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:{get_column_letter(len(cols1))}{max(r - 1, 1)}"

    # Sheet 2: Registered Lookalikes
    ws2 = wb.create_sheet("Registered Lookalikes")
    cols2 = ["Lookalike Domain", "Platform Severity", "Internal Severity", "Technique",
             "Mail Capable", "Serves Login", "Favicon Match", "Visual Match",
             "Resolved IPs", "Nameservers", "Registrar", "Registered", "Age (days)",
             "Source", "Assessment"]
    _header(ws2, cols2, Font, PatternFill, Alignment, Border, Side)
    order = {"SEV1": 1, "SEV2": 2, "SEV3": 3, "SEV4": 4, "SEV5": 5}
    rows2 = sorted(findings, key=lambda f: order.get(f["data"].get("sev_platform"), 9))
    note_col = len(cols2)
    for i, f in enumerate(rows2, 2):
        d = f["data"]
        vals = [f["value"], d.get("sev_platform"), d.get("severity"), d.get("fuzzer"),
                "Yes" if d.get("mail_capable") else "No",
                "Yes" if d.get("serves_login") else "No",
                "Yes" if d.get("favicon_match") else "No",
                "Yes" if d.get("visual_match") else "No",
                ", ".join(d.get("dns_a") or []), ", ".join(d.get("dns_ns") or []),
                d.get("registrar") or "", d.get("created") or "",
                d.get("age_days") if d.get("age_days") is not None else "",
                d.get("source"), _note(d)]
        for c, v in enumerate(vals, 1):
            cell = ws2.cell(i, c, _clean(v))
            cell.font = _base_font()
            cell.border = border
            cell.alignment = Alignment(vertical="top", wrap_text=(c == note_col))
            if c == 2 and v in SEV_FILL:
                cell.fill = PatternFill("solid", fgColor=SEV_FILL[v])
                cell.font = _base_font(bold=True, color=SEV_TEXT[v])
                cell.alignment = Alignment(horizontal="center", vertical="center")
    for c, w in enumerate([26, 16, 15, 16, 12, 12, 13, 12, 24, 28, 20, 13, 11, 14, 72], 1):
        ws2.column_dimensions[get_column_letter(c)].width = w
    ws2.freeze_panes = "A2"
    ws2.auto_filter.ref = f"A1:{get_column_letter(len(cols2))}{len(rows2) + 1}"

    bysev: dict = {}
    for f in findings:
        k = f["data"].get("sev_platform")
        bysev[k] = bysev.get(k, 0) + 1

    out.parent.mkdir(parents=True, exist_ok=True)
    wb.save(out)
    return {"candidates": len(pool), "registered": len(registered), "by_severity": bysev}


def main() -> int:
    if openpyxl is None:
        print("[!] openpyxl is required (pip install openpyxl).", file=sys.stderr)
        return 3
    ap = argparse.ArgumentParser(description="Export the lookalike candidate pool to Excel.")
    ap.add_argument("--scope", required=True, type=Path)
    ap.add_argument("--mode", choices=["passive", "semi", "active"], default="semi",
                    help="semi+ enables page/favicon enrichment on the registered ones")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--gen-timeout", type=int, default=120, help="dnstwist generation timeout")
    args = ap.parse_args()

    if not args.scope.is_file():
        print(f"[!] scope file not found: {args.scope}", file=sys.stderr)
        return 2

    cfg = load_config()
    scope = load_scope(args.scope)
    scope.mode = args.mode
    cfg.use_engagement(scope.target.name)   # per-client directory under DATA/engagements/<slug>
    out = args.out or cfg.paths["reports"] / f"{args.scope.stem}-lookalike-domains.xlsx"
    out.parent.mkdir(parents=True, exist_ok=True)

    pool = _candidate_pool(scope.all_domains, args.gen_timeout)
    findings = asyncio.run(_registered(scope, cfg))
    summary = _build_workbook(scope, pool, findings, out)

    print(f"[i] wrote {out}")
    print(f"[i] candidate pool {summary['candidates']}, registered {summary['registered']}, "
          f"by severity {summary['by_severity']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
