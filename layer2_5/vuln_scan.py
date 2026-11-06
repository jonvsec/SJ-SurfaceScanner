"""
layer2_5/vuln_scan.py — Nuclei vulnerability scanning.

Runs Nuclei (ProjectDiscovery) template engine against discovered hosts.
Template selection by mode:
  semi   → safe templates only: exposures, misconfigs, info, tech detection
  active → full suite including CVE templates and aggressive checks

Every Nuclei CVE finding is cross-referenced with EPSS + CISA KEV in Layer 4.
A CVSS 7.5 finding becomes actionable when EPSS is 94% + KEV confirms active
exploitation — this is the key differentiator vs. raw scanner output.

CLI tool required: nuclei (from ProjectDiscovery).
Active mode routes via VPS (NEVER runs locally — enforced in core/network.py).
"""
from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path
from typing import Any

import structlog

from core.config import Config
from core.network import run_command
from core.scope_guard import filter_in_scope
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "vuln_scan",
    "title":    "Vulnerability Scan",
    "description": "Template-driven CVE and misconfiguration detection",
    "layer":    2.5,
    "mode":     ["semi", "active"],
    "requires": [],
    "optional": True,
}

# Template categories by mode
# Template paths are relative to the nuclei templates directory, which is
# organised by protocol first (http/, ssl/, dns/, network/). The previous
# values ("exposures/", "cves/", …) match nothing on disk, so every nuclei
# invocation selected zero templates and the module reported no findings —
# indistinguishable from a clean result.
_SEMI_TEMPLATES = [
    "http/exposures/",        # 697  — exposed files, configs, backups
    "http/misconfiguration/", # 980  — server and app misconfigurations
    "http/technologies/",     # 907  — stack fingerprinting
    "http/default-logins/",   # 303  — default credential checks
    "http/takeovers/",        #  73  — dangling CNAME takeover
    "ssl/",                   #  38  — TLS/certificate issues
    "dns/",                   #  31  — DNS misconfiguration
]
_ACTIVE_TEMPLATES = [
    "http/cves/",             # 4160 — CVE detection
    "http/vulnerabilities/",  #  939 — exploitable vulnerabilities
    "http/exposed-panels/",   # 1555 — admin/login panel discovery
    "network/",               #  280 — non-HTTP service checks
]


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0        = time.monotonic()
    findings: list[dict] = []
    metadata: dict       = {"hosts_scanned": 0, "vulnerabilities": 0}

    hosts = await _get_hosts(scope, db)
    metadata["hosts_scanned"] = len(hosts)

    if not hosts:
        return {
            "module":   "layer2_5/vuln_scan",
            "status":   "partial",
            "findings": [],
            "metadata": {"note": "no resolved hosts to scan"},
            "duration": time.monotonic() - t0,
            "error":    None,
        }

    templates = _SEMI_TEMPLATES[:]
    if scope.mode == "active":
        templates.extend(_ACTIVE_TEMPLATES)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(f"https://{h}" for h in hosts[:200]))
        targets_file = Path(f.name)

    try:
        for template_path in templates:
            cmd = [
                "nuclei",
                "-l",    str(targets_file),
                "-t",    template_path,
                "-silent", "-jsonl", "-no-color",
                "-rate-limit", "50",
                "-timeout", "10",
                "-retries", "1",
            ]

            result = await run_command(
                cmd,
                recon_mode=scope.mode,
                config=config,
                timeout=config.timeouts.nuclei,
            )

            if not result.ok and not result.stdout.strip():
                if "not found" in result.stderr:
                    log.warning("nuclei.not_installed")
                    break
                continue

            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    hit = json.loads(line)
                    finding = _parse_nuclei_hit(hit)
                    if finding:
                        findings.append(finding)
                        if hit.get("info", {}).get("severity") in ("critical", "high", "medium"):
                            metadata["vulnerabilities"] += 1
                except json.JSONDecodeError:
                    pass
    finally:
        targets_file.unlink(missing_ok=True)

    log.info("nuclei.complete", hosts=len(hosts), findings=len(findings))
    return {
        "module":   "layer2_5/vuln_scan",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _get_hosts(scope: Scope, db: Any) -> list[str]:
    hosts: set[str] = set(scope.all_domains)
    if db is not None:
        try:
            run_id = await db.get_last_run_id(scope.target.name) or ""
            if run_id:
                rows = await db.get_findings(run_id, "resolved_host")
                hosts.update(r["value"] for r in rows if r.get("value"))
        except Exception:
            pass
    # Hosts from the DB are runtime discoveries and may include domains the
    # client never authorised. Never hand an unauthorised host to a tool that
    # sends traffic.
    return sorted(filter_in_scope(hosts, scope, module=__name__))


def _parse_nuclei_hit(hit: dict) -> dict | None:
    info   = hit.get("info", {})
    cve_id = info.get("classification", {}).get("cve-id", [])

    # Nuclei CVE templates match on a version string, banner, or response
    # fingerprint — they confirm the vulnerable VERSION is present, not that
    # the vulnerability is actually exploitable on this target. Treat every
    # CVE match as a pattern match pending manual verification (baseline
    # Rule: CVE pattern-match vs confirmed exploitation).
    requires_manual_verification = bool(cve_id)

    return {
        "type":  "nuclei_finding",
        "value": hit.get("host", ""),
        "data": {
            "template_id": hit.get("template-id"),
            "name":        info.get("name"),
            "severity":    info.get("severity"),
            "cvss_score":  info.get("classification", {}).get("cvss-score"),
            "cve_id":      cve_id,
            "cwe_id":      info.get("classification", {}).get("cwe-id", []),
            "host":        hit.get("host"),
            "matched_at":  hit.get("matched-at"),
            "type":        hit.get("type"),
            "tags":        info.get("tags", []),
            "reference":   info.get("reference", []),
            "requires_manual_verification": requires_manual_verification,
            "verification_note": (
                "Nuclei matched this CVE via signature/version detection — "
                "this confirms the vulnerable version string is present, not "
                "that exploitation succeeded. Manually verify before reporting "
                "as a confirmed vulnerability."
            ) if requires_manual_verification else None,
        },
    }
