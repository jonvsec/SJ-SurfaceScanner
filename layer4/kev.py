"""
layer4/kev.py — CISA Known Exploited Vulnerabilities catalog.

Downloads the CISA KEV catalog (updated daily) and cross-references all
CVEs discovered in the scan. A CVE in KEV means it has been confirmed
as actively exploited in the wild by CISA's threat intelligence teams.

KEV status changes the conversation completely:
  Not in KEV → "we should patch this"
  In KEV      → "threat actors are actively using this right now"

Combined with EPSS: EPSS gives probability, KEV gives confirmed reality.
A CVE with EPSS=0.3 but in KEV (confirmed exploitation) gets immediate priority
over EPSS=0.6 but not in KEV (predicted but not yet confirmed).

KEV catalog: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
Free, no key, updated daily.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import httpx
import structlog

from core.config import Config
from core.ratelimiter import RateLimiter
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "kev",
    "title":    "CISA KEV",
    "description": "Confirmed actively-exploited vulnerabilities",
    "layer":    4,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": False,
}

_KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_TIMEOUT  = 30
_CACHE_FILE = Path("/tmp/surfacescanner_kev_cache.json")


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict       = {}

    # Download KEV catalog (cache for 24h)
    kev_catalog = await _get_kev_catalog(limiter)
    metadata["kev_total_entries"] = len(kev_catalog)

    if not kev_catalog:
        return {
            "module":   "layer4/kev",
            "status":   "error",
            "findings": [],
            "metadata": {},
            "duration": time.monotonic() - t0,
            "error":    "failed to download KEV catalog",
        }

    # Build lookup dict: CVE-ID → KEV entry
    kev_lookup = {entry["cveID"].upper(): entry for entry in kev_catalog}

    # Get all CVEs from scan findings
    scan_cves = await _collect_scan_cves(scope, db)
    metadata["scan_cves"] = len(scan_cves)

    kev_hits = 0
    for cve in scan_cves:
        if cve.upper() in kev_lookup:
            kev_hits += 1
            entry = kev_lookup[cve.upper()]
            findings.append({
                "type":  "kev_match",
                "value": cve.upper(),
                "data": {
                    "cve":               cve.upper(),
                    "vendor_project":    entry.get("vendorProject"),
                    "product":           entry.get("product"),
                    "vulnerability_name": entry.get("vulnerabilityName"),
                    "date_added":        entry.get("dateAdded"),
                    "short_description": entry.get("shortDescription", "")[:500],
                    "required_action":   entry.get("requiredAction"),
                    "due_date":          entry.get("dueDate"),
                    "known_ransomware":  entry.get("knownRansomwareCampaignUse", "Unknown"),
                    "notes":             entry.get("notes", "")[:300],
                    "severity":          "critical",
                },
            })
            log.warning("kev.match_found", cve=cve, product=entry.get("product"))

    metadata["kev_matches"] = kev_hits

    # Also look for KEV CVEs that match our target's technology stack
    tech_kev = await _kev_by_technology(scope, db, kev_catalog)
    findings.extend(tech_kev)
    metadata["tech_kev_matches"] = len(tech_kev)

    log.info("kev.complete", matches=kev_hits, tech_matches=len(tech_kev))
    return {
        "module":   "layer4/kev",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _get_kev_catalog(limiter: RateLimiter) -> list[dict]:
    import json

    # Use cache if fresh (< 24h)
    if _CACHE_FILE.exists():
        age = time.time() - _CACHE_FILE.stat().st_mtime
        if age < 86400:
            try:
                return json.loads(_CACHE_FILE.read_text()).get("vulnerabilities", [])
            except Exception:
                pass

    await limiter.acquire("default")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            r = await client.get(_KEV_URL)
            r.raise_for_status()
            data = r.json()
            _CACHE_FILE.write_text(r.text)
            return data.get("vulnerabilities", [])
    except Exception as exc:
        log.error("kev.download_failed", error=str(exc))
        return []


async def _collect_scan_cves(scope, db) -> list[str]:
    if db is None:
        return []
    cves: set[str] = set()
    try:
        run_id = await db.get_last_run_id(scope.target.name) or ""
        if not run_id:
            return []
        for ftype in ("nuclei_finding", "shodan_cve", "epss_score", "wp_plugin_cve"):
            rows = await db.get_findings(run_id, ftype)
            for row in rows:
                cve = row.get("value", "")
                if cve.upper().startswith("CVE-"):
                    cves.add(cve.upper())
                # Also from nested data
                for c in row.get("data", {}).get("cve_id", []):
                    if c.upper().startswith("CVE-"):
                        cves.add(c.upper())
    except Exception:
        pass
    return sorted(cves)


async def _kev_by_technology(scope, db, kev_catalog: list[dict]) -> list[dict]:
    """Find KEV entries for technologies identified in the scan."""
    findings = []
    if db is None:
        return findings
    try:
        run_id = await db.get_last_run_id(scope.target.name) or ""
        if not run_id:
            return findings
        # Get detected technologies
        tech_rows = await db.get_findings(run_id, "technology")
        tech_names = {r.get("value", "").lower() for r in tech_rows}
        cms_rows   = await db.get_findings(run_id, "cms_detected")
        tech_names.update(r.get("data", {}).get("cms", "").lower() for r in cms_rows)

        for entry in kev_catalog:
            product = (entry.get("product") or "").lower()
            vendor  = (entry.get("vendorProject") or "").lower()
            if any(t and (t in product or t in vendor) for t in tech_names if t):
                findings.append({
                    "type":  "kev_technology_match",
                    "value": entry["cveID"].upper(),
                    "data": {
                        "cve":        entry["cveID"].upper(),
                        "product":    entry.get("product"),
                        "vendor":     entry.get("vendorProject"),
                        "name":       entry.get("vulnerabilityName"),
                        "date_added": entry.get("dateAdded"),
                        "ransomware": entry.get("knownRansomwareCampaignUse"),
                        "severity":   "critical",
                        "note":       "Technology detected in target — KEV entry exists",
                    },
                })
    except Exception:
        pass
    return findings[:20]  # cap
