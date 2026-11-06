"""
layer4/epss.py — EPSS (Exploit Prediction Scoring System) enrichment.

For every CVE found by Nuclei, Shodan, or any other module, queries the
FIRST EPSS API to get the probability of exploitation in the next 30 days.

EPSS is the missing context that makes CVSS scores actionable:
  CVSS 7.5 alone → "patch next quarter"
  CVSS 7.5 + EPSS 0.94 + KEV → "patch by end of day"

The EPSS model is trained on actual exploitation telemetry and updated daily.
A score of 0.94 means there is a 94% probability this CVE will be exploited
in the wild in the next 30 days — regardless of CVSS severity.

API: free, no key. https://api.first.org/data/v1/epss
"""
from __future__ import annotations

import time
from typing import Any

import httpx
import structlog

from core.config import Config
from core.ratelimiter import RateLimiter
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "epss",
    "title":    "EPSS Scoring",
    "description": "Probability of exploitation in the next 30 days",
    "layer":    4,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": False,
}

_EPSS_API = "https://api.first.org/data/v1/epss"
_TIMEOUT  = 20
_BATCH    = 30  # CVEs per API request (API supports comma-separated)


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict       = {"cves_enriched": 0}

    # Collect all CVEs from earlier modules
    cves = await _collect_cves(scope, db)
    metadata["cves_found"] = len(cves)

    if not cves:
        return {
            "module":   "layer4/epss",
            "status":   "partial",
            "findings": [],
            "metadata": {"note": "no CVEs found in previous modules"},
            "duration": time.monotonic() - t0,
            "error":    None,
        }

    # Original finding data for each CVE (from nuclei/shodan/wordpress), built once
    cve_contexts = await _build_cve_contexts(scope, db)

    # Batch query EPSS API
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        cve_list = sorted(set(cves))
        for i in range(0, len(cve_list), _BATCH):
            batch = cve_list[i:i + _BATCH]
            await limiter.acquire("default")
            scores = await _fetch_epss(client, batch)

            for score_entry in scores:
                cve     = score_entry.get("cve", "")
                epss    = float(score_entry.get("epss", 0))
                percentile = float(score_entry.get("percentile", 0))
                metadata["cves_enriched"] += 1

                cve_context = cve_contexts.get(cve.upper(), {"cve": cve, "source": "epss_lookup"})

                findings.append({
                    "type":  "epss_score",
                    "value": cve,
                    "data": {
                        "cve":        cve,
                        "epss":       epss,
                        "percentile": percentile,
                        "epss_date":  score_entry.get("date"),
                        "priority":   _epss_priority(epss),
                        "context":    cve_context,
                    },
                })

                log.debug("epss.scored", cve=cve, epss=epss, percentile=percentile)

    # Sort by EPSS score descending — highest exploitation risk first
    findings.sort(key=lambda f: f["data"].get("epss", 0), reverse=True)

    log.info("epss.complete", enriched=metadata["cves_enriched"])
    return {
        "module":   "layer4/epss",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _collect_cves(scope, db) -> list[str]:
    if db is None:
        return []
    cves: set[str] = set()
    try:
        run_id = await db.get_last_run_id(scope.target.name) or ""
        if not run_id:
            return []

        # From nuclei
        for row in await db.get_findings(run_id, "nuclei_finding"):
            data = row.get("data", {})
            for cve in data.get("cve_id", []):
                if cve.upper().startswith("CVE-"):
                    cves.add(cve.upper())

        # From WordPress plugin version-to-CVE mapping
        for row in await db.get_findings(run_id, "wp_plugin_cve"):
            data = row.get("data", {})
            for cve in data.get("cve_id", []):
                if cve.upper().startswith("CVE-"):
                    cves.add(cve.upper())

        # From shodan_cve
        for row in await db.get_findings(run_id, "shodan_cve"):
            cve = row.get("value", "")
            if cve.upper().startswith("CVE-"):
                cves.add(cve.upper())

        # From prefilter signals
        for finding_type in ("js_signals", "searxng", "web_result"):
            for row in await db.get_findings(run_id, finding_type):
                signals = row.get("data", {}).get("signals", {})
                for cve in signals.get("cves", []):
                    cves.add(cve.upper())

    except Exception as exc:
        log.debug("epss.collect_failed", error=str(exc))
    return sorted(cves)


async def _fetch_epss(client, cve_list: list[str]) -> list[dict]:
    try:
        r = await client.get(
            _EPSS_API,
            params={"cve": ",".join(cve_list), "scope": "public"},
        )
        r.raise_for_status()
        return r.json().get("data", [])
    except Exception as exc:
        log.warning("epss.api_failed", error=str(exc))
        return []


def _epss_priority(epss: float) -> str:
    if epss >= 0.9:
        return "critical"
    if epss >= 0.5:
        return "high"
    if epss >= 0.1:
        return "medium"
    return "low"


async def _build_cve_contexts(scope, db) -> dict[str, dict]:
    """
    Map each CVE to the finding that originally surfaced it, so the EPSS
    score can be correlated back to a specific host/severity rather than
    standing alone as an abstract CVE-level score.
    """
    contexts: dict[str, dict] = {}
    if db is None:
        return contexts
    try:
        run_id = await db.get_last_run_id(scope.target.name) or ""
        if not run_id:
            return contexts

        for row in await db.get_findings(run_id, "nuclei_finding"):
            data = row.get("data", {})
            for cve in data.get("cve_id", []):
                cve = cve.upper()
                if cve.startswith("CVE-") and cve not in contexts:
                    contexts[cve] = {
                        "cve":         cve,
                        "source":      "nuclei",
                        "host":        data.get("host"),
                        "severity":    data.get("severity"),
                        "cvss_score":  data.get("cvss_score"),
                        "template_id": data.get("template_id"),
                        "name":        data.get("name"),
                    }

        for row in await db.get_findings(run_id, "wp_plugin_cve"):
            data = row.get("data", {})
            for cve in data.get("cve_id", []):
                cve = cve.upper()
                if cve.startswith("CVE-") and cve not in contexts:
                    contexts[cve] = {
                        "cve":      cve,
                        "source":   "wp_plugin_cve",
                        "host":     data.get("host"),
                        "severity": data.get("severity"),
                        "plugin":   data.get("plugin"),
                        "version":  data.get("version"),
                    }

        for row in await db.get_findings(run_id, "shodan_cve"):
            cve = row.get("value", "").upper()
            if cve.startswith("CVE-") and cve not in contexts:
                data = row.get("data", {})
                contexts[cve] = {
                    "cve":      cve,
                    "source":   "shodan",
                    "host":     data.get("ip"),
                    "port":     data.get("port"),
                    "severity": data.get("severity"),
                }
    except Exception as exc:
        log.debug("epss.context_build_failed", error=str(exc))
    return contexts
