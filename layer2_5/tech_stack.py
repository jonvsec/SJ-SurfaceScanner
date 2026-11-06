"""
layer2_5/tech_stack.py — technology stack detection via BuiltWith and Wappalyzer.

BuiltWith provides historical technology usage data not available from live
HTTP responses — including technologies removed months ago.

Detection approach:
  1. BuiltWith free API (no key, limited data)
  2. BuiltWith API v14 (BUILTWITH_API_KEY — unlocks full history)
  3. Wappalyzer patterns via httpx (no external API needed)

Technology history from BuiltWith reveals:
  - Previous WAF/CDN providers (often misconfigured during migration)
  - Deprecated tech still in use on sub-paths
  - Stack changes that suggest technical debt or rushed migrations
"""
from __future__ import annotations

import os
import re
import time
from typing import Any

import httpx
import structlog

from core.config import Config
from core.ratelimiter import RateLimiter
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "tech_stack",
    "title":    "Technology Stack",
    "description": "Current and historical stack fingerprinting",
    "layer":    2.5,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": True,
}

_TIMEOUT = 20

# Wappalyzer-style fingerprints (subset — key technologies)
_WAPPALYZER_PATTERNS: list[dict] = [
    {"name": "React",        "pattern": r"react(?:\.min)?\.js|__react_fiber|React\.createElement"},
    {"name": "Angular",      "pattern": r"ng-version=|angular(?:\.min)?\.js"},
    {"name": "Vue.js",       "pattern": r"vue(?:\.min)?\.js|data-v-[a-f0-9]+"},
    {"name": "Next.js",      "pattern": r"/_next/|__NEXT_DATA__"},
    {"name": "Nuxt.js",      "pattern": r"/_nuxt/|__nuxt"},
    {"name": "jQuery",       "pattern": r"jquery(?:\.min)?\.js|jQuery v(\d[\d.]+)"},
    {"name": "Bootstrap",    "pattern": r"bootstrap(?:\.min)?\.(?:css|js)"},
    {"name": "WordPress",    "pattern": r"/wp-content/|/wp-includes/"},
    {"name": "Shopify",      "pattern": r"cdn\.shopify\.com|Shopify\.theme"},
    {"name": "Google Analytics", "pattern": r"google-analytics\.com/analytics|gtag\("},
    {"name": "Cloudflare",   "pattern": r"cloudflare(?:insights|rocket)"},
    {"name": "Intercom",     "pattern": r"intercomcdn|window\.intercomSettings"},
    {"name": "Segment",      "pattern": r"segment\.com/analytics|analytics\.js"},
    {"name": "Sentry",       "pattern": r"sentry\.io|@sentry/browser"},
    {"name": "Datadog RUM",  "pattern": r"datadoghq\.com/rum|DD_RUM"},
    {"name": "Stripe",       "pattern": r"js\.stripe\.com"},
    {"name": "Twilio",       "pattern": r"twilio\.com|Twilio\.Device"},
    {"name": "HubSpot",      "pattern": r"hs-scripts\.com|hubspot\.com"},
]


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict       = {}

    api_key = os.environ.get("BUILTWITH_API_KEY")

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        for domain in scope.all_domains:
            # BuiltWith API
            if api_key:
                bw_data = await _builtwith_api(client, domain, api_key, limiter)
                if bw_data:
                    findings.extend(bw_data)
            else:
                # Free endpoint (very limited)
                bw_free = await _builtwith_free(client, domain, limiter)
                findings.extend(bw_free)

            # Wappalyzer-style fingerprinting via page content
            wap_findings = await _wappalyzer_check(client, domain, limiter)
            findings.extend(wap_findings)

    metadata["findings"] = len(findings)
    return {
        "module":   "layer2_5/tech_stack",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _builtwith_api(client, domain, api_key, limiter) -> list[dict]:
    await limiter.acquire("default")
    try:
        r = await client.get(
            "https://api.builtwith.com/v21/api.json",
            params={"KEY": api_key, "LOOKUP": domain},
        )
        r.raise_for_status()
        data  = r.json()
        techs = []
        for result in data.get("Results", []):
            for path in result.get("Result", {}).get("Paths", []):
                for tech in path.get("Technologies", []):
                    techs.append({
                        "type":  "technology",
                        "value": tech.get("Name", ""),
                        "data": {
                            "domain":      domain,
                            "name":        tech.get("Name"),
                            "description": tech.get("Description"),
                            "categories":  tech.get("Categories", []),
                            "first_detected": tech.get("FirstDetected"),
                            "last_detected":  tech.get("LastDetected"),
                            "source":      "builtwith_api",
                        },
                    })
        return techs
    except Exception as exc:
        log.debug("builtwith.api_failed", domain=domain, error=str(exc))
        return []


async def _builtwith_free(client, domain, limiter) -> list[dict]:
    await limiter.acquire("default")
    try:
        r = await client.get(
            "https://api.builtwith.com/free1/api.json",
            params={"KEY": "free", "LOOKUP": domain},
        )
        if r.status_code != 200:
            return []
        data = r.json()
        techs = []
        for group in data.get("groups", []):
            for tech in group.get("categories", []):
                techs.append({
                    "type":  "technology",
                    "value": tech.get("name", ""),
                    "data": {
                        "domain":  domain,
                        "name":    tech.get("name"),
                        "source":  "builtwith_free",
                    },
                })
        return techs
    except Exception:
        return []


async def _wappalyzer_check(client, host, limiter) -> list[dict]:
    await limiter.acquire("default")
    try:
        r = await client.get(f"https://{host}", timeout=10)
        content   = r.text
        headers   = str(r.headers)
        full_text = content + headers
        findings  = []
        for fp in _WAPPALYZER_PATTERNS:
            if re.search(fp["pattern"], full_text, re.IGNORECASE):
                findings.append({
                    "type":  "technology",
                    "value": fp["name"],
                    "data": {
                        "domain": host,
                        "name":   fp["name"],
                        "source": "wappalyzer_pattern",
                    },
                })
        return findings
    except Exception:
        return []
