"""
layer3/darkweb_monitor.py — dark web monitoring via Ahmia and ransomware leak sites.

Searches the dark web for mentions of the target using:
  1. Ahmia (public Tor search engine — clearnet accessible)
  2. Ransomware leak site monitoring (requires explicit authorization)

IntelX dark web results land in the DB as their own "darkweb_mention"
findings (layer3/leak_search.py) and are pulled into the report alongside this
module's findings by core/report.py's `_fetch_all_findings` — no need to
re-read or re-aggregate them here.

Ransomware groups maintain public leak sites on Tor where they post
proof-of-compromise and eventually dump exfiltrated data. Monitoring
these reveals breaches before the company is even aware.

Note: ransomware leak site monitoring is only enabled when:
  - scope.mode == "active"
  - DARKWEB_MONITOR=true env var is set
  - Written client authorization confirmed

Ahmia search works without Tor (clearnet proxy).
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
    "name":     "darkweb_monitor",
    "title":    "Dark Web Monitor",
    "description": "Onion search and ransomware leak-site monitoring",
    "layer":    3,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": True,
}

_TIMEOUT = 30

# Known ransomware group leak sites (clearnet mirrors where available)
_RANSOMWARE_SITES = [
    {"group": "LockBit",    "url": "https://lockbit3753ekiocyo5epmpy6klmejchjtzddoekjlnt6mu3qh4de.onion"},
    {"group": "ALPHV/BlackCat", "url": "http://alphvmmm27o3abo3r2mlmjrpdmzle3rykajqc5xsj7j7ejksbpsa36ad.onion"},
    {"group": "Cl0p",       "url": "http://clop2p4cqpqtm23t.onion"},
    {"group": "RansomHub",  "url": "http://ransomhubn2op.onion"},
]


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict       = {}

    company = scope.target.name
    domain  = scope.primary_domain or ""

    # 1. Ahmia clearnet search (no Tor required)
    ahmia_results = await _search_ahmia(company, domain, limiter)
    metadata["ahmia_results"] = len(ahmia_results)
    for result in ahmia_results:
        findings.append({
            "type":  "darkweb_mention",
            "value": result.get("url", ""),
            "data": {
                "title":    result.get("title"),
                "url":      result.get("url"),
                "snippet":  result.get("snippet", "")[:300],
                "source":   "ahmia",
                "severity": "high",
            },
        })

    # 2. Ransomware leak site monitoring (active mode + explicit authorization)
    monitor_enabled = (
        scope.mode == "active"
        and os.environ.get("DARKWEB_MONITOR", "").lower() == "true"
    )
    if monitor_enabled:
        leak_findings = await _check_ransomware_leaks(company, domain, config)
        findings.extend(leak_findings)
        metadata["ransomware_sites_checked"] = len(_RANSOMWARE_SITES)
    else:
        metadata["ransomware_monitoring"] = "disabled (requires active mode + DARKWEB_MONITOR=true)"

    log.info("darkweb.complete", total_findings=len(findings))
    return {
        "module":   "layer3/darkweb_monitor",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _search_ahmia(company: str, domain: str, limiter: RateLimiter) -> list[dict]:
    results = []
    queries = [company, domain] if domain else [company]

    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
        headers     = {"User-Agent": "Mozilla/5.0"}
        extra_field = await _get_ahmia_antibot_field(client, headers, limiter)

        for query in queries:
            await limiter.acquire("default")
            try:
                params = {"q": f'"{query}"'}
                if extra_field:
                    params[extra_field[0]] = extra_field[1]
                r = await client.get(
                    "https://ahmia.fi/search/",
                    params=params,
                    headers=headers,
                )
                r.raise_for_status()
                results.extend(_parse_ahmia_html(r.text, query))
            except Exception as exc:
                log.debug("darkweb.ahmia_failed", query=query, error=str(exc))

    return results


async def _get_ahmia_antibot_field(
    client:  httpx.AsyncClient,
    headers: dict[str, str],
    limiter: RateLimiter,
) -> tuple[str, str] | None:
    """Ahmia's search form includes a hidden honeypot field; submitting a
    search without it gets redirected to the homepage instead of results.
    Fetch the homepage and read the field name/value so it adapts if Ahmia
    changes it."""
    await limiter.acquire("default")
    try:
        r = await client.get("https://ahmia.fi/", headers=headers)
        r.raise_for_status()
        m = re.search(r'<input type="hidden" name="([^"]+)" value="([^"]+)">', r.text)
        if m:
            return m.group(1), m.group(2)
    except Exception as exc:
        log.debug("darkweb.ahmia_antibot_field_failed", error=str(exc))
    return None


# Ahmia results are <li class="result"> blocks containing an <h4><a href="...">
# title</a></h4> and a <p>snippet</p> — extracted per-block so title/url/snippet
# stay aligned even when the page has unrelated <h4>/<p> elements elsewhere.
_RESULT_RE  = re.compile(r'<li class="result">(.*?)</li>', re.DOTALL)
_TITLE_RE   = re.compile(r'<h4[^>]*>(.*?)</h4>', re.DOTALL)
_URL_RE     = re.compile(r'redirect_url=([^"&\s]+\.onion[^"&\s]*)')
_SNIPPET_RE = re.compile(r'</h4>\s*<p[^>]*>(.*?)</p>', re.DOTALL)


def _parse_ahmia_html(html: str, query: str) -> list[dict]:
    results = []

    for block in _RESULT_RE.findall(html)[:20]:
        url_m = _URL_RE.search(block)
        if not url_m:
            continue
        title_m   = _TITLE_RE.search(block)
        snippet_m = _SNIPPET_RE.search(block)
        clean_url     = url_m.group(1)
        clean_title   = re.sub(r"<[^>]+>", "", title_m.group(1)).strip() if title_m else ""
        clean_snippet = re.sub(r"<[^>]+>", "", snippet_m.group(1)).strip() if snippet_m else ""

        if query.lower() in (clean_title + clean_snippet).lower():
            results.append({
                "url":     clean_url,
                "title":   clean_title,
                "snippet": clean_snippet[:300],
                "query":   query,
            })

    return results


async def _check_ransomware_leaks(company: str, domain: str, config) -> list[dict]:
    """
    Check ransomware leak sites via Tor proxy.
    Requires: tor running at localhost:9050 (Docker container in stack).
    """
    from core.network import run_command

    findings = []
    for site in _RANSOMWARE_SITES:
        # Use curl through Tor socks proxy
        result = await run_command(
            [
                "curl", "--socks5", "localhost:9050",
                "--max-time", "30",
                "-s", "-L",
                site["url"],
            ],
            recon_mode="active",
            config=config,
            timeout=40,
        )
        if result.ok and result.stdout:
            content = result.stdout.lower()
            if company.lower() in content or (domain and domain.lower() in content):
                findings.append({
                    "type":  "ransomware_leak_mention",
                    "value": site["group"],
                    "data": {
                        "group":    site["group"],
                        "onion_url": site["url"],
                        "company":  company,
                        "severity": "critical",
                        "note":     f"Company name found on {site['group']} leak site",
                    },
                })
                log.warning("darkweb.ransomware_match",
                            company=company, group=site["group"])

    return findings
