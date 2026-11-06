"""
layer2_5/web_archive.py — Wayback Machine CDX API for historical URL discovery.

Queries the Wayback CDX API for all archived URLs of target domains.
Historical snapshots reveal:
  - Old API versions still in production (often no authentication)
  - Removed pages with sensitive content still indexed
  - Historical subdomains and paths no longer in DNS
  - Technology changes over time (when did they add CloudFlare? Change auth?)
  - Deleted configuration files and backups that were briefly public

API: free, no key. CDX API is public. Rate limit: polite requests only.
"""
from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog

from core.config import Config
from core.ratelimiter import RateLimiter
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "web_archive",
    "title":    "Web Archive",
    "description": "Historical URLs and parameters via Wayback CDX",
    "layer":    2.5,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": True,
}

_CDX_BASE = "https://web.archive.org/cdx/search/cdx"
_TIMEOUT  = 30

# URL patterns worth flagging
_INTERESTING_PATTERNS = re.compile(
    r"(?:\.env|\.git|\.aws|\.ssh|/admin|/backup|/config|/swagger|"
    r"/api-docs|/actuator|/debug|phpmyadmin|wp-admin|/\.well-known/|"
    r"password|secret|credential|backup\.|\.sql|\.bak|\.dump)",
    re.IGNORECASE,
)


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict       = {"domains_queried": 0, "urls_found": 0}

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        for domain in scope.all_domains:
            metadata["domains_queried"] += 1
            urls = await _fetch_cdx(client, domain, limiter)
            metadata["urls_found"] += len(urls)

            # Deduplicate and categorise
            seen: set[str] = set()
            for url_entry in urls:
                url      = url_entry.get("url", "")
                if url in seen or not url:
                    continue
                seen.add(url)

                category = _categorise(url)
                finding  = {
                    "type":  category,
                    "value": url,
                    "data": {
                        "url":         url,
                        "timestamp":   url_entry.get("timestamp"),
                        "status_code": url_entry.get("statuscode"),
                        "mimetype":    url_entry.get("mimetype"),
                        "domain":      domain,
                        "source":      "wayback_cdx",
                    },
                }

                # Always include interesting URLs
                if _INTERESTING_PATTERNS.search(url):
                    finding["data"]["flagged"] = True
                    finding["data"]["severity"] = "medium"

                findings.append(finding)

    log.info("wayback.complete", urls=metadata["urls_found"])
    return {
        "module":   "layer2_5/web_archive",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _fetch_cdx(
    client:  httpx.AsyncClient,
    domain:  str,
    limiter: RateLimiter,
) -> list[dict]:
    await limiter.acquire("default")
    try:
        r = await client.get(
            _CDX_BASE,
            params={
                "url":       f"*.{domain}/*",
                "output":    "json",
                "fl":        "timestamp,statuscode,mimetype,original",
                "collapse":  "urlkey",
                "limit":     "5000",
                "filter":    "statuscode:200",
            },
        )
        r.raise_for_status()
        rows = r.json()
        if not rows or len(rows) < 2:
            return []

        # First row is headers
        headers = rows[0]
        entries = []
        for row in rows[1:]:
            entry = dict(zip(headers, row))
            entry["url"] = entry.pop("original", "")
            entries.append(entry)
        return entries
    except Exception as exc:
        log.warning("wayback.cdx_failed", domain=domain, error=str(exc) or repr(exc))
        return []


def _categorise(url: str) -> str:
    if _INTERESTING_PATTERNS.search(url):
        return "wayback_sensitive"
    parsed = urlparse(url)
    path   = parsed.path.lower()
    if path.endswith((".pdf", ".doc", ".docx", ".xls", ".xlsx")):
        return "wayback_document"
    if path.endswith((".js", ".ts")):
        return "wayback_javascript"
    if "/api/" in path or path.startswith("/v"):
        return "wayback_api"
    return "wayback_url"
