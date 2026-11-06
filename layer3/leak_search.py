"""
layer3/leak_search.py — IntelligenceX dark web and leak intelligence.

IntelligenceX indexes Tor sites, paste sites, Telegram channels, data
breaches, and darknet marketplaces. It finds:
  - Leaked credential dumps containing @domain.com accounts
  - Paste site posts mentioning the company or its infrastructure
  - Dark web forum discussions about the target
  - Telegram leak channel archives

This is the most comprehensive dark web source available via API.
Results are pre-filtered and structured — no Tor browser required.

Rate limit: 1 req/sec. Requires INTELX_API_KEY (paid).
"""
from __future__ import annotations

import asyncio
import os
import time
from typing import Any

import httpx
import structlog

from core.config import Config
from core.ratelimiter import RateLimiter
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "leak_search",
    "title":    "Leak Search",
    "description": "Dark web, paste and Telegram leak intelligence",
    "layer":    3,
    "mode":     ["passive", "semi", "active"],
    "requires": ["INTELX_API_KEY"],
    "optional": True,
}

_BASE    = "https://2.intelx.io"
_TIMEOUT = 30


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    api_key = os.environ.get("INTELX_API_KEY", "")
    limiter = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict       = {"queries": 0, "results": 0}

    headers = {"x-key": api_key}

    async with httpx.AsyncClient(timeout=_TIMEOUT, headers=headers) as client:
        # Search terms: domain, company name, executive emails
        search_terms = list(scope.all_domains) + [scope.target.name]
        search_terms += scope.emails[:5]

        for term in search_terms[:10]:
            metadata["queries"] += 1
            results = await _search_intelx(client, term, limiter)
            metadata["results"] += len(results)

            for result in results:
                bucket   = result.get("bucket", "")
                media    = result.get("media", 0)
                category = _classify_intelx_result(bucket, media)

                findings.append({
                    "type":  category,
                    "value": term,
                    "data": {
                        "term":    term,
                        "systype": result.get("systype"),
                        "bucket":  bucket,
                        "date":    result.get("date"),
                        "score":   result.get("score"),
                        "name":    result.get("name"),
                        "size":    result.get("size"),
                        "source":  "intelx",
                    },
                })

    log.info("intelx.complete", queries=metadata["queries"], results=metadata["results"])
    return {
        "module":   "layer3/leak_search",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _search_intelx(client, term, limiter) -> list[dict]:
    """Submit search and poll for results."""
    await limiter.acquire("intelx")

    # Step 1: submit search
    try:
        r = await client.post(
            f"{_BASE}/intelligent/search",
            json={
                "term":       term,
                "buckets":    [],
                "lookuplevel": 0,
                "maxresults": 50,
                "timeout":    20,
                "datefrom":   "",
                "dateto":     "",
                "sort":       4,  # newest first
                "media":      0,
                "terminate":  [],
            },
        )
        r.raise_for_status()
        search_id = r.json().get("id")
        if not search_id:
            return []
    except Exception as exc:
        log.debug("intelx.search_failed", term=term, error=str(exc))
        return []

    # Step 2: poll for results (up to 3 attempts)
    for _ in range(3):
        await asyncio.sleep(2)
        await limiter.acquire("intelx")
        try:
            r = await client.get(
                f"{_BASE}/intelligent/search/result",
                params={"id": search_id, "limit": 50, "offset": 0},
            )
            r.raise_for_status()
            data    = r.json()
            status  = data.get("status", 3)
            records = data.get("records", [])
            if records or status == 1:  # 1 = complete
                return records
        except Exception:
            pass

    return []


def _classify_intelx_result(bucket: str, media: int) -> str:
    b = bucket.lower()
    if "breach" in b or "combolist" in b or "leak" in b:
        return "credential_leak"
    if "paste" in b:
        return "paste_site"
    if "telegram" in b:
        return "telegram_leak"
    if "darkweb" in b or "tor" in b or ".onion" in b:
        return "darkweb_mention"
    if "email" in b:
        return "email_archive"
    return "intelx_result"
