"""
layer2/subdomain/subdomain_wayback.py, subdomains from web-archive history.

Hosts that only ever appeared in old page markup, retired links, or a form
action years ago still live in the Wayback Machine's URL index even after they
vanish from DNS, certificates, and every passive-DNS source. This module pulls
the archived-URL index for the domain and extracts every hostname under it.

Fully passive: it queries public archive indexes, never the client. The
hostnames it returns are historical candidates, dns_resolve downstream decides
which still answer.

No CLI tool and no API key. Pure HTTP against the Wayback CDX API, with the OTX
URL index as a second archive source.
"""
from __future__ import annotations

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
    "name":     "subdomain_wayback",
    "title":    "Wayback Subdomains",
    "description": "Hostnames mined from web-archive URL history",
    "layer":    2,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": True,
}

_TIMEOUT = 45
_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,62}\.)+[a-z]{2,}$")


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0        = time.monotonic()
    limiter   = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict       = {"domains_scanned": 0, "hosts_found": 0, "sources": {}}
    seen: set[str] = set()

    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
        for domain in scope.all_domains:
            metadata["domains_scanned"] += 1
            for source, hosts in (
                ("wayback", await _wayback_hosts(client, domain, limiter)),
                ("otx_url", await _otx_url_hosts(client, domain, limiter)),
            ):
                kept = 0
                for h in hosts:
                    h = h.strip().lower().lstrip("*.")
                    if not h or h in seen:
                        continue
                    if not (h == domain or h.endswith(f".{domain}")):
                        continue
                    if not _HOST_RE.match(h):
                        continue
                    seen.add(h)
                    kept += 1
                    findings.append({
                        "type":  "subdomain",
                        "value": h,
                        "data":  {"source": source, "parent_domain": domain,
                                  "historical": True},
                    })
                if kept:
                    metadata["sources"][source] = metadata["sources"].get(source, 0) + kept

    metadata["hosts_found"] = len(seen)
    log.info("wayback.complete", hosts=len(seen), sources=metadata["sources"])

    return {
        "module":   "layer2/subdomain/subdomain_wayback",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None if findings else "no archived hostnames found",
    }


async def _wayback_hosts(client, domain, limiter: RateLimiter) -> list[str]:
    """
    Wayback CDX index for *.domain/*, collapsed by host.

    fl=original returns the archived URL, collapse=urlkey dedupes aggressively
    server-side so the response stays small on a long-lived domain.
    """
    await limiter.acquire("default")
    url = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=100000"
    )
    try:
        r = await client.get(url)
        r.raise_for_status()
        rows = r.json() or []
    except Exception as exc:
        log.warning("wayback.failed", domain=domain, error=str(exc)[:160])
        return []
    # First row is the header ["original"] when fl=original, skip it.
    hosts: list[str] = []
    for row in rows[1:] if rows and rows[0] == ["original"] else rows:
        raw = row[0] if isinstance(row, list) and row else (row if isinstance(row, str) else "")
        host = _host_from_url(raw)
        if host:
            hosts.append(host)
    return hosts


async def _otx_url_hosts(client, domain, limiter: RateLimiter) -> list[str]:
    """OTX stores a URL list per domain, a second archive of historical hosts."""
    await limiter.acquire("default")
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500"
    try:
        r = await client.get(url, headers={"Accept": "application/json"})
        r.raise_for_status()
        data = r.json() or {}
    except Exception as exc:
        log.debug("otx_url.failed", domain=domain, error=str(exc)[:160])
        return []
    hosts: list[str] = []
    for rec in (data.get("url_list", []) or []):
        host = rec.get("hostname") or _host_from_url(rec.get("url", ""))
        if host:
            hosts.append(host)
    return hosts


def _host_from_url(raw: str) -> str:
    """Pull the hostname out of an archived URL without urllib overhead."""
    if not raw:
        return ""
    s = raw.split("://", 1)[-1]
    s = s.split("/", 1)[0]
    s = s.split("@", 1)[-1]     # strip userinfo
    s = s.split(":", 1)[0]      # strip port
    return s.strip().lower()
