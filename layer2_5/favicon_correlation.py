"""
layer2_5/favicon_correlation.py — favicon hash tracking for host correlation.

Computes the MurmurHash3 of target favicon files (the same algorithm Shodan
uses for its favicon search). Querying Shodan for this hash finds all hosts
serving the same favicon — including staging servers, internal tools, CDN
origins, and subsidiary infrastructure that would never appear in DNS.

A single favicon hash query on Shodan has found thousands of unreported
servers for large enterprise targets. This is one of the highest-yield
passive techniques for infrastructure discovery.

Requires SHODAN_API_KEY for the Shodan search step (optional).
Favicon download itself is passive (semi mode).
"""
from __future__ import annotations

import base64
import hashlib
import struct
import time
from typing import Any

import httpx
import structlog

from core.config import Config
from core.ratelimiter import RateLimiter
from core.scope_guard import filter_in_scope
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "favicon_correlation",
    "title":    "Favicon Correlation",
    "description": "Hash-based correlation of related hosts",
    "layer":    2.5,
    "mode":     ["semi", "active"],
    "requires": [],
    "optional": True,
}

_TIMEOUT = 15

# Common favicon paths to try
_FAVICON_PATHS = [
    "/favicon.ico",
    "/favicon.png",
    "/apple-touch-icon.png",
    "/static/favicon.ico",
    "/assets/favicon.ico",
    "/images/favicon.ico",
]


async def run(scope: Scope, config: Config, db: Any) -> dict:
    import os
    t0        = time.monotonic()
    limiter   = RateLimiter(config.rate_limits)
    shodan_key = os.environ.get("SHODAN_API_KEY")
    findings: list[dict] = []
    metadata: dict       = {"favicons_found": 0, "shodan_results": 0}

    hosts = await _get_hosts(scope, db)

    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
        for host in hosts[:20]:
            for path in _FAVICON_PATHS:
                await limiter.acquire("default")
                favicon_data = await _fetch_favicon(client, host, path)
                if not favicon_data:
                    continue

                metadata["favicons_found"] += 1
                mmh3_hash = _mmh3_hash(favicon_data)
                md5_hash  = hashlib.md5(favicon_data).hexdigest()

                findings.append({
                    "type":  "favicon",
                    "value": f"https://{host}{path}",
                    "data": {
                        "host":      host,
                        "path":      path,
                        "mmh3_hash": mmh3_hash,
                        "md5_hash":  md5_hash,
                        "size_bytes": len(favicon_data),
                        "shodan_query": f"http.favicon.hash:{mmh3_hash}",
                    },
                })

                # Shodan favicon search
                if shodan_key:
                    shodan_hits = await _shodan_favicon_search(
                        mmh3_hash, shodan_key, limiter
                    )
                    metadata["shodan_results"] += len(shodan_hits)
                    for hit in shodan_hits:
                        findings.append({
                            "type":  "favicon_correlated_host",
                            "value": hit.get("ip_str", ""),
                            "data": {
                                "ip":        hit.get("ip_str"),
                                "port":      hit.get("port"),
                                "org":       hit.get("org"),
                                "hostnames": hit.get("hostnames", []),
                                "mmh3_hash": mmh3_hash,
                                "source":    "shodan_favicon",
                            },
                        })

                break  # found a favicon, no need to try other paths

    log.info("tracker_favicon.complete",
             favicons=metadata["favicons_found"],
             correlated=metadata["shodan_results"])
    return {
        "module":   "layer2_5/favicon_correlation",
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


async def _fetch_favicon(
    client: httpx.AsyncClient,
    host:   str,
    path:   str,
) -> bytes | None:
    for scheme in ("https", "http"):
        try:
            r = await client.get(f"{scheme}://{host}{path}", timeout=10)
            if r.status_code == 200 and len(r.content) > 0:
                return r.content
        except Exception:
            pass
    return None


def _mmh3_hash(data: bytes) -> int:
    """
    Compute the MurmurHash3 (32-bit) as used by Shodan for favicon fingerprinting.
    Shodan uses the base64-encoded favicon bytes as input.
    """
    encoded = base64.encodebytes(data)
    return _murmurhash3_32(encoded, 0)


def _murmurhash3_32(data: bytes, seed: int) -> int:
    """MurmurHash3 32-bit implementation matching Shodan's algorithm."""
    length = len(data)
    h1     = seed & 0xFFFFFFFF
    c1     = 0xCC9E2D51
    c2     = 0x1B873593

    for i in range(0, length - 3, 4):
        k1 = struct.unpack("<I", data[i:i + 4])[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = ((h1 * 5) + 0xE6546B64) & 0xFFFFFFFF

    tail_size = length % 4
    if tail_size:
        tail  = data[length - tail_size:]
        k1    = int.from_bytes(tail, "little")
        k1    = (k1 * c1) & 0xFFFFFFFF
        k1    = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1    = (k1 * c2) & 0xFFFFFFFF
        h1   ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1  = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1  = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    # Return as signed 32-bit int (Shodan convention)
    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


async def _shodan_favicon_search(
    mmh3_hash: int,
    api_key:   str,
    limiter:   RateLimiter,
) -> list[dict]:
    await limiter.acquire("shodan")
    try:
        import asyncio
        import internet_scan as _shodan
        api    = _shodan.Shodan(api_key)
        loop   = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: api.search(f"http.favicon.hash:{mmh3_hash}", limit=50),
        )
        return result.get("matches", [])
    except Exception as exc:
        log.debug("tracker_favicon.shodan_failed", error=str(exc))
        return []
