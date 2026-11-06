"""
layer2_5/cloud_buckets.py — cloud storage bucket enumeration (cross-provider).

Systematically checks naming patterns for exposed cloud storage buckets
across AWS S3, Google Cloud Storage, Azure Blob, and DigitalOcean Spaces.

This module supplements layer2/cloud/* by running additional naming patterns
based on technologies and services inferred from job postings (Layer 1) and
by checking for public listing (not just existence).

Mode: passive — checks are against third-party cloud provider endpoints,
not the target's own infrastructure directly.
"""
from __future__ import annotations

import asyncio
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
    "name":     "cloud_buckets",
    "title":    "Cloud Storage Exposure",
    "description": "Cross-provider public bucket enumeration",
    "layer":    2.5,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": True,
}

_TIMEOUT = 10

_PROVIDERS = {
    "s3": {
        "url":         "https://{name}.s3.amazonaws.com",
        "url_path":    "https://s3.amazonaws.com/{name}",
        "list_marker": "<ListBucketResult",
        "exists_codes": [200, 403, 301],
    },
    "gcs": {
        "url":         "https://storage.googleapis.com/{name}",
        "url_path":    None,
        "list_marker": "<ListBucketResult",
        "exists_codes": [200, 403],
    },
    "azure": {
        "url":         "https://{name}.blob.core.windows.net",
        "url_path":    None,
        "list_marker": None,
        "exists_codes": [200, 403, 400, 401],
    },
    "do_spaces": {
        "url":         "https://{name}.nyc3.digitaloceanspaces.com",
        "url_path":    None,
        "list_marker": "<ListBucketResult",
        "exists_codes": [200, 403],
    },
}


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict       = {"checked": 0, "found": 0, "public": 0}

    names = _generate_names(scope)

    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False) as client:
        batch_size = 10
        for i in range(0, len(names), batch_size):
            batch = names[i:i + batch_size]
            tasks = []
            for name in batch:
                for provider, config_p in _PROVIDERS.items():
                    tasks.append(_check_bucket(client, name, provider, config_p, limiter))

            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                metadata["checked"] += 1
                if isinstance(result, dict) and result.get("exists"):
                    metadata["found"] += 1
                    if result.get("public"):
                        metadata["public"] += 1
                        log.warning("buckets.public_found", **result)
                    findings.append({
                        "type":  f"{result['provider']}_bucket",
                        "value": result["url"],
                        "data":  result,
                    })

    return {
        "module":   "layer2_5/cloud_buckets",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


def _generate_names(scope: Scope) -> list[str]:
    names = set()
    slug  = re.sub(r"[^a-z0-9\-]", "-", scope.target.name.lower()).strip("-")

    base_names = [slug, slug.replace("-", ""), slug[:20]]
    for domain in scope.all_domains[:3]:
        base_names.append(domain.split(".")[0])

    suffixes = [
        "", "-backup", "-data", "-logs", "-assets", "-static",
        "-media", "-files", "-uploads", "-dev", "-prod", "-staging",
        "-public", "-private", "-archive", "-reports", "-exports",
        "-terraform", "-tf-state", "-k8s", "-ci", "-build",
    ]

    for base in base_names:
        for suffix in suffixes:
            name = f"{base}{suffix}"
            if 3 <= len(name) <= 63:
                names.add(name)

    return sorted(names)


async def _check_bucket(
    client:   httpx.AsyncClient,
    name:     str,
    provider: str,
    cfg:      dict,
    limiter:  RateLimiter,
) -> dict | None:
    await limiter.acquire("default")
    url = cfg["url"].replace("{name}", name)
    try:
        r = await client.get(url, timeout=8)
        if r.status_code not in cfg["exists_codes"]:
            return None

        is_public  = r.status_code == 200
        is_listing = cfg.get("list_marker") and cfg["list_marker"] in r.text

        return {
            "name":     name,
            "provider": provider,
            "url":      url,
            "exists":   True,
            "public":   is_public,
            "listing":  bool(is_listing),
            "status":   r.status_code,
            "severity": "critical" if is_listing else ("high" if is_public else "medium"),
        }
    except Exception:
        return None
