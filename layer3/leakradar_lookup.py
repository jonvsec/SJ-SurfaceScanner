"""
layer3/leakradar_lookup.py — LeakRadar.io credential exposure lookup.

A third credential population, distinct again from breach compilations
(DeHashed, HIBP) and from stealer logs (Hudson Rock). LeakRadar aggregates
combolists and stealer dumps and, unlike Hudson Rock's free tier, returns the
unmasked password and the source dump name.

Added after an earlier client engagement, where DeHashed returned nothing for a
domain that other sources showed as actively leaked. No single credential
source is authoritative. See LESSONS #15.

Requires LEAKRADAR_API_KEY. The module is auto-disabled when the key is absent,
and its absence is reported as a coverage gap rather than a clean result.

Passwords are never stored in plaintext. Presence is recorded and the value is
masked, matching the handling in layer3/credential_lookup.py.
"""
from __future__ import annotations

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
    "name":        "leakradar_lookup",
    "title":       "LeakRadar Credential Exposure",
    "description": "Leaked credentials by domain (LeakRadar.io)",
    "layer":       3,
    "mode":        ["passive", "semi", "active"],
    "requires":    ["LEAKRADAR_API_KEY"],
    "optional":    True,
}

_BASE    = "https://leakradar.io/api/v1"
_TIMEOUT = 25


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    api_key = os.environ.get("LEAKRADAR_API_KEY", "")
    limiter = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict = {"domains_checked": 0, "records": 0, "errors": 0}

    headers = {"X-API-Key": api_key, "Accept": "application/json"}

    async with httpx.AsyncClient(timeout=_TIMEOUT, headers=headers) as client:
        for domain in scope.all_domains:
            metadata["domains_checked"] += 1
            for entry in await _query(client, domain, limiter, metadata):
                # Filter locally on the property we care about. A remote
                # field named for a domain may match on company association
                # rather than the mail domain strictly (LESSONS #9).
                email = str(entry.get("email") or "").lower()
                if email and not email.endswith("@" + domain.lower()):
                    continue
                metadata["records"] += 1
                pw = entry.get("password")
                findings.append({
                    "type":  "leaked_credential",
                    "value": email or entry.get("username", ""),
                    "data": {
                        "email":           email or None,
                        "username":        entry.get("username"),
                        "domain":          domain,
                        "has_password":    bool(pw),
                        "password_masked": "***REDACTED***" if pw else None,
                        "source_name":     entry.get("source", {}).get("name")
                                           if isinstance(entry.get("source"), dict)
                                           else entry.get("source"),
                        "breach_date":     entry.get("source", {}).get("breach_date")
                                           if isinstance(entry.get("source"), dict)
                                           else None,
                        "severity":        "critical" if pw else "high",
                        "source":          "leakradar",
                    },
                })

    attempted = metadata["domains_checked"]
    blind = attempted > 0 and metadata["errors"] >= attempted
    log.info("leakradar.complete", records=metadata["records"],
             errors=metadata["errors"], blind=blind)

    return {
        "module":   "layer3/leakradar_lookup",
        "status":   "error" if blind else ("success" if findings else "partial"),
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    ("every LeakRadar query failed, this is a coverage gap and "
                     "not an absence of exposure") if blind else None,
    }


async def _query(client, domain, limiter, metadata) -> list[dict]:
    await limiter.acquire("leakradar")
    try:
        r = await client.get(f"{_BASE}/query/{domain}", params={"type": "domain"})
        if r.status_code in (401, 403):
            metadata["errors"] += 1
            log.warning("leakradar.auth_failed", status=r.status_code,
                        detail="key rejected or plan does not permit domain search")
            return []
        if r.status_code == 404:
            return []          # genuine "nothing found", not an error
        r.raise_for_status()
        body = r.json()
        return body.get("result") or []
    except Exception as exc:
        metadata["errors"] += 1
        log.warning("leakradar.query_failed", domain=domain, error=str(exc))
        return []
