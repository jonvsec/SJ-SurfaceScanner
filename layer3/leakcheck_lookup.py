"""
layer3/leakcheck_lookup.py — LeakCheck.io credential exposure lookup.

A third credential population, distinct again from breach compilations
(DeHashed, HIBP) and from stealer logs (Hudson Rock). LeakCheck aggregates
combolists and stealer dumps and, unlike Hudson Rock's free tier, returns the
unmasked password and the source dump name.

Added after an earlier client engagement, where DeHashed returned nothing for a
domain that other sources showed as actively leaked. No single credential
source is authoritative. See LESSONS #15.

Requires LEAKCHECK_API_KEY. The module is auto-disabled when the key is absent,
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
    "name":        "leakcheck_lookup",
    "title":       "LeakCheck Credential Exposure",
    "description": "Leaked credentials by identity (LeakCheck.io)",
    "layer":       3,
    "mode":        ["passive", "semi", "active"],
    "requires":    [],          # public endpoint works keyless, key unlocks detail
    "optional":    True,
}

_BASE    = "https://leakcheck.io/api/v2"
_TIMEOUT = 25


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    api_key = os.environ.get("LEAKCHECK_API_KEY", "")
    limiter = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict = {"domains_checked": 0, "records": 0, "errors": 0}

    headers = {"X-API-Key": api_key, "Accept": "application/json"}

    async with httpx.AsyncClient(timeout=_TIMEOUT, headers=headers) as client:
        # Keyless path first. Works with no subscription, so a run always
        # produces something rather than silently skipping.
        for email in sorted({str(e).strip().lower()
                             for e in (getattr(scope, "emails", None) or []) if "@" in str(e)}):
            pub = await _query_public(client, email, limiter, metadata)
            if pub and pub["found"]:
                metadata["records"] += pub["found"]
                findings.append({
                    "type":  "leaked_credential_indicator",
                    "value": email,
                    "data": {
                        "email":        email,
                        "record_count": pub["found"],
                        "source_types": pub["sources"],
                        "fields_held":  pub["fields"],
                        "severity":     "critical" if "Stealer Logs" in pub["sources"] else "high",
                        "source":       "leakcheck-public",
                        "note":         "keyless endpoint, counts and source types only. "
                                        "An API key returns the credential values.",
                    },
                })

        if not api_key:
            metadata["domain_search_skipped"] = "no LEAKCHECK_API_KEY, keyless path only"
            log.info("leakcheck.keyless_only", records=metadata["records"])
            return {
                "module":   "layer3/leakcheck_lookup",
                "status":   "partial",
                "findings": findings,
                "metadata": metadata,
                "duration": time.monotonic() - t0,
                "error":    None,
            }

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
                        "source":          "leakcheck",
                    },
                })

    attempted = metadata["domains_checked"]
    blind = attempted > 0 and metadata["errors"] >= attempted
    log.info("leakcheck.complete", records=metadata["records"],
             errors=metadata["errors"], blind=blind)

    return {
        "module":   "layer3/leakcheck_lookup",
        "status":   "error" if blind else ("success" if findings else "partial"),
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    ("every LeakCheck query failed, this is a coverage gap and "
                     "not an absence of exposure") if blind else None,
    }


async def _query_public(client, email, limiter, metadata) -> dict | None:
    """Keyless public endpoint. Confirms exposure and names the source type.

    Returns counts and source names but no credential values. Verified working
    without a key on 2026-10-01: user-a@example.com -> found 1, "Stealer Logs";
    user-b@example.com -> found 12. Domain-wide queries are not supported here,
    so this path is per-identity only.
    """
    await limiter.acquire("leakcheck")
    try:
        r = await client.get("https://leakcheck.io/api/public",
                             params={"check": email})
        r.raise_for_status()
        body = r.json()
        if not body.get("success"):
            return None
        return {
            "found":   int(body.get("found") or 0),
            "sources": [x.get("name") for x in (body.get("sources") or [])],
            "fields":  body.get("fields") or [],
        }
    except Exception as exc:
        metadata["errors"] += 1
        log.warning("leakcheck.public_query_failed", email=email, error=str(exc))
        return None


async def _query(client, domain, limiter, metadata) -> list[dict]:
    await limiter.acquire("leakcheck")
    try:
        r = await client.get(f"{_BASE}/query/{domain}", params={"type": "domain"})
        if r.status_code in (401, 403):
            metadata["errors"] += 1
            log.warning("leakcheck.auth_failed", status=r.status_code,
                        detail="key rejected or plan does not permit domain search")
            return []
        if r.status_code == 404:
            return []          # genuine "nothing found", not an error
        r.raise_for_status()
        body = r.json()
        return body.get("result") or []
    except Exception as exc:
        metadata["errors"] += 1
        log.warning("leakcheck.query_failed", domain=domain, error=str(exc))
        return []
