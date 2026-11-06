"""
layer3/breach_lookup.py — Have I Been Pwned breach intelligence.

Queries the HIBP API for breaches associated with the target's domains.
HIBP tracks 12+ billion accounts across 700+ known breaches.

Domain search returns: all breaches where accounts @domain.com appeared,
with breach metadata: date, data types exposed, description, severity.

This directly answers "have employees' credentials been publicly exposed?"
which is the single most common initial access vector in 2024-2025.

Rate limit: 1 req/1.5s. Requires HIBP_API_KEY (free tier available).
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
    "name":     "breach_lookup",
    "title":    "Breach Lookup",
    "description": "Known breach exposure per domain and account",
    "layer":    3,
    "mode":     ["passive", "semi", "active"],
    "requires": ["HIBP_API_KEY"],
    "optional": True,
}

_BASE    = "https://haveibeenpwned.com/api/v3"
_TIMEOUT = 20


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    api_key = os.environ.get("HIBP_API_KEY", "")
    limiter = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict       = {"domains_checked": 0, "breaches_found": 0}

    headers = {
        "hibp-api-key": api_key,
        "User-Agent":   "SurfaceScanner/1.0",
    }

    async with httpx.AsyncClient(timeout=_TIMEOUT, headers=headers) as client:
        # Check each domain
        for domain in scope.all_domains:
            metadata["domains_checked"] += 1
            breaches = await _get_domain_breaches(client, domain, limiter)
            metadata["breaches_found"] += len(breaches)

            for breach in breaches:
                severity = _classify_breach_severity(breach)
                findings.append({
                    "type":  "data_breach",
                    "value": breach.get("Name", domain),
                    "data": {
                        "domain":        domain,
                        "breach_name":   breach.get("Name"),
                        "title":         breach.get("Title"),
                        "breach_domain": breach.get("Domain"),
                        "breach_date":   breach.get("BreachDate"),
                        "added_date":    breach.get("AddedDate"),
                        "pwn_count":     breach.get("PwnCount"),
                        "description":   breach.get("Description", "")[:500],
                        "data_classes":  breach.get("DataClasses", []),
                        "is_verified":   breach.get("IsVerified"),
                        "is_sensitive":  breach.get("IsSensitive"),
                        "severity":      severity,
                    },
                })

        # Check specific email addresses from scope
        for email in scope.emails:
            email_breaches = await _get_account_breaches(client, email, limiter)
            for breach in email_breaches:
                findings.append({
                    "type":  "account_breach",
                    "value": email,
                    "data": {
                        "email":       email,
                        "breach":      breach.get("Name"),
                        "breach_date": breach.get("BreachDate"),
                        "data_types":  breach.get("DataClasses", []),
                        "severity":    _classify_breach_severity(breach),
                    },
                })

        # Check email addresses discovered in Layer 3 contact module
        contact_emails = await _get_contact_emails(scope, db)
        for email in contact_emails[:50]:
            await limiter.acquire("default")
            email_breaches = await _get_account_breaches(client, email, limiter)
            for breach in email_breaches:
                findings.append({
                    "type":  "account_breach",
                    "value": email,
                    "data": {
                        "email":      email,
                        "breach":     breach.get("Name"),
                        "data_types": breach.get("DataClasses", []),
                        "severity":   _classify_breach_severity(breach),
                    },
                })

    _deduplicate(findings)
    log.info("hibp.complete", domains=metadata["domains_checked"], breaches=metadata["breaches_found"])

    return {
        "module":   "layer3/breach_lookup",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _get_domain_breaches(client, domain, limiter) -> list[dict]:
    await limiter.acquire("default")
    try:
        r = await client.get(f"{_BASE}/breaches", params={"domain": domain})
        if r.status_code == 404:
            return []
        r.raise_for_status()
        return r.json() if r.content else []
    except Exception as exc:
        log.debug("hibp.domain_failed", domain=domain, error=str(exc))
        return []


async def _get_account_breaches(client, email, limiter) -> list[dict]:
    # Rate limit: 1 req per 1500ms for account lookups
    import asyncio
    await asyncio.sleep(1.5)
    try:
        r = await client.get(
            f"{_BASE}/breachedaccount/{email}",
            params={"truncateResponse": "false"},
        )
        if r.status_code == 404:
            return []
        r.raise_for_status()
        return r.json() if r.content else []
    except Exception:
        return []


async def _get_contact_emails(scope, db) -> list[str]:
    if db is None:
        return []
    try:
        run_id = await db.get_last_run_id(scope.target.name) or ""
        if not run_id:
            return []
        rows = await db.get_findings(run_id, "email_address")
        return [r["value"] for r in rows if r.get("value")]
    except Exception:
        return []


def _classify_breach_severity(breach: dict) -> str:
    data_classes = [d.lower() for d in breach.get("DataClasses", [])]
    if any(d in data_classes for d in ["passwords", "password hints"]):
        return "critical"
    if any(d in data_classes for d in ["credit cards", "bank account numbers", "social security numbers"]):
        return "critical"
    if any(d in data_classes for d in ["email addresses", "usernames", "phone numbers"]):
        return "high"
    return "medium"


def _deduplicate(findings: list) -> None:
    seen = set()
    i    = 0
    while i < len(findings):
        key = (findings[i]["type"], findings[i]["value"])
        if key in seen:
            findings.pop(i)
        else:
            seen.add(key)
            i += 1
