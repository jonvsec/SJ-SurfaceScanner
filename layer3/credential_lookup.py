"""
layer3/credential_lookup.py — DeHashed credential search.

DeHashed indexes stolen credential databases and breach compilations.
Unlike HIBP (which only confirms breach membership), DeHashed returns
the actual leaked data: emails, usernames, passwords (hashed + plaintext),
IP addresses, phone numbers, and names.

Searches by email domain to find all accounts in their database.
Results are filtered to the target domain and deduplicated.

Requires DEHASHED_API_KEY (paid service). The v2 API authenticates with a
single `Dehashed-Api-Key` header — no separate username/Basic Auth.
Rate limit: 5 req/sec.
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
    "name":     "credential_lookup",
    "title":    "Credential Lookup",
    "description": "Breached credential records by domain",
    "layer":    3,
    "mode":     ["passive", "semi", "active"],
    "requires": ["DEHASHED_API_KEY"],
    "optional": True,
}

_BASE    = "https://api.dehashed.com/v2"

# Records per request, and a ceiling on how many pages to walk. The ceiling
# is a guard against a runaway loop rather than an expected limit.
_PAGE_SIZE = 10000
_MAX_PAGES = 100
_TIMEOUT = 20


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0       = time.monotonic()
    api_key  = os.environ.get("DEHASHED_API_KEY", "")
    limiter  = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict       = {"domains_checked": 0, "credentials_found": 0}

    headers = {"Dehashed-Api-Key": api_key, "Accept": "application/json"}

    async with httpx.AsyncClient(timeout=_TIMEOUT, headers=headers) as client:
        for domain in scope.all_domains:
            metadata["domains_checked"] += 1
            entries = await _search_domain(client, domain, limiter)
            metadata["credentials_found"] += len(entries)

            for entry in entries:
                # Never store plaintext passwords — flag presence only, mask value
                has_password    = bool(entry.get("password"))
                has_hash        = bool(entry.get("hashed_password"))
                password_masked = "***REDACTED***" if has_password else None
                hash_masked     = entry.get("hashed_password", "")[:8] + "..." if has_hash else None

                findings.append({
                    "type":  "leaked_credential",
                    "value": entry.get("email", ""),
                    "data": {
                        "email":           entry.get("email"),
                        "username":        entry.get("username"),
                        "domain":          domain,
                        "has_password":    has_password,
                        "password_masked": password_masked,
                        "has_hash":        has_hash,
                        "hash_prefix":     hash_masked,
                        "name":            entry.get("name"),
                        "phone":           entry.get("phone"),
                        "database_name":   entry.get("database_name"),
                        "severity":        "critical" if has_password else "high",
                        "source":          "dehashed",
                    },
                })

    # Aggregate stats
    with_passwords = sum(1 for f in findings if f["data"].get("has_password"))
    metadata["with_plaintext_password"] = with_passwords

    log.info("dehashed.complete",
             credentials=metadata["credentials_found"],
             with_passwords=with_passwords)

    return {
        "module":   "layer3/credential_lookup",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _search_domain(client, domain, limiter) -> list[dict]:
    """
    Retrieve every record for a domain, following pagination.

    The API caps a single response, so a domain with more records than that
    cap needs each page requested in turn. The earlier version requested page
    one only, which silently truncated any result set larger than one page and
    gave no indication that records were missing.
    """
    entries: list[dict] = []
    page = 1
    total: int | None = None

    while page <= _MAX_PAGES:
        await limiter.acquire("default")
        try:
            # v2 requires POST with a JSON body. A GET returns 404 with a
            # documentation pointer, which reads like a bad path rather than
            # a bad method and is easy to misdiagnose.
            r = await client.post(
                f"{_BASE}/search",
                json={
                    "query": f"domain:{domain}",
                    "size":  _PAGE_SIZE,
                    "page":  page,
                },
            )
            if r.status_code == 403 and "credit" in r.text.lower():
                log.warning(
                    "dehashed.insufficient_credits",
                    domain=domain,
                    detail="key authenticates but the account has no API credits",
                )
                break
            r.raise_for_status()
            doc = r.json()
        except Exception as exc:
            log.warning(
                "dehashed.search_failed",
                domain=domain, page=page, collected=len(entries), error=str(exc),
            )
            break

        batch = doc.get("entries") or []
        if total is None:
            total = doc.get("total")
            log.info("dehashed.result_total", domain=domain, total=total)

        entries.extend(batch)

        # A short page means the result set is exhausted.
        if len(batch) < _PAGE_SIZE:
            break
        # Stop once every advertised record has been collected.
        if total is not None and len(entries) >= total:
            break

        page += 1
        log.debug("dehashed.paging", domain=domain, page=page, collected=len(entries))
    else:
        log.warning(
            "dehashed.page_cap_reached",
            domain=domain, pages=_MAX_PAGES, collected=len(entries),
            detail="results may still be truncated",
        )

    log.info(
        "dehashed.domain_complete",
        domain=domain, records=len(entries), advertised_total=total, pages=page,
    )
    return entries
