"""
layer0/company_registry.py — OpenCorporates company intelligence.

Searches OpenCorporates for the target company across multiple jurisdictions.
Extracts: registration number, jurisdiction, incorporation date, status,
registered address, directors/officers, and related companies.

API: OpenCorporates now requires an API token for all `/companies/search`
requests (their old anonymous free tier was discontinued — unauthenticated
requests return 401 "Invalid Api Token"). Key: OPENCORPORATES_API_KEY.
Module auto-disables via the registry when the key is absent, rather than
making a guaranteed-401 request on every run.
"""
from __future__ import annotations

import time
from typing import Any

import httpx
import structlog

from core.config import Config
from core.ratelimiter import RateLimiter
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "company_registry",
    "title":    "Company Registry (global)",
    "description": "Cross-jurisdiction company registration, officers, addresses",
    "layer":    0,
    "mode":     ["passive", "semi", "active"],
    "requires": ["OPENCORPORATES_API_KEY"],
    "optional": True,
}

_BASE    = "https://api.opencorporates.com/v0.4"
_TIMEOUT = 20


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict       = {}

    import os
    api_key = os.environ.get("OPENCORPORATES_API_KEY")
    params_base = {"api_token": api_key} if api_key else {}

    headers = {"User-Agent": "SurfaceScanner security-research@example.com"}

    async with httpx.AsyncClient(timeout=_TIMEOUT, headers=headers) as client:
        # Search for the primary company name
        companies = await _search_company(
            client, scope.target.name, params_base, limiter
        )

        # Also search aliases
        for alias in scope.target.aliases:
            alias_results = await _search_company(
                client, alias, params_base, limiter
            )
            companies.extend(alias_results)

        metadata["companies_found"] = len(companies)

        for company in companies[:20]:  # cap to avoid runaway results
            c = company.get("company", company)
            entry = {
                "name":               c.get("name"),
                "jurisdiction":       c.get("jurisdiction_code"),
                "company_number":     c.get("company_number"),
                "status":             c.get("current_status") or c.get("company_status"),
                "incorporation_date": c.get("incorporation_date"),
                "dissolution_date":   c.get("dissolution_date"),
                "registered_address": _extract_address(c),
                "company_type":       c.get("company_type"),
                "opencorporates_url": c.get("opencorporates_url"),
            }

            if not entry["name"]:
                continue

            findings.append({
                "type":  "corporate_registration",
                "value": f"{entry['name']} ({entry['jurisdiction']})",
                "data":  entry,
            })

            # Fetch officers if available (requires a second API call)
            if c.get("opencorporates_url"):
                officers = await _fetch_officers(
                    client,
                    c.get("jurisdiction_code", ""),
                    c.get("company_number", ""),
                    params_base,
                    limiter,
                )
                for officer in officers[:10]:
                    findings.append({
                        "type":  "corporate_officer",
                        "value": officer.get("name", ""),
                        "data":  {**officer, "company": entry["name"]},
                    })

    status = "success" if findings else "partial"
    return {
        "module":   "layer0/company_registry",
        "status":   status,
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None if findings else "No companies found",
    }


async def _search_company(
    client:      httpx.AsyncClient,
    name:        str,
    params_base: dict,
    limiter:     RateLimiter,
) -> list[dict]:
    await limiter.acquire("default")
    try:
        r = await client.get(
            f"{_BASE}/companies/search",
            params={**params_base, "q": name, "per_page": "10"},
        )
        r.raise_for_status()
        data = r.json()
        return data.get("results", {}).get("companies", [])
    except Exception as exc:
        log.warning("opencorporates.search_failed", name=name, error=str(exc))
        return []


async def _fetch_officers(
    client:      httpx.AsyncClient,
    jurisdiction: str,
    number:      str,
    params_base: dict,
    limiter:     RateLimiter,
) -> list[dict]:
    if not jurisdiction or not number:
        return []
    await limiter.acquire("default")
    try:
        r = await client.get(
            f"{_BASE}/companies/{jurisdiction}/{number}/officers",
            params=params_base,
        )
        r.raise_for_status()
        data = r.json()
        officers = data.get("results", {}).get("officers", [])
        return [o.get("officer", o) for o in officers]
    except Exception as exc:
        log.debug("opencorporates.officers_failed", error=str(exc))
        return []


def _extract_address(company: dict) -> str | None:
    addr = company.get("registered_address") or {}
    if isinstance(addr, dict):
        parts = [
            addr.get("street_address"),
            addr.get("locality"),
            addr.get("region"),
            addr.get("postal_code"),
            addr.get("country"),
        ]
        return ", ".join(p for p in parts if p) or None
    return str(addr) if addr else None
