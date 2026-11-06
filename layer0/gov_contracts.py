"""
layer0/gov_contracts.py — government contract and procurement intelligence.

Public procurement databases reveal who supplies critical services to
the target — often the weakest link in the supply chain:

  USA: SAM.gov (System for Award Management) — free API, no key
  USA: USASpending.gov — all federal contracts, free API
  UK:  Contracts Finder — free, no key
  EU:  TED (Tenders Electronic Daily) — free

A contract with a small IT contractor often means that contractor has
privileged access to the target's infrastructure. Compromising the
contractor = compromising the target (supply chain attack).

Also reveals: cloud providers used, security tools purchased (MDR,
SOC services), and which departments have what budgets.
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
    "name":     "gov_contracts",
    "title":    "Government Contracts",
    "description": "Public procurement awards revealing suppliers and tooling",
    "layer":    0,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": True,
}

_USASPENDING_API = "https://api.usaspending.gov/api/v2"
_SAM_API         = "https://api.sam.gov/prod/opportunities/v2/search"
_TIMEOUT         = 25


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict       = {}

    company = scope.target.name

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        # USASpending.gov — federal contract awards
        usa_contracts = await _search_usaspending(client, company, limiter)
        metadata["usa_contracts"] = len(usa_contracts)

        for contract in usa_contracts[:20]:
            recipient  = contract.get("recipient", {})
            award_data = {
                "award_id":       contract.get("Award ID"),
                "award_amount":   contract.get("Award Amount"),
                "start_date":     contract.get("Start Date"),
                "end_date":       contract.get("End Date"),
                "awarding_agency": contract.get("Awarding Agency"),
                "recipient_name": recipient.get("recipient_name"),
                "description":    contract.get("Description", "")[:300],
                "source":         "usaspending",
            }
            findings.append({
                "type":  "government_contract",
                "value": contract.get("Award ID", company),
                "data":  award_data,
            })

            # High-value: IT/security contracts reveal vendors
            desc = award_data["description"].lower()
            if any(kw in desc for kw in ["cybersecurity", "information security", "soc", "cloud",
                                          "software", "it services", "managed services"]):
                findings.append({
                    "type":  "it_procurement",
                    "value": award_data["recipient_name"] or company,
                    "data": {
                        **award_data,
                        "note": "IT/security contract — supplier has potential privileged access",
                        "severity": "medium",
                    },
                })

        # SearXNG: broader procurement search (includes non-US)
        procurement_results = await _search_procurement(
            client, config.searxng.url, company, limiter
        )
        for result in procurement_results:
            findings.append({
                "type":  "procurement_mention",
                "value": result.get("url", ""),
                "data": {
                    "title":   result.get("title"),
                    "url":     result.get("url"),
                    "snippet": result.get("content", "")[:300],
                    "source":  "web_search",
                },
            })

    metadata["total_findings"] = len(findings)
    return {
        "module":   "layer0/gov_contracts",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _search_usaspending(client, company, limiter) -> list[dict]:
    await limiter.acquire("default")
    try:
        r = await client.post(
            f"{_USASPENDING_API}/search/spending_by_award/",
            json={
                "filters": {
                    "keywords":    [company],
                    "award_type_codes": ["A", "B", "C", "D"],  # contracts
                },
                "fields": [
                    "Award ID", "Recipient Name", "Award Amount",
                    "Start Date", "End Date", "Awarding Agency",
                    "Description",
                ],
                "page":  1,
                "limit": 25,
                "sort":  "Award Amount",
                "order": "desc",
            },
        )
        r.raise_for_status()
        return r.json().get("results", [])
    except Exception as exc:
        log.debug("contracts.usaspending_failed", company=company, error=str(exc))
        return []


async def _search_procurement(client, searxng_url, company, limiter) -> list[dict]:
    await limiter.acquire("default")
    queries = [
        f'"{company}" contract award procurement',
        f'"{company}" site:ted.europa.eu OR site:contracts.gov.uk',
    ]
    results = []
    for q in queries:
        try:
            r = await client.get(
                f"{searxng_url}/search",
                params={"q": q, "format": "json"},
            )
            r.raise_for_status()
            results.extend(r.json().get("results", [])[:5])
            await limiter.acquire("default")
        except Exception:
            pass
    return results
