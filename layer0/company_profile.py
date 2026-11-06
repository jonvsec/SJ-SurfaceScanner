"""
layer0/company_profile.py — LLM-grounded company profiling.

layer0/sec_filings.py only covers US SEC filers. For regional or private companies
(e.g. a Mexican fintech), sector/country/business context is otherwise
unknown and layer4/sector_intel.py silently defaults to "technology" —
which then drives the wrong APT groups, MITRE tactics, and kill chain
narrative for the rest of the report.

This module fixes that gap by grounding an LLM extraction in real evidence —
SearXNG search results + the target's homepage text — rather than relying on
LLM recall, which hallucinates confidently for smaller or regional companies.

If scope.target.sector is unset, the inferred sector is written back onto
the scope object so layer4/sector_intel.py uses it later in the same run.
"""
from __future__ import annotations

import time
from typing import Any

import httpx
import structlog
from bs4 import BeautifulSoup

from core.config import Config
from core.llm import LLMError, LLMRouter
from core.prefilter import prepare_for_llm
from core.ratelimiter import RateLimiter
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "company_profile",
    "title":    "Company Profile (LLM)",
    "description": "Sector, country and HQ inferred from grounded web evidence",
    "layer":    0,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": True,
}

_TIMEOUT = 20

# Must match the sector keys in layer4/sector_intel.py's _SECTOR_INTEL.
_VALID_SECTORS = {"fintech", "healthcare", "manufacturing", "technology", "retail", "government"}

_PROFILE_QUERIES = [
    '"{company}" company profile industry sector',
    '"{company}" about us headquarters country',
    '"{company}" customers clients services',
]


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    llm     = LLMRouter(config)
    findings: list[dict] = []
    metadata: dict       = {}

    company = scope.target.name
    domain  = scope.primary_domain or ""

    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
        evidence, sources = await _gather_evidence(client, config, limiter, company, domain)

    metadata["evidence_sources"] = len(sources)
    if not evidence.strip():
        return _result("partial", findings, metadata, t0,
                        error="no evidence gathered from SearXNG or homepage")

    profile = await _extract_profile(llm, company, domain, evidence, scope.data_classification)
    if profile is None:
        return _result("partial", findings, metadata, t0,
                        error="LLM profile extraction failed")

    profile["sources"] = sources
    findings.append({
        "type":  "company_profile",
        "value": company,
        "data":  profile,
    })

    # Populate scope.target.sector if unset so layer4/sector_intel uses it this run
    sector = str(profile.get("sector", "")).lower()
    if not scope.target.sector and sector in _VALID_SECTORS:
        scope.target.sector = sector
        metadata["sector_set"] = sector
        log.info("company_profile.sector_inferred", company=company, sector=sector)

    metadata["confidence"] = profile.get("confidence")
    log.info("company_profile.complete", company=company,
             sector=profile.get("sector"), confidence=profile.get("confidence"))

    return _result("success", findings, metadata, t0)


# ---------------------------------------------------------------------------
# Evidence gathering
# ---------------------------------------------------------------------------

async def _gather_evidence(
    client:  httpx.AsyncClient,
    config:  Config,
    limiter: RateLimiter,
    company: str,
    domain:  str,
) -> tuple[str, list[str]]:
    parts:   list[str] = []
    sources: list[str] = []

    for template in _PROFILE_QUERIES:
        query   = template.replace("{company}", company)
        results = await _search(client, config.searxng.url, query, limiter)
        for r in results[:5]:
            title, content, url = r.get("title", ""), r.get("content", ""), r.get("url", "")
            if content:
                parts.append(f"[{title}]({url}): {content}")
                sources.append(url)

    if domain:
        homepage_text, homepage_url = await _fetch_homepage(client, domain, limiter)
        if homepage_text:
            parts.append(f"[Homepage]({homepage_url}): {homepage_text}")
            sources.append(homepage_url)

    return "\n\n".join(parts), sources


async def _search(
    client:   httpx.AsyncClient,
    base_url: str,
    query:    str,
    limiter:  RateLimiter,
) -> list[dict]:
    await limiter.acquire("default")
    try:
        r = await client.get(
            f"{base_url}/search",
            params={"q": query, "format": "json", "language": "en", "pageno": "1"},
        )
        r.raise_for_status()
        return r.json().get("results", [])
    except Exception as exc:
        log.warning("company_profile.search_failed", query=query[:60], error=str(exc))
        return []


async def _fetch_homepage(
    client:  httpx.AsyncClient,
    domain:  str,
    limiter: RateLimiter,
) -> tuple[str, str]:
    for url in (f"https://{domain}", f"https://www.{domain}"):
        await limiter.acquire("default")
        try:
            r = await client.get(url)
            r.raise_for_status()
            soup = BeautifulSoup(r.text, "lxml")
            for tag in soup(["script", "style", "nav", "footer"]):
                tag.decompose()
            text = " ".join(soup.get_text(separator=" ").split())
            if text:
                return text[:4000], str(r.url)
        except Exception as exc:
            log.debug("company_profile.homepage_failed", url=url, error=str(exc))
    return "", ""


# ---------------------------------------------------------------------------
# LLM extraction
# ---------------------------------------------------------------------------

async def _extract_profile(
    llm:            LLMRouter,
    company:        str,
    domain:         str,
    evidence:       str,
    classification: str,
) -> dict | None:
    condensed = prepare_for_llm(evidence, max_chars=6000)
    valid     = ", ".join(sorted(_VALID_SECTORS))

    prompt = f"""You are a corporate intelligence analyst. Based ONLY on the evidence below, \
profile the company "{company}" (domain: {domain or 'unknown'}).

{condensed}

Reply with JSON containing exactly these fields:
- "sector": one of [{valid}], or "unknown" if the evidence doesn't support a confident choice
- "country": the company's primary country of operation, or "unknown"
- "headquarters": city/region of headquarters, or "unknown"
- "business_description": 2-3 sentence description of what the company does, based only on the evidence
- "main_customers": list of customer types or named customers mentioned in the evidence (empty list if none)
- "confidence": "high", "medium", or "low" — how well the evidence supports this profile

Do not invent facts not present in the evidence. If the evidence is insufficient for a field, \
use "unknown" (or an empty list for main_customers) and set confidence to "low"."""

    try:
        result = await llm.complete_json(prompt, classification=classification)
    except LLMError as exc:
        log.warning("company_profile.llm_failed", error=str(exc))
        return None

    if not isinstance(result, dict):
        return None
    return result


def _result(
    status:   str,
    findings: list[dict],
    metadata: dict,
    t0:       float,
    error:    str | None = None,
) -> dict:
    return {
        "module":   "layer0/company_profile",
        "status":   status,
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    error,
    }
