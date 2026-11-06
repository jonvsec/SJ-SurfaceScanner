"""
layer0/patents.py — patent intelligence for technology stack disclosure.

US Patent filings publicly disclose the exact technologies, algorithms,
and systems a company builds. A patent for "distributed key-value store
with Raft consensus" reveals internal infrastructure that never appears
in job postings or press releases.

Sources:
  USPTO PEDS (Patent Examination Data System) — free, no key
  Google Patents — via SearXNG query
  USPTO Full-Text search — free API

Findings feed the technology stack model (Layer 1 jobs_scraper correlation)
and sector intelligence (patents in biotech → regulatory attack surface).

Data classification: SEMI-PUBLIC (public filings).
"""
from __future__ import annotations

import re
import time
from typing import Any

import httpx
import structlog

from core.config import Config
from core.prefilter import extract_signals
from core.ratelimiter import RateLimiter
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "patents",
    "title":    "Patent Filings",
    "description": "Technology stack disclosed in public patent filings",
    "layer":    0,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": True,
}

_USPTO_SEARCH = "https://developer.uspto.gov/ibd-api/v1/patent/application"
_TIMEOUT      = 20

_TECH_RE = re.compile(
    r"\b(machine learning|deep learning|neural network|blockchain|"
    r"distributed system|microservice|kubernetes|docker|cloud native|"
    r"zero trust|encryption|homomorphic|differential privacy|"
    r"federated learning|FPGA|GPU|ASIC|NLP|computer vision|"
    r"real.time|edge computing|IoT|5G|API|REST|GraphQL|"
    r"PostgreSQL|MySQL|Redis|Kafka|Elasticsearch|Cassandra|"
    r"AWS|Azure|GCP|Terraform|Ansible|CI.CD)\b",
    re.IGNORECASE,
)


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict       = {}

    company = scope.target.name

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        # USPTO patent search by assignee name
        patents = await _search_uspto(client, company, limiter)
        metadata["patents_found"] = len(patents)

        tech_mentions: dict[str, int] = {}

        for patent in patents[:50]:  # cap to avoid huge result sets
            title    = patent.get("inventionTitle", "")
            abstract = patent.get("abstractText", [""])[0] if patent.get("abstractText") else ""
            text     = f"{title} {abstract}"

            # Extract technology mentions from patent text
            techs = [m.lower() for m in _TECH_RE.findall(text)]
            for tech in techs:
                tech_mentions[tech] = tech_mentions.get(tech, 0) + 1

            patent_data = {
                "title":           title,
                "filing_date":     patent.get("filingDate"),
                "application_num": patent.get("patentApplicationNumber"),
                "inventors":       patent.get("inventorNameArrayText", []),
                "technologies":    list(set(techs)),
                "abstract":        abstract[:500],
                "source":          "uspto",
            }
            signals = extract_signals(text).as_dict()
            if signals:
                patent_data["extracted_signals"] = signals

            findings.append({
                "type":  "patent",
                "value": patent.get("patentApplicationNumber", title),
                "data":  patent_data,
            })

        # SearXNG Google Patents fallback
        if not patents:
            gp_results = await _search_google_patents(
                client, config.searxng.url, company, limiter
            )
            for gp in gp_results:
                text  = f"{gp.get('title', '')} {gp.get('snippet', '')}"
                techs = [m.lower() for m in _TECH_RE.findall(text)]
                findings.append({
                    "type":  "patent",
                    "value": gp.get("url", ""),
                    "data":  {
                        "title":       gp.get("title"),
                        "url":         gp.get("url"),
                        "snippet":     gp.get("snippet", "")[:400],
                        "technologies": list(set(techs)),
                        "source":      "google_patents",
                    },
                })

        if tech_mentions:
            findings.append({
                "type":  "patent_tech_stack",
                "value": company,
                "data": {
                    "technologies": sorted(tech_mentions, key=lambda k: -tech_mentions[k])[:20],
                    "counts":       tech_mentions,
                    "source":       "patent_analysis",
                },
            })

    return {
        "module":   "layer0/patents",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _search_uspto(client, company, limiter) -> list[dict]:
    await limiter.acquire("default")
    try:
        r = await client.get(
            _USPTO_SEARCH,
            params={
                "assigneeEntityName": company,
                "start":              0,
                "rows":               50,
            },
            headers={"Accept": "application/json"},
        )
        r.raise_for_status()
        data = r.json()
        return data.get("results", {}).get("patentFileWrapperDataBag", [])
    except Exception as exc:
        log.debug("patents.uspto_failed", company=company, error=str(exc))
        return []


async def _search_google_patents(client, searxng_url, company, limiter) -> list[dict]:
    await limiter.acquire("default")
    try:
        r = await client.get(
            f"{searxng_url}/search",
            params={"q": f'site:patents.google.com "{company}"', "format": "json"},
        )
        r.raise_for_status()
        return r.json().get("results", [])[:20]
    except Exception:
        return []
