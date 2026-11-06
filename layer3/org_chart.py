"""
layer3/org_chart.py — organisational hierarchy mapping.

Builds a structured org chart from public sources without touching the target:
  - LinkedIn company page (via SearXNG snippets)
  - Company website /about, /team, /leadership pages
  - Press releases and news articles
  - Conference speaker bios

Named executives from SEC 10-K/proxy (DEF 14A) filings are a backlog item
(see DOSSIER.md Section 15) — EDGAR's full-text search index only returns
filer/company identity metadata (`display_names`, e.g. "Apple Inc. (AAPL)
(CIK 0000320193)"), not the named-officer text inside the filing itself.
Getting real executive names requires fetching and parsing the DEF 14A
document body.

Output drives social engineering vectors in the kill chain:
  - C-suite names → spear phishing targets
  - IT/security staff → pretexting targets
  - New employees → most susceptible to phishing (onboarding confusion)
  - Ex-employees → insider threat / credential reuse vector
"""
from __future__ import annotations

import re
import time
from typing import Any

import httpx
import structlog

from core.config import Config
from core.llm import LLMRouter
from core.prefilter import prepare_for_llm
from core.ratelimiter import RateLimiter
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "org_chart",
    "title":    "Organisation Chart",
    "description": "Hierarchy and reporting structure",
    "layer":    3,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": True,
}

_TIMEOUT = 20

_EXEC_TITLES = re.compile(
    r"\b(CEO|CTO|CISO|CFO|COO|CIO|CPO|VP|SVP|EVP|President|Director|"
    r"Head of|Chief\s+\w+|Principal|Fellow|Managing\s+Director|"
    r"Security\s+Engineer|DevOps|Infrastructure|Platform\s+Lead|"
    r"IT\s+Manager|Sys\s+Admin|Network\s+Engineer|Cloud\s+Architect)\b",
    re.IGNORECASE,
)

_LEADERSHIP_PATHS = [
    "/about", "/about-us", "/team", "/leadership", "/management",
    "/people", "/executives", "/board", "/founders", "/company",
]


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    llm     = LLMRouter(config)
    findings: list[dict] = []
    metadata: dict       = {"people_found": 0}

    company = scope.target.name
    domain  = scope.primary_domain or ""

    async with httpx.AsyncClient(
        timeout=_TIMEOUT, follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (compatible; SurfaceScanner/1.0)"},
    ) as client:
        # 1. Search SearXNG for leadership team
        search_results = await _searxng_people(client, config.searxng.url, company, limiter)
        people_from_search = _extract_people_from_snippets(search_results)
        for person in people_from_search:
            findings.append({
                "type":  "person",
                "value": person["name"],
                "data":  {**person, "source": "web_search"},
            })

        # 2. Scrape company website leadership pages
        for path in _LEADERSHIP_PATHS:
            if not domain:
                break
            url = f"https://{domain}{path}"
            await limiter.acquire("default")
            try:
                r = await client.get(url, timeout=10)
                if r.status_code == 200 and len(r.text) > 500:
                    page_people = _extract_people_from_html(r.text, url)
                    for person in page_people:
                        if not any(f["value"] == person["name"] for f in findings):
                            findings.append({
                                "type":  "person",
                                "value": person["name"],
                                "data":  {**person, "source": "company_website", "url": url},
                            })
            except Exception:
                pass

    # 3. LLM: infer org structure from all found people
    if findings:
        people_list = [f["value"] + " - " + f["data"].get("title", "") for f in findings if f["type"] == "person"]
        org_structure = await _infer_org_structure(llm, company, people_list, scope.data_classification)
        if org_structure:
            findings.append({
                "type":  "org_structure",
                "value": company,
                "data":  org_structure,
            })

    metadata["people_found"] = sum(1 for f in findings if f["type"] == "person")
    log.info("orgchart.complete", people=metadata["people_found"])

    return {
        "module":   "layer3/org_chart",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _searxng_people(client, base_url, company, limiter):
    await limiter.acquire("default")
    queries = [
        f'"{company}" CEO OR CTO OR CISO OR "Chief" site:linkedin.com',
        f'"{company}" leadership team OR executive team',
    ]
    results = []
    for query in queries:
        try:
            r = await client.get(
                f"{base_url}/search",
                params={"q": query, "format": "json", "language": "en"},
            )
            r.raise_for_status()
            results.extend(r.json().get("results", []))
            await limiter.acquire("default")
        except Exception:
            pass
    return results


def _extract_people_from_snippets(results: list[dict]) -> list[dict]:
    people = []
    seen   = set()
    name_pattern = re.compile(r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b")

    for result in results:
        text = f"{result.get('title', '')} {result.get('content', '')}"
        if not _EXEC_TITLES.search(text):
            continue
        for name_match in name_pattern.finditer(text):
            name = name_match.group(1)
            if len(name) < 5 or name in seen:
                continue
            # Find nearby title
            start = max(0, name_match.start() - 100)
            end   = min(len(text), name_match.end() + 100)
            context = text[start:end]
            title_match = _EXEC_TITLES.search(context)
            title = title_match.group(0) if title_match else None
            seen.add(name)
            people.append({"name": name, "title": title, "context": context[:150]})
    return people


def _extract_people_from_html(html: str, url: str) -> list[dict]:
    """Extract names and titles from company website pages."""
    import re as _re
    clean = _re.sub(r"<[^>]+>", " ", html)
    clean = _re.sub(r"\s+", " ", clean)
    return _extract_people_from_snippets([{"title": url, "content": clean[:5000]}])


async def _infer_org_structure(llm, company, people_list, classification) -> dict | None:
    if not people_list:
        return None
    prompt = f"""Given these people identified at {company}:

{chr(10).join(people_list[:20])}

Infer the organizational structure as a JSON object with:
{{
  "c_suite": ["list of C-level executives"],
  "it_security": ["list of IT/security personnel"],
  "engineering": ["list of engineering leaders"],
  "high_value_targets": ["people most valuable for social engineering"],
  "confidence": "high/medium/low"
}}"""
    try:
        return await llm.complete_json(
            prepare_for_llm(prompt, max_chars=3000),
            classification=classification,
        )
    except Exception:
        return None
