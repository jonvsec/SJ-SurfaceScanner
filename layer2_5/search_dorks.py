"""
layer2_5/search_dorks.py — LLM-generated Google dorks executed via SearXNG.

Generates sector-specific and target-specific dorks using the local LLM
(never external API — dork queries contain target name which is engagement data).
Executes them through SearXNG for privacy-preserving results.

LLM generates dorks based on:
  - Target company name and domain
  - Sector (fintech/healthcare/manufacturing/etc. from Layer 0)
  - Technologies inferred from job postings (Layer 1)

Dork categories: exposed files, login pages, error messages, backups,
configuration files, exposed databases, internal tools, source code.

All LLM calls use local Ollama regardless of classification — dork prompts
contain the target company name which is engagement-specific.
"""
from __future__ import annotations

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
    "name":     "search_dorks",
    "title":    "Search Dorks",
    "description": "LLM-generated exposure queries run via SearXNG",
    "layer":    2.5,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": True,
}

_TIMEOUT = 20

# Built-in dork templates — LLM supplements these with sector-specific ones
_BASE_DORKS = [
    'site:{domain} filetype:env OR filetype:conf OR filetype:config',
    'site:{domain} inurl:admin OR inurl:login OR inurl:portal',
    'site:{domain} "Index of /" OR "Directory listing"',
    'site:{domain} filetype:sql OR filetype:bak OR filetype:backup',
    'site:{domain} "error" OR "exception" OR "stack trace" OR "debug"',
    '"{company}" "internal use only" OR "confidential" filetype:pdf',
    '"{company}" site:pastebin.com OR site:pastecode.io',
    '"{domain}" ext:yaml OR ext:yml OR ext:json "password" OR "secret"',
    'site:{domain} inurl:swagger OR inurl:api-docs OR inurl:openapi',
    '"{company}" intext:password filetype:xls OR filetype:xlsx',
]


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    llm     = LLMRouter(config)
    findings: list[dict] = []
    metadata: dict       = {"dorks_run": 0, "results_found": 0}

    company = scope.target.name
    domain  = scope.primary_domain or ""
    sector  = scope.target.sector or "technology"

    # Substitute base dorks
    dorks = [
        d.replace("{company}", company).replace("{domain}", domain)
        for d in _BASE_DORKS
    ]

    # Generate sector-specific dorks via LLM
    # ALWAYS use local Ollama for this — company name is engagement data
    llm_dorks = await _generate_llm_dorks(llm, company, domain, sector)
    # The prompt asks the LLM to substitute {company}/{domain} itself, but
    # models sometimes echo the literal placeholders — substitute again here
    # as a safety net so a placeholder never reaches SearXNG as a search term.
    llm_dorks = [d.replace("{company}", company).replace("{domain}", domain) for d in llm_dorks]
    dorks.extend(llm_dorks)
    metadata["llm_dorks_generated"] = len(llm_dorks)

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        for dork in dorks:
            results = await _searxng_search(client, config.searxng.url, dork, limiter)
            metadata["dorks_run"]    += 1
            metadata["results_found"] += len(results)

            for r in results:
                url     = r.get("url", "")
                title   = r.get("title", "")
                snippet = r.get("content", "")
                category = _classify_dork_result(url, title, snippet, dork)

                findings.append({
                    "type":  category,
                    "value": url,
                    "data": {
                        "url":     url,
                        "title":   title,
                        "snippet": snippet[:300],
                        "dork":    dork,
                        "source":  "dork_search",
                    },
                })

    log.info("dorks.complete", dorks=metadata["dorks_run"], results=metadata["results_found"])
    return {
        "module":   "layer2_5/search_dorks",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _generate_llm_dorks(
    llm:     LLMRouter,
    company: str,
    domain:  str,
    sector:  str,
) -> list[str]:
    prompt = f"""Generate 10 targeted Google dorks for a security assessment of {company} (domain: {domain}, sector: {sector}).

Focus on dorks that would find:
1. Exposed configuration files specific to {sector} companies
2. Login pages for common {sector} SaaS tools
3. Error pages revealing technology stack
4. Exposed backups or database dumps
5. Internal documents accidentally indexed

Return ONLY a JSON array of dork strings. Example format:
["site:{domain} filetype:conf", "intitle:\"index of\" site:{domain}"]

Replace {company} and {domain} with actual values in your output."""

    # RULE: always pre-filter + use local LLM for engagement data
    try:
        result = await llm.complete_json(
            prepare_for_llm(prompt, max_chars=2000),
            classification="CONFIDENTIAL",  # company name = engagement data
        )
        if isinstance(result, list):
            return [str(d) for d in result if isinstance(d, str)][:15]
    except Exception as exc:
        log.warning("dorks.llm_failed", error=str(exc))
    return []


async def _searxng_search(
    client:   httpx.AsyncClient,
    base_url: str,
    query:    str,
    limiter:  RateLimiter,
) -> list[dict]:
    await limiter.acquire("default")
    try:
        r = await client.get(
            f"{base_url}/search",
            params={"q": query, "format": "json", "language": "en"},
        )
        r.raise_for_status()
        return r.json().get("results", [])
    except Exception as exc:
        log.warning("dorks.search_failed", query=query[:60], error=str(exc))
        return []


def _classify_dork_result(url: str, title: str, snippet: str, dork: str) -> str:
    url_l = url.lower()
    text  = f"{title} {snippet}".lower()

    if any(ext in url_l for ext in [".env", ".conf", ".config", ".yaml", ".yml"]):
        return "exposed_config"
    if any(ext in url_l for ext in [".sql", ".bak", ".backup", ".dump"]):
        return "exposed_backup"
    if "index of" in text or "directory listing" in text:
        return "directory_listing"
    if any(x in url_l for x in ["/admin", "/login", "/portal", "/console"]):
        return "exposed_admin"
    if "swagger" in url_l or "openapi" in url_l or "api-docs" in url_l:
        return "exposed_api_docs"
    if "pastebin" in url_l or "paste" in url_l:
        return "paste_site"
    if any(x in text for x in ["error", "exception", "stack trace", "debug"]):
        return "error_disclosure"
    return "dork_result"
