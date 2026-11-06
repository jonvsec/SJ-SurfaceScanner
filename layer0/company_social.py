"""
layer0/company_social.py — LinkedIn company page intelligence via SearXNG.

Avoids direct LinkedIn scraping (heavily blocked). Instead:
  1. Queries the local SearXNG instance for the company's LinkedIn page
  2. Extracts structured data from SearXNG result snippets
  3. Optionally fetches the public LinkedIn page via httpx for meta tags

Extracts: employee count, industry, specialties, HQ location, founding year,
technologies mentioned in company description.

No LinkedIn credentials or API key required.
"""
from __future__ import annotations

import re
import time
from typing import Any

import httpx
import structlog

from core.config import Config
from core.ratelimiter import RateLimiter
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "company_social",
    "title":    "Company Social Page",
    "description": "Employee count, industry and founding year from public profile",
    "layer":    0,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": True,
}

_TIMEOUT = 20


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict       = {}

    searxng_url = config.searxng.url
    engines     = config.searxng.engines
    company     = scope.target.name

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        # Search SearXNG for the LinkedIn company page
        results = await _searxng_search(
            client, searxng_url,
            f'site:linkedin.com/company "{company}"',
            limiter, engines,
        )
        metadata["searxng_results"] = len(results)

        linkedin_url = None
        for r in results:
            url = r.get("url", "")
            if "linkedin.com/company/" in url:
                linkedin_url = url
                break

        if not linkedin_url:
            # Try without site: restriction
            results = await _searxng_search(
                client, searxng_url,
                f'"{company}" linkedin.com/company',
                limiter, engines,
            )
            for r in results:
                url = r.get("url", "")
                if "linkedin.com/company/" in url:
                    linkedin_url = url
                    break

        # Direct fallback when search returns nothing (every SearXNG engine can
        # be CAPTCHA blocked). The public company page is fetchable directly, and
        # the company name usually maps straight to the page slug. Confirm by a
        # real fetch so a wrong guess is not recorded.
        if not linkedin_url:
            slug = re.sub(r"[^a-z0-9-]", "", company.lower().replace(" ", "-"))
            if slug:
                guess = f"https://www.linkedin.com/company/{slug}/"
                if await _fetch_linkedin_page(client, guess, limiter):
                    linkedin_url = guess
                    metadata["linkedin_url_source"] = "direct_slug"

        if linkedin_url:
            metadata["linkedin_url"] = linkedin_url
            findings.append({
                "type":  "linkedin_page",
                "value": linkedin_url,
                "data":  {"url": linkedin_url},
            })

            # Extract info from search result snippets
            snippets = [r.get("content", "") for r in results if linkedin_url in r.get("url", "")]
            for snippet in snippets:
                extracted = _extract_from_snippet(snippet, company)
                if extracted:
                    findings.append({
                        "type":  "company_profile",
                        "value": company,
                        "data":  extracted,
                    })
                    break

            # Try fetching the public page for og: meta tags
            profile_data = await _fetch_linkedin_page(client, linkedin_url, limiter)
            if profile_data:
                findings.append({
                    "type":  "company_profile",
                    "value": company,
                    "data":  profile_data,
                })

        # Also search for recent company news/announcements mentioning tech
        tech_results = await _searxng_search(
            client, searxng_url,
            f'"{company}" technology OR infrastructure OR cloud OR engineering',
            limiter, engines,
        )
        tech_mentions = _extract_tech_mentions([r.get("content", "") for r in tech_results])
        if tech_mentions:
            findings.append({
                "type":  "technology_mention",
                "value": company,
                "data":  {"technologies": tech_mentions, "source": "web_search"},
            })
            metadata["technology_mentions"] = tech_mentions

    status = "success" if findings else "partial"
    return {
        "module":   "layer0/company_social",
        "status":   status,
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None if findings else "No LinkedIn data found",
    }


async def _searxng_search(
    client:      httpx.AsyncClient,
    base_url:    str,
    query:       str,
    limiter:     RateLimiter,
    engines:     str | None = None,
) -> list[dict]:
    await limiter.acquire("default")
    try:
        params = {"q": query, "format": "json", "language": "en"}
        # Pin the engine set when configured. The SearXNG default set is
        # frequently CAPTCHA or rate-limit blocked and then returns nothing, so
        # an allowlist of working engines (for example bing) is what makes the
        # query actually return results.
        if engines:
            params["engines"] = engines
        r = await client.get(f"{base_url}/search", params=params)
        r.raise_for_status()
        return r.json().get("results", [])
    except Exception as exc:
        log.warning("linkedin.searxng_failed", query=query, error=str(exc))
        return []


async def _fetch_linkedin_page(
    client:      httpx.AsyncClient,
    url:         str,
    limiter:     RateLimiter,
) -> dict | None:
    """Fetch public LinkedIn company page and extract og: meta tags."""
    await limiter.acquire("default")
    try:
        r = await client.get(
            url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (compatible; Googlebot/2.1; "
                    "+http://www.google.com/bot.html)"
                )
            },
        )
        r.raise_for_status()
        return _parse_og_tags(r.text)
    except Exception as exc:
        log.debug("linkedin.page_fetch_failed", url=url, error=str(exc))
        return None


def _parse_og_tags(html: str) -> dict | None:
    og: dict[str, str] = {}
    for match in re.finditer(
        r'<meta[^>]+property=["\']og:([^"\']+)["\'][^>]+content=["\']([^"\']*)["\']',
        html, re.IGNORECASE
    ):
        og[match.group(1)] = match.group(2)

    if not og:
        return None

    # Also try description meta tag
    desc_match = re.search(
        r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']',
        html, re.IGNORECASE
    )

    return {
        "title":       og.get("title"),
        "description": og.get("description") or (desc_match.group(1) if desc_match else None),
        "image":       og.get("image"),
        "type":        og.get("type"),
    }


def _extract_from_snippet(snippet: str, company: str) -> dict | None:
    """Pull structured facts from a SearXNG result snippet."""
    data: dict[str, Any] = {}

    # Employee count patterns
    emp_match = re.search(
        r"(\d[\d,]+)\s*(?:employees?|members?|followers?)",
        snippet, re.IGNORECASE
    )
    if emp_match:
        data["employee_count"] = emp_match.group(1).replace(",", "")

    # Industry
    ind_match = re.search(
        r"(?:industry|sector)[:\s]+([A-Za-z &,]+?)(?:\.|,|\d|$)",
        snippet, re.IGNORECASE
    )
    if ind_match:
        data["industry"] = ind_match.group(1).strip()

    # HQ location
    hq_match = re.search(
        r"(?:headquarter|hq|location)[s]?[:\s]+([A-Za-z ,]+?)(?:\.|,\s*[A-Z]{2}|$)",
        snippet, re.IGNORECASE
    )
    if hq_match:
        data["headquarters"] = hq_match.group(1).strip()

    # Founded year
    year_match = re.search(r"founded[:\s]+(\d{4})", snippet, re.IGNORECASE)
    if year_match:
        data["founded"] = year_match.group(1)

    return data if data else None


_TECH_KEYWORDS = re.compile(
    r"\b(AWS|Azure|GCP|Kubernetes|Docker|Terraform|Ansible|Jenkins|GitLab|GitHub|"
    r"Datadog|Splunk|Elasticsearch|Kafka|PostgreSQL|MySQL|MongoDB|Redis|"
    r"React|Angular|Vue|Node\.js|Python|Go|Rust|Java|\.NET|"
    r"Okta|Auth0|CrowdStrike|Palo Alto|Cloudflare|Fastly|Akamai|"
    r"Jira|Confluence|Slack|Teams|Salesforce|Workday|ServiceNow)\b",
    re.IGNORECASE,
)


def _extract_tech_mentions(snippets: list[str]) -> list[str]:
    seen: set[str] = set()
    for snippet in snippets:
        for match in _TECH_KEYWORDS.finditer(snippet):
            seen.add(match.group(0).lower())
    return sorted(seen)
