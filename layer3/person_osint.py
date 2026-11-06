"""
layer3/person_osint.py — individual person OSINT and digital footprint.

For each person identified in orgchart.py, builds a deeper profile:
  - Social media presence (Twitter/X, GitHub, LinkedIn, Reddit)
  - Technical accounts (GitHub repos, Stack Overflow, HackerNews)
  - Conference talks and publications (reveals technical depth)
  - Personal domains and email addresses
  - Public key infrastructure (SSH keys on GitHub, GPG keys)

People with GitHub accounts reveal their technical stack, coding habits,
and sometimes accidentally commit credentials. Conference speakers reveal
the exact internal tools they use (slides, demos, repos).
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
    "name":     "person_osint",
    "title":    "Person OSINT",
    "description": "Per-individual digital footprint",
    "layer":    3,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": True,
    "depends_on": ['org_chart'],
}

_TIMEOUT = 20


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict       = {"people_researched": 0}

    # Get people from orgchart findings in DB — nothing to research without them
    people = await _get_people_from_db(scope, db)

    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
        for person in people[:20]:  # cap to avoid excessive queries
            name = person.get("name", "")
            if not name or len(name) < 4:
                continue
            metadata["people_researched"] += 1

            # GitHub account search
            gh_profile = await _find_github_profile(client, name, scope.target.name, limiter)
            if gh_profile:
                findings.append({
                    "type":  "github_profile",
                    "value": gh_profile["html_url"],
                    "data":  {**gh_profile, "person": name},
                })

            # SearXNG: social media and conference talks
            social = await _search_person(client, config.searxng.url, name, scope.target.name, limiter)
            for item in social:
                findings.append({
                    "type":  item["type"],
                    "value": item["url"],
                    "data":  {**item, "person": name},
                })

    metadata["findings"] = len(findings)
    return {
        "module":   "layer3/person_osint",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _get_people_from_db(scope: Scope, db: Any) -> list[dict]:
    if db is None:
        return []
    try:
        run_id = await db.get_last_run_id(scope.target.name) or ""
        if not run_id:
            return []
        rows = await db.get_findings(run_id, "person")
        return [r.get("data", {}) for r in rows if r.get("data")]
    except Exception:
        return []


async def _find_github_profile(client, name, company, limiter) -> dict | None:
    import os
    headers = {"Accept": "application/vnd.github+json"}
    token   = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    await limiter.acquire("github")
    try:
        # Search GitHub users
        query = f"{name} {company}"
        r = await client.get(
            "https://api.github.com/search/users",
            params={"q": query, "per_page": "5"},
            headers=headers,
        )
        if r.status_code in (403, 422):
            return None
        r.raise_for_status()
        items = r.json().get("items", [])
        if not items:
            return None

        user = items[0]
        # Fetch full profile
        await limiter.acquire("github")
        r2 = await client.get(user["url"], headers=headers)
        r2.raise_for_status()
        profile = r2.json()
        return {
            "login":       profile.get("login"),
            "name":        profile.get("name"),
            "company":     profile.get("company"),
            "blog":        profile.get("blog"),
            "email":       profile.get("email"),
            "bio":         profile.get("bio"),
            "public_repos": profile.get("public_repos"),
            "html_url":    profile.get("html_url"),
        }
    except Exception:
        return None


async def _search_person(client, searxng_url, name, company, limiter) -> list[dict]:
    items = []
    queries = [
        f'"{name}" site:linkedin.com OR site:twitter.com OR site:x.com',
        f'"{name}" "{company}" conference OR talk OR presentation OR keynote',
    ]
    for query in queries:
        await limiter.acquire("default")
        try:
            r = await client.get(
                f"{searxng_url}/search",
                params={"q": query, "format": "json"},
            )
            r.raise_for_status()
            for result in r.json().get("results", [])[:5]:
                url  = result.get("url", "")
                kind = _classify_person_result(url)
                items.append({
                    "type":    kind,
                    "url":     url,
                    "title":   result.get("title"),
                    "snippet": result.get("content", "")[:300],
                })
        except Exception:
            pass
    return items


def _classify_person_result(url: str) -> str:
    url_l = url.lower()
    if "linkedin.com" in url_l:
        return "linkedin_profile"
    if "twitter.com" in url_l or "x.com" in url_l:
        return "twitter_profile"
    if "github.com" in url_l:
        return "github_profile"
    if "speakerdeck.com" in url_l or "slideshare.net" in url_l:
        return "conference_talk"
    if "youtube.com" in url_l:
        return "conference_talk"
    return "person_mention"
