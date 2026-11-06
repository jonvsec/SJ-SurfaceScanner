"""
layer3/email_enum.py — email address enumeration and validation.

Discovers email addresses associated with the target organisation:
  1. Hunter.io API (requires HUNTER_API_KEY) — email finder + format detection
  2. Email permutation from known names + domain
  3. SearXNG queries for email addresses in public docs

Backlog (not yet implemented — see DOSSIER.md Section 15):
  4. SMTP VRFY/RCPT verification (active mode via VPS only)

Findings feed breach module and kill chain:
  - Valid executive emails → spear phishing targets
  - Email format (first.last vs f.last) → guess remaining employee emails
  - Catch-all detection → indicates whether guessing is viable
"""
from __future__ import annotations

import os
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
    "name":     "email_enum",
    "title":    "Email Enumeration",
    "description": "Address discovery and pattern inference",
    "layer":    3,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": True,
    "depends_on": ['org_chart'],
}

_TIMEOUT = 20

_EMAIL_FORMATS = [
    "{first}.{last}",
    "{f}{last}",
    "{first}{l}",
    "{first}",
    "{last}",
    "{first}-{last}",
    "{first}_{last}",
]


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict       = {}

    hunter_key = os.environ.get("HUNTER_API_KEY")

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        for domain in scope.all_domains:
            # Hunter.io domain search
            if hunter_key:
                hunter_emails = await _hunter_domain_search(client, domain, hunter_key, limiter)
                for email_data in hunter_emails:
                    findings.append({
                        "type":  "email_address",
                        "value": email_data["value"],
                        "data":  {**email_data, "source": "hunter_io"},
                    })

                # Hunter.io email format detection
                fmt = await _hunter_email_format(client, domain, hunter_key, limiter)
                if fmt:
                    findings.append({
                        "type":  "email_format",
                        "value": domain,
                        "data":  fmt,
                    })

            # SearXNG email extraction
            searxng_emails = await _searxng_emails(client, config.searxng.url, scope.target.name, domain, limiter)
            for email in searxng_emails:
                if not any(f["value"] == email for f in findings):
                    findings.append({
                        "type":  "email_address",
                        "value": email,
                        "data":  {"domain": domain, "source": "web_search"},
                    })

            # Permute emails from known people names
            people = await _get_people(scope, db)
            format_pattern = _infer_format(findings, domain)
            for person in people[:20]:
                name = person.get("name", "")
                parts = name.lower().split()
                if len(parts) >= 2:
                    guessed = _generate_email(parts[0], parts[-1], domain, format_pattern)
                    if guessed:
                        findings.append({
                            "type":  "email_guess",
                            "value": guessed,
                            "data": {
                                "domain":  domain,
                                "name":    name,
                                "format":  format_pattern,
                                "source":  "permutation",
                                "verified": False,
                            },
                        })

    metadata["emails_found"] = sum(1 for f in findings if f["type"] == "email_address")
    metadata["guesses"]      = sum(1 for f in findings if f["type"] == "email_guess")

    return {
        "module":   "layer3/email_enum",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _hunter_domain_search(client, domain, api_key, limiter) -> list[dict]:
    await limiter.acquire("hunter")
    try:
        r = await client.get(
            "https://api.hunter.io/v2/domain-search",
            params={"domain": domain, "api_key": api_key, "limit": 100},
        )
        r.raise_for_status()
        data   = r.json().get("data", {})
        emails = data.get("emails", [])
        return [
            {
                "value":      e.get("value"),
                "first_name": e.get("first_name"),
                "last_name":  e.get("last_name"),
                "position":   e.get("position"),
                "confidence": e.get("confidence"),
                "linkedin":   e.get("linkedin"),
            }
            for e in emails if e.get("value")
        ]
    except Exception as exc:
        log.debug("contact.hunter_failed", domain=domain, error=str(exc))
        return []


async def _hunter_email_format(client, domain, api_key, limiter) -> dict | None:
    await limiter.acquire("hunter")
    try:
        r = await client.get(
            "https://api.hunter.io/v2/domain-search",
            params={"domain": domain, "api_key": api_key, "limit": 1},
        )
        r.raise_for_status()
        data = r.json().get("data", {})
        return {
            "domain":       domain,
            "pattern":      data.get("pattern"),
            "organization": data.get("organization"),
            "disposable":   data.get("disposable"),
            "webmail":      data.get("webmail"),
        }
    except Exception:
        return None


async def _searxng_emails(client, searxng_url, company, domain, limiter) -> list[str]:
    await limiter.acquire("default")
    emails: set[str] = set()
    email_re = re.compile(r"\b[a-zA-Z0-9._%+\-]+@" + re.escape(domain) + r"\b")
    queries = [
        f'"{company}" "@{domain}" email',
        f'site:{domain} "email" OR "contact"',
    ]
    for q in queries:
        try:
            r = await client.get(
                f"{searxng_url}/search",
                params={"q": q, "format": "json"},
            )
            r.raise_for_status()
            for result in r.json().get("results", []):
                text = result.get("content", "") + " " + result.get("title", "")
                for m in email_re.finditer(text):
                    emails.add(m.group(0).lower())
            await limiter.acquire("default")
        except Exception:
            pass
    return sorted(emails)


async def _get_people(scope, db) -> list[dict]:
    if db is None:
        return []
    try:
        run_id = await db.get_last_run_id(scope.target.name) or ""
        rows   = await db.get_findings(run_id, "person") if run_id else []
        return [r.get("data", {}) for r in rows]
    except Exception:
        return []


def _infer_format(findings: list[dict], domain: str) -> str:
    for f in findings:
        if f["type"] == "email_format":
            return f["data"].get("pattern", "{first}.{last}")
    # Guess from known emails
    for f in findings:
        if f["type"] == "email_address":
            email = f["value"].split("@")[0]
            if "." in email:
                return "{first}.{last}"
            if "_" in email:
                return "{first}_{last}"
    return "{first}.{last}"


def _generate_email(first: str, last: str, domain: str, fmt: str) -> str | None:
    if not first or not last:
        return None
    email_user = (
        fmt
        .replace("{first}", first)
        .replace("{last}", last)
        .replace("{f}", first[0])
        .replace("{l}", last[0])
    )
    return f"{email_user}@{domain}"
