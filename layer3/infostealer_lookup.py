"""
layer3/infostealer_lookup.py — Hudson Rock infostealer exposure lookup.

Hudson Rock indexes credentials harvested by info-stealer malware (Redline,
Raccoon, Vidar and similar), which is a different population from the breach
compilations DeHashed and HIBP index. A credential stolen from an infected
machine never appears in a site breach dump, so a clean DeHashed result says
nothing about stealer exposure.

That is not theoretical. On an earlier client engagement DeHashed returned nothing
for the target domain while Hudson Rock held active stealer records for it,
including a corporate login to the client's WordPress admin. See LESSONS #15.

Uses the Cavalier free OSINT endpoints, which need no API key and are therefore
always available. Returned credentials are masked by Hudson Rock at source and
are masked again here before storage.

Queries, per domain and per scope email:
  /osint-tools/search-by-domain   company-wide exposure counts and affected URLs
  /osint-tools/search-by-email    per-identity stealer records
"""
from __future__ import annotations

import time
from typing import Any

import httpx
import structlog

from core.config import Config
from core.ratelimiter import RateLimiter
from core.scope_guard import in_scope
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":        "infostealer_lookup",
    "title":       "Infostealer Exposure",
    "description": "Credentials harvested by info-stealer malware (Hudson Rock)",
    "layer":       3,
    "mode":        ["passive", "semi", "active"],
    "requires":    [],          # free OSINT endpoints, no key needed
    "optional":    True,
}

_BASE    = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"
_TIMEOUT = 35


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0       = time.monotonic()
    limiter  = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict = {
        "domains_checked": 0,
        "emails_checked":  0,
        "domains_exposed": 0,
        "emails_exposed":  0,
        "errors":          0,
    }

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        for domain in scope.all_domains:
            metadata["domains_checked"] += 1
            doc = await _get(client, "search-by-domain", {"domain": domain},
                             limiter, metadata)
            if doc is None:
                continue
            f = _domain_finding(domain, doc)
            if f:
                metadata["domains_exposed"] += 1
                findings.append(f)

        for email in _emails(scope):
            metadata["emails_checked"] += 1
            doc = await _get(client, "search-by-email", {"email": email},
                             limiter, metadata)
            if doc is None:
                continue
            for f in _email_findings(email, doc):
                metadata["emails_exposed"] += 1
                findings.append(f)

    log.info("infostealer.complete",
             domains_exposed=metadata["domains_exposed"],
             emails_exposed=metadata["emails_exposed"],
             errors=metadata["errors"])

    # An error-free run that finds nothing is a real negative. A run where every
    # request failed is a coverage gap and must not read as "no exposure".
    attempted = metadata["domains_checked"] + metadata["emails_checked"]
    blind = attempted > 0 and metadata["errors"] >= attempted

    return {
        "module":   "layer3/infostealer_lookup",
        "status":   "error" if blind else ("success" if findings else "partial"),
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    ("every request to the infostealer source failed, this is a "
                     "coverage gap and not an absence of exposure") if blind else None,
    }


def _emails(scope: Scope) -> list[str]:
    """Scope emails whose domain is in scope. Never query a third party address."""
    out: list[str] = []
    for e in (getattr(scope, "emails", None) or []):
        e = str(e).strip().lower()
        if "@" not in e:
            continue
        if not in_scope(e.split("@", 1)[1], scope):
            log.warning("infostealer.out_of_scope_email_skipped", email=e)
            continue
        out.append(e)
    return sorted(set(out))


async def _get(client, path, params, limiter, metadata) -> dict | None:
    await limiter.acquire("hudsonrock")
    try:
        r = await client.get(f"{_BASE}/{path}", params=params)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        metadata["errors"] += 1
        log.warning("infostealer.query_failed", path=path,
                    params=params, error=str(exc))
        return None


def _domain_finding(domain: str, doc: dict) -> dict | None:
    stats     = doc.get("stats") or {}
    employees = int(doc.get("employees") or 0)
    users     = int(doc.get("users") or 0)
    third     = int(doc.get("third_parties") or 0)
    if not (employees or users or third):
        return None

    # Employee exposure means a corporate machine. User exposure means a
    # customer or a third party holding a login to the client's systems. The
    # second is still the client's problem, it is just someone else's machine.
    severity = "critical" if employees else "high"

    return {
        "type":  "infostealer_domain_exposure",
        "value": domain,
        "data": {
            "domain":            domain,
            "employees_exposed": employees,
            "users_exposed":     users,
            "third_parties":     third,
            "affected_urls":     (stats.get("employees_urls") or []) +
                                 (stats.get("clients_urls") or []),
            "total_records":     doc.get("total"),
            "severity":          severity,
            "source":            "hudsonrock",
            "note":              "stealer-harvested credentials, a different "
                                 "population from site breach dumps",
        },
    }


def _email_findings(email: str, doc: dict) -> list[dict]:
    out: list[dict] = []
    for s in (doc.get("stealers") or []):
        out.append({
            "type":  "infostealer_credential_exposure",
            "value": email,
            "data": {
                "email":                    email,
                "date_compromised":         s.get("date_compromised"),
                "computer_name":            s.get("computer_name"),
                "operating_system":         s.get("operating_system"),
                "antiviruses":              s.get("antiviruses"),
                "ip_masked":                s.get("ip"),
                "total_corporate_services": s.get("total_corporate_services"),
                "total_user_services":      s.get("total_user_services"),
                # Masked at source by Hudson Rock. Stored as-is, never unmasked,
                # and never resolved to plaintext from any other source.
                "top_logins_masked":        s.get("top_logins"),
                "password_count":           len(s.get("top_passwords") or []),
                "severity":                 "critical",
                "source":                   "hudsonrock",
            },
        })
    return out
