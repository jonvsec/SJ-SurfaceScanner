"""
layer2/subdomain/cert_transparency.py, certificate transparency log enumeration.

Queries crt.sh for all TLS certificates ever issued for target domains.
Certificate transparency logs are public and reveal every subdomain that
has ever had a valid TLS certificate, including forgotten, dev, and internal
subdomains that operators think are private.

Also queries by organization name (from scope.target.name) to catch
certificates for subsidiaries and alternate domains not listed in scope.

No API key. No rate limit stated. Use default limiter to be polite.
"""
from __future__ import annotations

import asyncio
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
    "name":     "cert_transparency",
    "title":    "Certificate Transparency",
    "description": "Subdomains from public TLS certificate logs",
    "layer":    2,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": False,
}

_BASE        = "https://crt.sh"
_CERTSPOTTER = "https://api.certspotter.com/v1"

# crt.sh returns sustained 502/429 for long stretches. Retry with backoff,
# then fall back to Certspotter rather than reporting "no certificates".
_CRTSH_ATTEMPTS = 3
_CRTSH_BACKOFF  = 2.0

# Certspotter's free tier hard-caps a response at 100 issuances and ignores a
# larger `limit`, so results must be paged with `after=`. The page ceiling
# bounds a pathological domain at ~5000 certificates.
_CERTSPOTTER_PAGE      = 100
_CERTSPOTTER_MAX_PAGES = 50

# Optional. Unauthenticated Certspotter is rate limited to roughly a single
# page per domain; a free API key raises that substantially. Absence only
# costs coverage, so the module stays enabled either way.
_CERTSPOTTER_TOKEN = os.getenv("CERTSPOTTER_API_KEY", "").strip()


class _CTSourceError(Exception):
    """A CT source failed after retries, try the next source."""
_TIMEOUT = 30

# crt.sh occasionally returns an anomalous volume of names for a single
# domain (SAN-stuffing / cert abuse on commonly-squatted domains). A query
# returning more candidates than this is flagged as suspected noise rather
# than trusted as real subdomains, dnsx resolution remains the ground truth.
_CONTAMINATION_THRESHOLD = 2000


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict       = {
        "queries": 0,
        "certs_found": 0,
        "contamination_suspected": [],
        "sources_used": {},
        "crtsh_failures": [],
        "all_sources_failed": [],
    }
    seen_subdomains: set[str] = set()

    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
        # Query by each domain (wildcard prefix catches all subdomains)
        for domain in scope.all_domains:
            certs = await _certs_for_domain(client, domain, limiter, metadata)
            metadata["queries"] += 1
            metadata["certs_found"] += len(certs)

            before = len(seen_subdomains)
            _extract_subdomains(certs, domain, seen_subdomains, findings)
            added = len(seen_subdomains) - before

            if added > _CONTAMINATION_THRESHOLD:
                log.warning("crtsh.contamination_suspected", domain=domain, count=added)
                metadata["contamination_suspected"].append({"domain": domain, "count": added})

        # Query by organization name to catch unclaimed subsidiary certs.
        # Certspotter has no org-name search, so this is crt.sh only, a
        # failure here loses subsidiary certs but not per-domain coverage.
        try:
            org_certs = await _query_crtsh(
                client, scope.target.name, limiter, by_org=True
            )
        except _CTSourceError:
            metadata["crtsh_failures"].append(f"org:{scope.target.name}")
            org_certs = []
        metadata["queries"]    += 1
        metadata["certs_found"] += len(org_certs)
        org_before = len(seen_subdomains)
        for cert in org_certs:
            for name in _names_from_cert(cert):
                if name not in seen_subdomains and _looks_like_domain(name):
                    seen_subdomains.add(name)
                    findings.append({
                        "type":  "certificate",
                        "value": name,
                        "data": {
                            "common_name":  cert.get("common_name"),
                            "issuer":       cert.get("issuer_name"),
                            "not_before":   cert.get("not_before"),
                            "not_after":    cert.get("not_after"),
                            "source":       "org_search",
                        },
                    })

        org_added = len(seen_subdomains) - org_before
        if org_added > _CONTAMINATION_THRESHOLD:
            log.warning("crtsh.contamination_suspected", domain=scope.target.name, count=org_added)
            metadata["contamination_suspected"].append(
                {"domain": f"org:{scope.target.name}", "count": org_added}
            )

    metadata["unique_subdomains"] = len(seen_subdomains)

    # Distinguish "this domain genuinely has no certificates" from "every CT
    # source was unreachable". Reporting the second as success is how an
    # entire discovery source disappears from a run without anyone noticing.
    total_failed = len(metadata["all_sources_failed"])
    if total_failed == len(scope.all_domains) and not findings:
        log.error("ct.all_sources_failed", domains=metadata["all_sources_failed"])
        return {
            "module":   "layer2/subdomain/cert_transparency",
            "status":   "error",
            "findings": [],
            "metadata": metadata,
            "duration": time.monotonic() - t0,
            "error":    "all CT sources unreachable (crt.sh and certspotter)",
        }

    log.info(
        "crtsh.complete",
        subdomains=len(seen_subdomains),
        sources=metadata["sources_used"],
        crtsh_failures=len(metadata["crtsh_failures"]),
    )

    return {
        "module":   "layer2/subdomain/cert_transparency",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _query_crtsh(
    client:  httpx.AsyncClient,
    query:   str,
    limiter: RateLimiter,
    by_org:  bool = False,
) -> list[dict]:
    """
    Query crt.sh, retrying transient server-side failures.

    crt.sh is chronically unstable (sustained 502s and 429s). Retries use
    exponential backoff; a persistent failure raises _CTSourceError so the
    caller can fall back to another CT log rather than silently recording
    "no certificates found".
    """
    last_exc: Exception | None = None

    for attempt in range(_CRTSH_ATTEMPTS):
        await limiter.acquire("default")
        try:
            if by_org:
                url = f"{_BASE}/?O={query}&output=json"
            else:
                url = f"{_BASE}/?q={query}&output=json"
            r = await client.get(url, headers={"Accept": "application/json"})
            r.raise_for_status()
            return r.json() if r.content else []
        except Exception as exc:
            last_exc = exc
            if attempt < _CRTSH_ATTEMPTS - 1:
                await asyncio.sleep(_CRTSH_BACKOFF * (2 ** attempt))

    log.warning("crtsh.query_failed", query=query, error=str(last_exc))
    raise _CTSourceError(str(last_exc))


async def _query_certspotter(
    client:  httpx.AsyncClient,
    domain:  str,
    limiter: RateLimiter,
) -> list[dict]:
    """
    Fallback CT source, SSLMate Certspotter.

    Free tier needs no API key. Returns records shaped like crt.sh rows so
    _extract_subdomains can consume them unchanged.
    """
    rows: list[dict] = []
    after: str | None = None

    # Certspotter's free tier returns at most 100 issuances per request and
    # ignores a larger `limit`. Without paging on `after=` a busy domain is
    # silently truncated to its first 100 certificates, which looks like a
    # successful query, not a partial one.
    for _ in range(_CERTSPOTTER_MAX_PAGES):
        await limiter.acquire("default")
        url = (
            f"{_CERTSPOTTER}/issuances?domain={domain}"
            "&include_subdomains=true&expand=dns_names&expand=issuer"
        )
        if after:
            url += f"&after={after}"

        headers = {"Accept": "application/json"}
        if _CERTSPOTTER_TOKEN:
            headers["Authorization"] = f"Bearer {_CERTSPOTTER_TOKEN}"

        r = await client.get(url, headers=headers)

        # The free tier rate-limits aggressively and will 429 partway through
        # paging. Keep what has already been collected rather than raising and
        # discarding the whole domain, partial CT data beats none.
        if r.status_code == 429:
            log.warning(
                "certspotter.rate_limited",
                domain=domain,
                collected=len(rows),
                detail="partial results; set CERTSPOTTER_API_KEY to page further",
            )
            break

        # First page failing outright is a real error; a later page failing
        # still leaves usable data.
        if r.status_code >= 400 and not rows:
            r.raise_for_status()
        if r.status_code >= 400:
            log.warning(
                "certspotter.page_failed",
                domain=domain, status=r.status_code, collected=len(rows),
            )
            break

        page = r.json() or []
        if not page:
            break

        for issuance in page:
            names = issuance.get("dns_names") or []
            issuer = (issuance.get("issuer") or {}).get("friendly_name")
            rows.append({
                "name_value":  "\n".join(names),
                "common_name": names[0] if names else None,
                "issuer_name": issuer,
                "not_before":  issuance.get("not_before"),
                "not_after":   issuance.get("not_after"),
            })

        # A short page means the log is exhausted.
        if len(page) < _CERTSPOTTER_PAGE:
            break
        after = page[-1].get("id")
        if not after:
            break
    else:
        log.warning(
            "certspotter.page_cap_reached",
            domain=domain,
            pages=_CERTSPOTTER_MAX_PAGES,
            detail="results may still be truncated",
        )

    return rows


async def _certs_for_domain(
    client:  httpx.AsyncClient,
    domain:  str,
    limiter: RateLimiter,
    metadata: dict,
) -> list[dict]:
    """
    Walk the certificate-transparency fallback chain until one source answers.

    crt.sh is the best single source but returns sustained 502/429, so rather
    than retry-loop a dead endpoint the module pivots through alternates that
    carry the same CT data on different infrastructure. The first source that
    returns rows wins, and the source that answered is recorded. The last two
    (URLScan, Anubis) are passive-DNS mirrors rather than true CT logs, kept as
    a floor so a domain never silently reports zero.

    Order: crt.sh, Certspotter, Censys (key-gated), Calidog CT mirror, OTX
    passive DNS, ThreatMiner, URLScan, Anubis-DB.
    """
    def _record(name: str, certs: list[dict]) -> list[dict]:
        metadata["sources_used"].setdefault(name, 0)
        metadata["sources_used"][name] += 1
        if name != "crtsh":
            log.info("crtsh.fallback_used", domain=domain, source=name, rows=len(certs))
        return certs

    # 1. crt.sh (its own retry + backoff lives in _query_crtsh)
    try:
        certs = await _query_crtsh(client, f"%.{domain}", limiter)
        if certs:
            return _record("crtsh", certs)
    except _CTSourceError:
        metadata["crtsh_failures"].append(domain)

    # 2-8. ordered fallbacks. Each returns crt.sh-shaped rows or raises.
    fallbacks = [
        ("certspotter", _query_certspotter),
        ("censys",      _query_censys),
        ("calidog",     _query_calidog),
        ("otx",         _query_otx),
        ("threatminer", _query_threatminer),
        ("urlscan",     _query_urlscan),
        ("anubis",      _query_anubis),
    ]
    for name, fn in fallbacks:
        try:
            certs = await fn(client, domain, limiter)
        except Exception as exc:
            log.debug("ct.source_failed", domain=domain, source=name, error=str(exc)[:160])
            continue
        if certs:
            return _record(name, certs)

    log.warning("ct.all_sources_empty", domain=domain)
    metadata["all_sources_failed"].append(domain)
    return []


def _rows_from_names(names: list[str], source: str) -> list[dict]:
    """Wrap a bare hostname list as crt.sh-shaped rows so _extract_subdomains
    (which reads name_value) consumes passive-DNS and mirror sources unchanged."""
    uniq = sorted({n.strip().lower().lstrip("*.") for n in names if n and n.strip()})
    if not uniq:
        return []
    return [{"name_value": "\n".join(uniq), "common_name": None,
             "issuer_name": source, "not_before": None, "not_after": None}]


async def _query_censys(client, domain, limiter) -> list[dict]:
    """Censys certificates search. Key-gated: needs CENSYS_API_ID and
    CENSYS_API_SECRET, absent keys skip it (returns [])."""
    api_id  = os.getenv("CENSYS_API_ID", "").strip()
    api_sec = os.getenv("CENSYS_API_SECRET", "").strip()
    if not (api_id and api_sec):
        return []
    await limiter.acquire("default")
    r = await client.post(
        "https://search.censys.io/api/v2/certificates/search",
        params={"q": f"names: {domain}", "per_page": 100},
        auth=(api_id, api_sec),
        headers={"Accept": "application/json"},
    )
    r.raise_for_status()
    names: list[str] = []
    for hit in (r.json().get("result", {}).get("hits", []) or []):
        names.extend(hit.get("names", []) or [])
    return _rows_from_names(names, "censys")


async def _query_calidog(client, domain, limiter) -> list[dict]:
    """Calidog certstream historical CT mirror. Rows already carry name_value."""
    await limiter.acquire("default")
    r = await client.get(f"https://crt.calidog.io/?q={domain}",
                         headers={"Accept": "application/json"})
    r.raise_for_status()
    rows = r.json() or []
    names: list[str] = []
    for row in rows:
        val = row.get("name_value") or row.get("common_name") or ""
        names.extend(re.split(r"[\n,\s]+", val))
    return _rows_from_names(names, "calidog")


async def _query_otx(client, domain, limiter) -> list[dict]:
    """AlienVault OTX passive DNS. Free, no key."""
    await limiter.acquire("default")
    r = await client.get(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
        headers={"Accept": "application/json"})
    r.raise_for_status()
    names = [rec.get("hostname", "") for rec in (r.json().get("passive_dns", []) or [])]
    return _rows_from_names(names, "otx")


async def _query_threatminer(client, domain, limiter) -> list[dict]:
    """ThreatMiner subdomain index (rt=5). Free, no key."""
    await limiter.acquire("default")
    r = await client.get(
        f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5",
        headers={"Accept": "application/json"})
    r.raise_for_status()
    return _rows_from_names(r.json().get("results", []) or [], "threatminer")


async def _query_urlscan(client, domain, limiter) -> list[dict]:
    """URLScan passive DNS via past scans. Free, no key."""
    await limiter.acquire("default")
    r = await client.get(
        f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000",
        headers={"Accept": "application/json"})
    r.raise_for_status()
    names = [res.get("page", {}).get("domain", "")
             for res in (r.json().get("results", []) or [])]
    return _rows_from_names(names, "urlscan")


async def _query_anubis(client, domain, limiter) -> list[dict]:
    """Anubis-DB subdomain mirror. Free, no key, last resort."""
    await limiter.acquire("default")
    r = await client.get(f"https://anubisdb.com/anubis/subdomains/{domain}",
                         headers={"Accept": "application/json",
                                  "User-Agent": "Mozilla/5.0"})
    r.raise_for_status()
    return _rows_from_names(r.json() or [], "anubis")


def _extract_subdomains(
    certs:    list[dict],
    domain:   str,
    seen:     set[str],
    findings: list[dict],
) -> None:
    for cert in certs:
        for name in _names_from_cert(cert):
            if name in seen:
                continue
            # Only keep names that are subdomains of the target domain
            if not (name.endswith(f".{domain}") or name == domain):
                continue
            seen.add(name)
            findings.append({
                "type":  "subdomain",
                "value": name,
                "data": {
                    "common_name": cert.get("common_name"),
                    "issuer":      cert.get("issuer_name"),
                    "not_before":  cert.get("not_before"),
                    "not_after":   cert.get("not_after"),
                    "source":      "crtsh",
                },
            })


def _names_from_cert(cert: dict) -> list[str]:
    """Extract all DNS names from a crt.sh certificate record."""
    names = set()
    for field in ("common_name", "name_value", "matching_identities"):
        val = cert.get(field, "") or ""
        for part in re.split(r"[\n,\s]+", val):
            part = part.strip().lower().lstrip("*.")
            if part:
                names.add(part)
    return list(names)


def _looks_like_domain(name: str) -> bool:
    return bool(re.match(r"^[a-z0-9][a-z0-9.\-]+\.[a-z]{2,}$", name))
