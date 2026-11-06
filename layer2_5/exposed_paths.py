"""
layer2_5/exposed_paths.py — Cerast Intelligence exposed-path search.

Cerast Intelligence (search.cerast-intelligence.com) maintains a corpus of
observed domains annotated with exposed paths and misconfigurations, queryable
by case-insensitive substring over the domain. A substring query is useful in
two directions:

  * exposure   — known-bad paths already observed on in-scope hosts, without
                 the assessor sending a single request to the target
  * discovery  — a brand substring ("smartsoft") returns every observed domain
                 containing it, which can surface root domains that subdomain
                 enumeration cannot reach

ACCESS MODEL — why this module requires a key.

The public search UI is gated by Cloudflare Turnstile. `/api/search` returns
`{"error":"verification required"}` to any unauthenticated caller, and
`/api/session` returns `{"error":"missing token"}`. The operator states
explicitly on the search page: "Searching from a script or tool? Request an API
key to skip this check entirely."

Automating around Turnstile would circumvent an anti-abuse control the operator
deliberately deployed, against their documented wishes, when a sanctioned path
exists. This module therefore declares CERAST_API_KEY in MODULE_META["requires"]
and the registry auto-disables it until a key is configured — the same pattern
used for Shodan, IntelX and DeHashed. Request a key from the operator.

AUTHENTICATION SHAPE IS UNVERIFIED. Cerast publishes no API documentation, so
the exact header could not be confirmed without a key. Both common conventions
are attempted (`Authorization: Bearer` then `X-API-Key`), and whichever is
accepted is recorded in the result metadata so the working form becomes known
after the first successful run. If neither is accepted the module reports a
clear error rather than a silent empty result.

Rate limit: unknown. Uses the shared limiter's default bucket, conservatively.
Data classification: SEMI-PUBLIC (third-party observations of public hosts).
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
    "name":     "exposed_paths",
    "title":    "Exposed Paths (Cerast)",
    "description": "Third-party corpus of observed exposed paths and misconfigurations, searched by domain substring",
    "layer":    2.5,
    "mode":     ["passive", "semi", "active"],
    "requires": ["CERAST_API_KEY"],
    "optional": True,
}

_BASE    = "https://search.cerast-intelligence.com"
_TIMEOUT = 30
_MIN_QUERY_LEN = 3          # the service rejects shorter substrings

_UA = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"),
    "Accept": "application/json",
}


async def run(scope: Scope, config: Config, db: Any) -> dict:
    import os

    t0      = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict = {
        "queries_run":   0,
        "queries_ok":    0,
        "auth_scheme":   None,
        "domains_seen":  0,
        "paths_seen":    0,
    }

    api_key = os.getenv("CERAST_API_KEY", "").strip()
    if not api_key:
        # Registry should prevent this, but never assume.
        return _result("error", findings, metadata, t0,
                       error="CERAST_API_KEY not set")

    queries = _build_queries(scope)
    metadata["queries_planned"] = len(queries)

    seen_domains: set[str] = set()

    async with httpx.AsyncClient(headers=_UA, timeout=_TIMEOUT,
                                 follow_redirects=True) as client:
        scheme = None
        for query in queries:
            await limiter.acquire("default")
            metadata["queries_run"] += 1
            payload, scheme = await _search(client, query, api_key, scheme)
            if payload is None:
                continue
            metadata["queries_ok"] += 1
            metadata["auth_scheme"] = scheme

            for entry in _iter_records(payload):
                domain = (entry.get("domain") or entry.get("host") or "").lower()
                path   = entry.get("path") or entry.get("url") or ""
                if not domain:
                    continue
                seen_domains.add(domain)
                if path:
                    metadata["paths_seen"] += 1
                    findings.append({
                        "type":  "exposed_path",
                        "value": f"{domain}{path}",
                        "data": {
                            "domain":     domain,
                            "path":       path,
                            "status":     entry.get("status") or entry.get("status_code"),
                            "category":   entry.get("category") or entry.get("type"),
                            "observed":   entry.get("observed") or entry.get("last_seen"),
                            "query":      query,
                            "source":     "cerast_intelligence",
                        },
                    })

            # A brand substring can return domains outside the declared scope.
            # These are candidates, not confirmed client assets — attribution is
            # the caller's job, so they are typed distinctly.
            known = {d.lower() for d in scope.all_domains}
            for domain in sorted(seen_domains):
                if not any(domain == k or domain.endswith("." + k) for k in known):
                    findings.append({
                        "type":  "candidate_domain",
                        "value": domain,
                        "data": {
                            "domain":     domain,
                            "query":      query,
                            "source":     "cerast_intelligence",
                            "attributed": False,
                            "note":       "substring match only — ownership NOT established",
                        },
                    })
            seen_domains.clear()

    metadata["domains_seen"] = len({f["data"]["domain"] for f in findings
                                    if "domain" in f.get("data", {})})

    if metadata["queries_ok"] == 0:
        return _result("error", findings, metadata, t0,
                       error="no query succeeded — API key rejected under both "
                             "Bearer and X-API-Key schemes, or the service is "
                             "unreachable")

    status = "success" if findings else "partial"
    log.info("exposed_paths.complete", queries=metadata["queries_run"],
             ok=metadata["queries_ok"], findings=len(findings))
    return _result(status, findings, metadata, t0)


def _build_queries(scope: Scope) -> list[str]:
    """Domain substrings worth querying: each root domain plus the brand token."""
    queries: list[str] = []
    for domain in scope.all_domains:
        if len(domain) >= _MIN_QUERY_LEN:
            queries.append(domain)
        label = domain.split(".")[0]
        if len(label) >= _MIN_QUERY_LEN:
            queries.append(label)
    brand = "".join(ch for ch in scope.target.name.lower() if ch.isalnum())
    if len(brand) >= _MIN_QUERY_LEN:
        queries.append(brand)
    return list(dict.fromkeys(queries))


async def _search(
    client:  httpx.AsyncClient,
    query:   str,
    api_key: str,
    scheme:  str | None,
) -> tuple[Any | None, str | None]:
    """
    Try the documented-by-convention auth headers. Once one works, reuse it for
    the rest of the run rather than re-probing on every query.
    """
    schemes = [scheme] if scheme else ["bearer", "x-api-key"]
    for s in schemes:
        headers = dict(_UA)
        if s == "bearer":
            headers["Authorization"] = f"Bearer {api_key}"
        else:
            headers["X-API-Key"] = api_key
        try:
            r = await client.get(f"{_BASE}/api/search", params={"q": query},
                                 headers=headers)
        except Exception as exc:
            log.debug("exposed_paths.request_failed", query=query, error=str(exc))
            continue
        if r.status_code != 200:
            continue
        try:
            payload = r.json()
        except Exception:
            continue
        # The unauthenticated response is a 200 carrying an error body, so the
        # status code alone must not be treated as success.
        if isinstance(payload, dict) and payload.get("error"):
            log.debug("exposed_paths.rejected", scheme=s, error=payload["error"])
            continue
        return payload, s
    return None, scheme


def _iter_records(payload: Any):
    """Yield record dicts from whichever envelope shape the API returns."""
    if isinstance(payload, list):
        for x in payload:
            if isinstance(x, dict):
                yield x
    elif isinstance(payload, dict):
        for key in ("results", "data", "items", "hits", "domains"):
            val = payload.get(key)
            if isinstance(val, list):
                for x in val:
                    if isinstance(x, dict):
                        yield x
                return


def _result(status, findings, metadata, t0, error=None) -> dict:
    return {
        "module":   "layer2_5/exposed_paths",
        "status":   status,
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    error,
    }
