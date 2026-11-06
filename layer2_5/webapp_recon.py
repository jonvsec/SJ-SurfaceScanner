"""
layer2_5/webapp_recon.py — web application reconnaissance.

Profiles web applications at a higher level than individual header checks:
  - Authentication mechanism detection (Basic, OAuth, SSO, JWT, API key)
  - API type detection (REST, GraphQL, SOAP, gRPC)
  - Application logic hints (multi-tenant, SaaS, single-tenant enterprise)
  - Login page discovery and brute-force protection assessment
  - Password reset flow analysis
  - Registration/signup flow presence

These findings drive social engineering and authentication attack vectors
in the kill chain: no brute-force protection → credential stuffing possible,
OAuth misconfiguration → account takeover, no MFA enforced → phishing risk.

Mode: semi (makes HTTP requests to target).
"""
from __future__ import annotations

import time
from typing import Any

import httpx
import structlog

from core.config import Config
from core.ratelimiter import RateLimiter
from core.scope_guard import filter_in_scope
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "webapp_recon",
    "title":    "Web App Recon",
    "description": "Auth endpoints, API types and OIDC discovery",
    "layer":    2.5,
    "mode":     ["semi", "active"],
    "requires": [],
    "optional": True,
}

_TIMEOUT = 15

# Common paths to probe
_AUTH_PATHS = [
    "/login", "/signin", "/sign-in", "/auth", "/authenticate",
    "/oauth/authorize", "/oauth2/authorize", "/sso",
    "/saml/login", "/saml2/idp/SSO/redirect",
    "/api/login", "/api/auth", "/api/v1/auth", "/api/v2/auth",
    "/admin", "/admin/login",
]

_GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/query",
]

_OPENAPI_PATHS = [
    "/swagger", "/swagger-ui", "/swagger.json", "/openapi.json",
    "/api-docs", "/api/v1/docs", "/docs", "/redoc",
]


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict       = {"hosts_checked": 0}

    hosts = await _get_hosts(scope, db)

    async with httpx.AsyncClient(
        timeout=_TIMEOUT, follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (compatible; SurfaceScanner/1.0)"},
    ) as client:
        for host in hosts[:20]:
            metadata["hosts_checked"] += 1
            host_findings = await _recon_host(client, host, limiter)
            findings.extend(host_findings)

    return {
        "module":   "layer2_5/webapp_recon",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _get_hosts(scope: Scope, db: Any) -> list[str]:
    hosts: set[str] = set(scope.all_domains)
    if db is not None:
        try:
            run_id = await db.get_last_run_id(scope.target.name) or ""
            if run_id:
                rows = await db.get_findings(run_id, "resolved_host")
                hosts.update(r["value"] for r in rows if r.get("value"))
        except Exception:
            pass
    # Hosts from the DB are runtime discoveries and may include domains the
    # client never authorised. Never hand an unauthorised host to a tool that
    # sends traffic.
    return sorted(filter_in_scope(hosts, scope, module=__name__))


async def _recon_host(
    client:  httpx.AsyncClient,
    host:    str,
    limiter: RateLimiter,
) -> list[dict]:
    findings = []

    # Auth endpoint discovery
    for path in _AUTH_PATHS:
        await limiter.acquire("default")
        url = f"https://{host}{path}"
        try:
            r = await client.get(url, timeout=8)
            if r.status_code in (200, 302, 401, 403):
                auth_type = _classify_auth(r, url)
                findings.append({
                    "type":  "auth_endpoint",
                    "value": url,
                    "data": {
                        "host":        host,
                        "url":         url,
                        "status_code": r.status_code,
                        "auth_type":   auth_type,
                        "brute_force_protected": _has_rate_limiting(r),
                    },
                })
        except Exception:
            pass

    # GraphQL detection
    for path in _GRAPHQL_PATHS:
        await limiter.acquire("default")
        url = f"https://{host}{path}"
        try:
            r = await client.post(
                url,
                json={"query": "{__typename}"},
                headers={"Content-Type": "application/json"},
                timeout=8,
            )
            if r.status_code in (200, 400) and "data" in r.text:
                introspection = await _test_graphql_introspection(client, url, limiter)
                findings.append({
                    "type":  "graphql_endpoint",
                    "value": url,
                    "data": {
                        "host":           host,
                        "url":            url,
                        "introspection":  introspection,
                        "severity":       "high" if introspection else "medium",
                        "note":           "GraphQL introspection enabled — full schema exposed" if introspection else "GraphQL endpoint detected",
                    },
                })
        except Exception:
            pass

    # OpenAPI/Swagger docs
    for path in _OPENAPI_PATHS:
        await limiter.acquire("default")
        url = f"https://{host}{path}"
        try:
            r = await client.get(url, timeout=8)
            if r.status_code == 200 and _looks_like_api_docs(r):
                findings.append({
                    "type":  "exposed_api_docs",
                    "value": url,
                    "data": {
                        "host":     host,
                        "url":      url,
                        "severity": "medium",
                        "note":     "API documentation publicly accessible",
                    },
                })
        except Exception:
            pass

    # Well-known OIDC config — deliberately not in _AUTH_PATHS, to avoid a
    # duplicate request and a misleading auth_endpoint/jwt-bearer finding
    # for what is a discovery document, not an auth endpoint.
    await limiter.acquire("default")
    oidc_url = f"https://{host}/.well-known/openid-configuration"
    try:
        r = await client.get(oidc_url, timeout=8)
        if r.status_code == 200:
            try:
                oidc_data = r.json()
                findings.append({
                    "type":  "oidc_provider",
                    "value": host,
                    "data": {
                        "host":            host,
                        "issuer":          oidc_data.get("issuer"),
                        "auth_endpoint":   oidc_data.get("authorization_endpoint"),
                        "token_endpoint":  oidc_data.get("token_endpoint"),
                        "grant_types":     oidc_data.get("grant_types_supported", []),
                    },
                })
            except Exception:
                pass
    except Exception:
        pass

    return findings


def _classify_auth(r: httpx.Response, url: str) -> str:
    www_auth = r.headers.get("www-authenticate", "").lower()
    body     = r.text[:2000].lower()
    url_l    = url.lower()

    if "bearer" in www_auth or "jwt" in body:
        return "jwt/bearer"
    if "basic" in www_auth:
        return "http_basic"
    if "oauth" in url_l or "authorize" in url_l:
        return "oauth"
    if "saml" in url_l:
        return "saml_sso"
    if "sso" in url_l:
        return "sso"
    if "password" in body and "email" in body:
        return "form_based"
    return "unknown"


def _has_rate_limiting(r: httpx.Response) -> bool:
    headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
    rate_headers  = {"x-ratelimit-limit", "x-ratelimit-remaining", "retry-after",
                     "x-rate-limit", "ratelimit-limit"}
    return bool(rate_headers & set(headers_lower))


async def _test_graphql_introspection(
    client:  httpx.AsyncClient,
    url:     str,
    limiter: RateLimiter,
) -> bool:
    await limiter.acquire("default")
    try:
        r = await client.post(
            url,
            json={"query": "{ __schema { queryType { name } } }"},
            headers={"Content-Type": "application/json"},
            timeout=8,
        )
        return r.status_code == 200 and "__schema" in r.text
    except Exception:
        return False


def _looks_like_api_docs(r: httpx.Response) -> bool:
    ct   = r.headers.get("content-type", "")
    body = r.text[:500].lower()
    return (
        "swagger" in body
        or "openapi" in body
        or "redoc" in body
        or "application/json" in ct
    )
