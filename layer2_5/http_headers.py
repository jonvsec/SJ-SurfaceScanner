"""
layer2_5/http_headers.py, HTTP security header analysis.

Fetches HTTP headers from all resolved hosts and evaluates security posture.
Missing or misconfigured headers are frequent low-hanging-fruit findings that
indicate the maturity level of the target's security programme.

Checks:
  Strict-Transport-Security (HSTS) , missing = MITM downgrade possible
  Content-Security-Policy (CSP), missing = XSS unrestricted
  X-Frame-Options, missing = clickjacking possible
  X-Content-Type-Options, missing = MIME sniffing attacks
  Referrer-Policy, info leakage
  Permissions-Policy, browser feature control
  Server / X-Powered-By, version disclosure
  Access-Control-Allow-Origin, CORS (also checked by cors_brute)
  Set-Cookie attributes, Secure, HttpOnly, SameSite flags

Mode: semi (makes HTTP requests to target).
"""
from __future__ import annotations

import asyncio
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
    "name":     "http_headers",
    "title":    "HTTP Security Headers",
    "description": "CSP, HSTS and information-disclosure headers",
    "layer":    2.5,
    "mode":     ["semi", "active"],
    "requires": [],
    "optional": False,
}

_TIMEOUT = 15

# A missing security header is a defense-in-depth hardening gap, not a
# demonstrated exploit, so it is rated Low across the board. Any real impact
# (an actual clickjacking or XSS proof) is raised as its own finding by the
# relevant module, scored on what was confirmed.
_SECURITY_HEADERS = {
    "strict-transport-security": {
        "severity": "low",
        "issue":    "Missing HSTS, HTTP downgrade and MITM attacks are possible",
    },
    "content-security-policy": {
        "severity": "low",
        "issue":    "Missing CSP, there is no defense-in-depth limit on XSS impact",
    },
    "x-frame-options": {
        "severity": "low",
        "issue":    "Missing X-Frame-Options, clickjacking is possible",
    },
    "x-content-type-options": {
        "severity": "low",
        "issue":    "Missing X-Content-Type-Options, MIME sniffing is possible",
    },
    "referrer-policy": {
        "severity": "low",
        "issue":    "Missing Referrer-Policy, URL parameters may leak to third parties",
    },
    "permissions-policy": {
        "severity": "low",
        "issue":    "Missing Permissions-Policy, browser features are not restricted",
    },
}


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
        batch_size = 5
        for i in range(0, len(hosts), batch_size):
            batch = hosts[i:i + batch_size]
            tasks = [_check_host(client, host, limiter) for host in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, list):
                    findings.extend(result)
                    metadata["hosts_checked"] += 1

    return {
        "module":   "layer2_5/http_headers",
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
    return sorted(filter_in_scope(hosts, scope, module=__name__))[:50]


async def _check_host(
    client:  httpx.AsyncClient,
    host:    str,
    limiter: RateLimiter,
) -> list[dict]:
    await limiter.acquire("default")
    findings = []

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            r = await client.get(url, timeout=10)
            headers = {k.lower(): v for k, v in r.headers.items()}

            # Security header checks
            for header_name, info in _SECURITY_HEADERS.items():
                if header_name not in headers:
                    findings.append({
                        "type":  "missing_security_header",
                        "value": host,
                        "data": {
                            "host":    host,
                            "url":     url,
                            "header":  header_name,
                            "issue":   info["issue"],
                            "severity": info["severity"],
                        },
                    })

            # HSTS quality check
            hsts = headers.get("strict-transport-security")
            if hsts:
                findings.extend(_analyse_hsts(host, url, hsts))

            # CSP quality check
            csp = headers.get("content-security-policy")
            if csp:
                findings.extend(_analyse_csp(host, url, csp))

            # Server / tech disclosure
            for disclosure_header in ("server", "x-powered-by", "x-generator", "x-aspnet-version"):
                val = headers.get(disclosure_header)
                if val:
                    findings.append({
                        "type":  "version_disclosure",
                        "value": host,
                        "data": {
                            "host":    host,
                            "header":  disclosure_header,
                            "value":   val,
                            "severity": "low",
                        },
                    })

            # Cookie security flags
            set_cookies = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else []
            for cookie in set_cookies:
                cookie_issues = _analyse_cookie(cookie)
                for issue in cookie_issues:
                    findings.append({
                        "type":  "cookie_security",
                        "value": host,
                        "data":  {**issue, "host": host, "url": url},
                    })

            break  # checked HTTPS, don't need HTTP too
        except Exception:
            if scheme == "https":
                continue  # try http fallback
            break

    return findings


def _analyse_hsts(host, url, hsts_value) -> list[dict]:
    issues = []
    lower  = hsts_value.lower()

    max_age_match = __import__("re").search(r"max-age=(\d+)", lower)
    max_age = int(max_age_match.group(1)) if max_age_match else 0

    if max_age < 31536000:
        issues.append({
            "type":  "weak_hsts",
            "value": host,
            "data": {
                "host":    host, "url": url,
                "max_age": max_age,
                "issue":   f"HSTS max-age={max_age} is below recommended 31536000 (1 year)",
                "severity": "medium",
            },
        })
    if "includesubdomains" not in lower:
        issues.append({
            "type":  "weak_hsts",
            "value": host,
            "data": {
                "host": host, "url": url,
                "issue": "HSTS missing includeSubDomains, subdomains not protected",
                "severity": "low",
            },
        })
    return issues


def _analyse_csp(host, url, csp_value) -> list[dict]:
    issues = []
    lower  = csp_value.lower()

    if "unsafe-inline" in lower:
        issues.append({
            "type":  "weak_csp",
            "value": host,
            "data": {
                "host":     host, "url": url,
                "issue":    "CSP allows 'unsafe-inline', XSS mitigation ineffective",
                "severity": "medium",
            },
        })
    if "unsafe-eval" in lower:
        issues.append({
            "type":  "weak_csp",
            "value": host,
            "data": {
                "host":     host, "url": url,
                "issue":    "CSP allows 'unsafe-eval', code injection possible",
                "severity": "medium",
            },
        })
    if "*" in csp_value and "script-src" in lower:
        issues.append({
            "type":  "weak_csp",
            "value": host,
            "data": {
                "host":     host, "url": url,
                "issue":    "CSP script-src uses wildcard, effectively no restriction",
                "severity": "high",
            },
        })
    return issues


def _analyse_cookie(cookie_header: str) -> list[dict]:
    issues = []
    lower  = cookie_header.lower()
    name   = cookie_header.split("=")[0].strip()

    if "secure" not in lower:
        issues.append({
            "cookie":   name, "issue": "Cookie missing Secure flag, sent over HTTP",
            "severity": "medium",
        })
    if "httponly" not in lower:
        issues.append({
            "cookie":   name, "issue": "Cookie missing HttpOnly, accessible via JavaScript",
            "severity": "medium",
        })
    if "samesite" not in lower:
        issues.append({
            "cookie":   name, "issue": "Cookie missing SameSite, CSRF risk",
            "severity": "low",
        })
    return issues
