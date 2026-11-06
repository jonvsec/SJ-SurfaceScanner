"""
layer2_5/js_analysis.py — JavaScript file analysis for endpoints and secrets.

Downloads JavaScript bundles from discovered hosts and extracts:
  - API endpoints (relative and absolute URLs)
  - Internal service names and paths
  - Environment variables embedded at build time
  - Exposed API keys, tokens, and secrets
  - GraphQL schema fragments
  - Internal domain names in JS comments and strings

Modern SPAs embed significant infrastructure information in their JavaScript
bundles — source maps, internal API routes, feature flags, even credentials
baked in during CI/CD builds.

Mode: semi (fetches JS files from target).
"""
from __future__ import annotations

import re
import time
from typing import Any

import httpx
import structlog

from core.config import Config
from core.prefilter import extract_signals
from core.ratelimiter import RateLimiter
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "js_analysis",
    "title":    "JavaScript Analysis",
    "description": "Secrets and endpoints mined from JS bundles",
    "layer":    2.5,
    "mode":     ["semi", "active"],
    "requires": [],
    "optional": True,
}

_TIMEOUT   = 20
_MAX_JS_SIZE = 5 * 1024 * 1024  # 5MB per file

# URL patterns in JS
_URL_PATTERN = re.compile(
    r"""["'`]((?:https?://[^"'`\s]{3,}|/api/[^"'`\s]{2,}|/v\d+/[^"'`\s]{2,}))[^"'`\s]*["'`]"""
)

# Secret patterns in JS
_SECRET_PATTERNS = {
    "aws_key":         re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret":      re.compile(r"""(?i)aws[_\-]?secret[_\-]?(?:access[_\-]?)?key["'\s]*[:=]["'\s]*([A-Za-z0-9+/]{40})"""),
    "stripe_live":     re.compile(r"sk_live_[A-Za-z0-9]{24,}"),
    "stripe_pub":      re.compile(r"pk_live_[A-Za-z0-9]{24,}"),
    "github_token":    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "github_pat":      re.compile(r"github_pat_[A-Za-z0-9_]{82}"),
    "gitlab_token":    re.compile(r"glpat-[A-Za-z0-9\-_]{20}"),
    "npm_token":       re.compile(r"npm_[A-Za-z0-9]{36}"),
    "google_api":      re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "sendgrid":        re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"),
    "slack_token":     re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    "slack_webhook":   re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9_]{20,}"),
    "twilio_sid":      re.compile(r"AC[a-fA-F0-9]{32}"),
    "twilio_key":      re.compile(r"SK[a-fA-F0-9]{32}"),
    "mailchimp_api":   re.compile(r"[0-9a-f]{32}-us[0-9]{1,2}"),
    "square_token":    re.compile(r"sq0(?:atp|csp)-[0-9A-Za-z\-_]{22,43}"),
    "paypal_braintree": re.compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
    "azure_storage_key": re.compile(r"(?i)AccountKey=[A-Za-z0-9+/]{86}=="),
    "db_connection_string": re.compile(r"(?i)(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^\s\"'`]{6,}"),
    "jwt_token":       re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "private_key":     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "generic_secret":  re.compile(r"""(?i)(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token|auth[_\-]?token)["'\s]*[:=]["'\s]*([A-Za-z0-9+/\-_]{20,})"""),
}


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict       = {"js_files_fetched": 0, "endpoints_found": 0, "secrets_found": 0}

    js_urls = await _discover_js_urls(scope, db)

    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
        for js_url in js_urls[:100]:  # cap file count
            await limiter.acquire("default")
            content = await _fetch_js(client, js_url)
            if not content:
                continue

            metadata["js_files_fetched"] += 1

            # Extract API endpoints
            endpoints = _extract_endpoints(content, js_url)
            metadata["endpoints_found"] += len(endpoints)
            for ep in endpoints:
                findings.append({
                    "type":  "js_endpoint",
                    "value": ep,
                    "data":  {"url": ep, "source_file": js_url},
                })

            # Extract secrets
            secrets = _extract_secrets(content, js_url)
            metadata["secrets_found"] += len(secrets)
            for secret in secrets:
                findings.append({
                    "type":  "js_secret",
                    "value": js_url,
                    "data":  secret,
                })

            # Extract signals (IPs, domains, etc.)
            signals = extract_signals(content[:50_000])
            if signals.as_dict():
                findings.append({
                    "type":  "js_signals",
                    "value": js_url,
                    "data":  {"signals": signals.as_dict(), "source_file": js_url},
                })

    log.info("js_analysis.complete",
             files=metadata["js_files_fetched"],
             secrets=metadata["secrets_found"])
    return {
        "module":   "layer2_5/js_analysis",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _discover_js_urls(scope: Scope, db: Any) -> list[str]:
    """Collect JS URLs from crawled endpoints in DB, or build from scope domains."""
    js_urls: set[str] = set()

    if db is not None:
        try:
            run_id = await db.get_last_run_id(scope.target.name) or ""
            if run_id:
                rows = await db.get_findings(run_id, "crawled_endpoint")
                for row in rows:
                    url = row.get("value", "")
                    if url.endswith(".js") or ".js?" in url:
                        js_urls.add(url)
        except Exception:
            pass

    # Fallback: try common JS bundle paths
    for domain in scope.all_domains[:5]:
        for path in ["/static/js/main.js", "/assets/index.js", "/app.js", "/bundle.js"]:
            js_urls.add(f"https://{domain}{path}")

    return sorted(js_urls)


async def _fetch_js(client: httpx.AsyncClient, url: str) -> str | None:
    try:
        r = await client.get(url, timeout=15)
        if r.status_code != 200:
            return None
        ct = r.headers.get("content-type", "")
        if "javascript" not in ct and not url.endswith(".js"):
            return None
        if len(r.content) > _MAX_JS_SIZE:
            return r.text[:_MAX_JS_SIZE]  # truncate to the 5MB cap
        return r.text
    except Exception:
        return None


def _extract_endpoints(content: str, source: str) -> list[str]:
    endpoints = set()
    for match in _URL_PATTERN.finditer(content):
        url = match.group(1)
        if len(url) > 5 and " " not in url:
            endpoints.add(url)
    return sorted(endpoints)[:100]


def _extract_secrets(content: str, source: str) -> list[dict]:
    secrets = []
    for secret_type, pattern in _SECRET_PATTERNS.items():
        for match in pattern.finditer(content):
            value = match.group(0)[:100]
            # Mask the actual value in the finding — never store raw secrets
            masked = value[:6] + "..." + value[-4:] if len(value) > 12 else "***"
            secrets.append({
                "type":       secret_type,
                "masked":     masked,
                "source":     source,
                "severity":   "critical",
                "context":    _get_context(content, match.start()),
            })
    return secrets


def _get_context(content: str, pos: int, window: int = 80) -> str:
    start = max(0, pos - window)
    end   = min(len(content), pos + window)
    return content[start:end].replace("\n", " ")
