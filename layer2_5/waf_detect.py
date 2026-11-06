"""
layer2_5/waf_detect.py — Web Application Firewall detection.

Identifies WAF products in front of target web applications by:
  1. Running wafw00f CLI (comprehensive WAF fingerprinting database)
  2. Fallback: HTTP response analysis (headers, cookies, error page patterns)

WAF detection informs the engagement strategy:
  - No WAF → active scanning is lower risk of detection
  - Cloudflare → rotate IPs, use low-and-slow techniques
  - Akamai/Imperva → very aggressive fingerprinting; requires advanced bypass
  - AWS WAF → check for misconfigured rules (common in self-managed deployments)

Mode: semi (makes HTTP requests to target).
"""
from __future__ import annotations

import time
from typing import Any

import httpx
import structlog

from core.config import Config
from core.network import run_command
from core.ratelimiter import RateLimiter
from core.scope_guard import filter_in_scope
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "waf_detect",
    "title":    "WAF Detection",
    "description": "Web application firewall fingerprinting",
    "layer":    2.5,
    "mode":     ["semi", "active"],
    "requires": [],
    "optional": True,
}

_TIMEOUT = 15

# WAF fingerprints: {header/cookie/body pattern: waf_name}
_HEADER_FINGERPRINTS: dict[str, str] = {
    "cf-ray":                   "Cloudflare",
    "cf-cache-status":          "Cloudflare",
    "__cfduid":                 "Cloudflare",
    "__cfuid":                  "Cloudflare",
    "x-sucuri-id":              "Sucuri",
    "x-sucuri-cache":           "Sucuri",
    "server: sucuri":           "Sucuri",
    "x-fw-hash":                "Fastly",
    "x-served-by":              "Fastly",
    "x-cache: hit from cloudfront": "AWS CloudFront",
    "x-amz-cf-id":              "AWS CloudFront",
    "x-amz-request-id":        "AWS WAF",
    "x-cache-hits":             "Varnish",
    "x-akamai-transformed":     "Akamai",
    "x-check-cacheable":        "Akamai",
    "x-cdn":                    "Imperva",
    "x-iinfo":                  "Imperva",
    "x-cdn-geo":                "Imperva",
    "x-datadome-request-id":    "DataDome",
    "x-denied-reason":          "Barracuda",
    "barra_counter_session":    "Barracuda",
    "server: ats":              "TrafficShield/ATS",
    "server: f5":               "F5 BIG-IP",
    "x-wa-info":                "Alibaba Cloud WAF",
}

_BODY_FINGERPRINTS: dict[str, str] = {
    "access denied | cloudflare": "Cloudflare",
    "cloudflare ray id":           "Cloudflare",
    "sucuri webiste firewall":     "Sucuri",
    "incapsula incident id":       "Imperva/Incapsula",
    "fortigate":                   "Fortinet FortiGate",
    "barracuda":                   "Barracuda",
    "f5 big-ip":                   "F5 BIG-IP",
    "citrix netscaler":            "Citrix NetScaler",
    "request rejected":            "Generic WAF",
    "you've been blocked":         "Generic WAF",
}


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict       = {"hosts_checked": 0}

    hosts = await _get_hosts(scope, db)

    for host in hosts[:30]:
        metadata["hosts_checked"] += 1

        # Try wafw00f first
        waf_result = await _run_wafw00f(host, config)
        if waf_result:
            findings.append({
                "type":  "waf_detected",
                "value": host,
                "data":  {**waf_result, "source": "wafw00f"},
            })
            continue

        # Fallback: HTTP fingerprinting
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
            await limiter.acquire("default")
            http_result = await _http_fingerprint(client, host)
            if http_result:
                findings.append({
                    "type":  "waf_detected" if http_result.get("waf") else "no_waf",
                    "value": host,
                    "data":  {**http_result, "source": "http_fingerprint"},
                })
            else:
                findings.append({
                    "type":  "no_waf",
                    "value": host,
                    "data":  {"host": host, "waf": None, "note": "No WAF detected"},
                })

    return {
        "module":   "layer2_5/waf_detect",
        "status":   "success",
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


async def _run_wafw00f(host: str, config: Config) -> dict | None:
    result = await run_command(
        ["wafw00f", f"https://{host}", "-o", "-", "-f", "json"],
        recon_mode="semi",
        config=config,
        timeout=30,
    )
    if not result.ok or not result.stdout.strip():
        return None
    try:
        import json
        data = json.loads(result.stdout)
        if isinstance(data, list) and data:
            entry = data[0]
            return {
                "host":       host,
                "waf":        entry.get("firewall"),
                "manufacturer": entry.get("manufacturer"),
                "detected":   entry.get("detected", False),
            }
    except Exception:
        pass
    return None


async def _http_fingerprint(
    client: httpx.AsyncClient,
    host:   str,
) -> dict | None:
    for scheme in ("https", "http"):
        try:
            r = await client.get(f"{scheme}://{host}", timeout=10)
            headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
            detected_waf  = None

            # Header fingerprinting
            for pattern, waf in _HEADER_FINGERPRINTS.items():
                if ":" in pattern:
                    k, v = pattern.split(":", 1)
                    if headers_lower.get(k.strip(), "").startswith(v.strip()):
                        detected_waf = waf
                        break
                elif pattern in headers_lower:
                    detected_waf = waf
                    break

            # Body fingerprinting if no header match
            if not detected_waf:
                body_lower = r.text[:5000].lower()
                for pattern, waf in _BODY_FINGERPRINTS.items():
                    if pattern in body_lower:
                        detected_waf = waf
                        break

            return {
                "host":       host,
                "waf":        detected_waf,
                "status":     r.status_code,
                "server":     r.headers.get("server"),
                "detected":   detected_waf is not None,
            }
        except Exception:
            if scheme == "https":
                continue
            return None
    return None
