"""
layer2/subdomain/subdomain_takeover.py, subdomain takeover detection.

A subdomain takeover occurs when a CNAME points to a cloud service
(S3, GitHub Pages, Heroku, Fastly, etc.) that is no longer claimed.
An attacker can claim the service and serve content on the victim's subdomain.

Detection approach:
  1. Fetch all resolved hosts with CNAME records from DB (from dnsx module)
  2. Check each CNAME against known takeover fingerprints
  3. HTTP probe the subdomain for error pages matching unclaimed service patterns

No CLI tool required for passive detection. Optionally uses nuclei takeover
templates for comprehensive checking (semi/active mode).
"""
from __future__ import annotations

import re
import time
from typing import Any

import httpx
import structlog

from core.config import Config
from core.network import run_command
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "subdomain_takeover",
    "title":    "Subdomain Takeover",
    "description": "Dangling CNAME detection against unclaimed services",
    "layer":    2,
    "mode":     ["semi", "active"],
    "requires": [],
    "optional": True,
}

# Cloud service CNAME patterns and their unclaimed-state HTTP fingerprints
_TAKEOVER_SIGNATURES: list[dict] = [
    {"service": "AWS S3",         "cname": r"\.s3\.amazonaws\.com$",        "fingerprint": "NoSuchBucket"},
    {"service": "AWS S3 Website", "cname": r"\.s3-website[^.]*\.amazonaws\.com$", "fingerprint": "NoSuchBucket"},
    {"service": "GitHub Pages",   "cname": r"\.github\.io$",                "fingerprint": "There isn't a GitHub Pages site here"},
    {"service": "Heroku",         "cname": r"\.herokuapp\.com$",             "fingerprint": "No such app"},
    {"service": "Heroku",         "cname": r"\.herokudns\.com$",             "fingerprint": "No such app"},
    {"service": "Fastly",         "cname": r"\.fastly\.net$",                "fingerprint": "Fastly error: unknown domain"},
    {"service": "Pantheon",       "cname": r"\.pantheonsite\.io$",           "fingerprint": "404 error unknown site"},
    {"service": "Shopify",        "cname": r"\.myshopify\.com$",             "fingerprint": "Sorry, this shop is currently unavailable"},
    {"service": "Tumblr",         "cname": r"\.tumblr\.com$",                "fingerprint": "Whatever you were looking for doesn't currently exist"},
    {"service": "WordPress.com",  "cname": r"\.wordpress\.com$",             "fingerprint": "Do you want to register"},
    {"service": "Cargo",          "cname": r"\.cargocollective\.com$",       "fingerprint": "If you're moving your domain away from Cargo"},
    {"service": "Zendesk",        "cname": r"\.zendesk\.com$",               "fingerprint": "Help Center Closed"},
    {"service": "Azure",          "cname": r"\.azurewebsites\.net$",         "fingerprint": "404 Web Site not found"},
    {"service": "Azure",          "cname": r"\.azurewebsites\.net$",         "fingerprint": "Error 404 - Web app not found"},
    {"service": "Azure Traffic",  "cname": r"\.trafficmanager\.net$",        "fingerprint": ""},
    {"service": "Surge.sh",       "cname": r"\.surge\.sh$",                  "fingerprint": "project not found"},
    {"service": "Fly.io",         "cname": r"\.fly\.dev$",                   "fingerprint": "404"},
    {"service": "Render",         "cname": r"\.onrender\.com$",              "fingerprint": "not found"},
    {"service": "Netlify",        "cname": r"\.netlify\.app$",               "fingerprint": "Not Found"},
    {"service": "Vercel",         "cname": r"\.vercel\.app$",                "fingerprint": "The deployment could not be found"},
    # Mailgun-pattern: the CNAME target (mailgun.org) resolves fine, so
    # tools that only check "does the CNAME target resolve" report a false
    # negative. The body fingerprint on the original host's Host header is
    # the only reliable signal, see baseline Rule 1.
    {"service": "Mailgun",        "cname": r"\.mailgun\.org$",               "fingerprint": "404 page not found"},
    {"service": "SendGrid",       "cname": r"\.sendgrid\.net$",              "fingerprint": "The page you are looking for is not here"},
]


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0        = time.monotonic()
    findings: list[dict] = []
    metadata: dict       = {"hosts_checked": 0, "potential_takeovers": 0}

    # Get resolved hosts with CNAME records from DB
    cname_hosts = await _get_cname_hosts(scope, db)
    metadata["cname_hosts"] = len(cname_hosts)

    if not cname_hosts:
        # Fall back to scope domains
        cname_hosts = {d: [] for d in scope.all_domains}

    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        for host, cnames in cname_hosts.items():
            metadata["hosts_checked"] += 1
            result = await _check_takeover(client, host, cnames)
            if result:
                metadata["potential_takeovers"] += 1
                findings.append({
                    "type":  "subdomain_takeover",
                    "value": host,
                    "data":  result,
                })
                log.warning(
                    "takeover.potential_found",
                    host=host,
                    service=result["service"],
                )

    # Nuclei takeover templates for semi/active mode
    if scope.mode in ("semi", "active") and cname_hosts:
        nuclei_findings = await _run_nuclei_takeover(
            list(cname_hosts.keys()), config
        )
        findings.extend(nuclei_findings)

    return {
        "module":   "layer2/subdomain/subdomain_takeover",
        "status":   "success",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _get_cname_hosts(scope: Scope, db: Any) -> dict[str, list[str]]:
    """Return {host: [cname, ...]} for resolved hosts from DB."""
    if db is None:
        return {}
    try:
        run_id = await db.get_last_run_id(scope.target.name) or ""
        if not run_id:
            return {}
        rows = await db.get_findings(run_id, "resolved_host")
        result = {}
        for row in rows:
            data  = row.get("data") or {}
            cname = data.get("cname", [])
            if cname:
                result[row["value"]] = cname
        return result
    except Exception as exc:
        log.debug("takeover.db_failed", error=str(exc))
        return {}


async def _check_takeover(
    client: httpx.AsyncClient,
    host:   str,
    cnames: list[str],
) -> dict | None:
    """Check if a host+cname combination matches a takeover signature."""
    # Check CNAME against known patterns
    for sig in _TAKEOVER_SIGNATURES:
        pattern = re.compile(sig["cname"])
        matched_cname = None
        for cname in cnames:
            if pattern.search(cname):
                matched_cname = cname
                break

        if not matched_cname and not any(pattern.search(c) for c in cnames):
            continue

        # CNAME matches, probe the subdomain HTTP response
        if not sig["fingerprint"]:
            # No HTTP fingerprint, flag based on CNAME alone
            return {
                "service":   sig["service"],
                "cname":     matched_cname,
                "method":    "cname_pattern",
                "confirmed": False,
            }

        try:
            for scheme in ("https", "http"):
                r = await client.get(f"{scheme}://{host}", timeout=8)
                if sig["fingerprint"].lower() in r.text.lower():
                    return {
                        "service":      sig["service"],
                        "cname":        matched_cname,
                        "fingerprint":  sig["fingerprint"],
                        "status_code":  r.status_code,
                        "method":       "http_fingerprint",
                        "confirmed":    True,
                    }
        except Exception:
            pass

    return None


async def _run_nuclei_takeover(hosts: list[str], config: Config) -> list[dict]:
    """Run nuclei subdomain takeover templates against discovered hosts."""
    import tempfile
    from pathlib import Path

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(f"https://{h}" for h in hosts[:200]))
        targets_file = Path(f.name)

    try:
        result = await run_command(
            [
                "nuclei", "-l", str(targets_file),
                "-t", "http/takeovers/",
                "-silent", "-jsonl", "-no-color",
            ],
            recon_mode="semi",
            config=config,
            timeout=300,
        )
    finally:
        targets_file.unlink(missing_ok=True)

    if not result.ok or not result.stdout.strip():
        return []

    findings = []
    import json
    for line in result.stdout.splitlines():
        try:
            hit = json.loads(line)
            findings.append({
                "type":  "subdomain_takeover",
                "value": hit.get("host", ""),
                "data": {
                    "template":   hit.get("template-id"),
                    "name":       hit.get("info", {}).get("name"),
                    "severity":   hit.get("info", {}).get("severity"),
                    "matched_at": hit.get("matched-at"),
                    "source":     "nuclei",
                },
            })
        except Exception:
            pass

    return findings
