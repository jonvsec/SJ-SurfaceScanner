"""
layer2_5/cms_detect.py — CMS and framework detection.

Fingerprints web applications to identify:
  WordPress, Drupal, Joomla, Ghost, Strapi → known CVE/plugin attack surface
  React, Angular, Vue, Next.js, Nuxt      → SPA → check for exposed API
  Django, Rails, Laravel, Spring          → known framework misconfigs
  Admin panels: phpMyAdmin, pgAdmin, Kibana, Grafana, Jenkins, Jira, Confluence

CMS detection informs which Nuclei templates to prioritise and which
plugin/theme CVEs are relevant for the kill chain in Layer 4.

Mode: semi (makes HTTP requests to target).
"""
from __future__ import annotations

import re
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
    "name":     "cms_detect",
    "title":    "CMS Detection",
    "description": "CMS/framework identification and plugin CVEs",
    "layer":    2.5,
    "mode":     ["semi", "active"],
    "requires": [],
    "optional": True,
}

_TIMEOUT = 15

_CMS_SIGNATURES: list[dict] = [
    # WordPress
    {"name": "WordPress",    "header": None, "path": "/wp-login.php",            "body": "wp-login"},
    {"name": "WordPress",    "header": None, "path": "/wp-json/",                 "body": "WordPress"},
    {"name": "WordPress",    "header": None, "path": "/xmlrpc.php",               "body": "xmlrpc"},
    # Drupal
    {"name": "Drupal",       "header": "x-drupal-cache", "path": None,           "body": None},
    {"name": "Drupal",       "header": None, "path": "/?q=user/login",            "body": "Drupal"},
    # Joomla
    {"name": "Joomla",       "header": None, "path": "/administrator/",           "body": "Joomla"},
    # Ghost
    {"name": "Ghost",        "header": None, "path": "/ghost/",                   "body": "Ghost"},
    # Strapi
    {"name": "Strapi",       "header": None, "path": "/admin/",                   "body": "Strapi"},
    # Admin panels
    {"name": "phpMyAdmin",   "header": None, "path": "/phpmyadmin/",              "body": "phpMyAdmin"},
    {"name": "phpMyAdmin",   "header": None, "path": "/pma/",                     "body": "phpMyAdmin"},
    {"name": "pgAdmin",      "header": None, "path": "/pgadmin/",                 "body": "pgAdmin"},
    {"name": "Kibana",       "header": None, "path": ":5601/",                    "body": "Kibana"},
    {"name": "Grafana",      "header": None, "path": "/grafana/",                 "body": "Grafana"},
    {"name": "Grafana",      "header": "x-grafana-config", "path": None,         "body": None},
    {"name": "Jenkins",      "header": "x-jenkins", "path": None,                 "body": None},
    {"name": "Jenkins",      "header": None, "path": "/jenkins/",                 "body": "Jenkins"},
    {"name": "Jira",         "header": None, "path": "/jira/",                    "body": "JIRA"},
    {"name": "Confluence",   "header": None, "path": "/confluence/",              "body": "Confluence"},
    {"name": "GitLab",       "header": "x-gitlab-meta", "path": None,            "body": None},
    {"name": "Prometheus",   "header": None, "path": ":9090/metrics",            "body": "Prometheus"},
    # Frameworks
    {"name": "Django",       "header": None, "path": "/",                         "body": "csrfmiddlewaretoken"},
    {"name": "Laravel",      "header": None, "path": "/",                         "body": "laravel_session"},
    {"name": "Spring Boot",  "header": None, "path": "/actuator/health",          "body": "status"},
    {"name": "Next.js",      "header": "x-nextjs-cache", "path": None,           "body": None},
    {"name": "Next.js",      "header": None, "path": "/_next/static/",            "body": None},
]

# /wp-content/plugins/<slug>/readme.txt is publicly accessible on unprotected
# WordPress installs and discloses the installed version via "Stable tag:"
# (baseline Rule 10). Probe the most commonly installed plugins.
_WP_PLUGINS_TO_PROBE = [
    "elementor", "wordfence", "wordpress-seo", "contact-form-7",
    "woocommerce", "jetpack", "akismet", "wp-super-cache",
    "all-in-one-seo-pack", "duplicator", "wpforms-lite",
    "classic-editor", "really-simple-ssl", "advanced-custom-fields",
    "w3-total-cache", "updraftplus", "wp-file-manager", "ninja-forms",
    "mailpoet", "revslider",
]

_README_VERSION_RE = re.compile(r"Stable tag:\s*([0-9][0-9a-zA-Z.\-]*)", re.IGNORECASE)

# Small curated set of well-known, high-impact plugin CVEs keyed by plugin
# slug. "max_version" means vulnerable up to and including that version.
# This is a static reference list, not a WPScan/NVD lookup — every match is
# flagged requires_manual_verification until confirmed against those sources.
_WP_PLUGIN_CVE_DB: dict[str, list[dict]] = {
    "wp-file-manager": [
        {"max_version": "6.0", "cve": "CVE-2020-25213", "severity": "critical",
         "description": "Unauthenticated arbitrary file upload via elFinder connector — leads to RCE"},
    ],
    "duplicator": [
        {"max_version": "1.3.26", "cve": "CVE-2020-11738", "severity": "high",
         "description": "Unauthenticated arbitrary file read/download via leftover installer.php"},
    ],
    "contact-form-7": [
        {"max_version": "5.3.1", "cve": "CVE-2020-35489", "severity": "high",
         "description": "Unrestricted file upload due to insufficient filename sanitization"},
    ],
}


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict       = {"hosts_checked": 0, "cms_detected": 0}

    hosts = await _get_hosts(scope, db)

    async with httpx.AsyncClient(
        timeout=_TIMEOUT, follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (compatible; SurfaceScanner/1.0)"},
    ) as client:
        for host in hosts[:30]:
            metadata["hosts_checked"] += 1
            detected = await _detect_cms(client, host, limiter)
            for cms_finding in detected:
                findings.append(cms_finding)
                if cms_finding["data"].get("confirmed"):
                    metadata["cms_detected"] += 1

            if any(d["data"].get("cms") == "WordPress" for d in detected):
                plugin_findings = await _probe_wp_plugins(client, host, limiter)
                findings.extend(plugin_findings)
                metadata["wp_plugins_found"] = metadata.get("wp_plugins_found", 0) + sum(
                    1 for f in plugin_findings if f["type"] == "wp_plugin"
                )

    return {
        "module":   "layer2_5/cms_detect",
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


async def _detect_cms(
    client:  httpx.AsyncClient,
    host:    str,
    limiter: RateLimiter,
) -> list[dict]:
    detected: dict[str, dict] = {}

    # Check base response headers first
    await limiter.acquire("default")
    try:
        r = await client.get(f"https://{host}", timeout=10)
        headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}

        for sig in _CMS_SIGNATURES:
            name = sig["name"]
            confirmed = False

            if sig["header"] and sig["header"].lower() in headers_lower:
                confirmed = True
            elif sig["body"] and sig["body"] and sig["body"].lower() in r.text.lower():
                confirmed = True

            if confirmed and name not in detected:
                detected[name] = {
                    "host":      host,
                    "cms":       name,
                    "confirmed": True,
                    "method":    "header" if sig["header"] else "body",
                    "severity":  "info",
                }
    except Exception:
        pass

    # Path-based checks for remaining signatures
    unchecked = [s for s in _CMS_SIGNATURES if s["path"] and s["name"] not in detected]
    for sig in unchecked[:10]:  # cap path checks per host
        await limiter.acquire("default")
        path = sig["path"]
        if path.startswith(":"):
            # Port-based path — skip for now
            continue
        url = f"https://{host}{path}"
        try:
            r = await client.get(url, timeout=8)
            name = sig["name"]
            if r.status_code in (200, 302, 401, 403):
                body_match = not sig["body"] or sig["body"].lower() in r.text.lower()
                if body_match and name not in detected:
                    detected[name] = {
                        "host":      host,
                        "cms":       name,
                        "url":       url,
                        "confirmed": r.status_code == 200 and body_match,
                        "status":    r.status_code,
                        "method":    "path",
                        "severity":  "medium" if r.status_code == 200 else "info",
                    }
        except Exception:
            pass

    return [
        {
            "type":  "cms_detected",
            "value": host,
            "data":  data,
        }
        for data in detected.values()
    ]


async def _probe_wp_plugins(
    client:  httpx.AsyncClient,
    host:    str,
    limiter: RateLimiter,
) -> list[dict]:
    """Probe common plugin readme.txt files for version disclosure (baseline Rule 10)."""
    findings = []
    for slug in _WP_PLUGINS_TO_PROBE:
        await limiter.acquire("default")
        url = f"https://{host}/wp-content/plugins/{slug}/readme.txt"
        try:
            r = await client.get(url, timeout=8)
            if r.status_code != 200:
                continue
            match = _README_VERSION_RE.search(r.text)
            if not match:
                continue
            version = match.group(1)

            findings.append({
                "type":  "wp_plugin",
                "value": f"{slug} {version}",
                "data": {
                    "host":       host,
                    "cms":        "WordPress",
                    "plugin":     slug,
                    "version":    version,
                    "readme_url": url,
                    "severity":   "info",
                },
            })

            for entry in _WP_PLUGIN_CVE_DB.get(slug, []):
                if _version_lte(version, entry["max_version"]):
                    findings.append({
                        "type":  "wp_plugin_cve",
                        "value": entry["cve"],
                        "data": {
                            "host":        host,
                            "plugin":      slug,
                            "version":     version,
                            "cve_id":      [entry["cve"]],
                            "severity":    entry["severity"],
                            "description": entry["description"],
                            "requires_manual_verification": True,
                            "verification_note": (
                                f"Version {version} is <= known-vulnerable "
                                f"{entry['max_version']} for {entry['cve']}. "
                                "Confirm against WPScan/NVD before reporting."
                            ),
                        },
                    })
        except Exception:
            pass
    return findings


def _version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", v))


def _version_lte(a: str, b: str) -> bool:
    return _version_tuple(a) <= _version_tuple(b)
