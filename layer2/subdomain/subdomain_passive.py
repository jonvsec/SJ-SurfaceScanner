"""
layer2/subdomain/subdomain_passive.py, passive subdomain enumeration via Subfinder.

Subfinder (ProjectDiscovery) aggregates 40+ passive sources: VirusTotal,
Shodan, Censys, SecurityTrails, crt.sh, BinaryEdge, DNSDumpster, and more.
A single command returns a comprehensive subdomain list without touching
the target directly.

CLI tool required: subfinder (installed system-wide).
API keys (optional): set via subfinder's ~/.config/subfinder/provider-config.yaml
The more keys configured there, the more sources are queried.
"""
from __future__ import annotations

import json
import time
from typing import Any

import structlog

from core.config import Config
from core.network import run_command
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "subdomain_passive",
    "title":    "Passive Subdomains",
    "description": "Aggregates 40+ passive sources via Subfinder",
    "layer":    2,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": True,
}


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0        = time.monotonic()
    findings: list[dict] = []
    metadata: dict       = {"domains_scanned": 0, "subdomains_found": 0}

    for domain in scope.all_domains:
        subdomains = await _run_subfinder(domain, config)
        metadata["domains_scanned"] += 1
        metadata["subdomains_found"] += len(subdomains)

        for sub in subdomains:
            findings.append({
                "type":  "subdomain",
                "value": sub,
                "data":  {"source": "subfinder", "parent_domain": domain},
            })

    return {
        "module":   "layer2/subdomain/subdomain_passive",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None if findings else "subfinder returned no results",
    }


async def _run_subfinder(domain: str, config: Config) -> list[str]:
    # -recursive asks subfinder to re-query its sources for subdomains of the
    # subdomains it just found, which reaches hosts two labels deep that a
    # single pass misses. -all widens the source set (key-gated sources such as
    # FOFA, ZoomEye, Netlas only fire when their keys are configured in
    # subfinder's provider-config.yaml, their absence only costs coverage).
    result = await run_command(
        ["subfinder", "-d", domain, "-silent", "-json", "-all", "-recursive"],
        recon_mode="passive",
        config=config,
        timeout=config.timeouts.default * 2,
    )

    if not result.ok:
        if "not found" in result.stderr:
            log.warning("subfinder.not_installed")
        else:
            log.warning("subfinder.failed", domain=domain, stderr=result.stderr[:200])
        return []

    subdomains: list[str] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            host = data.get("host", "")
        except json.JSONDecodeError:
            host = line  # subfinder -silent sometimes outputs plain names
        if host:
            subdomains.append(host.lower())

    return list(set(subdomains))
