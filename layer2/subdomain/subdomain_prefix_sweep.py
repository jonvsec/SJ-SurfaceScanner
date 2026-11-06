"""
layer2/subdomain/subdomain_prefix_sweep.py, curated common-prefix DNS sweep.

Passive certificate-transparency enumeration misses an estimated 20 to 40
percent of high-value subdomains: hosts behind wildcard certificates that never
expose the FQDN, HTTP-only or self-signed hosts that were never issued a public
cert, and very recently provisioned hosts not yet propagated to CT log mirrors.
This module pairs the passive sources with a short, hit-rate-ordered active
prefix probe.

It is distinct from subdomain_bruteforce (a large wordlist) and from
subdomain_permutations (mutations of already-known names). This is a small,
curated list of the prefixes that pay off most often in real engagements,
including the tuned entries commodity lists miss (sclepro, eapps, and the
procurement cluster). One A-record query per prefix, resolved through public
resolvers, so detectability is low (no port scan, no HTTP, nothing to the
client's own web stack).

CLI tool required: dnsx (ProjectDiscovery). puredns is used when present for
native wildcard filtering, dnsx is the fallback.
Mode: semi, the queries hit resolvers and are visible in passive DNS.
"""
from __future__ import annotations

import tempfile
import time
from pathlib import Path
from typing import Any

import structlog

from core.config import Config
from core.network import run_command
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "subdomain_prefix_sweep",
    "title":    "Common-Prefix Sweep",
    "description": "Curated hit-rate-ordered active prefix probe",
    "layer":    2,
    "mode":     ["semi", "active"],
    "requires": [],
    "optional": True,
}

# ~130 prefixes ordered by real-engagement hit rate, grouped by purpose. The
# unusual entries (sclepro, eapps, tender/suppliers/procurement) are the ones a
# generic top-list does not carry and are exactly what surfaced on past
# engagements.
PREFIXES: list[str] = [
    # mail
    "www", "mail", "webmail", "smtp", "imap", "pop", "owa", "autodiscover",
    "mx", "mx1", "mx2", "exchange", "relay", "email", "newsletter",
    # remote access
    "ftp", "sftp", "vpn", "sslvpn", "gateway", "gp", "globalprotect",
    "citrix", "anyconnect", "remote", "access", "rdp", "jump", "bastion",
    # api / app
    "api", "api1", "api2", "app", "apps", "mobile", "m",
    # identity
    "portal", "login", "sso", "idp", "iam", "identity", "accounts", "oauth",
    "auth", "adfs",
    # admin consoles
    "admin", "manage", "console", "dashboard", "cp", "cpanel",
    # internal / business
    "intranet", "internal", "hr", "payroll", "finance", "sap", "erp", "crm",
    "helpdesk", "servicedesk", "support", "help", "kb", "status",
    # ops / monitoring
    "monitoring", "monitor", "metrics", "grafana", "kibana", "prometheus",
    "logs", "logging", "elastic",
    # dev tooling
    "docs", "wiki", "confluence", "jira", "bitbucket", "gitlab", "jenkins",
    "sonar", "nexus", "git", "svn", "repo", "code", "ci", "cd",
    # environments
    "dev", "test", "staging", "stg", "qa", "uat", "sandbox", "preprod",
    "preview", "demo", "beta",
    # careers
    "careers", "jobs", "vacancies", "recruit", "eapps",
    # commerce
    "shop", "store", "ecommerce", "checkout", "payments", "pay", "billing",
    "cart",
    # legacy
    "old", "legacy", "archive", "backup", "v1", "v2", "classic", "deprecated",
    # cdn / static
    "cdn", "static", "assets", "media", "img", "images", "files", "downloads",
    "public", "storage",
    # nameservers
    "ns", "ns1", "ns2", "dns",
    # collaboration
    "zoom", "teams", "slack", "lync", "sip", "voice", "meet",
    # procurement cluster (engagement-tuned)
    "sclepro", "tender", "tenders", "suppliers", "vendor", "vendors",
    "procurement", "purchase",
]

_PUREDNS_RATE = 1000


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0        = time.monotonic()
    findings: list[dict] = []
    metadata: dict       = {"prefixes": len(PREFIXES), "bases": 0, "resolved": 0}

    bases = list(scope.all_domains)
    metadata["bases"] = len(bases)

    for base in bases:
        candidates = [f"{p}.{base}" for p in PREFIXES]
        resolved   = await _resolve_batch(candidates, config)
        metadata.setdefault("per_domain", {})[base] = len(resolved)
        metadata["resolved"] += len(resolved)
        for host in resolved:
            findings.append({
                "type":  "subdomain",
                "value": host,
                "data":  {"source": "prefix_sweep", "parent_domain": base},
            })

    log.info("prefix_sweep.complete", bases=len(bases), resolved=metadata["resolved"])

    return {
        "module":   "layer2/subdomain/subdomain_prefix_sweep",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None if findings else "no prefix candidates resolved",
    }


async def _resolve_batch(candidates: list[str], config: Config) -> list[str]:
    """puredns (native wildcard filtering) first, dnsx fallback."""
    if not candidates:
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(candidates))
        list_file = Path(f.name)

    resolvers = _find_resolvers(config)
    try:
        cmd = ["puredns", "resolve", str(list_file), "--quiet",
               "--wildcard-tests", "3", "--rate-limit", str(_PUREDNS_RATE)]
        if resolvers:
            cmd += ["--resolvers", str(resolvers)]
        result = await run_command(cmd, recon_mode="semi", config=config, timeout=300)

        if not (result.stdout or "").strip():
            result = await run_command(
                ["dnsx", "-l", str(list_file), "-silent", "-resp", "-retry", "2"],
                recon_mode="semi", config=config, timeout=300)
    finally:
        list_file.unlink(missing_ok=True)

    resolved = set()
    for line in (result.stdout or "").splitlines():
        parts = line.strip().split()
        if parts:
            resolved.add(parts[0].rstrip("."))
    return sorted(resolved)


def _find_resolvers(config: Config) -> Path | None:
    wl_dir = config.paths.get("wordlists", Path("/nonexistent"))
    for p in (wl_dir / "resolvers.txt", Path.home() / "resolvers.txt"):
        try:
            if p.is_file():
                return p
        except OSError:
            continue
    return None
