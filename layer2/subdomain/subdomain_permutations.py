"""
layer2/subdomain/subdomain_permutations.py, subdomain permutation generation via Alterx.

Takes the subdomains already discovered by crtsh/subfinder/amass and generates
intelligent permutations using word patterns: dev-, staging-, api-, internal-,
vpn-, mail-, etc. Permutations are piped to dnsx for immediate resolution.

Finds subdomains that are never in certificate logs or passive sources because
they were never publicly enumerated, only the naming pattern reveals them.

CLI tools required: alterx, dnsx (both from ProjectDiscovery).
Reads previous layer2 subdomain findings from PostgreSQL (run_id arg).
Falls back to scope.domains if no DB findings available.
"""
from __future__ import annotations

import time
from typing import Any

import structlog

from core.config import Config
from core.network import run_command
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "subdomain_permutations",
    "title":    "Subdomain Permutations",
    "description": "Generates and resolves naming-pattern variants",
    "layer":    2,
    "mode":     ["semi", "active"],
    "requires": [],
    "optional": True,
}

# Common permutation patterns alterx will expand these with
_PATTERNS = [
    "{{word}}-{{sub}}",
    "{{sub}}-{{word}}",
    "{{word}}.{{sub}}",
    "{{sub}}.{{word}}",
]


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0        = time.monotonic()
    findings: list[dict] = []
    metadata: dict       = {"input_domains": 0, "permutations_resolved": 0}

    # Collect existing subdomains from DB if available, else seed from scope
    seed_domains = await _get_seed_domains(scope, db)
    metadata["input_domains"] = len(seed_domains)

    if not seed_domains:
        return {
            "module":   "layer2/subdomain/subdomain_permutations",
            "status":   "partial",
            "findings": [],
            "metadata": metadata,
            "duration": time.monotonic() - t0,
            "error":    "no seed domains available for permutation",
        }

    resolved = await _run_alterx_dnsx(seed_domains, config)
    metadata["permutations_resolved"] = len(resolved)

    for host in resolved:
        findings.append({
            "type":  "subdomain",
            "value": host,
            "data":  {"source": "alterx_permutation", "resolved": True},
        })

    return {
        "module":   "layer2/subdomain/subdomain_permutations",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _get_seed_domains(scope: Scope, db: Any) -> list[str]:
    """Pull subdomain findings from DB if available, else use scope domains."""
    if db is None:
        return list(scope.all_domains)
    try:
        rows = await db.get_findings(
            await _latest_run_id(scope, db), "subdomain"
        )
        found = [r["value"] for r in rows if r.get("value")]
        return found if found else list(scope.all_domains)
    except Exception:
        return list(scope.all_domains)


async def _latest_run_id(scope: Scope, db: Any) -> str:
    try:
        return await db.get_last_run_id(scope.target.name) or ""
    except Exception:
        return ""


async def _run_alterx_dnsx(domains: list[str], config: Config) -> list[str]:
    """
    Pipe domain list through alterx to generate permutations, then resolve
    with dnsx. Returns only hosts that actually resolve.
    """
    import tempfile
    from pathlib import Path

    # Write seed list to temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(domains[:500]))  # cap seed to avoid runaway permutations
        seed_file = Path(f.name)

    try:
        # alterx reads the list and generates permutations
        alterx_result = await run_command(
            ["alterx", "-l", str(seed_file), "-silent"],
            recon_mode="semi",
            config=config,
            timeout=120,
        )

        if not alterx_result.ok:
            if "not found" in alterx_result.stderr:
                log.warning("alterx.not_installed")
            return []

        permutations = [l.strip() for l in alterx_result.stdout.splitlines() if l.strip()]

        if not permutations:
            return []

        # Write permutations to temp file for dnsx
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(permutations[:5000]))  # cap to avoid very long runs
            perm_file = Path(f.name)

        try:
            dnsx_result = await run_command(
                ["dnsx", "-l", str(perm_file), "-silent", "-resp"],
                recon_mode="semi",
                config=config,
                timeout=300,
            )

            if not dnsx_result.ok:
                return []

            resolved = set()
            for line in dnsx_result.stdout.splitlines():
                # dnsx -resp output: "host [IP]", one line per DNS record,
                # so a host with multiple A/AAAA records appears more than
                # once. Dedupe so each resolved host yields one finding.
                parts = line.strip().split()
                if parts:
                    resolved.add(parts[0].rstrip("."))
            return sorted(resolved)
        finally:
            perm_file.unlink(missing_ok=True)
    finally:
        seed_file.unlink(missing_ok=True)
