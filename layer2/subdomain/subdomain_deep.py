"""
layer2/subdomain/subdomain_deep.py, deep subdomain enumeration via OWASP Amass.

Amass runs longer than any other tool (up to config.timeouts.amass = 3600s)
and goes deeper: DNS brute-force, ASN enumeration, reverse WHOIS, BGP
routing lookups, certificate transparency, and passive data sources.

The no-time-limit philosophy applies here specifically, Amass running for
an hour on a complex target routinely finds subdomains missed by every
other tool. Do not add an artificial time limit.

Amass v4 dropped the v3 `-json <file>` flag entirely, discovered assets and
their relationships (FQDN -> a_record/aaaa_record -> IPAddress, etc.) are
written to an `amass.sqlite` database (Open Asset Model) inside `-dir`.
Results are read back via stdlib `sqlite3`, not a CLI output flag.

CLI tool required: amass (installed system-wide).
"""
from __future__ import annotations

import json
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Any

import structlog

from core.config import Config
from core.scope_guard import assert_in_scope, OutOfScopeError
from core.network import run_command
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "subdomain_deep",
    "title":    "Deep Subdomain Enum",
    "description": "Long-running exhaustive enumeration via OWASP Amass",
    "layer":    2,
    "mode":     ["semi", "active"],
    "requires": [],
    "optional": True,
}


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0        = time.monotonic()
    findings: list[dict] = []
    metadata: dict       = {"domains_scanned": 0, "subdomains_found": 0}

    for domain in scope.all_domains:
        # Authorisation check before any traffic. Enumerating a domain the
        # client has not authorised is a third-party problem, not a data one.
        try:
            assert_in_scope(domain, scope, module="layer2/subdomain/subdomain_deep",
                            action="enumerate with amass")
        except OutOfScopeError as exc:
            metadata.setdefault("blocked_out_of_scope", []).append(domain)
            log.error("subdomain_deep.out_of_scope", domain=domain, error=str(exc))
            continue

        subdomains = await _run_amass(domain, scope.mode, config)
        metadata["domains_scanned"]  += 1
        metadata["subdomains_found"] += len(subdomains)

        for entry in subdomains:
            findings.append({
                "type":  "subdomain",
                "value": entry["name"],
                "data":  {
                    "source":      "amass",
                    "addresses":   entry.get("addresses", []),
                    "tag":         entry.get("tag"),
                    "sources":     entry.get("sources", []),
                    "parent":      domain,
                },
            })

    return {
        "module":   "layer2/subdomain/subdomain_deep",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None if findings else "amass returned no results",
    }


async def _run_amass(domain: str, mode: str, config: Config) -> list[dict]:
    timeout = config.timeouts.amass  # no artificial limit

    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = Path(tmpdir)
        db_file = out_dir / "amass.sqlite"

        cmd = ["amass", "enum", "-passive", "-d", domain, "-dir", str(out_dir)]
        if mode == "active":
            # Remove -passive for active mode, enables brute force and active DNS
            cmd = ["amass", "enum", "-d", domain, "-dir", str(out_dir)]

        result = await run_command(cmd, recon_mode=mode, config=config, timeout=timeout)

        if not result.ok and not db_file.exists():
            if "not found" in result.stderr:
                log.warning("amass.not_installed")
            else:
                log.warning("amass.failed", domain=domain, stderr=result.stderr[:200])
            return []

        if not db_file.exists():
            return []

        return _parse_amass_db(db_file, domain)


def _parse_amass_db(db_file: Path, domain: str) -> list[dict]:
    """Read discovered FQDNs + resolved addresses from amass v4's OAM sqlite db."""
    entries: list[dict] = []
    try:
        conn = sqlite3.connect(str(db_file))
        try:
            cur = conn.cursor()
            cur.execute("SELECT id, content FROM assets WHERE type = 'FQDN'")
            fqdns: dict[int, str] = {}
            for asset_id, content in cur.fetchall():
                try:
                    name = json.loads(content).get("name")
                except (json.JSONDecodeError, AttributeError):
                    continue
                if name and name != domain and name.endswith(f".{domain}"):
                    fqdns[asset_id] = name

            addresses: dict[int, list[str]] = {asset_id: [] for asset_id in fqdns}
            if fqdns:
                cur.execute(
                    "SELECT r.from_asset_id, a.content FROM relations r "
                    "JOIN assets a ON a.id = r.to_asset_id "
                    "WHERE r.type IN ('a_record', 'aaaa_record') AND a.type = 'IPAddress'"
                )
                for from_id, content in cur.fetchall():
                    if from_id not in addresses:
                        continue
                    try:
                        addr = json.loads(content).get("address")
                    except (json.JSONDecodeError, AttributeError):
                        continue
                    if addr:
                        addresses[from_id].append(addr)

            for asset_id, name in fqdns.items():
                entries.append({
                    "name":      name,
                    "addresses": addresses.get(asset_id, []),
                })
        finally:
            conn.close()
    except sqlite3.Error as exc:
        log.warning("amass.db_parse_failed", domain=domain, error=str(exc))

    return entries
