"""
layer2/subdomain/dns_resolve.py, DNS resolution and validation of discovered subdomains.

Takes all subdomains found by crtsh, subfinder, amass, alterx, bruteforce
and resolves them with dnsx (ProjectDiscovery). Filters out dead domains,
extracts A/AAAA/CNAME/MX/NS records, and flags wildcards.

Running dnsx after all enumeration sources is the authoritative resolution
pass, only subdomains that actually resolve progress to Layer 2.5.

CLI tool required: dnsx (from ProjectDiscovery).
"""
from __future__ import annotations

import json
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
    "name":     "dns_resolve",
    "title":    "DNS Resolution",
    "description": "Authoritative resolution pass, ground truth for all hosts",
    "layer":    2,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": True,
    # Ground truth only works if every candidate source has already written its
    # findings. Without this the module resolves whatever happens to be in the
    # DB when it starts, which, run concurrently, is just the seed domains.
    "depends_on": [
        "cert_transparency",
        "subdomain_passive",
        "subdomain_deep",
        "subdomain_permutations",
        "subdomain_bruteforce",
    ],
}


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0        = time.monotonic()
    findings: list[dict] = []
    metadata: dict       = {}

    # Collect all unique subdomains discovered so far in this session
    # In Phase 1 we query the DB; fallback to scope domains only
    candidates = await _collect_candidates(scope, db)
    metadata["candidates"] = len(candidates)

    if not candidates:
        return {
            "module":   "layer2/subdomain/dns_resolve",
            "status":   "partial",
            "findings": [],
            "metadata": {"note": "no subdomain candidates to resolve"},
            "duration": time.monotonic() - t0,
            "error":    None,
        }

    # A wildcard record makes every possible label resolve, so resolution
    # stops being evidence that a host exists. Detect the wildcard IPs per
    # root domain first, then mark (never silently drop) matching hosts -
    # they need an HTTP response to count as real assets.
    wildcard_ips = await _detect_wildcards(scope, config)
    metadata["wildcard_domains"] = {d: sorted(ips) for d, ips in wildcard_ips.items() if ips}

    resolved = await _run_dnsx(candidates, config)
    metadata["resolved"] = len(resolved)

    wildcard_hits = 0
    for entry in resolved:
        host = entry.get("host", "").rstrip(".")
        if not host:
            continue

        a_records = entry.get("a", []) or []
        parent    = _matching_wildcard_parent(host, wildcard_ips)
        # Only a wildcard artefact if EVERY A record is a wildcard address and
        # there is no CNAME, a real host behind the same CDN IP will normally
        # differ in CNAME or carry additional records.
        is_wildcard = bool(
            parent
            and a_records
            and not entry.get("cname")
            and set(a_records) <= wildcard_ips[parent]
        )
        if is_wildcard:
            wildcard_hits += 1

        findings.append({
            "type":  "resolved_host",
            "value": host,
            "data": {
                "a":     a_records,
                "aaaa":  entry.get("aaaa", []),
                "cname": entry.get("cname", []),
                "mx":    entry.get("mx", []),
                "ns":    entry.get("ns", []),
                "ptr":   entry.get("ptr", []),
                "source": "dnsx",
                "wildcard_resolution": is_wildcard,
                "wildcard_parent":     parent if is_wildcard else None,
                "validated":           not is_wildcard,
            },
        })

    metadata["wildcard_resolutions"] = wildcard_hits
    metadata["validated_hosts"]      = len(findings) - wildcard_hits

    log.info(
        "dnsx.complete",
        candidates=len(candidates),
        resolved=len(resolved),
        wildcard_resolutions=wildcard_hits,
        validated=len(findings) - wildcard_hits,
    )

    return {
        "module":   "layer2/subdomain/dns_resolve",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _collect_candidates(scope: Scope, db: Any) -> list[str]:
    candidates: set[str] = set(scope.all_domains)

    if db is None:
        return sorted(candidates)

    try:
        # Pull subdomain findings from all layer2 subdomain modules
        run_id = await _latest_run_id(scope, db)
        if run_id:
            rows = await db.get_findings(run_id, "subdomain")
            candidates.update(r["value"] for r in rows if r.get("value"))
    except Exception as exc:
        log.debug("dnsx.db_query_failed", error=str(exc))

    return sorted(candidates)


async def _latest_run_id(scope: Scope, db: Any) -> str:
    try:
        return await db.get_last_run_id(scope.target.name) or ""
    except Exception:
        return ""


# Random labels that should never exist. If they resolve, the parent domain
# has a wildcard record and resolution alone proves nothing about a host.
_WILDCARD_PROBES = (
    "zz-nonexistent-wildcard-probe-a1",
    "zz-nonexistent-wildcard-probe-b2",
)


async def _detect_wildcards(scope: Scope, config: Config) -> dict[str, set[str]]:
    """
    Probe each root domain in scope with random labels.

    Returns {root_domain: {wildcard A records}}. An empty set means no
    wildcard. Both probes must resolve to the same address set, so a domain
    that merely happens to catch one probe is not misreported.
    """
    wildcards: dict[str, set[str]] = {}

    for domain in scope.all_domains:
        probes = [f"{label}.{domain}" for label in _WILDCARD_PROBES]
        entries = await _run_dnsx(probes, config)

        by_host = {
            e.get("host", "").rstrip("."): set(e.get("a", []) or [])
            for e in entries
        }
        sets = [by_host.get(p, set()) for p in probes]

        if all(sets) and sets[0] == sets[1]:
            wildcards[domain] = sets[0]
            log.warning(
                "dnsx.wildcard_detected",
                domain=domain,
                addresses=sorted(sets[0]),
            )
        else:
            wildcards[domain] = set()

    return wildcards


def _matching_wildcard_parent(host: str, wildcards: dict[str, set[str]]) -> str | None:
    """Return the scoped root domain whose wildcard could cover `host`."""
    for domain, ips in wildcards.items():
        if ips and host.endswith("." + domain):
            return domain
    return None


async def _run_dnsx(hosts: list[str], config: Config) -> list[dict]:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(hosts))
        list_file = Path(f.name)

    try:
        result = await run_command(
            [
                "dnsx", "-l", str(list_file),
                "-silent", "-json",
                "-a", "-aaaa", "-cname", "-mx", "-ns", "-ptr",
                "-resp", "-retry", "3",
            ],
            recon_mode="passive",
            config=config,
            timeout=config.timeouts.default * 3,
        )
    finally:
        list_file.unlink(missing_ok=True)

    if not result.ok and not result.stdout.strip():
        if "not found" in result.stderr:
            log.warning("dnsx.not_installed")
        else:
            log.warning("dnsx.failed", stderr=result.stderr[:200])
        return []

    entries: list[dict] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            pass

    return entries
