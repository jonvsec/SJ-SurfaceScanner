"""
layer2/network/zone_transfer.py, DNS zone transfer (AXFR) attempt.

Attempts AXFR zone transfer against the target's authoritative nameservers.
A successful zone transfer dumps the entire DNS zone, all hostnames, IPs,
MX records, SPF records, and internal naming conventions.

Still works surprisingly often against misconfigured DNS servers, especially
in enterprise environments where the primary NS is locked down but secondary
or internal NS servers accept transfers.

Mode: semi, makes DNS queries directly to target's nameservers.
Uses dnspython for Python-native AXFR without requiring dig.
"""
from __future__ import annotations

import time
from typing import Any

import structlog

from core.config import Config
from core.ratelimiter import RateLimiter
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "zone_transfer",
    "title":    "DNS Zone Transfer",
    "description": "AXFR attempt against authoritative nameservers",
    "layer":    2,
    "mode":     ["semi", "active"],
    "requires": [],
    "optional": True,
}


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict       = {"domains_tried": 0, "transfers_succeeded": 0}

    try:
        import dns.resolver
        import dns.zone
        import dns.query
        import dns.exception
    except ImportError:
        return {
            "module":   "layer2/network/zone_transfer",
            "status":   "error",
            "findings": [],
            "metadata": {},
            "duration": time.monotonic() - t0,
            "error":    "dnspython not installed",
        }

    import asyncio

    for domain in scope.all_domains:
        metadata["domains_tried"] += 1

        # First: get authoritative nameservers for the domain
        nameservers = await _get_nameservers(domain, dns.resolver)
        if not nameservers:
            log.debug("zonetransfer.no_ns", domain=domain)
            continue

        for ns in nameservers:
            # dns.query.xfr's `where` must be a literal IP address, it
            # raises ValueError (no DNS resolution) if given a hostname,
            # which _get_nameservers always returns.
            ns_ip = await _resolve_ns_ip(ns, dns.resolver)
            if not ns_ip:
                log.debug("zonetransfer.ns_unresolved", domain=domain, ns=ns)
                continue

            await limiter.acquire("default")
            try:
                loop     = asyncio.get_event_loop()
                zone     = await loop.run_in_executor(
                    None,
                    lambda: dns.zone.from_xfr(
                        dns.query.xfr(ns_ip, domain, timeout=10, lifetime=30)
                    ),
                )
                metadata["transfers_succeeded"] += 1
                log.warning(
                    "zonetransfer.success",
                    domain=domain,
                    nameserver=ns,
                    records=len(zone.nodes),
                )

                records = _parse_zone(zone, domain)
                for record in records:
                    findings.append({
                        "type":  "zone_transfer_record",
                        "value": record["name"],
                        "data":  {
                            **record,
                            "nameserver": ns,
                            "domain":     domain,
                            "source":     "axfr",
                        },
                    })

                # Add a summary finding flagging the misconfiguration
                findings.append({
                    "type":  "zone_transfer_vulnerability",
                    "value": domain,
                    "data": {
                        "domain":     domain,
                        "nameserver": ns,
                        "records":    len(records),
                        "severity":   "high",
                        "cwe":        "CWE-200",
                    },
                })
                break  # Got a transfer, no need to try other NSes

            except Exception as exc:
                # REFUSED or NOTAUTH is expected, silently continue
                error_str = str(exc).lower()
                if "refused" in error_str or "notauth" in error_str or "timeout" in error_str:
                    log.debug("zonetransfer.refused", domain=domain, ns=ns)
                else:
                    log.debug("zonetransfer.failed", domain=domain, ns=ns, error=str(exc))

    return {
        "module":   "layer2/network/zone_transfer",
        "status":   "success",  # always success, REFUSED is expected normal state
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _get_nameservers(domain: str, resolver) -> list[str]:
    try:
        import asyncio
        loop = asyncio.get_event_loop()
        ans  = await loop.run_in_executor(
            None,
            lambda: resolver.resolve(domain, "NS"),
        )
        return [str(ns).rstrip(".") for ns in ans]
    except Exception:
        return []


async def _resolve_ns_ip(ns: str, resolver) -> str | None:
    """Resolve a nameserver hostname to an IP address (A then AAAA)."""
    import asyncio
    loop = asyncio.get_event_loop()
    for rdtype in ("A", "AAAA"):
        try:
            ans = await loop.run_in_executor(
                None,
                lambda rt=rdtype: resolver.resolve(ns, rt),
            )
            return str(ans[0])
        except Exception:
            continue
    return None


def _parse_zone(zone, domain: str) -> list[dict]:
    records = []
    for name, node in zone.nodes.items():
        fqdn = f"{name}.{domain}".strip(".")
        for rdataset in node.rdatasets:
            rdtype = rdataset.rdtype
            for rdata in rdataset:
                records.append({
                    "name":  fqdn,
                    "type":  rdtype,
                    "value": str(rdata),
                    "ttl":   rdataset.ttl,
                })
    return records
