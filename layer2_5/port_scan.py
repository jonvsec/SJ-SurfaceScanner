"""
layer2_5/port_scan.py — port scanning (passive + active).

Passive mode (Shodan, Censys): queries third-party scan databases for open
ports on target IPs. No packets sent to target.

Active mode (nmap via VPS): performs TCP SYN scan on the full port range.
ALWAYS routes via disposable VPS — never port scans from local machine.
This is enforced by core/network.py, not just policy.

Ports found feed layer4/ kill chain: open RDP → lateral movement vector,
open Elasticsearch → data exposure, open Redis → no-auth exec.
"""
from __future__ import annotations

import time
import xml.etree.ElementTree as ET
from typing import Any

import structlog

from core.config import Config
from core.controls import CUSTOMER, SHARED, all_ports_open, attribute_hosting
from core.network import run_command
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "port_scan",
    "title":    "Port Scan",
    "description": "Passive and active open-port discovery",
    "layer":    2.5,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": True,
}

# High-value ports for targeted scanning
_INTERESTING_PORTS = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    443:   "HTTPS",
    445:   "SMB",
    1433:  "MSSQL",
    1521:  "Oracle",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    9200:  "Elasticsearch",
    9300:  "Elasticsearch Cluster",
    27017: "MongoDB",
    5601:  "Kibana",
    9090:  "Prometheus",
    2181:  "ZooKeeper",
    2379:  "etcd",
    4369:  "RabbitMQ EPMD",
    5672:  "AMQP",
    6443:  "Kubernetes API",
}


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    findings: list[dict] = []
    metadata: dict       = {}

    # Passive: Shodan for known IPs
    shodan_findings = await _shodan_ports(scope, db)
    findings.extend(shodan_findings)
    metadata["shodan_findings"] = len(shodan_findings)

    # Active: nmap via VPS (active mode only)
    if scope.mode == "active":
        ip_ranges = list(scope.ip_ranges)
        db_ranges = await _get_db_ranges(scope, db)
        ip_ranges.extend(r for r in db_ranges if r not in ip_ranges)

        nmap_findings = await _nmap_scan(ip_ranges[:5], config)
        findings.extend(nmap_findings)
        metadata["nmap_findings"] = len(nmap_findings)

    # Flag high-risk open ports
    for finding in findings:
        port    = finding["data"].get("port")
        service = _INTERESTING_PORTS.get(port)
        if service and port in (3389, 445, 6379, 9200, 27017, 5432, 3306):
            finding["data"]["high_risk"] = True
            finding["data"]["risk_note"] = f"Open {service} ({port}) — common exploitation target"
            finding["data"]["severity"]  = finding["data"].get("severity", "medium")

    return {
        "module":   "layer2_5/port_scan",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _shodan_ports(scope: Scope, db: Any) -> list[dict]:
    """Re-use Shodan findings already in DB from layer2/network/shodan."""
    findings = []
    if db is None:
        return findings
    try:
        run_id = await db.get_last_run_id(scope.target.name) or ""
        if not run_id:
            return findings
        rows = await db.get_findings(run_id, "shodan_host")
        for row in rows:
            data = row.get("data") or {}
            port = data.get("port")
            ip   = data.get("ip") or row.get("value", "")
            # A service on a shared platform belongs to the platform operator,
            # not to the customer. Addresses on platforms such as Cloudflare,
            # Fastly, Vercel and Framer must be removed from the customer's port
            # findings, and content delivery front ends often report almost
            # every port open, which is a filtering device answering
            # indiscriminately rather than a service inventory.
            hosting, platform = attribute_hosting(
                data.get("org"), data.get("isp"), data.get("hostname"),
                data.get("product"), ip,
            )
            findings.append({
                "type":  "open_port",
                "value": f"{ip}:{port}",
                "data": {
                    "ip":       ip,
                    "port":     port,
                    "service":  _INTERESTING_PORTS.get(port, data.get("product", "unknown")),
                    "product":  data.get("product"),
                    "version":  data.get("version"),
                    "source":   "shodan",
                    "hosting":  hosting,
                    "platform": platform,
                    "actionable_by_customer": hosting == CUSTOMER,
                    "severity": "medium" if hosting == CUSTOMER else "info",
                },
            })
    except Exception as exc:
        log.debug("ports.shodan_db_failed", error=str(exc))
    return findings


async def _nmap_scan(ip_ranges: list[str], config: Config) -> list[dict]:
    if not ip_ranges:
        return []

    findings = []
    port_list = ",".join(str(p) for p in _INTERESTING_PORTS)

    for ip_range in ip_ranges:
        result = await run_command(
            [
                "nmap", "-sS", "-p", port_list,
                "--open", "-oX", "-", "--max-retries", "1",
                "--host-timeout", "120s",
                ip_range,
            ],
            recon_mode="active",  # enforces VPS routing
            config=config,
            timeout=600,
        )

        if not result.ok:
            if "not found" in result.stderr:
                log.warning("ports.nmap_not_installed")
            else:
                log.warning("ports.nmap_failed", error=result.stderr[:300])
            continue

        try:
            root = ET.fromstring(result.stdout)
            for host in root.findall("host"):
                ip = _extract_ip(host)
                for port_el in host.findall("./ports/port"):
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue
                    port       = int(port_el.get("portid"))
                    service_el = port_el.find("service")
                    service    = _INTERESTING_PORTS.get(
                        port, service_el.get("name", "") if service_el is not None else ""
                    )
                    findings.append({
                        "type":  "open_port",
                        "value": f"{ip}:{port}",
                        "data": {
                            "ip":       ip,
                            "port":     port,
                            "state":    "open",
                            "service":  service,
                            "version":  service_el.get("version") if service_el is not None else None,
                            "source":   "nmap",
                            "severity": "medium",
                        },
                    })
        except Exception as exc:
            log.warning("ports.nmap_parse_failed", error=str(exc))

    return findings


async def _get_db_ranges(scope: Scope, db: Any) -> list[str]:
    if db is None:
        return []
    try:
        run_id = await db.get_last_run_id(scope.target.name) or ""
        rows   = await db.get_findings(run_id, "ip_range") if run_id else []
        return [r["value"] for r in rows if r.get("value")]
    except Exception:
        return []


def _extract_ip(host: ET.Element) -> str:
    for addr in host.findall("address"):
        if addr.get("addrtype") in ("ipv4", "ipv6"):
            return addr.get("addr", "")
    return ""
