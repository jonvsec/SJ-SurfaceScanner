"""
layer2_5/service_banners.py — service banner grabbing and version detection.

Connects to open ports discovered by ports.py and grabs service banners.
Extracts software versions for CVE correlation in Layer 4.

Services of particular interest:
  SSH banners (OpenSSH version → CVE lookup)
  SMTP banners (Postfix/Sendmail version)
  FTP banners (vsftpd/ProFTPD version)
  HTTP Server headers (nginx/Apache version)
  Database error messages (MySQL/PostgreSQL version disclosure)

Mode: semi (connects to target ports). Routes to VPS for active.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

import structlog

from core.config import Config
from core.ratelimiter import RateLimiter
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "service_banners",
    "title":    "Service Banners",
    "description": "Banner grabbing and version detection",
    "layer":    2.5,
    "mode":     ["semi", "active"],
    "requires": [],
    "optional": True,
}

_TIMEOUT   = 8
_BANNER_PORTS = {
    21:   "ftp",
    22:   "ssh",
    23:   "telnet",
    25:   "smtp",
    110:  "pop3",
    143:  "imap",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    27017: "mongodb",
}


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict       = {"ports_probed": 0, "banners_grabbed": 0}

    # Get open ports from DB (from ports.py)
    port_list = await _get_open_ports(scope, db)

    for ip, port in port_list[:100]:
        if port not in _BANNER_PORTS:
            continue
        metadata["ports_probed"] += 1
        await limiter.acquire("default")

        banner = await _grab_banner(ip, port)
        if banner:
            metadata["banners_grabbed"] += 1
            version = _extract_version(banner, port)
            findings.append({
                "type":  "service_banner",
                "value": f"{ip}:{port}",
                "data": {
                    "ip":       ip,
                    "port":     port,
                    "protocol": _BANNER_PORTS[port],
                    "banner":   banner[:300],
                    "version":  version,
                    "severity": "medium" if version else "info",
                },
            })

    return {
        "module":   "layer2_5/service_banners",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _get_open_ports(scope: Scope, db: Any) -> list[tuple[str, int]]:
    ports: list[tuple[str, int]] = []
    if db is None:
        return ports
    try:
        run_id = await db.get_last_run_id(scope.target.name) or ""
        if not run_id:
            return ports
        rows = await db.get_findings(run_id, "open_port")
        for row in rows:
            data = row.get("data") or {}
            ip   = data.get("ip", "")
            port = data.get("port", 0)
            if ip and port:
                ports.append((ip, int(port)))
    except Exception:
        pass
    return ports


async def _grab_banner(ip: str, port: int) -> str | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=_TIMEOUT,
        )
        # Some services send banner on connect; others need a prompt
        try:
            banner = await asyncio.wait_for(reader.read(1024), timeout=_TIMEOUT)
            if not banner and port in (25, 21, 110, 143):
                # Try sending a greeting
                writer.write(b"EHLO test\r\n")
                await writer.drain()
                banner = await asyncio.wait_for(reader.read(1024), timeout=_TIMEOUT)
        finally:
            writer.close()

        return banner.decode(errors="replace").strip() if banner else None
    except Exception:
        return None


import re as _re
_VERSION_PATTERNS = {
    "ssh":        _re.compile(r"SSH-\d+\.\d+-(\S+)"),
    "smtp":       _re.compile(r"(?:ESMTP|MTA)\s+(\S+)"),
    "ftp":        _re.compile(r"(?:vsftpd|ProFTPD|Pure-FTPd)\s+([\d.]+)"),
    "mysql":      _re.compile(r"(\d+\.\d+\.\d+)-"),
    "postgresql": _re.compile(r"PostgreSQL\s+([\d.]+)"),
    "redis":      _re.compile(r"Redis\s+([\d.]+)"),
}


def _extract_version(banner: str, port: int) -> str | None:
    protocol = _BANNER_PORTS.get(port, "")
    pattern  = _VERSION_PATTERNS.get(protocol)
    if pattern:
        m = pattern.search(banner)
        if m:
            return m.group(1)
    return None
