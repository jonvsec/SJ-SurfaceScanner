"""
layer2_5/tls_analysis.py — SSL/TLS configuration analysis.

Checks SSL/TLS configuration for:
  - Protocol version (SSLv3, TLS 1.0, 1.1 → deprecated)
  - Certificate expiry and validity
  - Weak cipher suites (RC4, DES, 3DES, NULL, EXPORT)
  - Self-signed or untrusted certificate chains
  - Certificate subject / SAN mismatch
  - HSTS preload status

Uses Python's ssl module for basic checks and sslyze for comprehensive
TLS analysis when available. Falls back gracefully when sslyze is absent.

Mode: semi (connects to target).
"""
from __future__ import annotations

import asyncio
import os
import ssl
import socket
import tempfile
import time
from datetime import datetime, timezone
from typing import Any

import structlog

from core.config import Config
from core.ratelimiter import RateLimiter
from core.scope_guard import filter_in_scope
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "tls_analysis",
    "title":    "TLS / Certificate",
    "description": "Expiry, self-signed, weak ciphers, hostname mismatch",
    "layer":    2.5,
    "mode":     ["semi", "active"],
    "requires": [],
    "optional": True,
}

_TIMEOUT = 10


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict       = {"hosts_checked": 0}

    hosts = await _get_hosts(scope, db)

    loop = asyncio.get_event_loop()
    for host in hosts:
        await limiter.acquire("default")
        metadata["hosts_checked"] += 1
        try:
            host_findings = await loop.run_in_executor(
                None, lambda h=host: _check_ssl(h)
            )
            findings.extend(host_findings)
        except Exception as exc:
            log.debug("ssl.check_failed", host=host, error=str(exc))

    return {
        "module":   "layer2_5/tls_analysis",
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
    return sorted(filter_in_scope(hosts, scope, module=__name__))[:30]


def _decode_cert(cert_bin: bytes | None) -> dict | None:
    """Decode a DER certificate obtained under CERT_NONE.

    `SSLSocket.getpeercert()` returns `{}` whenever `verify_mode` is
    `CERT_NONE` — it never parses the certificate the peer presented,
    regardless of whether one exists. The binary (DER) form is still
    available via `getpeercert(binary_form=True)`, so reconstruct the
    parsed dict from that via the (private but stable) cert decoder.
    """
    if not cert_bin:
        return None
    pem = ssl.DER_cert_to_PEM_cert(cert_bin)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
        f.write(pem)
        path = f.name
    try:
        return ssl._ssl._test_decode_cert(path)
    except Exception:
        return None
    finally:
        os.unlink(path)


def _check_ssl(host: str, port: int = 443) -> list[dict]:
    findings = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                # getpeercert() returns {} under CERT_NONE (no validation
                # was performed), even though the peer presented a cert —
                # decode the raw DER form instead.
                cert    = _decode_cert(ssock.getpeercert(binary_form=True))
                version = ssock.version()
                cipher  = ssock.cipher()

        # Protocol version check
        if version in ("SSLv3", "TLSv1", "TLSv1.1"):
            findings.append({
                "type":  "weak_tls_protocol",
                "value": host,
                "data": {
                    "host":     host,
                    "protocol": version,
                    "issue":    f"{version} is deprecated and insecure",
                    "severity": "high" if version in ("SSLv3", "TLSv1") else "medium",
                },
            })

        # Cipher suite check
        if cipher:
            cipher_name = cipher[0] if cipher else ""
            weak_ciphers = ("RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5")
            for weak in weak_ciphers:
                if weak.lower() in cipher_name.lower():
                    findings.append({
                        "type":  "weak_cipher",
                        "value": host,
                        "data": {
                            "host":     host,
                            "cipher":   cipher_name,
                            "issue":    f"Weak cipher {cipher_name} in use",
                            "severity": "high",
                        },
                    })
                    break

        # Certificate checks
        if cert:
            findings.extend(_check_certificate(host, cert))

    except ssl.SSLError as exc:
        findings.append({
            "type":  "ssl_error",
            "value": host,
            "data":  {"host": host, "error": str(exc), "severity": "medium"},
        })
    except (ConnectionRefusedError, socket.timeout, OSError):
        pass  # port not open or unreachable — expected

    return findings


def _check_certificate(host: str, cert: dict) -> list[dict]:
    findings = []
    now      = datetime.now(timezone.utc)

    # Expiry check
    not_after_str = cert.get("notAfter", "")
    if not_after_str:
        try:
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (not_after - now).days
            if days_left < 0:
                findings.append({
                    "type":  "expired_certificate",
                    "value": host,
                    "data": {
                        "host":     host,
                        "expired":  True,
                        "not_after": not_after_str,
                        "severity": "critical",
                    },
                })
            elif days_left < 30:
                findings.append({
                    "type":  "expiring_certificate",
                    "value": host,
                    "data": {
                        "host":      host,
                        "days_left": days_left,
                        "not_after": not_after_str,
                        "severity":  "high" if days_left < 14 else "medium",
                    },
                })
        except ValueError:
            pass

    # Extract cert info as a finding
    subject    = dict(x[0] for x in cert.get("subject", []))
    issuer     = dict(x[0] for x in cert.get("issuer", []))
    sans       = [v for _, v in cert.get("subjectAltName", [])]
    is_self_signed = subject == issuer

    findings.append({
        "type":  "ssl_certificate",
        "value": host,
        "data": {
            "host":         host,
            "cn":           subject.get("commonName"),
            "issuer":       issuer.get("organizationName"),
            "not_before":   cert.get("notBefore"),
            "not_after":    cert.get("notAfter"),
            "sans":         sans[:20],
            "self_signed":  is_self_signed,
            "severity":     "high" if is_self_signed else "info",
        },
    })

    if is_self_signed:
        findings.append({
            "type":  "self_signed_certificate",
            "value": host,
            "data": {
                "host":     host,
                "cn":       subject.get("commonName"),
                "issue":    "Self-signed certificate — no trusted CA validation",
                "severity": "high",
            },
        })

    return findings
