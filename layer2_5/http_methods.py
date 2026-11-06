"""
layer2_5/http_methods.py — request method handling.

Checks whether a host accepts methods that write or that echo the request back,
covering OPTIONS advertisement, TRACE, and the write methods PUT, DELETE and
PATCH.

TRACE is the reason this module verifies rather than reports on status alone.
A host can answer TRACE with 200 and still not be vulnerable to cross site
tracing: a single page application often returns its own login page as HTML for
any method rather than echoing the request as message/http, so the method is
being handled like an ordinary read and nothing can be extracted through it.
A genuinely enabled TRACE returns the request it was sent, so this module sends
a header it can recognise and looks for it coming back.

Write methods are checked with a path that does not exist and are never sent a
body, so nothing is created even where the method is accepted. A 405 or 501 is
the expected healthy answer.

Mode: semi (sends requests to the target).
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
import structlog

from core.config import Config
from core.controls import Coverage, fingerprint_catchall
from core.ratelimiter import RateLimiter
from core.scope_guard import filter_in_scope
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":        "http_methods",
    "title":       "Request Method Handling",
    "description": "Write methods, TRACE echo and advertised method sets",
    "layer":       2.5,
    "mode":        ["semi", "active"],
    "requires":    [],
    "optional":    False,
}

_TIMEOUT = 12
_CONCURRENCY = 6
_PROBE_HEADER = "X-SurfaceScanner-Probe"
_PROBE_VALUE = "trace-echo-check"
_WRITE_METHODS = ("PUT", "DELETE", "PATCH")
_ACCEPTED = (200, 201, 202, 204)


async def _trace(client, host, limiter, cov) -> dict | None:
    """
    Confirm cross site tracing rather than assume it from a status code.

    A real TRACE response has content type message/http and contains the
    request that was sent, including the probe header.
    """
    await limiter.acquire("default")
    try:
        r = await client.request("TRACE", f"https://{host}/",
                                 headers={_PROBE_HEADER: _PROBE_VALUE}, timeout=_TIMEOUT)
        cov.record(True)
    except Exception:
        cov.record(False)
        return None

    if r.status_code != 200:
        return None

    ctype = r.headers.get("content-type", "").lower()
    body = r.text[:2048]
    echoed = _PROBE_VALUE.lower() in body.lower() or _PROBE_HEADER.lower() in body.lower()
    is_trace = "message/http" in ctype

    if not (echoed or is_trace):
        # answered, but as an ordinary page. Not cross site tracing.
        cov.drop()
        log.debug("methods.trace_not_echo", host=host, ctype=ctype)
        return None

    cov.keep()
    return {
        "type":  "trace_method_enabled",
        "value": f"https://{host}/",
        "data": {
            "host": host, "severity": "low",
            "content_type": ctype,
            "request_echoed": echoed,
            "note": "TRACE returns the request it was sent, which allows cross site tracing",
            "preview": body[:200],
        },
    }


async def _writes(client, host, limiter, cov, fp) -> list[dict]:
    out = []
    target = f"https://{host}/surfacescanner-method-check"
    for method in _WRITE_METHODS:
        await limiter.acquire("default")
        try:
            r = await client.request(method, target, timeout=_TIMEOUT)
            cov.record(True)
        except Exception:
            cov.record(False)
            continue
        if r.status_code not in _ACCEPTED:
            continue
        if fp.matches(r.status_code, len(r.content), r.content):
            cov.drop()               # the host answers anything with its index page
            continue
        cov.keep()
        out.append({
            "type":  "write_method_accepted",
            "value": f"{method} {target}",
            "data": {
                "host": host, "method": method, "status": r.status_code,
                "severity": "high" if method in ("PUT", "PATCH") else "medium",
                "note": f"{method} returned {r.status_code} on a path that does not exist. "
                        "No body was sent, so nothing was written. Confirm by hand before acting.",
            },
        })
    return out


async def _options(client, host, limiter, cov) -> dict | None:
    await limiter.acquire("default")
    try:
        r = await client.request("OPTIONS", f"https://{host}/", timeout=_TIMEOUT)
        cov.record(True)
    except Exception:
        cov.record(False)
        return None
    allow = r.headers.get("allow") or r.headers.get("access-control-allow-methods")
    if not allow:
        return None
    risky = [m for m in ("PUT", "DELETE", "PATCH", "TRACE", "CONNECT")
             if m in allow.upper()]
    if not risky:
        return None
    return {
        "type":  "methods_advertised",
        "value": f"https://{host}/",
        "data": {
            "host": host, "allow": allow, "risky": risky, "severity": "low",
            "note": "The host advertises methods beyond read. Advertisement is not "
                    "acceptance, and the write checks in this module test that separately.",
        },
    }


async def _host(client, host, limiter, cov) -> list[dict]:
    fp = await fingerprint_catchall(client, host)
    out: list[dict] = []
    t = await _trace(client, host, limiter, cov)
    if t:
        out.append(t)
    o = await _options(client, host, limiter, cov)
    if o:
        out.append(o)
    out.extend(await _writes(client, host, limiter, cov, fp))
    return out


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


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0 = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    cov = Coverage()
    findings: list[dict] = []

    hosts = await _get_hosts(scope, db)
    sem = asyncio.Semaphore(_CONCURRENCY)

    async with httpx.AsyncClient(
        verify=False, follow_redirects=False,
        headers={"User-Agent": "Mozilla/5.0 (compatible; SurfaceScanner/1.0)"},
    ) as client:

        async def one(h: str) -> list[dict]:
            async with sem:
                try:
                    return await _host(client, h, limiter, cov)
                except Exception as exc:
                    log.debug("methods.host_failed", host=h, error=str(exc))
                    return []

        for r in await asyncio.gather(*(one(h) for h in hosts)):
            findings.extend(r)

    metadata = {
        "hosts_checked": len(hosts),
        "trace_enabled": sum(1 for f in findings if f["type"] == "trace_method_enabled"),
        "write_methods_accepted": sum(1 for f in findings if f["type"] == "write_method_accepted"),
        **cov.summary(),
    }
    log.info("methods.done", hosts=len(hosts), findings=len(findings),
             dropped_by_control=cov.controls_failed)

    return {
        "module":   "layer2_5/http_methods",
        "status":   "success",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }
