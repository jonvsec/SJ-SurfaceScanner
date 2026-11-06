"""
layer2_5/js_dependencies.py — JavaScript library versions and their advisories.

Retrieves every JavaScript file reachable from the confirmed hosts and checks
the libraries it contains against the published advisory database, using
retire.js where it is installed.

The point of this module is not the scan. It is the gate that follows it.

This scan can flag many files across many hosts, and the raw advisory list for
the framework versions involved runs to hundreds of entries including
authorisation bypass and server side request forgery. But many of those hosts
are often static exports served straight from object storage with no framework
process behind them, so every server side advisory is unreachable no matter how
old the bundle is. Reporting the raw result overstates the exposure by an order
of magnitude.

So each host is classified by how it is served before any advisory is attached
to it, and advisories that describe server behaviour are recorded as not
applicable where no server runs. A finding still records the outdated version,
because a static export that later moves behind a runtime inherits the whole
list at that moment, but it says plainly which of the two situations it is.

Mode: semi (retrieves files from the target).
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx
import structlog

from core.config import Config
from core.controls import (SERVER, STATIC, UNKNOWN, VENDOR, Coverage,
                           advisories_reachable, runtime_model)
from core.network import run_command
from core.ratelimiter import RateLimiter
from core.scope_guard import filter_in_scope
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":        "js_dependencies",
    "title":       "JavaScript Dependency Analysis",
    "description": "Library versions checked against published advisories, gated by hosting model",
    "layer":       2.5,
    "mode":        ["semi", "active"],
    "requires":    [],
    "optional":    True,
}

_TIMEOUT = 20
_MAX_FILE = 4 * 1024 * 1024
_CONCURRENCY = 8
_JS_RE = re.compile(r"""["'\s(]((?:https?:)?//[^"'\s)]+?\.js|/[^"'\s)]+?\.js)(?:\?[^"'\s)]*)?""")

# Advisory wording that describes something happening on the server. Where the
# host serves static files these cannot be reached.
_SERVER_SIDE = ("middleware", "server component", "server action", "server-side",
                "ssrf", "request forgery", "cache poisoning", "deserial",
                "authorization bypass", "authorisation bypass", "denial of service")


async def _discover_js(client: httpx.AsyncClient, host: str, limiter: RateLimiter) -> set[str]:
    """Find the script files a host references from its own front page."""
    await limiter.acquire("default")
    urls: set[str] = set()
    try:
        r = await client.get(f"https://{host}/", timeout=_TIMEOUT)
    except Exception:
        return urls
    for m in _JS_RE.finditer(r.text):
        u = m.group(1)
        if u.startswith("//"):
            u = "https:" + u
        elif u.startswith("/"):
            u = f"https://{host}{u}"
        urls.add(u)
    return urls


async def _host_model(client: httpx.AsyncClient, host: str) -> tuple[str, dict]:
    """Classify how the host is served, which decides advisory reachability."""
    try:
        r = await client.get(f"https://{host}/", timeout=_TIMEOUT)
    except Exception:
        return UNKNOWN, {}
    headers = dict(r.headers)
    return runtime_model(headers), {
        "server": headers.get("server"),
        "signals": {k: v for k, v in headers.items()
                    if k.lower().startswith(("x-goog", "x-nextjs", "x-hs", "x-vercel", "x-amz"))},
    }


async def _retrieve(client, url, dest: Path, limiter, cov) -> Path | None:
    await limiter.acquire("default")
    try:
        r = await client.get(url, timeout=_TIMEOUT)
        cov.record(True)
    except Exception:
        cov.record(False)
        return None
    if r.status_code != 200 or not r.content or len(r.content) > _MAX_FILE:
        return None
    p = dest / (re.sub(r"[^A-Za-z0-9]", "_", url)[-90:] + ".js")
    p.write_bytes(r.content)
    return p


def _parse_retire(report: Path) -> list[dict]:
    try:
        doc = json.loads(report.read_text())
    except Exception:
        return []
    out = []
    for entry in doc.get("data", []):
        for res in entry.get("results", []):
            vulns = res.get("vulnerabilities", [])
            if not vulns:
                continue
            out.append({
                "file":      entry.get("file"),
                "component": res.get("component"),
                "version":   res.get("version"),
                "advisories": [
                    {
                        "severity": v.get("severity"),
                        "below":    v.get("below"),
                        "summary":  (v.get("identifiers") or {}).get("summary", "")[:300],
                        "id":       (v.get("identifiers") or {}).get("githubID")
                                    or (v.get("identifiers") or {}).get("CVE"),
                        "info":     (v.get("info") or [])[:3],
                    }
                    for v in vulns
                ],
            })
    return out


def _split_by_reachability(advisories: list[dict], model: str) -> tuple[list, list]:
    """Separate advisories that can apply here from those that cannot."""
    if advisories_reachable(model):
        return advisories, []
    applies, not_applicable = [], []
    for a in advisories:
        text = f"{a.get('summary','')}".lower()
        (not_applicable if any(s in text for s in _SERVER_SIDE) else applies).append(a)
    return applies, not_applicable


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

    if not shutil.which("retire"):
        log.warning("jsdeps.retire_missing")
        return {
            "module": "layer2_5/js_dependencies", "status": "skipped",
            "findings": [], "metadata": {"reason": "retire.js is not installed"},
            "duration": time.monotonic() - t0, "error": None,
        }

    hosts = await _get_hosts(scope, db)
    models: dict[str, tuple[str, dict]] = {}
    file_owner: dict[str, str] = {}

    with tempfile.TemporaryDirectory(prefix="ss_jsdeps_") as tmp:
        dest = Path(tmp)
        sem = asyncio.Semaphore(_CONCURRENCY)

        async with httpx.AsyncClient(
            verify=False, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; SurfaceScanner/1.0)"},
        ) as client:

            async def prepare(host: str) -> None:
                async with sem:
                    models[host] = await _host_model(client, host)
                    for url in await _discover_js(client, host, limiter):
                        p = await _retrieve(client, url, dest, limiter, cov)
                        if p:
                            file_owner[p.name] = host

            await asyncio.gather(*(prepare(h) for h in hosts), return_exceptions=True)

        if not file_owner:
            return {
                "module": "layer2_5/js_dependencies", "status": "success",
                "findings": [], "metadata": {"hosts_checked": len(hosts),
                                             "files_retrieved": 0, **cov.summary()},
                "duration": time.monotonic() - t0, "error": None,
            }

        report = dest / "retire.json"
        await run_command(
            ["retire", "--jspath", str(dest), "--outputformat", "json",
             "--outputpath", str(report), "--exitwith", "0"],
            timeout=600,
        )
        results = _parse_retire(report)

        for res in results:
            host = file_owner.get(Path(res["file"]).name, "unknown")
            model, signals = models.get(host, (UNKNOWN, {}))
            applies, blocked = _split_by_reachability(res["advisories"], model)
            worst = "high" if any(a["severity"] in ("critical", "high") for a in applies) else \
                    "medium" if applies else "low"
            findings.append({
                "type":  "vulnerable_js_dependency",
                "value": f"{host} {res['component']} {res['version']}",
                "data": {
                    "host":       host,
                    "component":  res["component"],
                    "version":    res["version"],
                    "hosting_model": model,
                    "hosting_signals": signals,
                    "advisories_reachable": advisories_reachable(model),
                    "applicable_advisories": applies,
                    "not_applicable_advisories": blocked,
                    "severity": worst if advisories_reachable(model) else "low",
                    "note": (
                        "Server side advisories apply, a runtime is present."
                        if model == SERVER else
                        "Served as static files with no runtime, so server side advisories "
                        "cannot be reached. The version is still outdated and would inherit "
                        "them if this application moves behind a server."
                        if model == STATIC else
                        "Hosted by a third party platform, so the libraries are the vendor's "
                        "to patch rather than the customer's."
                        if model == VENDOR else
                        "Hosting model not established, advisories treated as reachable."
                    ),
                },
            })

    by_model: dict[str, int] = {}
    for f in findings:
        by_model[f["data"]["hosting_model"]] = by_model.get(f["data"]["hosting_model"], 0) + 1

    metadata = {
        "hosts_checked":   len(hosts),
        "files_retrieved": len(file_owner),
        "files_vulnerable": len(findings),
        "by_hosting_model": by_model,
        "reachable_findings": sum(1 for f in findings if f["data"]["advisories_reachable"]),
        **cov.summary(),
    }
    log.info("jsdeps.done", **{k: v for k, v in metadata.items() if isinstance(v, int)})

    return {
        "module":   "layer2_5/js_dependencies",
        "status":   "success",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }
