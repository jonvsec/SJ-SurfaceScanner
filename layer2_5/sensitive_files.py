"""
layer2_5/sensitive_files.py — exposed source control, configuration and secrets.

Requests a small set of paths that should never be served from a document root,
covering source control directories, environment and configuration files, cloud
credential files, editor artefacts and server status pages.

The reason this module exists as a separate thing rather than as another
wordlist in content discovery is the negative control. A single page
application returns its index page for any path, so this sweep can produce many
apparent hits that are all the same page. Reported without a control they read
as exposed cloud credentials on an administrative host, which would be a serious
finding and completely wrong.

So each host is fingerprinted first with a path that cannot exist, and any
result matching that fingerprint is discarded and counted rather than reported.

Mode: semi (sends requests to the target).
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
import structlog

from core.config import Config
from core.controls import CatchAll, Coverage, fingerprint_catchall
from core.ratelimiter import RateLimiter
from core.scope_guard import filter_in_scope
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":        "sensitive_files",
    "title":       "Sensitive File Exposure",
    "description": "Source control, configuration and credential files served from the web root",
    "layer":       2.5,
    "mode":        ["semi", "active"],
    "requires":    [],
    "optional":    False,
}

_TIMEOUT = 12
_CONCURRENCY = 6

# Each entry carries what a genuine hit means, because "200 on /.git/config"
# and "200 on /.well-known/security.txt" are not the same kind of result.
_PATHS: list[tuple[str, str, str]] = [
    (".git/HEAD",           "high",   "Source control directory served, repository may be retrievable"),
    (".git/config",         "high",   "Source control configuration served, may name internal remotes"),
    (".svn/entries",        "high",   "Source control metadata served"),
    (".env",                "high",   "Environment file served, commonly holds credentials"),
    (".aws/credentials",    "high",   "Cloud credential file served"),
    ("config.json",         "medium", "Configuration file served from the document root"),
    ("docker-compose.yml",  "medium", "Deployment definition served, names services and often secrets"),
    ("web.config",          "medium", "Application configuration served"),
    ("phpinfo.php",         "medium", "Interpreter configuration page served"),
    ("server-status",       "medium", "Server status page served, discloses request activity"),
    (".DS_Store",           "low",    "Editor artefact served, discloses directory contents"),
    ("backup.zip",          "high",   "Backup archive served from the document root"),
    (".well-known/security.txt", "info", "Security contact published, expected rather than a fault"),
]

# Content that proves the response is the real thing rather than a page that
# merely returned a success status.
_MARKERS = {
    ".git/HEAD":        ("ref:", "refs/heads"),
    ".git/config":      ("[core]", "repositoryformatversion"),
    ".svn/entries":     ("dir", "svn"),
    ".env":             ("=",),
    ".aws/credentials": ("aws_access_key_id", "[default]"),
    "phpinfo.php":      ("phpinfo()", "PHP Version"),
    "server-status":    ("Apache Server Status", "Server uptime"),
    ".DS_Store":        ("Bud1",),
}


async def _probe(
    client:  httpx.AsyncClient,
    host:    str,
    path:    str,
    severity: str,
    note:    str,
    fp:      CatchAll,
    limiter: RateLimiter,
    cov:     Coverage,
) -> dict | None:
    await limiter.acquire("default")
    url = f"https://{host}/{path}"
    try:
        r = await client.get(url, timeout=_TIMEOUT)
        cov.record(True)
    except Exception:
        cov.record(False)
        return None

    if r.status_code != 200 or not r.content:
        return None

    # The control: does this look exactly like the host's not-found response?
    if fp.matches(r.status_code, len(r.content), r.content):
        cov.drop()
        log.debug("sensitive.catchall", host=host, path=path)
        return None

    body = r.text[:4096]
    markers = _MARKERS.get(path)
    confirmed = True
    if markers:
        confirmed = any(m.lower() in body.lower() for m in markers)
        if not confirmed:
            # right status, wrong content. Report it lower rather than dropping
            # it, since an unexpected body on this path is still worth a look.
            severity = "low"
            note = f"{note}, but the response does not carry the expected content"

    cov.keep()
    return {
        "type":  "sensitive_file",
        "value": url,
        "data": {
            "host":        host,
            "path":        path,
            "status":      r.status_code,
            "size":        len(r.content),
            "severity":    severity,
            "note":        note,
            "content_verified": confirmed,
            "control": {
                "catchall_status": fp.status,
                "catchall_length": fp.length,
                "host_is_catchall": fp.is_catchall,
            },
            "preview": body[:200],
        },
    }


async def _host(client, host, limiter, cov) -> list[dict]:
    fp = await fingerprint_catchall(client, host)
    if fp.is_catchall:
        log.info("sensitive.host_answers_everything", host=host,
                 status=fp.status, length=fp.length)

    out = []
    for path, severity, note in _PATHS:
        r = await _probe(client, host, path, severity, note, fp, limiter, cov)
        if r:
            out.append(r)
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

    async def one(h: str) -> list[dict]:
        async with sem:
            try:
                return await _host(client, h, limiter, cov)
            except Exception as exc:
                log.debug("sensitive.host_failed", host=h, error=str(exc))
                return []

    async with httpx.AsyncClient(
        verify=False, follow_redirects=False,
        headers={"User-Agent": "Mozilla/5.0 (compatible; SurfaceScanner/1.0)"},
    ) as client:
        results = await asyncio.gather(*(one(h) for h in hosts))

    for r in results:
        findings.extend(r)

    metadata = {
        "hosts_checked": len(hosts),
        "paths_per_host": len(_PATHS),
        **cov.summary(),
    }
    log.info("sensitive.done", hosts=len(hosts), found=len(findings),
             dropped_by_control=cov.controls_failed)

    return {
        "module":   "layer2_5/sensitive_files",
        "status":   "success",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }
