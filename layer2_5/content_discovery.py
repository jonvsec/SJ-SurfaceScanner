"""
layer2_5/content_discovery.py — ffuf-driven content and virtual-host discovery.

Two jobs DNS enumeration structurally cannot do:

  1. Path discovery — brute-forces paths on discovered hosts. Finds admin
     panels, backups, .git directories and API docs that are linked from
     nowhere, so a crawler will never reach them.

  2. Virtual-host discovery — fuzzes the Host header against an IP that
     serves several known hostnames. A vhost with no public DNS record is
     invisible to dnsx because there is nothing to resolve; it answers only
     when asked for by name.

Both generate real HTTP traffic against client infrastructure, so this module
is active-mode only and is rate limited by default. Concurrency is applied
*across* targets while each individual target stays under its own request
ceiling — parallel breadth, polite depth.

CLI tool required: ffuf.
"""
from __future__ import annotations

import asyncio
import json
import tempfile
import time
from pathlib import Path
from typing import Any

import structlog

from core.config import Config
from core.network import run_command
from core.scope_guard import in_scope, filter_in_scope
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "content_discovery",
    "title":    "Content & VHost Discovery",
    "description": "ffuf path and virtual-host fuzzing on discovered hosts",
    "layer":    2.5,
    "mode":     ["active"],
    "requires": [],
    "optional": True,
    # Needs resolved hosts and their addresses before it can pick targets.
    "depends_on": ["dns_resolve", "http_headers"],
}

# --- Politeness ------------------------------------------------------------
# Requests/second per target host. ffuf enforces this internally via -rate.
_RATE_PER_HOST = 10
# Concurrent ffuf worker threads within a single target.
_THREADS       = 5
# How many targets are fuzzed at once. Total RPS is bounded by
# _RATE_PER_HOST * _PARALLEL_TARGETS, so both knobs stay meaningful.
_PARALLEL_TARGETS = 4
# Per-target wall-clock ceiling.
_TIMEOUT       = 900

# Cap work so a large estate cannot produce an unbounded run.
_MAX_PATH_TARGETS  = 25
_MAX_VHOST_TARGETS = 10
_MAX_WORDS         = 4000

# Status codes worth reporting. 404 is excluded; everything else is triaged
# against a negative control before it becomes a finding.
_MATCH_CODES = "200,201,203,204,301,302,307,401,403,405,500"

_BUILTIN_PATHS = """admin administrator login wp-admin phpmyadmin pma dbadmin
.git .git/config .env .env.local .env.production config config.json config.yaml
backup backups dump dumps db.sql database.sql backup.zip backup.tar.gz
api api/v1 api/v2 swagger swagger-ui openapi.json api-docs docs redoc graphql
actuator actuator/health actuator/env metrics debug status health healthz
server-status server-info .well-known/security.txt robots.txt sitemap.xml
console manage manager jenkins grafana kibana prometheus vault consul
test staging dev internal private secret tmp temp old bak
.svn .hg .DS_Store web.config appsettings.json credentials.json
storage uploads files download logs log""".split()


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0 = time.monotonic()
    findings: list[dict] = []
    metadata: dict = {
        "rate_per_host":    _RATE_PER_HOST,
        "parallel_targets": _PARALLEL_TARGETS,
    }

    if not await _have_ffuf(config):
        log.warning("content_discovery.ffuf_missing")
        return _result(findings, {"note": "ffuf not installed"}, t0, "partial")

    hosts, ip_map = await _load_targets(scope, db)
    if not hosts:
        return _result(findings, {"note": "no validated hosts available"}, t0, "partial")

    words     = _load_words(config)
    path_tgts = hosts[:_MAX_PATH_TARGETS]

    metadata["words"]        = len(words)
    metadata["path_targets"] = len(path_tgts)

    log.info(
        "content_discovery.starting",
        path_targets=len(path_tgts),
        words=len(words),
        rate_per_host=_RATE_PER_HOST,
        parallel=_PARALLEL_TARGETS,
    )

    # --- Path discovery, parallel across hosts, rate limited per host ------
    sem = asyncio.Semaphore(_PARALLEL_TARGETS)

    async def _one_path_target(host: str) -> list[dict]:
        async with sem:
            return await _fuzz_paths(host, words, config)

    results = await asyncio.gather(
        *(_one_path_target(h) for h in path_tgts), return_exceptions=True
    )
    for host, res in zip(path_tgts, results):
        if isinstance(res, list):
            findings.extend(res)
        else:
            log.warning("content_discovery.path_failed", host=host, error=str(res))

    # --- VHost discovery on IPs serving more than one known hostname -------
    shared = {ip: hs for ip, hs in ip_map.items() if len(hs) > 1}
    vhost_tgts = sorted(shared.items(), key=lambda kv: -len(kv[1]))[:_MAX_VHOST_TARGETS]
    metadata["vhost_targets"] = len(vhost_tgts)

    async def _one_vhost_target(ip: str, known: set[str]) -> list[dict]:
        async with sem:
            return await _fuzz_vhosts(ip, known, words, scope, config)

    vresults = await asyncio.gather(
        *(_one_vhost_target(ip, hs) for ip, hs in vhost_tgts), return_exceptions=True
    )
    for (ip, _), res in zip(vhost_tgts, vresults):
        if isinstance(res, list):
            findings.extend(res)
        else:
            log.warning("content_discovery.vhost_failed", ip=ip, error=str(res))

    log.info("content_discovery.complete", findings=len(findings))
    return _result(findings, metadata, t0, "success" if findings else "partial")


async def _fuzz_paths(host: str, words: list[str], config: Config) -> list[dict]:
    """Path fuzz a single host, filtering against its own catch-all response."""
    wl  = _write_words(words)
    out_file = Path(tempfile.mktemp(suffix=".json"))
    try:
        cmd = [
            "ffuf",
            "-u", f"https://{host}/FUZZ",
            "-w", str(wl),
            "-mc", _MATCH_CODES,
            "-rate", str(_RATE_PER_HOST),
            "-t", str(_THREADS),
            "-timeout", "10",
            "-ac",                      # auto-calibrate against catch-all
            "-s", "-of", "json", "-o", str(out_file),
            "-noninteractive",
        ]
        await run_command(
            cmd, recon_mode="active", config=config, timeout=_TIMEOUT
        )
        raw = out_file.read_text() if out_file.exists() else ""
    finally:
        wl.unlink(missing_ok=True)
        out_file.unlink(missing_ok=True)

    out: list[dict] = []
    for r in _parse_ffuf(raw):
        out.append({
            "type":  "exposed_path",
            "value": r.get("url") or f"https://{host}/{r.get('input', {}).get('FUZZ', '')}",
            "data": {
                "host":     host,
                "status":   r.get("status"),
                "length":   r.get("length"),
                "words":    r.get("words"),
                "source":   "ffuf_path",
                "severity": _severity(r.get("status"), str(r.get("url", ""))),
            },
        })
    return out


async def _fuzz_vhosts(
    ip:     str,
    known:  set[str],
    words:  list[str],
    scope:  Scope,
    config: Config,
) -> list[dict]:
    """
    Fuzz the Host header against an IP, reporting only names that differ from
    the catch-all AND are not already known from DNS.
    """
    root = sorted(scope.all_domains, key=len)[0] if scope.all_domains else ""
    if not root:
        return []

    wl  = _write_words(words)
    out_file = Path(tempfile.mktemp(suffix=".json"))
    try:
        cmd = [
            "ffuf",
            "-u", f"https://{ip}/",
            "-H", f"Host: FUZZ.{root}",
            "-w", str(wl),
            "-mc", _MATCH_CODES,
            "-rate", str(_RATE_PER_HOST),
            "-t", str(_THREADS),
            "-timeout", "10",
            "-ac",
            "-s", "-of", "json", "-o", str(out_file),
            "-noninteractive",
        ]
        await run_command(
            cmd, recon_mode="active", config=config, timeout=_TIMEOUT
        )
        raw = out_file.read_text() if out_file.exists() else ""
    finally:
        wl.unlink(missing_ok=True)
        out_file.unlink(missing_ok=True)

    out: list[dict] = []
    for r in _parse_ffuf(raw):
        label = (r.get("input") or {}).get("FUZZ", "")
        if not label:
            continue
        vhost = f"{label}.{root}"
        if vhost in known:
            continue          # already known from DNS — not a new discovery
        out.append({
            "type":  "virtual_host",
            "value": vhost,
            "data": {
                "ip":       ip,
                "status":   r.get("status"),
                "length":   r.get("length"),
                "source":   "ffuf_vhost",
                "note":     "responds by Host header; verify it has no DNS record",
                "severity": "medium",
            },
        })
    return out


def _severity(status: Any, url: str) -> str:
    u = url.lower()
    if any(k in u for k in (".git", ".env", "backup", "dump", ".sql", "credentials")):
        return "high"
    if status in (401, 403):
        return "info"      # exists but protected
    if any(k in u for k in ("admin", "phpmyadmin", "actuator", "console", "vault")):
        return "medium"
    return "low"


def _parse_ffuf(stdout: str) -> list[dict]:
    """ffuf -of json writes one JSON document with a `results` array."""
    if not (stdout or "").strip():
        return []
    try:
        return json.loads(stdout).get("results", []) or []
    except json.JSONDecodeError:
        # Some builds emit JSON lines instead
        out = []
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return out


async def _load_targets(scope: Scope, db: Any) -> tuple[list[str], dict[str, set[str]]]:
    """
    Return (hosts, ip -> hostnames).

    Only hosts dns_resolve marked `validated` are used — wildcard artefacts
    would otherwise be fuzzed, wasting the entire budget on hosts that do
    not exist.
    """
    if db is None:
        return [], {}

    hosts: list[str] = []
    ip_map: dict[str, set[str]] = {}
    try:
        run_id = await db.get_last_run_id(scope.target.name) or ""
        if not run_id:
            return [], {}
        for row in await db.get_findings(run_id, "resolved_host"):
            data = row.get("data") or {}
            if data.get("wildcard_resolution"):
                continue
            host = (row.get("value") or "").strip().lower()
            if not host:
                continue
            # Content discovery fuzzes paths. Never against an unauthorised host.
            if not in_scope(host, scope):
                log.warning("content_discovery.out_of_scope_skipped", host=host)
                continue
            hosts.append(host)
            for a in data.get("a") or []:
                ip_map.setdefault(a, set()).add(host)
    except Exception as exc:
        log.debug("content_discovery.target_query_failed", error=str(exc))
        return [], {}

    return sorted(set(hosts)), ip_map


def _load_words(config: Config) -> list[str]:
    wl_dir = config.paths.get("wordlists", Path("/nonexistent"))
    for p in (
        wl_dir / "content.txt",
        wl_dir / "SecLists/Discovery/Web-Content/raft-medium-directories.txt",
        wl_dir / "SecLists/Discovery/Web-Content/common.txt",
        Path.home() / "SecLists/Discovery/Web-Content/raft-medium-directories.txt",
        Path("/usr/share/seclists/Discovery/Web-Content/common.txt"),
    ):
        try:
            if p.is_file():
                words = [
                    l.strip() for l in p.read_text(errors="ignore").splitlines()
                    if l.strip() and not l.startswith("#")
                ]
                if words:
                    return words[:_MAX_WORDS]
        except OSError:
            continue
    return _BUILTIN_PATHS


def _write_words(words: list[str]) -> Path:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(words))
        return Path(f.name)


async def _have_ffuf(config: Config) -> bool:
    r = await run_command(["which", "ffuf"], recon_mode="passive", config=config, timeout=10)
    return r.ok and bool((r.stdout or "").strip())


def _result(findings: list, metadata: dict, t0: float, status: str) -> dict:
    return {
        "module":   "layer2_5/content_discovery",
        "status":   status,
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }
