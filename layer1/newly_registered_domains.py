"""
layer1/newly_registered_domains.py — lookalikes the permutation set misses.

dnstwist (layer1/brand_protection) only checks names it can generate by mutating
the client's own domains. A phishing operator often registers something the
permutation engine never produces: a brand term inside a longer hostname
(acme-support-login.com), an unusual TLD, or a convincing new string that is not
a character-level mutation at all. This module catches those by watching two
live sources for freshly appearing names and keeping the ones that resemble a
client brand.

  1. Certificate Transparency (crt.sh). Every public TLS certificate is logged.
     Querying crt.sh for the brand label surfaces hosts the moment they get a
     certificate, which is usually before the phishing page goes live.
  2. Newly registered domain feed (WHOISDS daily list). The day a lookalike is
     registered it appears here, long before it would show up in a permutation
     run.

Both are cross-matched against the client brand labels with the shared fuzzy
matcher, resolved, lightly RDAP-enriched, scored and SEV-mapped the same way as
dnstwist findings, so everything downstream treats one lookalike the same
regardless of which producer found it. Optional extra generators (urlcrazy,
ail-typo-squatting) widen the candidate set when those binaries are present.

Pure scripting, no AI. crt.sh and the NRD feed are public data, nothing client
side leaves the machine.
"""
from __future__ import annotations

import asyncio
import io
import json
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import structlog

from core.config import Config
from core.network import run_command
from layer1 import _lookalike_common as lc
# One implementation of RDAP, DNS and ageing, reused from the dnstwist producer.
from layer1.brand_protection import (
    _age_days, _issue, _owned_domains, _rdap_bulk,
)
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "newly_registered_domains",
    "title":    "Newly Registered / CT Lookalike Discovery",
    "description": "Brand-resembling domains from certificate transparency and NRD feeds",
    "layer":    1,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": True,
}

_CRTSH   = "https://crt.sh/"
_TIMEOUT = 30


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0 = time.monotonic()
    findings: list[dict] = []
    bp = config.brand_protection
    metadata: dict = {"sources": [], "candidates": 0}

    labels = _brand_labels(scope)
    metadata["brand_labels"] = sorted(labels)
    owned = _owned_domains(scope)

    # Gather candidate domains from every enabled source.
    candidates: dict[str, str] = {}   # domain -> source
    if bp.crtsh_enabled:
        hits = await _crtsh(labels, bp)
        metadata["sources"].append("crt.sh")
        for d in hits:
            candidates.setdefault(d, "crt.sh")
    if bp.nrd_feed_url:
        hits = await _nrd_feed(labels, bp, config)
        metadata["sources"].append("nrd-feed")
        for d in hits:
            candidates.setdefault(d, "nrd-feed")
    for gen in bp.extra_generators:
        hits = await _extra_generator(gen, scope, config)
        if hits:
            metadata["sources"].append(gen)
            for d in hits:
                candidates.setdefault(d, gen)

    # Drop names the client owns and anything the dnstwist producer already
    # recorded this run, so a domain is reported once.
    already = await _already_reported(scope, db)
    candidates = {
        d: s for d, s in candidates.items()
        if d not in owned and d not in already
    }
    metadata["candidates"] = len(candidates)
    log.info("nrd.candidates", count=len(candidates), sources=metadata["sources"])

    if not candidates:
        return _result(findings, metadata, t0, "partial")

    # Resolve + RDAP so discovered names are scored like dnstwist ones.
    legit_ns = await _legit_nameservers(scope, config)
    dns = await _resolve_bulk(sorted(candidates), config)
    rdap = await _rdap_bulk(sorted(candidates), config)
    now = datetime.now(timezone.utc)

    for name in sorted(candidates):
        d  = dns.get(name, {})
        rd = rdap.get(name, {})
        mx = d.get("mx") or []
        a  = d.get("a") or []
        ns = d.get("ns") or []
        created = rd.get("registration")
        age_days = _age_days(created, now)

        sev, reasons = lc.score(
            mx=mx, a=a, ns=ns, legit_ns=legit_ns,
            age_days=age_days, registered=rd.get("registered"),
            fuzzer="ct/nrd", distinctive_brand=True,
            weights=bp.weights, recent_days=bp.recent_days,
        )
        sev = lc.apply_staleness(
            sev, age_days=age_days, mail_capable=bool(mx), stale_days=bp.stale_days,
        )
        sev_platform = lc.map_sev_platform(
            sev, mail_capable=bool(mx), serves_login=False,
            favicon_match=False, visual_match=False, sev_map=bp.sev_map,
        )
        findings.append({
            "type":  "lookalike_domain",
            "value": name,
            "data": {
                "origin_domain":   None,
                "fuzzer":          candidates[name],
                "dns_a":           a,
                "dns_mx":          mx,
                "dns_ns":          ns,
                "registered":      rd.get("registered"),
                "registrar":       rd.get("registrar"),
                "created":         created,
                "expires":         rd.get("expiration"),
                "age_days":        age_days,
                "mail_capable":    bool(mx),
                "serves_login":    False,
                "favicon_match":   False,
                "visual_match":    False,
                "new_since_last_run": True,
                "severity":        sev,
                "sev_platform":    sev_platform,
                "issue":           _issue(name, sev, bool(mx), False, False),
                "reasons":         reasons,
                "source":          candidates[name],
            },
        })

    campaigns = lc.cluster_campaigns(findings)
    metadata["campaigns"] = campaigns
    by_platform: dict[str, int] = {}
    for f in findings:
        p = f["data"]["sev_platform"]
        by_platform[p] = by_platform.get(p, 0) + 1
    metadata["by_sev_platform"] = by_platform

    log.info("nrd.complete", findings=len(findings), by_sev_platform=by_platform)
    return _result(findings, metadata, t0, "success" if findings else "partial")


def _brand_labels(scope: Scope) -> set[str]:
    """Distinctive labels to match against: domain second-level labels + aliases."""
    labels: set[str] = set()
    for d in scope.all_domains:
        lab = lc.brand_label(d)
        if len(lab) >= 4:
            labels.add(lab)
    for alias in scope.target.aliases or []:
        a = alias.strip().lower()
        if " " in a:
            continue
        lab = lc.brand_label(a) if "." in a else a
        if len(lab) >= 4:
            labels.add(lab)
    return labels


async def _crtsh(labels: set[str], bp: Any) -> set[str]:
    """Domains from certificate transparency that resemble a brand label."""
    found: set[str] = set()
    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
        for label in sorted(labels):
            try:
                r = await client.get(
                    _CRTSH, params={"q": f"%{label}%", "output": "json"}
                )
                if r.status_code != 200 or not r.text.strip():
                    continue
                rows = r.json()
            except Exception as exc:
                log.debug("nrd.crtsh_failed", label=label, error=str(exc))
                continue
            for row in rows if isinstance(rows, list) else []:
                for nv in str(row.get("name_value", "")).splitlines():
                    name = nv.strip().lstrip("*.").lower()
                    if not name or "@" in name:
                        continue
                    if lc.fuzzy_brand_match(name, labels, bp.fuzzy_max_distance):
                        found.add(name)
    return found


async def _nrd_feed(labels: set[str], bp: Any, config: Config) -> set[str]:
    """Brand-resembling names in the day's newly-registered-domain feed."""
    found: set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
            r = await client.get(bp.nrd_feed_url)
            if r.status_code != 200 or not r.content:
                return found
            data = r.content
    except Exception as exc:
        log.debug("nrd.feed_failed", error=str(exc))
        return found

    lines: list[str] = []
    try:
        if data[:2] == b"PK":   # zip
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for member in z.namelist():
                    lines += z.read(member).decode(errors="replace").splitlines()
        else:
            lines = data.decode(errors="replace").splitlines()
    except Exception as exc:
        log.debug("nrd.feed_unpack_failed", error=str(exc))
        return found

    for line in lines:
        name = line.strip().lower()
        if not name or name.startswith("#") or "." not in name:
            continue
        if lc.fuzzy_brand_match(name, labels, bp.fuzzy_max_distance):
            found.add(name)
    return found


async def _extra_generator(gen: str, scope: Scope, config: Config) -> set[str]:
    """
    Optional extra permutation generators. Tool-gated: if the binary is absent
    the stage is skipped, never fatal.

    urlcrazy and ail-typo-squatting both print candidate domains; we take the
    domain column and leave resolution/scoring to the shared path.
    """
    tool = gen.split()[0]
    check = await run_command(["which", tool], recon_mode="passive", config=config, timeout=10)
    if not (check.ok and (check.stdout or "").strip()):
        log.info("nrd.generator_missing", tool=tool)
        return set()

    out: set[str] = set()
    for domain in scope.all_domains:
        if tool == "urlcrazy":
            cmd = ["urlcrazy", "-f", "csv", domain]
        elif tool in ("ail-typo-squatting", "typo"):
            cmd = [tool, "-d", domain]
        else:
            cmd = [tool, domain]
        try:
            r = await run_command(cmd, recon_mode="passive", config=config, timeout=300)
        except Exception as exc:
            log.debug("nrd.generator_failed", tool=tool, error=str(exc))
            continue
        for line in (r.stdout or "").splitlines():
            tok = line.strip().strip('"').split(",")[0].strip().lower()
            if tok and "." in tok and " " not in tok:
                out.add(tok)
    return out


async def _resolve_bulk(domains: list[str], config: Config) -> dict[str, dict]:
    """A/MX/NS for each candidate via dig, bounded concurrency, passive."""
    sem = asyncio.Semaphore(16)
    out: dict[str, dict] = {}

    async def one(d: str) -> None:
        async with sem:
            rec: dict[str, list[str]] = {}
            for rtype, key in (("A", "a"), ("MX", "mx"), ("NS", "ns")):
                r = await run_command(
                    ["dig", "+short", rtype, d],
                    recon_mode="passive", config=config, timeout=15,
                )
                rec[key] = [
                    ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()
                ]
            out[d] = rec

    await asyncio.gather(*(one(d) for d in domains), return_exceptions=True)
    return out


async def _legit_nameservers(scope: Scope, config: Config) -> set[str]:
    out: set[str] = set()
    for d in scope.all_domains:
        r = await run_command(
            ["dig", "+short", "NS", d], recon_mode="passive", config=config, timeout=20
        )
        for line in (r.stdout or "").splitlines():
            if line.strip():
                out.add(lc.ns_root(line.strip()))
    return {x for x in out if x}


async def _already_reported(scope: Scope, db: Any) -> set[str]:
    if db is None:
        return set()
    try:
        run_id = await db.get_last_run_id(scope.target.name) or ""
        if not run_id:
            return set()
        rows = await db.get_findings(run_id, "lookalike_domain")
        return {(r.get("value") or "").lower() for r in rows if r.get("value")}
    except Exception as exc:
        log.debug("nrd.history_failed", error=str(exc))
        return set()


def _result(findings: list, metadata: dict, t0: float, status: str) -> dict:
    return {
        "module":   "layer1/newly_registered_domains",
        "status":   status,
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }
