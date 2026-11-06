"""
layer1/brand_protection.py — typosquat and phishing-domain monitoring.

Generates lookalike variants of the target's domains (character swaps,
omissions, homoglyphs, TLD swaps, hyphenation, pluralisation) with dnstwist,
then establishes which are actually registered.

This is the one part of the pipeline that looks at domains the target does
*not* own. Everything else maps assets belonging to the client; here the
finding is that somebody else holds a name close enough to theirs to phish
their customers or staff.

Two-stage status check:

  1. DNS  — fast, but only proves a domain resolves. A registered domain
            parked with no nameservers looks unregistered.
  2. RDAP — authoritative. Gives registration date and registrar, which is
            what separates "the client defensively registered this" from
            "a stranger bought this three weeks ago".

Risk is driven mainly by MX. A lookalike with no mail records is dormant; the
moment MX appears, someone has made it able to send and receive mail as the
brand, which is the last step before a phishing campaign.

In semi/active mode the module also fingerprints each live lookalike: its
favicon hash (compared to the real brand favicon), whether it serves a login
form, and dnstwist's own perceptual/HTML similarity to the real page. Those
signals drive both the SEV1 to SEV5 mapping for the platform and the
infrastructure-pivot clustering into campaigns. Passive mode stays contactless
(DNS, RDAP, dnstwist registration only).

Scoring, severity mapping, fuzzy matching and enrichment live in
layer1/_lookalike_common.py so the newly-registered-domain producer scores the
same way. No AI anywhere in this module.

CLI tool required: dnstwist. Optional: gowitness (screenshots).
"""
from __future__ import annotations

import asyncio
import json
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import structlog

from core.config import Config
from core.network import run_command
from core.ratelimiter import RateLimiter
from layer1 import _lookalike_common as lc
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "brand_protection",
    "title":    "Brand Protection / Typosquat Monitoring",
    "description": "Registered lookalike domains that could be used to phish the brand",
    "layer":    1,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": True,
}

_RDAP        = "https://rdap.org/domain"
_RDAP_LIMIT  = 8          # concurrent RDAP lookups
_TIMEOUT     = 30
_ENRICH_LIMIT = 8         # concurrent HTTP enrichment fetches
# dnstwist reports phash/ssdeep as a 0-100 similarity to the real page. At or
# above this the lookalike is treated as a visual/HTML clone.
_VISUAL_SIM_THRESHOLD = 70


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0 = time.monotonic()
    findings: list[dict] = []
    metadata: dict = {"domains_checked": [], "permutations": 0}
    bp = config.brand_protection

    if not await _have_dnstwist(config):
        log.warning("brand_protection.dnstwist_missing")
        return _result(findings, {"note": "dnstwist not installed"}, t0, "partial")

    tld_file = _find_tld_file(config)
    metadata["tld_file"] = str(tld_file) if tld_file else None

    legit_ns = await _legit_nameservers(scope, config)
    metadata["legit_nameservers"] = sorted(legit_ns)

    # Domains the organisation demonstrably owns must never be reported as
    # lookalikes of each other (a multi-TLD estate, defensive registrations).
    owned = _owned_domains(scope)
    metadata["owned_excluded"] = sorted(owned)

    # Page/favicon enrichment and dnstwist's --phash/--lsh all make HTTP
    # requests to the lookalike hosts and the real brand page. For the lookalike
    # vertical these run by default (always_enrich), because a lookalike host is
    # suspect by definition. A scope in semi/active mode also turns them on. The
    # only way to a contactless run is always_enrich=false and a passive scope.
    do_enrich = bp.always_enrich or scope.mode in ("semi", "active")

    candidates: dict[str, dict] = {}
    for domain in scope.all_domains:
        rows = await _run_dnstwist(domain, tld_file, config, visual=do_enrich)
        metadata["domains_checked"].append(domain)
        metadata["permutations"] += len(rows)
        for r in rows:
            name = (r.get("domain") or "").strip().lower()
            if not name or name in owned:
                continue
            candidates.setdefault(name, {"origin": domain, **r})

    metadata["registered_candidates"] = len(candidates)
    log.info(
        "brand_protection.candidates",
        registered=len(candidates),
        permutations=metadata["permutations"],
    )

    enriched = await _rdap_bulk(sorted(candidates), config)

    # Page/favicon enrichment runs when do_enrich is set (see above).
    brand_favicons: set[int] = set()
    page_info: dict[str, dict] = {}
    if do_enrich:
        brand_favicons = await _brand_favicon_hashes(scope, bp)
        live = [n for n in sorted(candidates) if candidates[n].get("dns_a")]
        page_info = await _enrich_bulk(live[: bp.max_enrich], bp, config)
    metadata["enriched"] = do_enrich
    metadata["brand_favicon_hashes"] = sorted(brand_favicons)

    known = await _previously_seen(scope, db)
    now   = datetime.now(timezone.utc)

    for name in sorted(candidates):
        c    = candidates[name]
        rdap = enriched.get(name, {})
        pg   = page_info.get(name, {})

        # dnstwist marks a failed lookup with a sentinel like "!ServFail" in the
        # record list. Drop those: a sentinel is not a real A record (it must not
        # count as "resolves" or leak into the signal as an IP) and not a real MX
        # (it must not flip mail_capable and inflate severity to SEV2).
        mx = [v for v in (c.get("dns_mx") or []) if isinstance(v, str) and not v.startswith("!")]
        a  = [v for v in (c.get("dns_a")  or []) if isinstance(v, str) and not v.startswith("!")]
        ns = [v for v in (c.get("dns_ns") or []) if isinstance(v, str) and not v.startswith("!")]

        created  = rdap.get("registration")
        age_days = _age_days(created, now)

        favicon_hash  = pg.get("favicon_hash")
        favicon_match = favicon_hash is not None and favicon_hash in brand_favicons
        serves_login  = bool(pg.get("serves_login"))
        vis_sim, html_sim = _similarity(c)
        visual_match = (
            (vis_sim is not None and vis_sim >= _VISUAL_SIM_THRESHOLD)
            or (html_sim is not None and html_sim >= _VISUAL_SIM_THRESHOLD)
        )

        distinctive = _is_distinctive(c.get("origin", ""), bp)
        sev, reasons = lc.score(
            mx=mx, a=a, ns=ns, legit_ns=legit_ns,
            age_days=age_days, registered=rdap.get("registered"),
            fuzzer=c.get("fuzzer", ""), distinctive_brand=distinctive,
            weights=bp.weights, recent_days=bp.recent_days,
        )
        sev = lc.apply_staleness(
            sev, age_days=age_days, mail_capable=bool(mx),
            serves_login=serves_login, visual_match=visual_match,
            favicon_match=favicon_match, stale_days=bp.stale_days,
        )
        sev_platform = lc.map_sev_platform(
            sev, mail_capable=bool(mx), serves_login=serves_login,
            favicon_match=favicon_match, visual_match=visual_match,
            sev_map=bp.sev_map,
        )

        findings.append({
            "type":  "lookalike_domain",
            "value": name,
            "data": {
                "origin_domain":   c.get("origin"),
                "fuzzer":          c.get("fuzzer"),
                "dns_a":           a,
                "dns_mx":          mx,
                "dns_ns":          ns,
                "registered":      rdap.get("registered"),
                "registrar":       rdap.get("registrar"),
                "created":         created,
                "expires":         rdap.get("expiration"),
                "age_days":        age_days,
                "mail_capable":    bool(mx),
                "serves_login":    serves_login,
                "page_title":      pg.get("page_title"),
                "server":          pg.get("server"),
                "favicon_hash":    favicon_hash,
                "favicon_match":   favicon_match,
                "visual_similarity": vis_sim,
                "html_similarity":   html_sim,
                "visual_match":    visual_match,
                "new_since_last_run": name not in known,
                "severity":        sev,
                "sev_platform":    sev_platform,
                "issue":           _issue(name, sev, bool(mx), serves_login, visual_match),
                "reasons":         reasons,
                "source":          "dnstwist+rdap",
            },
        })

    # Infrastructure pivoting: group confirmed lookalikes into campaigns.
    campaigns = lc.cluster_campaigns(findings)
    metadata["campaigns"] = campaigns

    by_sev: dict[str, int] = {}
    by_platform: dict[str, int] = {}
    for f in findings:
        d = f["data"]
        by_sev[d["severity"]] = by_sev.get(d["severity"], 0) + 1
        by_platform[d["sev_platform"]] = by_platform.get(d["sev_platform"], 0) + 1
    metadata["by_severity"] = by_sev
    metadata["by_sev_platform"] = by_platform
    metadata["mail_capable"] = sum(1 for f in findings if f["data"]["mail_capable"])
    metadata["serves_login"] = sum(1 for f in findings if f["data"]["serves_login"])
    metadata["visual_match"] = sum(1 for f in findings if f["data"]["visual_match"])
    metadata["new_since_last_run"] = sum(
        1 for f in findings if f["data"]["new_since_last_run"]
    )

    log.info(
        "brand_protection.complete",
        findings=len(findings),
        by_severity=by_sev,
        by_sev_platform=by_platform,
        campaigns=len(campaigns),
        mail_capable=metadata["mail_capable"],
        new=metadata["new_since_last_run"],
    )
    return _result(findings, metadata, t0, "success" if findings else "partial")


def _issue(name: str, sev: str, mail: bool, login: bool, visual: bool) -> str:
    bits = []
    if login:
        bits.append("serves a login page")
    if visual:
        bits.append("visually clones the brand")
    if mail:
        bits.append("mail capable")
    tail = (": " + ", ".join(bits)) if bits else ""
    return f"Lookalike domain {name}{tail}"


def _similarity(c: dict) -> tuple[int | None, int | None]:
    """
    dnstwist's own similarity of a lookalike page to the real one.

    --phash reports a perceptual (screenshot) similarity, --lsh an HTML fuzzy
    similarity, both as 0-100. Key names vary across dnstwist versions, so read
    defensively and return (visual, html).
    """
    def num(*keys: str) -> int | None:
        for k in keys:
            v = c.get(k)
            if isinstance(v, (int, float)):
                return int(v)
        return None
    visual = num("phash", "phash_similarity", "phash_score")
    html   = num("ssdeep", "ssdeep_score", "lsh", "tlsh")
    return visual, html


def _is_distinctive(domain: str, bp: Any) -> bool:
    """True when the brand label is specific enough for TLD swaps to be meaningful."""
    label = (domain or "").split(".")[0].strip().lower()
    generic = {g.strip().lower() for g in bp.generic_labels}
    if not label or label in generic:
        return False
    return len(label) >= bp.min_distinctive_len


def _owned_domains(scope: Scope) -> set[str]:
    """Domains to exclude from lookalike reporting: scoped plus any alias domain."""
    owned = {d.strip().lower() for d in scope.all_domains}
    for alias in scope.target.aliases or []:
        a = alias.strip().lower()
        if "." in a and " " not in a:
            owned.add(a)
    return owned


async def _legit_nameservers(scope: Scope, config: Config) -> set[str]:
    out: set[str] = set()
    for d in scope.all_domains:
        r = await run_command(
            ["dig", "+short", "NS", d],
            recon_mode="passive", config=config, timeout=20,
        )
        for line in (r.stdout or "").splitlines():
            if line.strip():
                out.add(lc.ns_root(line.strip()))
    return {x for x in out if x}


async def _run_dnstwist(
    domain: str, tld_file: Path | None, config: Config, *, visual: bool = False
) -> list[dict]:
    """
    Registered permutations of one domain.

    --registered keeps the result set to names that actually resolve. When
    visual is set (semi/active only), --phash and --lsh add dnstwist's own
    perceptual and HTML similarity of each lookalike's page to the real one,
    which we read back for visual_match. Both fetch pages over HTTP, so they
    stay off in passive mode. --phash additionally renders pages and needs a
    headless browser, so it is opt-in via config.
    """
    bp = config.brand_protection
    out_file = Path(tempfile.mktemp(suffix=".json"))
    cmd = [
        "dnstwist",
        "--registered",
        "--mxcheck",
        "--format", "json",
        "--threads", str(bp.dnstwist_threads),
        "--output", str(out_file),
    ]
    if visual and bp.use_phash:
        cmd.append("--phash")
    if visual and bp.use_lsh:
        cmd += ["--lsh", bp.use_lsh]
    if tld_file:
        cmd += ["--tld", str(tld_file)]
    cmd.append(domain)

    try:
        await run_command(
            cmd, recon_mode="passive", config=config, timeout=bp.dnstwist_timeout
        )
        raw = out_file.read_text() if out_file.exists() else ""
    except Exception as exc:
        log.warning("brand_protection.dnstwist_failed", domain=domain, error=str(exc))
        return []
    finally:
        out_file.unlink(missing_ok=True)

    if not raw.strip():
        return []
    try:
        rows = json.loads(raw)
    except json.JSONDecodeError:
        log.warning("brand_protection.dnstwist_unparsable", domain=domain)
        return []

    # Drop dnstwist's echo of the original domain
    return [r for r in rows if r.get("fuzzer") != "*original"]


async def _rdap_bulk(domains: list[str], config: Config) -> dict[str, dict]:
    """RDAP lookups, bounded concurrency, never fatal."""
    sem = asyncio.Semaphore(_RDAP_LIMIT)
    limiter = RateLimiter(config.rate_limits)
    out: dict[str, dict] = {}

    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
        async def one(d: str) -> None:
            async with sem:
                await limiter.acquire("default")
                try:
                    r = await client.get(f"{_RDAP}/{d}")
                    if r.status_code == 404:
                        out[d] = {"registered": False}
                        return
                    if r.status_code != 200:
                        out[d] = {}
                        return
                    out[d] = _parse_rdap(r.json())
                except Exception as exc:
                    log.debug("brand_protection.rdap_failed", domain=d, error=str(exc))
                    out[d] = {}

        await asyncio.gather(*(one(d) for d in domains), return_exceptions=True)

    return out


async def _brand_favicon_hashes(scope: Scope, bp: Any) -> set[int]:
    """Favicon hash of each real brand domain, as the match baseline."""
    if not bp.enrich_favicon:
        return set()
    out: set[int] = set()
    async with httpx.AsyncClient(follow_redirects=True) as client:
        for d in scope.all_domains:
            h = await lc.enrich_favicon(client, d)
            if h is not None:
                out.add(h)
    return out


async def _enrich_bulk(hosts: list[str], bp: Any, config: Config) -> dict[str, dict]:
    """Page fingerprint + favicon hash for live lookalikes, bounded concurrency."""
    if not hosts or not (bp.enrich_http or bp.enrich_favicon):
        return {}
    sem = asyncio.Semaphore(_ENRICH_LIMIT)
    out: dict[str, dict] = {}
    async with httpx.AsyncClient(follow_redirects=True) as client:
        async def one(h: str) -> None:
            async with sem:
                info: dict[str, Any] = {}
                try:
                    if bp.enrich_http:
                        info.update(await lc.enrich_http(client, h))
                    if bp.enrich_favicon:
                        info["favicon_hash"] = await lc.enrich_favicon(client, h)
                except Exception as exc:
                    log.debug("brand_protection.enrich_failed", host=h, error=str(exc))
                out[h] = info
        await asyncio.gather(*(one(h) for h in hosts), return_exceptions=True)
    return out


def _parse_rdap(doc: dict) -> dict:
    events = {
        e.get("eventAction"): (e.get("eventDate") or "")[:10]
        for e in (doc.get("events") or [])
    }
    registrar = None
    for ent in doc.get("entities") or []:
        if "registrar" in (ent.get("roles") or []):
            try:
                for field in ent["vcardArray"][1]:
                    if field[0] == "fn":
                        registrar = field[3]
                        break
            except (KeyError, IndexError, TypeError):
                pass
            break
    return {
        "registered":   True,
        "registrar":    registrar,
        "registration": events.get("registration"),
        "expiration":   events.get("expiration"),
    }


def _age_days(created: str | None, now: datetime) -> int | None:
    if not created:
        return None
    try:
        d = datetime.strptime(created, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return max((now - d).days, 0)
    except ValueError:
        return None


async def _previously_seen(scope: Scope, db: Any) -> set[str]:
    """Lookalikes recorded in the previous run, for the new-since-last-run delta."""
    if db is None:
        return set()
    try:
        run_id = await db.get_last_run_id(scope.target.name) or ""
        if not run_id:
            return set()
        rows = await db.get_findings(run_id, "lookalike_domain")
        return {(r.get("value") or "").lower() for r in rows if r.get("value")}
    except Exception as exc:
        log.debug("brand_protection.history_failed", error=str(exc))
        return set()


def _find_tld_file(config: Config) -> Path | None:
    wl = config.paths.get("wordlists", Path("/nonexistent"))
    for p in (wl / "tlds.txt", Path.home() / "tlds.txt"):
        try:
            if p.is_file():
                return p
        except OSError:
            continue
    return None


async def _have_dnstwist(config: Config) -> bool:
    r = await run_command(
        ["which", "dnstwist"], recon_mode="passive", config=config, timeout=10
    )
    return r.ok and bool((r.stdout or "").strip())


def _result(findings: list, metadata: dict, t0: float, status: str) -> dict:
    return {
        "module":   "layer1/brand_protection",
        "status":   status,
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }
