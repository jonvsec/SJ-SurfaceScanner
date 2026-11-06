"""
layer0/estate_expander.py. Ownership-pivot estate expansion.

Turns one seed domain into more OWNED root domains using shared-operator
signals, the pivot the methodology calls "how one domain becomes the estate".
Two signals are mined from each in-scope seed and then reverse-looked-up:

  1. Analytics and ad-tech IDs. A site embeds a Google Analytics (UA-/G-),
     Google Tag Manager (GTM-), or AdSense (ca-pub-) identifier. The SAME id
     reused on another domain links the two to one operator. SurfaceScanner
     previously only FINGERPRINTED that analytics was present (layer2_5
     tech_stack), it never extracted the id or pivoted on it. This module does.
  2. Favicon hash. The MurmurHash3 that Shodan indexes. A shared favicon hash
     across domains is a weaker but useful operator signal. The hash math is
     reused from layer2_5/favicon_correlation.

Why layer 0 and not layer2_5: this is a DISCOVERY expander. It produces new
registrable roots that later layers (subdomain, surface recon) then work on.
The favicon module in layer2_5 only correlates HOSTS late in the pipeline and
emits IPs, so it never grows the root estate. This closes that gap.

Discipline: only in-scope seed domains are ever fetched. Every root the reverse
lookup returns is emitted as `attribution-only` with the id or hash that tied
it in as the ownership signal. Nothing discovered here is auto-promoted to
active testing, and no traffic is ever sent to a discovered root.

Backends are all optional and tried in order, each guarded by its key:
  PUBLICWWW_API_KEY  reverse source-code search (best analytics-id coverage)
  SHODAN_API_KEY     reverse favicon-hash search (reuses the layer2_5 helper)
  (keyless)          best-effort PublicWWW public results page, bounded
With no key at all the module still extracts and reports every id and hash as a
pivot primitive for manual lookup (the fully passive path).
"""
from __future__ import annotations

import os
import re
import time
from typing import Any

import httpx
import structlog

try:
    import tldextract
    _EXT = tldextract.TLDExtract()
except Exception:  # pragma: no cover
    _EXT = None

from core.config import Config
from core.ratelimiter import RateLimiter
from core.scope_guard import filter_in_scope
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "estate_expander",
    "title":    "Estate Expander (analytics / favicon pivot)",
    "description": "Discovers sibling root domains via shared analytics IDs and favicon hashes",
    "layer":    0,
    "mode":     ["semi", "active"],
    "requires": [],
    "optional": True,
}

_TIMEOUT = 15
_MAX_SEEDS = 25            # cap seed fetches per run
_MAX_HITS_PER_ID = 200     # cap reverse results merged per identifier

# Extraction patterns. GTM and GA4 ids are case-insensitive hex-ish tokens.
_PATTERNS = {
    "ga4":     re.compile(r"\bG-[A-Z0-9]{6,12}\b"),
    "ua":      re.compile(r"\bUA-\d{4,10}-\d{1,4}\b"),
    "gtm":     re.compile(r"\bGTM-[A-Z0-9]{4,10}\b"),
    "adsense": re.compile(r"\bca-pub-\d{10,20}\b|\bpub-\d{10,20}\b"),
}


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0        = time.monotonic()
    limiter   = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict = {
        "seeds_fetched": 0, "ids_found": 0, "favicons_found": 0,
        "roots_discovered": 0, "backend": _active_backends(),
    }

    publicwww_key = os.environ.get("PUBLICWWW_API_KEY")
    shodan_key    = os.environ.get("SHODAN_API_KEY")

    seeds = _seed_roots(scope)
    # id/hash -> set of seed roots it was seen on (for the ownership signal note)
    pivots: dict[tuple[str, str], set[str]] = {}

    headers = {"User-Agent": "SurfaceScanner security-research@example.com"}
    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True,
                                 headers=headers) as client:
        for seed in seeds[:_MAX_SEEDS]:
            await limiter.acquire("default")
            html = await _fetch_home(client, seed)
            if html is None:
                continue
            metadata["seeds_fetched"] += 1

            for kind, rx in _PATTERNS.items():
                for m in set(rx.findall(html)):
                    ident = m if isinstance(m, str) else next(x for x in m if x)
                    pivots.setdefault((kind, ident), set()).add(seed)

            fav = await _fetch_favicon_hash(client, seed)
            if fav is not None:
                metadata["favicons_found"] += 1
                pivots.setdefault(("favicon", str(fav)), set()).add(seed)

    metadata["ids_found"] = sum(1 for (k, _) in pivots if k != "favicon")

    # Always emit the pivot primitives, even with no reverse backend.
    for (kind, ident), on_roots in pivots.items():
        findings.append({
            "type":  "tracker_id",
            "value": ident,
            "data": {
                "kind":        kind,
                "seen_on":     sorted(on_roots),
                "pivot_query": _pivot_query_hint(kind, ident),
            },
        })

    # Reverse-lookup each pivot to discover sibling roots.
    seed_set = set(seeds)
    discovered: dict[str, dict] = {}   # root -> {signals:set, sources:set}
    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True,
                                 headers=headers) as client:
        for (kind, ident), on_roots in pivots.items():
            hits: list[tuple[str, str]] = []   # (root, source)
            if kind == "favicon":
                if shodan_key:
                    for r in await _reverse_favicon_shodan(ident, shodan_key, limiter):
                        hits.append((r, "shodan_favicon"))
            else:
                if publicwww_key:
                    for r in await _reverse_publicwww(client, ident, limiter,
                                                      publicwww_key):
                        hits.append((r, "publicwww"))
                else:
                    for r in await _reverse_publicwww_free(client, ident, limiter):
                        hits.append((r, "publicwww_free"))

            for root, source in hits[:_MAX_HITS_PER_ID]:
                if not root or root in seed_set:
                    continue
                d = discovered.setdefault(root, {"signals": set(), "sources": set()})
                d["signals"].add(f"{kind}:{ident}")
                d["sources"].add(source)

    for root, info in sorted(discovered.items()):
        findings.append({
            "type":  "estate_root",
            "value": root,
            "data": {
                "scope_tag":       "attribution-only",
                "ownership_signal": sorted(info["signals"]),
                "source":          sorted(info["sources"]),
                "parent_domain":   root,
                "note": "shared operator id/hash, confirm ownership before scoping",
            },
        })
    metadata["roots_discovered"] = len(discovered)

    log.info("estate_expander.complete",
             seeds=metadata["seeds_fetched"], ids=metadata["ids_found"],
             roots=metadata["roots_discovered"], backend=metadata["backend"])
    return {
        "module":   "layer0/estate_expander",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _active_backends() -> list[str]:
    b = []
    if os.environ.get("PUBLICWWW_API_KEY"): b.append("publicwww")
    else:                                   b.append("publicwww_free")
    if os.environ.get("SHODAN_API_KEY"):    b.append("shodan_favicon")
    return b


def _root_of(host: str) -> str | None:
    host = host.lower().strip().strip(".")
    if not host:
        return None
    if _EXT is None:
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else None
    e = _EXT(host)
    return f"{e.domain}.{e.suffix}" if e.domain and e.suffix else None


def _seed_roots(scope: Scope) -> list[str]:
    roots: set[str] = set()
    for d in scope.all_domains:
        r = _root_of(d)
        if r:
            roots.add(r)
    # only fetch things the engagement authorised
    return sorted(filter_in_scope(roots, scope, module=__name__))


async def _fetch_home(client: httpx.AsyncClient, root: str) -> str | None:
    for host in (f"www.{root}", root):
        for scheme in ("https", "http"):
            try:
                r = await client.get(f"{scheme}://{host}/", timeout=10)
                if r.status_code < 500 and r.text:
                    return r.text
            except Exception:
                pass
    return None


async def _fetch_favicon_hash(client: httpx.AsyncClient, root: str) -> int | None:
    try:
        from layer2_5.favicon_correlation import _mmh3_hash
    except Exception:
        return None
    for path in ("/favicon.ico", "/favicon.png"):
        for scheme in ("https", "http"):
            try:
                r = await client.get(f"{scheme}://{root}{path}", timeout=10)
                if r.status_code == 200 and r.content:
                    return _mmh3_hash(r.content)
            except Exception:
                pass
    return None


def _pivot_query_hint(kind: str, ident: str) -> str:
    if kind == "favicon":
        return f"http.favicon.hash:{ident}"
    return f'publicwww: "{ident}"'


async def _reverse_publicwww(
    client: httpx.AsyncClient, ident: str, limiter: RateLimiter, key: str,
) -> list[str]:
    await limiter.acquire("default")
    url = (f"https://publicwww.com/websites/%22{ident}%22/"
           f"?export=urls&key={key}")
    try:
        r = await client.get(url, timeout=_TIMEOUT)
        if r.status_code != 200 or not r.text:
            return []
        return _roots_from_lines(r.text)
    except Exception as exc:
        log.debug("estate_expander.publicwww_failed", error=str(exc)[:80])
        return []


async def _reverse_publicwww_free(
    client: httpx.AsyncClient, ident: str, limiter: RateLimiter,
) -> list[str]:
    # Keyless best-effort: PublicWWW serves a bounded public results page.
    await limiter.acquire("default")
    url = f"https://publicwww.com/websites/%22{ident}%22/"
    try:
        r = await client.get(url, timeout=_TIMEOUT)
        if r.status_code != 200 or not r.text:
            return []
        hosts = re.findall(r'href="/websites/[^"]*?/([a-z0-9.-]+\.[a-z]{2,24})/?"',
                           r.text, re.I)
        return _roots_from_lines("\n".join(hosts))
    except Exception as exc:
        log.debug("estate_expander.publicwww_free_failed", error=str(exc)[:80])
        return []


async def _reverse_favicon_shodan(
    fav_hash: str, key: str, limiter: RateLimiter,
) -> list[str]:
    try:
        from layer2_5.favicon_correlation import _shodan_favicon_search
    except Exception:
        return []
    try:
        matches = await _shodan_favicon_search(int(fav_hash), key, limiter)
    except Exception:
        return []
    roots: set[str] = set()
    for hit in matches:
        for h in hit.get("hostnames", []) or []:
            r = _root_of(h)
            if r:
                roots.add(r)
    return sorted(roots)


def _roots_from_lines(text: str) -> list[str]:
    roots: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        host = re.sub(r"^https?://", "", line).split("/")[0].split(":")[0]
        r = _root_of(host)
        if r:
            roots.add(r)
    return sorted(roots)
