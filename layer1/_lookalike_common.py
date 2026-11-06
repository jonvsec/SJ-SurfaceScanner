"""
layer1/_lookalike_common.py — shared scoring, severity mapping, and enrichment
for the lookalike-domain producers.

This file deliberately carries no MODULE_META, so the registry does not pick it
up as a pipeline module. It is a plain helper imported by both
layer1/brand_protection.py (dnstwist permutations) and
layer1/newly_registered_domains.py (crt.sh + newly-registered-domain feeds), so
there is one implementation of the risk score, the SEV1 to SEV5 mapping, the
fuzzy brand match, and the page/favicon/infrastructure enrichment rather than a
copy in each.

Everything here is pure scripting. No LLM, no AI. The HTTP-based enrichers
(favicon, page fingerprint) touch the lookalike host, not the client, and the
callers gate them to semi/active mode so passive runs stay contactless.
"""
from __future__ import annotations

import asyncio
from typing import Any, Iterable

import httpx
import structlog

# One implementation of the Shodan-style favicon MurmurHash3, reused rather
# than copied. favicon_correlation carries MODULE_META but importing it has no
# side effects beyond defining the module.
from layer2_5.favicon_correlation import _mmh3_hash

log = structlog.get_logger(__name__)

# --------------------------------------------------------------------------
# Scoring — moved out of brand_protection so both producers score identically.
# Weights and thresholds are passed in by the caller from config, never baked
# in here, so config stays the single source of truth.
# --------------------------------------------------------------------------

DEFAULT_WEIGHTS = {"mx": 3, "a": 1, "recent": 2, "ns_differ": 1}
DEFAULT_RECENT_DAYS = 180


def ns_root(ns: str) -> str:
    """awsdns from ns-913.awsdns-50.net — enough to compare providers."""
    parts = (ns or "").strip(".").lower().split(".")
    if len(parts) >= 2:
        return parts[-2].split("-")[0]
    return ns or ""


def score(
    *,
    mx: list, a: list, ns: list, legit_ns: set[str],
    age_days: int | None, registered: bool | None,
    fuzzer: str = "", distinctive_brand: bool = True,
    weights: dict[str, int] | None = None,
    recent_days: int = DEFAULT_RECENT_DAYS,
) -> tuple[str, list[str]]:
    """
    Rank a lookalike by how ready it is to be used against the brand.

    Mail capability dominates: a lookalike that can send and receive mail is one
    configuration step from a live phishing campaign, whereas a parked name with
    no records is only a placeholder. Returns an internal severity in the
    engine vocabulary (critical/high/medium/low/info) plus the reasons.
    """
    w = {**DEFAULT_WEIGHTS, **(weights or {})}
    reasons: list[str] = []
    s = 0

    # A TLD swap on a generic brand label is not brand abuse — it is a different
    # company that happens to share a common word. Report it as context only.
    if not distinctive_brand and fuzzer in ("tld-swap", "subdomain"):
        return "info", [
            "TLD/subdomain variant of a generic brand label, "
            "almost certainly an unrelated third party, not a typosquat"
        ]

    if mx:
        s += w["mx"]
        reasons.append("MX records present, can send/receive mail as the brand")
    if a:
        s += w["a"]
        reasons.append("resolves to a live host")
    if age_days is not None and age_days <= recent_days:
        s += w["recent"]
        reasons.append(f"registered {age_days} days ago")
    if ns and legit_ns and not any(ns_root(n) in legit_ns for n in ns):
        s += w["ns_differ"]
        reasons.append("nameservers differ from the organisation's own")

    # RDAP 404 does not mean "available". Several registries (.de among them)
    # publish no public RDAP service at all, so trust DNS over RDAP silence.
    if registered is False and not (a or mx or ns):
        return "info", ["not registered"]
    if registered is False:
        reasons.append("registration date unavailable, registry publishes no RDAP")

    if s >= 4:
        return "high", reasons
    if s >= 2:
        return "medium", reasons
    if s >= 1:
        return "low", reasons
    return "info", reasons or ["registered but dormant"]


# --------------------------------------------------------------------------
# SEV1 to SEV5 mapping — the one place the team's severity decision lives.
# The rules below are the defaults; the caller passes the config overrides.
# --------------------------------------------------------------------------

DEFAULT_SEV_MAP = {
    # internal engine severity -> platform severity
    "base": {
        "critical": "SEV2",
        "high":     "SEV2",
        "medium":   "SEV3",
        "low":      "SEV4",
        "info":     "SEV5",
    },
    # All of these true forces SEV1 (a confirmed live clone).
    "sev1_when_all": ["serves_login", "visual_match", "mail_capable"],
    # Any of these true, together with mail_capable, forces at least SEV2.
    "sev2_when_any_with_mail": ["serves_login", "visual_match", "favicon_match"],
}

_SEV_ORDER = ["SEV1", "SEV2", "SEV3", "SEV4", "SEV5"]
_INTERNAL_ORDER = ["critical", "high", "medium", "low", "info"]


def apply_staleness(
    internal_sev: str,
    *,
    age_days: int | None,
    mail_capable: bool,
    serves_login: bool = False,
    visual_match: bool = False,
    favicon_match: bool = False,
    stale_days: int = 730,
) -> str:
    """
    Downgrade an old, dormant lookalike to info.

    The value of this module is the change since the last cycle: a freshly bought
    name being staged against the brand. A name registered years ago that only
    resolves, with no mail and no active content, is not a live campaign, so it
    drops to info rather than sitting in the alerting band. A mail-capable or
    actively-serving name keeps its rank regardless of age, because that is a
    working capability, not an idle registration. Age unknown means no downgrade,
    since we cannot tell.
    """
    if age_days is None or age_days <= stale_days:
        return internal_sev
    if mail_capable or serves_login or visual_match or favicon_match:
        return internal_sev
    return "info"


def _at_least(current: str, floor: str) -> str:
    """Return whichever of current/floor is the more severe (lower number)."""
    try:
        return floor if _SEV_ORDER.index(floor) < _SEV_ORDER.index(current) else current
    except ValueError:
        return current


def map_sev_platform(
    internal_sev: str,
    *,
    mail_capable: bool = False,
    serves_login: bool = False,
    favicon_match: bool = False,
    visual_match: bool = False,
    sev_map: dict | None = None,
) -> str:
    """
    Map the internal severity onto the platform SEV1 to SEV5 scale.

    The platform scale is a fixed given on the JOES AIR side. This function only
    decides which SEV a lookalike lands on, driven by the config table so the
    team can retune the mapping in one place without touching code.
    """
    m = sev_map or DEFAULT_SEV_MAP
    signals = {
        "mail_capable": mail_capable,
        "serves_login": serves_login,
        "favicon_match": favicon_match,
        "visual_match": visual_match,
    }

    sev = (m.get("base") or {}).get(internal_sev, "SEV5")

    if m.get("sev1_when_all") and all(signals.get(k) for k in m["sev1_when_all"]):
        return "SEV1"

    if mail_capable and any(signals.get(k) for k in m.get("sev2_when_any_with_mail", [])):
        sev = _at_least(sev, "SEV2")

    return sev


# --------------------------------------------------------------------------
# Fuzzy brand match — used by the CT and newly-registered-domain discovery to
# decide whether a freshly seen domain resembles a client brand. openSquat-style
# normalisation plus bounded edit distance, stdlib only.
# --------------------------------------------------------------------------

def _levenshtein(a: str, b: str, cap: int) -> int:
    """Edit distance, short-circuited once it provably exceeds cap."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        best = i
        for j, cb in enumerate(b, 1):
            cur.append(min(
                prev[j] + 1,
                cur[j - 1] + 1,
                prev[j - 1] + (ca != cb),
            ))
            best = min(best, cur[-1])
        if best > cap:
            return cap + 1
        prev = cur
    return prev[-1]


# Common Latin -> Cyrillic / Greek confusables (Unicode TR39 style). Single
# character swaps that render identically in most fonts. These are the scripts
# dnstwist does not emit for a .com brand, so we generate them ourselves.
_CONFUSABLES: dict[str, list[str]] = {
    "a": ["а", "α"],   # Cyrillic a, Greek alpha
    "c": ["с"],              # Cyrillic es
    "e": ["е"],              # Cyrillic ie
    "i": ["і", "ι"],   # Cyrillic byelorussian i, Greek iota
    "j": ["ј"],              # Cyrillic je
    "o": ["о", "ο"],   # Cyrillic o, Greek omicron
    "p": ["р", "ρ"],   # Cyrillic er, Greek rho
    "s": ["ѕ"],              # Cyrillic dze
    "x": ["х", "χ"],   # Cyrillic ha, Greek chi
    "y": ["у", "γ"],   # Cyrillic u, Greek gamma
    "n": ["η"],              # Greek eta
    "b": ["в"],              # Cyrillic ve
    "h": ["һ"],              # Cyrillic shha
    "k": ["к"],              # Cyrillic ka
    "m": ["м"],              # Cyrillic em
    "t": ["т"],              # Cyrillic te
}


def homoglyph_idn_variants(domain: str) -> list[dict]:
    """
    Single-character Cyrillic/Greek homoglyph swaps of a domain label.

    Returns the Unicode display form and the registrable punycode (xn--) form.
    These are the mixed-script homographs dnstwist suppresses for a .com brand
    as "unconvincing", but attackers register them anyway, so for a monitoring
    watcher we want the full set.
    """
    parts = (domain or "").strip().lower().split(".")
    if len(parts) < 2:
        return []
    label, tld = parts[0], ".".join(parts[1:])
    out: list[dict] = []
    seen: set[str] = set()
    for i, ch in enumerate(label):
        for g in _CONFUSABLES.get(ch, []):
            uni = label[:i] + g + label[i + 1:] + "." + tld
            if uni in seen:
                continue
            seen.add(uni)
            try:
                puny = uni.encode("idna").decode("ascii")
            except Exception:
                try:
                    puny = ".".join(
                        p.encode("idna").decode("ascii") for p in uni.split(".")
                    )
                except Exception:
                    continue
            out.append({"unicode": uni, "punycode": puny, "swapped": ch})
    return out


# ccTLDs/gTLDs usable for the domain-hack split. Kept small and curated so the
# split produces plausible, registrable names rather than noise.
_HACK_TLDS = {
    "es", "io", "co", "me", "ai", "it", "in", "is", "as", "to", "tv", "fm",
    "ly", "us", "eu", "de", "be", "re", "se", "sh", "st", "gg", "gl", "so",
    "nu", "ws", "cc", "ca", "ac", "al", "am", "at",
}


def domain_hack_variants(domains: list[str], extra_tlds: set[str] | None = None) -> list[str]:
    """
    Domain-hack / TLD-split forms of each brand domain.

    acme -> ac.me, acm.e ... whenever a trailing slice
    of the label is itself a usable TLD. This is the form dnstwist does not
    generate (it only swaps the existing TLD, never splits the label).
    """
    tlds = _HACK_TLDS | (extra_tlds or set())
    out: set[str] = set()
    for d in domains:
        label = brand_label(d)
        if len(label) < 4:
            continue
        for k in range(2, len(label) - 1):
            head, tail = label[:k], label[k:]
            if tail in tlds and len(head) >= 2:
                out.add(f"{head}.{tail}")
    return sorted(out)


# Words attackers most often bolt onto a brand for a phishing or login lure.
_COMBO_KEYWORDS = [
    "login", "signin", "secure", "security", "account", "accounts", "verify",
    "verification", "support", "help", "portal", "sso", "auth", "mail",
    "webmail", "admin", "update", "confirm", "service", "services", "online",
    "official", "team", "app", "apps", "cloud", "vpn", "access", "client",
    "customer", "billing", "pay", "payment", "hr", "it", "corp", "group",
    "global", "info", "web", "my", "secure-login", "password", "reset",
]

# Common and commonly abused TLDs for the TLD-substitution sweep. Broader than
# dnstwist's default set so a brand is checked across the extensions attackers
# actually buy, without reaching into the full obscure IANA tail.
_COMMON_TLDS = [
    "com", "net", "org", "co", "io", "info", "biz", "us", "uk", "co.uk", "ca",
    "de", "fr", "es", "it", "nl", "eu", "ru", "cn", "jp", "br", "in", "au",
    "mx", "ch", "se", "no", "dk", "fi", "pl", "pt", "be", "at", "ie", "nz",
    "me", "tv", "cc", "ws", "xyz", "online", "site", "shop", "store", "tech",
    "app", "dev", "cloud", "live", "life", "world", "today", "news", "email",
    "support", "help", "center", "pro", "vip", "club", "icu", "top", "fun",
    "link", "click", "work", "digital", "network", "systems", "solutions",
    "services", "group", "global", "company", "agency", "page", "web", "site",
    "ai", "sh", "gg", "to", "fm", "ly", "st", "so", "re", "co.in", "com.br",
    "com.au", "com.mx", "co.za", "org.uk", "net.co",
]


def combosquat_variants(domains: list[str], keywords: list[str] | None = None) -> list[str]:
    """
    Brand plus a plausible word, the most common real phishing technique.

    For each brand domain this emits brand+keyword and keyword+brand, both
    hyphenated and concatenated, under the brand's own TLD. acme.com
    produces acme-login.com, login-acme.com, acmelogin.com
    and so on.
    """
    kws = keywords or _COMBO_KEYWORDS
    out: set[str] = set()
    for d in domains:
        parts = (d or "").strip().lower().split(".")
        if len(parts) < 2:
            continue
        label, tld = parts[0], ".".join(parts[1:])
        if len(label) < 3:
            continue
        for kw in kws:
            out.add(f"{label}-{kw}.{tld}")
            out.add(f"{kw}-{label}.{tld}")
            out.add(f"{label}{kw}.{tld}")
            out.add(f"{kw}{label}.{tld}")
    return sorted(out)


def tld_substitution_variants(domains: list[str], tlds: list[str] | None = None) -> list[str]:
    """The brand label under every common and commonly abused TLD."""
    ext = tlds or _COMMON_TLDS
    out: set[str] = set()
    for d in domains:
        label = (d or "").strip().lower().split(".")[0]
        if len(label) < 3:
            continue
        for t in ext:
            cand = f"{label}.{t}"
            if cand != (d or "").strip().lower():
                out.add(cand)
    return sorted(out)


def brand_label(domain: str) -> str:
    """Second-level label of a domain, lowercased: shop.acme.co.uk -> acme."""
    parts = (domain or "").strip().strip(".").lower().split(".")
    # Drop a known public-suffix-ish tail heuristically: keep the label left of
    # the last one or two components.
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov", "edu", "ac"}:
        return parts[-3]
    if len(parts) >= 2:
        return parts[-2]
    return parts[0] if parts else ""


def fuzzy_brand_match(domain: str, brand_labels: Iterable[str], max_distance: int = 2) -> str | None:
    """
    Return the brand label a domain resembles, or None.

    A match is either the brand label appearing as a run inside the candidate's
    own label (typosquat prefix/suffix, e.g. acme-login) or an edit distance
    within max_distance (character swap, omission, doubling).
    """
    cand = brand_label(domain)
    if not cand:
        return None
    for b in brand_labels:
        b = (b or "").strip().lower()
        if len(b) < 4:
            continue
        if b in cand or cand in b:
            return b
        if _levenshtein(cand, b, max_distance) <= max_distance:
            return b
    return None


# --------------------------------------------------------------------------
# HTTP / favicon enrichment — semi+ only. Each is best-effort and never raises.
# --------------------------------------------------------------------------

_PW_MARKERS = ('type="password"', "type='password'", "type=password")
_LOGIN_WORDS = ("log in", "login", "sign in", "signin", "password", "username")


async def enrich_http(client: httpx.AsyncClient, host: str) -> dict:
    """Page title, Server header, and whether the page presents a login form."""
    out: dict[str, Any] = {"page_title": None, "server": None, "serves_login": False}
    for scheme in ("https", "http"):
        try:
            r = await client.get(f"{scheme}://{host}/", timeout=10)
        except Exception:
            continue
        body = (r.text or "")[:200_000]
        low = body.lower()
        out["server"] = r.headers.get("server")
        title = _between(low, "<title>", "</title>", body)
        out["page_title"] = title[:200] if title else None
        out["serves_login"] = (
            any(m in low for m in _PW_MARKERS)
            or sum(w in low for w in _LOGIN_WORDS) >= 2
        )
        return out
    return out


def _between(low: str, start: str, end: str, original: str) -> str | None:
    i = low.find(start)
    if i == -1:
        return None
    j = low.find(end, i + len(start))
    if j == -1:
        return None
    return original[i + len(start):j].strip()


async def enrich_favicon(client: httpx.AsyncClient, host: str) -> int | None:
    """Shodan-style MurmurHash3 of the host favicon, or None."""
    for scheme in ("https", "http"):
        try:
            r = await client.get(f"{scheme}://{host}/favicon.ico", timeout=10)
            if r.status_code == 200 and r.content:
                return _mmh3_hash(r.content)
        except Exception:
            continue
    return None


# --------------------------------------------------------------------------
# Infrastructure pivoting — cluster confirmed lookalikes into campaigns by
# shared A-record IP, shared favicon hash, or shared nameserver root. Mutates
# each finding with a cluster_id and returns the campaign summaries.
# --------------------------------------------------------------------------

def cluster_campaigns(findings: list[dict]) -> list[dict]:
    """
    Group non-info lookalikes that share hosting infrastructure.

    A single actor registering a batch of lookalikes typically parks them on one
    IP, serves one favicon, or uses one nameserver. Grouping on any shared pivot
    turns a list of domains into the shape of a campaign, which is what the blue
    team acts on.
    """
    nodes = [
        f for f in findings
        if f.get("data", {}).get("severity") not in (None, "info")
    ]
    parent: dict[int, int] = {i: i for i in range(len(nodes))}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        parent[find(a)] = find(b)

    def pivots(f: dict) -> set[str]:
        d = f.get("data", {})
        p: set[str] = set()
        for ip in d.get("dns_a") or []:
            p.add(f"ip:{ip}")
        if d.get("favicon_hash") is not None:
            p.add(f"fav:{d['favicon_hash']}")
        for n in d.get("dns_ns") or []:
            p.add(f"ns:{ns_root(n)}")
        return p

    seen: dict[str, int] = {}
    for i, f in enumerate(nodes):
        for pv in pivots(f):
            if pv in seen:
                union(i, seen[pv])
            else:
                seen[pv] = i

    groups: dict[int, list[int]] = {}
    for i in range(len(nodes)):
        groups.setdefault(find(i), []).append(i)

    campaigns: list[dict] = []
    cid = 0
    for members in groups.values():
        if len(members) < 2:
            continue
        cid += 1
        cluster_id = f"cluster-{cid}"
        shared_ips: set[str] = set()
        shared_fav: set[int] = set()
        shared_ns: set[str] = set()
        domains: list[str] = []
        for idx in members:
            f = nodes[idx]
            f["data"]["cluster_id"] = cluster_id
            domains.append(f.get("value", ""))
            d = f["data"]
            shared_ips.update(d.get("dns_a") or [])
            if d.get("favicon_hash") is not None:
                shared_fav.add(d["favicon_hash"])
            shared_ns.update(ns_root(n) for n in (d.get("dns_ns") or []))
        campaigns.append({
            "cluster_id": cluster_id,
            "domains": sorted(d for d in domains if d),
            "shared_ips": sorted(shared_ips),
            "shared_favicon_hashes": sorted(shared_fav),
            "shared_nameservers": sorted(x for x in shared_ns if x),
        })
    return campaigns
