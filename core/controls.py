"""
core/controls.py — negative controls and result attribution.

Every false positive of this class traces back to the same missing step: a
module asserted that something existed without first establishing what the
target returns for something that does not exist. Each module tended to solve
this on its own, or not at all. This module is the shared primitive so it is
solved once.

Four kinds of control live here.

1. HTTP catch-all fingerprinting. A single page application answers 200 with
   its index page for every path, so a sensitive file sweep can return many
   apparent hits that are all the same index page. Fingerprint the host with a
   random path first, then any result matching that fingerprint is discarded.

2. Wildcard DNS detection. A wildcard record resolves every name under a zone,
   so resolution proves nothing: a large share of apparently live hosts can be
   the same few servers answering under generated names.

3. Hosting attribution. Ports and services on a shared platform belong to the
   platform operator, not to the customer. Addresses belonging to platforms
   such as Cloudflare, Fastly, Vercel, Framer and HubSpot must be removed from
   the customer's findings rather than reported as the customer's surface.

4. Runtime model detection. A client bundle version does not tell you whether
   the server side advisories against that framework are reachable. A host
   flagged by the dependency scan may be a static export served from object
   storage with no framework server behind it, in which case the middleware
   and request handling advisories cannot apply to it at all.

Modules should treat a failed control as a reason to drop a result, and should
record the control outcome alongside anything they keep, so a reviewer can see
what was ruled out rather than taking the finding on trust.
"""
from __future__ import annotations

import asyncio
import hashlib
import math
import random
import re
import string
from dataclasses import dataclass, field
from typing import Any, Iterable

import httpx
import structlog

log = structlog.get_logger(__name__)

_TIMEOUT = 12
_UA = "Mozilla/5.0 (compatible; SurfaceScanner/1.0)"


# --------------------------------------------------------------------------
# 1. HTTP catch-all fingerprinting
# --------------------------------------------------------------------------

def _random_label(n: int = 16) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


@dataclass
class CatchAll:
    """What a host returns for a path that certainly does not exist."""
    host:        str
    status:      int | None = None
    length:      int | None = None
    body_hash:   str | None = None
    is_catchall: bool = False       # answers 2xx to anything
    probes:      int = 0

    def matches(self, status: int, length: int, body: bytes | str | None = None) -> bool:
        """True when a result is indistinguishable from the not-found response."""
        if self.status is None:
            return False
        if status != self.status:
            return False
        # Body hash is the strongest signal. Fall back to length, which catches
        # the common case of a fixed index page served for every path.
        if body is not None and self.body_hash:
            if _hash(body) == self.body_hash:
                return True
        if self.length is not None and length == self.length:
            return True
        return False


def _hash(body: bytes | str) -> str:
    if isinstance(body, str):
        body = body.encode("utf-8", "replace")
    return hashlib.sha256(body).hexdigest()


async def fingerprint_catchall(
    client: httpx.AsyncClient,
    host: str,
    *,
    probes: int = 2,
    scheme: str = "https",
) -> CatchAll:
    """
    Establish the host's response to paths that do not exist.

    Two probes rather than one, because a host that returns a different body
    each time (a timestamp, a request id) cannot be fingerprinted by hash and
    must fall back to status and length.
    """
    fp = CatchAll(host=host)
    seen: list[tuple[int, int, str]] = []

    for _ in range(max(1, probes)):
        path = f"{_random_label()}/{_random_label()}"
        try:
            r = await client.get(f"{scheme}://{host}/{path}", timeout=_TIMEOUT)
        except Exception:
            continue
        seen.append((r.status_code, len(r.content), _hash(r.content)))
        fp.probes += 1

    if not seen:
        return fp

    fp.status = seen[0][0]
    fp.length = seen[0][1]
    # Only trust the hash when every probe agreed, otherwise the body varies.
    if len({h for _, _, h in seen}) == 1:
        fp.body_hash = seen[0][2]
    if len({l for _, l, _ in seen}) != 1:
        fp.length = None
    fp.is_catchall = 200 <= fp.status < 300

    if fp.is_catchall:
        log.debug("catchall.detected", host=host, status=fp.status, length=fp.length)
    return fp


async def fingerprint_many(
    client: httpx.AsyncClient,
    hosts: Iterable[str],
    *,
    concurrency: int = 8,
) -> dict[str, CatchAll]:
    """Fingerprint a set of hosts, bounded so this does not become the scan."""
    sem = asyncio.Semaphore(concurrency)

    async def one(h: str) -> tuple[str, CatchAll]:
        async with sem:
            return h, await fingerprint_catchall(client, h)

    out = await asyncio.gather(*(one(h) for h in hosts), return_exceptions=True)
    return {h: fp for r in out if not isinstance(r, Exception) for h, fp in [r]}


# --------------------------------------------------------------------------
# 2. Wildcard DNS
# --------------------------------------------------------------------------

@dataclass
class WildcardZone:
    zone:      str
    addresses: set[str] = field(default_factory=set)

    @property
    def active(self) -> bool:
        return bool(self.addresses)


async def detect_wildcard(zone: str, resolver: Any, *, probes: int = 3) -> WildcardZone:
    """
    Probe a zone with random labels. Anything they resolve to is a wildcard
    answer, and a later result pointing at the same address proves nothing
    about that name existing.
    """
    wz = WildcardZone(zone=zone)
    for _ in range(probes):
        name = f"{_random_label()}.{zone}"
        try:
            answers = await resolver.resolve(name, "A")
            for a in answers:
                wz.addresses.add(str(a))
        except Exception:
            continue
    if wz.active:
        log.info("wildcard.zone", zone=zone, addresses=sorted(wz.addresses))
    return wz


def is_wildcard_answer(address: str, zones: Iterable[WildcardZone]) -> bool:
    return any(address in z.addresses for z in zones)


# --------------------------------------------------------------------------
# 3. Hosting attribution
# --------------------------------------------------------------------------

# Matched against reverse DNS, certificate subject, whois netname and server
# header. Deliberately conservative: a wrong "shared" verdict hides a real
# finding, so anything unrecognised stays customer operated and is reviewed.
_PLATFORM_SIGNS: dict[str, tuple[str, ...]] = {
    "Cloudflare":      ("cloudflare",),
    "Fastly":          ("fastly", "n.sni.global"),
    "Akamai":          ("akamai", "akamaitechnologies"),
    "Amazon CloudFront": ("cloudfront",),
    "Vercel":          ("vercel",),
    "Netlify":         ("netlify",),
    "Framer":          ("framer.app", "sites.framer"),
    "HubSpot":         ("hubspot", "hs-sites", "hsstatic"),
    "Google Cloud":    ("googleusercontent", "1e100.net", "uploadserver", "storage.googleapis"),
    "Google Load Balancer": ("google frontend", "gfe"),
    "Azure":           ("azureedge", "azurewebsites", "trafficmanager"),
    "Shopify":         ("shopify",),
    "WPEngine":        ("wpengine",),
    "Short.io":        ("short.io", "short.cm"),
    "Intercom":        ("intercom",),
    "Zendesk":         ("zendesk",),
}

SHARED = "Shared platform"
CUSTOMER = "Customer operated"


def attribute_hosting(*signals: str | None) -> tuple[str, str | None]:
    """
    Classify an address or host from whatever signals are available.

    Returns (classification, platform). Services on a shared platform belong to
    that platform's operator, so they must not be reported as the customer's
    exposure. Everything unrecognised is treated as customer operated, which
    errs toward reporting rather than hiding.
    """
    blob = " ".join(s.lower() for s in signals if s)
    if not blob:
        return CUSTOMER, None
    for platform, needles in _PLATFORM_SIGNS.items():
        if any(n in blob for n in needles):
            return SHARED, platform
    return CUSTOMER, None


def all_ports_open(ports: Iterable[int]) -> bool:
    """
    A host reporting almost every port open is a filtering device answering
    indiscriminately, not a real service inventory. Content delivery front ends
    commonly behave this way.
    """
    return len(set(ports)) > 100


# --------------------------------------------------------------------------
# 4. Runtime model
# --------------------------------------------------------------------------

STATIC = "Static export"
SERVER = "Server runtime"
VENDOR = "Vendor hosted"
UNKNOWN = "Unknown"

_STATIC_HEADERS = ("x-goog-generation", "x-goog-storage-class", "x-amz-id-2", "x-amz-request-id")
_SERVER_HEADERS = ("x-nextjs-cache", "x-powered-by", "x-matched-path", "x-vercel-cache",
                   "x-aspnet-version", "x-rails-", "x-django-")
_VENDOR_HEADERS = ("x-hs-portal-id", "x-shopify-", "x-zendesk-")


def runtime_model(headers: dict[str, str], server: str | None = None) -> str:
    """
    Decide whether a framework's server side advisories can apply at all.

    A build served straight from object storage has no framework process behind
    it, so advisories describing middleware, request deserialisation or server
    side request forgery cannot be reached however old the bundle is. Reporting
    them anyway overstates the exposure by an order of magnitude.
    """
    low = {k.lower(): (v or "").lower() for k, v in headers.items()}
    joined = " ".join(f"{k}:{v}" for k, v in low.items())
    srv = (server or low.get("server", "")).lower()

    if any(h in low for h in _VENDOR_HEADERS) or any(h in joined for h in _VENDOR_HEADERS):
        return VENDOR
    if any(h in low for h in _SERVER_HEADERS):
        return SERVER
    if any(h in low for h in _STATIC_HEADERS) or "uploadserver" in srv:
        return STATIC
    return UNKNOWN


def advisories_reachable(model: str) -> bool:
    """Server side advisories only apply where a server actually runs."""
    return model in (SERVER, UNKNOWN)


# --------------------------------------------------------------------------
# 5. CVSS 3.1
# --------------------------------------------------------------------------

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C":  {"H": 0.56, "L": 0.22, "N": 0.0},
    "I":  {"H": 0.56, "L": 0.22, "N": 0.0},
    "A":  {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27},
       "C": {"N": 0.85, "L": 0.68, "H": 0.5}}

_VECTOR_RE = re.compile(r"^(CVSS:3\.[01]/)?((?:[A-Z]+:[A-Z]/?)+)$")


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss_score(vector: str) -> float:
    """
    Base score from a CVSS 3.1 vector.

    Two findings in the Cycle 3 report carried a hand-calculated score that did
    not match their own vector. Scores are computed here so that cannot recur.
    """
    if not _VECTOR_RE.match(vector.strip()):
        raise ValueError(f"not a CVSS 3.1 vector: {vector!r}")
    p = dict(part.split(":") for part in vector.replace("CVSS:3.1/", "").replace("CVSS:3.0/", "").split("/") if part)
    for k in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
        if k not in p:
            raise ValueError(f"vector missing {k}: {vector!r}")

    scope = p["S"]
    iss = 1 - ((1 - _W["C"][p["C"]]) * (1 - _W["I"][p["I"]]) * (1 - _W["A"][p["A"]]))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    if impact <= 0:
        return 0.0

    expl = 8.22 * _W["AV"][p["AV"]] * _W["AC"][p["AC"]] * _PR[scope][p["PR"]] * _W["UI"][p["UI"]]
    base = min(impact + expl, 10) if scope == "U" else min(1.08 * (impact + expl), 10)
    return _roundup(base)


def cvss_severity(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Informational"


def score_finding(vector: str) -> dict[str, Any]:
    """Score and label together, so the two cannot disagree in a report."""
    s = cvss_score(vector)
    return {"cvss_score": s, "cvss_vector": f"CVSS:3.1/{vector.replace('CVSS:3.1/', '')}",
            "severity": cvss_severity(s)}


# --------------------------------------------------------------------------
# 6. Coverage accounting
# --------------------------------------------------------------------------

@dataclass
class Coverage:
    """
    Track what was attempted against what completed.

    When a share of vulnerability template requests fail to complete, nothing
    surfaces it unless the results are read by hand. A finding count taken from
    a partial scan is a floor, and a report should say so rather than presenting
    it as a total.
    """
    attempted: int = 0
    completed: int = 0
    failed:    int = 0
    controls_run:     int = 0
    controls_failed:  int = 0     # results dropped because a control caught them

    def record(self, ok: bool) -> None:
        self.attempted += 1
        if ok:
            self.completed += 1
        else:
            self.failed += 1

    def drop(self) -> None:
        self.controls_run += 1
        self.controls_failed += 1

    def keep(self) -> None:
        self.controls_run += 1

    @property
    def completion_rate(self) -> float:
        return self.completed / self.attempted if self.attempted else 1.0

    @property
    def partial(self) -> bool:
        """True when enough requests failed that results understate the total."""
        return self.completion_rate < 0.95

    def summary(self) -> dict[str, Any]:
        return {
            "attempted": self.attempted,
            "completed": self.completed,
            "failed": self.failed,
            "completion_rate": round(self.completion_rate, 4),
            "partial_coverage": self.partial,
            "controls_run": self.controls_run,
            "results_dropped_by_control": self.controls_failed,
        }
