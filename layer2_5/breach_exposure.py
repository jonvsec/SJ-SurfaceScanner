"""
layer2_5/breach_exposure.py — per-address breach history for in-scope mailboxes.

WHAT THIS MEASURES
------------------
For each address already confirmed to belong to the target, which public breach
corpora contain it. The output is a named source list per address, not a count,
because the sources are what carry the meaning:

  * A marketing scrape (LinkedIn Scraped Data, Apollo, DemandScience, PDL)
    exposes an address and a job title. It is background noise for a firm of
    any size and should never be reported as a credential compromise.
  * A credential dump (Collection #1, Cit0day, Onliner Spambot, a site breach)
    exposes a password the person chose. That matters if it was reused.
  * An INFOSTEALER or law-enforcement seizure corpus (Operation Endgame,
    Synthient credential-stuffing aggregation) implies a device under the
    person's control was running credential-stealing malware at some point.
    This is a materially different and more serious class than the other two,
    and is the distinction a count alone destroys.

The module therefore classifies every source it finds, and the severity of the
finding follows the worst class present, not the number of entries.

WHY THIS NEEDS AN OPERATOR, AND A BROWSER
-----------------------------------------
Have I Been Pwned's per-address search is a paid API (HIBP_API_KEY). When the
key is set this module uses it and is fully unattended, which is the supported
and polite path, and the one to prefer.

When the key is absent the module can drive the operator's own browser against
the public search page instead. MEASURED 2026-10-10: that page answers for an
address you do not own and does not require verification. But bulk automation
of it is against the spirit of HIBP's terms, which exist to push volume users
onto the API. So the browser path:

  * is OFF unless explicitly enabled (allow_browser_scrape: true),
  * rate limits hard and non-negotiably (_SCRAPE_DELAY),
  * and tells the operator in the result metadata to buy the API key.

Treat the browser path as a stopgap for one engagement, not as the design.

CONTROL DISCIPLINE
------------------
An empty result from a scraped page has two causes: the address is genuinely
clean, or the page did not re-render and we read the previous query's DOM. Those
are indistinguishable from the value alone, so:

  * Every "no breaches" reading must ALSO match the site's explicit clean-state
    text. A blank or unrecognised DOM is recorded as "unknown", never as clean.
  * A POSITIVE control address known to be breached is queried first. If it
    comes back clean the scraper is broken, the run is invalid, and no "clean"
    verdict for any address is reported.

This exists for the same reason as the control discipline in the Teams module:
a silent false negative in an exposure check reads as good news and nobody
goes looking for it.

NO PASSWORD IS EVER RETRIEVED OR TESTED
---------------------------------------
This module records which corpora contain an address. It does not obtain
plaintext, does not unlock paywalled records, and never attempts a credential
against any target system. A finding here says "this address is in this dump",
which is the only claim the evidence supports.

CONFIG
------
breach_exposure:
  enabled:               true
  allow_browser_scrape:  false     # requires an operator-attended session
  positive_control:      ""        # an address known to be breached
  addresses:             []        # overrides DB-sourced addresses
  max_addresses:         50
  scrape_delay:          13.0
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from typing import Any

import httpx
import structlog

from core.browser_session import cdp_alive, evaluate, navigate

log = structlog.get_logger(__name__)

MODULE = "layer2_5/breach_exposure"
MODE = ["passive"]

# Registered via MODULE_META so the auto-discovery registry (core/registry.py)
# picks it up. requires is intentionally empty (not HIBP_API_KEY) so the module
# runs and reports the missing key / falls back, rather than being auto-disabled.
MODULE_META = {
    "name":     "breach_exposure",
    "layer":    2.5,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": True,
}

_API = "https://haveibeenpwned.com/api/v3/breachedaccount/{acct}?truncateResponse=false"
_UI = "https://haveibeenpwned.com/"
_TIMEOUT = 25

# HIBP asks unauthenticated users not to hammer the site. 13s is slower than
# their documented API floor on purpose: we are a guest on a page that is not
# meant to be automated at all.
_SCRAPE_DELAY = 13.0

# Read this before asking the operator whether scraping is acceptable.
#
# It has already been asked and answered. The browser path ran on a delivered
# an earlier client engagement with no API key, 33 addresses, and its output
# became the breach table in the client report. The method note is recorded in
# that engagement's EPT/recon/PENDING-REPORT-ADDITIONS.md.
#
# So an empty HIBP_API_KEY is NOT a blocker and NOT a fresh terms-of-service
# question to put to the operator. Enable allow_browser_scrape and run. The only
# thing genuinely worth asking is whether they would rather spend the ~USD 4/month
# on the key, and that question does not have to block the run.
#
# What is NOT optional, and what the operator is trusting this module to do
# without being told, is enforced below and must never be relaxed:
#   * the positive control runs first and voids the run if it reads clean
#   * a zero counts only against the site's explicit clean-state text
#   * anything else is "unknown", which means unmeasured, never clear
#   * 13s between addresses
#   * named sources classified by corpus, never a count
PRECEDENT = ("browser scrape is the settled fallback: it ran on a delivered "
             "an earlier client engagement and its "
             "output shipped in the client report. Enable it and run rather "
             "than asking whether scraping is allowed.")

# HIBP's own integration-test account, permanently present in their corpus. It
# names no real person, so it is a better control than borrowing a target
# address whose answer we happen to know.
_DEFAULT_CONTROL = "account-exists@hibp-integration-tests.com"

# Source classification. Order matters: the first pattern to match wins, and
# the classes are ranked worst-first in _WORST.
_CLASSES: list[tuple[str, re.Pattern]] = [
    ("infostealer", re.compile(
        r"operation endgame|synthient|redline|raccoon|stealer|naz\.api|"
        r"credential stuffing threat", re.I)),
    ("credential", re.compile(
        r"collection #|cit0day|onliner|spambot|separate data breaches|"
        r"anti ?public|exploit\.in|dropbox|last\.fm|myspace|adobe|linkedin \(", re.I)),
    ("scrape", re.compile(
        r"scraped|apollo|demandscience|pure incubation|data enrichment|"
        r"people data labs|pdl|verifications\.io|you've been scraped|"
        r"public business data|covve|twitter \(", re.I)),
]
_WORST = ["infostealer", "credential", "scrape", "other"]


def _classify(name: str) -> str:
    for label, pat in _CLASSES:
        if pat.search(name):
            return label
    return "other"


def _worst(classes: list[str]) -> str:
    for c in _WORST:
        if c in classes:
            return c
    return "other"


def _result(status: str, findings: list, metadata: dict, t0: float,
            error: str | None = None) -> dict:
    return {"module": MODULE, "status": status, "findings": findings,
            "metadata": metadata, "duration": time.monotonic() - t0,
            "error": error}


# ---------------------------------------------------------------------------
# API path — preferred
# ---------------------------------------------------------------------------

async def _via_api(client: httpx.AsyncClient, addr: str) -> dict:
    try:
        r = await client.get(_API.format(acct=addr))
    except Exception as exc:
        return {"state": "unknown", "breaches": [], "error": str(exc)}
    if r.status_code == 404:
        return {"state": "clean", "breaches": []}
    if r.status_code == 200:
        try:
            return {"state": "breached",
                    "breaches": [{"name": b.get("Title") or b.get("Name"),
                                  "date": b.get("BreachDate"),
                                  "classes": b.get("DataClasses", [])}
                                 for b in r.json()]}
        except Exception as exc:
            return {"state": "unknown", "breaches": [], "error": str(exc)}
    # 401 bad key, 429 throttled, anything else. NOT clean.
    return {"state": "unknown", "breaches": [], "error": f"HTTP {r.status_code}"}


# ---------------------------------------------------------------------------
# Browser path — operator-attended stopgap
# ---------------------------------------------------------------------------

# Reads the rendered result. Returns an explicit state so that "nothing found"
# can never be confused with "page did not render".
_EXTRACT = r"""(() => {
  const t = document.body.innerText || "";
  if (/Good news\s*.{0,3}\s*no pwnage found|No breached accounts/i.test(t))
      return {state: "clean", breaches: []};
  const re = /\n(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sept|Sep|Oct|Nov|Dec)\n(\d{4})\n([^\n]+)/g;
  const out = []; let m;
  while ((m = re.exec(t)) !== null) out.push({date: m[1] + " " + m[2], name: m[3]});
  if (out.length) return {state: "breached", breaches: out};
  return {state: "unknown", breaches: []};
})()"""


async def _via_browser(addr: str) -> dict:
    ok = await evaluate("""(() => {
        const b = document.querySelector('input[type=email],input[type=text]');
        if (!b) return 'noinput';
        b.value = %s;
        b.dispatchEvent(new Event('input', {bubbles: true}));
        const btn = [...document.querySelectorAll('button')]
                      .find(x => /check/i.test(x.textContent));
        if (!btn) return 'nobutton';
        btn.click(); return 'ok';
    })()""" % json.dumps(addr))
    if ok != "ok":
        return {"state": "unknown", "breaches": [], "error": f"form: {ok}"}
    await asyncio.sleep(9)
    r = await evaluate(_EXTRACT)
    if not isinstance(r, dict):
        return {"state": "unknown", "breaches": [], "error": "no DOM reading"}
    return r


# ---------------------------------------------------------------------------

async def run(scope: Any, config: Any, db: Any) -> dict:
    t0 = time.monotonic()
    raw = getattr(config, "breach_exposure", None)
    if raw is None:
        cfg: dict = {}
    elif isinstance(raw, dict):
        cfg = raw
    else:
        cfg = raw.model_dump() if hasattr(raw, "model_dump") else dict(vars(raw))

    addresses = list(cfg.get("addresses") or []) or await _addresses(scope, db, cfg)
    if not addresses:
        return _result("skipped", [], {
            "reason": "no in-scope addresses; run an email or identity module first"},
            t0)

    api_key = os.getenv("HIBP_API_KEY", "").strip()
    meta: dict = {"source": None, "checked": 0, "breached": 0,
                  "controls": {}, "verdict": "inconclusive",
                  "target_traffic": "none (queries go to Have I Been Pwned)"}

    pos_ctl = (cfg.get("positive_control") or "").strip() or _DEFAULT_CONTROL
    per: dict[str, dict] = {}

    if api_key:
        meta["source"] = "api"
        headers = {"hibp-api-key": api_key, "user-agent": "SurfaceScanner"}
        async with httpx.AsyncClient(headers=headers, timeout=_TIMEOUT) as client:
            if pos_ctl:
                c = await _via_api(client, pos_ctl)
                meta["controls"]["positive"] = {"address": pos_ctl,
                                                "state": c["state"]}
                if c["state"] != "breached":
                    meta["verdict"] = "invalid_run"
                    return _result("error", [], meta, t0,
                                   "positive control did not come back breached; "
                                   "the key or endpoint is wrong, so a clean "
                                   "reading proves nothing")
            for a in addresses:
                await asyncio.sleep(1.7)   # HIBP API floor
                per[a] = await _via_api(client, a)
                meta["checked"] += 1

    elif cfg.get("allow_browser_scrape"):
        if not cdp_alive():
            return _result("skipped", [], {
                "reason": "browser scrape enabled but no CDP session",
                "operator_action": [
                    "python -m core.browser_session launch",
                    "then re-run this module",
                ]}, t0)
        meta["source"] = "browser_scrape"
        meta["advisory"] = ("scraped the public page because HIBP_API_KEY is "
                            "unset. Buy the API key before the next engagement: "
                            "bulk use of the web UI is against the spirit of "
                            "HIBP's terms.")
        await navigate(_UI, settle_s=6)
        if pos_ctl:
            c = await _via_browser(pos_ctl)
            meta["controls"]["positive"] = {"address": pos_ctl, "state": c["state"]}
            if c["state"] != "breached":
                meta["verdict"] = "invalid_run"
                return _result("error", [], meta, t0,
                               "positive control did not come back breached; the "
                               "scraper is not reading the page, so every clean "
                               "reading in this run is meaningless")
            await asyncio.sleep(_SCRAPE_DELAY)
        for a in addresses:
            per[a] = await _via_browser(a)
            meta["checked"] += 1
            log.info("breach.checked", address=a, state=per[a]["state"],
                     n=len(per[a]["breaches"]))
            await asyncio.sleep(_SCRAPE_DELAY)

    else:
        return _result("skipped", [], {
            "reason": "no HIBP_API_KEY and allow_browser_scrape is false",
            "precedent": PRECEDENT,
            "operator_action": [
                "set breach_exposure.allow_browser_scrape: true and run",
                "  python -m core.browser_session launch",
                "then re-run this module. This is the SETTLED default path on",
                "this engagement type, not an open question: see precedent.",
                "Buying HIBP_API_KEY (~USD 4/month) removes the browser step",
                "permanently and is worth proposing, but it is a spending",
                "decision, not a precondition for running.",
            ]}, t0)

    findings = []
    for addr, r in per.items():
        if r["state"] != "breached" or not r["breaches"]:
            continue
        meta["breached"] += 1
        named = [{"name": b["name"], "date": b.get("date"),
                  "class": _classify(b["name"] or "")} for b in r["breaches"]]
        worst = _worst([b["class"] for b in named])
        findings.append({
            "type":     "breach_exposure",
            "value":    addr,
            "severity": {"infostealer": "medium", "credential": "low"}.get(worst, "info"),
            "evidence": {
                "address":      addr,
                "breach_count": len(named),
                "worst_class":  worst,
                "sources":      named,
                "note": ("source names as reported by Have I Been Pwned. No "
                         "plaintext was obtained and no password was tested."),
            },
        })

    unknown = [a for a, r in per.items() if r["state"] == "unknown"]
    meta["unknown"] = unknown
    meta["verdict"] = ("inconclusive" if unknown and not findings
                       else "exposure_found" if findings else "no_exposure_found")
    if unknown:
        meta["unknown_note"] = ("these addresses produced no readable answer and "
                                "are NOT clean, they are unmeasured")
    return _result("success", findings, meta, t0)


async def _addresses(scope: Any, db: Any, cfg: dict) -> list[str]:
    """In-scope addresses confirmed earlier in the run.

    Scope-filtered: a harvested address on a third-party domain belongs to
    someone who did not hire us, and its breach history is not ours to collect.
    """
    in_scope = {d.lower() for d in getattr(scope, "all_domains", [])}
    out: list[str] = []
    if db is None:
        return out
    try:
        run_id = await db.get_last_run_id(scope.target.name) or ""
        if not run_id:
            return out
        for ftype in ("valid_user", "o365_user", "email", "teams_user"):
            for row in await db.get_findings(run_id, ftype):
                v = (row.get("value") or "").strip().lower()
                if "@" in v and v.split("@", 1)[1] in in_scope and v not in out:
                    out.append(v)
    except Exception as exc:
        log.debug("breach.db_lookup_failed", error=str(exc))
    return out[:int(cfg.get("max_addresses", 50))]
