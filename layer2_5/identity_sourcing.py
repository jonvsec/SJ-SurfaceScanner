"""
layer2_5/identity_sourcing.py — build the candidate address list, with a gate.

WHAT THIS DOES
--------------
Turns staff names into candidate email addresses for the enumeration modules
(teams_external_access, breach_exposure, o365 user checks) by applying the
local-part patterns the target actually uses.

WHY IT ASKS FIRST, ALWAYS
-------------------------
The two sources that make this worth doing are:

  1. hunter.io  — a paid API. Someone's credits get spent, and the operator,
     not the scanner, decides that.
  2. LinkedIn company "People" pages — scraping these is against LinkedIn's
     terms of service and has, in the past, got accounts restricted. It is the
     OPERATOR'S account and the operator's risk.

Neither is a decision this tool gets to make on its own, and neither is a
decision that should be buried in a config default. So this module does nothing
until a human has said yes, in this engagement, for these sources:

    identity_sourcing:
      confirmed: true          # must be set deliberately, never defaulted on
      sources: [hunter, linkedin_manual]

With confirmed unset or false the module returns "skipped" and prints exactly
what it needs. That is the intended resting state. A skipped run here is not a
failure, it is the gate doing its job.

LINKEDIN IS DELIBERATELY MANUAL
-------------------------------
This module will NOT drive a browser against LinkedIn. Automating a logged-in
LinkedIn session is the part that gets accounts banned, and an automated
scraper is also the part that turns a judgement call into an unsupervised
habit. The operator opens the company People page themselves, copies the
visible names, and drops them in a text file. The module does the boring part,
which is the pattern expansion.

PATTERNS ARE DERIVED, NOT ASSUMED
---------------------------------
MEASURED on a live engagement 2026-10-10: one 50-person firm used THREE
conventions at once (initial+surname, surname only, firstname+surname), and
four mailboxes answered on two addresses each. Picking one convention would
have missed roughly half the directory. So every known-good address seen so far
is reduced to a pattern, the observed patterns are ranked by how often they
occur, and all of them are expanded for every name.

Candidates are candidates. Nothing here is a finding. Only a downstream module
that gets a positive, control-checked answer turns one into a confirmed
account, and an address that fails to resolve is NOT evidence the person has no
mailbox.

CONFIG
------
identity_sourcing:
  confirmed:     false
  sources:       [hunter, linkedin_manual]
  names_file:    ""       # one "First Last" per line, operator supplied
  known_file:    ""       # known-good addresses, one per line, to learn from
  patterns:      []       # override the derived patterns
  max_candidates: 200
"""

from __future__ import annotations

import os
import re
import time
import unicodedata
from pathlib import Path
from typing import Any

import httpx
import structlog

log = structlog.get_logger(__name__)

MODULE = "layer2_5/identity_sourcing"
MODE = ["passive"]

# Registered via MODULE_META so the auto-discovery registry (core/registry.py)
# picks it up. Previously only declared the legacy `MODE` var, which the registry
# does not read, so the module was silently never registered.
MODULE_META = {
    "name":     "identity_sourcing",
    "layer":    2.5,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": True,
}

_HUNTER = "https://api.hunter.io/v2/domain-search"
_TIMEOUT = 25

# Named so a report can say which convention a hit came from.
_PATTERNS: dict[str, Any] = {
    "f.last":      lambda f, l: f"{f}.{l}",
    "flast":       lambda f, l: f"{f[0]}{l}",
    "last":        lambda f, l: l,
    "firstlast":   lambda f, l: f"{f}{l}",
    "first":       lambda f, l: f,
    "first.last":  lambda f, l: f"{f}.{l}",
    "lastf":       lambda f, l: f"{l}{f[0]}",
}


def _norm(s: str) -> str:
    """Fold accents and strip anything not a letter.

    MEASURED: directories store "Nicolo Francese" for "Nicolò Francese" and
    "Marco della Giacoma" collapses to "dellagiacoma". Leaving the accent in
    produces a candidate that silently never matches.
    """
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    return re.sub(r"[^a-z]", "", s.lower())


def _split_name(raw: str) -> tuple[str, str] | None:
    # Drop credential suffixes and parentheticals: "Kostas Feruliovas, CFA".
    raw = re.sub(r"[,(].*$", "", raw).strip()
    parts = [p for p in raw.split() if p]
    if len(parts) < 2:
        return None
    first = _norm(parts[0])
    # Keep surname particles attached: "della Giacoma" -> dellagiacoma.
    last = _norm("".join(parts[1:]))
    return (first, last) if first and last else None


def _derive_patterns(known: list[str]) -> list[str]:
    """Which conventions does this target actually use, most common first."""
    seen: dict[str, int] = {}
    for addr in known:
        local = addr.split("@", 1)[0].lower()
        for name, fn in _PATTERNS.items():
            # We cannot invert without the name, so match structurally instead.
            if name == "last" and local.isalpha() and len(local) > 4:
                seen[name] = seen.get(name, 0) + 1
            elif name == "flast" and re.fullmatch(r"[a-z][a-z]{3,}", local):
                seen[name] = seen.get(name, 0) + 1
            elif name == "f.last" and "." in local:
                seen[name] = seen.get(name, 0) + 1
    return [k for k, _ in sorted(seen.items(), key=lambda x: -x[1])] or \
           ["flast", "last", "firstlast", "f.last"]


def _result(status: str, findings: list, metadata: dict, t0: float,
            error: str | None = None) -> dict:
    return {"module": MODULE, "status": status, "findings": findings,
            "metadata": metadata, "duration": time.monotonic() - t0,
            "error": error}


async def _hunter(domain: str, key: str) -> list[dict]:
    out = []
    async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
        try:
            r = await c.get(_HUNTER, params={"domain": domain, "api_key": key,
                                             "limit": 100})
            if r.status_code != 200:
                log.warning("hunter.http", status=r.status_code)
                return out
            for e in (r.json().get("data") or {}).get("emails") or []:
                out.append({
                    "address":    (e.get("value") or "").lower(),
                    "name":       " ".join(x for x in (e.get("first_name"),
                                                       e.get("last_name")) if x),
                    "position":   e.get("position"),
                    "confidence": e.get("confidence"),
                    "sources":    len(e.get("sources") or []),
                })
        except Exception as exc:
            log.warning("hunter.failed", error=str(exc))
    return out


async def run(scope: Any, config: Any, db: Any) -> dict:
    t0 = time.monotonic()
    raw = getattr(config, "identity_sourcing", None)
    if raw is None:
        cfg: dict = {}
    elif isinstance(raw, dict):
        cfg = raw
    else:
        cfg = raw.model_dump() if hasattr(raw, "model_dump") else dict(vars(raw))

    domain = (scope.all_domains[0] if getattr(scope, "all_domains", None)
              else cfg.get("domain", ""))

    # ---- THE GATE -------------------------------------------------------
    if not cfg.get("confirmed"):
        return _result("skipped", [], {
            "reason": "identity sourcing not confirmed by the operator",
            "why_asked": [
                "hunter.io spends paid credits that belong to the operator",
                "scraping LinkedIn company People pages breaches LinkedIn's "
                "terms of service and risks the operator's own account",
                "both are the operator's call, per engagement, and must not "
                "default to on",
            ],
            "operator_action": [
                "confirm in scope that OSINT staff enumeration is authorised,",
                "then set in config.yaml:",
                "  identity_sourcing:",
                "    confirmed: true",
                "    sources: [hunter, linkedin_manual]",
                "",
                "for LinkedIn, open the company People page yourself and save the",
                "visible names, one 'First Last' per line, then set:",
                "    names_file: /path/to/names.txt",
                "",
                "this module will not drive a browser against LinkedIn.",
            ],
        }, t0)
    # ---------------------------------------------------------------------

    sources = cfg.get("sources") or ["hunter", "linkedin_manual"]
    meta: dict = {"domain": domain, "sources_used": [], "patterns": [],
                  "asserted": 0, "names": 0, "candidates": 0,
                  "note": ("candidates are unverified. An address here is a "
                           "guess until an enumeration module confirms it "
                           "against controls.")}

    asserted: list[dict] = []
    if "hunter" in sources:
        key = os.getenv("HUNTER_API_KEY", "").strip()
        if not key:
            meta["hunter_skipped"] = "HUNTER_API_KEY unset"
        elif domain:
            asserted = await _hunter(domain, key)
            meta["sources_used"].append("hunter")
    meta["asserted"] = len(asserted)

    names: list[str] = []
    nf = (cfg.get("names_file") or "").strip()
    if nf and Path(nf).is_file():
        names = [l.strip() for l in Path(nf).read_text().splitlines()
                 if l.strip() and not l.startswith("#")]
        meta["sources_used"].append("linkedin_manual")
    meta["names"] = len(names)

    known = [a["address"] for a in asserted if a.get("address")]
    kf = (cfg.get("known_file") or "").strip()
    if kf and Path(kf).is_file():
        known += [l.strip().lower() for l in Path(kf).read_text().splitlines()
                  if "@" in l]
    patterns = cfg.get("patterns") or _derive_patterns(known)
    meta["patterns"] = patterns

    candidates: dict[str, dict] = {}
    for a in asserted:
        if a.get("address", "").endswith("@" + domain):
            candidates[a["address"]] = {"origin": "hunter", "name": a.get("name"),
                                        "position": a.get("position"),
                                        "confidence": a.get("confidence")}
    for n in names:
        sp = _split_name(n)
        if not sp:
            continue
        f, l = sp
        for pname in patterns:
            fn = _PATTERNS.get(pname)
            if not fn:
                continue
            addr = f"{fn(f, l)}@{domain}"
            candidates.setdefault(addr, {"origin": f"derived:{pname}", "name": n})

    cands = dict(list(candidates.items())[:int(cfg.get("max_candidates", 200))])
    meta["candidates"] = len(cands)

    findings = [{
        "type":     "email_candidate",
        "value":    addr,
        "severity": "info",
        "evidence": {**info, "verified": False},
    } for addr, info in cands.items()]

    if not findings:
        meta["reason"] = ("confirmed, but no hunter results and no names file; "
                          "nothing to expand")
        return _result("skipped", [], meta, t0)
    return _result("success", findings, meta, t0)
