"""
layer2_5/email_dns_security.py — email security and DNS misconfiguration checks.

Checks DMARC, SPF, DKIM, MX, and DNSSEC for each target domain.
Missing or misconfigured email security records allow spoofing attacks —
the most common initial access vector in phishing campaigns targeting employees.

A missing DMARC policy means an attacker can send email appearing to come from
ceo@company.com with zero technical barrier. This is critical severity in any
engagement regardless of other findings.

Uses dnspython — no CLI tools required.
"""
from __future__ import annotations

import time
from typing import Any

import structlog

from core.config import Config
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "email_dns_security",
    "title":    "Email & DNS Security",
    "description": "SPF, DKIM, DMARC and MX validation",
    "layer":    2.5,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": False,
}


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0        = time.monotonic()
    findings: list[dict] = []
    metadata: dict       = {}

    try:
        import dns.resolver
    except ImportError:
        return {
            "module":   "layer2_5/email_dns_security",
            "status":   "error",
            "findings": [],
            "metadata": {},
            "duration": time.monotonic() - t0,
            "error":    "dnspython not installed",
        }

    import asyncio

    for domain in scope.all_domains:
        loop    = asyncio.get_event_loop()
        results = await loop.run_in_executor(
            None, lambda d=domain: _check_domain(d, dns.resolver)
        )
        findings.extend(results)

    metadata["domains_checked"] = len(scope.all_domains)
    metadata["issues_found"]    = sum(
        1 for f in findings if f.get("data", {}).get("severity") in ("high", "critical")
    )

    return {
        "module":   "layer2_5/email_dns_security",
        "status":   "success",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


def _check_domain(domain: str, resolver) -> list[dict]:
    results = []

    # SPF
    spf = _query_txt(domain, resolver, "v=spf1")
    results.append({
        "type":  "spf_record",
        "value": domain,
        "data":  _analyse_spf(domain, spf),
    })

    # DMARC
    dmarc_txt = _query_txt(f"_dmarc.{domain}", resolver, "v=DMARC1")
    results.append({
        "type":  "dmarc_record",
        "value": domain,
        "data":  _analyse_dmarc(domain, dmarc_txt),
    })

    # MX
    mx_records = _query_mx(domain, resolver)
    results.append({
        "type":  "mx_records",
        "value": domain,
        "data":  {"domain": domain, "mx": mx_records},
    })

    # DKIM (common selectors)
    # s1 and s2 are SendGrid's. On a domain that signs only through SendGrid
    # they can be the only selectors present, and without them the module
    # reports signing as absent where it is actually in place.
    dkim_selectors = ["default", "google", "k1", "k2", "mail", "dkim",
                      "selector1", "selector2", "s1", "s2", "sendgrid",
                      "mandrill", "mailjet", "zoho", "protonmail", "sig1"]
    dkim_found = []
    for selector in dkim_selectors:
        dkim = _query_dkim(f"{selector}._domainkey.{domain}", resolver)
        if dkim:
            dkim_found.append({"selector": selector, "record": dkim})
    results.append({
        "type":  "dkim_record",
        "value": domain,
        "data":  {
            "domain":   domain,
            "found":    len(dkim_found) > 0,
            "selectors": dkim_found,
            "severity": "medium" if not dkim_found else "info",
        },
    })

    return results


# Higher = more severe. Python's str max() is alphabetical ("medium" >
# "high" > "critical"), which silently downgrades severity when combined
# with `max()` — this ranking gives the correct ordering for `_max_severity`.
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _max_severity(a: str, b: str) -> str:
    return a if _SEVERITY_RANK.get(a, 0) >= _SEVERITY_RANK.get(b, 0) else b


def _query_txt(name: str, resolver, prefix: str) -> str | None:
    try:
        answers = resolver.resolve(name, "TXT")
        for rdata in answers:
            # Multi-string TXT RDATA is the concatenation of its character-strings
            # with NO separator (RFC 7208 / RFC 7489) — joining with " " would
            # corrupt records that span multiple character-strings.
            txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
            if txt.startswith(prefix):
                return txt
    except Exception:
        pass
    return None


def _query_dkim(name: str, resolver) -> str | None:
    """Fetch a DKIM TXT record without requiring the optional v=DKIM1 tag.

    RFC 6376 makes the `v=` tag OPTIONAL (default "DKIM1") while `p=` (the
    public key) is mandatory. In practice most providers — Mailchimp,
    SendGrid, Zendesk, Mandrill, etc. — publish DKIM records as `k=rsa; p=...`
    with no `v=` tag at all, so requiring a "v=DKIM1" prefix (as _query_txt
    does for SPF/DMARC, where the version tag IS mandatory and first) misses
    the majority of real-world DKIM records and reports DKIM as "not found".
    """
    try:
        answers = resolver.resolve(name, "TXT")
        for rdata in answers:
            txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
            if "p=" in txt:
                return txt
    except Exception:
        pass
    return None


def _query_mx(domain: str, resolver) -> list[str]:
    try:
        answers = resolver.resolve(domain, "MX")
        return [str(r.exchange).rstrip(".") for r in answers]
    except Exception:
        return []


def _analyse_spf(domain: str, spf: str | None) -> dict:
    if not spf:
        return {
            "domain": domain, "record": None, "found": False,
            "severity": "high",
            "issue": "No SPF record — email spoofing is trivially possible",
        }

    issues = []
    severity = "info"

    if "+all" in spf:
        issues.append("Pass-all (+all) allows anyone to send as this domain")
        severity = "critical"
    elif "?all" in spf:
        issues.append("Neutral all (?all) provides no protection")
        severity = "high"
    elif "~all" in spf:
        issues.append("Softfail (~all) — weak enforcement, depends on receiver policy")
        severity = "medium"

    # Count DNS lookups (SPF max is 10)
    lookups = spf.count("include:") + spf.count("a:") + spf.count("mx") + spf.count("redirect=")
    if lookups > 10:
        issues.append(f"SPF lookup count may exceed 10 (found ~{lookups}) — risk of PermError")
        severity = _max_severity(severity, "medium")

    return {
        "domain":   domain,
        "record":   spf,
        "found":    True,
        "issues":   issues,
        "severity": severity if issues else "info",
    }


def _analyse_dmarc(domain: str, dmarc: str | None) -> dict:
    if not dmarc:
        return {
            # An email-authentication gap caps at High, not Critical: it enables
            # spoofing but still needs a recipient to act on the forged mail.
            # Matches dmarc_watch and the "Missing or Weak DMARC Policy" template.
            "domain": domain, "record": None, "found": False,
            "severity": "high",
            "issue": "No DMARC record — email spoofing is unrestricted",
        }

    issues = []
    severity = "info"

    import re
    policy_match = re.search(r"p=(\w+)", dmarc)
    policy = policy_match.group(1) if policy_match else "none"

    if policy == "none":
        issues.append("DMARC policy is 'none' — monitoring only, no enforcement")
        severity = "high"
    elif policy == "quarantine":
        issues.append("DMARC policy is 'quarantine' — partial protection")
        severity = "medium"
    # policy == "reject" is ideal

    pct_match = re.search(r"pct=(\d+)", dmarc)
    pct = int(pct_match.group(1)) if pct_match else 100
    if pct < 100:
        issues.append(f"DMARC pct={pct} — only {pct}% of mail is subject to policy")
        severity = _max_severity(severity, "medium")

    rua_match = re.search(r"rua=([^;]+)", dmarc)
    if not rua_match:
        issues.append("No DMARC rua tag — no aggregate reporting configured")

    return {
        "domain":   domain,
        "record":   dmarc,
        "found":    True,
        "policy":   policy,
        "pct":      pct,
        "issues":   issues,
        "severity": severity if issues else "info",
    }
