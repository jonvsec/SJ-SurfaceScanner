"""
layer3/credential_triage.py — credential aggregation, deduplication, and triage.

Pulls credential findings from HIBP, DeHashed, and IntelX and builds a
consolidated, triaged view:
  - Deduplicates across sources
  - Identifies high-value accounts (executives, IT, security roles)
  - Estimates freshness (recent breaches → credentials may still be active)
  - Flags accounts with plaintext passwords (highest priority for reuse)
  - Generates credential stuffing target list

This module produces no new external queries — it's a pure aggregation
and analysis layer over what other Layer 3 modules discovered.

LLM analysis: identifies patterns in breached accounts (common password
patterns, repeated breach appearances = password reuse = higher risk).
"""
from __future__ import annotations

import time
from typing import Any

import structlog

from core.config import Config
from core.llm import LLMRouter
from core.prefilter import prepare_for_llm
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "credential_triage",
    "title":    "Credential Triage",
    "description": "Aggregates, dedupes and prioritises leaked credentials",
    "layer":    3,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": True,
    "depends_on": ['org_chart', 'breach_lookup', 'credential_lookup', 'leak_search'],
}

_HIGH_VALUE_ROLES = {
    "ceo", "cto", "ciso", "cfo", "coo", "cio",
    "vp", "svp", "director", "head", "chief",
    "security", "infosec", "admin", "administrator",
    "devops", "sre", "platform", "infrastructure",
    "it", "sysadmin", "network", "firewall",
}


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0        = time.monotonic()
    llm       = LLMRouter(config)
    findings: list[dict] = []
    metadata: dict       = {}

    # Pull all credential findings from earlier modules in this run
    breach_data    = await _collect_breach_data(scope, db)
    metadata["total_breached_accounts"] = len(breach_data)

    if not breach_data:
        return {
            "module":   "layer3/credential_triage",
            "status":   "partial",
            "findings": [],
            "metadata": {"note": "no breach data found — run hibp, dehashed, intelx first"},
            "duration": time.monotonic() - t0,
            "error":    None,
        }

    # Triage
    with_plaintext  = [e for e in breach_data if e.get("has_password")]
    high_value      = await _identify_high_value(breach_data, scope, db)
    multi_breach    = _find_repeated_accounts(breach_data)

    metadata["with_plaintext_password"] = len(with_plaintext)
    metadata["high_value_accounts"]     = len(high_value)
    metadata["repeated_breach_accounts"] = len(multi_breach)

    # High-value accounts get their own findings
    for account in high_value:
        findings.append({
            "type":  "high_value_credential",
            "value": account["email"],
            "data":  {**account, "severity": "critical"},
        })

    # Plaintext password accounts
    for account in with_plaintext:
        if not any(f["value"] == account["email"] for f in findings):
            findings.append({
                "type":  "plaintext_credential",
                "value": account["email"],
                "data":  {**account, "severity": "critical"},
            })

    # Multi-breach = password reuse signal
    for account in multi_breach:
        findings.append({
            "type":  "repeated_breach_account",
            "value": account["email"],
            "data": {
                **account,
                "note":     "Account appears in multiple breaches — high password reuse risk",
                "severity": "high",
            },
        })

    # Summary finding
    findings.append({
        "type":  "credential_summary",
        "value": scope.target.name,
        "data": {
            "total_accounts":         len(breach_data),
            "with_plaintext":         len(with_plaintext),
            "high_value_accounts":    len(high_value),
            "repeated_breach":        len(multi_breach),
            "credential_stuffing_risk": "critical" if with_plaintext else ("high" if multi_breach else "medium"),
        },
    })

    # LLM: risk narrative for credentials section
    if breach_data:
        narrative = await _credential_narrative(llm, scope.target.name, metadata, scope.data_classification)
        if narrative:
            findings.append({
                "type":  "credential_risk_narrative",
                "value": scope.target.name,
                "data":  {"narrative": narrative},
            })

    log.info("credentials.complete", **metadata)
    return {
        "module":   "layer3/credential_triage",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _collect_breach_data(scope, db) -> list[dict]:
    if db is None:
        return []
    accounts: dict[str, dict] = {}
    try:
        run_id = await db.get_last_run_id(scope.target.name) or ""
        if not run_id:
            return []
        for finding_type in ("account_breach", "leaked_credential"):
            rows = await db.get_findings(run_id, finding_type)
            for row in rows:
                email = row.get("value", "")
                data  = row.get("data", {})
                if email not in accounts:
                    accounts[email] = {
                        "email":        email,
                        "breaches":     [],
                        "has_password": False,
                        "sources":      [],
                    }
                accounts[email]["breaches"].append(data.get("breach") or data.get("database_name", ""))
                accounts[email]["sources"].append(data.get("source", ""))
                if data.get("has_password"):
                    accounts[email]["has_password"] = True
    except Exception as exc:
        log.debug("credentials.db_failed", error=str(exc))
    return list(accounts.values())


async def _identify_high_value(accounts: list[dict], scope, db) -> list[dict]:
    high_value  = []
    name_tokens = await _get_executive_name_tokens(scope, db)

    for account in accounts:
        email    = account.get("email", "")
        username = email.split("@")[0].lower() if "@" in email else ""

        role_match = next((role for role in _HIGH_VALUE_ROLES if role in username), None)
        if role_match:
            account["high_value_reason"] = f"role keyword '{role_match}' in email"
            high_value.append(account)
            continue

        name_match = next((name for name in name_tokens if name in username), None)
        if name_match:
            account["high_value_reason"] = f"matches known executive name '{name_match}'"
            high_value.append(account)

    return high_value


async def _get_executive_name_tokens(scope, db) -> set[str]:
    """Lowercase name fragments (>2 chars) for people whose title implies seniority."""
    tokens: set[str] = set()
    if db is None:
        return tokens
    try:
        run_id = await db.get_last_run_id(scope.target.name) or ""
        if not run_id:
            return tokens
        rows = await db.get_findings(run_id, "person")
        for row in rows:
            title = (row.get("data", {}) or {}).get("title", "") or ""
            if not any(role in title.lower() for role in _HIGH_VALUE_ROLES):
                continue
            for part in row.get("value", "").split():
                part = part.strip(".,").lower()
                if len(part) > 2:
                    tokens.add(part)
    except Exception as exc:
        log.debug("credentials.executive_names_failed", error=str(exc))
    return tokens


def _find_repeated_accounts(accounts: list[dict]) -> list[dict]:
    return [a for a in accounts if len(a.get("breaches", [])) > 1]


async def _credential_narrative(llm, company, stats, classification) -> str | None:
    prompt = f"""Write a 2-3 sentence executive summary for the credential exposure findings for {company}:

Statistics:
- Total breached accounts found: {stats.get('total_breached_accounts', 0)}
- Accounts with plaintext passwords: {stats.get('with_plaintext_password', 0)}
- High-value accounts (executive/IT): {stats.get('high_value_accounts', 0)}
- Multi-breach accounts (password reuse): {stats.get('repeated_breach_accounts', 0)}

Focus on business risk and immediate action required. Be specific and direct."""
    try:
        return await llm.complete(
            prepare_for_llm(prompt, max_chars=1000),
            classification=classification,
        )
    except Exception:
        return None
