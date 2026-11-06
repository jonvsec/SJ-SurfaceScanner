"""
layer4/narrative.py — LLM-generated executive kill chain narrative.

The final module. Takes all findings, the kill chain, EPSS scores, KEV matches,
and sector context, and produces a complete intelligence report narrative:

  1. Executive Summary (3-4 sentences, non-technical)
  2. Attack Narrative (full story: how an attacker would compromise the target)
  3. Critical Findings (top 5 with business impact)
  4. Remediation Roadmap (prioritised by EPSS+KEV+severity)

ALWAYS uses local Ollama — all findings at this point are CONFIDENTIAL
(they contain specific vulnerabilities, credentials, and internal infrastructure).
Never routes to OpenRouter regardless of context size.

This is the deliverable. This is what the client reads.
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
    "name":     "narrative",
    "title":    "Executive Narrative",
    "description": "LLM-written report narrative for decision makers",
    "layer":    4,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": False,
}


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0        = time.monotonic()
    llm       = LLMRouter(config)
    findings: list[dict] = []
    metadata: dict       = {}

    # Collect the key intelligence for narrative generation
    intel = await _gather_intelligence(scope, db)
    metadata["intel_sections"] = list(intel.keys())

    # 1. Executive summary
    exec_summary = await _generate_exec_summary(llm, scope.target.name, intel)
    if exec_summary:
        findings.append({
            "type":  "executive_summary",
            "value": scope.target.name,
            "data":  {"text": exec_summary, "section": "executive_summary"},
        })

    # 2. Full attack narrative
    attack_narrative = await _generate_attack_narrative(llm, scope.target.name, intel)
    if attack_narrative:
        findings.append({
            "type":  "attack_narrative",
            "value": scope.target.name,
            "data":  {"text": attack_narrative, "section": "attack_narrative"},
        })

    # 3. Top findings with business impact
    top_findings = await _generate_top_findings(llm, scope.target.name, intel)
    if top_findings:
        findings.append({
            "type":  "critical_findings_narrative",
            "value": scope.target.name,
            "data":  {"text": top_findings, "section": "critical_findings"},
        })

    # 4. Remediation roadmap
    remediation = await _generate_remediation(llm, scope.target.name, intel)
    if remediation:
        findings.append({
            "type":  "remediation_roadmap",
            "value": scope.target.name,
            "data":  {"text": remediation, "section": "remediation"},
        })

    log.info("narrative.complete", sections=len(findings))
    return {
        "module":   "layer4/narrative",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _gather_intelligence(scope, db) -> dict:
    intel = {
        "company":        scope.target.name,
        "domain":         scope.primary_domain or "",
        "sector":         scope.target.sector or "technology",
        "mode":           scope.mode,
        "attack_paths":   [],
        "initial_vectors": [],
        "kev_matches":    [],
        "epss_top":       [],
        "credentials":    {},
        "overall_risk":   {},
        "sector_context": "",
        "techniques":     [],
    }

    if db is None:
        return intel

    try:
        run_id = await db.get_last_run_id(scope.target.name) or ""
        if not run_id:
            return intel

        # Attack paths
        rows = await db.get_findings(run_id, "attack_path")
        intel["attack_paths"] = [r.get("data", {}) for r in rows[:5]]

        # Initial access vectors
        rows = await db.get_findings(run_id, "initial_access_vector")
        intel["initial_vectors"] = [r.get("data", {}) for r in rows[:10]]

        # KEV matches
        rows = await db.get_findings(run_id, "kev_match")
        intel["kev_matches"] = [
            {
                "cve":     r.get("value"),
                "product": r.get("data", {}).get("product"),
                "name":    r.get("data", {}).get("vulnerability_name"),
                "ransomware": r.get("data", {}).get("known_ransomware"),
            }
            for r in rows[:10]
        ]

        # Top EPSS scores
        rows = await db.get_findings(run_id, "epss_score")
        rows.sort(key=lambda r: r.get("data", {}).get("epss", 0), reverse=True)
        intel["epss_top"] = [
            {"cve": r.get("value"), "epss": r.get("data", {}).get("epss"), "priority": r.get("data", {}).get("priority")}
            for r in rows[:10]
        ]

        # Credential summary
        rows = await db.get_findings(run_id, "credential_summary")
        if rows:
            intel["credentials"] = rows[0].get("data", {})

        # Overall risk
        rows = await db.get_findings(run_id, "overall_risk")
        if rows:
            intel["overall_risk"] = rows[0].get("data", {})

        # Sector context
        rows = await db.get_findings(run_id, "sector_attack_context")
        if rows:
            intel["sector_context"] = rows[0].get("data", {}).get("context", "")

        # Top techniques
        rows = await db.get_findings(run_id, "attack_technique")
        intel["techniques"] = [
            {"id": r.get("value"), "name": r.get("data", {}).get("technique_name")}
            for r in rows[:8]
        ]

    except Exception as exc:
        log.debug("narrative.gather_failed", error=str(exc))

    return intel


async def _generate_exec_summary(llm, company, intel) -> str | None:
    risk     = intel.get("overall_risk", {})
    kev_n    = len(intel.get("kev_matches", []))
    cred_n   = intel.get("credentials", {}).get("total_accounts", 0)
    rating   = risk.get("rating", "UNKNOWN")
    epss_top = intel.get("epss_top", [])
    top_epss = (
        f"{epss_top[0]['epss']:.0%} for {epss_top[0]['cve']}"
        if epss_top and epss_top[0].get("epss") is not None
        else "N/A"
    )

    prompt = f"""Write a 3-4 sentence executive summary for a security assessment of {company}.

Overall risk rating: {rating}
KEV (actively exploited CVEs) found: {kev_n}
Highest EPSS (30-day exploitation probability) score: {top_epss}
Breached employee accounts found: {cred_n}
Sector context: {intel.get("sector_context", "")[:300]}

Write for a C-suite audience. Non-technical. Focus on business risk and urgency.
Be direct. If the risk is critical, say so clearly."""

    try:
        # Executive summary: fast, no thinking needed — structured factual output
        return await llm.complete(
            prepare_for_llm(prompt, max_chars=2000),
            classification="CONFIDENTIAL",
        )
    except Exception as exc:
        log.warning("narrative.exec_summary_failed", error=str(exc))
        return None


async def _generate_attack_narrative(llm, company, intel) -> str | None:
    paths   = intel.get("attack_paths", [])
    vectors = intel.get("initial_vectors", [])

    if not paths and not vectors:
        return None

    # Build a concise summary of the attack surface
    path_summaries = []
    for p in paths[:3]:
        entry  = p.get("entry_point", "unknown")
        impact = p.get("impact", "system compromise")
        epss   = p.get("epss", 0)
        kev    = " [ACTIVELY EXPLOITED]" if p.get("in_kev") else ""
        path_summaries.append(f"- {entry}{kev} → {impact} (EPSS: {epss:.0%})")

    prompt = f"""Write a 4-5 sentence attack narrative for {company}. Describe how a threat actor would realistically compromise this organisation step-by-step.

Most viable attack paths identified:
{chr(10).join(path_summaries) if path_summaries else "Standard phishing + credential stuffing"}

Sector: {intel.get("sector")}
{intel.get("sector_context", "")[:400]}

Write in present tense as if the attack is being described as it happens.
Reference specific findings (e.g. 'using the exposed {paths[0].get("entry_point", "endpoint") if paths else "endpoint"}').
Conclude with the likely impact."""

    try:
        # Attack narrative: use thinking mode for deep chain-of-thought reasoning
        return await llm.complete_with_thinking(
            prepare_for_llm(prompt, max_chars=3000),
            classification="CONFIDENTIAL",
        )
    except Exception as exc:
        log.warning("narrative.attack_narrative_failed", error=str(exc))
        return None


async def _generate_top_findings(llm, company, intel) -> str | None:
    kev     = intel.get("kev_matches", [])
    vectors = intel.get("initial_vectors", [])[:5]
    creds   = intel.get("credentials", {})

    items = []
    for k in kev[:3]:
        items.append(f"CVE: {k.get('cve')} in {k.get('product')} - {k.get('name')} [CISA KEV CONFIRMED]")
    for v in vectors[:3]:
        items.append(f"{v.get('finding_type')}: {v.get('value')} (severity: {v.get('severity')}, EPSS: {v.get('epss', 0):.0%})")
    if creds.get("with_plaintext"):
        items.append(f"Credentials: {creds['with_plaintext']} accounts with plaintext passwords in breach databases")

    if not items:
        return None

    prompt = f"""Write 3-5 critical findings for {company} as bullet points with business impact.

Findings to describe:
{chr(10).join(items)}

For each finding: what it is, why it matters to the business, and immediate action required.
Use plain language. No CVE jargon without explanation."""

    try:
        return await llm.complete(
            prepare_for_llm(prompt, max_chars=3000),
            classification="CONFIDENTIAL",
        )
    except Exception as exc:
        log.warning("narrative.top_findings_failed", error=str(exc))
        return None


async def _generate_remediation(llm, company, intel) -> str | None:
    vectors = sorted(
        intel.get("initial_vectors", []),
        key=lambda v: v.get("score", 0),
        reverse=True,
    )[:8]

    items = []
    for v in vectors:
        epss  = v.get("epss", 0)
        kev   = "[KEV]" if v.get("in_kev") else ""
        items.append(f"{kev} {v.get('finding_type')}: {v.get('value')[:80]} | EPSS {epss:.0%} | {v.get('severity')}")

    if not items:
        return None

    prompt = f"""Create a prioritised remediation roadmap for {company}.

Findings ordered by exploitation risk (EPSS + KEV + severity):
{chr(10).join(items)}

Group into three priority levels:
1. IMMEDIATE (< 48 hours): KEV-confirmed or EPSS > 50%
2. SHORT-TERM (< 30 days): High severity without active exploitation
3. MEDIUM-TERM (< 90 days): Medium severity findings

For each item: specific action, owner (IT/security/dev), effort estimate."""

    try:
        return await llm.complete(
            prepare_for_llm(prompt, max_chars=3000),
            classification="CONFIDENTIAL",
        )
    except Exception as exc:
        log.warning("narrative.remediation_failed", error=str(exc))
        return None
