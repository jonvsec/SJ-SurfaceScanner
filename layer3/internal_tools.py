"""
layer3/internal_tools.py — internal tools and work environment intelligence.

Builds a picture of the daily tooling employees use, which reveals
attack surfaces not visible from external scanning:

  - Glassdoor reviews: "We use Jira, Confluence, Slack, and AWS internally"
  - LinkedIn profiles: skills sections reveal internal stack
  - GitHub dotfiles: personal configs leak tool versions and internal URLs
  - Stack Overflow: questions about internal systems sometimes posted publicly

Cross-referenced with job postings from Layer 1 to build high-confidence
technology map including collaboration tools, CI/CD, monitoring, and security.

This is how you find that they use a 3-year-old Confluence version (CVE-rich)
or that their VPN is a specific product with known issues.
"""
from __future__ import annotations

import re
import time
from typing import Any

import httpx
import structlog

from core.config import Config
from core.llm import LLMRouter
from core.prefilter import prepare_for_llm
from core.ratelimiter import RateLimiter
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "internal_tools",
    "title":    "Internal Tooling",
    "description": "Day-to-day systems inferred from public signals",
    "layer":    3,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": True,
    "depends_on": ['org_chart'],
}

_TIMEOUT = 20

_TOOL_CATEGORIES = {
    "collaboration":  ["Slack", "Teams", "Zoom", "Google Meet", "Webex"],
    "project_mgmt":   ["Jira", "Linear", "Asana", "Monday", "Notion", "Confluence"],
    "source_control": ["GitHub", "GitLab", "Bitbucket", "Perforce"],
    "ci_cd":          ["Jenkins", "CircleCI", "GitHub Actions", "GitLab CI", "ArgoCD", "Spinnaker"],
    "cloud":          ["AWS", "Azure", "GCP", "Oracle Cloud", "IBM Cloud"],
    "monitoring":     ["Datadog", "New Relic", "Dynatrace", "Grafana", "Prometheus", "Splunk", "Elastic"],
    "security":       ["CrowdStrike", "SentinelOne", "Palo Alto", "Okta", "Duo", "Ping", "CyberArk"],
    "databases":      ["PostgreSQL", "MySQL", "MongoDB", "Redis", "Cassandra", "DynamoDB", "Snowflake"],
    "vpn_remote":     ["Cisco AnyConnect", "Pulse Secure", "GlobalProtect", "OpenVPN", "Tailscale", "ZeroTier"],
    "email":          ["Google Workspace", "Office 365", "Exchange", "Proofpoint", "Mimecast"],
}


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    llm     = LLMRouter(config)
    findings: list[dict] = []
    metadata: dict       = {}

    company = scope.target.name
    all_snippets: list[str] = []

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        searxng_url = config.searxng.url
        queries = [
            f'"{company}" review "we use" OR "tools" site:glassdoor.com OR site:indeed.com',
            f'"{company}" "internal tools" OR "tech stack" OR "engineering blog"',
            f'"{company}" engineering site:medium.com OR site:dev.to OR site:engineering.{scope.primary_domain or "company"}.com',
        ]
        for q in queries:
            await limiter.acquire("default")
            try:
                r = await client.get(f"{searxng_url}/search", params={"q": q, "format": "json"})
                r.raise_for_status()
                for result in r.json().get("results", []):
                    snippet = result.get("content", "") + " " + result.get("title", "")
                    all_snippets.append(snippet)
            except Exception:
                pass

    # Cross-reference with job posting data from DB
    job_tech = await _get_job_tech_from_db(scope, db)
    all_snippets.extend(job_tech)

    # Extract tool mentions
    all_text  = " ".join(all_snippets)
    tool_hits = _extract_tools(all_text)
    metadata["tools_identified"]  = sum(len(tools) for tools in tool_hits.values())
    metadata["tool_categories"]   = len(tool_hits)

    for category, tools in tool_hits.items():
        if tools:
            findings.append({
                "type":  "internal_tool",
                "value": f"{company} - {category}",
                "data": {
                    "company":  company,
                    "category": category,
                    "tools":    tools,
                    "source":   "glassdoor_linkedin_web",
                },
            })

    # LLM: infer security posture from tool stack
    if tool_hits:
        posture = await _infer_security_posture(llm, company, tool_hits, scope.data_classification)
        if posture:
            findings.append({
                "type":  "security_posture",
                "value": company,
                "data":  posture,
            })

    return {
        "module":   "layer3/internal_tools",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


def _extract_tools(text: str) -> dict[str, list[str]]:
    result = {}
    for category, tools in _TOOL_CATEGORIES.items():
        found = []
        for tool in tools:
            if re.search(r"\b" + re.escape(tool) + r"\b", text, re.IGNORECASE):
                found.append(tool)
        if found:
            result[category] = found
    return result


async def _get_job_tech_from_db(scope, db) -> list[str]:
    if db is None:
        return []
    try:
        run_id = await db.get_last_run_id(scope.target.name) or ""
        if not run_id:
            return []
        rows = await db.get_findings(run_id, "inferred_tech_stack")
        return [str(r.get("data", {}).get("technologies", [])) for r in rows]
    except Exception:
        return []


async def _infer_security_posture(llm, company, tool_hits, classification) -> dict | None:
    tools_summary = "\n".join(f"{cat}: {', '.join(tools)}" for cat, tools in tool_hits.items())
    prompt = f"""Based on the tool stack identified for {company}:

{tools_summary}

Assess their security posture as JSON:
{{
  "edr_solution": "identified EDR or null",
  "idp_solution": "identified identity provider or null",
  "mfa_likely": true/false,
  "cloud_maturity": "high/medium/low",
  "security_gaps": ["list of likely gaps based on missing security tools"],
  "attack_recommendations": ["list of attack vectors that are likely viable given this stack"],
  "confidence": "high/medium/low"
}}"""
    try:
        return await llm.complete_json(
            prepare_for_llm(prompt, max_chars=2000),
            classification=classification,
        )
    except Exception:
        return None
