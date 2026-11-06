"""
layer4/sector_intel.py — sector-specific threat intelligence.

Provides threat context tailored to the target's industry sector:
  - Which APT groups most frequently target this sector
  - Most common initial access techniques for this sector (MITRE)
  - Relevant regulations and compliance frameworks
  - Common misconfiguration patterns in this sector
  - Recent sector-specific incidents and CVEs

Sector is confirmed by Layer 0 (EDGAR SIC code + LLM inference).
If sector is unknown, defaults to generic threat landscape.

This is what separates a generic report from an analyst-quality report:
"APT41 (China) frequently targets fintech for financial gain and IP theft.
Your exposed Citrix CVE-2023-3519 is a known initial access vector for APT41."
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
    "name":     "sector_intel",
    "title":    "Sector Threat Intel",
    "description": "Sector-specific actors, tactics and CVE families",
    "layer":    4,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": True,
}

# Static threat intelligence by sector
_SECTOR_INTEL: dict[str, dict] = {
    "fintech": {
        "apt_groups":    ["APT41", "Lazarus Group", "FIN7", "Carbanak"],
        "tactics":       ["T1566 Phishing", "T1190 Public-Facing App Exploit", "T1078 Valid Accounts"],
        "common_cves":   ["Citrix CVEs", "Confluence CVEs", "Exchange CVEs"],
        "regulations":   ["PCI-DSS", "SOX", "FFIEC", "GDPR"],
        "high_risk":     ["payment APIs", "transaction systems", "customer PII", "wire transfer portals"],
        "social_eng":    "BEC and CFO fraud are highest frequency. Target finance and treasury teams.",
    },
    "healthcare": {
        "apt_groups":    ["Lazarus Group", "FIN12", "ALPHV/BlackCat"],
        "tactics":       ["T1566 Phishing", "T1486 Ransomware", "T1078 Valid Accounts"],
        "common_cves":   ["VMware CVEs", "Citrix CVEs", "Fortinet CVEs"],
        "regulations":   ["HIPAA", "HITECH", "SOC 2", "GDPR"],
        "high_risk":     ["EHR systems", "medical devices", "patient data", "insurance systems"],
        "social_eng":    "Clinical staff are high-value phishing targets. COVID-era device proliferation created legacy attack surface.",
    },
    "manufacturing": {
        "apt_groups":    ["APT10", "Sandworm", "Volt Typhoon"],
        "tactics":       ["T1190 Public-Facing App", "T1133 External Remote Services", "T1566 Phishing"],
        "common_cves":   ["OT/SCADA CVEs", "VPN CVEs", "RDP vulnerabilities"],
        "regulations":   ["NIST CSF", "IEC 62443", "ISO 27001"],
        "high_risk":     ["OT/ICS networks", "supply chain portals", "CAD/design systems", "ERP"],
        "social_eng":    "IT/OT convergence creates bridges. Spear-phishing engineers with fake CAD updates.",
    },
    "technology": {
        "apt_groups":    ["APT41", "Cozy Bear", "Scattered Spider"],
        "tactics":       ["T1190 Public-Facing App", "T1078 Valid Accounts", "T1566 Phishing"],
        "common_cves":   ["Log4Shell", "Spring4Shell", "Confluence CVEs", "GitLab CVEs"],
        "regulations":   ["SOC 2", "ISO 27001", "GDPR", "CCPA"],
        "high_risk":     ["CI/CD pipelines", "cloud credentials", "customer data", "API keys"],
        "social_eng":    "Supply chain attacks (malicious npm/PyPI packages) and CI/CD compromise are primary vectors.",
    },
    "retail": {
        "apt_groups":    ["FIN7", "Carbanak", "Magecart"],
        "tactics":       ["T1056.003 Web Portal Capture", "T1195 Supply Chain Compromise", "T1059 Command Execution"],
        "common_cves":   ["Magento CVEs", "WooCommerce CVEs", "Shopify app CVEs"],
        "regulations":   ["PCI-DSS", "GDPR", "CCPA"],
        "high_risk":     ["e-commerce checkout pages", "payment processors", "loyalty databases", "POS systems"],
        "social_eng":    "Magecart skimming via third-party JS is the primary threat. Check all third-party scripts.",
    },
    "government": {
        "apt_groups":    ["Cozy Bear (APT29)", "Fancy Bear (APT28)", "Volt Typhoon", "APT40"],
        "tactics":       ["T1566 Phishing", "T1190 Public-Facing App", "T1133 External Remote Services"],
        "common_cves":   ["VMware CVEs", "Pulse Secure CVEs", "Exchange CVEs", "Ivanti CVEs"],
        "regulations":   ["FedRAMP", "FISMA", "NIST SP 800-53", "CMMC"],
        "high_risk":     ["email systems", "VPN concentrators", "classified network boundaries", "contractor portals"],
        "social_eng":    "Spear-phishing of senior officials. Watering hole attacks on government news sites.",
    },
}

_DEFAULT_INTEL = {
    "apt_groups":  ["Multiple threat actors"],
    "tactics":     ["T1566 Phishing", "T1190 Public-Facing App", "T1078 Valid Accounts"],
    "common_cves": ["Common web application CVEs"],
    "regulations": ["ISO 27001", "GDPR"],
    "high_risk":   ["web applications", "credentials", "cloud storage"],
    "social_eng":  "Phishing remains the most common initial access vector across all sectors.",
}


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    llm     = LLMRouter(config)
    findings: list[dict] = []
    metadata: dict       = {}

    sector = await _determine_sector(scope, db)
    metadata["sector"] = sector

    intel = _SECTOR_INTEL.get(sector.lower(), _DEFAULT_INTEL)

    findings.append({
        "type":  "sector_threat_intel",
        "value": scope.target.name,
        "data": {
            "sector":        sector,
            "company":       scope.target.name,
            "apt_groups":    intel.get("apt_groups", []),
            "primary_tactics": intel.get("tactics", []),
            "common_cves":   intel.get("common_cves", []),
            "regulations":   intel.get("regulations", []),
            "high_risk_assets": intel.get("high_risk", []),
            "social_engineering_context": intel.get("social_eng"),
        },
    })

    # LLM: generate sector-specific attack narrative context
    context = await _generate_sector_context(llm, scope.target.name, sector, intel, scope.data_classification)
    if context:
        findings.append({
            "type":  "sector_attack_context",
            "value": scope.target.name,
            "data":  {"context": context, "sector": sector},
        })

    return {
        "module":   "layer4/sector_intel",
        "status":   "success",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _determine_sector(scope, db) -> str:
    if scope.target.sector:
        return scope.target.sector

    if db is None:
        return "technology"

    try:
        run_id = await db.get_last_run_id(scope.target.name) or ""
        if not run_id:
            return "technology"
        rows = await db.get_findings(run_id, "corporate_profile")
        for row in rows:
            sic_desc = row.get("data", {}).get("sic_desc", "")
            if sic_desc:
                return _sic_to_sector(sic_desc)
    except Exception:
        pass
    return "technology"


def _sic_to_sector(sic_desc: str) -> str:
    sic_lower = sic_desc.lower()
    if any(w in sic_lower for w in ["bank", "financial", "insurance", "invest", "credit"]):
        return "fintech"
    if any(w in sic_lower for w in ["health", "hospital", "medical", "pharma", "biotech"]):
        return "healthcare"
    if any(w in sic_lower for w in ["manufactur", "industrial", "automotive", "aerospace"]):
        return "manufacturing"
    if any(w in sic_lower for w in ["software", "computer", "technology", "internet", "data"]):
        return "technology"
    if any(w in sic_lower for w in ["retail", "store", "shop", "commerce", "wholesale"]):
        return "retail"
    if any(w in sic_lower for w in ["government", "public", "federal", "state", "defense"]):
        return "government"
    return "technology"


async def _generate_sector_context(llm, company, sector, intel, classification) -> str | None:
    apt_list = ", ".join(intel.get("apt_groups", [])[:4])
    prompt = f"""In 3-4 sentences, describe the specific threat landscape for {company} as a {sector} company.

Key facts: APT groups targeting this sector include {apt_list}.
Primary initial access: {', '.join(intel.get('tactics', [])[:3])}.
Commonly exploited CVE families in this sector: {', '.join(intel.get('common_cves', [])[:4])}.
High-risk assets: {', '.join(intel.get('high_risk', [])[:4])}.

Be specific about how these threat actors operate and what makes {company} an attractive target.
Do not be generic. Reference the specific APT groups and their known TTPs."""
    try:
        return await llm.complete(
            prepare_for_llm(prompt, max_chars=1500),
            classification=classification,
        )
    except Exception:
        return None
