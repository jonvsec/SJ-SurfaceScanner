"""
layer4/kill_chain.py — kill chain assembly with EPSS+KEV+MITRE correlation.

Assembles all findings into a structured attack kill chain. This is the
core differentiator of SurfaceScanner — not just a finding list but a
coherent attack story with evidence-backed prioritisation.

For each potential attack path:
  1. Initial access vector (how does the attacker get in?)
  2. Execution/persistence mechanism
  3. Lateral movement opportunities
  4. Target assets (what can they reach?)
  5. Impact (what's the worst case?)

Prioritisation uses EPSS + KEV + MITRE + finding severity:
  Priority = EPSS_score * (1.5 if in KEV) * severity_multiplier
  A CVSS 5.5 with EPSS 0.89 + KEV + active APT = actionable immediately.
  A CVSS 9.8 with EPSS 0.001 + not in KEV = fix next quarter.
"""
from __future__ import annotations

import time
from typing import Any

import structlog

from core.config import Config
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "kill_chain",
    "title":    "Kill Chain",
    "description": "Attack path assembly weighted by EPSS, KEV and severity",
    "layer":    4,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": False,
}

_SEVERITY_MULTIPLIER = {
    "critical": 2.0,
    "high":     1.5,
    "medium":   1.0,
    "low":      0.5,
    "info":     0.1,
}

# Finding types that represent initial access vectors
_INITIAL_ACCESS_TYPES = {
    "kev_match", "nuclei_finding", "subdomain_takeover", "missing_dmarc",
    "cors_misconfiguration", "weak_spf", "leaked_credential", "data_breach",
    "exposed_api_docs", "graphql_endpoint", "zone_transfer_vulnerability",
    "s3_bucket", "gcs_bucket", "azure_blob", "firebase_rtdb",
    "potential_secret", "js_secret", "exposed_admin", "directory_listing",
    "exposed_config", "exposed_backup", "wp_plugin_cve",
}

# Finding types that represent lateral movement opportunities
_LATERAL_MOVEMENT_TYPES = {
    "open_port", "service_banner", "cms_detected", "auth_endpoint",
    "waf_detected", "no_waf", "ixp_membership",
}

# Finding types representing valuable targets
_TARGET_ASSET_TYPES = {
    "corporate_profile", "company_profile", "subsidiary", "person",
    "high_value_credential", "bgp_prefix", "ip_range", "resolved_host",
    "aws_api_gateway", "cloudfront_distribution", "azure_ad_tenant",
}


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0        = time.monotonic()
    findings: list[dict] = []
    metadata: dict       = {}

    # Collect all layer 0-3 findings and layer 4 enrichment
    all_data = await _collect_all(scope, db)
    metadata["findings_processed"] = sum(len(v) for v in all_data.values())

    # 1. Build prioritised initial access vectors
    initial_access = _build_initial_access(all_data)
    metadata["initial_access_vectors"] = len(initial_access)

    for vector in initial_access[:10]:  # top 10
        findings.append({
            "type":  "initial_access_vector",
            "value": vector["value"],
            "data":  vector,
        })

    # 2. Build attack paths (IA → lateral → target)
    attack_paths = _build_attack_paths(initial_access, all_data)
    metadata["attack_paths"] = len(attack_paths)

    for path in attack_paths[:5]:  # top 5 most viable paths
        findings.append({
            "type":  "attack_path",
            "value": f"{path['entry_point']} → {path['target']}",
            "data":  path,
        })

    # 3. Credential attack opportunities
    cred_attacks = _build_cred_attack_chains(all_data)
    findings.extend(cred_attacks)

    # 4. Overall risk rating
    risk = _calculate_risk_rating(initial_access, all_data)
    findings.append({
        "type":  "overall_risk",
        "value": scope.target.name,
        "data":  risk,
    })
    metadata["overall_risk"] = risk["rating"]

    log.info("killchain.complete",
             vectors=metadata["initial_access_vectors"],
             paths=metadata["attack_paths"],
             risk=metadata["overall_risk"])

    return {
        "module":   "layer4/kill_chain",
        "status":   "success",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _collect_all(scope, db) -> dict[str, list[dict]]:
    if db is None:
        return {}
    result: dict[str, list[dict]] = {}
    try:
        run_id = await db.get_last_run_id(scope.target.name) or ""
        if not run_id:
            return {}

        all_types = (
            list(_INITIAL_ACCESS_TYPES)
            + list(_LATERAL_MOVEMENT_TYPES)
            + list(_TARGET_ASSET_TYPES)
            + ["epss_score", "kev_match", "attack_technique", "sector_threat_intel",
               "corporate_profile", "subsidiary", "subdomain", "resolved_host"]
        )

        for ftype in set(all_types):
            rows = await db.get_findings(run_id, ftype)
            if rows:
                result[ftype] = rows
    except Exception as exc:
        log.debug("killchain.collect_failed", error=str(exc))
    return result


def _epss_and_kev_for_finding(finding: dict, epss_map: dict, kev_set: set) -> tuple[float, bool]:
    """
    Resolve the EPSS score and KEV status for a finding.

    Most initial-access findings (nuclei_finding, wp_plugin_cve) carry their
    CVE(s) in `data["cve_id"]`, while `finding["value"]` is the affected
    host — not a CVE. kev_match findings (and some wp_plugin_cve) instead
    carry the CVE directly as `value`. Check both so EPSS/KEV scores
    actually attach to the vulnerability findings they describe.
    """
    data = finding.get("data", {})
    cves = {c.upper() for c in data.get("cve_id", []) if isinstance(c, str)}
    value = finding.get("value", "")
    if isinstance(value, str) and value.upper().startswith("CVE-"):
        cves.add(value.upper())

    if not cves:
        return 0, False

    epss   = max((epss_map.get(cve, 0) for cve in cves), default=0)
    in_kev = any(cve in kev_set for cve in cves)
    return epss, in_kev


def _build_initial_access(all_data: dict) -> list[dict]:
    """Build and score initial access vectors."""
    vectors = []

    # EPSS-enriched findings get highest weight
    epss_map = {
        r["value"].upper(): r["data"].get("epss", 0)
        for r in all_data.get("epss_score", [])
    }
    kev_set = {
        r["value"].upper() for r in all_data.get("kev_match", [])
    }

    for ftype in _INITIAL_ACCESS_TYPES:
        for finding in all_data.get(ftype, []):
            severity = finding.get("data", {}).get("severity", "medium")
            epss, in_kev = _epss_and_kev_for_finding(finding, epss_map, kev_set)

            score = (
                epss
                * (1.5 if in_kev else 1.0)
                * _SEVERITY_MULTIPLIER.get(severity, 1.0)
                + _SEVERITY_MULTIPLIER.get(severity, 1.0) * 0.1  # base score
            )

            vectors.append({
                "finding_type": ftype,
                "value":        finding.get("value", ""),
                "score":        round(score, 4),
                "epss":         epss,
                "in_kev":       in_kev,
                "severity":     severity,
                "data":         finding.get("data", {}),
                "mitre":        _map_to_mitre(ftype),
                "requires_manual_verification": finding.get("data", {}).get(
                    "requires_manual_verification", False
                ),
            })

    # Sort by score descending
    vectors.sort(key=lambda v: v["score"], reverse=True)
    return vectors


def _build_attack_paths(initial_access: list[dict], all_data: dict) -> list[dict]:
    """Construct plausible attack paths from initial access to impact."""
    paths = []
    lateral_movement = all_data.get("open_port", []) + all_data.get("service_banner", [])
    targets          = all_data.get("high_value_credential", []) + all_data.get("subsidiary", [])

    for vector in initial_access[:5]:
        path = {
            "entry_point":      vector["value"],
            "initial_technique": vector.get("mitre", {}).get("technique_id", ""),
            "entry_severity":   vector["severity"],
            "epss":             vector["epss"],
            "in_kev":           vector["in_kev"],
            "score":            vector["score"],
            "lateral_opportunities": [],
            "target":           "corporate infrastructure",
            "impact":           _infer_impact(vector["finding_type"]),
            "requires_manual_verification": vector.get("requires_manual_verification", False),
        }

        # Add lateral movement options
        for lm in lateral_movement[:3]:
            port    = lm.get("data", {}).get("port")
            service = lm.get("data", {}).get("service", "")
            if port or service:
                path["lateral_opportunities"].append(
                    f"{service} ({port})" if port else service
                )

        # Add high-value target
        if targets:
            path["target"] = targets[0].get("value", "corporate infrastructure")

        paths.append(path)

    return paths


def _build_cred_attack_chains(all_data: dict) -> list[dict]:
    chains = []
    hv_creds = all_data.get("high_value_credential", [])
    pt_creds = all_data.get("plaintext_credential", [])

    if pt_creds:
        chains.append({
            "type":  "credential_attack_chain",
            "value": "Credential Stuffing",
            "data": {
                "technique":     "T1110.004 Credential Stuffing",
                "accounts":      len(pt_creds),
                "severity":      "critical",
                "description":   f"{len(pt_creds)} accounts with plaintext passwords — immediate credential stuffing risk",
                "recommended_action": "Enforce password reset for all listed accounts. Enable MFA immediately.",
            },
        })

    if hv_creds:
        chains.append({
            "type":  "credential_attack_chain",
            "value": "Executive Account Compromise",
            "data": {
                "technique":     "T1078 Valid Accounts",
                "accounts":      len(hv_creds),
                "severity":      "critical",
                "description":   f"{len(hv_creds)} high-value accounts (executive/IT) found in breach data",
                "recommended_action": "Immediate password reset + MFA enrollment for all listed accounts.",
            },
        })

    return chains


def _calculate_risk_rating(initial_access: list[dict], all_data: dict) -> dict:
    kev_count      = len(all_data.get("kev_match", []))
    critical_count = sum(1 for v in initial_access if v["severity"] == "critical")
    high_count     = sum(1 for v in initial_access if v["severity"] == "high")
    cred_breach    = len(all_data.get("leaked_credential", [])) + len(all_data.get("data_breach", []))
    max_epss       = max((v["epss"] for v in initial_access), default=0)

    if kev_count > 0 or (max_epss > 0.7 and critical_count > 0):
        rating = "CRITICAL"
        summary = f"{kev_count} actively exploited CVEs (KEV), {critical_count} critical findings"
    elif critical_count > 0 or cred_breach > 100 or max_epss > 0.4:
        rating = "HIGH"
        summary = f"{critical_count} critical findings, {cred_breach} breached accounts"
    elif high_count > 0 or cred_breach > 0:
        rating = "MEDIUM"
        summary = f"{high_count} high-severity findings, {cred_breach} breached accounts"
    else:
        rating = "LOW"
        summary = "No critical or high-severity findings detected"

    return {
        "rating":           rating,
        "summary":          summary,
        "kev_count":        kev_count,
        "critical_vectors": critical_count,
        "high_vectors":     high_count,
        "breached_accounts": cred_breach,
        "max_epss":         round(max_epss, 3),
        "action_required":  rating in ("CRITICAL", "HIGH"),
    }


def _map_to_mitre(finding_type: str) -> dict:
    mapping = {
        "nuclei_finding":      {"technique_id": "T1190", "tactic": "initial-access"},
        "kev_match":           {"technique_id": "T1190", "tactic": "initial-access"},
        "leaked_credential":   {"technique_id": "T1078", "tactic": "initial-access"},
        "data_breach":         {"technique_id": "T1078", "tactic": "initial-access"},
        "missing_dmarc":       {"technique_id": "T1566", "tactic": "initial-access"},
        "subdomain_takeover":  {"technique_id": "T1584", "tactic": "resource-development"},
        "s3_bucket":           {"technique_id": "T1530", "tactic": "collection"},
        "cors_misconfiguration": {"technique_id": "T1185", "tactic": "collection"},
        "wp_plugin_cve":       {"technique_id": "T1190", "tactic": "initial-access"},
    }
    return mapping.get(finding_type, {"technique_id": "T1190", "tactic": "initial-access"})


def _infer_impact(finding_type: str) -> str:
    impacts = {
        "nuclei_finding":      "Remote code execution or data exfiltration",
        "kev_match":           "Active exploitation risk — immediate system compromise",
        "leaked_credential":   "Account takeover → lateral movement → data breach",
        "data_breach":         "Credential reuse → account takeover",
        "missing_dmarc":       "Email spoofing → phishing → credential theft",
        "s3_bucket":           "Data exfiltration of stored objects",
        "gcs_bucket":          "Data exfiltration of stored objects",
        "subdomain_takeover":  "Session hijacking, phishing page hosting",
        "cors_misconfiguration": "Cross-origin credential theft from authenticated users",
        "exposed_api_docs":    "Full API enumeration → targeted attacks on all endpoints",
        "graphql_endpoint":    "Data extraction via introspection queries",
        "wp_plugin_cve":       "Plugin-specific RCE, file upload, or data exposure",
    }
    return impacts.get(finding_type, "System compromise or data exposure")
