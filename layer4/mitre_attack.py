"""
layer4/mitre_attack.py — MITRE ATT&CK technique mapping.

Maps findings to MITRE ATT&CK techniques using a local rule-based mapping
(_FINDING_TO_TECHNIQUE / _PORT_TO_TECHNIQUE below) — no external calls.

Mapping approach:
  1. Rule-based: known finding types → ATT&CK technique IDs
     (e.g., "missing_dmarc" → T1566 Phishing, T1598 Spearphishing)
  2. Technology-based: detected tech → relevant technique IDs
     (e.g., "RDP open" → T1021.001 Remote Services: RDP)
  3. Credential-based: leaked creds → T1078 Valid Accounts

Produces: technique-to-finding mapping for kill chain assembly.

Backlog (see DOSSIER.md Section 15): enrich technique names/tactics by
downloading and caching MITRE's ATT&CK enterprise STIX bundle instead of
relying solely on the local mapping above.
"""
from __future__ import annotations

import time
from typing import Any

import structlog

from core.config import Config
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "mitre_attack",
    "title":    "MITRE ATT&CK",
    "description": "Technique mapping for observed findings",
    "layer":    4,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": False,
}

# Rule-based finding → ATT&CK technique mapping
_FINDING_TO_TECHNIQUE: dict[str, list[dict]] = {
    "missing_dmarc":            [{"id": "T1566",     "name": "Phishing"},
                                  {"id": "T1598",     "name": "Phishing for Information"}],
    "weak_spf":                 [{"id": "T1566",     "name": "Phishing"}],
    "missing_security_header":  [{"id": "T1059.007", "name": "JavaScript"}],
    "weak_csp":                 [{"id": "T1059.007", "name": "JavaScript / XSS"}],
    "cors_misconfiguration":    [{"id": "T1185",     "name": "Browser Session Hijacking"}],
    "subdomain_takeover":       [{"id": "T1584.001", "name": "Compromise Infrastructure: Domains"}],
    "exposed_api_docs":         [{"id": "T1119",     "name": "Automated Collection"}],
    "graphql_endpoint":         [{"id": "T1119",     "name": "Automated Collection"}],
    "s3_bucket":                [{"id": "T1530",     "name": "Data from Cloud Storage"}],
    "gcs_bucket":               [{"id": "T1530",     "name": "Data from Cloud Storage"}],
    "azure_blob":               [{"id": "T1530",     "name": "Data from Cloud Storage"}],
    "data_breach":              [{"id": "T1078",     "name": "Valid Accounts"},
                                  {"id": "T1589.001", "name": "Gather Victim Identity Information: Credentials"}],
    "leaked_credential":        [{"id": "T1078",     "name": "Valid Accounts"},
                                  {"id": "T1110.004", "name": "Credential Stuffing"}],
    "nuclei_finding":           [{"id": "T1190",     "name": "Exploit Public-Facing Application"}],
    "kev_match":                [{"id": "T1190",     "name": "Exploit Public-Facing Application"}],
    "zone_transfer_vulnerability": [{"id": "T1590.002", "name": "DNS"}],
    "open_port":                [{"id": "T1046",     "name": "Network Service Discovery"}],
    "service_banner":           [{"id": "T1592.004", "name": "Gather Victim Host Information: Client Configurations"}],
    "version_disclosure":       [{"id": "T1592.004", "name": "Gather Victim Host Information"}],
    "potential_secret":         [{"id": "T1552.001", "name": "Unsecured Credentials: Credentials In Files"}],
    "js_secret":                [{"id": "T1552.001", "name": "Unsecured Credentials: Credentials In Files"}],
    "firebase_rtdb":            [{"id": "T1530",     "name": "Data from Cloud Storage"}],
    "github_repo":              [{"id": "T1213.003", "name": "Data from Code Repositories"}],
    "darkweb_mention":          [{"id": "T1591",     "name": "Gather Victim Org Information"}],
    "ransomware_leak_mention":  [{"id": "T1486",     "name": "Data Encrypted for Impact"},
                                  {"id": "T1657",     "name": "Financial Theft"}],
    "person":                   [{"id": "T1589",     "name": "Gather Victim Identity Information"}],
    "ixp_membership":           [{"id": "T1590.004", "name": "Network Topology"}],
    "bgp_prefix":               [{"id": "T1590.004", "name": "Network Topology"}],
    "waf_detected":             [{"id": "T1562.006", "name": "Indicator Blocking"}],
    "no_waf":                   [{"id": "T1190",     "name": "Exploit Public-Facing Application"}],
}

# Port → technique mapping
_PORT_TO_TECHNIQUE: dict[int, list[dict]] = {
    3389: [{"id": "T1021.001", "name": "Remote Services: Remote Desktop Protocol"}],
    445:  [{"id": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares"}],
    22:   [{"id": "T1021.004", "name": "Remote Services: SSH"}],
    23:   [{"id": "T1021",     "name": "Remote Services (Telnet — plaintext)"}],
    6379: [{"id": "T1505",     "name": "Server Software Component (Redis RCE)"}],
    9200: [{"id": "T1530",     "name": "Data from Cloud Storage (Elasticsearch)"}],
    27017:[{"id": "T1530",     "name": "Data from Cloud Storage (MongoDB)"}],
    5432: [{"id": "T1190",     "name": "Exploit Public-Facing Application (PostgreSQL)"}],
    3306: [{"id": "T1190",     "name": "Exploit Public-Facing Application (MySQL)"}],
    6443: [{"id": "T1613",     "name": "Container and Resource Discovery (Kubernetes API)"}],
}


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0        = time.monotonic()
    findings: list[dict] = []
    metadata: dict       = {"techniques_mapped": 0}

    # Collect all findings from this run
    scan_findings = await _collect_all_findings(scope, db)
    metadata["scan_findings_processed"] = len(scan_findings)

    # Map each finding to ATT&CK techniques
    technique_map: dict[str, list[str]] = {}  # technique_id → [finding_values]

    for finding in scan_findings:
        ftype  = finding.get("type", "")
        value  = finding.get("value", "")
        data   = finding.get("data", {})
        techniques = []

        # Rule-based mapping
        if ftype in _FINDING_TO_TECHNIQUE:
            techniques.extend(_FINDING_TO_TECHNIQUE[ftype])

        # Port-specific mapping
        if ftype == "open_port":
            port = data.get("port", 0)
            if port in _PORT_TO_TECHNIQUE:
                techniques.extend(_PORT_TO_TECHNIQUE[port])

        for tech in techniques:
            tid = tech["id"]
            technique_map.setdefault(tid, []).append(value)

    metadata["techniques_mapped"] = len(technique_map)

    # Create findings per technique
    for technique_id, evidence in technique_map.items():
        technique_name = _get_technique_name(technique_id)
        tactic         = _get_tactic(technique_id)
        findings.append({
            "type":  "attack_technique",
            "value": technique_id,
            "data": {
                "technique_id":   technique_id,
                "technique_name": technique_name,
                "tactic":         tactic,
                "evidence_count": len(evidence),
                "evidence":       evidence[:5],
                "confidence":     "high" if len(evidence) > 2 else "medium",
            },
        })

    # Produce a prioritised technique list (most evidence first)
    findings.sort(key=lambda f: f["data"]["evidence_count"], reverse=True)

    log.info("mitre.complete", techniques=metadata["techniques_mapped"])
    return {
        "module":   "layer4/mitre_attack",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def _collect_all_findings(scope, db) -> list[dict]:
    if db is None:
        return []
    all_findings = []
    try:
        run_id = await db.get_last_run_id(scope.target.name) or ""
        if not run_id:
            return []
        # Collect findings from all finding types we care about
        relevant_types = list(_FINDING_TO_TECHNIQUE.keys()) + ["open_port"]
        for ftype in relevant_types:
            rows = await db.get_findings(run_id, ftype)
            all_findings.extend(rows)
    except Exception as exc:
        log.debug("mitre.collect_failed", error=str(exc))
    return all_findings


def _get_technique_name(technique_id: str) -> str:
    """Return technique name from our local mapping or a generic name."""
    for techniques in _FINDING_TO_TECHNIQUE.values():
        for tech in techniques:
            if tech["id"] == technique_id:
                return tech["name"]
    for techniques in _PORT_TO_TECHNIQUE.values():
        for tech in techniques:
            if tech["id"] == technique_id:
                return tech["name"]
    return f"ATT&CK {technique_id}"


def _get_tactic(technique_id: str) -> str:
    """Infer ATT&CK tactic from technique ID prefix/range."""
    tid = technique_id.replace("T", "").split(".")[0]
    try:
        num = int(tid)
    except ValueError:
        return "unknown"

    if num in range(1566, 1600):
        return "initial-access"
    if num in range(1059, 1100):
        return "execution"
    if num in range(1547, 1567):
        return "persistence"
    if num in range(1548, 1570):
        return "privilege-escalation"
    if num in range(1110, 1140):
        return "credential-access"
    if num in range(1046, 1060):
        return "discovery"
    if num in range(1021, 1046):
        return "lateral-movement"
    if num in range(1119, 1135):
        return "collection"
    if num in range(1590, 1600):
        return "reconnaissance"
    if num in range(1583, 1590):
        return "resource-development"
    if num in range(1486, 1500):
        return "impact"
    return "unknown"
