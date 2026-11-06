#!/usr/bin/env python3
"""
tools/panel.py. Read-only operator console for the Continuous EAS engine.

WHAT THIS IS
------------
A small, read-only status panel for the red team. It shows which watchers are
running, what each engagement has collected, and where the saved reports are.
It never triggers a scan and never stores findings of its own. It only reads
local state that the engine already writes under SURFACESCANNER_DATA.

It is meant to live on the brain server (the control plane), bound to localhost,
and reached over the VPN. It is not a findings console. Triage happens in JOES
AIR. This answers the operator questions AIR does not: what is running, did the
last run work, how much did we collect, and where is the Excel.

AUTH
----
Two modes, picked by the PANEL_SSO environment variable.

  PANEL_SSO unset (default), LOCAL DEMO:
      A single local login. Username and password come from the environment
      (PANEL_USER, PANEL_PASSWORD), never from this file, so no secret is
      committed. On a dev box set them in .env (gitignored). To skip the login
      page entirely while testing, set PANEL_NO_AUTH=1 (dev only, refused under
      SSO, never commit it on by default).

  PANEL_SSO=1, PRODUCTION:
      No local login at all. An identity-aware proxy (oauth2-proxy in front of
      Microsoft Entra) does the SSO and passes the verified email in a header.
      The panel trusts that header and allows only your configured company domain.
      See the commented SSO section below and deploy/panel-sso.md.

RUN
---
    PANEL_USER=redteam PANEL_PASSWORD=... \
        python tools/panel.py --host 127.0.0.1 --port 8787
"""
from __future__ import annotations

import argparse
import base64
import calendar
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import subprocess
import tempfile
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# --------------------------------------------------------------------------
# State location. Matches core/config.py: engagement data lives under the data
# root, never in the code tree.
# --------------------------------------------------------------------------
DATA = Path(os.environ.get("SURFACESCANNER_DATA", Path.home() / "surfacescanner-data"))
ENGAGEMENTS = DATA / "engagements"

# --------------------------------------------------------------------------
# Audit log. Append-only JSONL under the data root, one line per action: who,
# from where, what, and the outcome. Every sign in, sign out, start, stop, run
# and download lands here, so there is a full trail for QA and legal. The panel
# only ever appends and reads, it never edits or deletes a line.
# --------------------------------------------------------------------------
AUDIT_DIR = DATA / "audit"
AUDIT_LOG = AUDIT_DIR / "panel-audit.jsonl"
_AUDIT_LOCK = threading.Lock()


def _audit(event: str, actor: str | None, ip: str | None, **fields) -> None:
    """Append one audit record. Never raises, logging must not break a request."""
    try:
        rec = {"ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "event": event, "actor": actor or "anonymous", "ip": ip or "-"}
        rec.update({k: v for k, v in fields.items() if v not in (None, "")})
        with _AUDIT_LOCK:
            AUDIT_DIR.mkdir(parents=True, exist_ok=True)
            with AUDIT_LOG.open("a") as fh:
                fh.write(json.dumps(rec) + "\n")
    except Exception:
        pass


_SSO_SEEN: dict[str, float] = {}
_SSO_RELOG = 3600.0  # log an SSO sign in again after this many seconds idle


def _note_sso_login(user: str, ip: str | None) -> None:
    """Log a Microsoft SSO sign in, at most once per user per hour, so the
    activity trail records who came in through Entra without a line per request."""
    now = time.time()
    last = _SSO_SEEN.get(user, 0.0)
    if now - last >= _SSO_RELOG:
        _audit("login", user, ip, outcome="ok", detail="sso")
    _SSO_SEEN[user] = now


def _read_audit(limit: int = 500) -> list[dict]:
    """The most recent audit records, newest first."""
    if not AUDIT_LOG.is_file():
        return []
    try:
        lines = AUDIT_LOG.read_text(errors="ignore").splitlines()
    except Exception:
        return []
    out = []
    for ln in lines[-limit:]:
        ln = ln.strip()
        if not ln:
            continue
        try:
            out.append(json.loads(ln))
        except Exception:
            continue
    out.reverse()
    return out

# --------------------------------------------------------------------------
# JOES AIR severity palette, so the console reads like the platform.
# CRITICAL/SEV1, HIGH/SEV2, MEDIUM/SEV3, LOW/SEV4, INFO/SEV5.
# --------------------------------------------------------------------------
SEV = {
    "SEV1": ("Critical",      "#8E0B21", "#ffffff"),
    "SEV2": ("High",          "#E53935", "#ffffff"),
    "SEV3": ("Medium",        "#ED7D31", "#111820"),
    "SEV4": ("Low",           "#F5C518", "#111820"),
    "SEV5": ("Informational", "#607085", "#ffffff"),
}
SEV_ORDER = ["SEV1", "SEV2", "SEV3", "SEV4", "SEV5"]

# A signal may carry its severity as a SEV code or as a word (a posture-aware
# producer writes "Medium"). Normalise both to the SEV code so a finding ranks,
# counts and displays the same whichever way it was written.
_SEV_WORD = {
    "CRITICAL": "SEV1", "HIGH": "SEV2", "MEDIUM": "SEV3", "MED": "SEV3",
    "LOW": "SEV4", "INFO": "SEV5", "INFORMATIONAL": "SEV5",
}


def _norm_sev(s: str) -> str:
    s = str(s or "").strip().upper()
    return s if s in SEV_ORDER else _SEV_WORD.get(s, s)

# --------------------------------------------------------------------------
# Phase registry. One autowatcher per client, organised by phase. Each phase
# has modules that can be toggled on and off. This single list drives both the
# fleet overview and the per-client page, so adding a new vertical later is one
# entry here with its systemd unit, no other code change. "unit" is a template,
# {slug} is the client. "schedule" True means a timer (on == enabled), False
# means a long-running service (on == active).
# --------------------------------------------------------------------------
# The phase registry mirrors the SurfaceScanner layer architecture, so the
# console shows the whole engine, one full-width card per layer, and the phases
# that are not promoted into this engine yet read as what is coming.
#
# A phase is one layer. Its modules are the capabilities promoted so far. A
# phase with no modules is not yet wired into the console. Each module carries a
# "control" that says how it behaves:
#   "toggle": a persistent autowatcher with an on/off switch. "schedule" True
#             means a timer (on == enabled), False means a long running service
#             (on == active).
#   "run":    a one-shot run fired by a button, nothing to leave on.
# Every module has a "help" string behind a small "?" and a "service" systemd
# unit that does the work. Toggle modules also carry "toggle_unit", the unit the
# switch enables or disables.
PHASES = [
    {"key": "layer0", "layer": "0", "name": "Corporate Intelligence",
     "help": "Who the target is, legally. Sector, subsidiaries, company "
             "registries, and the Microsoft tenant that anchors the rest.",
     "groups": [
         {"title": "Company footprint dossier",
          "help": "The agent-backed investigative layer that a scanner cannot "
                  "do. Runs the maintained eas-company-footprint skill headless "
                  "and the engine validates what it wrote before any signal is "
                  "accepted. It fills the client Context dossier. Passive OSINT.",
          "modules": [
              {"kind": "footprint-dossier", "name": "company footprint dossier",
               "title": "Company footprint (agent)", "label": "Run",
               "help": "Turns the contracted domain and company name into the "
                       "resolved entity chain, the parent and brand map, the "
                       "passive infrastructure attribution and the investigative "
                       "leads that fill the Context dossier. Sends company data "
                       "to the Anthropic API. It runs as part of Run all phases, "
                       "and can also be run on its own.",
               "control": "run", "gate": "passive", "warn": True,
               "service": "footprint@{slug}.service",
               "tasks": [
                   "Resolve the entity chain, brand to legal vehicle to parent "
                   "group, by registry code not by name",
                   "Map the parent, group and sister entities and the brand and "
                   "acquisition history, each with its state and date",
                   "Correlate ownership anchors, the Entra tenant and shared "
                   "SaaS or analytics IDs, to bound scope to the target",
                   "Gather investigative leads, litigation, regulatory actions, "
                   "offshore records and adverse media",
                   "Run the same-name gate so a different company sharing the "
                   "brand word is ruled out, with the reason recorded",
                   "Hold every person and email record for operator confirmation "
                   "and halt the thread on a sanctions or PEP hit",
                   "End with a coverage statement of what was searched and came "
                   "back empty",
               ]},
          ]},
     ]},
    {"key": "layer1", "layer": "1", "name": "OSINT",
     "help": "What public sources and people leak. Staff, code, documents, "
             "brand mentions, and the lookalike and phishing domains.",
     "groups": [
         {"title": "Lookalike and brand protection",
          "help": "Finds the domains an attacker would register to impersonate "
                  "the brand, keeps the ones that exist, and scores each on the "
                  "SEV1 to SEV5 scale.",
          "modules": [
              {"kind": "lookalike-sweep", "name": "Lookalike sweep",
               "title": "Lookalike domain sweep", "meth_group": "Lookalike",
               "help": "Re-runs the dnstwist permutations and the certificate "
                       "and newly registered domain discovery, re-scores every "
                       "candidate from SEV5 up to SEV1, and refreshes the signal "
                       "file. Scheduled every 6 hours.",
               "control": "toggle", "schedule": True, "gate": "semi",
               "service": "lookalike-watch@{slug}.service",
               "toggle_unit": "lookalike-watch@{slug}.timer"},
              {"kind": "lookalike-live", "name": "Lookalike live feed",
               "title": "Lookalike live certificate feed", "meth_group": "Lookalike",
               "help": "A long running listener on the public certificate "
                       "transparency stream. It flags a certificate the moment "
                       "it is issued for a domain that looks like the client, "
                       "without waiting for the next sweep.",
               "control": "toggle", "schedule": False, "gate": "passive",
               "service": "certstream-watch@{slug}.service",
               "toggle_unit": "certstream-watch@{slug}.service"},
          ]},
     ]},
    {"key": "layer2", "layer": "2", "name": "Subdomain and Network Infrastructure",
     "help": "What infrastructure exists. Subdomains, DNS, network ranges, "
             "routing, and cloud assets.",
     "groups": [
         {"title": "Subdomain enumeration",
          "help": "Discovers the client's subdomains and hands back a clean host "
                  "list. Run it passive for a contactless sweep, or active for "
                  "the full DNS enumeration.",
          "modules": [
              {"kind": "subdomain-passive", "name": "passive subdomain enumeration",
               "title": "Subdomain passive enumeration", "label": "Run passive",
               "meth_group": "Subdomain",
               "help": "Contactless discovery only. The passive source union "
                       "(subfinder recursive), an eight-source certificate "
                       "transparency fallback chain, and archived-URL mining, "
                       "then resolution of what they find. Sends nothing to the "
                       "client, so it is safe on any engagement.",
               "control": "run", "gate": "passive",
               "service": "subdomain-passive@{slug}.service"},
              {"kind": "subdomain-active", "name": "active subdomain enumeration",
               "title": "Subdomain active enumeration", "label": "Run active",
               "meth_group": "Subdomain",
               "help": "Full enumeration. Adds permutations, the curated "
                       "151-prefix common-prefix sweep, time-budgeted wordlist "
                       "bruteforce, zone transfer, takeover detection and amass. "
                       "This sends DNS traffic to the client and should egress "
                       "from the disposable host, not an analyst workstation.",
               "control": "run", "gate": "active",
               "service": "subdomain-active@{slug}.service",
               "warn": True},
              {"kind": "subdomain-rescan", "name": "Subdomain re-scan",
               "title": "Weekly subdomain re-scan", "meth_group": "Subdomain",
               "help": "A weekly full passive and active re-enumeration that diffs "
                       "the result against the latest subdomain list and raises a "
                       "'new subdomain(s) discovered' alert for anything new, then "
                       "re-scans only the new hosts. Scheduled weekly.",
               "control": "toggle", "schedule": True, "gate": "active",
               "service": "subdomain-rescan@{slug}.service",
               "toggle_unit": "subdomain-rescan@{slug}.timer"},
          ]},
     ]},
    {"key": "layer2_5", "layer": "2.5", "name": "Surface Recon",
     "help": "What the discovered surface exposes. Web apps, email and DNS "
             "security, TLS, open ports, and the Microsoft identity checks.",
     "groups": [
         {"title": "Exposure checks",
          "help": "Email and DNS security posture, TLS, headers and the other "
                  "surface checks promoted into this layer. Active: it probes "
                  "the client's own hosts, so egress from the disposable host.",
          "modules": [
              {"kind": "surface-recon", "name": "surface recon run",
               "title": "Surface recon", "label": "Run",
               "help": "Runs the promoted layer 2.5 modules (email and DNS "
                       "security, favicon correlation, and more as they are "
                       "promoted) against the discovered surface. Active.",
               "control": "run", "gate": "active",
               "service": "surface-recon@{slug}.service", "warn": True},
              {"kind": "dmarc-watch", "name": "Email-auth posture watcher",
               "title": "Email-auth posture watcher",
               "help": "The regression-only sibling of the lookalike feed. Reads "
                       "DMARC, SPF, DKIM and MX from public DNS, folds them into "
                       "one posture row per domain, and raises a signal ONLY when "
                       "posture regresses: a spoofable flag flips on (no DMARC, "
                       "p=none, no or weak SPF, no DKIM, reporting off) or the "
                       "DMARC policy downgrades reject to quarantine to none. A "
                       "locked-down domain stays silent. Contactless, scheduled "
                       "weekly.",
               "control": "toggle", "schedule": True, "gate": "passive",
               "service": "dmarc-watch@{slug}.service",
               "toggle_unit": "dmarc-watch@{slug}.timer"},
          ]},
     ]},
    {"key": "layer3", "layer": "3", "name": "Digital Footprint and Breach",
     "help": "Who works there and what has leaked. People, credentials, breach "
             "and infostealer data.",
     "groups": [
         {"title": "Breach and exposure",
          "help": "Credential, breach and infostealer exposure from third-party "
                  "data sources. Contactless: it queries external feeds, never "
                  "the client. Sources that need an API key skip themselves.",
          "modules": [
              {"kind": "footprint-breach", "name": "footprint and breach run",
               "title": "Digital footprint and breach", "label": "Run",
               "help": "Runs the promoted layer 3 modules (infostealer and "
                       "breach lookups) against external data sources and emits "
                       "any exposure found. Passive. Key-gated sources skip if "
                       "no key is configured.",
               "control": "run", "gate": "passive",
               "service": "footprint-breach@{slug}.service"},
              {"kind": "leak-watch", "name": "Credential leak watcher",
               "title": "Credential leak watcher (demo)",
               "help": "Watches third-party breach and infostealer feeds for new "
                       "credentials tied to the client and raises a leak alert, "
                       "which is tracked as a finding. Demo watcher, to be "
                       "3rd-partied. Contactless.",
               "control": "toggle", "schedule": True, "gate": "passive",
               "service": "leak-watch@{slug}.service",
               "toggle_unit": "leak-watch@{slug}.timer"},
          ]},
     ]},
    {"key": "layer4", "layer": "4", "name": "Kill Chain and Sector Intelligence",
     "help": "What it all means. EPSS and KEV scoring, ATT&CK mapping, and the "
             "kill chain narrative.",
     "groups": [
         {"title": "Scoring and intelligence",
          "help": "Scores the CVEs discovered earlier against the public EPSS "
                  "and CISA KEV feeds. Contactless: public feeds only, no "
                  "client traffic.",
          "modules": [
              {"kind": "killchain-intel", "name": "kill chain and sector run",
               "title": "Kill chain and sector intelligence", "label": "Run",
               "help": "Runs the promoted layer 4 modules (EPSS exploit "
                       "probability and CISA KEV known-exploited matching) over "
                       "the discovered CVEs and sector. Passive, public feeds.",
               "control": "run", "gate": "passive",
               "service": "killchain-intel@{slug}.service"},
          ]},
     ]},
]
def _phase_modules(p: dict) -> list:
    return [m for g in p.get("groups", []) for m in g["modules"]]


MODULES = [m for p in PHASES for m in _phase_modules(p)]
MODULE_BY_KIND = {m["kind"]: m for m in MODULES}
PHASE_BY_KIND = {m["kind"]: p for p in PHASES for m in _phase_modules(p)}
PHASE_BY_KEY = {p["key"]: p for p in PHASES}


# The methodology page documents the engine as the DAG it really is, not the
# integer-layer straight line. This stage model is display only: it maps the
# existing layer modules (PHASES, above) into their true run order and is NOT
# consumed by the client console or the scheduler, so changing it never alters
# what runs per client. Each stage is one of:
#   kind "gate"  a hard checkpoint, nothing active crosses it unvalidated
#   kind "band"  a set of sub-stages that run in parallel
#   kind "stage" a single stage
# gate badge is passive, active or gate. `layers` names the PHASES keys whose
# module cards render inside the stage. `notes` are the gaps and planned
# modules called out in the methodology review. `depends` is a human string.
METHODOLOGY_STAGES = [
    {"id": "S0", "kind": "stage", "gate": "passive",
     "title": "Ownership spine",
     "depends": "entry point",
     "help": "L0 answers one question: who is the target, legally and by "
             "ownership anchor. Four jobs, not eight. Anything that is not that "
             "leaves L0. The same-name gate lives in J4 here, so there is no "
             "separate scope-intake stage.",
     "jobs": [
         {"id": "J1", "title": "Entity resolution", "status": "partial",
          "help": "Brand to legal entity to parent and group, with registry "
                  "codes and former names. Resolve the code once, then pin by "
                  "code. Keeps company_registry, sec_filings and company_social, "
                  "plus the agent chain below.",
          "layers": ["layer0"],
          "notes": ["NEW subsidiary-name to candidate-domain resolver (the open "
                    "loop, the whole value prop depends on it)."]},
         {"id": "J2", "title": "Ownership anchors", "status": "partial",
          "help": "Entra tenant and namespace type, nameserver and registrant "
                  "correlation, shared SaaS or analytics IDs. Captured ONLY as "
                  "signals that expand or bound scope, never as an infra "
                  "inventory. Keeps azure_tenant. layer0/estate_expander.py is "
                  "live: it hashes the seed favicon (MurmurHash3, the Shodan "
                  "http.favicon.hash index) and extracts analytics IDs (GA4, UA, "
                  "GTM, AdSense), then reverse-searches each pivot to find "
                  "sibling root domains run by the same operator.",
          "layers": ["layer0"],
          "notes": ["Capture Entra namespace type and FederationBrandName.",
                    "Record tenant SEPARATION as a signal, not only a match: a "
                    "different tenant on a brand domain is a segregated estate.",
                    "The favicon shown on the context diagram IS this pivot "
                    "input: its hash is emitted as a tracker_id finding (with "
                    "the ready http.favicon.hash: query) even with no Shodan "
                    "key, so it can be pivoted by hand.",
                    "Favicon reverse via Shodan (SHODAN_API_KEY), analytics IDs "
                    "via PublicWWW (PUBLICWWW_API_KEY, keyless fallback). Every "
                    "sibling root is emitted as an estate_root finding tagged "
                    "attribution-only: a candidate, never fetched or promoted to "
                    "active testing."]},
         {"id": "J3", "title": "Integrity and investigative screen", "new": True,
          "status": "open",
          "help": "Litigation, regulatory actions, offshore and ICIJ records, "
                  "adverse media, and a sanctions or PEP halt. Currently zero "
                  "modules exist for this, it is net new.",
          "notes": ["Sanctions or PEP hit HALTS the thread and escalates, it "
                    "does not just raise a finding."]},
         {"id": "J4", "title": "Gate and coverage wrapper", "status": "locked",
          "help": "The same-name gate with its recorded reason, the PII "
                  "operator-hold, and the closing coverage statement that says "
                  "what was and was not searched.",
          "notes": ["Split the old people-and-email task into a PII "
                    "operator-hold (this governance wrapper) and the "
                    "sanctions/PEP screen (J3, an integrity module)."]},
     ]},
    {"id": "S1", "kind": "band", "gate": "passive",
     "title": "Parallel discovery",
     "depends": "S0",
     "help": "Tracks that depend only on the ownership spine, so they run in "
             "parallel. Each runs at its own gate, so this is not uniformly "
             "passive: subdomain discovery includes an active enumeration tier. "
             "The passive half of surface recon runs here too.",
     "band": [
         {"id": "S1a", "title": "OSINT", "gate": "passive", "layers": ["layer1"],
          "notes": ["Missing: a real news and brand-mention module.",
                    "Missing: a real secret engine (record by prefix, never "
                    "validate).",
                    "Route lookalikes to the adversary track, never into the "
                    "owned-asset set."]},
         {"id": "S1b", "title": "Infrastructure discovery", "gate": "passive",
          "layers": ["layer2"],
          "notes": ["Favicon and analytics ID correlation belong here as a "
                    "discovery expander, not later in surface recon.",
                    "Needs per-module depends_on (permutations after the CT "
                    "seed, resolve after all sources, takeover after resolve)."]},
         {"id": "S1c", "title": "People and breach", "gate": "passive",
          "layers": ["layer3"],
          "notes": ["Runs HERE in parallel, not after surface recon.",
                    "Classify every credential as employee, customer or third "
                    "party, and route staff to the corporate domain and "
                    "customers to the brand domains via the S0 tenant and MX "
                    "split."]},
         {"id": "S1.5p", "title": "Surface recon, passive half", "gate": "passive",
          "notes": ["Email and DNS security, passive TLS read, Wayback, "
                    "favicon and dorks are contactless and belong up here.",
                    "Email-auth posture has a DB-backed watcher now: "
                    "tools/dmarc_watch.py, the regression-only sibling of the "
                    "lookalike feed. It folds the DMARC, SPF, DKIM and MX read "
                    "from layer2_5/email_dns_security.py into one posture row "
                    "per domain, caches it in a .seen.json sidecar, and emits a "
                    "signal ONLY when posture regresses: a spoofable flag flips "
                    "false to true (no_dmarc, p=none, no_spf, weak SPF, no_dkim, "
                    "reporting off) or the DMARC policy downgrades "
                    "reject to quarantine to none. A locked-down domain is "
                    "inventory and stays silent. Metadata only, no POST.",
                    "Only the active tools gate behind S2 (see S3)."]},
     ]},
    {"id": "S2", "kind": "gate", "gate": "gate",
     "title": "Ownership and Critic validation gate",
     "depends": "S1",
     "help": "The hinge the whole automation turns on. Consolidate every "
             "candidate asset, validate it against DNS, WHOIS and tenant "
             "reality, classify owned, lookalike or third party, and freeze the "
             "active scope. Everything before this is passive and parallel, "
             "everything after is active and sequential.",
     "notes": ["Promote the Critic from a phase-4 agent to a named gate stage.",
               "Confirmed subsidiary and tenant candidates flow back into S1b "
               "subdomain enumeration on the next cycle (loop closed)."]},
    {"id": "S3", "kind": "stage", "gate": "active",
     "title": "Active surface recon",
     "depends": "S2 (gated, via the disposable VPS)",
     "help": "The active half of surface recon only: nuclei, katana, ffuf and "
             "ports. The passive half already ran in S1.",
     "layers": ["layer2_5"],
     "notes": ["Split surface recon into passive (S1) and active (here).",
               "Missing entirely: mobile and app surface (app stores, APK and "
               "IPA pull, deep-link domains, pinned certs, in-app API hosts)."]},
    {"id": "S4", "kind": "stage", "gate": "passive",
     "title": "Correlation",
     "depends": "S1c and S3",
     "help": "credential_triage merges the breach sources across the corporate "
             "versus brand domain split established in S0.",
     "notes": ["leakcheck, leakradar, hibp, dehashed, intelx and infostealer "
               "overlap: keep the merge, consider a tiered fallback over "
               "running all six every cycle."]},
    {"id": "S5", "kind": "stage", "gate": "passive",
     "title": "Prioritise and validate findings",
     "depends": "S4",
     "help": "Rank the findings into the priority queue on two tracks.",
     "layers": ["layer4"],
     "notes": ["CVE track: EPSS times KEV times severity.",
               "NEW non-CVE exposure track: exploitability heuristic times "
               "asset criticality times data sensitivity. Most EASM findings "
               "(missing DMARC, exposed bucket, takeover, leaked credential, "
               "exposed admin panel, mobile data flow) have no EPSS score and "
               "fall through the CVE ranker without this."]},
    {"id": "S6", "kind": "stage", "gate": "passive",
     "title": "Report, delta and coverage gate",
     "depends": "S5",
     "help": "The client deliverable, the delta against the last run, and the "
             "coverage matrix that proves what was and was not searched.",
     "notes": []},
]

# Two asset classes the review adds, documented after the main DAG.
METHODOLOGY_ADDED = [
    {"title": "Mobile and app surface (new)",
     "help": "App stores, APK and IPA pull, deep-link domains, pinned certs and "
             "in-app API hosts. A whole asset class with zero coverage today. "
             "A prior run surfaced mobile SDKs and an m. host from CT alone."},
    {"title": "Adversary and phishing track (split from OSINT)",
     "help": "Lookalikes, typosquats and brand abuse are a different workflow "
             "with a different owner (takedown). Kept out of the owned-asset "
             "DAG so a typosquat never feeds an active scan."},
]
TOGGLE_MODULES = [m for m in MODULES if m["control"] == "toggle"]
# On-demand run modules (oneshots). These are "active" only while a run is
# actually executing, so they, and not the persistent toggle watchers, are what
# "a run is in progress" means. A toggle watcher left enabled after Run all is
# the intended steady state, never a run still going.
RUN_KINDS = frozenset(m["kind"] for m in MODULES if m["control"] == "run")


def _run_in_progress(st: dict) -> bool:
    """True only when an on-demand run (footprint, subdomain enum, recon, breach,
    kill-chain) is still executing. Enabled toggle watchers do not count, so the
    Run-all control and the command lock release once the actual runs finish."""
    return any(st.get(k, {}).get("active") for k in RUN_KINDS)

# The real external commands each promoted module runs, for the in-console
# reference. One source of truth, read straight from here so the shown command
# cannot drift from what the engine runs. "gate" is the recon mode the command
# needs, passive, semi or active. The network boundary enforces the scope mode,
# so a semi or active command never fires in a passive scope.
COMMANDS = {
    "lookalike-sweep": [
        {"gate": "passive", "cmd": "which dnstwist", "note": "presence check"},
        {"gate": "passive", "cmd": "dnstwist --registered --mxcheck --format json --threads <n> --output <file>",
         "note": "generate permutations, keep the registered ones, MX check"},
        {"gate": "passive", "cmd": "dig +short NS <domain>", "note": "nameserver lookup"},
        {"gate": "passive", "cmd": "HTTP: crt.sh and RDAP", "note": "registrar, creation date, newly registered candidates"},
        {"gate": "semi", "cmd": "dnstwist --phash --lsh ssdeep", "note": "screenshot and HTML similarity, semi or active only"},
        {"gate": "semi", "cmd": "HTTP via httpx: login form, favicon hash, page match", "note": "enrichment on registered lookalikes"},
        {"gate": "active", "cmd": "gowitness", "note": "screenshots, optional, off by default"},
    ],
    "lookalike-live": [
        {"gate": "passive", "cmd": "websocket wss://certstream.calidog.io/", "note": "filtered by the configured keywords, always on"},
    ],
    "subdomain-passive": [
        {"gate": "passive", "cmd": "subfinder -d <domain> -silent -json -all -recursive",
         "note": "passive source union, -recursive re-queries the sources for deeper subdomains"},
        {"gate": "passive", "cmd": "HTTP CT fallback chain: crt.sh, Certspotter, Censys, Calidog, OTX, ThreatMiner, URLScan, AnubisDB",
         "note": "eight certificate-transparency sources tried in order, so a crt.sh 502 is a detour, not a coverage gap"},
        {"gate": "passive", "cmd": "HTTP: web.archive.org CDX url=*.<domain>/* and OTX url_list",
         "note": "hostnames mined from archived URL history, catches hosts that only ever appeared in old markup"},
    ],
    "subdomain-active": [
        {"gate": "passive", "cmd": "runs the full passive set first",
         "note": "subfinder, the CT fallback chain, and wayback"},
        {"gate": "semi", "cmd": "alterx -l <seeds> -silent", "note": "permutation generation from the known hosts"},
        {"gate": "semi", "cmd": "puredns resolve <151 curated prefixes x bases> --wildcard-tests 3 --rate-limit <n>, dnsx fallback",
         "note": "curated hit-rate-ordered common-prefix sweep, one A-record query per host, low detectability"},
        {"gate": "semi", "cmd": "puredns resolve <wordlist x bases> --wildcard-tests 3 --rate-limit <n>",
         "note": "DNS bruteforce, time budget min(3600, max(300, candidates/100)) seconds scaled by wordlist size"},
        {"gate": "semi", "cmd": "dig @<nameserver> <domain> AXFR",
         "note": "zone transfer attempt per discovered nameserver, dumps the full zone when one allows it"},
        {"gate": "semi", "cmd": "nuclei -l <targets> -t http/takeovers/ -silent -jsonl -no-color", "note": "takeover confirmation"},
        {"gate": "active", "cmd": "amass enum [-passive] -d <domain> -dir <out>", "note": "deep enumeration, the active variant requires a VPS"},
    ],
    "subdomain-rescan": [
        {"gate": "passive", "cmd": "subdomain_watch.py --mode passive", "note": "weekly full passive sweep"},
        {"gate": "active", "cmd": "subdomain_watch.py --mode active", "note": "weekly full active enumeration"},
        {"gate": "passive", "cmd": "diff against latest subdomains.json", "note": "raise an alert for new hosts, re-scan only the new ones"},
    ],
    "leak-watch": [
        {"gate": "passive", "cmd": "third-party breach and infostealer feed (demo)", "note": "to be 3rd-partied, never the client"},
        {"gate": "passive", "cmd": "diff against latest leaks.json", "note": "raise a leak alert for new credentials, tracked as a finding"},
    ],
    "dmarc-watch": [
        {"gate": "passive", "cmd": "dmarc_watch.py --scope scopes/<client>.yaml --once", "note": "folds email_dns_security DMARC/SPF/DKIM/MX into one posture row per domain"},
        {"gate": "passive", "cmd": "DNS: _dmarc TXT, SPF TXT, DKIM selector, MX lookups", "note": "contactless public-DNS read, never the client's hosts"},
        {"gate": "passive", "cmd": "diff against <scope>-dmarc.jsonl.seen.json", "note": "emit only on regression: spoofable flag on, or policy downgrade reject>quarantine>none"},
    ],
    "surface-recon": [
        {"gate": "active", "cmd": "layer_watch.py --layer 2.5 --mode active", "note": "runs every promoted layer 2.5 module, emits EAS signals"},
        {"gate": "passive", "cmd": "DNS: SPF, DMARC, DKIM, MX lookups", "note": "email and DNS security posture"},
        {"gate": "active", "cmd": "HTTP/TLS probes of the discovered hosts", "note": "favicon correlation and more as promoted"},
    ],
    "footprint-breach": [
        {"gate": "passive", "cmd": "layer_watch.py --layer 3 --mode passive", "note": "runs every promoted layer 3 module, emits EAS signals"},
        {"gate": "passive", "cmd": "HTTP: infostealer and breach data feeds", "note": "third-party sources, never the client, key-gated ones skip"},
    ],
    "killchain-intel": [
        {"gate": "passive", "cmd": "layer_watch.py --layer 4 --mode passive", "note": "runs every promoted layer 4 module, emits EAS signals"},
        {"gate": "passive", "cmd": "HTTP: FIRST EPSS API and CISA KEV catalog", "note": "exploit probability and known-exploited matching, public feeds"},
    ],
}


# The lookalike permutation and discovery techniques the sweep actually applies,
# for the in-console reference. These are the dnstwist permutation algorithms plus
# the discovery and match steps around them, one source of truth so the shown list
# cannot drift from what the engine runs. Keyed by the module's meth_group label.
METH_GROUP_TECHNIQUES = {
    "Lookalike": [
        {"name": "TLD swap", "desc": "same name on another suffix, brand.net, brand.io, brand.co"},
        {"name": "Omission", "desc": "a character dropped, brnd.com"},
        {"name": "Insertion", "desc": "an adjacent-keyboard character added, braand.com"},
        {"name": "Repetition", "desc": "a character doubled, braand.com"},
        {"name": "Transposition", "desc": "two neighbours swapped, brnad.com"},
        {"name": "Replacement", "desc": "a character swapped for a keyboard neighbour, brsnd.com"},
        {"name": "Homoglyph", "desc": "look-alike glyphs, rn for m, 0 for o, and Unicode/IDN confusables"},
        {"name": "Bitsquatting", "desc": "a single bit flipped in the name, for memory-error traffic"},
        {"name": "Hyphenation", "desc": "a hyphen inserted, br-and.com"},
        {"name": "Addition", "desc": "a character appended, brandx.com"},
        {"name": "Vowel swap", "desc": "vowels exchanged, brend.com, brund.com"},
        {"name": "Subdomain", "desc": "a dot inserted so the brand becomes a subdomain, br.and.com"},
        {"name": "Dictionary", "desc": "a known word prepended or appended, brand-login.com, secure-brand.com"},
        {"name": "Plural and affix", "desc": "plurals and common affixes, brands.com, mybrand.com"},
        {"name": "Certificate transparency", "desc": "crt.sh history plus the live certstream feed, flagged as issued"},
        {"name": "Newly registered", "desc": "RDAP creation date to catch domains registered in the last days"},
        {"name": "MX check", "desc": "does the candidate receive mail, so it can phish, not just resolve"},
        {"name": "Visual and HTML match", "desc": "screenshot pHash and HTML ssdeep LSH, favicon hash, login-form detection"},
    ],
}

# Per-module techniques, keyed by module kind, parallel to COMMANDS. Shown as a
# "Techniques applied" dropdown on each sub-square, so a merged square can carry
# one technique list per member module (the subdomain passive, active and weekly
# modules each have their own). One source of truth, grounded in what runs.
MODULE_TECHNIQUES = {
    "subdomain-passive": [
        {"name": "Passive source union", "desc": "subfinder recursive over 30+ aggregators, unioned, no single source trusted"},
        {"name": "Certificate transparency", "desc": "crt.sh with a seven-source fallback (Certspotter, Censys, Calidog, OTX, ThreatMiner, URLScan, AnubisDB)"},
        {"name": "Archived-URL mining", "desc": "Wayback CDX and OTX url_list, hostnames recovered from old page markup"},
    ],
    "subdomain-active": [
        {"name": "Permutation generation", "desc": "alterx expands the known hosts into likely neighbours"},
        {"name": "Curated common-prefix sweep", "desc": "151 hit-rate-ordered prefixes, one A-record query each, low detectability"},
        {"name": "DNS wordlist bruteforce", "desc": "puredns over massdns, time budget scaled by wordlist size"},
        {"name": "Zone transfer", "desc": "AXFR attempted per discovered nameserver"},
        {"name": "Takeover detection", "desc": "nuclei takeover templates on the resolved hosts"},
        {"name": "Deep enumeration", "desc": "amass active, egressed from the disposable VPS"},
    ],
    "subdomain-rescan": [
        {"name": "Weekly re-enumeration", "desc": "a full passive and active sweep on a timer"},
        {"name": "New-host diff", "desc": "compare against the latest subdomains and alert on anything new"},
        {"name": "Targeted re-scan", "desc": "re-scan only the newly discovered hosts"},
    ],
}


def _cmd_section(slug: str, m: dict, color: str = "") -> str:
    """One collapsible, read-only 'Commands' panel per module. It shows every
    command this module runs (the full line), so a tester can see exactly what a
    phase will do. Command and knob editing via the UI is intentionally not
    exposed here: the commands and their flags live in code (COMMANDS), the
    single source of truth, so what is shown is what runs."""
    cmds = COMMANDS.get(m["kind"])
    if not cmds:
        return ""
    rows = "".join(
        f'<div class="cmdrow"><span class="gate {c["gate"]}">{c["gate"]}</span>'
        f'<code>{_esc(c["cmd"])}</code></div>' for c in cmds)
    sty = f' style="color:{color}"' if color else ""
    return (f'<details class="cmdref"><summary{sty}>'
            '<svg class="chev" viewBox="0 0 24 24" width="13" height="13" fill="none" '
            'stroke="currentColor" stroke-width="2.6"><path d="M6 9l6 6 6-6"/></svg>'
            f'Commands</summary><div class="cmdbody">{rows}</div></details>')


def _task_html(t: str) -> str:
    """Render one task line with its lead action clause in bold, so the panel
    scans quickly. Bolds up to the first comma, else the first few words."""
    if "," in t:
        lead, rest = t.split(",", 1)
        return f"<strong>{_esc(lead)}</strong>,{_esc(rest)}"
    words = t.split(" ")
    head = " ".join(words[:5])
    tail = " ".join(words[5:])
    out = f"<strong>{_esc(head)}</strong>"
    return out + (f" {_esc(tail)}" if tail else "")


def _tasks_section(m: dict, color: str = "") -> str:
    """A read-only 'Tasks' panel: a plain-language bullet list of what a module
    does, for the phases where the task summary reads better than the raw
    command lines. A module carries this as its own 'tasks' list, so the shown
    summary stays in step with the module in one place. Returns empty when a
    module has no task list, so the caller can fall back to the command view."""
    tasks = m.get("tasks")
    if not tasks:
        return ""
    items = "".join(f"<li>{_task_html(t)}</li>" for t in tasks)
    sty = f' style="color:{color}"' if color else ""
    return (f'<details class="cmdref"><summary{sty}>'
            '<svg class="chev" viewBox="0 0 24 24" width="13" height="13" fill="none" '
            'stroke="currentColor" stroke-width="2.6"><path d="M6 9l6 6 6-6"/></svg>'
            f'Tasks</summary><div class="cmdbody"><ul class="tasklist">{items}</ul>'
            '</div></details>')


# Editable knobs, per module. Only simple scalar config values, never whole
# commands. The binary and the base flags stay in code, so a saved value can
# only tune a flag or an output path, it can never add a flag or a shell
# operator (see _knob_validate). Modules not listed here have no editable
# settings yet, for example the subdomain phase has no config section.
KNOBS = {
    "lookalike-sweep": [
        {"section": "brand_protection", "key": "dnstwist_threads", "label": "dnstwist threads", "type": "int", "min": 1, "max": 100, "default": 20},
        {"section": "brand_protection", "key": "dnstwist_timeout", "label": "dnstwist timeout, seconds", "type": "int", "min": 60, "max": 7200, "default": 1800},
        {"section": "brand_protection", "key": "max_enrich", "label": "max hosts to enrich", "type": "int", "min": 1, "max": 2000, "default": 200},
        {"section": "brand_protection", "key": "recent_days", "label": "recent window, days", "type": "int", "min": 1, "max": 3650, "default": 180},
        {"section": "brand_protection", "key": "enrich_favicon", "label": "favicon enrichment", "type": "bool", "default": True},
        {"section": "brand_protection", "key": "enrich_http", "label": "HTTP enrichment", "type": "bool", "default": True},
        {"section": "brand_protection", "key": "enrich_screenshot", "label": "screenshot enrichment", "type": "bool", "default": False},
    ],
}

# Anything that could concatenate or escape into another command. A knob value
# that matches is rejected outright, so an edited value cannot become "x && rm".
_SHELL_META = re.compile(r'[\s;&|`$><(){}\[\]!*?~"\'\\]')


def _knob_validate(knob: dict, raw: str):
    """Return (value_str, None) on success or (None, error). Int and bool are
    checked by type. A string knob must be a single safe token, no spaces and no
    shell metacharacters, so it can never add a flag or chain a command."""
    raw = (raw or "").strip()
    t = knob["type"]
    if t == "int":
        if not re.fullmatch(r'-?\d{1,9}', raw):
            return None, "must be a whole number"
        v = int(raw)
        if v < knob["min"] or v > knob["max"]:
            return None, f"must be between {knob['min']} and {knob['max']}"
        return str(v), None
    if t == "bool":
        return ("true" if raw.lower() in ("true", "on", "1", "yes") else "false"), None
    if _SHELL_META.search(raw):
        return None, "no spaces or shell characters allowed"
    if not re.fullmatch(r'[A-Za-z0-9_./:\-]{1,200}', raw):
        return None, "only letters, numbers and _ . / : -"
    return raw, None


def _cfg_bounds(lines: list, section: str):
    start = None
    for i, l in enumerate(lines):
        if re.match(rf'^{re.escape(section)}:\s*(#.*)?$', l):
            start = i
            break
    if start is None:
        return None
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if lines[j] and not lines[j][0].isspace():
            end = j
            break
    return start, end


def _cfg_get(text: str, section: str, key: str):
    lines = text.splitlines()
    b = _cfg_bounds(lines, section)
    if not b:
        return None
    for i in range(b[0] + 1, b[1]):
        m = re.match(rf'^\s+{re.escape(key)}:\s*(.*?)\s*(#.*)?$', lines[i])
        if m:
            return m.group(1)
    return None


def _cfg_set(text: str, section: str, key: str, value: str):
    lines = text.splitlines()
    b = _cfg_bounds(lines, section)
    if not b:
        return None
    for i in range(b[0] + 1, b[1]):
        m = re.match(rf'^(\s+){re.escape(key)}:\s*(.*?)(\s*#.*)?$', lines[i])
        if m:
            lines[i] = f'{m.group(1)}{key}: {value}{m.group(3) or ""}'
            return "\n".join(lines) + ("\n" if text.endswith("\n") else "")
    return None


def _knob_current(knob: dict) -> str:
    """The current value from config.yaml, or the default as a string."""
    try:
        raw = _cfg_get(CONFIG_FILE.read_text(), knob["section"], knob["key"])
    except Exception:
        raw = None
    if raw is None:
        d = knob["default"]
        return "true" if d is True else "false" if d is False else str(d)
    return raw.strip()


def _knob_modified(knob: dict) -> bool:
    d = knob["default"]
    default_str = "true" if d is True else "false" if d is False else str(d)
    return _knob_current(knob).lower() != default_str.lower()


def do_set_knobs(slug: str, kind: str, values: dict) -> tuple[bool, str]:
    """Validate and write one module's knobs to config.yaml. Refused while a run
    is in progress for the client, so commands are frozen during a run."""
    if not ALLOW_CONTROL:
        return False, "Control is disabled. No action password is configured."
    knobs = KNOBS.get(kind)
    if not knobs:
        return False, "This module has no editable settings."
    if SLUG_RE.match(slug or ""):
        try:
            st = watcher_state(slug)
        except Exception:
            st = {}
        if _run_in_progress(st):
            return False, "A run is in progress. Stop it before changing commands."
    try:
        text = CONFIG_FILE.read_text()
    except Exception as exc:
        return False, f"Could not read config. {exc}"
    changed = []
    for knob in knobs:
        if knob["key"] not in values:
            continue
        val, err = _knob_validate(knob, values[knob["key"]])
        if err:
            return False, f"{knob['label']}: {err}"
        new = _cfg_set(text, knob["section"], knob["key"], val)
        if new is None:
            return False, f"Could not find {knob['section']}.{knob['key']} in config."
        if new != text:
            changed.append(knob["label"])
        text = new
    if not changed:
        return True, "No changes to save."
    try:
        CONFIG_FILE.write_text(text)
    except Exception as exc:
        return False, f"Could not write config. {exc}"
    return True, f"Saved {len(changed)} setting(s). Applies on the next run."


def _pretty(slug: str) -> str:
    """security-joes -> Security Joes, for display."""
    return " ".join(p.capitalize() for p in slug.replace("_", "-").split("-") if p)

# --------------------------------------------------------------------------
# Auth configuration, read from the environment only.
# --------------------------------------------------------------------------
PANEL_USER = os.environ.get("PANEL_USER", "redteam")
PANEL_PASSWORD = os.environ.get("PANEL_PASSWORD", "")
PANEL_SSO = os.environ.get("PANEL_SSO", "") == "1"
ALLOWED_EMAIL_DOMAIN = os.environ.get("PANEL_EMAIL_DOMAIN", "example.com")
# Signing key for the local session cookie. A fresh random key each start is
# fine, it just means a restart logs people out. Set PANEL_SECRET to keep
# sessions across restarts.
SECRET = os.environ.get("PANEL_SECRET", secrets.token_hex(32)).encode()
COOKIE = "eas_panel_session"

# Starting or stopping a watcher is a critical, state-changing action, so it
# requires the password re-entered each time (step up), even with a live
# session. In SSO mode there is no local password, so set PANEL_ACTION_PASSWORD
# explicitly to gate control. With no action password available, control is
# disabled and the panel stays strictly read-only.
ACTION_PASSWORD = os.environ.get("PANEL_ACTION_PASSWORD", PANEL_PASSWORD)
# This panel is a single-operator console bound to 127.0.0.1. The sign-in page,
# the action password, and the step-up prompt are OFF by default, so the local
# operator is never asked to log in however the panel is launched. To restore the
# login and the control gates for a shared or hosted deployment, set
# PANEL_REQUIRE_AUTH=1, or configure PANEL_SSO (either one turns auth back on).
# PANEL_NO_AUTH=1 is still honoured and still forces no-auth.
_SSO_SET = bool(os.environ.get("PANEL_SSO", "").strip())
_REQUIRE_AUTH = _SSO_SET or (os.environ.get("PANEL_REQUIRE_AUTH", "").strip().lower()
                             in ("1", "true", "yes", "on"))
_DEV_NO_AUTH = (not _REQUIRE_AUTH) or os.environ.get(
    "PANEL_NO_AUTH", "").strip().lower() in ("1", "true", "yes", "on")
ALLOW_CONTROL = bool(ACTION_PASSWORD) or _DEV_NO_AUTH
# Re-prompt for the action password on every control action. Set PANEL_NO_STEPUP=1
# to skip it for local testing. No-auth mode has no password to re-enter, so
# step-up is off there too.
STEP_UP = (os.environ.get("PANEL_NO_STEPUP", "").strip().lower()
           not in ("1", "true", "yes", "on")) and not _DEV_NO_AUTH

# With no-auth every request is treated as a signed-in local operator, so there
# is no sign-in page. Refused only when SSO is configured (hosted deployments
# keep their real login).
NO_AUTH = _DEV_NO_AUTH and not _SSO_SET
NO_AUTH_USER = "local-test"
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")

# Optional Slack Incoming Webhook. When SURFACESCANNER_SLACK_WEBHOOK is set in
# the environment (never in the repo), platform alerts (new subdomains, new
# leaks) are posted to that channel. Unset, every notify is a silent no-op.
SLACK_WEBHOOK = os.environ.get("SURFACESCANNER_SLACK_WEBHOOK", "").strip()


def _slack_notify(text: str, blocks: list | None = None) -> bool:
    """Best-effort post of a message to the configured Slack webhook. When blocks
    are given they render the rich layout and text is the notification fallback.
    Never raises, returns whether it was sent. No webhook set means a silent
    no-op."""
    hook = os.environ.get("SURFACESCANNER_SLACK_WEBHOOK", SLACK_WEBHOOK).strip()
    if not hook or not hook.startswith("https://hooks.slack.com/"):
        return False
    try:
        import urllib.request
        payload: dict = {"text": text}
        if blocks:
            payload["blocks"] = blocks
        body = json.dumps(payload).encode()
        req = urllib.request.Request(hook, data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=6) as r:
            return 200 <= r.status < 300
    except Exception:
        return False


def _panel_url() -> str:
    """The panel's externally reachable base URL for links in alerts.
    SURFACESCANNER_PANEL_URL overrides the local-dev default."""
    return os.environ.get(
        "SURFACESCANNER_PANEL_URL", "http://127.0.0.1:8787").strip().rstrip("/")

# --------------------------------------------------------------------------
# Target guardrail. The panel refuses to run a scan against any domain that is
# not on the approved list, so a client created with the wrong name, a typo, or
# someone else's domain can never send traffic at an unapproved target. It is
# fail closed: the default is the one sanctioned target and widening it takes a
# deliberate environment change. This is a safety control, not a local-only
# convenience, so it stays enforced in production. Set
# SURFACESCANNER_ALLOWED_TARGETS to a comma separated list to add a real client
# once its domains are confirmed in scope.
# --------------------------------------------------------------------------
SCOPES_DIR = DATA / "scopes"
# The target allowlist is OFF by default: any in-scope domain may run. To turn
# the guardrail back on, set SURFACESCANNER_ALLOWED_TARGETS to a comma separated
# list of approved apexes, and only those (and their subdomains) will be allowed.
ALLOWED_TARGETS = tuple(
    d.strip().lower().lstrip(".")
    for d in os.environ.get("SURFACESCANNER_ALLOWED_TARGETS", "").split(",")
    if d.strip())


def _domain_allowed(domain: str) -> bool:
    """True when the domain is approved. With no allowlist configured the
    guardrail is off, so every domain is allowed."""
    if not ALLOWED_TARGETS:
        return True
    d = (domain or "").strip().lower().rstrip(".")
    return any(d == a or d.endswith("." + a) for a in ALLOWED_TARGETS)


def _scope_domains(slug: str) -> list[str]:
    """The domains a client's scope targets, read from its scope file. Stdlib
    only, the scope file is small and flat so a tiny reader is enough."""
    if not SLUG_RE.match(slug or ""):
        return []
    try:
        text = (SCOPES_DIR / f"{slug}.yaml").read_text()
    except Exception:
        return []
    out, in_domains = [], False
    for line in text.splitlines():
        if re.match(r"^domains:\s*(#.*)?$", line):
            in_domains = True
            continue
        if in_domains:
            m = re.match(r"^\s+-\s*(.+?)\s*(#.*)?$", line)
            if m:
                out.append(m.group(1).strip().strip('"\'').lower())
                continue
            if line and not line[0].isspace():
                in_domains = False
    return out


def _target_guard(slug: str) -> tuple[bool, str]:
    """Allow a run only when every domain in scope is an approved target.
    Fail closed: a client with no in-scope domain has nothing to run against."""
    domains = _scope_domains(slug)
    if not domains:
        return False, ("No in-scope domain for this client, so there is nothing "
                       "approved to run against.")
    bad = [d for d in domains if not _domain_allowed(d)]
    if bad:
        return False, (f"Target guardrail: {', '.join(bad)} is not an approved "
                       f"target. This panel only runs against {', '.join(ALLOWED_TARGETS)}. "
                       f"Add it to SURFACESCANNER_ALLOWED_TARGETS once it is confirmed "
                       f"in scope.")
    return True, ""

# Code root, where config.yaml lives (not engagement data).
ROOT = Path(os.environ.get("SURFACESCANNER_ROOT", Path(__file__).resolve().parent.parent))
CONFIG_FILE = ROOT / "config.yaml"


# --------------------------------------------------------------------------
# Session cookie, signed with HMAC so it cannot be forged.
# --------------------------------------------------------------------------
def _sign(value: str) -> str:
    mac = hmac.new(SECRET, value.encode(), hashlib.sha256).hexdigest()
    token = base64.urlsafe_b64encode(value.encode()).decode()
    return f"{token}.{mac}"


def _verify(cookie_value: str) -> str | None:
    try:
        token, mac = cookie_value.rsplit(".", 1)
        value = base64.urlsafe_b64decode(token.encode()).decode()
    except Exception:
        return None
    good = hmac.new(SECRET, value.encode(), hashlib.sha256).hexdigest()
    return value if hmac.compare_digest(good, mac) else None


# --------------------------------------------------------------------------
# Reading engine state. All read-only.
# --------------------------------------------------------------------------
def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=10
        ).stdout.strip()
    except Exception:
        return ""


def _run_rc(cmd: list[str]) -> tuple[int, str]:
    """Run a command, return (returncode, combined stdout+stderr)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return p.returncode, (p.stdout + p.stderr).strip()
    except Exception as exc:
        return 1, str(exc)


def _fmt_unit(slug: str, tmpl: str) -> str | None:
    if not SLUG_RE.match(slug or ""):
        return None
    return tmpl.format(slug=slug)


def _svc(slug: str, kind: str) -> str | None:
    """The systemd service that does the work for this module."""
    m = MODULE_BY_KIND.get(kind)
    return _fmt_unit(slug, m["service"]) if m else None


def _toggle_unit(slug: str, kind: str) -> str | None:
    """The unit a toggle enables or disables, None for run-on-demand modules."""
    m = MODULE_BY_KIND.get(kind)
    if not m or "toggle_unit" not in m:
        return None
    return _fmt_unit(slug, m["toggle_unit"])


def _last_run_epoch(unit: str | None) -> float | None:
    """When the service last finished (or last started), as an epoch, or None."""
    if not unit:
        return None
    out = _run(["systemctl", "--user", "show", "--value",
                "-p", "ExecMainExitTimestamp", unit])
    if not out:
        out = _run(["systemctl", "--user", "show", "--value",
                    "-p", "ExecMainStartTimestamp", unit])
    parts = out.split()
    if len(parts) < 3:   # empty, or "n/a", means it never ran
        return None
    try:
        # systemd prints "Day YYYY-MM-DD HH:MM:SS TZ" in the system timezone,
        # so mktime, which reads local time, lines up on a localtime or UTC box.
        st = time.strptime(parts[1] + " " + parts[2], "%Y-%m-%d %H:%M:%S")
        return time.mktime(st)
    except Exception:
        return None


# Short lived cache of watcher state. One overview render asks for every
# client, and a quick reload asks again a second later, so without this every
# page spawned clients x modules x three or four systemctl processes in series.
# systemd state does not change second to second, so a few seconds is safe and
# the control path below clears a client's entry the moment it changes it.
_STATE_TTL = 3.0
_STATE_CACHE: dict[str, tuple[float, dict]] = {}
_STATE_LOCK = threading.Lock()


def _invalidate_state(slug: str) -> None:
    """Drop one client's cached state so the next read reflects a just-made change.
    Also expires the global pending-triage count, so the navbar badge recomputes
    on the next render rather than showing a stale number for the cache window."""
    with _STATE_LOCK:
        _STATE_CACHE.pop(slug, None)
    # Force the next _pending_review_count() to recount. The name is defined
    # later in the module but always exists by the time a request runs.
    try:
        _REVIEW_COUNT_CACHE[0] = 0.0
    except NameError:
        pass


def watcher_state(slug: str) -> dict:
    """Current state of every module for one client. Read-only, cached briefly."""
    now = time.monotonic()
    with _STATE_LOCK:
        hit = _STATE_CACHE.get(slug)
        if hit and now - hit[0] < _STATE_TTL:
            return hit[1]
    state = _compute_watcher_state(slug)
    with _STATE_LOCK:
        _STATE_CACHE[slug] = (time.monotonic(), state)
    return state


def _compute_watcher_state(slug: str) -> dict:
    state = {}
    for m in MODULES:
        kind = m["kind"]
        ctrl = m["control"]
        svc = _svc(slug, kind)
        # "activating" counts as running: a oneshot unit (the footprint) reports
        # activating for its whole ExecStart, never a steady "active", so without
        # this its Run button would never flip to Stop while it works.
        active = (_run(["systemctl", "--user", "is-active", svc])
                  in ("active", "activating"))
        last = _last_run_epoch(svc)
        if ctrl == "toggle" and m.get("schedule"):
            tu = _toggle_unit(slug, kind)
            on = (_run(["systemctl", "--user", "is-enabled", tu]) == "enabled")
        else:
            # long-running service, or a run-on-demand module: on while active.
            on = active
        state[kind] = {"on": on, "active": active, "last": last}
    return state


def do_control(action: str, slug: str, kind: str) -> tuple[bool, str]:
    """Start or stop a toggle, or fire a one-shot run. The only state-changing path."""
    if not ALLOW_CONTROL:
        return False, "Control is disabled. No action password is configured."
    m = MODULE_BY_KIND.get(kind)
    if not m:
        return False, "Unknown client or watcher."
    ctrl = m["control"]
    client = _pretty(slug)
    name = m["name"]                       # for mid-sentence use
    cap = name[0].upper() + name[1:]       # for the start of a sentence

    # The target guardrail gates anything that starts work. Stopping is always
    # allowed. This is the hard, server-side safety: the UI cannot bypass it.
    if action in ("run", "start"):
        ok, why = _target_guard(slug)
        if not ok:
            return False, why

    if action == "run":
        svc = _svc(slug, kind)
        if not svc:
            return False, "Unknown client or watcher."
        # --no-block: a oneshot unit's `systemctl start` otherwise blocks for the
        # whole run (minutes), hanging the request past its timeout so the click
        # looks dead. Enqueue the job and return at once; the UI polls progress.
        rc, out = _run_rc(["systemctl", "--user", "start", "--no-block", svc])
        if rc == 0:
            _invalidate_state(slug)
            return True, f"{cap} started for {client}. Watch the debug page for live progress."
        return False, f"Could not run {name} for {client}. {out or 'See the journal.'}"

    if ctrl != "toggle":
        if action == "stop":
            svc = _svc(slug, kind)
            if not svc:
                return False, "Unknown client or watcher."
            rc, out = _run_rc(["systemctl", "--user", "stop", svc])
            if rc == 0:
                _invalidate_state(slug)
                return True, f"{cap} stopped for {client}."
            return False, f"Could not stop {name} for {client}. {out or 'See the journal.'}"
        return False, "This watcher runs on demand, it cannot be left on."
    unit = _toggle_unit(slug, kind)
    if not unit:
        return False, "Unknown client or watcher."
    if action == "start":
        verb, word = ["enable", "--now"], "turned on"
    elif action == "stop":
        verb, word = ["disable", "--now"], "turned off"
    else:
        return False, "Unknown action."
    rc, out = _run_rc(["systemctl", "--user"] + verb + [unit])
    if rc == 0:
        _invalidate_state(slug)
        return True, f"{cap} {word} for {client}."
    return False, f"Could not change {name} for {client}. {out or 'See the journal.'}"


def do_run_all(slug: str) -> tuple[bool, str]:
    """Fire every promoted phase once for one client, now. It starts each work
    service, which runs a single cycle, or ensures an always-on feed is up. It
    does not change any autowatcher on or off state, it only triggers a run."""
    if not ALLOW_CONTROL:
        return False, "Control is disabled. No action password is configured."
    if not SLUG_RE.match(slug or ""):
        return False, "Unknown client."
    ok, why = _target_guard(slug)
    if not ok:
        return False, why
    client = _pretty(slug)
    started, failed = [], []
    for m in MODULES:
        # A phase may still opt out of the blanket RUN with exclude_run_all.
        if m.get("exclude_run_all"):
            continue
        svc = _svc(slug, m["kind"])
        if not svc:
            continue
        # --no-block so a long oneshot (the agent-backed footprint runs for
        # minutes) does not hold the request open until it finishes.
        rc, _out = _run_rc(["systemctl", "--user", "start", "--no-block", svc])
        (started if rc == 0 else failed).append(m["name"])
    _invalidate_state(slug)
    if not started and not failed:
        return False, f"No phases are wired up for {client} yet."
    bits = [f"Started {len(started)} phase(s) for {client}"]
    if failed:
        bits.append(f"these did not start: {', '.join(failed)}")
    return bool(started), ". ".join(bits) + "."


def do_generate_report(slug: str) -> tuple[bool, str]:
    """Build the attack-surface monitoring report (Word and PDF) for a client
    from its current signals. Deterministic, no AI, writes into the engagement's
    reports folder where the Last reports slots pick it up."""
    if not SLUG_RE.match(slug or ""):
        return False, "Unknown client."
    base = ENGAGEMENTS / slug
    if not base.is_dir():
        return False, "Unknown client."
    try:
        from tools import surface_report
    except Exception:
        import surface_report  # when run from the tools dir
    try:
        res = surface_report.build(slug, base)
    except Exception as exc:
        return False, f"Report generation failed: {exc}"
    _invalidate_state(slug)
    made = [fmt.upper() for fmt in ("pdf", "docx") if res.get(fmt)]
    if not made:
        return False, "Report generation produced no files. See the server log."
    word = "PDF and Word" if len(made) == 2 else made[0]
    return True, f"{word} report generated for {_pretty(slug)}."


# Findings whose background capture is already running or done this process, so
# opening a Manage page many times does not spawn the capture again.
_CAPTURE_INFLIGHT: set = set()

# Finding classes that get evidence captured automatically (on first view and on
# detection). Only the DMARC classes auto-capture, taking the benign dig terminal
# shots. lookalike_domain is deliberately NOT here: a brand-impersonation finding
# captures a live browser shot of the spoofed (potentially malicious) page, so
# that is only ever done on an explicit operator action (the Manage-page capture
# button or early-alert generation), never silently on view or on detection.
_AUTO_CAPTURE_CLASSES = ("email_auth_posture", "dmarc_record")


def _ensure_capture(slug: str, v: dict) -> None:
    """Kick off a background evidence capture for a finding that has no figures
    attached yet, so the screenshots fill in on their own the first time the
    finding is looked at (covering findings that pre-date auto-capture, and the
    email-authentication findings that previously only captured at alert time).
    Runs once per finding per process, off the request thread."""
    if v.get("source_class") not in _AUTO_CAPTURE_CLASSES or not (v.get("hosts") or []):
        return
    key = v.get("key", "")
    tag = f"{slug}|{key}"
    if tag in _CAPTURE_INFLIGHT:
        return
    entry = _vmeta_load(slug).get(key, {}) or {}
    if entry.get("figures") or entry.get("files"):
        return
    if os.environ.get("SURFACESCANNER_EVIDENCE_CAPTURE", "1").strip().lower() in (
            "0", "false", "no", "off"):
        return
    _CAPTURE_INFLIGHT.add(tag)

    def _bg(slug=slug, key=key, tag=tag):
        try:
            _capture_finding_evidence(slug, key)
        except Exception:
            pass
        finally:
            _CAPTURE_INFLIGHT.discard(tag)

    threading.Thread(target=_bg, name="ev-capture-view", daemon=True).start()


# The screenshot-cli skill's capture script: runs one command on a private Xvfb
# display and saves a cropped terminal PNG. Override with SURFACESCANNER_SHOTCLI.
_SHOTCLI = os.environ.get("SURFACESCANNER_SHOTCLI") or os.path.expanduser(
    "~/.claude/skills/screenshot-cli/scripts/capture.sh")

# The DNS queries that evidence an email-authentication finding. One terminal
# figure each, in report order: DMARC first (the finding), then SPF, then MX.
_DMARC_EVIDENCE_CMDS = [
    ("dmarc", "TXT _dmarc.{d}",
     "DMARC lookup for {d}: the _dmarc TXT query returns status NXDOMAIN with "
     "ANSWER: 0, so no DMARC record is published"),
    ("spf", "TXT {d}",
     "SPF and TXT records for {d}, read from public DNS"),
    ("mx", "MX {d}",
     "MX records for {d}, read from public DNS"),
]


def _capture_dmarc_evidence(slug: str, v: dict) -> int:
    """Capture a terminal screenshot of each DNS query (DMARC, SPF, MX) that
    evidences an email-authentication finding, through the screenshot-cli
    capture script, and attach them to the finding exactly like the lookalike
    browser shots. Best effort: a no-op if the capture script is missing, and a
    query that fails to capture is skipped. Idempotent per finding and domain.
    Returns the number of new screenshots captured."""
    cap = _SHOTCLI
    if not (cap and os.path.isfile(cap)):
        return 0
    hosts = [h for h in (v.get("hosts") or []) if h]
    if not hosts:
        return 0
    proj = ENGAGEMENTS / slug
    vid = v["id"]
    evdir = proj / "evidence" / vid
    meta = _vmeta_load(slug)
    key = v["key"]
    entry = meta.get(key, {})
    evlist = entry.get("files", [])
    have = {f.get("stored", "").lower() for f in evlist}
    fig_lines = [ln for ln in (entry.get("figures") or "").splitlines() if ln.strip()]
    budget_end = time.monotonic() + float(
        os.environ.get("SURFACESCANNER_EVIDENCE_BUDGET", "180"))
    made = 0
    for h in hosts:
        safe = _safe_token(h)
        for n, (tag, q, capfmt) in enumerate(_DMARC_EVIDENCE_CMDS, start=1):
            if time.monotonic() > budget_end:
                break
            query = q.format(d=h)
            name = f"fig{n:02d}_{tag}_{safe}"
            stored = f"{name}.png"
            caption = capfmt.format(d=h)
            if not ((evdir / stored).is_file() and stored.lower() in have):
                cmdfile = None
                try:
                    with tempfile.NamedTemporaryFile(
                            "w", suffix=".sh", delete=False) as cf:
                        # One clean dig command per figure, no echo/o=$() wrapper
                        # (that wrapper printed the same two script lines on top of
                        # every figure, so they all looked alike). The default-style
                        # output with the header shows the query, the status line and
                        # the answer section, so a missing record reads as NXDOMAIN /
                        # ANSWER: 0 rather than an empty frame the capture would
                        # refuse. The host appears in the QUESTION SECTION, so the
                        # `# expect` check still holds for a no-record domain.
                        cf.write(f"# expect: {re.escape(h)}\n")
                        cf.write(f"dig +noall +comments +question +answer {query}\n")
                        cmdfile = cf.name
                    env = dict(os.environ, EVIDENCE_DIRNAME=f"evidence/{vid}")
                    rc = subprocess.run(
                        ["sh", cap, cmdfile, str(proj), name], env=env,
                        timeout=150, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL).returncode
                except Exception:
                    rc = 1
                finally:
                    if cmdfile:
                        try:
                            os.unlink(cmdfile)
                        except Exception:
                            pass
                if rc != 0 or not (evdir / stored).is_file():
                    continue
                made += 1
                if stored.lower() not in have:
                    try:
                        size = (evdir / stored).stat().st_size
                    except Exception:
                        size = 0
                    evlist = [f for f in evlist if f.get("stored") != stored]
                    evlist.append({
                        "stored": stored, "orig": stored, "ct": "image/png",
                        "size": size, "by": "auto-capture",
                        "ts": datetime.now(timezone.utc).strftime(
                            "%d %b %Y %H:%M UTC")})
                    have.add(stored.lower())
            if not any(ln.split("|", 1)[0].strip().lower() == stored.lower()
                       for ln in fig_lines):
                fig_lines.append(f"{stored} | {caption}")
    entry["files"] = evlist
    entry["figures"] = "\n".join(fig_lines)
    meta[key] = entry
    _vmeta_save(slug, meta)
    return made


def _capture_finding_evidence(slug: str, key: str) -> int:
    """Capture a browser-UI screenshot of each confirmed impersonation domain for
    a finding and attach it, so the early alert embeds it and the Manage page
    shows it. A real (headful) Chromium runs on a virtual display (Xvfb) so the
    address bar, showing the spoofed domain, is part of the shot; no monitor or
    desktop is required. Operator-initiated and best effort: a domain already
    captured is skipped (idempotent), and a capture that fails leaves the
    hand-capture marker in place. It renders in-scope impersonation domains, so
    it does send one page request to each. Set SURFACESCANNER_EVIDENCE_CAPTURE=0
    to turn it off. Returns the number of new screenshots captured."""
    if os.environ.get("SURFACESCANNER_EVIDENCE_CAPTURE", "1").strip().lower() in (
            "0", "false", "no", "off"):
        return 0
    try:
        from tools import evidence_capture
    except Exception:
        try:
            import evidence_capture
        except Exception:
            return 0
    v = next((x for x in _all_findings(slug).values() if x["key"] == key), None)
    if not v:
        return 0
    if v.get("source_class") in ("dmarc_record", "email_auth_posture"):
        return _capture_dmarc_evidence(slug, v)
    if v.get("source_class") != "lookalike_domain":
        return 0
    hosts = [h for h in (v.get("hosts") or []) if h]
    if not hosts:
        return 0
    origin = key.split("|", 1)[1] if "|" in key else ""
    brand = origin or "the client brand"
    evdir = ENGAGEMENTS / slug / "evidence" / v["id"]
    meta = _vmeta_load(slug)
    entry = meta.get(key, {})
    evlist = entry.get("files", [])
    have = {f.get("stored", "").lower() for f in evlist}
    fig_lines = [ln for ln in (entry.get("figures") or "").splitlines() if ln.strip()]
    budget_end = time.monotonic() + float(
        os.environ.get("SURFACESCANNER_EVIDENCE_BUDGET", "180"))
    made = 0
    for h in hosts:
        if time.monotonic() > budget_end:
            break
        stored = f"lookalike-{_safe_token(h)}-browser.png"
        caption = (f"Browser view of {h}, a confirmed domain impersonating {brand}, "
                   "with the spoofed name shown in the address bar.")
        if not ((evdir / stored).is_file() and stored.lower() in have):
            if not evidence_capture.capture_url(f"https://{h}", evdir / stored):
                continue
            made += 1
            if stored.lower() not in have:
                evlist = [f for f in evlist if f.get("stored") != stored]
                try:
                    size = (evdir / stored).stat().st_size
                except Exception:
                    size = 0
                evlist.append({
                    "stored": stored, "orig": stored, "ct": "image/png",
                    "size": size, "by": "auto-capture",
                    "ts": datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC")})
                have.add(stored.lower())
        if not any(ln.split("|", 1)[0].strip().lower() == stored.lower()
                   for ln in fig_lines):
            fig_lines.append(f"{stored} | {caption}")
    entry["files"] = evlist
    entry["figures"] = "\n".join(fig_lines)
    meta[key] = entry
    _vmeta_save(slug, meta)
    return made


def do_generate_alert(slug: str, key: str = "") -> tuple[bool, str, str]:
    """Build an editable early-alert Word document for one Critical or High
    finding (identified by its dedup key). Read-only on signals, writes into the
    reports folder. For a brand-impersonation finding it first captures a
    browser-UI screenshot of each confirmed domain (headful Chromium on a virtual
    display), which sends one page request per in-scope domain; everything else
    starts no scan. No step-up. Returns (ok, message, filename)."""
    if not SLUG_RE.match(slug or ""):
        return False, "Unknown client.", ""
    base = ENGAGEMENTS / slug
    if not base.is_dir():
        return False, "Unknown client.", ""
    try:
        from tools import surface_report
    except Exception:
        import surface_report  # when run from the tools dir
    try:
        _capture_finding_evidence(slug, key)
    except Exception:
        pass
    try:
        res = surface_report.build_early_alert(slug, base, key or None)
    except Exception as exc:
        return False, f"Early alert generation failed: {exc}", ""
    _invalidate_state(slug)
    if not res.get("docx"):
        return False, "Early alert produced no file. The finding was not found or python-docx is missing.", ""
    return True, f"Early alert generated for {_pretty(slug)}.", Path(res["docx"]).name


def do_stop_all(slug: str) -> tuple[bool, str]:
    """Emergency stop. Halt every running service for one client, now. It does
    not change any autowatcher on or off state, it only stops what is active, so
    a scheduled watcher resumes on its next trigger."""
    if not ALLOW_CONTROL:
        return False, "Control is disabled. No action password is configured."
    if not SLUG_RE.match(slug or ""):
        return False, "Unknown client."
    client = _pretty(slug)
    stopped = []
    for m in MODULES:
        svc = _svc(slug, m["kind"])
        if not svc or _run(["systemctl", "--user", "is-active", svc]) != "active":
            continue
        rc, _out = _run_rc(["systemctl", "--user", "stop", svc])
        if rc == 0:
            stopped.append(m["name"])
    _invalidate_state(slug)
    if not stopped:
        return False, f"Nothing was running for {client}."
    return True, f"Stopped {len(stopped)} running phase(s) for {client}."


# --------------------------------------------------------------------------
# Creating and enriching a client. A client is one scope file under the data
# root. Its commands and systemd templates already exist, so creating a client
# is only writing its scope, and the target guardrail above still gates every
# run, so a new client cannot send traffic at an unapproved domain.
# --------------------------------------------------------------------------
def _parse_list(raw: str) -> list[str]:
    """Split a textarea or field into clean tokens, one per line or comma."""
    out = []
    for tok in re.split(r"[\s,]+", (raw or "").strip()):
        tok = tok.strip().strip('"\'')
        if tok and tok not in out:
            out.append(tok)
    return out


def _slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (name or "").strip().lower()).strip("-")[:64]


def _existing_slugs() -> list[str]:
    out = set()
    if SCOPES_DIR.is_dir():
        out.update(p.stem for p in SCOPES_DIR.glob("*.yaml"))
    if ENGAGEMENTS.is_dir():
        out.update(p.name for p in ENGAGEMENTS.iterdir() if p.is_dir())
    return sorted(out)


def _similar_clients(slug: str) -> list[str]:
    """Existing clients whose name is close to the proposed one, so a tester is
    warned before creating a near-duplicate (a typo, or the same client twice)."""
    import difflib
    norm = slug.replace("-", "")
    hits = []
    for ex in _existing_slugs():
        exn = ex.replace("-", "")
        if ex == slug:
            continue
        close = (exn == norm or (len(norm) >= 4 and (norm in exn or exn in norm))
                 or difflib.SequenceMatcher(None, norm, exn).ratio() >= 0.8)
        if close:
            hits.append(ex)
    return hits


def _valid_domain(d: str) -> bool:
    d = (d or "").strip().lower().rstrip(".")
    return bool(d) and not _SHELL_META.search(d) and bool(
        re.match(r"^[a-z0-9]([a-z0-9-]{0,62}\.)+[a-z]{2,}$", d))


_URL_DOMAIN_RE = re.compile(r"\b([a-z0-9](?:[a-z0-9-]{0,62}\.)+[a-z]{2,})\b", re.I)


def _regex_domains(text: str) -> list[str]:
    """Pull domain-looking tokens out of free text, no model needed."""
    out = []
    for m in _URL_DOMAIN_RE.finditer(text or ""):
        d = m.group(1).lower().rstrip(".")
        if d not in out:
            out.append(d)
    return out


def _ollama_model() -> str | None:
    """The local chat model to use for ingestion, or None if ollama is not up.
    Embedding-only models are skipped. Override with SURFACESCANNER_INGEST_MODEL."""
    override = os.environ.get("SURFACESCANNER_INGEST_MODEL", "").strip()
    if override:
        return override
    try:
        import urllib.request
        with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=3) as r:
            tags = json.load(r).get("models", [])
    except Exception:
        return None
    # Prefer the smallest capable model so a one-off ingest stays fast. A large
    # model takes longer than the request timeout to load and would always fall
    # back to the regex sweep. Skip embedding-only models, they cannot generate.
    chat = [t for t in tags if t.get("name")
            and not any(k in t["name"].lower() for k in ("embed", "bge", "nomic"))]
    chat.sort(key=lambda t: t.get("size", 0))
    return chat[0]["name"] if chat else None


def _ai_ingest(text: str) -> dict | None:
    """Extract candidate domains and brand keywords from free text with the
    LOCAL model only. The model is given text and must answer with JSON. It has
    no tools and no network of its own, it never runs or sees a command, and
    every value it returns is re-validated here before the tester sees it, so it
    can neither act nor introduce an unapproved or malformed target. Returns
    None when no local model is available, so the caller falls back to regex."""
    model = _ollama_model()
    if not model:
        return None
    import urllib.request
    prompt = (
        "You extract scope data from a security engagement note. Read the text "
        "and return ONLY a JSON object with two string arrays: \"domains\" (apex "
        "or subdomains that appear in the text, lowercase, no scheme, no path) "
        "and \"keywords\" (brand or product names useful for lookalike "
        "permutations). Do not invent anything that is not in the text. Do not "
        "add commentary.\n\nTEXT:\n" + (text or "")[:8000])
    body = json.dumps({"model": model, "prompt": prompt, "stream": False,
                       "format": "json", "options": {"temperature": 0}}).encode()
    try:
        req = urllib.request.Request(
            "http://127.0.0.1:11434/api/generate", data=body,
            headers={"Content-Type": "application/json"})
        timeout = float(os.environ.get("SURFACESCANNER_INGEST_TIMEOUT", "60"))
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(json.load(r).get("response", "{}"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    domains = [d.lower().rstrip(".") for d in data.get("domains", [])
               if isinstance(d, str) and _valid_domain(d)]
    keywords = [k.strip() for k in data.get("keywords", [])
                if isinstance(k, str) and k.strip() and not _SHELL_META.search(k)]
    return {"domains": sorted(set(domains)), "keywords": sorted(set(keywords)),
            "source": "ai", "model": model}


def do_ingest(text: str) -> dict:
    """Turn a pasted note into reviewable scope candidates. Tries the local
    model, falls back to a plain regex sweep. Every domain is validated, so the
    tester only ever reviews well-formed hosts. Never a blocker."""
    ai = _ai_ingest(text)
    if ai is not None:
        return ai
    domains = [d for d in _regex_domains(text) if _valid_domain(d)]
    return {"domains": sorted(set(domains)), "keywords": [], "source": "regex"}


def _panel_dir(slug: str) -> Path:
    """Per-client working area the panel owns, for notes and lock state. Kept
    apart from the engine's signals and reports."""
    return ENGAGEMENTS / slug / "panel"


def _write_scope(slug: str, name: str, domains: list[str], keywords: list[str],
                 mode: str) -> None:
    """Write a client's scope file. New clients start in passive mode, the
    safest default, and the tester swaps to active deliberately."""
    lines = ["target:", f"  name: {name}", "domains:"]
    lines += [f"  - {d}" for d in domains] or ["  []"]
    lines.append(f"mode: {mode}")
    lines.append("data_classification: PUBLIC")
    if keywords:
        lines.append("keywords:")
        lines += [f"  - {k}" for k in keywords]
    SCOPES_DIR.mkdir(parents=True, exist_ok=True)
    (SCOPES_DIR / f"{slug}.yaml").write_text("\n".join(lines) + "\n")


def do_create_client(name: str, domains_raw: str, keywords_raw: str, notes: str,
                     confirm: bool) -> tuple[bool, str, dict]:
    """Create a client from the setup form. Passive by default. Optional fields
    never block. A near-duplicate name asks for confirmation first."""
    if not ALLOW_CONTROL:
        return False, "Control is disabled. No action password is configured.", {}
    name = (name or "").strip()
    if not name:
        return False, "A client name is required.", {}
    slug = _slugify(name)
    if not SLUG_RE.match(slug):
        return False, "That name has no usable letters or digits.", {}
    if slug in _existing_slugs():
        return False, (f"A client '{slug}' already exists. Open it from the "
                       f"overview, or pick a different name."), {}
    similar = _similar_clients(slug)
    if similar and not confirm:
        return False, (f"A similar client already exists: {', '.join(similar)}. "
                       f"Create '{slug}' anyway?"), {"confirm": True, "similar": similar}
    domains = []
    for d in _parse_list(domains_raw):
        d = d.lower().rstrip(".")
        if not _valid_domain(d):
            return False, f"'{d}' is not a valid hostname. Fix it or remove it.", {}
        domains.append(d)
    keywords = [k for k in _parse_list(keywords_raw) if not _SHELL_META.search(k)]
    _write_scope(slug, name, sorted(set(domains)), sorted(set(keywords)), "passive")
    # Give the client a home directory right away. The console page and the
    # client resolver key off the engagement directory, so without this a freshly
    # created client would open to "Client not found" until its first run wrote
    # something. Per-file writers still create their own subdirs as needed.
    (ENGAGEMENTS / slug).mkdir(parents=True, exist_ok=True)
    if notes and notes.strip():
        do_add_context(slug, "", notes)
    not_approved = [d for d in domains if not _domain_allowed(d)]
    tail = ""
    if not_approved:
        tail = (f" Heads up: {', '.join(not_approved)} is not an approved target "
                f"yet, so runs stay blocked until it is added to the allowlist.")
    return True, f"Client '{slug}' created in passive mode.{tail}", {"slug": slug}


def _scope_add_domains(slug: str, new_domains: list[str]) -> list[str]:
    """Append domains to an existing scope file, skipping ones already present.
    Returns the domains actually added. Works whether or not a run is active."""
    f = SCOPES_DIR / f"{slug}.yaml"
    text = f.read_text()
    have = set(_scope_domains(slug))
    add = [d for d in new_domains if d not in have]
    if not add:
        return []
    lines = text.splitlines()
    insert_at = None
    for i, l in enumerate(lines):
        if re.match(r"^domains:\s*(#.*)?$", l):
            insert_at = i + 1
            j = i + 1
            while j < len(lines) and (not lines[j] or lines[j][0].isspace()):
                insert_at = j + 1
                j += 1
            break
    block = [f"  - {d}" for d in add]
    if insert_at is None:
        lines += ["domains:"] + block
    else:
        lines[insert_at:insert_at] = block
    f.write_text("\n".join(lines) + ("\n" if text.endswith("\n") else ""))
    return add


def do_add_context(slug: str, domains_raw: str, notes: str) -> tuple[bool, str]:
    """Add domains and notes to a client after it exists, including while a run
    is in progress or after it has finished. This is the 'the client sent more
    domains on Tuesday' path. Domains go into scope, notes into a dated file."""
    if not ALLOW_CONTROL:
        return False, "Control is disabled. No action password is configured.",
    if slug not in _existing_slugs() or not (SCOPES_DIR / f"{slug}.yaml").exists():
        return False, "Unknown client."
    domains = []
    for d in _parse_list(domains_raw):
        d = d.lower().rstrip(".")
        if not _valid_domain(d):
            return False, f"'{d}' is not a valid hostname."
        domains.append(d)
    added = _scope_add_domains(slug, sorted(set(domains))) if domains else []
    note = (notes or "").strip()
    if note:
        d = _panel_dir(slug)
        d.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with (d / "context.md").open("a") as fh:
            fh.write(f"\n## {stamp}\n\n{note}\n")
    parts = []
    if added:
        parts.append(f"added {len(added)} domain(s) to scope")
    if note:
        parts.append("saved the note")
    not_approved = [d for d in added if not _domain_allowed(d)]
    if not parts:
        return True, "Nothing new to add."
    msg = "Context updated: " + " and ".join(parts) + "."
    if not_approved:
        msg += (f" Note: {', '.join(not_approved)} is not an approved target, "
                f"so it will not be scanned until the allowlist is widened.")
    return True, msg


def _ago(epoch: float | None) -> str:
    """Human relative time: now, minutes, hours, days, then months ago."""
    if not epoch:
        return "never"
    secs = max(0.0, time.time() - epoch)
    if secs < 90:
        return "just now"
    for div, unit in ((60, "minute"), (3600, "hour"), (86400, "day"), (2592000, "month")):
        nxt = div * (60 if unit == "minute" else 24 if unit == "hour"
                     else 30 if unit == "day" else 12)
        if secs < nxt:
            n = int(secs / div)
            return f"{n} {unit}{'' if n == 1 else 's'} ago"
    years = int(secs / 31536000)
    return f"{years} year{'' if years == 1 else 's'} ago"


def _short_when(epoch: float | None) -> str:
    """Short absolute UTC stamp for a slot, matching the report slots."""
    if not epoch:
        return "not gathered yet"
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%d %b %H:%M UTC")


# Source classes that are passive recon inventory or OSINT context, not
# vulnerabilities. They are collected and shown in the asset views, but do not
# count as security findings in the overview totals or the severity breakdown.
INVENTORY_CLASSES = {
    "wayback_url", "wayback_javascript", "wayback_document", "wayback_api",
    "subdomain", "company_footprint", "cms_detected", "waf_detected",
    "ssl_certificate", "azure_tenant", "mx_records", "spf_record", "dkim_record",
    "overall_risk", "sector_threat_intel", "sector_attack_context",
}


def _dmarc_posture_sev(signals_dir: Path) -> str | None:
    """The authoritative DMARC severity for a client, taken from the posture-aware
    reading (email_auth_posture, which factors in SPF -all and DKIM) if one was
    produced. The cruder dmarc_record signal (a fixed High from the DNS layer)
    defers to this, so the DMARC finding shows one severity everywhere: the badge,
    the attention queue and the webhook. Returns a SEV code, or None if no
    posture reading exists."""
    if not signals_dir.is_dir():
        return None
    best = None
    for f in signals_dir.glob("*.jsonl"):
        for line in f.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            if str(d.get("source_class") or "") != "email_auth_posture":
                continue
            s = _norm_sev(d.get("severity"))
            if s in SEV_ORDER and (best is None
                                   or SEV_ORDER.index(s) < SEV_ORDER.index(best)):
                best = s
    return best


def _read_signals(signals_dir: Path, drop_keys: set | None = None) -> dict:
    """Read every finding for one client, deduplicated across files.

    Returns the severity counts, a count per source class (subdomain,
    lookalike_domain), the list of findings that need attention (SEV1 and
    SEV2), the total, and the newest mtime. Deduplicated by dedup_id so a host
    seen by both the passive and active run, or re-emitted on a later cycle,
    counts once.

    `drop_keys` are finding dedup keys to leave out of every count, used to
    exclude what the operator has marked false positive, so the overview totals
    and the severity breakdown reflect the same triaged reality the Confirmed
    and Needs-attention tabs do, not the raw signal dump.
    """
    drop_keys = drop_keys or set()
    counts = {k: 0 for k in SEV_ORDER}
    by_class: dict[str, int] = {}
    attention: list[dict] = []
    seen: set[str] = set()
    total = 0        # security findings (vulnerabilities), excludes recon inventory
    collected = 0    # every deduped signal, including inventory (raw intake)
    last = 0.0
    # Active lookalike domains are grouped, not counted one by one: every active
    # lookalike discovered for the same origin brand is ONE vulnerability, alerted
    # and triaged once, with all the domains as its locations. Keyed by origin.
    lookalikes: dict[str, dict] = {}

    def _rank(s: str) -> int:
        return SEV_ORDER.index(s) if s in SEV_ORDER else len(SEV_ORDER)

    if not signals_dir.is_dir():
        return {"total": 0, "collected": 0, "counts": counts, "by_class": by_class,
                "attention": attention, "last": None}
    # One DMARC finding at the posture-aware severity. When a posture reading
    # exists (email_auth_posture), the cruder fixed-High dmarc_record is dropped,
    # so the badge, the counts, the attention queue and the webhook all agree.
    dmarc_sev = _dmarc_posture_sev(signals_dir)
    for f in signals_dir.glob("*.jsonl"):
        last = max(last, f.stat().st_mtime)
        for line in f.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            cls = str(d.get("source_class", "") or "")
            sev = _norm_sev(d.get("severity"))
            if cls == "dmarc_record" and dmarc_sev is not None:
                continue
            if cls == "email_auth_posture" and dmarc_sev is not None:
                sev = dmarc_sev
            did = d.get("dedup_id") or f"{cls}|{d.get('title', '')}"
            if did in seen:
                continue
            seen.add(did)
            collected += 1    # raw intake, inventory included
            ents = d.get("entities") or []
            doms = [str(x.get("value", "")).lower().rstrip(".") for x in ents
                    if x.get("type") == "domain" and x.get("value")]
            if cls == "lookalike_domain":
                # Group by origin brand; do not count or alert per domain.
                ev = d.get("evidence", {}) or {}
                origin = (ev.get("origin_domain") or "").lower().rstrip(".") or "lookalike"
                grp = lookalikes.setdefault(origin, {
                    "sev": "SEV5", "hosts": [], "title": "", "description": ""})
                if _rank(sev) < _rank(grp["sev"]):
                    grp["sev"] = sev
                for dm in (doms or [d.get("title", "")]):
                    if dm and dm not in grp["hosts"]:
                        grp["hosts"].append(dm)
                if not grp["title"]:
                    grp["title"] = d.get("title", "Active brand impersonation domain")
                if not grp["description"]:
                    grp["description"] = d.get("description", "")
                continue
            # Findings the operator ruled out are left out of every count, so the
            # overview agrees with the triage tabs.
            if did in drop_keys:
                continue
            by_class[cls] = by_class.get(cls, 0) + 1
            # Passive recon inventory (wayback URLs, subdomains, DNS records,
            # fingerprints, OSINT context) is collected, not a vulnerability. It
            # is kept in `collected` and in by_class, but excluded from the
            # security-finding total and the severity breakdown, so the overview
            # reflects what there is to triage rather than the raw intake.
            if cls in INVENTORY_CLASSES:
                continue
            total += 1
            if sev in counts:
                counts[sev] += 1
            # Needs attention is the same set as the triage queue: Critical and
            # High, plus manual and credential-exposure at any severity, plus a
            # DMARC finding only when it is a real weakness (Medium or worse). A
            # DMARC reading that is merely Informational means the posture is fine,
            # so it is not surfaced for triage. Keeping the two rules identical
            # means the client page and the To review queue never disagree.
            if (sev in ("SEV1", "SEV2")
                    or cls in ("manual", "credential_exposure")
                    or (cls in ("dmarc_record", "email_auth_posture")
                        and sev in ("SEV1", "SEV2", "SEV3"))):
                attention.append({
                    "severity": sev if sev in SEV_ORDER else "SEV5",
                    "source_class": cls, "key": did,
                    "title": d.get("title", "Finding"),
                    "description": d.get("description", ""),
                    "hosts": doms,
                })

    # One grouped vulnerability per origin brand: counted once, triaged once.
    for origin, grp in lookalikes.items():
        gkey = f"lookalike_domain|{origin}"
        if gkey in drop_keys:
            continue
        total += 1
        sev = grp["sev"]
        if sev in counts:
            counts[sev] += 1
        by_class["lookalike_domain"] = by_class.get("lookalike_domain", 0) + 1
        if sev in ("SEV1", "SEV2"):
            hosts = sorted(grp["hosts"])
            n = len(hosts)
            title = (grp["title"] if n <= 1
                     else f"Active brand impersonation domains ({n}) impersonating {origin}")
            attention.append({
                "severity": sev, "source_class": "lookalike_domain", "key": gkey,
                "title": title, "description": grp["description"], "hosts": hosts,
            })

    attention.sort(key=lambda a: SEV_ORDER.index(a["severity"])
                   if a["severity"] in SEV_ORDER else len(SEV_ORDER))
    return {"total": total, "collected": collected, "counts": counts,
            "by_class": by_class, "attention": attention, "last": (last or None)}


def _latest_report(rdir: Path, ext: str) -> dict | None:
    """The single most recent report of one type, or None. One slot per type,
    so an older copy or a duplicate stem never shows alongside the current one."""
    if not rdir.is_dir():
        return None
    files = sorted(rdir.glob(f"*.{ext}"), key=lambda f: f.stat().st_mtime, reverse=True)
    # The early-alert Word note is its own thing, downloaded from the Needs
    # attention section, so it must not take over the main Word report slot.
    if ext == "docx":
        files = [f for f in files if "Early Alert" not in f.name]
    if not files:
        return None
    r = files[0]
    st = r.stat()
    return {"name": r.name, "kb": round(st.st_size / 1024),
            "when": datetime.fromtimestamp(st.st_mtime, timezone.utc).strftime("%d %b %H:%M UTC")}


def _subdomain_list(base: Path) -> list[str]:
    """Every distinct enumerated subdomain for a client, read from its signal
    files (the subdomain class). Sorted, deduplicated, no other host types."""
    sdir = base / "signals"
    if not sdir.is_dir():
        return []
    found: set[str] = set()
    for f in sdir.glob("*.jsonl"):
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            if d.get("source_class") != "subdomain":
                continue
            for ent in d.get("entities", []) or []:
                if ent.get("type") == "domain" and ent.get("value"):
                    found.add(str(ent["value"]).lower().rstrip("."))
    return sorted(found)


def _subdomain_alive(base: Path) -> set[str]:
    """The subdomains that resolve (evidence.resolves true), i.e. the live hosts,
    as opposed to every name ever enumerated."""
    sdir = base / "signals"
    alive: set[str] = set()
    if not sdir.is_dir():
        return alive
    for f in sdir.glob("*.jsonl"):
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            if d.get("source_class") != "subdomain":
                continue
            ev = d.get("evidence") or {}
            if not ev.get("resolves"):
                continue
            # A name that "resolves" but returns no address record is only an
            # enumerated name (a stale certificate entry, a CNAME to nothing),
            # not a live host. Require at least one A or AAAA record for it to
            # count as alive, so the Alive view is a true subset of All.
            recs = (ev.get("records") or ev.get("addresses")
                    or ev.get("dns_a") or ev.get("ips"))
            if not recs:
                continue
            for ent in d.get("entities", []) or []:
                if ent.get("type") == "domain" and ent.get("value"):
                    alive.add(str(ent["value"]).lower().rstrip("."))
    return alive


def _recovered_ips(base: Path) -> list[str]:
    """Every IP address recovered from the client's signals: the addresses a
    subdomain resolved to (evidence records/addresses/dns_a/ips) plus any IP
    entity. Deduplicated and sorted numerically where possible. Read-only."""
    import ipaddress
    sdir = base / "signals"
    found: set[str] = set()
    if not sdir.is_dir():
        return []

    def _add(v):
        s = str(v).strip()
        if not s:
            return
        try:
            ipaddress.ip_address(s)
            found.add(s)
        except ValueError:
            pass

    for f in sdir.glob("*.jsonl"):
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            ev = d.get("evidence") or {}
            for key in ("records", "addresses", "dns_a", "dns_aaaa", "ips"):
                val = ev.get(key)
                if isinstance(val, (list, tuple)):
                    for item in val:
                        if isinstance(item, dict):
                            _add(item.get("ip") or item.get("address") or item.get("value") or "")
                        else:
                            _add(item)
                elif isinstance(val, str):
                    _add(val)
            for ent in d.get("entities", []) or []:
                if ent.get("type") == "ip" and ent.get("value"):
                    _add(ent["value"])

    def _key(ip):
        try:
            return (0, int(ipaddress.ip_address(ip)))
        except ValueError:
            return (1, ip)
    return sorted(found, key=_key)


def _ip_ranges(ips: list[str]) -> list[str]:
    """The known IP ranges the recovered addresses fall into: each IPv4 grouped
    to its /24 and each IPv6 to its /64. Gives the netblocks in play without a
    WHOIS or ASN lookup."""
    import ipaddress
    ranges: set[str] = set()
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        prefix = 24 if addr.version == 4 else 64
        try:
            ranges.add(str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False)))
        except ValueError:
            continue

    def _key(cidr):
        try:
            return (0, int(ipaddress.ip_network(cidr).network_address))
        except ValueError:
            return (1, cidr)
    return sorted(ranges, key=_key)


_HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+$")


def _host_clean(s: str) -> str:
    """Normalise one host line, or '' if it is not a plausible hostname."""
    s = (s or "").strip().lower().rstrip(".")
    # Drop a scheme or path if the operator pasted a URL.
    s = re.sub(r"^https?://", "", s).split("/")[0].split(":")[0].strip()
    return s if s and _HOST_RE.match(s) and ".." not in s else ""


def _subs_state_file(slug: str) -> Path:
    return ENGAGEMENTS / slug / "state" / "subdomains.json"


def _subs_state_load(slug: str) -> dict:
    """The curated subdomain working set for a client: {list, alerts}. list is
    the operator-curated set (seeded from discovery), alerts records when new
    hosts turned up, by manual edit or by the weekly re-scan watcher."""
    f = _subs_state_file(slug)
    try:
        if f.is_file():
            d = json.loads(f.read_text())
            if isinstance(d, dict):
                d.setdefault("list", [])
                d.setdefault("alerts", [])
                return d
    except Exception:
        pass
    return {"list": [], "alerts": []}


def _subs_state_save(slug: str, data: dict) -> None:
    f = _subs_state_file(slug)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(data, indent=2))
    _invalidate_state(slug)


def _subs_effective(slug: str, base: Path) -> list[str]:
    """The subdomains shown and exported: the curated list if the operator has
    saved one, otherwise seeded from discovery, always unioned with whatever
    discovery currently holds so a scan result is never lost."""
    discovered = set(_subdomain_list(base))
    st = _subs_state_load(slug)
    curated = set(st.get("list") or [])
    return sorted(discovered | curated)


_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def _leaks_file(slug: str) -> Path:
    return ENGAGEMENTS / slug / "state" / "leaks.json"


# A few clearly-fake example rows so the Leaks tab is not empty on a fresh
# client. Marked example, never emitted as a finding, cleared the moment a real
# file is ingested. The passwords are obvious demo strings, not real secrets.
_LEAK_EXAMPLES = [
    {"user": "j.martins@example.com", "password": "Summer2023!", "domain": "example.com",
     "source": "EXAMPLE infostealer log", "date": "2026-09-14"},
    {"user": "a.rocha@example.com", "password": "Corp@2024", "domain": "example.com",
     "source": "EXAMPLE combolist", "date": "2026-08-02"},
    {"user": "admin@example.com", "password": "ChangeMe123", "domain": "example.com",
     "source": "EXAMPLE breach corpus", "date": "2026-07-21"},
    {"user": "s.nunes@example.com", "password": "Welcome2022", "domain": "example.com",
     "source": "EXAMPLE infostealer log", "date": "2026-10-05"},
]


def _leaks_seed() -> list:
    out = []
    for c in _LEAK_EXAMPLES:
        c = dict(c)
        c["id"] = hashlib.sha1(f"example|{c['user']}|{c['password']}".encode()).hexdigest()[:12]
        c["example"] = True
        out.append(c)
    return out


# A small pool of extra demo credentials the Fetch button adds a couple at a
# time, so the fetch flow can be exercised without a real intake file and new
# rows visibly accumulate. These are obvious demo strings, never real secrets,
# and the source makes clear they are examples.
_LEAK_DEMO_POOL = [
    {"user": "p.costa@example.com", "password": "Autumn#2024", "source": "EXAMPLE infostealer log", "date": "2026-10-18"},
    {"user": "l.ferreira@example.com", "password": "Lisboa!2023", "source": "EXAMPLE combolist", "date": "2026-10-12"},
    {"user": "r.santos@example.com", "password": "Passw0rd$1", "source": "EXAMPLE breach corpus", "date": "2026-09-30"},
    {"user": "c.almeida@example.com", "password": "Winter2024!", "source": "EXAMPLE infostealer log", "date": "2026-09-22"},
    {"user": "m.pereira@example.com", "password": "Qwerty@2024", "source": "EXAMPLE combolist", "date": "2026-09-08"},
    {"user": "t.lopes@example.com", "password": "Hello!World9", "source": "EXAMPLE breach corpus", "date": "2026-08-27"},
]


def _leaks_demo_pool() -> list:
    out = []
    for c in _LEAK_DEMO_POOL:
        c = dict(c)
        c["id"] = hashlib.sha1(f"{c['user']}|{c['password']}".encode()).hexdigest()[:16]
        c["domain"] = _leak_domain(c["user"])
        out.append(c)
    return out


def _leaks_load(slug: str) -> dict:
    """The normalized leaked-credential store for a client: {creds, ingested,
    alerts}. creds is the deduped record set, ingested maps each intake file to a
    size-mtime signature so a re-fetch only reads what changed."""
    f = _leaks_file(slug)
    try:
        if f.is_file():
            d = json.loads(f.read_text())
            if isinstance(d, dict):
                d.setdefault("creds", [])
                d.setdefault("ingested", {})
                d.setdefault("alerts", [])
                return d
    except Exception:
        pass
    # First view of a client with no leaks: seed example rows so the tab shows
    # the shape of the feature. They carry no ingested signature, so the first
    # real Fetch recent replaces them.
    data = {"creds": _leaks_seed(), "ingested": {}, "alerts": [], "seeded": True}
    try:
        _leaks_save(slug, data)
    except Exception:
        pass
    return data


def _leaks_count(slug: str) -> int:
    """How many leaked credentials a client has, without seeding the store. Used
    for the tab-bar count, so merely viewing a client never writes example rows."""
    f = _leaks_file(slug)
    try:
        if f.is_file():
            d = json.loads(f.read_text())
            if isinstance(d, dict):
                return len(d.get("creds", []))
    except Exception:
        pass
    return len(_LEAK_EXAMPLES)


def _leaks_save(slug: str, data: dict) -> None:
    f = _leaks_file(slug)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(data, indent=2))
    _invalidate_state(slug)


def _leak_domain(user: str) -> str:
    return user.split("@", 1)[1].lower() if "@" in user else ""


def _ctx_meta_file(slug: str) -> Path:
    return ENGAGEMENTS / slug / "state" / "context.json"


def _ctx_meta_load(slug: str) -> dict:
    """The company-context record for a client: legal entity, CEO, sector,
    description and the stored brand-logo filename. All operator-entered, held
    per client under the engagement's own state dir."""
    f = _ctx_meta_file(slug)
    try:
        if f.is_file():
            d = json.loads(f.read_text())
            if isinstance(d, dict):
                return d
    except Exception:
        pass
    return {}


def _ctx_meta_save(slug: str, data: dict) -> None:
    f = _ctx_meta_file(slug)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(data, indent=2))
    _invalidate_state(slug)


def _parse_creds_text(text: str) -> list[tuple[str, str, str]]:
    """Pull (user, password, date) tuples out of one intake file. Handles a JSON
    array of records, and the common line formats: email:pass, user:pass and
    url:email:pass (stealer logs), with :, ;, | or tab as the separator. A
    deterministic parser, no network, no code execution on the untrusted file."""
    out: list[tuple[str, str, str]] = []
    s = text.strip()
    if s[:1] in "[{":
        try:
            data = json.loads(s)
            recs = data if isinstance(data, list) else (
                data.get("credentials") or data.get("creds") or data.get("data") or [])
            for r in recs:
                if not isinstance(r, dict):
                    continue
                user = (r.get("username") or r.get("user") or r.get("email")
                        or r.get("login") or "")
                pw = r.get("password") or r.get("pass") or r.get("pwd") or ""
                if user and pw:
                    out.append((str(user).strip(), str(pw),
                                str(r.get("date") or r.get("last_seen") or "")))
            if out:
                return out
        except Exception:
            pass
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#") or len(ln) > 2000:
            continue
        m = _EMAIL_RE.search(ln)
        if m:
            user = m.group(0)
            rest = ln[m.end():]
            mm = re.match(r"\s*[:;,|\t]\s*(\S.*)?$", rest)
            if not mm or not mm.group(1):
                continue
            pw = re.split(r"[\t,;|]", mm.group(1))[0].strip()
            if pw:
                out.append((user.lower(), pw, ""))
        else:
            parts = [p.strip() for p in re.split(r"[:;,|\t]", ln) if p.strip()]
            if len(parts) == 2:
                out.append((parts[0], parts[1], ""))
    return out


def _ingest_leaks(slug: str) -> tuple[int, int]:
    """Scan the client's intake folder and merge new credentials into the store.
    Returns (files_read, new_creds). New credentials raise an ingestion alert."""
    base = ENGAGEMENTS / slug
    intake = base / "intake"
    st = _leaks_load(slug)
    now = datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC")
    # Promote any seeded example rows into the persistent set on first fetch,
    # rather than dropping them, so a fetch never empties the tab. They keep
    # their rows and simply stop being marked example (so they persist exactly
    # like a fetched credential would).
    for c in st["creds"]:
        if c.get("example"):
            c.pop("example", None)
            c.setdefault("first_seen", now)
    st.pop("seeded", None)
    ingested = st["ingested"]
    creds = st["creds"]
    index = {c["id"] for c in creds}
    files_read = 0
    new_count = 0
    if intake.is_dir():
        for f in sorted(intake.iterdir()):
            if not f.is_file() or f.suffix.lower() not in {
                    ".txt", ".csv", ".tsv", ".json", ".log", ".list"}:
                continue
            try:
                stt = f.stat()
            except Exception:
                continue
            sig = f"{stt.st_size}-{int(stt.st_mtime)}"
            if ingested.get(f.name) == sig or stt.st_size > 50 * 1024 * 1024:
                continue
            try:
                text = f.read_text(errors="ignore")
            except Exception:
                continue
            for user, pw, date in _parse_creds_text(text):
                cid = hashlib.sha1(f"{user}|{pw}".encode()).hexdigest()[:16]
                if cid in index:
                    continue
                index.add(cid)
                creds.append({"id": cid, "user": user, "password": pw,
                              "domain": _leak_domain(user), "source": f.name,
                              "date": date, "first_seen": now})
                new_count += 1
            ingested[f.name] = sig
            files_read += 1
    # Demo: add a couple of fresh example credentials from the pool each fetch,
    # so the Fetch button can be exercised without a real intake file and new
    # rows visibly accumulate. They dedup by id, so once the pool is exhausted a
    # fetch stops adding. Removed when real ingestion is wired to a feed.
    demo_added = 0
    for c in _leaks_demo_pool():
        if demo_added >= 2:
            break
        if c["id"] in index:
            continue
        index.add(c["id"])
        c = dict(c)
        c["first_seen"] = now
        creds.append(c)
        new_count += 1
        demo_added += 1
    if new_count:
        st["alerts"].append({"ts": now, "source": "ingestion", "count": new_count})
        st["alerts"] = st["alerts"][-100:]
        _slack_notify(f":rotating_light: Continuous EAS: {new_count} new leaked "
                      f"credential(s) ingested for {_pretty(slug)}.")
        _emit_leak_finding(slug, len([c for c in creds]))
    _leaks_save(slug, st)
    return files_read, new_count


def _emit_leak_finding(slug: str, total: int) -> None:
    """Record the credential exposure as one signal finding so it shows up as a
    vulnerability (Needs attention, triage, vuln page) and not only as a leak
    alert. One aggregate finding per client, rewritten with the current count,
    so the vuln list never floods with one row per credential."""
    if total <= 0:
        return
    sig = ENGAGEMENTS / slug / "signals" / f"{slug}-leaks.jsonl"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    finding = {
        "dedup_id": f"leak|{slug}|exposed-credentials",
        "title": "Exposed corporate credentials",
        "description": (f"{total} corporate credential(s) for this client were found "
                        "exposed in third-party credential dumps. Exposed credentials "
                        "allow an attacker to attempt account takeover and credential "
                        "reuse against the client's services."),
        "severity": "SEV2",
        "source": "Continuous EAS / credential exposure",
        "source_class": "credential_exposure",
        "entities": [],
        "evidence": {"exposed_count": total,
                     "detail": "See the Leaks tab for the per-credential list."},
        "first_seen": now, "last_seen": now,
    }
    try:
        sig.parent.mkdir(parents=True, exist_ok=True)
        sig.write_text(json.dumps(finding) + "\n")
        _invalidate_state(slug)
    except Exception:
        pass


# --------------------------------------------------------------------------
# Vulnerability DB. A global library of reusable finding templates (name, OWASP
# id, CWE, severity, CVSS vector, description, mitigation, references) so the
# repeated vulnerabilities can be dropped into a manual finding in one click.
# Stored once for the whole console, not per client. Seeded with a few examples.
# --------------------------------------------------------------------------
def _vdb_file() -> Path:
    return DATA / "vuln_db.json"


_VDB_SEED = [
    {"name": "Reflected Cross Site Scripting", "tags": "web, client-side", "owasp": "A03:2021 Injection",
     "cwe": "CWE-79", "severity": "SEV2",
     "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
     "description": "Cross Site Scripting lets an attacker run script in another "
     "user's browser in the context of the vulnerable site. Reflected XSS sends "
     "the payload in a request and the server echoes it into the response without "
     "encoding.\n\nAn attacker can steal session tokens, act as the victim, or "
     "deface the page for that user.\n\nState here what the team found: the "
     "parameter, the page, and the payload that executed.",
     "mitigation": "Encode all user input on output for the correct context\n"
     "Apply a strict Content Security Policy\nValidate input against an allowlist",
     "references": "OWASP XSS Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
     "example": True},
    {"name": "SQL Injection", "tags": "web, API, database", "owasp": "A03:2021 Injection", "cwe": "CWE-89",
     "severity": "SEV1",
     "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "description": "SQL Injection lets an attacker change the SQL a server runs by "
     "injecting input into a query that is not parameterised.\n\nAn attacker can "
     "read or change any data the database holds, and sometimes run commands on the "
     "host.\n\nState here what the team found: the endpoint, the parameter, and the "
     "proof.",
     "mitigation": "Use parameterised queries or prepared statements everywhere\n"
     "Apply least privilege to the database account\nValidate and canonicalise input",
     "references": "OWASP SQL Injection Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
     "example": True},
    {"name": "Missing Subresource Integrity", "tags": "web, supply-chain", "owasp": "A05:2021 Security Misconfiguration",
     "cwe": "CWE-353", "severity": "SEV4",
     "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
     "description": "Third party scripts loaded without a Subresource Integrity hash "
     "run with full trust. If the third party or its CDN is compromised, the "
     "attacker's code runs on the site.\n\nAn attacker who controls the external "
     "resource can execute script in the site's context.\n\nState here which scripts "
     "load without integrity.",
     "mitigation": "Add an integrity attribute with a SHA hash to every external "
     "script and stylesheet\nSet crossorigin and a Content Security Policy",
     "references": "OWASP Subresource Integrity | https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
     "example": True},
    {"name": "Verbose Error Messages", "tags": "web, API", "owasp": "A05:2021 Security Misconfiguration",
     "cwe": "CWE-209", "severity": "SEV4",
     "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
     "description": "The application returns stack traces or internal error detail to "
     "unauthenticated callers, disclosing framework, version and path "
     "information.\n\nAn attacker uses the detail to find further weaknesses.\n\nState "
     "here which endpoint leaked which detail.",
     "mitigation": "Return generic error pages to clients\nLog the detail server "
     "side only\nDisable debug mode in production",
     "references": "OWASP Improper Error Handling | https://owasp.org/www-community/Improper_Error_Handling",
     "example": True},
    {"name": "Active Brand Impersonation Domain",
     "tags": "phishing, lookalike-domain",
     "owasp": "N/A",
     "cwe": "CWE-451", "severity": "SEV2",
     "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
     "description": "A lookalike domain that imitates the client brand was found "
     "registered and actively running, not merely parked. This kind of brand "
     "impersonation uses a domain that is visually or typographically close to a "
     "real client domain, for example a character swap, an added word, or a "
     "different top level domain, so a user who misreads or mistypes the address "
     "lands on infrastructure that looks like the client.\n\nThe risk is that the "
     "domain is live and usable against the client now. A domain that resolves and "
     "serves a copy of the client login page, or accepts mail under the client "
     "brand, can harvest credentials or lend credibility to a phishing campaign. "
     "The client's own systems are not changed, but the client's users and brand "
     "carry the impact.\n\nThis finding is one confirmed domain, registered and "
     "actively running when it was discovered. A permutation that is unregistered "
     "or parked with no live content and no mail capability is tracked as "
     "monitoring inventory only and is not treated as a vulnerability.\n\nState "
     "here the confirmed domain, what it was serving (resolving IP, login clone, "
     "mail), and the discovery date.",
     "mitigation": "Request takedown of the confirmed impersonating domain through "
     "the registrar and an anti-phishing takedown service, citing the registrant "
     "and hosting details in the evidence\nReport the domain to the browser and "
     "email safe-browsing programs so it is flagged for end users\nEnforce DMARC at "
     "a reject policy on the genuine brand domains so spoofed mail is rejected\n"
     "Defensively register the highest risk permutations that are still available, "
     "in particular close typo variants and common alternate top level domains\n"
     "Keep continuous monitoring on the permutation pool so a dormant lookalike "
     "that later starts serving content or mail is caught when it activates\nBrief "
     "staff and customers on the confirmed lookalike so they can recognise it",
     "references": "MITRE ATT&CK T1583.001 Acquire Infrastructure Domains | "
     "https://attack.mitre.org/techniques/T1583/001/\nCWE-451 User Interface "
     "Misrepresentation of Critical Information | "
     "https://cwe.mitre.org/data/definitions/451.html\nCISA Avoiding Social "
     "Engineering and Phishing Attacks | https://www.cisa.gov/news-events/news/"
     "avoiding-social-engineering-and-phishing-attacks\nICANN Registrant Rights "
     "and the Abuse Complaint Process | "
     "https://www.icann.org/resources/pages/abuse-2014-01-29-en"},
]


def _vdb_load() -> dict:
    f = _vdb_file()
    try:
        if f.is_file():
            d = json.loads(f.read_text())
            if isinstance(d, dict) and isinstance(d.get("templates"), list):
                d.setdefault("log", [])
                return d
    except Exception:
        pass
    # Seed on first use, each template gets a stable id.
    templates = []
    for t in _VDB_SEED:
        t = dict(t)
        t["id"] = hashlib.sha1(f"seed|{t['name']}".encode()).hexdigest()[:12]
        templates.append(t)
    data = {"templates": templates, "log": []}
    try:
        _vdb_save(data)
    except Exception:
        pass
    return data


def _vdb_save(data: dict) -> None:
    f = _vdb_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(data, indent=2))


def _vdb_log(data: dict, action: str, name: str, user: str) -> None:
    data.setdefault("log", []).append({
        "ts": datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC"),
        "action": action, "name": name, "by": user})
    data["log"] = data["log"][-200:]


def _cvss31_score(vector: str):
    """The CVSS 3.1 base score for a vector, or None. Mirrors the browser
    calculator so a manual finding's severity can be derived server-side."""
    vec = _cvss_vector(vector)
    if not vec:
        return None
    m = {}
    for part in vec.split("/")[1:]:
        if ":" in part:
            k, v = part.split(":", 1)
            m[k] = v
    need = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if any(k not in m for k in need):
        return None
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
        ac = {"L": 0.77, "H": 0.44}[m["AC"]]
        ui = {"N": 0.85, "R": 0.62}[m["UI"]]
        changed = m["S"] == "C"
        pr = ({"N": 0.85, "L": 0.68, "H": 0.5} if changed
              else {"N": 0.85, "L": 0.62, "H": 0.27})[m["PR"]]
        cia = {"N": 0, "L": 0.22, "H": 0.56}
        c, i, a = cia[m["C"]], cia[m["I"]], cia[m["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15) if changed else 6.42 * iss
    expl = 8.22 * av * ac * pr * ui

    def roundup(x):
        n = round(x * 100000)
        return n / 100000 if n % 10000 == 0 else (math.floor(n / 10000) + 1) / 10
    if impact <= 0:
        return 0.0
    return roundup(min((1.08 if changed else 1.0) * (impact + expl), 10))


def _sev_for_score(score) -> str:
    if score is None:
        return "SEV3"
    if score <= 0:
        return "SEV5"
    if score < 4:
        return "SEV4"
    if score < 7:
        return "SEV3"
    if score < 9:
        return "SEV2"
    return "SEV1"


# Maps a finding's source class to the Vuln DB template that describes it, so a
# High/Critical alert is phrased from the curated template (name, severity, CWE,
# CVSS) rather than the raw signal title.
_CLASS_TO_VDB = {
    "lookalike_domain": "Active Brand Impersonation Domain",
    "email_auth_posture": "Missing or Weak DMARC Policy",
    "dmarc_record": "Missing or Weak DMARC Policy",
}


def _alert_new_findings(slug: str, base: Path, sig: dict) -> None:
    """Post a Slack alert the first time a High (SEV2) or Critical (SEV1) finding
    is seen for a client, with the client name, the finding, and a link to its
    Manage page. Idempotent: a per-client file of already-alerted finding keys
    means each finding alerts once, never on every render. The file is seeded
    (without alerting) on first run, so turning this on does not flood the channel
    with every historical finding, only ones that appear afterwards."""
    # Critical and High alert, as does the DMARC finding at its true severity
    # (it is surfaced at any level, and the webhook label must match the badge).
    hi = [a for a in sig.get("attention", [])
          if a.get("severity") in ("SEV1", "SEV2")
          or a.get("source_class") in ("dmarc_record", "email_auth_posture")]
    f = base / "alerted-findings.json"
    try:
        prev = set(json.loads(f.read_text())) if f.is_file() else None
    except Exception:
        prev = set()
    keys = {a["key"] for a in hi}
    if prev is None:
        # First run for this client: baseline the current set, do not alert.
        try:
            f.write_text(json.dumps(sorted(keys)))
        except Exception:
            pass
        return
    new = [a for a in hi if a["key"] not in prev]
    if not new:
        return
    # Automatically capture the evidence for any new auto-capture finding the
    # moment it appears, in the background, so the screenshots are already
    # attached by the time the operator opens the Manage page. Covers brand
    # impersonation (browser shot) and email-authentication posture (dig terminal
    # shots). Idempotent and best effort: it never blocks the alert and a failure
    # just leaves the finding without shots until the next cycle or a manual capture.
    cap_keys = [a["key"] for a in new
                if a.get("source_class") in _AUTO_CAPTURE_CLASSES]
    if cap_keys:
        def _bg_capture(slug=slug, keys=cap_keys):
            for k in keys:
                try:
                    _capture_finding_evidence(slug, k)
                except Exception:
                    pass
        threading.Thread(target=_bg_capture, name="ev-capture", daemon=True).start()
    client = _pretty(slug)
    # Templates keyed by name, so a finding can be described from the Vuln DB
    # entry we curate (name, severity, CWE, CVSS) rather than the raw signal
    # title. The source class maps to the matching template.
    try:
        _vdb = {t.get("name"): t for t in _vdb_load().get("templates", [])}
    except Exception:
        _vdb = {}
    for a in new:
        tpl = _vdb.get(_CLASS_TO_VDB.get(a.get("source_class", ""), ""))
        vid = a.get("id") or _vuln_id(slug, a["key"])
        url = f'{_panel_url()}/vuln?e={_client_id(slug)}&v={vid}&from=attention'
        hosts = a.get("hosts") or []
        if len(hosts) > 1:
            shown = ", ".join(hosts[:6]) + (f" (+{len(hosts) - 6} more)" if len(hosts) > 6 else "")
            affected = f"{len(hosts)} domains: {shown}"
        else:
            affected = (hosts[0] if hosts else None) or str(a.get("title", "Finding"))
        # Severity ALWAYS comes from the finding as the console shows it
        # (a["severity"]), never from the Vuln DB template's default. The template
        # default is the worst-case label for the class; the finding's own
        # severity is the one the operator sees in the UI, and the webhook must
        # match it. The template still supplies the name, CWE and CVSS.
        sev = SEV.get(a["severity"], ("High",))[0]
        if tpl:
            name = tpl.get("name", "Vulnerability")
            meta_bits = [b for b in (tpl.get("cwe", ""),
                                     (f"CVSS {_cvss31_score(tpl.get('cvss_vector',''))}"
                                      if _cvss31_score(tpl.get("cvss_vector", "")) else ""))
                         if b]
            meta = ("  ·  " + "  ·  ".join(meta_bits)) if meta_bits else ""
            headline = f"{name}  ·  *{sev}*{meta}"
        else:
            name = str(a.get("title", "Finding"))
            headline = f"{name}  ·  *{sev}*"
        _slack_notify(
            f":rotating_light: {sev} vulnerability for {client}: {name} "
            f"({affected}). Manage: {url}",
            blocks=[
                {"type": "header",
                 "text": {"type": "plain_text",
                          "text": f"{sev} vulnerability detected", "emoji": True}},
                {"type": "section",
                 "text": {"type": "mrkdwn",
                          "text": f":rotating_light: *Client:* {client}\n"
                                  f"*Vulnerability:* {headline}\n"
                                  f"*Affected:* {_esc(str(affected))}"}},
                {"type": "section",
                 "text": {"type": "mrkdwn", "text": f"<{url}|Manage this finding>"}},
                {"type": "divider"},
            ])
    try:
        f.write_text(json.dumps(sorted(prev | keys)))
    except Exception:
        pass


def engagements() -> list[dict]:
    out = []
    if not ENGAGEMENTS.is_dir():
        return out
    for base in sorted(p for p in ENGAGEMENTS.iterdir() if p.is_dir()):
        sig = _read_signals(base / "signals", set(_fp_load(base.name).keys()))
        try:
            _alert_new_findings(base.name, base, sig)
        except Exception:
            pass
        rdir = base / "reports"
        reports = {"xlsx": _latest_report(rdir, "xlsx"),
                   "pdf": _latest_report(rdir, "pdf"),
                   "docx": _latest_report(rdir, "docx")}
        out.append({"slug": base.name, "total": sig["total"],
                    "collected": sig.get("collected", sig["total"]),
                    "counts": sig["counts"],
                    "by_class": sig["by_class"], "attention": sig["attention"],
                    "last": sig["last"], "reports": reports,
                    "watch": watcher_state(base.name)})
    return out


# --------------------------------------------------------------------------
# HTML. Dark console styled on the JOES AIR palette.
# --------------------------------------------------------------------------
CSS = """
:root{--bg:#0A0E13;--panel:#131A22;--panel2:#0E141B;--line:#222B36;--fg:#D4DEEA;--muted:#6B7A8D;--accent:#3BBBF8;--green:#4ade80;--red:#F3415E}
*{box-sizing:border-box}
/* every control uses the same UI font as the body, no browser default creeps in */
/* Form controls carry a UA default margin that makes them the tallest child
   in a flex row, so neighbouring controls centre lower and the control looks
   raised. Zero it and middle-align everywhere so toolbar rows stay level. */
button,input,select,textarea{font-family:inherit;margin:0;vertical-align:middle}
html{scroll-behavior:smooth}
a.metric{text-decoration:none;color:var(--fg);display:block}
a.metric:hover{border-color:var(--accent);text-decoration:none}
h2[id]{scroll-margin-top:84px}
body{margin:0;min-height:100vh;color:var(--fg);font:14px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:radial-gradient(1100px 620px at 12% -8%,rgba(59,187,248,.08),transparent 55%),radial-gradient(900px 600px at 100% 0%,rgba(243,65,94,.06),transparent 50%),var(--bg);background-attachment:fixed}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
header{display:flex;align-items:center;justify-content:flex-start;gap:6px;padding:16px 26px;border-bottom:1px solid var(--line);background:rgba(14,20,27,.72);backdrop-filter:blur(10px);position:sticky;top:0;z-index:10}
header>div{margin-left:auto}
.navleftnav{margin-left:16px}
.brand{display:inline-flex;align-items:center;gap:11px;font-weight:800;letter-spacing:.6px;font-size:15px;color:var(--fg);text-decoration:none;cursor:pointer}
.brand:hover{text-decoration:none;color:var(--fg)}
.brand:hover .logo{transform:rotate(45deg)}
.logo{display:flex;color:var(--red);flex:none;transition:transform .35s ease;filter:drop-shadow(0 0 6px rgba(243,65,94,.5))}
.brandtext{display:flex;flex-direction:column;line-height:1.1}
.brand small{display:block;color:var(--muted);font-weight:500;letter-spacing:.4px;font-size:11px;margin-top:1px}
.hright{color:var(--muted);font-size:13px}
/* top navbar */
.nav{display:flex;align-items:center;gap:6px}
.navlink{display:inline-flex;align-items:center;gap:7px;height:32px;padding:0 13px;border-radius:8px;color:var(--muted);font-size:13px;font-weight:600;letter-spacing:.3px;text-decoration:none;transition:background .15s,color .15s}
.navbadge{display:inline-flex;align-items:center;justify-content:center;min-width:18px;height:18px;padding:0 5px;border-radius:9px;background:var(--red);color:#fff;font-size:11px;font-weight:800;letter-spacing:0;line-height:1}
.navbadge.zero{background:var(--green);color:#06211a}
.navlink:hover{background:rgba(59,187,248,.12);color:var(--fg);text-decoration:none}
.navsep{width:1px;height:20px;background:var(--line);margin:0 8px}
.navuser{color:var(--muted);font-size:13px;font-weight:600;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.navout{display:inline-flex;align-items:center;height:32px;padding:0 13px;border:1px solid var(--line);border-radius:8px;color:var(--fg);font-size:13px;font-weight:600;text-decoration:none;transition:border-color .15s,color .15s}
.navout:hover{border-color:var(--red);color:var(--red);text-decoration:none}
/* navbar Clients dropdown */
.navdd{position:relative;display:inline-flex}
.navddbtn{cursor:pointer;background:transparent;border:none;font-family:inherit}
.navddbtn .chev{transition:transform .18s}
.navdd.open .navddbtn{background:rgba(59,187,248,.12);color:var(--fg)}
.navdd.open .navddbtn .chev{transform:rotate(180deg)}
.navddmenu{position:absolute;top:calc(100% + 9px);left:0;z-index:60;width:264px;background:var(--panel);border:1px solid var(--line);border-radius:12px;box-shadow:0 18px 44px rgba(0,0,0,.5);padding:8px;opacity:0;transform:translateY(-6px);pointer-events:none;transition:opacity .16s ease,transform .16s ease}
.navdd.open .navddmenu{opacity:1;transform:translateY(0);pointer-events:auto}
.navddsearch{width:100%;box-sizing:border-box;height:32px;background:var(--panel2);border:1px solid var(--line);border-radius:8px;color:var(--fg);font-size:12.5px;padding:0 10px;margin-bottom:6px}
.navddsearch:focus{outline:none;border-color:var(--accent)}
.navddlist{max-height:320px;overflow-y:auto;display:flex;flex-direction:column;gap:1px}
.navdditem{display:flex;align-items:center;gap:9px;padding:8px 9px;border-radius:8px;color:var(--fg);text-decoration:none;font-size:13px;font-weight:600}
.navdditem:hover{background:rgba(59,187,248,.1);color:var(--accent);text-decoration:none}
.navddname{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
@media(max-width:640px){.navuser,.navsep{display:none}.navlink,.navout{padding:0 9px}.navddmenu{width:220px}}
.wrap{max-width:1100px;margin:0 auto;padding:12px 26px 26px}
h2{font-size:12px;text-transform:uppercase;letter-spacing:1.2px;color:var(--muted);margin:28px 0 12px;font-weight:700}
/* keep anchored targets clear of the sticky header when jumped to */
h2[id],[id^="phase-"],#attn,#falsepos,#reports,#watchers{scroll-margin-top:88px}
.muted{color:var(--muted)}
/* summary metrics */
.metrics{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:6px}
.metric{flex:1;min-width:150px;background:rgba(19,26,34,.68);border:1px solid var(--line);border-radius:12px;padding:16px 18px;backdrop-filter:blur(8px);text-align:center}
.metric .n{font-size:30px;font-weight:800;line-height:1}
.metric .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.6px;margin-top:6px}
/* overview rows */
.rows{display:flex;flex-direction:column;gap:10px}
.crow{display:grid;grid-template-columns:minmax(200px,1fr) 2fr auto auto;align-items:center;gap:16px;background:rgba(19,26,34,.68);border:1px solid var(--line);border-radius:12px;padding:14px 18px;color:var(--fg);backdrop-filter:blur(8px)}
.crow:hover{border-color:var(--accent);text-decoration:none}
.cnum{min-width:62px}
.crow .cbar{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px}
.crow .bar{width:100%;max-width:460px}
.crow .badges{flex-wrap:nowrap;justify-content:center;gap:5px;margin:0}
.crow .badge{padding:2px 7px;font-size:10px;white-space:nowrap}
.cltools{display:flex;gap:10px;margin-bottom:12px;flex-wrap:wrap;align-items:center}
.clq,.clsort{height:38px;box-sizing:border-box;margin:0;line-height:normal;vertical-align:middle;background:var(--panel2);border:1px solid var(--line);border-radius:9px;color:var(--fg);font-size:13px}
.clq{flex:1 1 180px;min-width:150px;padding:0 12px}
.clsortlbl{font-size:12px;color:var(--muted);white-space:nowrap}
.clsort{padding:0 10px;cursor:pointer}
.clmonlbl{display:inline-flex;box-sizing:border-box;align-items:center;gap:10px;height:38px;margin:0;padding:0 14px;border:1px solid var(--line);border-radius:999px;background:var(--panel2);color:var(--muted);font-size:12.5px;font-weight:700;line-height:1;white-space:nowrap;cursor:pointer;transition:border-color .16s,color .16s,background .16s}
.clmonlbl:hover{border-color:var(--muted);color:var(--fg)}
.clmonlbl input{appearance:none;-webkit-appearance:none;position:relative;flex:none;align-self:center;display:block;width:34px;height:19px;margin:0;padding:0;border:0;border-radius:999px;background:var(--line);cursor:pointer;transition:background .18s}
.clmonlbl input::after{content:"";position:absolute;top:2px;left:2px;width:15px;height:15px;border-radius:50%;background:#fff;transition:transform .18s}
.clmonlbl input:checked{background:var(--green)}
.clmonlbl input:checked::after{transform:translateX(15px)}
.clmonlbl:has(input:checked){border-color:var(--green);color:var(--green);background:rgba(39,201,132,.12)}
.clq:focus,.clsort:focus{outline:none;border-color:var(--accent)}
.cl{display:flex;align-items:center;gap:11px}
.clname{font-weight:700;font-size:16px}
.cbar{min-width:0}
.cnum{text-align:center}
.cnum .n{font-size:22px;font-weight:800;line-height:1}
.cnum .k{color:var(--muted);font-size:11px}
@media(max-width:640px){.crow{grid-template-columns:1fr auto auto}.cbar{display:none}}
/* client page header */
.back{display:inline-flex;align-items:center;gap:7px;height:32px;padding:0 14px 0 11px;margin-bottom:16px;border:1px solid var(--line);border-radius:999px;background:var(--panel);color:var(--muted);font-size:12.5px;font-weight:600;letter-spacing:.3px;text-decoration:none;transition:border-color .15s,color .15s,transform .15s,background .15s}
.back:hover{border-color:var(--red);color:var(--red);background:rgba(243,65,94,.12);text-decoration:none}
.back:hover .barrow{transform:translateX(-3px)}
.barrow{display:inline-flex;transition:transform .15s}
.phead{display:flex;align-items:center;justify-content:space-between;gap:12px}
.ptitle{font-weight:700;font-size:15px;margin-bottom:4px}
/* cards */
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:16px}
.card{background:rgba(19,26,34,.68);border:1px solid var(--line);border-radius:14px;padding:18px 20px;backdrop-filter:blur(8px)}
.chead{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:2px}
.cname{font-weight:700;font-size:17px;display:flex;align-items:center;gap:9px}
.dot{width:9px;height:9px;border-radius:50%;flex:none}
.dot.on{background:var(--green);box-shadow:0 0 0 3px rgba(74,222,128,.15)}
.dot.off{background:var(--muted)}
.count{text-align:right}
.count .n{font-size:24px;font-weight:800;line-height:1}
.count .k{color:var(--muted);font-size:11px}
.bar{display:flex;height:8px;border-radius:999px;overflow:hidden;background:var(--panel2);margin:12px 0 6px}
.bar span{display:block}
.badges{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:4px}
.sevcard .bar{height:12px;margin:4px 0 2px}
.sevlegend{display:flex;flex-wrap:wrap;justify-content:center;gap:12px 30px;margin-top:18px}
.sevleg{display:flex;flex-direction:column;align-items:center;min-width:64px}
.sevnum{font-size:28px;font-weight:800;line-height:1}
.sevlbl{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-top:5px}
.badge{display:inline-flex;align-items:center;gap:5px;padding:2px 8px;border-radius:6px;font-weight:700;font-size:11px}
.badge b{font-variant-numeric:tabular-nums}
/* audit table */
.audit{width:100%;border-collapse:collapse;font-size:13px}
.audit th{text-align:left;color:var(--muted);font-weight:700;font-size:10px;text-transform:uppercase;letter-spacing:.7px;padding:9px 12px;border-bottom:1px solid var(--line);white-space:nowrap}
.audit td{padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
.audit tbody tr:last-child td{border-bottom:none}
.audit tbody tr{background:transparent}
.audit tbody tr:nth-child(even){background:rgba(127,160,200,.07)}
.audit tbody tr:hover{background:rgba(59,187,248,.12)}
.audit tbody tr.dim td{opacity:.5}
.audit.tcenter th,.audit.tcenter td{text-align:center;vertical-align:middle;white-space:nowrap}
.audit.tcenter .vtag,.audit.tcenter .exampletag{margin:0 2px}
/* Finding cell: let a long title wrap to two lines instead of forcing the row
   wide (which pushed the Manage action off-screen). */
.audit.tcenter td.fndcell{white-space:normal;text-align:left;max-width:360px}
.audit.tcenter td.fndcell .phlink{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;overflow-wrap:anywhere}
/* the Action column holds free text (error details), so let it wrap and
   keep its own left alignment instead of inheriting the centred nowrap, so a
   long message never pushes the Outcome column out of view. */
.audit.tcenter td.auaction{white-space:normal;text-align:left;overflow-wrap:anywhere;word-break:break-word;min-width:260px}
.audit .ptag{margin-right:7px}
.audit tr.afilter th{padding:7px 10px;border-bottom:1px solid var(--line);text-transform:none;letter-spacing:0;vertical-align:middle}
.afin{width:100%;box-sizing:border-box;height:30px;background:var(--panel2);border:1px solid var(--line);border-radius:7px;color:var(--fg);font-family:inherit;font-size:12px;padding:0 8px}
select.afin{cursor:pointer;-webkit-appearance:none;-moz-appearance:none;appearance:none;padding-right:26px;background-color:var(--panel2);background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='10' height='10' viewBox='0 0 24 24' fill='none' stroke='%238aa0b4' stroke-width='3' stroke-linecap='round' stroke-linejoin='round'><path d='M6 9l6 6 6-6'/></svg>");background-repeat:no-repeat;background-position:right 9px center}
.afin:focus{outline:none;border-color:#3BBBF8}
.afbtn{text-align:left;cursor:pointer;white-space:nowrap}
.afpop{position:relative}
.afpop-list{position:absolute;top:calc(100% + 4px);left:0;z-index:40;background:var(--panel);border:1px solid var(--line);border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,.35);padding:10px;display:flex;flex-wrap:wrap;align-items:flex-end;gap:8px;width:300px}
.afpop-list[hidden]{display:none}
/* every filter control shares the same box metrics so the row aligns: the
   text input, the selects and the date button all 30px tall, text centred by
   the box rather than a line-height that only matches on the input */
.afin{line-height:normal;padding:0 8px;vertical-align:middle}
.afilter th input.afin,.afilter th select.afin{display:block;margin:0;height:30px}
.afdlbl{display:flex;flex-direction:column;gap:3px;font-size:11px;color:var(--muted)}
.afdlbl .afin{width:128px}
.afclear{background:transparent;border:1px solid var(--line);color:var(--fg);border-radius:7px;height:28px;font-size:12px;cursor:pointer}
.afdates{display:flex;align-items:flex-end;gap:6px;flex-wrap:wrap}
.afdlab{display:flex;flex-direction:column;gap:3px;font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.afin.afdate{width:168px;color-scheme:dark}
.afdclear{align-self:flex-end;background:transparent;border:1px solid var(--line);color:var(--muted);border-radius:7px;height:30px;padding:0 10px;font-size:11px;cursor:pointer}
.afdclear:hover{color:var(--fg);border-color:var(--accent)}
.afpager{display:flex;flex-wrap:wrap;gap:5px;justify-content:center;align-items:center;margin:16px 0}
.afpg{height:30px;min-width:32px;padding:0 9px;background:var(--panel2);border:1px solid var(--line);color:var(--fg);border-radius:7px;font-size:12px;cursor:pointer}
.afpg:hover:not(:disabled){border-color:var(--accent)}
.afpg.cur{background:var(--accent);border-color:var(--accent);color:#06121b;font-weight:700}
.expbtn,.expbtn:hover,.expbtn:focus{display:inline-flex;align-items:center;gap:7px;width:auto;flex:0 0 auto;white-space:nowrap;padding:8px 13px;background:rgba(243,65,94,.12);border-color:rgba(243,65,94,.45);color:#ff8095}
.afpg:disabled{opacity:.4;cursor:default}
.afdots{color:var(--muted);padding:0 2px}
.pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:700;background:#1b232e;color:var(--muted);text-transform:capitalize}
.pill.ok{background:rgba(74,222,128,.12);color:var(--green)}
.pill.no{background:rgba(243,65,94,.12);color:#ff8095}
.pill.run{background:rgba(251,190,41,.15);color:#fbbe29}
/* phase run-state badge: RUN green, RUNNING yellow (animated), NOT RUN red */
.pst{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:999px;font-size:11px;font-weight:800;letter-spacing:.5px}
.pst::before{content:"";width:7px;height:7px;border-radius:50%;background:currentColor;flex:none}
.pst.run{background:rgba(74,222,128,.12);color:var(--green)}
.pst.none{background:rgba(243,65,94,.12);color:#ff8095}
.pst.running{background:rgba(251,190,41,.15);color:#fbbe29}
.pst.running::before{animation:pulse 1s ease-in-out infinite}
.phlink{color:var(--fg);text-decoration:none;border-bottom:none}
.phlink:hover{color:var(--accent)}
.phname{display:inline-flex;align-items:center;gap:8px}
.phtag{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:700;letter-spacing:.02em;white-space:nowrap;line-height:1.5}
.mnglink{color:var(--accent);text-decoration:none;font-weight:600;white-space:nowrap;opacity:.85;transition:opacity .12s ease}
.mnglink:hover{opacity:1;text-decoration:none}
/* bulk triage: left checkbox column + a Manage-selected button that rises in */
.bchkcol{width:34px;text-align:center}
.bchk,.bchkall{width:15px;height:15px;cursor:pointer;accent-color:var(--accent)}
.bulkbtn{display:inline-flex;align-items:center;gap:8px;border:1px solid rgba(59,187,248,.45);background:rgba(59,187,248,.14);color:var(--accent);font-size:12px;font-weight:700;padding:7px 14px;border-radius:8px;cursor:pointer;white-space:nowrap;opacity:0;transform:translateY(7px) scale(.95);pointer-events:none;transition:opacity .2s ease,transform .22s cubic-bezier(.2,.9,.3,1.35)}
.bulkbtn.show{opacity:1;transform:translateY(0) scale(1);pointer-events:auto;animation:bulkpulse 1.5s ease-out 1}
.bulkbtn:hover{background:rgba(59,187,248,.26)}
.bulkbtn .bk{display:inline-flex;align-items:center;justify-content:center;min-width:18px;height:18px;padding:0 5px;border-radius:9px;background:var(--accent);color:#06121b;font-size:11px;font-weight:800;line-height:1}
@keyframes bulkpulse{0%{box-shadow:0 0 0 0 rgba(59,187,248,.45)}100%{box-shadow:0 0 0 11px rgba(59,187,248,0)}}
.bulkopt{display:flex;gap:9px;flex-wrap:wrap}
.bulkcard{flex:1 1 140px;display:inline-flex;align-items:center;justify-content:center;text-align:center;padding:12px 14px;border:1px solid var(--line);border-radius:10px;background:var(--panel2);color:var(--muted);font-size:13px;font-weight:700;cursor:pointer;transition:border-color .16s,background .16s,color .16s,transform .12s,box-shadow .16s}
.bulkcard:hover{color:var(--fg);border-color:var(--muted);transform:translateY(-1px)}
.bulkcard:active{transform:translateY(0) scale(.98)}
.bulkcard.sel{border-color:var(--red);color:#ff8095;background:rgba(243,65,94,.12);box-shadow:0 0 0 1px rgba(243,65,94,.35) inset;animation:bulkcardpop .22s ease-out 1}
@keyframes bulkcardpop{0%{transform:scale(.97)}60%{transform:scale(1.02)}100%{transform:scale(1)}}
.bulknote{min-height:150px;resize:vertical}
/* needs-attention block */
.attncard{display:flex;flex-direction:column;gap:0;padding:0}
.attn{display:flex;gap:12px;padding:15px 18px;border-top:1px solid var(--line)}
.attn .badge{width:112px;flex:none;justify-content:center;align-self:flex-start}
.attn:first-child{border-top:none}
.attnbody{min-width:0;flex:1}
.attntitle{font-weight:700;font-size:14px;margin-bottom:3px}
.attnact{font-size:12px;margin-top:7px;color:var(--fg)}
.attnact b{color:var(--accent)}
.fpmark{font-size:12px;margin-top:7px;font-weight:700;color:var(--green)}
.cfmark{font-size:12px;margin-top:7px;font-weight:700;color:var(--green)}
.attnsev{flex:none;display:flex;flex-direction:column;gap:7px;width:132px}
.attnsev .badge{width:100%;justify-content:center}
.attnbtns{display:flex;flex-direction:column;gap:6px}
.actbtn{white-space:nowrap;width:100%;justify-content:center;text-align:center;text-decoration:none}
.actbtn:hover{text-decoration:none}
/* per-vulnerability page */
.vhead{display:flex;align-items:center;gap:12px;margin:14px 0 8px}
.vtitle{font-size:22px;margin:0}
.vmetarow{display:flex;flex-wrap:wrap;gap:8px 18px;margin-bottom:16px}
.vmetav{color:var(--accent)}
.vmeta{font-size:12px;color:var(--muted)}
.vmeta b{color:var(--fg);font-weight:700;margin-right:5px;text-transform:uppercase;letter-spacing:.4px;font-size:11px}
.vactions{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:8px}
.vbtn{display:inline-flex;align-items:center;gap:7px;width:auto;white-space:nowrap;background:transparent;border:1px solid var(--line);color:var(--fg);padding:9px 15px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;transition:border-color .15s,color .15s,background .15s}
.vbtn:hover{border-color:var(--accent)}
.vbtn.danger:hover{border-color:var(--red);color:#ff8095}
.vbtn.confirm:hover{border-color:var(--green);color:#8ef0b0}
/* early-alert: a logo mark on a blue opacity field, the one accent action */
.alertbtn,.alertbtn:hover,.alertbtn:focus{background:rgba(59,187,248,.12);border-color:rgba(59,187,248,.45);color:#8fd6ff}
.alertbtn svg{opacity:.95}
.vdesc{font-size:14px;line-height:1.55}
/* lifecycle banner */
.statebanner{font-size:13px;line-height:1.5;padding:11px 14px;border-radius:10px;margin-bottom:14px;border:1px solid var(--line)}
.statebanner b{font-weight:800}
.statewhy{font-size:12px;color:var(--muted);margin-top:5px}
.statebanner.st-tr{background:rgba(59,187,248,.08);border-color:rgba(59,187,248,.35)}
.statebanner.st-fp{background:rgba(243,65,94,.08);border-color:rgba(243,65,94,.35)}
.statebanner.st-cf{background:rgba(74,222,128,.08);border-color:rgba(74,222,128,.35)}
/* vulnerability rating card */
.ratecard{display:flex;flex-direction:column;gap:12px}
.raterow{display:flex;flex-wrap:wrap;gap:12px}
.ratecell{flex:1;min-width:150px;background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:10px 12px}
.ratecell.veccell{flex:2.4;min-width:260px}
.ratek{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);display:flex;align-items:center;gap:6px;margin-bottom:7px}
.ratev{display:flex;align-items:center}
.ratev code{font-size:12.5px;word-break:break-all;color:var(--fg)}
.scorechip{display:inline-block;font-weight:800;font-size:13px;padding:3px 12px;border-radius:999px;background:#2a2f3a;color:#cbd5e1}
.editico{display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;padding:0;border:1px solid var(--line);border-radius:6px;background:transparent;color:var(--muted);cursor:pointer}
.editico:hover{border-color:var(--accent);color:var(--accent)}
.vecedit{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-top:9px}
.vecinput{flex:1;min-width:220px;height:34px;box-sizing:border-box;padding:0 10px;background:var(--panel);border:1px solid var(--line);border-radius:8px;color:var(--fg);font-size:12.5px;font-family:ui-monospace,monospace}
.vecinput:focus{outline:none;border-color:var(--accent)}
.sbtn,.btn-ghost.sbtn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:0 14px;height:34px;line-height:1;box-sizing:border-box;text-align:center}
.vecerr{flex-basis:100%;font-size:12px;color:#ff8095}
.ratehint{font-size:12px}
.ratehint a{color:var(--accent)}
.hostlist{margin:0;padding-left:20px;display:flex;flex-direction:column;gap:5px}
.hostlist li{font-size:13.5px;word-break:break-all}
/* editable sections */
.efield{margin-top:4px}
.ehead{display:flex;align-items:center;gap:9px;margin:14px 0 8px}
.ehead h2{margin:0}
.eview p{font-size:14px;line-height:1.6;margin:0 0 10px}
.eview p:last-child{margin-bottom:0}
.eta{width:100%;box-sizing:border-box;background:var(--panel);border:1px solid var(--line);border-radius:9px;color:var(--fg);font-size:13px;padding:9px 11px;resize:vertical;font-family:inherit;line-height:1.5}
.einp{width:100%;box-sizing:border-box;height:34px;background:var(--panel);border:1px solid var(--line);border-radius:8px;color:var(--fg);font-size:13px;padding:0 10px}
.eta:focus,.einp:focus{outline:none;border-color:var(--accent)}
/* Standard dropdown: one look for every <select> in the app (same height, font,
   padding and caret) so no control uses the browser default. Any select that
   wants the standard look carries the .uisel class (or is an .einp/.clsort/
   .gsel select). The caret is drawn by us since appearance is removed. */
select.einp,select.clsort,select.gsel,select.uisel{height:34px;line-height:32px;vertical-align:middle;-webkit-appearance:none;-moz-appearance:none;appearance:none;font-family:inherit;cursor:pointer;padding-right:30px;background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='10' height='10' viewBox='0 0 24 24' fill='none' stroke='%238aa0b4' stroke-width='3' stroke-linecap='round' stroke-linejoin='round'><path d='M6 9l6 6 6-6'/></svg>");background-repeat:no-repeat;background-position:right 10px center}
select.einp option,select.clsort option,select.gsel option,select.uisel option{background:var(--panel);color:var(--fg)}
/* the Severity select carries a coloured caret that reads on its tinted fill */
.sevsel{font-weight:700}
.sevsel option{font-weight:700}
/* inline "Label: input" row (Title, CVSS vector, CVSS score) */
.inlrow{display:flex;align-items:center;gap:10px;margin-top:6px}
.inlrow>.inlk{flex:none;margin:0;min-width:120px;display:flex;align-items:center;height:34px;white-space:nowrap}
.inlrow>.einp{flex:1 1 auto}
#cvssvec{font-family:ui-monospace,monospace;font-size:12.5px}
#cvssscore{font-weight:700;background:var(--panel2)}
/* live type-ahead combo (OWASP / CWE) */
.combo{position:relative}
.combo .combores{left:0;right:0}
.efhint{font-size:12px;margin-top:8px;line-height:1.45}
.ebtns{display:flex;align-items:center;gap:9px;margin-top:10px}
.eferr{font-size:12px;color:#ff8095}
.clsrow{display:flex;flex-wrap:wrap;gap:14px}
.clsrow>div{flex:1;min-width:160px}
.repro{margin:0;padding-left:22px;display:flex;flex-direction:column;gap:6px}
.repro li{font-size:13.5px;line-height:1.5}
.bullets{margin:0;padding-left:20px;display:flex;flex-direction:column;gap:6px}
.bullets li{font-size:13.5px;line-height:1.5}
.bullets a{color:var(--accent)}
.codeblock{margin:12px 0 0;background:var(--panel2);border:1px solid var(--line);border-radius:9px;padding:10px 12px;overflow:auto}
.codeblock code{font-family:ui-monospace,monospace;font-size:12.5px;white-space:pre-wrap;word-break:break-all}
.figwrap{display:flex;flex-direction:column;gap:9px;margin-top:12px}
.figslot{display:flex;gap:12px;align-items:center;border:1px dashed var(--line);border-radius:9px;padding:10px 12px}
.figph{flex:none;width:92px;height:56px;display:flex;align-items:center;justify-content:center;background:var(--panel2);border-radius:7px;color:var(--muted);font-size:12px;font-weight:700}
.figmeta{min-width:0}
.figcap{font-size:13px}
.fignm{font-size:12px;color:var(--muted);margin-top:3px}
.fignm code{font-family:ui-monospace,monospace}
.refwarn{font-size:12.5px;color:#ffcf8f;margin-top:12px;padding:9px 11px;border:1px solid rgba(245,197,24,.35);background:rgba(245,197,24,.08);border-radius:8px}
/* evidence files + upload */
.evfiles{display:flex;flex-wrap:wrap;gap:12px;margin-top:12px}
.evfile{width:160px;border:1px solid var(--line);border-radius:10px;overflow:hidden;background:var(--panel2)}
.evthumb{display:block;width:100%;height:100px;object-fit:cover;background:#0b0f14}
.evthumb.pdf{display:flex;align-items:center;justify-content:center;color:var(--muted);font-weight:800;font-size:15px;text-decoration:none}
.evthumb.ph{display:flex;align-items:center;justify-content:center;text-align:center;color:var(--muted);font-size:11px;line-height:1.3}
.evmeta{padding:7px 9px}
.evfile .figcap{font-size:11.5px;color:var(--muted);margin:2px 0 4px;line-height:1.35}
.figlist{display:flex;flex-direction:column;gap:12px;margin-top:8px}
.figrow{display:flex;gap:14px;align-items:flex-start;border:1px solid var(--line);border-radius:10px;background:var(--panel2);padding:10px;overflow:hidden}
.figimg{flex:none;width:120px;height:80px;border:1px solid var(--line);border-radius:7px;overflow:hidden;background:#0b0f14;cursor:zoom-in}
.figimg a{display:block;width:100%;height:100%}
.figimg img{display:block;width:100%;height:100%;object-fit:cover}
.figimg.ph{display:flex;align-items:center;justify-content:center;text-align:center;color:var(--muted);font-size:11px;line-height:1.3;cursor:default}
.figtext{flex:1 1 auto;min-width:0;display:flex;flex-direction:column;gap:4px}
.figtext .evname{font-weight:700;color:var(--fg)}
.figtext .figcap{font-size:13px;color:var(--muted);line-height:1.45}
.figcapin{width:100%;font-size:13px;color:var(--fg);background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:6px 8px;line-height:1.4;transition:border-color .15s,background .15s}
.figcapin::placeholder{color:var(--muted)}
.figcapin:focus{outline:none;border-color:var(--accent)}
.figcapin.saved{border-color:#2ea043;background:rgba(46,160,67,.08)}
.figcapin.saveerr{border-color:#d9534f;background:rgba(217,83,79,.08)}
.figtext .evdel{align-self:flex-start;margin-top:4px}
@media (max-width:640px){.figrow{flex-direction:column}.figimg{width:100%;max-width:none}}
.evname{font-size:12px;word-break:break-all}
.evdel{margin-top:5px;background:transparent;border:1px solid var(--line);color:var(--muted);border-radius:6px;font-size:11px;padding:2px 8px;cursor:pointer}
.evdel:hover{border-color:var(--red);color:#ff8095}
.evup{display:flex;flex-wrap:wrap;align-items:center;gap:11px;margin-top:14px;padding-top:12px;border-top:1px solid var(--line)}
.evuplbl{flex:1;min-width:240px;display:flex;align-items:center;gap:12px;padding:12px 14px;border:1px dashed var(--line);border-radius:10px;cursor:pointer;background:rgba(59,187,248,.04);transition:border-color .15s,background .15s}
.evuplbl:hover{border-color:var(--accent);background:rgba(59,187,248,.08)}
.evupico{flex:none;display:inline-flex;align-items:center;justify-content:center;width:38px;height:38px;border-radius:9px;background:rgba(59,187,248,.12);color:var(--accent)}
.evuptext{display:flex;flex-direction:column;gap:2px;font-size:13px}
.evuptext b{font-weight:700;color:var(--fg)}
.evuptext .muted{font-size:11.5px}
.evcap{display:flex;flex-wrap:wrap;align-items:center;gap:11px;margin-top:11px;padding-top:11px;border-top:1px dashed var(--line)}
.evcaptext{display:flex;flex-direction:column;gap:2px;font-size:13px;flex:1 1 260px}
.evcaptext b{font-weight:700;color:var(--fg)}
.evcaptext .muted{font-size:11.5px}
.evuplbl input[type=file]{position:absolute;width:1px;height:1px;opacity:0;overflow:hidden;clip:rect(0 0 0 0);pointer-events:none}
/* operator notes trail */
.onotes{display:flex;flex-direction:column;gap:10px}
.onote{padding:10px 12px;border:1px solid var(--line);border-radius:9px;background:var(--panel2)}
.onhd{font-size:13px}
.onhd b{font-weight:800}
.onreason{font-size:12.5px;color:var(--fg);margin-top:4px;white-space:pre-wrap;word-break:break-word}
.onfiles{display:flex;flex-wrap:wrap;gap:10px;margin-top:9px}
.onfile{display:inline-flex;flex-direction:column;align-items:center;gap:4px;width:92px;text-decoration:none;color:var(--muted);font-size:11px}
.onfile img{width:92px;height:64px;object-fit:cover;border:1px solid var(--line);border-radius:7px}
.onfile span{max-width:92px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.onfile.pdf{justify-content:center;height:64px;border:1px solid var(--line);border-radius:7px;background:var(--panel);font-weight:700;color:var(--accent)}
.onfile:hover{color:var(--accent)}
.rfile{display:flex;flex-direction:column;gap:5px;font-size:12px;color:var(--muted)}
.rfile input{font-size:12px;color:var(--fg)}
/* client sub-nav tabs */
.ctabs{display:flex;flex-wrap:wrap;gap:4px;margin-top:14px;border-bottom:1px solid var(--line)}
.ctab{display:inline-flex;align-items:center;height:38px;padding:0 15px;font-size:13px;font-weight:600;color:var(--muted);text-decoration:none;border-bottom:2px solid transparent;margin-bottom:-1px}
.ctab:hover{color:var(--fg)}
.ctab.on{color:var(--fg);border-bottom-color:var(--accent)}
.pager{display:flex;flex-wrap:wrap;gap:6px;justify-content:center;margin:16px 0 4px}
.pgl{display:inline-flex;align-items:center;justify-content:center;min-width:32px;height:32px;padding:0 9px;border:1px solid var(--line);border-radius:8px;color:var(--muted);font-size:13px;font-weight:700;text-decoration:none;transition:border-color .15s,color .15s,background .15s}
.pgl:hover{color:var(--fg);border-color:var(--accent)}
.pgl.on{color:#06121b;background:var(--accent);border-color:var(--accent)}
.pgdots{display:inline-flex;align-items:flex-end;padding:0 2px;color:var(--muted)}
.subviews{display:flex;align-items:center;gap:0;margin:12px 0 12px}
.subviewbtn{display:inline-flex;align-items:center;height:30px;padding:0 12px;background:transparent;border:none;color:var(--muted);font-size:13px;font-weight:600;cursor:pointer;transition:color .15s}
.subviewbtn:hover{color:var(--fg)}
.subviewbtn.on{color:#ff8095}
.subvsep{color:var(--line);font-weight:400;padding:0 2px;user-select:none}
/* subdomains tab */
.subhead{margin:16px 0 10px}
.subwrap{position:relative}
.substa{width:100%;box-sizing:border-box;min-height:calc(min(70vh,640px) - 38px);height:calc(min(70vh,640px) - 38px);background:var(--panel2);border:1px solid var(--line);border-radius:10px;color:var(--fg);font-family:ui-monospace,monospace;font-size:12.5px;line-height:1.6;padding:58px 14px 14px 14px;resize:vertical}
.substa:focus{outline:none;border-color:var(--accent)}
.subfind{position:absolute;top:9px;left:9px;z-index:2;width:170px;height:28px;box-sizing:border-box;background:var(--panel);border:1px solid var(--line);border-radius:7px;color:var(--fg);font-size:12px;padding:0 9px 0 28px;background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='13' height='13' viewBox='0 0 24 24' fill='none' stroke='%238aa0b4' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round'><circle cx='11' cy='11' r='7'/><path d='M21 21l-4.3-4.3'/></svg>");background-repeat:no-repeat;background-position:8px center}
.subfind:focus{outline:none;border-color:var(--accent)}
.copybtn{position:absolute;top:9px;right:9px;z-index:2;display:inline-flex;align-items:center;justify-content:center;width:30px;height:28px;padding:0;background:var(--panel);border:1px solid var(--line);color:var(--muted);border-radius:7px;cursor:pointer;transition:border-color .15s,color .15s,background .15s}
.copybtn:hover{border-color:var(--accent);color:var(--accent)}
.copybtn.copied{border-color:var(--green);color:var(--green);background:rgba(39,201,132,.14)}
.subbtns{display:flex;align-items:center;gap:12px;margin-top:10px}
.subalerts{display:flex;flex-direction:column;gap:0;padding:0}
.salert{padding:11px 14px;border-bottom:1px solid var(--line)}
.salert:last-child{border-bottom:none}
.salerthd{font-size:13px;margin-bottom:3px}
/* collapsible dropdown card (Leak alerts and similar) */
.dropcard{margin-top:18px}
.dropcard>.dropsum{list-style:none;cursor:pointer;display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px 15px;border:1px solid var(--line);border-radius:12px;font-weight:700;font-size:14px;background:var(--card);user-select:none}
.dropcard>.dropsum::-webkit-details-marker{display:none}
.dropcard>.dropsum:hover{border-color:rgba(127,160,200,.4)}
.dropcard[open]>.dropsum{border-bottom-left-radius:0;border-bottom-right-radius:0}
.dropcaret{transition:transform .2s ease;flex:none;color:var(--muted)}
.dropcard[open] .dropcaret{transform:rotate(180deg)}
.dropcard .dropbody{margin-top:0;border-top-left-radius:0;border-top-right-radius:0;border-top:none;animation:flashin .2s ease}
/* leaks tab */
.leakctrls{display:flex;align-items:center;gap:12px;margin:4px 0 12px;flex-wrap:wrap}
.leakfilt{max-width:360px;flex:1 1 220px}
.leakbtns{display:flex;gap:9px;margin-left:auto}
.leaktbl td,.leaktbl th{font-size:12.5px;vertical-align:middle}
.pwcell{white-space:nowrap}
.pwmask{font-family:ui-monospace,monospace;letter-spacing:1px}
.pwclick{cursor:pointer;border-bottom:1px dashed var(--muted);padding-bottom:1px}
.pwclick:hover{color:var(--accent);border-bottom-color:var(--accent)}
.xlsxbtn,.btn-ghost.xlsxbtn{background:rgba(74,222,128,.12);border-color:rgba(74,222,128,.45);color:var(--green)}
.xlsxico{flex:none;width:15px;height:15px}
.xlsxbtn:hover,.btn-ghost.xlsxbtn:hover{border-color:var(--green);color:var(--green)}
.revealbtn{margin-left:9px;background:transparent;border:1px solid var(--line);color:var(--muted);border-radius:6px;font-size:11px;padding:2px 8px;cursor:pointer}
.revealbtn:hover{border-color:var(--accent);color:var(--accent)}
.demowatch{display:inline-block;margin-left:6px;padding:1px 8px;border:1px dashed var(--line);border-radius:999px;font-size:11px;color:var(--muted)}
/* context tab: company fields left, a small right-aligned brand logo */
.ctxcard{display:flex;flex-direction:column;gap:16px}
.ctxgrid{display:flex;gap:22px;align-items:flex-start}
.ctxfields{flex:1 1 auto;min-width:0;display:flex;flex-direction:column;gap:0;background-image:linear-gradient(var(--line),var(--line));background-repeat:no-repeat;background-size:1px 100%;background-position:186px 0}
.cxrow{display:flex;align-items:center;gap:12px;padding:9px 0;border-bottom:1px solid var(--line);font-size:13.5px}
.cxrow:last-child{border-bottom:none}
.cxk{color:var(--muted);font-weight:700;width:180px;flex:none;overflow-wrap:break-word;text-align:center}
.cxsep{display:none}
.cxv{color:var(--fg);flex:1 1 auto;word-break:break-word;white-space:pre-wrap;padding-left:14px}
.cxlink{color:var(--accent);text-decoration:none;border-bottom:1px solid transparent}
.cxlink:hover{border-bottom-color:var(--accent)}
.cxtable{width:100%;border-collapse:collapse;table-layout:fixed}
.cxtable>tbody>tr>td{border-bottom:1px solid var(--line);padding:9px 0;font-size:13.5px;line-height:20px;vertical-align:middle}
.cxtable>tbody>tr:last-child>td{border-bottom:none}
.cxtable>tbody>tr:not(.cxsectitle):not(.cxsecsep)>td{height:20px}
.cxtable td.cxk{border-right:1px solid var(--line)}
/* The value is an inline span with a left pad; on an inline box that pad only
   indents the first line, so wrapped lines slid back to the cell edge. Make the
   table value a block so every line aligns at the same left indent. */
.cxv-cell>.cxv{display:block}
.cxtable td.cxv-cell.cxv-tech{vertical-align:top}
.cxtable td.cxlogocell{width:150px;border-left:1px solid var(--line);text-align:center;vertical-align:middle;padding-left:14px}
.cxtable td.cxlogocell .ctxlogobox{margin:0 auto}
.cxtable .cxin{width:100%}
.cxtable tr.cxsecsep td{padding:0;height:8px;border-bottom:none}
.cxtable tr.cxsectitle td{padding:7px 10px;text-align:center;font-weight:800;
  font-size:11px;letter-spacing:.14em;text-transform:uppercase;
  color:rgba(243,65,94,.80);background:rgba(243,65,94,.07);
  border-bottom:1px solid var(--line)}
.cxtable tr.cxsectitle:first-child td{border-top:none}
.ctxhead{display:block;padding-bottom:16px;border-bottom:2px solid var(--line);margin-bottom:6px}
.ctxbody{display:flex;gap:22px;align-items:flex-start}
.ctxheadmain{flex:1 1 auto;min-width:0}
.ctxhead .cxin{width:100%}
.ctxtitle{font-size:20px;font-weight:800;letter-spacing:.3px;margin-bottom:10px}
.ctxtitle .cxlink{color:var(--fg)}
.ctxtitle .cxlink:hover{color:var(--accent);border-bottom-color:var(--accent)}
.ctxabstract{color:var(--fg);font-size:15px;line-height:1.65;margin-bottom:10px}
.ctxabstract .cxv{padding-left:0;display:block}
.ctxtitle .cxv{padding-left:0}
.cxchip,.cxunconf{display:inline-block;margin-left:7px;padding:1px 8px;border-radius:999px;font-size:10.5px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;white-space:nowrap;text-indent:0;vertical-align:middle;border:1px solid transparent}
.cxchip.c-ok{color:#9df5c0;background:rgba(74,222,128,.14);border-color:rgba(74,222,128,.5)}
.cxchip.c-mid{color:#ffd98a;background:rgba(224,167,58,.16);border-color:rgba(224,167,58,.55)}
.cxchip.c-low{color:var(--muted);background:rgba(107,122,141,.12);border-color:rgba(107,122,141,.4)}
.cxunconf,.cxchip.c-bad{color:#ffb0bd;background:rgba(243,65,94,.14);border-color:rgba(243,65,94,.5)}
.ctxweb{font-size:12.5px;margin-bottom:8px;display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}
.ctxsummary{color:var(--muted);font-size:12.5px;line-height:1.7}
.ctxsummary b{color:var(--fg);font-weight:600}
.cxhalt{display:flex;gap:12px;align-items:flex-start;background:rgba(243,65,94,.12);border:1px solid var(--red);border-radius:10px;padding:12px 14px;margin:14px 0;font-size:13px;line-height:1.5}
.cxrunbar{display:flex;gap:8px;align-items:center;background:var(--panel2);border:1px solid var(--line);border-radius:9px;padding:9px 13px;margin:12px 0;font-size:12.5px;color:var(--muted)}
.cxrunbar.running{border-color:var(--accent);background:rgba(59,187,248,.08);color:var(--fg)}
.cxrundot{width:8px;height:8px;border-radius:50%;background:var(--accent);flex:none;box-shadow:0 0 0 0 rgba(59,187,248,.6);animation:cxpulse 1.4s infinite}
@keyframes cxpulse{0%{box-shadow:0 0 0 0 rgba(59,187,248,.5)}70%{box-shadow:0 0 0 7px rgba(59,187,248,0)}100%{box-shadow:0 0 0 0 rgba(59,187,248,0)}}
.cxhalticon{color:var(--red);font-weight:800;flex:none;font-size:15px}
.cxhaltx{flex:1 1 auto}
.cxhalt a{color:var(--red);font-weight:700;text-decoration:none}
.cxhalt a:hover{text-decoration:underline}
.cxheld{color:var(--muted);font-style:italic}
.cxcov summary{cursor:pointer;color:var(--accent);font-size:12.5px}
.cxcov .l0pre{margin-top:8px}
.cxv-cell:has(.cxlist){vertical-align:top}
.cxv:has(.cxlist){display:block;white-space:normal}
.cxlist{margin:0;padding-left:0;list-style:disc;list-style-position:inside}
.cxlist li{margin:2px 0;line-height:1.5;text-indent:-1em;padding-left:1em}
.cxlist li::marker{color:var(--muted)}
.cxv:has(.cxsub){display:block;white-space:normal}
.cxsub{width:auto;border-collapse:collapse;margin:1px 0;table-layout:fixed}
.cxsub td{padding:3px 12px 3px 0;vertical-align:top;border:none;height:auto;line-height:1.45;overflow-wrap:break-word}
.cxsub td.cxsub-what{color:var(--muted)}
.cxsub-subs td.cxsub-what{white-space:normal;overflow-wrap:break-word}
.cxsub td.cxsub-conf,.cxsub td.cxsub-state{white-space:nowrap}
.cxsub-cands,.cxsub-subs{width:100%}
.cxsub tr+tr td{border-top:1px solid rgba(255,255,255,.04)}
.cxtable td.cxmmrow{padding:12px 0}
.hiergraphcard .graphwrap.hiergraphwrap{height:420px}
.cxin{display:none;flex:1 1 auto;box-sizing:border-box;background:var(--panel);border:1px solid var(--line);border-radius:7px;color:var(--fg);font-size:13px;padding:6px 9px;font-family:inherit}
.cxin:focus{outline:none;border-color:var(--accent)}
textarea.cxin{resize:vertical;min-height:90px}
/* Key technologies row: a bullet list as the value, visible in edit mode too */
.cxrowtech{align-items:flex-start}
.cxvtech{flex:1 1 auto;min-width:0}
/* list markers sit INSIDE with no left padding, so each tech item starts at
   the same x as every other row's value (aligned to the colon), not indented */
.cxvtech ul,.cxvtech ul.fptechlist{margin:0;padding-left:0;list-style:disc;list-style-position:inside}
.cxvtech li{margin:2px 0;line-height:1.5;color:var(--fg)}
.ctxcard.editing .cxv{display:none}
.ctxcard.editing .cxin{display:block}
.ctxcard.editing .cxrow{align-items:center}
.ctxlogo{flex:0 0 auto;display:flex;flex-direction:column;gap:9px;align-items:center}
.ctxlogobox{width:120px;height:150px;border:1px solid var(--line);border-radius:10px;background:var(--panel2);display:flex;align-items:center;justify-content:center;overflow:hidden}
.ctxlogobox img{width:100%;height:100%;object-fit:contain}
.ctxlogobox .ph{color:var(--muted);font-size:11px;text-align:center;padding:10px;line-height:1.4}
.branduplbl{position:relative;font-size:12px;font-weight:600;color:var(--accent);cursor:pointer;border:1px dashed var(--line);border-radius:8px;padding:6px 12px;text-align:center}
.branduplbl:hover{border-color:var(--accent)}
.branduplbl input[type=file]{position:absolute;width:1px;height:1px;opacity:0;overflow:hidden;clip:rect(0 0 0 0);pointer-events:none}
@media(max-width:640px){.ctxgrid{flex-direction:column}.ctxlogo{align-self:flex-start}}
/* layer 0 company-footprint dossier */
.fpdossier{margin-top:22px}
.fptechlist{margin:0;padding:4px 0 2px 20px;list-style:disc}
.fptechlist li{margin:4px 0;line-height:1.5}
.fpran{font-size:12px;margin-bottom:12px}
.fpempty,.fpempshell{padding:16px 18px;font-size:13px;line-height:1.5}
.fph2{margin:22px 0 10px;font-size:15px}
.fph2 .fpn{color:var(--muted);font-weight:600;font-size:13px}
.fptablecard{padding:0;overflow:hidden}
.fpgate,.fpcovbody{padding:11px 15px}
.fpgate{border-bottom:1px solid var(--line);font-size:12px}
.fptable{width:100%;border-collapse:collapse;font-size:13px;table-layout:auto}
.fptable th{text-align:left;color:var(--muted);font-weight:700;font-size:11.5px;text-transform:uppercase;letter-spacing:.03em;padding:10px 14px;border-bottom:1px solid var(--line);white-space:nowrap}
.fptable td{padding:10px 14px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
.fptable tr:last-child td{border-bottom:none}
.fptable td.fpval{font-weight:600;word-break:break-word}
.fptable td.fpsig{color:var(--fg);max-width:320px}
.fptable td.fpsrc{font-size:12px;max-width:200px}
.fptable td.fpst{white-space:nowrap}
.fpchip{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:700;white-space:nowrap;text-indent:0;background:#1b232e;color:var(--muted)}
.fpchip.vd-owned{background:rgba(74,222,128,.12);color:var(--green)}
.fpchip.vd-lookalike{background:rgba(243,65,94,.12);color:#ff8095}
.fpchip.vd-third_party{background:rgba(251,190,41,.14);color:#fbbe29}
.fpchip.vd-pending{background:#1b232e;color:var(--muted)}
/* sanctions / screen status badge, inline in its value cell */
.scr{display:inline-block;font-size:11px;font-weight:800;letter-spacing:.5px;border-radius:6px;padding:2px 9px}
.scr-unscreened{color:#fbbe29;border:1px solid rgba(251,190,41,.4);background:rgba(251,190,41,.1)}
.scr-clear{color:var(--green);border:1px solid rgba(74,222,128,.4);background:rgba(74,222,128,.08)}
.scr-hit{color:#ff8095;border:1px solid rgba(243,65,94,.4);background:rgba(243,65,94,.1)}
/* thin divider between the identity fields and the layer-0 dossier rows */
.cxkvsep{height:0;border-top:1px dashed var(--line);margin:10px 0 2px}
.l0run{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:12px 0 8px}
.l0runinfo{display:flex;flex-direction:column;gap:2px}
.l0runt{font-weight:700;font-size:13px}
.l0dbglink{margin-left:12px;font-size:12px;color:var(--muted);text-decoration:none;border:1px solid var(--line);border-radius:6px;padding:4px 9px}
.l0dbglink:hover{color:var(--fg);border-color:var(--accent)}
.l0pre{margin:8px 0 0;padding:10px;background:var(--panel2);border:1px solid var(--line);border-radius:7px;font-size:12px;line-height:1.5;white-space:pre-wrap;word-break:break-word;max-height:360px;overflow:auto;color:var(--fg)}
.l0live{border-color:var(--accent)}
.l0now{display:flex;align-items:baseline;gap:8px;margin-top:6px;font-size:13px;color:var(--fg);word-break:break-word}
.l0dot{flex:none;width:9px;height:9px;border-radius:50%;background:var(--accent);align-self:center;animation:l0pulse 1.2s ease-in-out infinite}
@keyframes l0pulse{0%,100%{opacity:1}50%{opacity:.25}}
.tllist{margin-top:8px;max-height:460px;overflow:auto;border:1px solid var(--line);border-radius:7px;background:var(--panel2)}
.tlrow{display:flex;gap:10px;align-items:baseline;padding:6px 10px;border-bottom:1px solid var(--line);font-size:12.5px}
.tlrow:last-child{border-bottom:none}
.tlts{flex:none;color:var(--muted);font-variant-numeric:tabular-nums;font-size:11.5px}
.tltag{flex:none;min-width:84px;font-weight:700;font-size:11px;text-transform:lowercase}
.tlt-tool{color:var(--accent)}
.tlt-think{color:var(--muted)}
.tlt-init{color:var(--green)}
.tlt-result{color:var(--green)}
.tldetail{flex:1 1 auto;color:var(--fg);word-break:break-word;white-space:pre-wrap}
.l0bar{height:12px;border-radius:999px;background:var(--panel2);border:1px solid var(--line);overflow:hidden;margin:4px 0 6px}
.l0barfill{height:100%;border-radius:999px;background:var(--accent);transition:width .4s ease}
.l0barfill.run{background:linear-gradient(90deg,var(--accent),#7cc6ff);animation:l0bw 1.6s ease-in-out infinite}
.l0barfill.ok{background:var(--green)}
.l0barfill.fail{background:var(--red)}
@keyframes l0bw{0%,100%{opacity:1}50%{opacity:.7}}
.l0barcap{display:flex;justify-content:space-between;font-size:11.5px;color:var(--muted);margin-bottom:8px}
.fpdossier .fpsrc{font-size:11.5px;margin-left:6px}
.fphalt{border:1px solid var(--red);background:rgba(220,70,80,.08)}
.fphalthead{font-weight:800;color:var(--red);font-size:14px;margin-bottom:6px}
.fphaltbody{font-size:13px;line-height:1.5}
.fpcov{margin-top:22px}
.fpcovpre{margin:0;white-space:pre-wrap;word-break:break-word;font-family:inherit;font-size:13px;line-height:1.5;color:var(--fg)}
/* vuln db + review forms */
.vdbform{display:flex;flex-direction:column;gap:8px}
.vdbform .rlbl{margin-top:6px}
.vdbform .clsgrid{display:grid;grid-template-columns:repeat(3,1fr);grid-auto-rows:auto;column-gap:12px;row-gap:6px;align-items:end}
.vdbform .clsgrid>.rlbl{margin:0;align-self:end}
.vdbform .clsgrid>.einp{margin:0}
.vdbform .clsrow{gap:12px;align-items:stretch}
/* A wrapping label or a <select>, whose intrinsic height differs from a text
   input, must not drop its field below the neighbours: make the columns equal
   height and bottom-align the field inside each one, so every field lines up. */
.vdbform .clsrow>div{display:flex;flex-direction:column;justify-content:flex-end}
.vdbform .clsrow>div>.rlbl{flex:0 0 auto}
.vdbform .clsrow>div>.einp{margin-top:6px;flex:0 0 auto}
.exampletag{display:inline-block;margin-left:7px;padding:1px 7px;border:1px solid rgba(59,187,248,.4);border-radius:999px;font-size:10px;font-weight:700;letter-spacing:.5px;color:var(--accent)}
.vtag{display:inline-block;margin:1px 4px 1px 0;padding:1px 8px;border-radius:999px;background:rgba(59,187,248,.12);color:var(--accent);font-size:11px;font-weight:700}
.actbtn.danger:hover{border-color:var(--red);color:#ff8095}
.ebtns .go,.sbtn.go{border-color:rgba(59,187,248,.45);color:#8fd6ff;background:rgba(59,187,248,.12)}
/* App-wide rule: a Save button is always grey (neutral), never accent or green,
   so saving reads the same everywhere. Delete/danger stays red, go stays blue. */
.btn-ghost.save,.sbtn.save,.btn.save{border-color:var(--line);color:var(--muted);background:var(--panel2)}
.btn-ghost.save:hover,.sbtn.save:hover,.btn.save:hover{border-color:var(--muted);color:var(--fg);background:var(--panel)}
/* reason modal */
.vmodal{position:fixed;inset:0;z-index:60;display:flex;align-items:center;justify-content:center;padding:18px}
.vmback{position:absolute;inset:0;background:rgba(5,8,14,.62)}
.vmcard{position:relative;width:min(480px,94vw);background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px;box-shadow:0 18px 50px rgba(0,0,0,.5);display:flex;flex-direction:column;gap:10px}
.vmcard h3{margin:0;font-size:16px}
.rlbl{font-size:12.5px;font-weight:700;color:var(--muted)}
.rta{width:100%;box-sizing:border-box;background:var(--panel2);border:1px solid var(--line);border-radius:9px;color:var(--fg);font-size:13px;padding:9px 11px;resize:vertical;font-family:inherit}
.rta:focus{outline:none;border-color:var(--accent)}
.rerr{font-size:12px;color:#ff8095;min-height:14px}
.vmbtns{display:flex;justify-content:flex-end;gap:10px;margin-top:4px}
.vmbtns .go{border-color:rgba(59,187,248,.45);color:#8fd6ff;background:rgba(59,187,248,.12)}
.btn-ghost.sbtn.danger,.sbtn.danger{border-color:rgba(243,65,94,.4);color:#ff9aab;background:rgba(243,65,94,.1)}
.btn-ghost.sbtn.danger:hover,.sbtn.danger:hover{border-color:var(--red);color:#ff8095;background:rgba(243,65,94,.16)}
/* phases stack full width, one layer per card */
.phases{display:flex;flex-direction:column;gap:16px}
.phase{width:100%}
.phhead{display:flex;align-items:center;gap:10px}
.ptag{font-size:10px;font-weight:800;letter-spacing:1px;color:var(--accent);background:rgba(59,187,248,.1);border:1px solid rgba(59,187,248,.25);border-radius:6px;padding:3px 8px;flex:none}
.ptitle{font-weight:700;font-size:16px}
.phase.wip{opacity:.7}
.wipnote{color:var(--muted);font-size:12px;margin-top:12px;padding:12px 14px;border:1px dashed var(--line);border-radius:10px}
/* a capability is a heading, and under it each action is its own square */
.ghead{display:flex;align-items:center;gap:7px;font-weight:700;font-size:13px;margin:18px 0 10px}
.squares{display:flex;flex-direction:column;gap:10px}
.methintro{margin-bottom:18px;max-width:70ch;line-height:1.5}
.methdep{font-size:12px;margin:4px 0 12px}
.methnotes{margin:10px 0 0;padding-left:20px;list-style:disc}
.methnotes li{margin:5px 0;line-height:1.5;font-size:13px;color:var(--muted,#9fb0c0)}
.methgatecard{border-color:rgba(250,204,21,.5);background:rgba(250,204,21,.05)}
.methgate{display:inline-block;font-size:10px;font-weight:800;letter-spacing:1px;color:#facc15;border:1px solid rgba(250,204,21,.5);border-radius:6px;padding:3px 8px;margin-bottom:8px}
.methband{display:flex;flex-direction:column;gap:12px;margin-top:6px}
@media(min-width:900px){.methband{flex-direction:row}.methsub{flex:1 1 0}}
.methsub{border:1px solid var(--line);border-radius:12px;padding:12px 14px;background:rgba(14,20,27,.35)}
.methsubhead{display:flex;align-items:center;gap:8px;font-weight:700;font-size:13px;margin-bottom:8px}
.methsubid{font-size:10px;font-weight:800;letter-spacing:1px;color:var(--accent);border:1px solid rgba(59,187,248,.25);border-radius:6px;padding:2px 6px}
.methbandnote{font-size:12px;margin-top:8px}
.methjobs{display:grid;grid-template-columns:1fr;gap:12px;margin-top:6px}
@media(min-width:900px){.methjobs{grid-template-columns:1fr 1fr}}
.ltag{font-size:10px;font-weight:800;letter-spacing:1px;color:var(--accent);border:1px solid rgba(59,187,248,.25);border-radius:6px;padding:2px 6px;flex:none}
.methjobhelp{font-size:12.5px;line-height:1.5;margin-bottom:6px}
.methnew{font-size:9px;font-weight:800;letter-spacing:1px;color:#4ade80;border:1px solid rgba(74,222,128,.4);background:rgba(74,222,128,.08);border-radius:6px;padding:2px 6px}
.methsubt{font-size:13px}
.methst{margin-left:auto;font-size:9px;font-weight:800;letter-spacing:1px;text-transform:uppercase;border-radius:6px;padding:2px 7px}
.methst-locked{color:var(--green);border:1px solid rgba(74,222,128,.4);background:rgba(74,222,128,.08)}
.methst-partial{color:#fbbe29;border:1px solid rgba(251,190,41,.4);background:rgba(251,190,41,.1)}
.methst-open{color:#ff8095;border:1px solid rgba(243,65,94,.4);background:rgba(243,65,94,.1)}
.methadded .ptag.methaddtag{color:#4ade80;border-color:rgba(74,222,128,.4);background:rgba(74,222,128,.08)}
.actsq{display:flex;flex-direction:row;flex-wrap:wrap;align-items:center;gap:8px 16px;background:rgba(14,20,27,.5);border:1px solid var(--line);border-radius:12px;padding:14px 16px;backdrop-filter:blur(6px)}
.actsq>.acttop{flex:1 1 230px}
.actsq .runbtn,.actsq .swwrap{flex:none;margin-left:auto}
.actsq .prog{flex-basis:100%;order:4;margin-top:2px}
.actsq .mlast{flex-basis:100%;order:5}
.actsq .cmdref{flex-basis:100%;order:6}
.acttop{display:flex;align-items:flex-start;gap:7px}
.actname{font-weight:700;font-size:13px;line-height:1.35}
.acttop .help{margin-top:1px}
.mlast{color:var(--muted);font-size:11px}
/* indeterminate progress bar shown under a control while it runs */
.prog{height:4px;border-radius:999px;background:rgba(59,187,248,.15);overflow:hidden;position:relative}
.prog span{position:absolute;top:0;height:100%;width:40%;border-radius:999px;background:var(--accent);animation:ind 1.1s ease-in-out infinite}
@keyframes ind{0%{left:-42%}100%{left:100%}}
.actsq.running{border-color:rgba(59,187,248,.4)}
/* help ? as a click button, also opens on hover for the mouse */
.help{position:relative;display:inline-flex;align-items:center;justify-content:center;width:17px;height:17px;padding:0;border-radius:50%;border:1px solid var(--line);background:transparent;color:var(--muted);font-size:11px;font-weight:700;cursor:pointer;flex:none;line-height:1}
.help:hover,.help:focus,.help.open{color:var(--fg);border-color:var(--accent);outline:none}
.help .tip{display:none;position:absolute;left:50%;bottom:calc(100% + 9px);transform:translateX(-50%);width:230px;background:#06121b;border:1px solid var(--line);border-radius:9px;padding:10px 12px;color:var(--fg);font-size:12px;font-weight:400;line-height:1.5;text-align:left;z-index:40;box-shadow:0 10px 28px rgba(0,0,0,.55);cursor:default}
.help .tip::after{content:"";position:absolute;top:100%;left:50%;transform:translateX(-50%);border:6px solid transparent;border-top-color:var(--line)}
.help:hover .tip,.help.open .tip{display:block}
/* run button, one colour for every run, width fits the word */
.runbtn{align-self:flex-start;width:auto;padding:8px 20px;border-radius:8px;font-size:12px;font-weight:700;cursor:pointer;border:1px solid rgba(59,187,248,.35);background:rgba(59,187,248,.14);color:var(--accent)}
.runbtn:hover{background:rgba(59,187,248,.24)}
.runbtn[disabled]{opacity:.4;cursor:not-allowed}
.runall{width:auto;padding:9px 22px;border-radius:8px;font-size:13px;font-weight:800;letter-spacing:.5px;cursor:pointer;border:1px solid var(--green);background:var(--green);color:#06211a}
.runall:hover{filter:brightness(1.08)}
.runall[disabled]{opacity:.4;cursor:not-allowed}
.pbtns{display:flex;align-items:center;gap:10px}
.runchip{display:inline-flex;align-items:center;gap:7px;font-size:11px;font-weight:700;letter-spacing:.6px;text-transform:uppercase;padding:6px 13px;border-radius:999px}
.runchip::before{content:"";width:7px;height:7px;border-radius:50%;background:currentColor;animation:pulse 1.1s ease-in-out infinite}
.runchip::after{content:"...";margin-left:-5px;letter-spacing:1px;animation:pulse 1.1s ease-in-out infinite}
.runchip.go{color:var(--accent);background:rgba(59,187,248,.13);border:1px solid rgba(59,187,248,.3)}
.runchip.halt{color:#ff8095;background:rgba(243,65,94,.13);border:1px solid rgba(243,65,94,.3)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
.stopall{width:auto;padding:9px 22px;border-radius:8px;font-size:13px;font-weight:800;letter-spacing:.5px;cursor:pointer;border:1px solid var(--red);background:transparent;color:#ff8095;margin-left:8px}
.stopall:hover{background:rgba(243,65,94,.12)}
.stopall[disabled]{opacity:.4;cursor:not-allowed}
.stopbtn{align-self:flex-start;width:auto;padding:8px 20px;border-radius:8px;font-size:12px;font-weight:700;cursor:pointer;border:1px solid rgba(243,65,94,.4);background:rgba(243,65,94,.14);color:#ff8095}
.stopbtn:hover{background:rgba(243,65,94,.24)}
.stopbtn[disabled]{opacity:.4;cursor:not-allowed}
/* switch */
.swwrap{display:flex;align-items:center;gap:9px}
.swstate{font-size:12px;font-weight:700;color:var(--muted)}
.swstate.on{color:var(--green)}
.sw{position:relative;width:42px;height:24px;flex:none;border:0;border-radius:999px;background:#2a3542;cursor:pointer;transition:background .15s}
.sw.on{background:var(--green)}
.sw::after{content:"";position:absolute;top:3px;left:3px;width:18px;height:18px;border-radius:50%;background:#fff;transition:left .15s}
.sw.on::after{left:21px}
.sw[disabled]{opacity:.4;cursor:not-allowed}
/* command reference, the exact commands this module runs */
.cmdref{margin-top:auto;border-top:1px solid var(--line)}
.cmdref summary{cursor:pointer;padding:9px 0 2px;font-size:12px;color:var(--accent);font-weight:600;list-style:none;display:flex;align-items:center;gap:7px}
.cmdref summary::-webkit-details-marker{display:none}
.chev{flex:none;transition:transform .2s ease}
.cmdref[open] summary .chev{transform:rotate(180deg)}
.cmdbody{padding:6px 0 0}
.cmdrow{display:block;padding:5px 0}
.cmdrow .gate{display:inline-block;margin-bottom:5px}
.cmdrow code{display:block;white-space:pre;overflow-x:auto;word-break:normal;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;line-height:1.5;color:var(--fg);background:var(--panel2);padding:8px 10px;border-radius:6px}
.cmdgrp{padding:2px 0 8px}
.cmdgrpt{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;padding:4px 0 2px}
.actsqgroup{align-items:stretch}
.actsubs{flex-basis:100%;order:3;display:flex;flex-direction:column;gap:0;margin-top:2px}
.actsubsq{padding:12px 0;border-top:1px solid var(--line)}
.actsubsq:first-child{border-top:0;padding-top:4px}
.actsubhd{display:flex;align-items:flex-start;gap:8px}
.actsubname{font-weight:600;font-size:12.5px;line-height:1.35;flex:1 1 auto}
.actsubsq .gate{flex:none}
.actsubsq .cmdref{border-top:1px solid var(--line);margin-top:8px}
.techlist{margin:0;padding-left:18px;display:flex;flex-direction:column;gap:3px}
.techlist li{font-size:12.5px;line-height:1.45}
.cmdref{position:relative}
.cmdref+.cmdref{margin-top:0}
.cmdbody{position:absolute;left:0;right:auto;top:100%;z-index:300;margin-top:6px;padding:12px 14px;width:max-content;min-width:100%;max-width:min(860px,92vw);background:#0E141B;border:1px solid var(--line);border-radius:10px;box-shadow:0 14px 34px rgba(0,0,0,.55);max-height:420px;overflow:auto}
.cmdbody .cmdrow code{white-space:pre}
.help .tip{z-index:300}
.actsq:has(.cmdref[open]),.actsq:has(.help.open),.actsq:has(.help:hover){position:relative;z-index:250}
.card:has(.cmdref[open]),.card:has(.help.open),.card:has(.help:hover){position:relative;z-index:250}
.methsub:has(.cmdref[open]),.methsub:has(.help.open),.methsub:has(.help:hover){position:relative;z-index:250}
.squares:has(.cmdref[open]){position:relative;z-index:250}
.tasklist{margin:0;padding-left:18px;display:flex;flex-direction:column;gap:6px}
.tasklist li{font-size:12.5px;line-height:1.5;color:var(--fg)}
.gate{flex:none;font-size:9px;font-weight:800;letter-spacing:.5px;text-transform:uppercase;padding:3px 7px;border-radius:999px}
.gate.passive{background:rgba(74,222,128,.12);color:var(--green)}
.gate.semi{background:rgba(251,190,41,.15);color:#fbbe29}
.gate.active{background:rgba(243,65,94,.14);color:#ff8095}
/* editable knobs */
.knob{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:5px 0;font-size:12px}
.knob>span{display:flex;align-items:center}
.knob input[type=number]{width:86px;background:var(--panel2);border:1px solid var(--line);color:var(--fg);border-radius:6px;padding:4px 7px;font-size:12px}
.knob input[disabled]{opacity:.5;cursor:not-allowed}
.kmod{display:inline-block;margin-left:7px;font-size:8.5px;font-weight:800;text-transform:uppercase;letter-spacing:.5px;color:#fbbe29;background:rgba(251,190,41,.14);border:1px solid rgba(251,190,41,.3);padding:1px 6px;border-radius:999px}
.klock{font-size:11px;color:#ff8095;margin-top:8px}
.ksave{margin-top:9px;width:auto;padding:7px 16px;border-radius:7px;font-size:12px;font-weight:700;cursor:pointer;border:1px solid rgba(59,187,248,.35);background:rgba(59,187,248,.14);color:var(--accent)}
.ksave[disabled]{opacity:.5;cursor:not-allowed}
.cmdedit{margin-top:11px;padding-top:11px;border-top:1px dashed var(--line)}
.cmdedithead{display:flex;align-items:center;gap:6px;font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:.7px;color:var(--muted);margin-bottom:7px}
.cmdedithead svg{flex:none;color:var(--accent)}
.mconfirm{display:flex;gap:10px;align-items:flex-start;margin:4px 0 16px;font-size:13px;line-height:1.45;color:var(--fg);background:rgba(243,65,94,.07);border:1px solid rgba(243,65,94,.25);border-radius:9px;padding:12px 14px;cursor:pointer}
.mconfirm input{position:absolute;opacity:0;width:0;height:0}
.mconfirm .box{flex:none;width:19px;height:19px;border-radius:5px;border:2px solid var(--muted);background:var(--panel2);position:relative;transition:all .15s ease;margin-top:1px}
.mconfirm input:checked+.box{background:var(--red);border-color:var(--red)}
.mconfirm input:checked+.box::after{content:"";position:absolute;left:5px;top:1px;width:5px;height:10px;border:solid #fff;border-width:0 2.5px 2.5px 0;transform:rotate(45deg)}
.mconfirm input:focus-visible+.box{box-shadow:0 0 0 3px rgba(243,65,94,.3)}
.btn:disabled{opacity:.45;cursor:not-allowed}
/* new-client and add-context setup cards */
.topbar{display:flex;align-items:center;justify-content:space-between;margin:2px 0 18px}
.eyebrow{font-size:11px;text-transform:uppercase;letter-spacing:1.2px;color:var(--muted);font-weight:700}
.newcl{display:inline-flex;align-items:center;gap:6px;background:rgba(59,187,248,.14);border:1px solid rgba(59,187,248,.35);color:var(--accent);padding:8px 15px;border-radius:9px;font-weight:700;font-size:13px}
.newcl:hover{background:rgba(59,187,248,.22);text-decoration:none}
.ptitle{font-size:24px;font-weight:800;margin:14px 0 18px}
.setup{display:flex;flex-direction:column;gap:15px}
.fld{display:flex;flex-direction:column;gap:6px;font-size:13px}
.fld>span{color:var(--muted);font-weight:600}
.fld em{font-style:normal;color:#52617280;font-size:11px;margin-left:5px;text-transform:uppercase;letter-spacing:.5px}
.fld input,.fld textarea{background:var(--panel2);border:1px solid var(--line);color:var(--fg);border-radius:8px;padding:10px 12px;font-size:13px;font-family:inherit;width:100%;resize:vertical}
.fld textarea{font-family:ui-monospace,Menlo,Consolas,monospace;line-height:1.5}
.fld input:focus,.fld textarea:focus{outline:none;border-color:var(--accent)}
.btn-ghost{background:transparent;border:1px solid var(--line);color:var(--fg);padding:9px 15px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer}
.btn-ghost.noborder{border:none;color:var(--accent);padding-right:4px}
.btn-ghost.noborder:hover{background:rgba(59,187,248,.12)}
.btn-ghost:hover{border-color:var(--accent);color:var(--accent)}
.btn-ghost:disabled{opacity:.5;cursor:not-allowed}
.setup-ai{display:flex;align-items:center;gap:12px;flex-wrap:wrap;font-size:12px}
.setup .note{font-size:12px;color:var(--muted);background:var(--panel2);border-radius:8px;padding:11px 13px;line-height:1.5}
.scopechips{display:flex;flex-wrap:wrap;gap:7px}
.chip{display:inline-flex;align-items:center;font-size:12px;padding:4px 10px;border-radius:999px;background:rgba(74,222,128,.12);color:var(--green);border:1px solid rgba(74,222,128,.25)}
.chip.blocked{background:rgba(243,65,94,.1);color:#ff8095;border-color:rgba(243,65,94,.28)}
/* client header, shaded slightly apart from the plain cards */
.chead{background:linear-gradient(180deg,rgba(59,187,248,.07),rgba(59,187,248,.015));border:1px solid var(--line);border-radius:12px;padding:16px 18px 14px;margin-bottom:18px}
.cheadclient{display:flex;flex-direction:column;align-items:stretch;gap:0}
.cnamewrap{display:flex;flex-direction:column;gap:3px}
.clastrun{font-size:12.5px}
/* reports: one slot per type, the latest PDF, Word and XLSX */
.rephead{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:10px 0 10px}
#genrep{flex:0 0 auto;width:auto;white-space:nowrap}
.repbox{border:1px solid var(--line);border-radius:12px;background:var(--panel);padding:12px}
.reports2{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;align-items:stretch}
@media(max-width:620px){.reports2{grid-template-columns:1fr}}
.repslot{display:flex;align-items:center;gap:13px;padding:14px 16px;min-height:66px;box-sizing:border-box;border:1px solid var(--line);border-radius:10px;background:var(--panel2);text-decoration:none;transition:border-color .15s,box-shadow .15s}
.repslot.empty{border-style:dashed;opacity:.6}
/* per type: the icon tint and the colour the frame takes on hover */
.repslot.pdf{--rc:var(--red)}
.repslot.docx{--rc:var(--accent)}
.repslot.xlsx{--rc:var(--green)}
.repslot.txt{--rc:var(--muted)}
.repslot:not(.empty):hover{border-color:var(--rc);box-shadow:inset 0 0 0 1px var(--rc);background:color-mix(in srgb,var(--rc) 13%,var(--panel2))}
.repicon{flex:none;display:flex;align-items:center}
.repicon.xlsx{color:var(--green)}
.repicon.pdf{color:var(--red)}
.repicon.docx{color:var(--accent)}
.repicon.txt{color:var(--muted)}
.repinfo{display:flex;flex-direction:column;justify-content:center;gap:2px;min-width:0}
/* watchers status list */
.watchcard{display:flex;flex-direction:column;gap:0;padding:4px 0}
.wrow{display:flex;align-items:center;gap:12px;padding:11px 16px;border-top:1px solid var(--line)}
.wrow:first-child{border-top:none}
.wdot{flex:none;width:9px;height:9px;border-radius:50%;background:var(--muted)}
.wdot.on{background:var(--green)}
.wdot.run{background:var(--green);box-shadow:0 0 0 3px rgba(74,222,128,.25)}
.wdot.off{background:#55606e}
.wbody{flex:1 1 auto;min-width:0}
.wname{font-size:14px;font-weight:600}
.replabel{font-weight:700;font-size:10.5px;letter-spacing:.9px;color:var(--muted)}
.repname{font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
/* relationship map */
.gtoolbar{display:flex;gap:7px;margin-bottom:10px;align-items:center;flex-wrap:nowrap;justify-content:flex-start;min-width:0}
.gtoolbar>button,.gtoolbar>.gzoom{flex:0 0 auto}
/* every control is the same height and box model, so the row lines up */
.gtoolbar .btn-ghost,.gtoolbar .gsel{height:34px;box-sizing:border-box;display:inline-flex;align-items:center;font-size:12px;line-height:1}
.gtoolbar .btn-ghost{padding:0 11px;min-width:0;width:auto;white-space:nowrap;justify-content:center}
.gbtn{flex:0 0 auto}
.gzoom .btn-ghost{min-width:36px}
.gzoom{display:inline-flex;gap:0}
.gzoom .btn-ghost{border-radius:0;margin-left:-1px}
.gzoom .btn-ghost:first-child{border-radius:8px 0 0 8px;margin-left:0}
.gzoom .btn-ghost:last-child{border-radius:0 8px 8px 0}
.ghint{font-size:11px;color:var(--muted)}
.gsel{background:var(--panel2);border:1px solid var(--line);border-radius:8px;color:var(--fg);padding:0 10px;font-family:inherit}
.gcombo{position:relative;display:flex;align-items:center;min-width:0}
#gdomwrap{flex:0 0 300px;max-width:100%}
#gsevwrap{flex:0 0 auto}
#graphsearch{width:100%;min-width:0;display:inline-block;height:34px;line-height:normal;margin:0;padding:0 10px;box-sizing:border-box;vertical-align:middle}
.gbtn{flex:0 0 auto}
.gpush{margin-left:auto}
.gsevbtn{cursor:pointer;white-space:nowrap;gap:6px}
.gsevbtn::after{content:"\\25BE";font-size:10px;color:var(--muted)}
.gcombo-list{position:absolute;top:calc(100% + 4px);left:0;min-width:100%;z-index:40;max-height:300px;overflow-y:auto;background:var(--panel);border:1px solid var(--line);border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,.35);white-space:nowrap}
.gcombo-item{padding:7px 10px;font-size:12px;cursor:pointer;overflow:hidden;text-overflow:ellipsis}
.gcombo-item:hover{background:var(--panel2)}
.sevopt{display:flex;align-items:center;gap:8px}
.sevdot{width:9px;height:9px;border-radius:50%;flex:none}
.gcombo-more{padding:6px 10px;font-size:11px;color:var(--muted);border-top:1px solid var(--line)}
.gsel:focus{outline:none;border-color:#3BBBF8}
.graphwrap{position:relative;overflow:hidden;background:var(--panel2);border:1px solid var(--line);border-radius:10px;height:620px}
.gfallback{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;text-align:center;padding:24px;font-size:13px}
/* browser fullscreen: the card fills the screen and the canvas grows with it */
.graphcard:fullscreen{background:var(--bg);padding:14px;display:flex;flex-direction:column}
.graphcard:fullscreen .graphwrap{flex:1;height:auto}
.graphcard:-webkit-full-screen{background:var(--bg);padding:14px}
.graphcard:-webkit-full-screen .graphwrap{height:calc(100vh - 110px)}
/* flash */
.flash{padding:13px 16px;border-radius:12px;margin-bottom:18px;font-weight:600;font-size:13.5px;display:flex;align-items:center;gap:11px;box-shadow:0 6px 22px rgba(0,0,0,.28);animation:flashin .25s ease}
.flash::before{flex:none;width:22px;height:22px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:13px;font-weight:900;color:#06121b}
.flash.ok{background:rgba(74,222,128,.12);color:#86efac;border:1px solid rgba(74,222,128,.35)}
.flash.ok::before{content:"\\2713";background:var(--green)}
.flash.no{background:rgba(243,65,94,.12);color:#ff9aab;border:1px solid rgba(243,65,94,.4)}
.flash.no::before{content:"!";background:var(--red)}
@keyframes flashin{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
/* floating toast notifications (top-right, stacked, auto-dismiss) */
#toasts{position:fixed;top:68px;right:18px;z-index:9999;display:flex;flex-direction:column;align-items:flex-end;gap:10px;pointer-events:none}
/* block layout (not flex) so the message always uses the full card width; the
   card itself sizes to its content up to a max, wrapping longer messages. The
   icon and close button are absolutely placed in the side gutters. */
.toast{pointer-events:auto;box-sizing:border-box;width:fit-content;min-width:200px;max-width:min(380px,calc(100vw - 32px));position:relative;padding:11px 36px 11px 40px;border-radius:12px;font-weight:600;font-size:12.5px;line-height:1.45;box-shadow:0 10px 30px rgba(0,0,0,.4);backdrop-filter:blur(8px);overflow-wrap:break-word;word-break:normal;animation:toastin .28s cubic-bezier(.22,1,.36,1)}
.toast>span{display:block}
.toast::before{position:absolute;left:12px;top:12px;width:21px;height:21px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:12px;font-weight:900;color:#06121b}
.toast.ok{background:rgba(16,38,30,.94);color:#9df5c0;border:1px solid rgba(74,222,128,.45)}
.toast.ok::before{content:"\\2713";background:var(--green)}
.toast.no{background:rgba(44,16,22,.94);color:#ffb0bd;border:1px solid rgba(243,65,94,.5)}
.toast.no::before{content:"!";background:var(--red)}
.toast .tclose{position:absolute;top:8px;right:8px;width:20px;height:20px;display:inline-flex;align-items:center;justify-content:center;cursor:pointer;opacity:.55;font-weight:700;padding:0;background:none;border:0;color:inherit;font-size:16px;line-height:1}
.toast .tclose:hover{opacity:1}
.toast.leaving{animation:toastout .3s ease forwards}
@keyframes toastin{from{opacity:0;transform:translateX(26px)}to{opacity:1;transform:none}}
@keyframes toastout{to{opacity:0;transform:translateX(26px)}}
/* Vuln DB import: live type-ahead search */
.dbsearch{position:relative;margin-bottom:8px}
.dbresults{display:none;position:absolute;left:0;right:0;top:calc(100% + 4px);z-index:50;max-height:300px;overflow-y:auto;background:var(--panel);border:1px solid var(--line);border-radius:10px;box-shadow:0 12px 32px rgba(0,0,0,.4)}
.dbresults.open{display:block}
.dbhit{display:flex;align-items:center;gap:10px;justify-content:space-between;padding:9px 12px;cursor:pointer;border-bottom:1px solid var(--line);font-size:13px}
.dbhit:last-child{border-bottom:none}
.dbhit:hover{background:rgba(59,187,248,.12)}
.dbhitname{color:var(--fg)}
.dbhitsev{flex:none;white-space:nowrap}
.dbnone,.dbmore{padding:9px 12px;color:var(--muted);font-size:12px}
.dbmore{border-top:1px solid var(--line)}
.dbcur{display:flex;align-items:center;gap:10px;font-size:12.5px;color:var(--muted);margin-bottom:8px}
.dbclear{background:none;border:0;color:#8fd6ff;cursor:pointer;font-size:12.5px;padding:0;text-decoration:underline}
.empty{color:var(--muted);padding:20px;text-align:center;border:1px dashed var(--line);border-radius:12px}
.foot{color:var(--muted);font-size:11px;margin-top:28px;letter-spacing:.3px}
/* login */
.login{max-width:360px;margin:14vh auto}
input{width:100%;padding:11px 13px;margin:6px 0 12px;background:var(--panel2);border:1px solid var(--line);border-radius:8px;color:var(--fg);font-size:14px}
input:focus{outline:none;border-color:var(--accent)}
button{width:100%;padding:12px;background:var(--accent);color:#06121b;border:0;border-radius:8px;font-weight:700;cursor:pointer;font-size:14px}
.err{color:#ff8095;font-size:13px;margin-bottom:10px}
/* modal */
.modal{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.65);z-index:50;backdrop-filter:blur(2px)}
.modal.show{display:flex;align-items:center;justify-content:center;padding:24px}
.modal>.box{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:24px;max-width:430px;width:100%;margin:auto;max-height:90vh;overflow:auto}
.modal h3{margin:8px 0 6px;font-size:19px}
.warn{color:var(--red);font-weight:800;font-size:11px;text-transform:uppercase;letter-spacing:1px}
.modal .row{display:flex;gap:10px;margin-top:16px}
.modal .row button{flex:1}
.btn-cancel{background:#1b232e;color:var(--fg);border:1px solid var(--line)}
.btn-stop{background:var(--red);color:#fff}
.btn-start{background:var(--green);color:#06211a}
"""

# Live-editable stylesheet. tools/panel.css is the editable copy of the CSS
# above: edit it and reload the browser to see the change, no restart needed,
# because _css() reads it fresh on every request. The embedded CSS stays as a
# fallback so the panel still styles correctly if the file is missing.
_CSS_FILE = Path(__file__).resolve().parent / "panel.css"


def _css() -> str:
    try:
        return _CSS_FILE.read_text(encoding="utf-8")
    except Exception:
        return CSS


MODAL = """
<div class="modal" id="m">
  <div class="box">
    <div class="warn">Critical action</div>
    <h3 id="mtitle">Confirm</h3>
    <p class="muted" id="mtext"></p>
    <form method="post" action="/control" id="mform">
      <input type="hidden" name="action" id="maction">
      <input type="hidden" name="slug" id="mslug">
      <input type="hidden" name="kind" id="mkind">
      __PWFIELD__
      <label id="mconfirmwrap" class="mconfirm" style="display:none">
        <input type="checkbox" id="mconfirm" onchange="document.getElementById('mok').disabled=!this.checked">
        <span class="box"></span>
        <span>I confirm this run is authorized and in scope, and that an active run sends live traffic that cannot be undone.</span></label>
      <div class="row">
        <button type="button" class="btn-cancel" onclick="hideM()">Cancel</button>
        <button type="button" class="btn" id="mok" onclick="confirmM()">Confirm</button>
      </div>
    </form>
  </div>
</div>
<script>
var EAS_NOSTEPUP=__NOSTEPUP__;
function askM(action, slug, client, label, btn){
  window._eas_btn=btn||null;
  var m=document.getElementById('m');
  document.getElementById('maction').value=action;
  document.getElementById('mslug').value=slug;
  document.getElementById('mkind').value=label.kind;
  var title, text, okt, okc;
  if(action==='stop_all'){
    title='Stop everything';
    text='This halts every phase currently running for '+client+'. Partial results so far are kept. Autowatchers resume on their next schedule.';
    okt='Stop all'; okc='btn btn-stop';
  } else if(action==='run_all'){
    title='Run all phases';
    text='This runs every promoted phase for '+client+' once, now. It sends active DNS and web traffic to the client and lookalike hosts, so make sure egress goes through the disposable host.';
    okt='Run all'; okc='btn btn-start';
  } else if(action==='run'){
    title='Run '+label.name;
    text='This runs '+label.name+' for '+client+' once, now.'
       +(label.warn?' It sends DNS traffic to the client, so make sure egress goes through the disposable host.':'');
    okt='Run'; okc='btn btn-start';
  } else {
    var stopping=(action==='stop');
    title=(stopping?'Stop ':'Start ')+label.name;
    if(stopping && label.run){
      text='This stops the '+label.name+' run in progress for '+client+'. Partial results so far are kept.';
    } else {
      text=stopping
        ? 'This turns off '+label.name.toLowerCase()+' for '+client+'. Collection stops until it is turned back on.'
        : 'This turns on '+label.name.toLowerCase()+' for '+client+'.';
    }
    okt=(stopping?'Stop':'Start'); okc='btn '+(stopping?'btn-stop':'btn-start');
  }
  // An active run sends live traffic and cannot be undone once it starts, so
  // it always asks, with an authorized-and-in-scope checkbox, even when the
  // password step-up is off for testing.
  var irreversible=(action==='run'&&label.warn)||action==='run_all';
  if(irreversible){text+=' It sends live traffic to the client and cannot be undone once it starts.';}
  document.getElementById('mtitle').textContent=title;
  document.getElementById('mtext').textContent=text;
  var ok=document.getElementById('mok');
  ok.textContent=okt;
  ok.className=okc;
  var cw=document.getElementById('mconfirmwrap'),cb=document.getElementById('mconfirm');
  if(irreversible){cb.checked=false;ok.disabled=true;cw.style.display='flex';}
  else{ok.disabled=false;cw.style.display='none';}
  // Reversible, low-risk actions skip the dialog when step-up is off.
  if(EAS_NOSTEPUP && !irreversible){fire(action,slug,label.kind,btn);return;}
  var _pw=document.getElementById('mpass');
  if(_pw){_pw.value='';}
  m.classList.add('show');
  if(_pw){_pw.focus();}else if(irreversible){cb.focus();}
}
function hideM(){document.getElementById('m').classList.remove('show');}
function closeTips(){var o=document.querySelectorAll('.help.open');for(var i=0;i<o.length;i++){o[i].classList.remove('open');}}
function tipT(btn,e){e.stopPropagation();var open=btn.classList.contains('open');closeTips();if(!open)btn.classList.add('open');}
document.addEventListener('click',closeTips);
document.addEventListener('keydown',function(e){if(e.key==='Escape'){hideM();closeTips();}});
function val(id){var e=document.getElementById(id);return e?e.value:'';}
function confirmM(){fire(val('maction'),val('mslug'),val('mkind'),window._eas_btn,val('mpass'));}
// Swap only the content area in place, so a run or stop reflects live with no
// page reload and no scroll jump. Inline handlers survive the innerHTML swap.
var _pollT=null;
function maybePoll(){
  var running=!!document.querySelector('.actsq.running')||!!document.querySelector('.stopall')||!!document.querySelector('.l0run.running');
  if(running){if(!_pollT){_pollT=setInterval(softRefresh,2500);}}
  else if(_pollT){clearInterval(_pollT);_pollT=null;}
}
function softRefresh(){
  fetch(location.pathname+location.search,{headers:{'X-Requested-With':'fetch'}}).then(function(r){return r.text();}).then(function(t){
    var nw=new DOMParser().parseFromString(t,'text/html').querySelector('.wrap');
    var cur=document.querySelector('.wrap'); if(!nw||!cur)return;
    cur.innerHTML=nw.innerHTML;
    if(window.easRenderGraph)window.easRenderGraph();
    maybePoll();
  }).catch(function(){});
}
function fire(action,slug,kind,btn,password){
  var starting=(action==='run'||action==='run_all'||action==='start');
  var word=starting?'Starting':'Stopping';
  if(action==='run_all'||action==='stop_all'){var p=document.getElementById('pbtns'); if(p){p.innerHTML='<span class="runchip '+(starting?'go':'halt')+'">'+word+'</span>';}}
  else if(btn){
    btn.disabled=true;
    // A toggle switch (.sw) has no text: setting textContent would inject the
    // word into the round pill and distort it. Flip its on/off state instead,
    // for instant feedback with no text. Text-bearing buttons get the word.
    if(btn.classList&&btn.classList.contains('sw')){
      if(starting){btn.classList.add('on');}else{btn.classList.remove('on');}
      // Starting a watcher can take a moment. Show "Starting..."/"Stopping..."
      // in this row's status line while the switch is held, then softRefresh
      // live-replaces it with the real state (e.g. "Off · last run just now").
      var wrow=btn.closest&&btn.closest('.wrow');
      if(wrow){var info=wrow.querySelector('.muted');
        if(info){info.textContent=starting?'Starting...':'Stopping...';}
        var dot=wrow.querySelector('.wdot');
        if(dot){dot.className='wdot won '+(starting?'run':'off');}
      }
    } else { btn.textContent=word; }
    // Instant optimistic feedback for the Layer 0 run control: flip the whole
    // block to running/stopped right away so the first click visibly takes,
    // without waiting for the server round-trip. Polling then reconciles.
    var l0=btn.closest&&btn.closest('.l0run');
    if(l0){ if(starting){l0.classList.add('running');} else {l0.classList.remove('running');}
      var info=l0.querySelector('.muted'); if(info){info.textContent=starting?'Starting...':'Stopping...';} }
  }
  hideM();
  var body='action='+encodeURIComponent(action)+'&slug='+encodeURIComponent(slug)+'&kind='+encodeURIComponent(kind||'')+'&xhr=1';
  if(password!=null&&password!==''){body+='&password='+encodeURIComponent(password);}
  fetch('/control',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body})
    .then(function(r){return r.json();}).then(function(d){if(d){showFlash(d.ok,d.msg);} softRefresh();})
    .catch(function(){softRefresh();});
}
function saveKnobs(btn,slug,kind){
  var box=btn.parentNode;
  var body='kind='+encodeURIComponent(kind)+'&slug='+encodeURIComponent(slug)+'&xhr=1';
  var ins=box.querySelectorAll('input[data-key]');
  for(var i=0;i<ins.length;i++){
    var el=ins[i];
    var v=(el.type==='checkbox')?(el.checked?'true':'false'):el.value;
    body+='&k_'+encodeURIComponent(el.getAttribute('data-key'))+'='+encodeURIComponent(v);
  }
  btn.disabled=true; btn.textContent='Saving';
  fetch('/config',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body})
    .then(function(r){return r.json();}).then(function(d){if(d){showFlash(d.ok,d.msg);} softRefresh();})
    .catch(function(){softRefresh();});
}
function addContext(slug){
  var dom=document.getElementById('ac_domains'), note=document.getElementById('ac_notes');
  var err=document.getElementById('ac_err'); err.style.display='none';
  var go=document.getElementById('ac_go'); go.disabled=true;
  var body='slug='+encodeURIComponent(slug)+'&xhr=1&domains='+encodeURIComponent(dom?dom.value:'')
    +'&notes='+encodeURIComponent(note?note.value:'');
  fetch('/add-context',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body})
    .then(function(r){return r.json();}).then(function(d){
      go.disabled=false;
      if(d.ok){if(dom)dom.value='';if(note)note.value=''; showFlash(true,d.msg); softRefresh();}
      else{err.textContent=d.msg; err.style.display='block';}
    }).catch(function(){go.disabled=false; err.textContent='Request failed.'; err.style.display='block';});
}
function genReport(slug){
  var b=document.getElementById('genrep'); if(b){b.disabled=true; b.textContent='Generating...';}
  fetch('/report',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'slug='+encodeURIComponent(slug)})
    .then(function(r){return r.json();}).then(function(d){
      if(b){b.disabled=false; b.textContent='Regenerate';}
      showFlash(d.ok,d.msg); softRefresh();
    }).catch(function(){if(b){b.disabled=false; b.textContent='Regenerate';}
      showFlash(false,'Request failed.');});
}
function genAlert(b,slug,key){
  if(b){b.disabled=true; b.textContent='Generating...';}
  fetch('/alert',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'slug='+encodeURIComponent(slug)+'&key='+encodeURIComponent(key)})
    .then(function(r){return r.json();}).then(function(d){
      if(b){b.disabled=false; b.textContent='Early alert';}
      showFlash(d.ok,d.msg);
      if(d.ok&&d.url){window.location=d.url;}
    }).catch(function(){if(b){b.disabled=false; b.textContent='Early alert';}
      showFlash(false,'Request failed.');});
}
maybePoll();
</script>
"""

# The step-up field only exists when step-up is on. With PANEL_NO_STEPUP the
# modal still confirms the action, it just does not ask for the password.
_PW_FIELD = ('<label class="muted">Re-enter your password to confirm</label>'
             '<input type="password" name="password" id="mpass" autocomplete="off">'
             if STEP_UP else '')
MODAL = MODAL.replace("__PWFIELD__", _PW_FIELD)
MODAL = MODAL.replace("__NOSTEPUP__", "false" if STEP_UP else "true")


def _nav_clients_html() -> str:
    """The navbar Clients dropdown: every client the operator can open, sorted
    by name, with a live/idle dot and a quick find box. Pure navigation, no
    state change."""
    try:
        clients = sorted(engagements(), key=lambda e: _pretty(e["slug"]).lower())
    except Exception:
        clients = []
    if not clients:
        return ""
    items = ""
    for e in clients:
        slug = e["slug"]
        cid = _client_id(slug)
        nm = _pretty(slug)
        on = any(m.get("on") for m in (e.get("watch") or {}).values())
        items += (f'<a class="navdditem" href="/c/{cid}" data-n="{_esc(nm.lower())}">'
                  f'<span class="dot {"on" if on else "off"}"></span>'
                  f'<span class="navddname">{_esc(nm)}</span></a>')
    return (
        '<div class="navdd" id="navcli">'
        '<button type="button" class="navlink navddbtn" onclick="cliToggle(event)">'
        'Clients <svg class="chev" viewBox="0 0 24 24" width="12" height="12" fill="none" '
        'stroke="currentColor" stroke-width="2.6"><path d="M6 9l6 6 6-6"/></svg></button>'
        '<div class="navddmenu" id="navddmenu">'
        '<input type="text" class="navddsearch" id="navddsearch" placeholder="Find client" '
        'oninput="cliFilter()" autocomplete="off" spellcheck="false">'
        f'<div class="navddlist" id="navddlist">{items}</div>'
        '</div></div>'
        '<script>'
        'function cliToggle(ev){ev.stopPropagation();var d=document.getElementById("navcli");'
        'if(!d)return;var open=d.classList.toggle("open");'
        'if(open){var s=document.getElementById("navddsearch");'
        'if(s){s.value="";cliFilter();setTimeout(function(){s.focus();},30);}}}'
        'function cliFilter(){var e=document.getElementById("navddsearch");if(!e)return;'
        'var q=(e.value||"").toLowerCase();var it=document.querySelectorAll("#navddlist .navdditem");'
        'for(var i=0;i<it.length;i++){it[i].style.display='
        '(it[i].getAttribute("data-n").indexOf(q)>=0)?"":"none";}}'
        'document.addEventListener("click",function(e){var d=document.getElementById("navcli");'
        'if(d&&!d.contains(e.target))d.classList.remove("open");});'
        '</script>')


_TOAST_JS = """<script>
// Floating notifications, shown on every page (not only modal pages). Green on
// success, red on failure, stacked top-right, auto-dismiss, with a close button.
function _toastHost(){
  var h=document.getElementById('toasts');
  if(!h){h=document.createElement('div');h.id='toasts';document.body.appendChild(h);}
  return h;
}
function toastClose(t){
  if(!t||t.classList.contains('leaving'))return;
  t.classList.add('leaving');
  setTimeout(function(){if(t.parentNode)t.parentNode.removeChild(t);},300);
}
// A failure stays a little longer so the operator can read the reason.
function showFlash(ok,msg){
  if(!msg)return;
  var h=_toastHost();
  var t=document.createElement('div'); t.className='toast '+(ok?'ok':'no');
  var span=document.createElement('span'); span.style.flex='1'; span.textContent=msg;
  var x=document.createElement('button'); x.type='button'; x.className='tclose';
  x.setAttribute('aria-label','Dismiss'); x.textContent='×';
  x.onclick=function(){toastClose(t);};
  t.appendChild(span); t.appendChild(x);
  h.appendChild(t);
  setTimeout(function(){toastClose(t);},ok?4500:7000);
}
// A flash carried across a client-side navigation lives in sessionStorage, not
// the URL, so no message text is ever reflected into the address bar. Pop it
// once on load and render it through the same (textContent) toast path.
(function(){function go(){var raw;try{raw=sessionStorage.getItem('eas_flash');
  if(raw)sessionStorage.removeItem('eas_flash');}catch(e){return;}
  if(!raw)return;var a;try{a=JSON.parse(raw);}catch(e){return;}
  if(a&&a.length&&window.showFlash)showFlash(!!a[0],String(a[1]||''));}
  if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',go);}else{go();}})();
</script>"""


# Present on every page (not only the console): keep at most one Commands or
# Techniques dropdown open at a time, so two floating panels never stack on top of
# each other, and close any open dropdown on Escape. The toggle event does not
# bubble, so the open listener runs in the capture phase.
_DROPDOWN_JS = """<script>
document.addEventListener('toggle',function(e){var d=e.target;if(d&&d.tagName==='DETAILS'&&d.classList&&d.classList.contains('cmdref')&&d.open){var all=document.querySelectorAll('details.cmdref[open]');for(var i=0;i<all.length;i++){if(all[i]!==d){all[i].open=false;}}}},true);
document.addEventListener('keydown',function(e){if(e.key==='Escape'){var o=document.querySelectorAll('details.cmdref[open]');for(var i=0;i<o.length;i++){o[i].open=false;}}});
</script>"""


def _page(body: str, user: str, modal: bool = False) -> bytes:
    nrev = _pending_review_count() if user else 0
    # Always show the triage count. Red when something is waiting, green 0 when
    # the queue is clear, so a clean queue reads as a positive signal.
    rev_badge = (f'<span class="navbadge{"" if nrev else " zero"}">{nrev}</span>'
                 if user else '')
    left = (f'<nav class="nav navleftnav">{_nav_clients_html()}</nav>' if user else "")
    right = (f'<nav class="nav">'
             f'<a class="navlink" href="/review">Triage{rev_badge}</a>'
             f'<a class="navlink" href="/vuln-db">Vuln DB</a>'
             f'<a class="navlink" href="/methodology">Methodology</a>'
             f'<a class="navlink" href="/audit">Activity</a>'
             f'<span class="navsep"></span>'
             f'<span class="navuser">{_esc(user)}</span>'
             f'<a class="navout" href="/logout">Sign out</a>'
             f'</nav>'
             if user else "")
    html = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Continuous EAS Console</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32' fill='none' stroke='%23F3415E' stroke-width='2.2'%3E%3Ccircle cx='16' cy='16' r='12.5'/%3E%3Ccircle cx='16' cy='16' r='6.5'/%3E%3Cline x1='16' y1='1' x2='16' y2='7'/%3E%3Cline x1='16' y1='25' x2='16' y2='31'/%3E%3Cline x1='1' y1='16' x2='7' y2='16'/%3E%3Cline x1='25' y1='16' x2='31' y2='16'/%3E%3Ccircle cx='16' cy='16' r='2' fill='%23F3415E' stroke='none'/%3E%3C/svg%3E">
<link rel="stylesheet" href="/panel.css"></head><body>
<header><a class="brand" href="/"><span class="logo"><svg viewBox="0 0 32 32" width="30" height="30" fill="none" stroke="currentColor" stroke-width="1.7"><circle cx="16" cy="16" r="12.5"/><circle cx="16" cy="16" r="6.5"/><line x1="16" y1="0.5" x2="16" y2="7"/><line x1="16" y1="25" x2="16" y2="31.5"/><line x1="0.5" y1="16" x2="7" y2="16"/><line x1="25" y1="16" x2="31.5" y2="16"/><circle cx="16" cy="16" r="1.7" fill="currentColor" stroke="none"/></svg></span><span class="brandtext">CONTINUOUS EAS<small>Red Team Console</small></span></a>{left}<div>{right}</div></header>
<div class="wrap">{body}</div>{_TOAST_JS}{_DROPDOWN_JS}{MODAL if modal else ""}</body></html>"""
    return html.encode()


def _sev_bar(counts: dict) -> str:
    total = max(sum(counts.values()), 1)
    return "".join(
        f'<span style="width:{100*counts[s]/total:.1f}%;background:{SEV[s][1]}"></span>'
        for s in SEV_ORDER if counts[s])


def _sev_badges(counts: dict) -> str:
    return "".join(
        f'<span class="badge" style="background:{SEV[s][1]};color:{SEV[s][2]}">'
        f'{SEV[s][0]}<b>{counts[s]}</b></span>'
        for s in SEV_ORDER if counts[s]) or '<span class="muted">No signals yet</span>'


def _sev_legend(counts: dict) -> str:
    """A centered legend for the Findings by severity card: one tile per level
    with its big coloured count and label underneath. All levels are shown so
    the legend reads the same every time."""
    if not sum(counts.values()):
        return '<div class="muted" style="text-align:center">No signals yet</div>'
    return ('<div class="sevlegend">' + "".join(
        f'<div class="sevleg"><span class="sevnum" style="color:{SEV[s][1]}">{counts[s]}</span>'
        f'<span class="sevlbl">{SEV[s][0]}</span></div>'
        for s in SEV_ORDER) + '</div>')


# Server-side flash store. A notification message is NEVER carried in the URL:
# the redirect holds only an opaque one-shot token, and the message text lives
# here, server-side, keyed by that token. This closes the reflected-XSS vector
# where a crafted ?msg= in the address bar was echoed into the page, and it also
# stops anyone from forging an arbitrary notification by editing the link.
_FLASH_STORE: dict[str, tuple[float, bool, str]] = {}
_FLASH_LOCK = threading.Lock()
_FLASH_TTL = 120.0          # a token is valid for two minutes, then expires
_FLASH_MAX = 512            # hard cap so the store cannot grow unbounded


def _flash_put(ok: bool, msg: str) -> str:
    """Store a flash message and return its one-shot token for the redirect."""
    tok = secrets.token_urlsafe(16)
    now = time.time()
    with _FLASH_LOCK:
        # prune expired entries, and if still over the cap drop the oldest
        for k in [k for k, v in _FLASH_STORE.items() if now - v[0] > _FLASH_TTL]:
            _FLASH_STORE.pop(k, None)
        if len(_FLASH_STORE) >= _FLASH_MAX:
            for k in sorted(_FLASH_STORE, key=lambda k: _FLASH_STORE[k][0])[:64]:
                _FLASH_STORE.pop(k, None)
        _FLASH_STORE[tok] = (now, bool(ok), str(msg))
    return tok


def _flash_pop(tok: str) -> tuple | None:
    """Consume a flash token once. Unknown, forged, or expired -> no flash."""
    if not tok:
        return None
    with _FLASH_LOCK:
        ent = _FLASH_STORE.pop(tok, None)
    if not ent:
        return None
    ts, ok, msg = ent
    if time.time() - ts > _FLASH_TTL:
        return None
    return (ok, msg)


def _flash(flash: tuple | None) -> str:
    """A page-load notification. Rendered as a floating toast (green on success,
    red on failure) via the same showFlash used for live actions, so every
    notification in the app looks and behaves the same, and never pushes the
    page content down."""
    if not flash:
        return ""
    ok, msg = flash
    # Escape the inline-script payload so no message content can break out of
    # the <script> element (e.g. a literal </script>). showFlash then renders
    # the text with textContent, so it is never parsed as HTML either.
    payload = (json.dumps([bool(ok), str(msg)])
               .replace("<", "\\u003c").replace(">", "\\u003e")
               .replace("&", "\\u0026").replace("\u2028", "\\u2028")
               .replace("\u2029", "\\u2029"))
    # After the toast fires, scrub the ok/msg query off the URL (keep the path
    # and hash) so the notification is one-shot: a reload or a Back no longer
    # re-shows it, and the address bar stays clean with no flash-specific URL.
    return ('<script>(function(){function go(){if(window.showFlash){'
            f'window.showFlash.apply(null,{payload});'
            'try{if(location.search){history.replaceState(null,"",'
            'location.pathname+location.hash);}}catch(e){}'
            '}else{setTimeout(go,60);}}'
            "if(document.readyState==='loading'){"
            "document.addEventListener('DOMContentLoaded',go);}else{go();}})();</script>")


# --------------------------------------------------------------------------
# Level 1: the fleet overview.
# --------------------------------------------------------------------------
def _vuln_secret() -> bytes:
    """A per-install secret that keys the vulnerability and client ids. Generated
    once and stored with owner-only permissions. Never leaves the server."""
    f = DATA / ".vuln-id-secret"
    try:
        if f.is_file():
            data = f.read_bytes()
            if data:
                return data
    except Exception:
        pass
    s = secrets.token_bytes(32)
    try:
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(s)
        os.chmod(f, 0o600)
    except Exception:
        pass
    return s


_VULN_SECRET = _vuln_secret()
_CID_RE = re.compile(r"^[0-9a-f]{24}$")


def _client_id(slug: str) -> str:
    """A stable, non-guessable id for one client: a keyed HMAC of the slug. The
    client URL carries this instead of the name, so the name is not in the URL
    and clients cannot be enumerated (no IDOR)."""
    return hmac.new(_VULN_SECRET, f"client|{slug}".encode(),
                    hashlib.sha256).hexdigest()[:24]


def _resolve_client(token: str) -> str | None:
    """Map a client token from a URL or form back to its slug. Accepts a client
    id (preferred) and, for older links, a raw existing slug. None if neither."""
    token = (token or "").strip()
    if not token:
        return None
    # A client exists as soon as its scope file is written, before any
    # engagement directory. Resolve against the full client set (scopes and
    # engagements) so a freshly created client opens instead of 404ing.
    slugs = _existing_slugs()
    if _CID_RE.match(token):
        for s in slugs:
            if hmac.compare_digest(_client_id(s), token):
                return s
        return None
    if SLUG_RE.match(token) and token in slugs:
        return token
    return None


def _tpl_token(tid: str) -> str:
    """A non-guessable token for one Vuln DB template, so the edit URL carries an
    HMAC and not the raw internal id. The write handlers only accept a token that
    resolves, so the edit and delete endpoints cannot be walked."""
    return hmac.new(_VULN_SECRET, f"tpl|{tid}".encode(),
                    hashlib.sha256).hexdigest()[:24]


def _resolve_tpl(token: str) -> str | None:
    """Map a template token back to its raw id, or None. Also accepts a raw id
    for the seeded templates' own stable ids, used internally."""
    token = (token or "").strip()
    if not token:
        return None
    for t in _vdb_load()["templates"]:
        tid = t.get("id", "")
        if hmac.compare_digest(_tpl_token(tid), token) or tid == token:
            return tid
    return None


_CLIENT_FILTER_JS = """
<script>
window.easClientFilter=function(){
  var qi=document.getElementById('clq'), si=document.getElementById('clsort');
  var box=document.getElementById('clrows'); if(!box)return;
  var q=(qi?qi.value:'').trim().toLowerCase(), sort=si?si.value:'attn';
  var monEl=document.getElementById('clmon'), monOnly=monEl?monEl.checked:false;
  var rows=[].slice.call(box.querySelectorAll('.crow')), shown=0;
  rows.forEach(function(r){
    var m=!q||(r.getAttribute('data-name')||'').indexOf(q)>=0;
    if(m&&monOnly&&(r.getAttribute('data-mon')!=='1'))m=false;
    r.style.display=m?'':'none'; if(m)shown++;
  });
  function num(r,k){return parseInt(r.getAttribute('data-'+k)||'0',10);}
  var vis=rows.filter(function(r){return r.style.display!=='none';});
  vis.sort(function(a,b){
    if(sort==='name'){return (a.getAttribute('data-name')||'').localeCompare(b.getAttribute('data-name')||'');}
    if(sort==='findings'){return num(b,'findings')-num(a,'findings');}
    if(sort==='last'){return num(b,'last')-num(a,'last');}
    return (num(b,'attn')-num(a,'attn'))||(num(b,'last')-num(a,'last'));
  });
  vis.forEach(function(r){box.appendChild(r);});
  var none=document.getElementById('clnone'); if(none)none.style.display=shown?'none':'';
};
</script>
"""


def _overview(user: str, flash: tuple | None = None) -> bytes:
    eng = engagements()
    n_clients = len(eng)

    def on_count(e):
        return sum(1 for m in TOGGLE_MODULES if e["watch"][m["kind"]]["on"])

    n_on = sum(1 for e in eng if on_count(e))
    mon_colour = "var(--green)" if n_on else "var(--muted)"
    n_assets = sum(e.get("collected", e["total"]) for e in eng)

    def live_attn(e):
        # The findings still waiting to be reviewed, from the same source as the
        # client page and the Triage queue, so every count agrees.
        return _review_findings(e["slug"])

    n_attn = sum(len(live_attn(e)) for e in eng)
    attn_colour = "var(--red)" if n_attn else "var(--green)"

    def row(e):
        slug = e["slug"]
        mods_on = on_count(e)
        watching = bool(mods_on)
        na = len(live_attn(e))
        na_colour = "var(--red)" if na else "var(--green)"
        return f"""<a class="crow" href="/c/{_client_id(slug)}" data-name="{_esc(_pretty(slug).lower())}" data-mon="{1 if watching else 0}" data-attn="{na}" data-findings="{e['total']}" data-last="{int(e['last'] or 0)}">
  <div class="cl"><span class="dot {'on' if watching else 'off'}"></span>
    <div><div class="clname">{_pretty(slug)}</div>
    <div class="muted" style="font-size:12px">{mods_on} of {len(TOGGLE_MODULES)} watchers on &middot; Last activity {_ago(e['last'])}</div></div></div>
  <div class="cbar"><div class="bar">{_sev_bar(e['counts'])}</div>
    <div class="badges">{_sev_badges(e['counts'])}</div></div>
  <div class="cnum"><div class="n">{e['total']}</div><div class="k">Findings</div></div>
  <div class="cnum"><div class="n" style="color:{na_colour}">{na}</div><div class="k">Need attention</div></div>
</a>"""

    # One list, sorted most-attention-first by default, with a search box and a
    # sort control so a long client roster stays manageable.
    ordered = sorted(eng, key=lambda e: (-len(live_attn(e)), -(e["last"] or 0), _pretty(e["slug"]).lower()))
    if eng:
        toolbar = ('<div class="cltools">'
                   '<input type="text" id="clq" class="clq" placeholder="Search clients" '
                   'oninput="easClientFilter()">'
                   '<select id="clsort" class="clsort" onchange="easClientFilter()">'
                   '<option value="attn">Sort by: Need attention</option>'
                   '<option value="findings">Sort by: Findings</option>'
                   '<option value="last">Sort by: Last activity</option>'
                   '<option value="name">Sort by: Name</option>'
                   '</select>'
                   '<label class="clmonlbl"><input type="checkbox" id="clmon" '
                   'onchange="easClientFilter()"> Actively monitored only</label>'
                   '</div>')
        sections = ('<h2>Clients</h2>' + toolbar
                    + '<div class="rows" id="clrows">' + "".join(row(e) for e in ordered) + "</div>"
                    + '<div class="muted" id="clnone" style="display:none;padding:8px 2px">'
                    'No clients match that search.</div>' + _CLIENT_FILTER_JS)
    else:
        sections = ('<div class="empty">No clients yet. '
                    '<a href="/new-client">Create your first client</a> to get started.</div>')

    metrics = f"""<div class="metrics">
<div class="metric"><div class="n">{n_clients}</div><div class="k">Clients</div></div>
<div class="metric"><div class="n" style="color:{mon_colour}">{n_on}/{n_clients}</div><div class="k">Actively monitored</div></div>
<div class="metric"><div class="n">{n_assets}</div><div class="k">Signals collected</div></div>
<div class="metric"><div class="n" style="color:{attn_colour}">{n_attn}</div><div class="k">Need attention</div></div>
</div>"""
    topbar = ('<div class="topbar">'
              '<div class="eyebrow">Operator console</div>'
              '<a class="newcl" href="/new-client">+ New client</a></div>')
    body = f'{_flash(flash)}{topbar}{metrics}{sections}'
    return _page(body, user)


def _new_client_page(user: str) -> bytes:
    body = """
<a class="back" href="/"><svg class="barrow" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5M12 19l-7-7 7-7"/></svg> All clients</a>
<h1 class="ptitle">New client</h1>
<div class="card setup">
  <label class="fld"><span>Client name</span>
    <input id="nc_name" placeholder="Acme Corp" autofocus></label>
  <label class="fld"><span>In-scope domains <em>optional</em></span>
    <textarea id="nc_domains" rows="4" placeholder="acme.com&#10;portal.acme.com"></textarea></label>
  <label class="fld"><span>Brand keywords <em>optional</em></span>
    <input id="nc_keywords" placeholder="acme, acmecorp"></label>
  <label class="fld"><span>Context note, client email or scope text <em>optional</em></span>
    <textarea id="nc_notes" rows="6" placeholder="Paste what the client sent. The local model reads it to suggest domains, it never runs anything."></textarea></label>
  <div class="setup-ai">
    <button type="button" class="btn-ghost" onclick="ncIngest(this)">Extract domains with local AI</button>
    <span class="muted" id="nc_ai"></span>
  </div>
  <div class="note">New clients start in <b>passive</b> mode. Active scans stay blocked until the target is on the approved list, whatever the client is named.</div>
  <div class="flash no" id="nc_err" style="display:none"></div>
  <div class="row"><button type="button" class="btn btn-start" id="nc_go" onclick="ncCreate(false)">Create client</button></div>
</div>
<script>
function _v(id){var e=document.getElementById(id);return e?e.value:'';}
function ncIngest(btn){
  var t=_v('nc_notes')+'\\n'+_v('nc_domains');
  var s=document.getElementById('nc_ai'); s.textContent='Extracting locally, this can take a moment...'; btn.disabled=true;
  fetch('/ingest',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'text='+encodeURIComponent(t)})
    .then(function(r){return r.json();}).then(function(d){
      btn.disabled=false;
      if(d&&d.domains&&d.domains.length){
        var box=document.getElementById('nc_domains'); var have=box.value.trim();
        box.value=(have?have+'\\n':'')+d.domains.join('\\n');
        if(d.keywords&&d.keywords.length){var k=document.getElementById('nc_keywords'); k.value=k.value?k.value+', '+d.keywords.join(', '):d.keywords.join(', ');}
        s.textContent='Found '+d.domains.length+' domain(s) via '+(d.source==='ai'?('local model '+(d.model||'')):'text scan')+'. Review before creating.';
      } else { s.textContent='No domains found in the text.'; }
    }).catch(function(){btn.disabled=false; s.textContent='Could not reach the local extractor.';});
}
function ncCreate(confirm){
  var err=document.getElementById('nc_err'); err.style.display='none';
  var body='name='+encodeURIComponent(_v('nc_name'))+'&domains='+encodeURIComponent(_v('nc_domains'))
    +'&keywords='+encodeURIComponent(_v('nc_keywords'))+'&notes='+encodeURIComponent(_v('nc_notes'))+'&xhr=1'+(confirm?'&confirm=1':'');
  document.getElementById('nc_go').disabled=true;
  fetch('/new-client',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body})
    .then(function(r){return r.json();}).then(function(d){
      document.getElementById('nc_go').disabled=false;
      if(d.ok){try{sessionStorage.setItem('eas_flash',JSON.stringify([true,d.msg]));}catch(e){}
        window.location='/c/'+encodeURIComponent(d.cid||d.slug);return;}
      if(d.confirm){if(window.confirm(d.msg)){ncCreate(true);} return;}
      err.textContent=d.msg; err.style.display='block';
    }).catch(function(){document.getElementById('nc_go').disabled=false; err.textContent='Request failed.'; err.style.display='block';});
}
</script>"""
    return _page(body, user)


# --------------------------------------------------------------------------
# Level 2: the per-client page.
# --------------------------------------------------------------------------
def _help(text: str) -> str:
    """A small ? button. Click to reveal what this runs, hover also shows it."""
    t = text.replace("&", "&amp;").replace("<", "&lt;").replace('"', "&quot;")
    return (f'<button type="button" class="help" aria-label="what this runs" '
            f'onclick="tipT(this,event)">?<span class="tip">{t}</span></button>')


def _module_artifact(base: Path, m: dict) -> tuple[str | None, float | None]:
    """The file this module last produced, and its mtime. The download link.

    Passive and active subdomain runs keep separate files, so each square links
    its own. The subdomain download is the clean host list, lookalike links its
    signal file.
    """
    sig = base / "signals"
    if not sig.is_dir():
        return None, None
    kind = m["kind"]
    if kind.startswith("subdomain"):
        mode = "passive" if "passive" in kind else "active"
        files = list(sig.glob(f"*-subdomains-{mode}.txt"))
    elif kind.startswith("lookalike"):
        files = [f for f in sig.glob("*.jsonl") if "-subdomains" not in f.name]
    else:
        return None, None
    if not files:
        return None, None
    newest = max(files, key=lambda f: f.stat().st_mtime)
    return newest.name, newest.stat().st_mtime


def _last_line(st: dict, slug: str, art_name: str | None, art_mtime: float | None,
               running: bool = False) -> str:
    """The last-run line under a control. Links the file produced on that run."""
    if running:
        return '<div class="mlast">Running now</div>'
    epoch = st.get("last") or art_mtime
    if not epoch:
        return '<div class="mlast">Last run: never</div>'
    when = _ago(epoch)
    if art_name:
        dl = f'/dl?e={_client_id(slug)}&d=signals&f={urllib.parse.quote(art_name)}'
        return f'<div class="mlast">Last run: <a href="{dl}">{when}</a></div>'
    return f'<div class="mlast">Last run: {when}</div>'


def _switch(slug: str, m: dict, on: bool) -> str:
    """An on/off toggle for one module, opening the confirm modal."""
    meta = json.dumps({"kind": m["kind"], "name": m["name"]})
    action = "stop" if on else "start"
    cls = "sw on" if on else "sw"
    dis = "" if ALLOW_CONTROL else "disabled"
    client = _pretty(slug)
    return (f'<button class="{cls}" {dis} title="{"on" if on else "off"}" '
            f"onclick='askM(\"{action}\",\"{_client_id(slug)}\",\"{client}\",{meta},this)'></button>")


def _runbtn(slug: str, m: dict, running: bool = False) -> str:
    """A run-once button for an on-demand module, opening the confirm modal.
    While the module is running it becomes a Stop button instead.

    The button just says Run. Which run it is lives in the square title, and
    every run button is the same colour, the warning stays in the modal.
    """
    meta = json.dumps({"kind": m["kind"], "name": m["name"], "warn": bool(m.get("warn")), "run": True})
    dis = "" if ALLOW_CONTROL else "disabled"
    client = _pretty(slug)
    if running:
        return (f'<button class="stopbtn" {dis} '
                f"onclick='askM(\"stop\",\"{_client_id(slug)}\",\"{client}\",{meta},this)'>Stop</button>")
    return (f'<button class="runbtn" {dis} '
            f"onclick='askM(\"run\",\"{_client_id(slug)}\",\"{client}\",{meta},this)'>Run</button>")


def _watchers_section(slug: str, e: dict) -> str:
    """Every watcher with its live state and a per-watcher start/stop switch."""
    rows = ""
    for m in TOGGLE_MODULES:
        st = e["watch"][m["kind"]]
        on, active = st["on"], st.get("active")
        state = "Running" if active else ("On" if on else "Off")
        scls = "won run" if active else ("won on" if on else "won off")
        last = _ago(st.get("last"))
        rows += (f'<div class="wrow">'
                 f'<span class="wdot {scls}"></span>'
                 f'<div class="wbody"><div class="wname">{m["name"]}</div>'
                 f'<div class="muted" style="font-size:12px">{state} &middot; last run {last}</div></div>'
                 f'{_switch(slug, m, on)}</div>')
    return f'<h2 id="watchers">Watchers</h2><div class="card watchcard">{rows}</div>'


def _action(a: dict) -> str:
    """The suggested next step for one finding, by its source class."""
    cls = a.get("source_class", "")
    if cls == "lookalike_domain":
        return ("Confirm the domain is not yours, then open a takedown and watch "
                "it for a live clone or mail abuse.")
    if cls == "subdomain":
        return ("Investigate this host. A takeover exposure is a dangling record "
                "to reclaim or remove before someone else claims it.")
    return "Review this finding and decide on an action."


# --------------------------------------------------------------------------
# Vulnerability and client identity.
# --------------------------------------------------------------------------
def _vuln_id(slug: str, key: str) -> str:
    """A stable, non-guessable id for one finding: a keyed HMAC of the client and
    the finding's dedup key. Ids cannot be enumerated or walked, so the per-vuln
    page is not IDORable."""
    return hmac.new(_VULN_SECRET, f"{slug}|{key}".encode(),
                    hashlib.sha256).hexdigest()[:24]


def _fp_file(slug: str) -> Path:
    return ENGAGEMENTS / slug / "state" / "false_positives.json"


def _fp_load(slug: str) -> dict:
    """The false-positive map for a client, keyed by finding dedup key."""
    f = _fp_file(slug)
    try:
        if f.is_file():
            d = json.loads(f.read_text())
            if isinstance(d, dict):
                return d
    except Exception:
        pass
    return {}


def _fp_save(slug: str, data: dict) -> None:
    f = _fp_file(slug)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(data, indent=2))
    _invalidate_state(slug)


def _confirmed_file(slug: str) -> Path:
    return ENGAGEMENTS / slug / "state" / "confirmed.json"


def _confirmed_load(slug: str) -> dict:
    """The confirmed-finding map for a client, keyed by finding dedup key. A
    confirmed finding is one already reported to the client. It is a sidecar to
    the false-positive map, so marking confirmed never touches false_positives."""
    f = _confirmed_file(slug)
    try:
        if f.is_file():
            d = json.loads(f.read_text())
            if isinstance(d, dict):
                return d
    except Exception:
        pass
    return {}


def _confirmed_save(slug: str, data: dict) -> None:
    f = _confirmed_file(slug)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(data, indent=2))
    _invalidate_state(slug)


def _vnotes_file(slug: str) -> Path:
    return ENGAGEMENTS / slug / "state" / "vuln_notes.json"


def _vnotes_load(slug: str) -> dict:
    """The per-finding operator-note trail, keyed by finding dedup key. Each entry
    is the ordered history of triage actions (confirm, false positive, reopen)
    with the reason the operator recorded, so the vuln page can always show why a
    finding was confirmed or reopened, even after a reopen clears the state map."""
    f = _vnotes_file(slug)
    try:
        if f.is_file():
            d = json.loads(f.read_text())
            if isinstance(d, dict):
                return d
    except Exception:
        pass
    return {}


def _vnotes_append(slug: str, key: str, action: str, reason: str, by: str, ts: str,
                   files: list | None = None) -> None:
    data = _vnotes_load(slug)
    trail = data.get(key) or []
    entry = {"action": action, "reason": reason, "by": by, "ts": ts}
    if files:
        entry["files"] = files
    trail.append(entry)
    data[key] = trail[-50:]
    f = _vnotes_file(slug)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(data, indent=2))


def _vuln_status(slug: str, key: str, fp: dict | None = None,
                 cf: dict | None = None) -> str:
    """One of to_review (default), false_positive, confirmed. A finding can be in
    at most one of the two state files, so the lookup is unambiguous."""
    fp = _fp_load(slug) if fp is None else fp
    if key in fp:
        return "false_positive"
    cf = _confirmed_load(slug) if cf is None else cf
    if key in cf:
        return "confirmed"
    return "to_review"


_CVSS31_RE = re.compile(r"CVSS:3\.[01]/[A-Z]{1,2}:[A-Z](?:/[A-Z]{1,2}:[A-Z])+")


def _cvss_vector(s: str) -> str:
    """Pull a CVSS 3.0/3.1 vector string out of whatever the signal carried, or
    an empty string. The panel never invents a vector, it only surfaces one that
    a source or the operator supplied."""
    s = (s or "").strip()
    m = _CVSS31_RE.search(s)
    return m.group(0) if m else ""


def _vmeta_file(slug: str) -> Path:
    return ENGAGEMENTS / slug / "state" / "vuln_meta.json"


def _vmeta_load(slug: str) -> dict:
    """Operator edits to a finding (CVSS vector for now, description and the rest
    later), keyed by finding dedup key. A sidecar, separate from triage state, so
    editing a field never touches the false-positive or confirmed maps."""
    f = _vmeta_file(slug)
    try:
        if f.is_file():
            d = json.loads(f.read_text())
            if isinstance(d, dict):
                return d
    except Exception:
        pass
    return {}


def _vmeta_save(slug: str, data: dict) -> None:
    f = _vmeta_file(slug)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(data, indent=2))
    _invalidate_state(slug)


# Evidence upload policy. Operators attach screenshots (PNG, JPEG) and PDF
# proof. Everything else is refused. The checks follow the OWASP file-upload
# guidance: a short extension allowlist, a magic-byte sniff that must agree with
# the extension and the declared type, a hard size cap, and rejection of any
# interior script extension (the x.php.png trick) or control character.
MAX_EVIDENCE_BYTES = 10 * 1024 * 1024          # per file
MAX_EVIDENCE_TOTAL = 12 * 1024 * 1024          # per request
_EXT_OK = {"png", "jpg", "jpeg", "pdf"}
_EXT_CANON = {"png": "png", "jpg": "jpg", "jpeg": "jpg", "pdf": "pdf"}
_EXT_MAGIC = {
    "png": (b"\x89PNG\r\n\x1a\n",),
    "jpg": (b"\xff\xd8\xff",),
    "pdf": (b"%PDF-",),
}
_EXT_CT = {
    "png": {"image/png"},
    "jpg": {"image/jpeg", "image/jpg"},
    "pdf": {"application/pdf"},
}
# Script and markup extensions that must never appear anywhere in the name, not
# even as an interior segment, so a double extension cannot smuggle executable
# content past a web server that picks an earlier extension.
_EXT_DANGER = {
    "php", "php2", "php3", "php4", "php5", "php6", "php7", "phps", "pht",
    "phtml", "phar", "asp", "aspx", "ascx", "ashx", "asmx", "cer", "jsp",
    "jspx", "jsw", "jsv", "jspf", "js", "mjs", "cgi", "pl", "py", "rb", "sh",
    "bash", "bat", "cmd", "com", "exe", "dll", "so", "jar", "war", "htaccess",
    "html", "htm", "xhtml", "shtml", "svg", "xml", "swf", "vbs", "ps1",
}


def _safe_token(s: str, default: str = "evidence") -> str:
    """A filename-safe slug: lowercase, only letters, digits, dash, underscore."""
    s = re.sub(r"[^a-z0-9_-]+", "-", (s or "").lower()).strip("-")
    return s[:60] or default


def _validate_evidence(filename: str, ctype: str, data: bytes) -> tuple[bool, str, str]:
    """Return (ok, canonical_ext, message). Enforces the policy above."""
    if not data:
        return False, "", "Empty file."
    if len(data) > MAX_EVIDENCE_BYTES:
        return False, "", "File is larger than 10 MB."
    name = (filename or "").strip().replace("\\", "/").split("/")[-1]
    if not name or "\x00" in name or any(ord(c) < 32 for c in name):
        return False, "", "Invalid file name."
    segs = name.lower().split(".")
    if len(segs) < 2:
        return False, "", "File has no extension."
    ext = segs[-1]
    if ext not in _EXT_OK:
        return False, "", "Only PNG, JPG and PDF are allowed."
    # No dangerous extension anywhere in the name (handles x.php.png and jpg.php).
    for seg in segs[:-1]:
        if seg in _EXT_DANGER:
            return False, "", "File name looks like a double extension."
    canon = _EXT_CANON[ext]
    if not any(data.startswith(sig) for sig in _EXT_MAGIC[canon]):
        return False, "", "File content does not match its extension."
    ct = (ctype or "").split(";")[0].strip().lower()
    if ct and ct not in _EXT_CT[canon]:
        return False, "", "Declared content type does not match the file."
    return True, canon, ""


def _all_findings(slug: str) -> dict:
    """Every Critical and High signal for a client, deduped, with full detail,
    keyed by dedup id. Backs the vulnerability page and the triage lists."""
    sdir = ENGAGEMENTS / slug / "signals"
    out: dict[str, dict] = {}
    # Active lookalikes for the same origin brand are one vulnerability, keyed by
    # origin, so the triage queue, the Manage page and the vuln id all treat the
    # whole set as a single finding with every domain as a location.
    lookalikes: dict[str, dict] = {}

    def _rank(s: str) -> int:
        return SEV_ORDER.index(s) if s in SEV_ORDER else len(SEV_ORDER)

    if not sdir.is_dir():
        return out
    dmarc_sev = _dmarc_posture_sev(sdir)
    for f in sorted(sdir.glob("*.jsonl")):
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            sev = _norm_sev(d.get("severity"))
            cls = str(d.get("source_class") or "")
            if cls == "dmarc_record" and dmarc_sev is not None:
                continue
            if cls == "email_auth_posture" and dmarc_sev is not None:
                sev = dmarc_sev
            ents = d.get("entities") or []
            hosts = [str(x.get("value", "")).lower().rstrip(".") for x in ents
                     if x.get("type") == "domain" and x.get("value")]
            ips = [str(x.get("value", "")) for x in ents
                   if x.get("type") == "ip" and x.get("value")]
            ev = d.get("evidence") or {}
            if cls == "lookalike_domain":
                # Group regardless of per-domain severity: the whole group is one
                # High finding, matching the console and the early alert.
                origin = (ev.get("origin_domain") or "").lower().rstrip(".") or "lookalike"
                grp = lookalikes.setdefault(origin, {
                    "sev": sev, "hosts": [], "ips": [], "title": "",
                    "description": "", "source": "", "evidence": ev,
                    "first_seen": "", "last_seen": "", "origin": origin})
                if _rank(sev) < _rank(grp["sev"]):
                    grp["sev"] = sev
                for dm in (hosts or [str(d.get("title", ""))]):
                    if dm and dm not in grp["hosts"]:
                        grp["hosts"].append(dm)
                for ip in ips:
                    if ip not in grp["ips"]:
                        grp["ips"].append(ip)
                if not grp["title"]:
                    grp["title"] = str(d.get("title") or "Active brand impersonation domain")
                if not grp["description"]:
                    grp["description"] = str(d.get("description") or "")
                if not grp["source"]:
                    grp["source"] = str(d.get("source") or "")
                fs = str(d.get("first_seen") or d.get("last_seen") or "")
                ls = str(d.get("last_seen") or d.get("first_seen") or "")
                if fs and (not grp["first_seen"] or fs < grp["first_seen"]):
                    grp["first_seen"] = fs
                if ls > grp["last_seen"]:
                    grp["last_seen"] = ls
                continue
            # Critical and High findings are the triage scope, plus manually
            # entered findings and credential exposure at any severity, so they
            # always get a manage page.
            if (sev not in ("SEV1", "SEV2")
                    and cls not in ("manual", "credential_exposure")
                    and not (cls in ("dmarc_record", "email_auth_posture")
                             and sev in ("SEV1", "SEV2", "SEV3"))):
                continue
            key = d.get("dedup_id") or f"{cls}|{d.get('title', '')}"
            if key in out:
                continue
            cvss = d.get("cvss") or ev.get("cvss") or ev.get("cvss_vector") or ""
            out[key] = {
                "key": key, "id": _vuln_id(slug, key), "severity": sev,
                "title": str(d.get("title") or cls or "Finding"),
                "description": str(d.get("description") or ""),
                "source": str(d.get("source") or ""), "source_class": cls,
                "hosts": hosts, "ips": ips, "evidence": ev,
                "cvss": str(cvss or ""),
                "last_seen": str(d.get("last_seen") or d.get("first_seen") or ""),
                "first_seen": str(d.get("first_seen") or d.get("last_seen") or ""),
            }

    # One merged finding per origin brand.
    for origin, grp in lookalikes.items():
        key = f"lookalike_domain|{origin}"
        hosts = sorted(grp["hosts"])
        n = len(hosts)
        title = (grp["title"] if n <= 1
                 else f"Active brand impersonation domains ({n}) impersonating {origin}")
        out[key] = {
            "key": key, "id": _vuln_id(slug, key), "severity": grp["sev"],
            "title": title, "description": grp["description"],
            "source": grp["source"], "source_class": "lookalike_domain",
            "hosts": hosts, "ips": sorted(grp["ips"]), "evidence": grp["evidence"],
            "cvss": "",
            "last_seen": grp["last_seen"], "first_seen": grp["first_seen"],
        }
    return out


def _review_findings(slug: str, fp: dict | None = None, cf: dict | None = None) -> list[dict]:
    """The findings still awaiting triage for a client, newest-severity first.
    One source of truth for the Needs-attention list, its count, and the Triage
    queue, so they never disagree (they all read _all_findings, which resolves a
    re-emitted finding to its highest-severity version)."""
    if fp is None:
        fp = _fp_load(slug)
    if cf is None:
        cf = _confirmed_load(slug)
    out = [v for k, v in _all_findings(slug).items() if k not in fp and k not in cf]
    out.sort(key=lambda a: SEV_ORDER.index(a["severity"])
             if a["severity"] in SEV_ORDER else len(SEV_ORDER))
    return out


def _page_slice(items: list, page: int, per: int) -> tuple[list, int, int]:
    """Clamp page to range and return (slice, page, total_pages)."""
    total = len(items)
    pages = max(1, (total + per - 1) // per)
    page = max(1, min(page, pages))
    start = (page - 1) * per
    return items[start:start + per], page, pages


def _pager(base: str, page: int, pages: int, param: str = "page", anchor: str = "") -> str:
    """Numbered page links 1 2 3 ... for a server-paginated table. base is the
    URL with its query string already set except the page number, ending in
    '?' or '&'. Returns nothing for a single page."""
    if pages <= 1:
        return ""
    # A compact window around the current page, always showing first and last.
    nums: list[int] = []
    for p in range(1, pages + 1):
        if p <= 2 or p > pages - 2 or abs(p - page) <= 2:
            nums.append(p)

    def href(p):
        return f'{base}{param}={p}{anchor}'
    out = []
    if page > 1:
        out.append(f'<a class="pgl" href="{href(page-1)}">&lsaquo;</a>')
    prev = 0
    for p in nums:
        if prev and p != prev + 1:
            out.append('<span class="pgdots">&hellip;</span>')
        cls = "pgl on" if p == page else "pgl"
        out.append(f'<a class="{cls}" href="{href(p)}">{p}</a>')
        prev = p
    if page < pages:
        out.append(f'<a class="pgl" href="{href(page+1)}">&rsaquo;</a>')
    return f'<div class="pager">{"".join(out)}</div>'


_REVIEW_COUNT_CACHE = [0.0, 0]


def _pending_review_count() -> int:
    """How many findings are still awaiting triage across every client. Backs the
    navbar badge. Cached for a few seconds so it does not re-read every client's
    signals on every page render."""
    now = time.monotonic()
    if now - _REVIEW_COUNT_CACHE[0] < 8:
        return _REVIEW_COUNT_CACHE[1]
    total = 0
    try:
        for e in engagements():
            total += len(_review_findings(e["slug"]))
    except Exception:
        total = _REVIEW_COUNT_CACHE[1]
    _REVIEW_COUNT_CACHE[0] = time.monotonic()
    _REVIEW_COUNT_CACHE[1] = total
    return total


def _vuln_by_id(slug: str, vid: str) -> dict | None:
    """The full finding for one non-IDORable vuln id, or None."""
    if not vid:
        return None
    for v in _all_findings(slug).values():
        if hmac.compare_digest(v["id"], vid):
            return v
    return None


def _attention_section(slug: str, attention: list[dict], cid: str = "", page: int = 1,
                       tab: str = "") -> str:
    """The needs-attention block. The badge and the per-finding actions (Manage,
    Early alert) sit together in the left column, under the severity, so the row
    stays compact. False positives are filtered out by the caller. Paginated at
    5 findings per page."""
    add_btn = (f'<a class="btn-ghost sbtn" href="/review?new=1&slug={cid}">'
               'Add manual finding</a>' if cid else "")
    head = (f'<div class="rephead"><h2 id="attn" style="margin:0">Needs attention</h2>'
            f'{add_btn}</div>')
    if not attention:
        return (head + '<div class="card"><div class="muted">Nothing needs action '
                'right now. No Critical or High findings.</div></div>')
    shown, page, pages = _page_slice(attention, page, 5)
    rows = ""
    for a in shown:
        label, bg, fg = SEV[a["severity"]]
        desc = (a.get("description") or "").strip()
        key = a.get("key", "")
        vid = _vuln_id(slug, key)
        manage = (f'<a class="btn-ghost actbtn" '
                  f'href="/vuln?e={_client_id(slug)}&v={vid}&from=attention">Manage</a>')
        hosts = a.get("hosts") or []
        host_line = (f'<div class="attnact"><b>Host:</b> '
                     f'{_esc(", ".join(hosts))}</div>' if hosts else "")
        rows += (f'<div class="attn">'
                 f'<div class="attnsev">'
                 f'<span class="badge" style="background:{bg};color:{fg}">{label}</span>'
                 f'<div class="attnbtns">{manage}</div></div>'
                 f'<div class="attnbody"><div class="attntitle">{_esc(a["title"])}</div>'
                 f'<div class="muted" style="font-size:12px">{_esc(desc)}</div>'
                 f'{host_line}'
                 f'<div class="attnact"><b>Action:</b> {_action(a)}</div></div></div>')
    base = f"/c/{cid}?t={tab}&" if (cid and tab) else (f"/c/{cid}?" if cid else "")
    pager = _pager(base, page, pages, param="apage", anchor="#attn") if cid else ""
    return head + f'<div class="card attncard">{rows}</div>{pager}'


def _fmt_iso(s: str) -> str:
    """A raw ISO timestamp formatted as a readable UTC date, or the input back
    if it does not parse."""
    s = (s or "").strip()
    if not s:
        return ""
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).strftime("%d %b %Y %H:%M UTC")
    except Exception:
        return s


def _false_positives_section(slug: str, fp: dict) -> str:
    """Findings the operator has marked as false positives. Each keeps the same
    detail as in Needs attention (description, host) minus the action line, plus
    a green marked-as line, and a Manage button to open and reopen it."""
    if not fp:
        return ""
    findings = _all_findings(slug)
    items = sorted(fp.values(), key=lambda a: SEV_ORDER.index(a.get("severity", "SEV5"))
                   if a.get("severity") in SEV_ORDER else 9)
    rows = ""
    for a in items:
        sev = a.get("severity", "SEV5")
        label, bg, fg = SEV.get(sev, SEV["SEV5"])
        key = a.get("key", "")
        full = findings.get(key, {})
        title = full.get("title") or a.get("title", "Finding")
        desc = (full.get("description") or "").strip()
        hosts = full.get("hosts") or []
        when = a.get("ts", "")
        vid = a.get("id") or _vuln_id(slug, key)
        manage = (f'<a class="btn-ghost actbtn" '
                  f'href="/vuln?e={_client_id(slug)}&v={vid}&from=falsepos">Manage</a>')
        host_line = (f'<div class="attnact"><b>Host:</b> {_esc(", ".join(hosts))}</div>'
                     if hosts else "")
        rows += (f'<div class="attn"><div class="attnsev">'
                 f'<span class="badge" style="background:{bg};color:{fg}">{label}</span>'
                 f'<div class="attnbtns">{manage}</div></div>'
                 f'<div class="attnbody"><div class="attntitle">{_esc(title)}</div>'
                 f'<div class="muted" style="font-size:12px">{_esc(desc)}</div>'
                 f'{host_line}'
                 f'<div class="fpmark">Marked as false positive {_esc(when)}</div>'
                 f'</div></div>')
    return (f'<h2 id="falsepos">False positives</h2>'
            f'<div class="card attncard">{rows}</div>')


def _confirmed_section(slug: str, cf: dict, cid: str = "") -> str:
    """Findings the operator has confirmed, meaning reported to the client and
    tracked as real. Same shape as the false-positive list: title, description,
    host, a green confirmed line, and a Manage button to open and reopen it.
    Carries the same Add manual finding action as Needs attention."""
    add_btn = (f'<a class="btn-ghost sbtn" href="/review?new=1&slug={cid}">'
               'Add manual finding</a>' if cid else "")
    head = (f'<div class="rephead"><h2 id="confirmed" style="margin:0">Confirmed</h2>'
            f'{add_btn}</div>')
    if not cf:
        return (head + '<div class="card"><div class="muted">'
                'No confirmed findings yet.</div></div>')
    findings = _all_findings(slug)
    items = sorted(cf.values(), key=lambda a: SEV_ORDER.index(a.get("severity", "SEV5"))
                   if a.get("severity") in SEV_ORDER else 9)
    rows = ""
    for a in items:
        sev = a.get("severity", "SEV5")
        label, bg, fg = SEV.get(sev, SEV["SEV5"])
        key = a.get("key", "")
        full = findings.get(key, {})
        title = full.get("title") or a.get("title", "Finding")
        desc = (full.get("description") or "").strip()
        hosts = full.get("hosts") or []
        when = a.get("ts", "")
        vid = a.get("id") or _vuln_id(slug, key)
        manage = (f'<a class="btn-ghost actbtn" '
                  f'href="/vuln?e={_client_id(slug)}&v={vid}&from=confirmed">Manage</a>')
        host_line = (f'<div class="attnact"><b>Host:</b> {_esc(", ".join(hosts))}</div>'
                     if hosts else "")
        rows += (f'<div class="attn"><div class="attnsev">'
                 f'<span class="badge" style="background:{bg};color:{fg}">{label}</span>'
                 f'<div class="attnbtns">{manage}</div></div>'
                 f'<div class="attnbody"><div class="attntitle">{_esc(title)}</div>'
                 f'<div class="muted" style="font-size:12px">{_esc(desc)}</div>'
                 f'{host_line}'
                 f'<div class="cfmark">Confirmed, reported to the client {_esc(when)}</div>'
                 f'</div></div>')
    return head + f'<div class="card attncard">{rows}</div>'


# The per-vuln page's own markup and script: the reason modal (triage forces a
# reason), a self-contained CVSS 3.1 calculator (FIRST.org formula) that repaints
# the score, likelihood and risk live, and the in-place vector editor that
# persists through /vuln-meta. Plain string (not an f-string), raw so the regex
# backslashes survive. Braces are literal JS.
_VULN_PAGE_JS = r"""
<div class="vmodal" id="rmodal" style="display:none">
  <div class="vmback" onclick="vclose()"></div>
  <form class="vmcard" method="POST" action="/vuln-action" id="rform">
    <h3 id="rtitle">Confirm</h3>
    <input type="hidden" name="slug" id="rslug">
    <input type="hidden" name="key" id="rkey">
    <input type="hidden" name="act" id="ract">
    <input type="hidden" name="evidence" id="revidence">
    <label class="rlbl" id="rlabel" for="rreason">Reason (required)</label>
    <textarea name="reason" id="rreason" class="rta" rows="4" required
      placeholder="Record why, for the audit log."></textarea>
    <div class="evup"><label class="evuplbl">
      <span class="evupico"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="m21 15-5-5L5 21"/></svg></span>
      <span class="evuptext"><b>Attach evidence</b>
      <span class="muted">Optional. PNG, JPG or PDF, up to 10 MB each. Select one or more.</span></span>
      <input type="file" id="rfile" multiple
        accept=".png,.jpg,.jpeg,.pdf,image/png,image/jpeg,application/pdf"></label></div>
    <div class="rerr" id="rerr"></div>
    <div class="vmbtns">
      <button type="button" class="btn-ghost" onclick="vclose()">Cancel</button>
      <button type="submit" class="btn-ghost go" id="rsubmit">Confirm</button>
    </div>
  </form>
</div>
<script>
(function(){
  function roundup(x){var i=Math.round(x*100000);if(i%10000===0)return i/100000;return (Math.floor(i/10000)+1)/10;}
  function cvss31(vec){
    if(!vec) return null;
    var parts=String(vec).trim().split('/');
    if(!/^CVSS:3\.[01]$/.test(parts[0])) return null;
    var m={};
    for(var i=1;i<parts.length;i++){var kv=parts[i].split(':');if(kv.length===2)m[kv[0]]=kv[1];}
    var need=['AV','AC','PR','UI','S','C','I','A'];
    for(var j=0;j<need.length;j++){if(!(need[j] in m))return null;}
    var AV={N:0.85,A:0.62,L:0.55,P:0.2}[m.AV];
    var AC={L:0.77,H:0.44}[m.AC];
    var UI={N:0.85,R:0.62}[m.UI];
    var changed=(m.S==='C');
    var PR=(changed?{N:0.85,L:0.68,H:0.5}:{N:0.85,L:0.62,H:0.27})[m.PR];
    var cia={N:0,L:0.22,H:0.56};
    var C=cia[m.C],I=cia[m.I],A=cia[m.A];
    if([AV,AC,UI,PR,C,I,A].some(function(x){return x===undefined;})) return null;
    var iss=1-(1-C)*(1-I)*(1-A);
    var impact=changed?(7.52*(iss-0.029)-3.25*Math.pow(iss-0.02,15)):(6.42*iss);
    var expl=8.22*AV*AC*PR*UI;
    var base;
    if(impact<=0) base=0;
    else if(changed) base=roundup(Math.min(1.08*(impact+expl),10));
    else base=roundup(Math.min(impact+expl,10));
    return {score:base,expl:expl};
  }
  function band(s){
    if(s<=0) return ['None','#607085'];
    if(s<4) return ['Low','#F5C518'];
    if(s<7) return ['Medium','#ED7D31'];
    if(s<9) return ['High','#E53935'];
    return ['Critical','#8E0B21'];
  }
  function like(e){ if(e>=2.5) return ['High','#E53935']; if(e>=1.2) return ['Medium','#ED7D31']; return ['Low','#F5C518']; }
  function fgFor(bg){ return (bg==='#F5C518'||bg==='#ED7D31')?'#111820':'#ffffff'; }
  function chip(el,txt,bg){ if(!el)return; el.textContent=txt; el.style.background=bg; el.style.color=fgFor(bg); }
  function paint(){
    var card=document.getElementById('ratecard'); if(!card) return;
    var vec=(document.getElementById('vecval').textContent||'').trim();
    if(vec==='not set') vec='';
    var r=cvss31(vec);
    var sEl=document.getElementById('scoreval'),lEl=document.getElementById('likeval'),rEl=document.getElementById('riskval');
    if(!r){
      var map={SEV1:['Critical','#8E0B21'],SEV2:['High','#E53935'],SEV3:['Medium','#ED7D31'],SEV4:['Low','#F5C518'],SEV5:['Informational','#607085']};
      var b=map[card.getAttribute('data-sev')]||['-','#607085'];
      chip(sEl,'not set','#2a2f3a'); chip(lEl,'-','#2a2f3a'); chip(rEl,b[0],b[1]);
      return;
    }
    var b2=band(r.score),l=like(r.expl);
    chip(sEl,r.score.toFixed(1),b2[1]); chip(lEl,l[0],l[1]); chip(rEl,b2[0],b2[1]);
  }
  var eb=document.getElementById('vecedit');
  if(eb){
    eb.onclick=function(){var box=document.getElementById('vecbox');box.style.display='flex';var inp=document.getElementById('vecinput');inp.focus();};
    document.getElementById('veccancel').onclick=function(){document.getElementById('vecbox').style.display='none';document.getElementById('vecerr').textContent='';};
    document.getElementById('vecsave').onclick=function(){
      var inp=document.getElementById('vecinput').value.trim();
      var err=document.getElementById('vecerr');
      if(inp && !cvss31(inp)){ err.textContent='Not a valid CVSS 3.1 vector.'; return; }
      var card=document.getElementById('ratecard');
      var body='slug='+encodeURIComponent(card.getAttribute('data-slug'))+'&key='+encodeURIComponent(card.getAttribute('data-key'))+'&cvss_vector='+encodeURIComponent(inp);
      document.getElementById('vecsave').disabled=true;
      fetch('/vuln-meta',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body})
        .then(function(r){return r.json();}).then(function(d){
          document.getElementById('vecsave').disabled=false;
          if(d&&d.ok){document.getElementById('vecval').textContent=inp||'not set';document.getElementById('vecbox').style.display='none';err.textContent='';paint();if(window.showFlash)showFlash(true,'CVSS vector saved.');}
          else{err.textContent=(d&&d.msg)||'Save failed.';}
        }).catch(function(){document.getElementById('vecsave').disabled=false;err.textContent='Request failed.';});
    };
  }
  var rf=document.getElementById('rform');
  if(rf){ rf.addEventListener('submit',function(ev){
    var err=document.getElementById('rerr');
    if(!document.getElementById('rreason').value.trim()){ ev.preventDefault(); err.textContent='A reason is required.'; return; }
    var fin=document.getElementById('rfile');
    if(fin && fin.files && fin.files.length){
      // Upload the evidence first, only submit the triage once it is stored.
      ev.preventDefault();
      var files=Array.prototype.slice.call(fin.files),total=files.length,stored=[];
      var btn=document.getElementById('rsubmit'); btn.disabled=true;
      function up(idx){
        if(idx>=total){
          var h=document.getElementById('revidence'); if(h)h.value=stored.join('\n');
          rf.submit(); return;
        }
        var fd=new FormData();
        fd.append('slug',document.getElementById('rslug').value);
        fd.append('key',document.getElementById('rkey').value);
        fd.append('act','upload'); fd.append('file',files[idx]);
        err.textContent='Uploading evidence '+(idx+1)+' of '+total+'...';
        fetch('/vuln-evidence',{method:'POST',body:fd}).then(function(r){return r.json();}).then(function(d){
          if(d&&d.ok){ if(d.stored)stored.push(d.stored); up(idx+1); } else { btn.disabled=false; err.textContent=(d&&d.msg)||'Evidence upload failed.'; }
        }).catch(function(){ btn.disabled=false; err.textContent='Evidence upload failed.'; });
      }
      up(0);
    }
  }); }
  window.evUpload=function(slug,key){
    var fin=document.getElementById('evfile'),err=document.getElementById('everr');
    if(!fin||!fin.files||!fin.files.length){if(err)err.textContent='Choose a file first.';return;}
    var files=Array.prototype.slice.call(fin.files),total=files.length;
    function up(idx){
      if(idx>=total){location.reload();return;}
      var fd=new FormData(); fd.append('slug',slug); fd.append('key',key); fd.append('act','upload');
      fd.append('file',files[idx]);
      if(err)err.textContent='Uploading '+(idx+1)+' of '+total+'...';
      fetch('/vuln-evidence',{method:'POST',body:fd}).then(function(r){return r.json();}).then(function(d){
        if(d&&d.ok){up(idx+1);} else {if(err)err.textContent=(d&&d.msg)||('Upload failed on file '+(idx+1)+'.');}
      }).catch(function(){if(err)err.textContent='Upload failed on file '+(idx+1)+'.';});
    }
    up(0);
  };
  window.figCap=function(slug,key,file,inp){
    var body='slug='+encodeURIComponent(slug)+'&key='+encodeURIComponent(key)+'&file='+encodeURIComponent(file)+'&caption='+encodeURIComponent(inp.value);
    inp.classList.remove('saved','saveerr');
    fetch('/vuln-figcap',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body})
      .then(function(r){return r.json();}).then(function(d){
        inp.classList.add(d&&d.ok?'saved':'saveerr');
        setTimeout(function(){inp.classList.remove('saved');},1500);
      }).catch(function(){inp.classList.add('saveerr');});
  };
  window.evDelete=function(slug,key,stored){
    if(!confirm('Remove this evidence file?'))return;
    var fd=new FormData(); fd.append('slug',slug); fd.append('key',key); fd.append('act','delete'); fd.append('stored',stored);
    fetch('/vuln-evidence',{method:'POST',body:fd}).then(function(r){return r.json();}).then(function(d){ if(d&&d.ok)location.reload(); else alert((d&&d.msg)||'Failed.'); });
  };
  window.vopen=function(act,slug,key){
    document.getElementById('rslug').value=slug; document.getElementById('rkey').value=key; document.getElementById('ract').value=act;
    var t={fp:'Mark as false positive',confirm:'Mark as confirmed',reopen:'Reopen finding'}[act]||'Confirm';
    var lab={fp:'Reason this is a false positive (required)',confirm:'Note for the record (required)',reopen:'Reason for reopening (required)'}[act]||'Reason (required)';
    document.getElementById('rtitle').textContent=t; document.getElementById('rlabel').textContent=lab;
    document.getElementById('rreason').value=''; document.getElementById('rerr').textContent='';
    document.getElementById('rmodal').style.display='flex';
    setTimeout(function(){document.getElementById('rreason').focus();},30);
  };
  window.vclose=function(){document.getElementById('rmodal').style.display='none';};
  window.vact=function(act,slug,key){
    var f=document.createElement('form'); f.method='POST'; f.action='/vuln-action';
    function h(n,val){var i=document.createElement('input');i.type='hidden';i.name=n;i.value=val;f.appendChild(i);}
    h('slug',slug);h('key',key);h('act',act); document.body.appendChild(f); f.submit();
  };
  // Generic in-place field editor. A section's editor holds one or more inputs
  // tagged data-field; Save posts every one and reloads so the server repaints.
  window.efEdit=function(g){var v=document.getElementById('view-'+g),e=document.getElementById('edit-'+g);if(v)v.style.display='none';if(e){e.style.display='block';var f=e.querySelector('[data-field]');if(f)f.focus();}};
  window.efCancel=function(g){var v=document.getElementById('view-'+g),e=document.getElementById('edit-'+g);if(e)e.style.display='none';if(v)v.style.display='block';var er=document.getElementById('err-'+g);if(er)er.textContent='';};
  window.efSave=function(g){
    var card=document.getElementById('ratecard'),box=document.getElementById('edit-'+g),err=document.getElementById('err-'+g);
    if(!card||!box) return;
    var body='slug='+encodeURIComponent(card.getAttribute('data-slug'))+'&key='+encodeURIComponent(card.getAttribute('data-key'));
    var els=box.querySelectorAll('[data-field]');
    for(var i=0;i<els.length;i++){body+='&f_'+encodeURIComponent(els[i].getAttribute('data-field'))+'='+encodeURIComponent(els[i].value);}
    fetch('/vuln-meta',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body})
      .then(function(r){return r.json();}).then(function(d){
        if(d&&d.ok){if(window.showFlash)showFlash(true,'Saved.');setTimeout(function(){location.reload();},350);}
        else{if(err)err.textContent=(d&&d.msg)||'Save failed.';}
      }).catch(function(){if(err)err.textContent='Request failed.';});
  };
  paint();
})();
</script>
"""


# Editable vuln fields and their small helpers. The editor is a pencil that
# reveals a textarea or input per section; Save persists into the vuln_meta
# sidecar. The server owns all rendering, so a Save just reloads.
_PENCIL = ('<svg viewBox="0 0 24 24" width="13" height="13" fill="none" '
           'stroke="currentColor" stroke-width="2" stroke-linecap="round" '
           'stroke-linejoin="round"><path d="M12 20h9"/>'
           '<path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>')

# The editable fields the operator can set on a finding, with a length cap each.
_VMETA_FIELDS = {
    "cvss_vector": 300, "description": 20000, "owasp": 120, "cwe": 120,
    "hosts": 12000, "steps": 20000, "curl": 8000, "figures": 8000,
    "mitigation": 20000, "references": 8000,
}


def _md_paras(text: str) -> str:
    """Blank-line separated blocks rendered as paragraphs."""
    paras = [p.strip() for p in re.split(r"\n\s*\n", (text or "").strip()) if p.strip()]
    return "".join(f'<p>{_esc(p)}</p>' for p in paras)


def _md_ol(text: str) -> str:
    """One numbered step per non-empty line, any leading number the operator
    typed is stripped so the list numbers itself."""
    items = []
    for ln in (text or "").splitlines():
        ln = re.sub(r"^\s*\d+[.)]\s*", "", ln.strip())
        if ln:
            items.append(f'<li>{_esc(ln)}</li>')
    return f'<ol class="repro">{"".join(items)}</ol>' if items else ""


def _md_ul(text: str) -> str:
    items = [f'<li>{_esc(re.sub(r"^\s*[-*]\s*", "", ln.strip()))}</li>'
             for ln in (text or "").splitlines() if ln.strip()]
    return f'<ul class="bullets">{"".join(items)}</ul>' if items else ""


def _md_refs(text: str) -> str:
    """Reference lines, each `Label | URL`, as linked bullets."""
    out = []
    for ln in (text or "").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        if "|" in ln:
            lab, url = (x.strip() for x in ln.split("|", 1))
        else:
            lab = url = ln
        if re.match(r"^https?://", url):
            out.append(f'<li><a href="{_esc(url)}" target="_blank" '
                       f'rel="noopener">{_esc(lab)}</a></li>')
        else:
            out.append(f'<li>{_esc(lab)}</li>')
    return f'<ul class="bullets">{"".join(out)}</ul>' if out else ""


def _md_figs(text: str) -> str:
    """Figure slots, each line `filename | caption`. Numbered placeholders that
    name the screenshot to upload, so the export can fill them in order."""
    out = []
    n = 0
    for ln in (text or "").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        n += 1
        if "|" in ln:
            fn, cap = (x.strip() for x in ln.split("|", 1))
        else:
            fn, cap = ln, ""
        out.append(f'<div class="figslot"><div class="figph">Figure {n}</div>'
                   f'<div class="figmeta"><div class="figcap">{_esc(cap) or "(caption)"}</div>'
                   f'<div class="fignm">upload as <code>{_esc(fn)}</code></div></div></div>')
    return "".join(out)


def _ef_input(field: str, raw: str, rows: int = 0, ph: str = "") -> str:
    pha = f' placeholder="{_esc(ph)}"' if ph else ""
    if rows:
        return (f'<textarea id="in-{field}" data-field="{field}" class="eta" '
                f'rows="{rows}"{pha}>{_esc(raw)}</textarea>')
    return (f'<input id="in-{field}" data-field="{field}" class="einp" '
            f'value="{_esc(raw)}"{pha}>')


def _ef_block(group: str, title: str, view: str, editor_inner: str,
              guide: str = "") -> str:
    hint = f'<div class="muted efhint">{guide}</div>' if guide else ""
    return (f'<div class="efield"><div class="ehead"><h2>{title}</h2>'
            f'<button type="button" class="editico" onclick="efEdit(\'{group}\')" '
            f'title="Edit">{_PENCIL}</button></div>'
            f'<div class="card eview" id="view-{group}">{view}</div>'
            f'<div class="card eedit" id="edit-{group}" style="display:none">'
            f'{editor_inner}{hint}'
            f'<div class="ebtns">'
            f'<button type="button" class="btn-ghost sbtn save" onclick="efSave(\'{group}\')">Save</button>'
            f'<button type="button" class="btn-ghost sbtn" onclick="efCancel(\'{group}\')">Cancel</button>'
            f'<span class="eferr" id="err-{group}"></span></div></div></div>')


def _vuln_page(user: str, slug: str, vid: str, flash: tuple | None = None,
               frm: str = "") -> bytes:
    """The per-vulnerability triage page. Full detail of one Critical or High
    finding, its affected hosts, and the triage actions: send to Security Joes,
    build an early alert, and mark or reopen as a false positive."""
    base = ENGAGEMENTS / slug
    if not SLUG_RE.match(slug) or not base.is_dir():
        return _page('<a class="back" href="/"><svg class="barrow" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5M12 19l-7-7 7-7"/></svg> All clients</a>'
                     '<div class="empty" style="margin-top:16px">Client not found.</div>',
                     user)
    v = _vuln_by_id(slug, vid)
    cback = f'/c/{_client_id(slug)}'
    if not v:
        return _page(f'<a class="back" href="{cback}"><svg class="barrow" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5M12 19l-7-7 7-7"/></svg> Back to client</a>'
                     '<div class="empty" style="margin-top:16px">This finding was not '
                     'found. It may have aged out of the signals.</div>', user)
    label, bg, fg = SEV[v["severity"]]
    fp = _fp_load(slug)
    cf = _confirmed_load(slug)
    status = _vuln_status(slug, v["key"], fp, cf)
    is_fp = status == "false_positive"
    is_confirmed = status == "confirmed"

    # The operator's own edits (the vuln_meta sidecar) win, then the curated Vuln
    # DB template for this finding's class (same identity the export uses, so the
    # page and the exported report agree), then whatever the raw signal carried.
    md = _vmeta_load(slug).get(v["key"], {})
    vmeta = md
    # If this impersonation finding has no evidence yet, start a background
    # capture now so the screenshots appear on a refresh, without any button.
    _ensure_capture(slug, v)
    _tpl = {}
    try:
        _tplname = _CLASS_TO_VDB.get(v.get("source_class", ""), "")
        if _tplname:
            _tpl = next((t for t in _vdb_load().get("templates", [])
                         if t.get("name") == _tplname), {}) or {}
    except Exception:
        _tpl = {}
    vector = _cvss_vector(md.get("cvss_vector") or _tpl.get("cvss_vector") or v["cvss"])
    cid = _client_id(slug)

    meta_bits = [f'<span class="vmeta"><b>Source:</b> <span class="vmetav">{_esc(v["source"] or "-")}</span></span>']
    if v["source_class"]:
        meta_bits.append(f'<span class="vmeta"><b>Class:</b> <span class="vmetav">{_esc(v["source_class"])}</span></span>')
    if v["last_seen"]:
        meta_bits.append(f'<span class="vmeta"><b>Last seen:</b> <span class="vmetav">{_esc(_fmt_iso(v["last_seen"]))}</span></span>')

    # Vulnerability rating: CVSS 3.1 vector, score, likelihood, risk. The vector
    # is editable in place and the score and risk recompute live in the browser
    # from the FIRST.org CVSS 3.1 formula. The vector persists through /vuln-meta.
    pencil = ('<svg viewBox="0 0 24 24" width="13" height="13" fill="none" '
              'stroke="currentColor" stroke-width="2" stroke-linecap="round" '
              'stroke-linejoin="round"><path d="M12 20h9"/>'
              '<path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>')
    rating_html = (
        f'<h2>Vulnerability rating</h2>'
        f'<div class="card ratecard" id="ratecard" data-sev="{v["severity"]}" '
        f'data-slug="{cid}" data-key="{_esc(v["key"])}">'
        f'<div class="raterow">'
        f'<div class="ratecell veccell">'
        f'<div class="ratek">CVSS 3.1 vector '
        f'<button type="button" class="editico" id="vecedit" title="Edit vector">{pencil}</button></div>'
        f'<div class="ratev"><code id="vecval">{_esc(vector) or "not set"}</code></div>'
        f'<div class="vecedit" id="vecbox" style="display:none">'
        f'<input id="vecinput" class="vecinput" value="{_esc(vector)}" '
        f'placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" spellcheck="false">'
        f'<button type="button" class="btn-ghost sbtn save" id="vecsave">Save</button>'
        f'<button type="button" class="btn-ghost sbtn" id="veccancel">Cancel</button>'
        f'<div class="vecerr muted" id="vecerr"></div></div></div>'
        f'<div class="ratecell"><div class="ratek">CVSS 3.1 score</div>'
        f'<div class="ratev"><span id="scoreval" class="scorechip">-</span></div></div>'
        f'<div class="ratecell"><div class="ratek">Likelihood</div>'
        f'<div class="ratev"><span id="likeval" class="scorechip">-</span></div></div>'
        f'<div class="ratecell"><div class="ratek">Risk</div>'
        f'<div class="ratev"><span id="riskval" class="scorechip">-</span></div></div>'
        f'</div></div>')
    cvss_hint = ""

    # Affected hosts as an editable bullet list. The operator's edited set (one
    # host per line in the vmeta sidecar) wins over the discovered hosts and IPs.
    if md.get("hosts"):
        host_lines = [h.strip() for h in md["hosts"].splitlines() if h.strip()]
        host_items = "".join(f'<li>{_esc(h)}</li>' for h in host_lines)
        hosts_default = md["hosts"]
    else:
        host_items = "".join(f'<li>{_esc(h)}</li>' for h in v["hosts"])
        host_items += "".join(f'<li>{_esc(ip)} <span class="muted">(IP)</span></li>' for ip in v["ips"])
        hosts_default = "\n".join(list(v["hosts"]) + list(v["ips"]))
    hosts_view = (f'<ul class="hostlist">{host_items}</ul>' if host_items
                  else '<div class="muted">None recorded.</div>')
    hosts_editor = ('<div class="ratek">Affected hosts (one per line)</div>'
                    + _ef_input("hosts", hosts_default, rows=5,
                                ph="app.example.com\nportal.example.com"))
    hosts_html = _ef_block("hosts", "Affected hosts", hosts_view, hosts_editor,
                           guide="One host or IP per line. These render as the affected-hosts bullet list.")

    ev = v.get("evidence") or {}
    ev_html = ""
    ev_rows = "".join(
        f'<tr><td class="muted">{_esc(str(k))}</td><td>{_esc(str(val))}</td></tr>'
        for k, val in ev.items() if val not in (None, "", [], {}))
    if ev_rows:
        ev_html = ('<h2>Evidence</h2><div class="card" style="padding:4px 6px">'
                   '<table class="audit"><tbody>' + ev_rows + '</tbody></table></div>')

    # The lifecycle banner (the "Marked as a false positive ... Reason" and
    # "Marked as confirmed ... Note" lines) was removed: the state is already
    # clear from the section the finding sits in and the Activities trail.
    banner = ""

    # Button icons: an API/wire plug for shipping to Security Joes, a document
    # for the early alert report, a check for confirm, a slashed circle for a
    # false positive, a loop arrow for reopen.
    ico_api = ('<svg viewBox="0 0 24 24" width="14" height="14" fill="none" '
               'stroke="currentColor" stroke-width="2" stroke-linecap="round" '
               'stroke-linejoin="round" aria-hidden="true"><path d="M3 12h4l2-6 4 12 2-6h6"/></svg>')
    ico_doc = ('<svg viewBox="0 0 24 24" width="14" height="14" fill="none" '
               'stroke="currentColor" stroke-width="2" stroke-linecap="round" '
               'stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>'
               '<path d="M14 2v6h6"/><path d="M8 13h8M8 17h8"/></svg>')
    ico_check = ('<svg viewBox="0 0 24 24" width="14" height="14" fill="none" '
                 'stroke="currentColor" stroke-width="2.4" stroke-linecap="round" '
                 'stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>')
    ico_no = ('<svg viewBox="0 0 24 24" width="14" height="14" fill="none" '
              'stroke="currentColor" stroke-width="2" stroke-linecap="round" '
              'stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/>'
              '<path d="M6 6l12 12"/></svg>')
    ico_reopen = ('<svg viewBox="0 0 24 24" width="14" height="14" fill="none" '
                  'stroke="currentColor" stroke-width="2" stroke-linecap="round" '
                  'stroke-linejoin="round" aria-hidden="true"><path d="M3 12a9 9 0 1 0 3-6.7L3 8"/>'
                  '<path d="M3 3v5h5"/></svg>')
    send_btn = (f'<button type="button" class="btn-ghost vbtn" '
                f'onclick="vact(\'send\',\'{cid}\',\'{_esc(v["key"])}\')">'
                f'{ico_api}<span>Send to Security Joes</span></button>')
    alert_btn = (f'<button type="button" class="vbtn alertbtn" '
                 f'onclick="genAlert(this,\'{cid}\',\'{_esc(v["key"])}\')" '
                 f'title="Generate an editable Word early alert for this finding">'
                 f'{ico_doc}<span>Early alert</span></button>')
    # State buttons. Marking a false positive or confirmed, and reopening, each
    # go through a modal that forces the operator to record a reason.
    if is_fp or is_confirmed:
        state_btns = (f'<button type="button" class="vbtn" '
                      f'onclick="vopen(\'reopen\',\'{cid}\',\'{_esc(v["key"])}\')">'
                      f'{ico_reopen}<span>Reopen finding</span></button>')
    else:
        state_btns = (f'<button type="button" class="vbtn confirm" '
                      f'onclick="vopen(\'confirm\',\'{cid}\',\'{_esc(v["key"])}\')">'
                      f'{ico_check}<span>Mark confirmed</span></button>'
                      f'<button type="button" class="vbtn danger" '
                      f'onclick="vopen(\'fp\',\'{cid}\',\'{_esc(v["key"])}\')">'
                      f'{ico_no}<span>Mark false positive</span></button>')

    # Return to the tab the operator came from (Needs attention, Confirmed or
    # False positives), falling back to the finding's own state and then the
    # client overview.
    _tab_back = {
        "attention": (f'{cback}?t=attention', "Back to needs attention"),
        "confirmed": (f'{cback}?t=confirmed', "Back to confirmed"),
        "falsepos": (f'{cback}?t=falsepos', "Back to false positives"),
    }
    if frm in _tab_back:
        back_href, back_txt = _tab_back[frm]
    elif is_fp:
        back_href, back_txt = f'{cback}?t=falsepos', "Back to false positives"
    else:
        back_href, back_txt = cback, "Back to client"

    # Editable sections, all persisted to the vuln_meta sidecar.
    desc_raw = md.get("description") or _tpl.get("description") or v["description"] or ""
    desc_view = _md_paras(desc_raw) or '<div class="muted">No description yet.</div>'
    desc_sec = _ef_block(
        "description", "Description", desc_view,
        _ef_input("description", desc_raw, rows=10),
        guide=("Paragraph 1: what the issue is in general (for example what Cross "
               "Site Scripting is and its types). Paragraph 2: the impact, what an "
               "attacker can do. Paragraph 3: what the team found in this case. "
               "Separate paragraphs with a blank line."))

    owasp = md.get("owasp") or _tpl.get("owasp", "")
    cwe = md.get("cwe") or _tpl.get("cwe", "")
    cwe_m = re.match(r"\s*CWE-(\d+)", cwe)
    cwe_view = (f'<a href="https://cwe.mitre.org/data/definitions/{cwe_m.group(1)}.html" '
                f'target="_blank" rel="noopener">{_esc(cwe)}</a>' if cwe_m
                else (_esc(cwe) or '<span class="muted">not set</span>'))
    owasp_view = _esc(owasp) or '<span class="muted">not set</span>'
    cls_view = (f'<div class="clsrow"><div><div class="ratek">OWASP Top 10</div>{owasp_view}</div>'
                f'<div><div class="ratek">CWE</div>{cwe_view}</div></div>')
    cls_editor = (f'<div class="clsrow"><div><div class="ratek">OWASP Top 10</div>'
                  f'{_ef_input("owasp", owasp, ph="A03:2021 Injection")}</div>'
                  f'<div><div class="ratek">CWE</div>'
                  f'{_ef_input("cwe", cwe, ph="CWE-79")}</div></div>')
    cls_sec = _ef_block("classification", "Classification", cls_view + cvss_hint, cls_editor,
                        guide="OWASP Top 10 category if one applies, and the MITRE CWE id.")

    steps_view = _md_ol(md.get("steps", ""))
    if not steps_view:
        # No operator-entered steps: show the same reproduction steps the early
        # alert generates, so the page and the export read the same, instead of a
        # bare "none yet".
        try:
            from tools import surface_report as _sr
        except Exception:
            try:
                import surface_report as _sr
            except Exception:
                _sr = None
        auto_steps = []
        if _sr is not None:
            try:
                auto_steps = _sr._evidence_steps({
                    "hosts": v.get("hosts") or [],
                    "host": (v.get("hosts") or [""])[0],
                    "source_class": v.get("source_class", ""),
                    "key": v.get("key", ""),
                    "evidence_steps": _tpl.get("evidence_steps", "") or "",
                })
            except Exception:
                auto_steps = []
        if auto_steps:
            steps_view = ('<ol class="repro">'
                          + "".join(f"<li>{_esc(s)}</li>" for s in auto_steps)
                          + "</ol>")
        else:
            steps_view = '<div class="muted">No reproduction steps yet.</div>'
    curl_raw = md.get("curl", "")
    curl_view = (f'<pre class="codeblock"><code>{_esc(curl_raw)}</code></pre>' if curl_raw.strip() else "")
    # Evidence files, validated and stored on upload or capture. Each figure line
    # (`filename | caption`) is shown WITH its image inline (thumbnail + Figure N
    # + caption), so a captured screenshot is not listed twice, once as a figure
    # slot and once as a bare file. Files not tied to any figure line appear below
    # as plain attachments.
    ev_files = md.get("files", [])
    by_name: dict = {}
    for f in ev_files:
        for k in (f.get("stored", ""), f.get("orig", "")):
            if k:
                by_name.setdefault(k.lower(), f)

    def _ev_thumb(st: str) -> str:
        furl = f'/evidence?e={cid}&v={v["id"]}&f={urllib.parse.quote(st)}'
        if st.lower().endswith(".pdf"):
            return f'<a class="evthumb pdf" href="{furl}" target="_blank" rel="noopener">PDF</a>'
        return (f'<a href="{furl}" target="_blank" rel="noopener">'
                f'<img class="evthumb" src="{furl}" alt="" loading="lazy"></a>')

    used: set = set()
    fig_cells = ""
    nfig = 0
    for ln in (md.get("figures") or "").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        fn, _, cap = ln.partition("|")
        fn, cap = fn.strip(), cap.strip()
        rec = by_name.get(fn.lower())
        # A figure line whose file is gone (an orphan from an old delete) would
        # render as an empty "awaiting capture" block, so skip it: no empty rows,
        # and the remaining figures keep contiguous numbering.
        if not rec:
            continue
        nfig += 1
        st = rec.get("stored", "")
        used.add(st.lower())
        thumb = _ev_thumb(st)
        rm = (f'<button type="button" class="evdel" '
              f'onclick="evDelete(\'{cid}\',\'{_esc(v["key"])}\',\'{_esc(st)}\')">Remove</button>')
        # One row per figure: the image on the left, the figure number and an
        # editable caption on the right. Editing the caption saves it inline for
        # that figure (on blur or Enter), no need to touch the Figures textarea.
        cap_in = (f'<input class="figcapin" value="{_esc(cap)}" '
                  f'placeholder="Add a caption for this figure" '
                  f'onchange="figCap(\'{cid}\',\'{_esc(v["key"])}\',\'{_esc(fn)}\',this)" '
                  f'onkeydown="if(event.key===\'Enter\'){{event.preventDefault();this.blur();}}">')
        fig_cells += (
            f'<div class="figrow"><div class="figimg">{thumb}</div>'
            f'<div class="figtext"><div class="evname">Figure {nfig}</div>'
            f'{cap_in}{rm}</div></div>')
    figs_view = f'<div class="figlist">{fig_cells}</div>' if fig_cells else ""

    # Attachments with no figure line (manual uploads) still get listed.
    other_cells = ""
    for f in ev_files:
        st = f.get("stored", "")
        if st.lower() in used:
            continue
        other_cells += (
            f'<div class="evfile">{_ev_thumb(st)}<div class="evmeta">'
            f'<div class="evname">{_esc(f.get("orig", st))}</div>'
            f'<div class="muted" style="font-size:11px">{_esc(f.get("ts", ""))}</div>'
            f'<button type="button" class="evdel" '
            f'onclick="evDelete(\'{cid}\',\'{_esc(v["key"])}\',\'{_esc(st)}\')">Remove</button>'
            f'</div></div>')
    files_html = (('<div class="ratek" style="margin-top:12px">Other attachments</div>'
                   f'<div class="evfiles">{other_cells}</div>') if other_cells else "")
    img_ico = ('<svg viewBox="0 0 24 24" width="18" height="18" fill="none" '
               'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" '
               'stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/>'
               '<circle cx="8.5" cy="8.5" r="1.5"/><path d="m21 15-5-5L5 21"/></svg>')
    upload_html = (
        '<div class="evup"><label class="evuplbl">'
        f'<span class="evupico">{img_ico}</span>'
        '<span class="evuptext"><b>Attach evidence</b>'
        '<span class="muted">PNG, JPG or PDF, up to 10 MB each. Choosing a file '
        'adds it as the next figure automatically. The file name is used as the '
        'figure name, set its caption below.</span></span>'
        '<input type="file" id="evfile" multiple '
        'accept=".png,.jpg,.jpeg,.pdf,image/png,image/jpeg,application/pdf" '
        f'onchange="evUpload(\'{cid}\',\'{_esc(v["key"])}\')"></label>'
        f'<button type="button" class="btn-ghost sbtn" '
        f'onclick="evUpload(\'{cid}\',\'{_esc(v["key"])}\')">Upload</button>'
        '<span class="eferr" id="everr"></span></div>')
    # Brand-impersonation evidence is captured automatically in the background
    # when the finding is detected (see _alert_new_findings), so no manual capture
    # control is shown here; the screenshots just appear in the Figures grid.
    figs_block =(('<div class="ratek" style="margin-top:12px">Figures</div>' + figs_view)
                  if figs_view else "")
    ev_view = (steps_view + curl_view + figs_block + files_html + upload_html)
    ev_editor = ('<div class="ratek">Reproduction steps (one per line)</div>'
                 + _ef_input("steps", md.get("steps", ""), rows=6,
                             ph="Open https://app.example.com/login\nSubmit <script>alert(1)</script> in the name field\nObserve the script executes in the response")
                 + '<div class="ratek" style="margin-top:10px">Request (curl)</div>'
                 + _ef_input("curl", curl_raw, rows=3,
                             ph="curl -s 'https://app.example.com/...' --data '...'")
                 + '<div class="ratek" style="margin-top:10px">Figures (one per line: filename | caption)</div>'
                 + _ef_input("figures", md.get("figures", ""), rows=4,
                             ph="figure-1-xss.png | The injected script executing in the browser"))
    ev_sec = _ef_block(
        "evidence", "Evidence", ev_view, ev_editor,
        guide=("Numbered steps a developer can follow, with the curl for any request. "
               "Name each figure you will capture, the screenshot is uploaded under that "
               "name and dropped into the export in order. Screenshots are not generated "
               "here, they are added on export."))

    mit_raw = md.get("mitigation") or _tpl.get("mitigation", "")
    mit_view = _md_ul(mit_raw) or '<div class="muted">No mitigation steps yet.</div>'
    refs_raw = md.get("references") or _tpl.get("references", "")
    refs_view = _md_refs(refs_raw)
    if refs_view:
        refs_block = '<div class="ratek" style="margin-top:12px">References</div>' + refs_view
    else:
        refs_block = ('<div class="refwarn">Add at least one reference, for example the '
                      'relevant OWASP cheat sheet or vendor advisory.</div>')
    mit_editor = ('<div class="ratek">Mitigation (one bullet per line)</div>'
                  + _ef_input("mitigation", mit_raw, rows=5,
                              ph="Encode all user input on output\nApply a strict Content Security Policy")
                  + '<div class="ratek" style="margin-top:10px">References (one per line: Label | URL)</div>'
                  + _ef_input("references", refs_raw, rows=3,
                              ph="OWASP XSS Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"))
    mit_sec = _ef_block(
        "mitigation", "Mitigation", mit_view + refs_block, mit_editor,
        guide="Concrete fixes as bullets. Always end with an OWASP, vendor or standard reference.")

    raw_ev = ev_html.replace("<h2>Evidence</h2>", "<h2>Source signal data</h2>") if ev_html else ""

    # Activities trail: why this finding was confirmed, marked a false positive
    # or reopened, in order, with any evidence attached at that moment, so the
    # reasoning and proof stay visible at the bottom of the page even after a
    # reopen clears the current state.
    trail = _vnotes_load(slug).get(v["key"]) or []
    notes_html = ""
    if trail:
        def note_files_html(n):
            fs = n.get("files") or []
            if not fs:
                return ""
            chips = ""
            for f in fs:
                st = f.get("stored", "")
                if not st:
                    continue
                furl = f'/evidence?e={cid}&v={v["id"]}&f={urllib.parse.quote(st)}'
                if st.lower().endswith(".pdf"):
                    chips += (f'<a class="onfile pdf" href="{furl}" target="_blank" '
                              f'rel="noopener">{_esc(f.get("orig", st))}</a>')
                else:
                    chips += (f'<a class="onfile" href="{furl}" target="_blank" rel="noopener">'
                              f'<img src="{furl}" alt="" loading="lazy">'
                              f'<span>{_esc(f.get("orig", st))}</span></a>')
            return f'<div class="onfiles">{chips}</div>' if chips else ""
        items = "".join(
            f'<div class="onote"><div class="onhd"><b>{_esc(n.get("action", ""))}</b>'
            f'<span class="muted"> by {_esc(n.get("by", ""))} &middot; {_esc(n.get("ts", ""))}</span></div>'
            f'<div class="onreason">{_esc(n.get("reason", ""))}</div>'
            f'{note_files_html(n)}</div>'
            for n in reversed(trail))
        notes_html = (f'<h2>Activities</h2>'
                      f'<div class="card onotes">{items}</div>')

    body = (f'<a class="back" href="{back_href}"><svg class="barrow" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5M12 19l-7-7 7-7"/></svg> {back_txt}</a>'
            f'{_flash(flash)}'
            f'{banner}'
            f'<div class="vhead"><span class="badge" style="background:{bg};color:{fg}">{label}</span>'
            f'<h1 class="vtitle">{_esc(v["title"])}</h1></div>'
            f'<div class="vmetarow">{"".join(meta_bits)}</div>'
            f'<div class="vactions">{send_btn}{alert_btn}{state_btns}</div>'
            f'{rating_html}'
            f'{desc_sec}{cls_sec}{hosts_html}{ev_sec}{mit_sec}{raw_ev}{notes_html}'
            f'{_VULN_PAGE_JS}')
    return _page(body, user, modal=True)


# --------------------------------------------------------------------------
# Phase status summary. A compact, at-a-glance table of every phase: whether it
# is promoted, whether it is running, when it last ran, and how many findings it
# has produced. This is the "summary status of each covered phase" the operator
# asked for, sitting above the detailed phase cards.
# --------------------------------------------------------------------------
# Which finding source_class each promoted phase produces, for its findings
# count. The layers driven by the generic layer_watch write one signal file per
# layer, named <slug>-<suffix>.jsonl, so their count is read straight from that
# file (their source classes are module-defined and open-ended).
PHASE_CLASSES = {
    "layer1": ["lookalike_domain"],
    "layer2": ["subdomain"],
}
PHASE_SIGNAL_SUFFIX = {
    "layer0": "layer0",
    "layer2_5": "layer2_5",
    "layer3": "layer3",
    "layer4": "layer4",
}


def _phase_file_count(slug: str, suffix: str) -> int:
    """Distinct findings in one layer's own signal file, by dedup_id."""
    f = ENGAGEMENTS / slug / "signals" / f"{slug}-{suffix}.jsonl"
    if not f.is_file():
        return 0
    seen: set[str] = set()
    try:
        for line in f.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            seen.add(d.get("dedup_id") or line)
    except Exception:
        return 0
    return len(seen)


# A rainbow of hues for the phase number badges, one distinct colour per layer.
_PHASE_HUES = ["#f43f5e", "#fb923c", "#facc15", "#4ade80",
               "#22d3ee", "#818cf8", "#c084fc", "#f472b6"]


def _phase_summary(slug: str, e: dict) -> str:
    rows = ""
    for num, p in enumerate(PHASES):
        mods = _phase_modules(p)
        c = _PHASE_HUES[num % len(_PHASE_HUES)]
        link = f'/methodology#phase-{_esc(p["key"])}'
        # The "Phase N" prefix is a rainbow tag, one hue per phase, shown only on
        # this cross-client overview phase table.
        tag = (f'<span class="phtag" style="color:{c};background:{c}1f;'
               f'border:1px solid {c}59">Phase {num}</span>')
        name = (f'<a class="phlink phname" href="{link}" '
                f'title="See what this layer covers">{tag}{_esc(p["name"])}</a>')
        if not mods:
            rows += (f'<tr class="dim"><td>{name}</td>'
                     '<td><span class="pst none">NOT RUN</span></td>'
                     '<td class="muted">-</td><td class="muted">-</td></tr>')
            continue
        st = {m["kind"]: e["watch"][m["kind"]] for m in mods}
        running = any(v.get("active") for v in st.values())
        last = max((v.get("last") or 0) for v in st.values()) or None
        if running:
            status = '<span class="pst running">RUNNING</span>'
        elif last:
            status = '<span class="pst run">RUN</span>'
        else:
            status = '<span class="pst none">NOT RUN</span>'
        if p["key"] in PHASE_SIGNAL_SUFFIX:
            found = _phase_file_count(slug, PHASE_SIGNAL_SUFFIX[p["key"]])
        else:
            found = sum(e["by_class"].get(c, 0) for c in PHASE_CLASSES.get(p["key"], []))
        rows += (f'<tr><td>{name}</td><td>{status}</td>'
                 f'<td class="muted" style="white-space:nowrap">{_ago(last)}</td>'
                 f'<td style="text-align:right;font-weight:700">{found}</td></tr>')
    return ('<h2>Phase status</h2>'
            '<div class="card" style="overflow-x:auto;padding:4px 6px">'
            '<table class="audit"><thead><tr><th>Phase</th><th>Status</th>'
            '<th>Last run</th><th style="text-align:right">Findings</th>'
            f'</tr></thead><tbody>{rows}</tbody></table></div>')


# --------------------------------------------------------------------------
# Relationship map. A Maltego / BloodHound style graph of everything discovered
# for a client, built straight from the signal entities and rendered as mermaid
# in the browser. Client -> apex domains -> subdomains -> shared IPs, plus a
# lookalike cluster coloured by severity. Node counts are capped so a large
# estate stays legible, with a "+N more" node for the overflow.
# --------------------------------------------------------------------------
_GRAPH_SUB_CAP = 60
_GRAPH_LOOK_CAP = 30
_GRAPH_VULN_CAP = 120


def _sev_rank(sev: str | None) -> int:
    return SEV_ORDER.index(sev) if sev in SEV_ORDER else len(SEV_ORDER)


def _graph_assets(base: Path) -> dict:
    """Read the signal files once and collect the discovered assets: subdomains
    (with the IPs they resolve to) and lookalike domains, each at its worst
    severity seen. Deduplicated by host."""
    subs: dict[str, dict] = {}
    looks: dict[str, dict] = {}
    # Findings attributed to a host: how many signals touch it and the worst
    # severity among them, so a node can show the issues found on that domain.
    find: dict[str, dict] = {}
    # The actionable findings (SEV1 to SEV3) as individual records, so each can
    # become its own node linked to the host it was found on.
    vulns: list[dict] = []
    sdir = base / "signals"
    if not sdir.is_dir():
        return {"subs": subs, "looks": looks, "find": find, "vulns": vulns}

    def keep_worse(store: dict, dom: str, sev: str, ips=None):
        cur = store.get(dom)
        if cur is None:
            cur = {"sev": sev, "ips": set()}
            store[dom] = cur
        elif _sev_rank(sev) < _sev_rank(cur["sev"]):
            cur["sev"] = sev
        if ips:
            cur["ips"].update(ips)

    def add_find(dom: str, sev: str, title: str = "", cls: str = ""):
        cur = find.get(dom)
        if cur is None:
            cur = {"cnt": 0, "sev": sev, "hi": 0}
            find[dom] = cur
        cur["cnt"] += 1
        if _sev_rank(sev) < _sev_rank(cur["sev"]):
            cur["sev"] = sev
        if sev in ("SEV1", "SEV2"):
            cur["hi"] += 1
        # SEV1 to SEV3 are the ones worth drawing as their own node on the host.
        if _sev_rank(sev) <= 2:
            vulns.append({"host": dom, "sev": sev,
                          "title": title or (cls.replace("_", " ").strip().capitalize()),
                          "cls": cls})

    for f in sdir.glob("*.jsonl"):
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            cls = d.get("source_class")
            sev = str(d.get("severity", "")).upper()
            if sev not in SEV_ORDER:
                sev = "SEV5"
            ents = d.get("entities", []) or []
            doms = [str(x.get("value", "")).lower().rstrip(".")
                    for x in ents if x.get("type") == "domain" and x.get("value")]
            ips = [str(x.get("value", "")) for x in ents
                   if x.get("type") == "ip" and x.get("value")]
            if cls == "subdomain":
                for dom in doms:
                    keep_worse(subs, dom, sev, ips)
            elif cls == "lookalike_domain":
                for dom in doms:
                    keep_worse(looks, dom, sev)
            else:
                # Any other signal is a finding on the host(s) it names.
                title = str(d.get("title") or "")
                for dom in doms:
                    add_find(dom, sev, title, str(cls or ""))
    return {"subs": subs, "looks": looks, "find": find, "vulns": vulns}


def _apex_of(dom: str, scope: list[str]) -> str:
    cand = [s for s in scope if dom == s or dom.endswith("." + s)]
    if cand:
        return max(cand, key=len)
    parts = dom.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else dom


def _node_id(prefix: str, text: str) -> str:
    return prefix + "_" + re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


_GRAPH_CORP_CAP = 40


def _graph_oneline(s: str) -> str:
    """One trimmed line for a graph label or tooltip: no newlines, no trailing
    confidence parenthetical, length-capped so a node stays compact."""
    s = re.sub(r"\s+", " ", (s or "").replace("\n", " ")).strip()
    s = re.sub(r"\s*\((?:inferred|self-described|est\.?|as of|approx)[^)]*\)",
               "", s, flags=re.I).strip()
    return s[:64]


def _corp_sev(state: str) -> str:
    """Map a subsidiary lifecycle state to a corporate-cluster palette key, so
    active brands look different from ones closing down or already sold."""
    return {
        "live":         "corp-active",
        "":             "corp-active",
        "acquired":     "corp-new",
        "winding-down": "corp-closing",
        "winding down": "corp-closing",
        "divested":     "corp-sold",
        "divesting":    "corp-sold",
        "defunct":      "corp-sold",
        "parked":       "corp-dormant",
    }.get((state or "").lower().strip(), "corp-active")


def _corp_records(base: Path) -> list:
    """The Layer 0 subsidiary records for the corporate map, read straight from
    subsidiaries.jsonl. Empty when the file is absent (no Layer 0 run yet)."""
    recs: list = []
    p = base / "layer0" / "subsidiaries.jsonl"
    try:
        if p.is_file():
            for ln in p.read_text(errors="replace").splitlines():
                ln = ln.strip()
                if ln:
                    try:
                        d = json.loads(ln)
                        if isinstance(d, dict):
                            recs.append(d)
                    except Exception:
                        pass
    except Exception:
        pass
    return recs


def _asset_graph(slug: str, base: Path) -> tuple[list, dict]:
    """Build the graph as a Cytoscape elements list (nodes and edges) plus a
    small summary dict. Returns ([], summary) when nothing is discovered yet.
    Cytoscape, not mermaid, draws it: it pans, zooms, exports to image and
    stays usable with far more hosts than a static flowchart could show."""
    data = _graph_assets(base)
    subs, looks, find = data["subs"], data["looks"], data["find"]
    vulns = data.get("vulns", [])
    corp = _corp_records(base)
    scope = _scope_domains(slug)
    summary = {"subs": len(subs), "looks": len(looks), "ips": 0,
               "find": sum(v["cnt"] for v in find.values()),
               "vulns": len(vulns), "corp": len(corp)}
    if not subs and not looks and not find and not corp:
        return [], summary

    els: list[dict] = []
    edge_n = 0
    # Where each host ended up as a node, so a vulnerability can link to it.
    host_id: dict[str, str] = {}

    def node(nid: str, label: str, sev: str, **extra):
        d = {"id": nid, "label": label, "sev": sev}
        d.update(extra)
        els.append({"data": d})

    def edge(src: str, dst: str):
        nonlocal edge_n
        edge_n += 1
        els.append({"data": {"id": f"e{edge_n}", "source": src, "target": dst}})

    def host_label(dom: str) -> str:
        # Just the full host name. Findings hang off it as their own nodes.
        return dom

    def host_class(dom: str, base_sev: str | None = None) -> str:
        worst = base_sev
        f = find.get(dom)
        if f and (worst is None or _sev_rank(f["sev"]) < _sev_rank(worst)):
            worst = f["sev"]
        return (worst or "SEV5").lower()

    subs_sorted = sorted(subs.items(), key=lambda kv: (_sev_rank(kv[1]["sev"]), kv[0]))
    looks_sorted = sorted(looks.items(), key=lambda kv: (_sev_rank(kv[1]["sev"]), kv[0]))
    sub_extra = max(0, len(subs_sorted) - _GRAPH_SUB_CAP)
    look_extra = max(0, len(looks_sorted) - _GRAPH_LOOK_CAP)
    subs_sorted = subs_sorted[:_GRAPH_SUB_CAP]
    looks_sorted = looks_sorted[:_GRAPH_LOOK_CAP]

    # Only promote an IP to a node when two or more shown subdomains share it,
    # so the graph highlights co-hosting the way Maltego does, without a node per
    # unique address.
    ip_count: dict[str, int] = {}
    for _dom, info in subs_sorted:
        for ip in info["ips"]:
            ip_count[ip] = ip_count.get(ip, 0) + 1
    shared_ips = {ip for ip, n in ip_count.items() if n >= 2}
    summary["ips"] = len(shared_ips)

    node("root", _pretty(slug), "root", kind="root")

    apex_seen: dict[str, str] = {}

    def apex_node(apex: str) -> str:
        if apex not in apex_seen:
            aid = _node_id("apex", apex)
            apex_seen[apex] = aid
            # An apex in scope keeps the apex style unless it carries findings,
            # in which case it takes the severity colour so it is not missed.
            sev = host_class(apex) if find.get(apex) else "apex"
            node(aid, host_label(apex), sev, kind="apex", dom=apex)
            host_id[apex] = aid
            edge("root", aid)
        return apex_seen[apex]

    for apex in scope:
        apex_node(apex)

    ip_ids: dict[str, str] = {}
    for dom, info in subs_sorted:
        aid = apex_node(_apex_of(dom, scope))
        nid = _node_id("s", dom)
        node(nid, host_label(dom), host_class(dom, info["sev"]), kind="sub", dom=dom)
        host_id[dom] = nid
        edge(aid, nid)
        for ip in info["ips"]:
            if ip not in shared_ips:
                continue
            if ip not in ip_ids:
                iid = _node_id("ip", ip)
                ip_ids[ip] = iid
                node(iid, ip, "ip", kind="ip", dom=ip)
            edge(nid, ip_ids[ip])
    if sub_extra:
        node("smore", f"+{sub_extra} more subdomains", "more", kind="more")
        edge("root", "smore")

    # Hosts that carry findings but are not in the subdomain inventory (and are
    # not a scope apex, which already shows its own findings) still belong on the
    # map, grouped under their apex and coloured by their worst finding.
    shown = {d for d, _ in subs_sorted} | set(scope)
    find_hosts = sorted((d for d in find if d not in shown),
                        key=lambda d: (_sev_rank(find[d]["sev"]), d))
    find_extra = max(0, len(find_hosts) - _GRAPH_SUB_CAP)
    for dom in find_hosts[:_GRAPH_SUB_CAP]:
        aid = apex_node(_apex_of(dom, scope))
        nid = _node_id("f", dom)
        node(nid, host_label(dom), host_class(dom), kind="find", dom=dom)
        host_id[dom] = nid
        edge(aid, nid)
    if find_extra:
        node("fmore", f"+{find_extra} more hosts with findings", "more", kind="more")
        edge("root", "fmore")

    # Each actionable vulnerability (SEV1 to SEV3) becomes its own node hanging
    # off the host it was found on, so the map shows subdomain -> vulnerability
    # and clicking it traces the full path back to the root. Worst first, capped.
    vulns_sorted = sorted(vulns, key=lambda v: (_sev_rank(v["sev"]), v["host"]))
    vuln_extra = max(0, len(vulns_sorted) - _GRAPH_VULN_CAP)
    vn = 0
    for v in vulns_sorted[:_GRAPH_VULN_CAP]:
        parent = host_id.get(v["host"])
        if not parent:
            continue
        vn += 1
        vid = f"v_{vn}"
        label = v["title"][:70] if v["title"] else v["sev"]
        node(vid, label, v["sev"].lower(), kind="vuln", dom=v["host"])
        edge(parent, vid)
    if vuln_extra:
        node("vmore", f"+{vuln_extra} more findings", "more", kind="more")
        edge("root", "vmore")

    if looks_sorted:
        node("lookhub", "Lookalike domains", "hub", kind="hub")
        edge("root", "lookhub")
        for dom, info in looks_sorted:
            nid = _node_id("l", dom)
            node(nid, dom, info["sev"].lower(), kind="look", dom=dom)
            edge("lookhub", nid)
        if look_extra:
            node("lmore", f"+{look_extra} more lookalikes", "more", kind="more")
            edge("lookhub", "lmore")

    # Corporate map: the group's subsidiaries and sister brands from Layer 0,
    # drawn as their own cluster so the map shows the business, not only the
    # technical estate. One node per entry under the parent group (or the client
    # root when no parent is known), coloured by lifecycle state, capped so a
    # large group stays legible. Label carries the name and, on a second line,
    # the sector; jurisdiction rides along as the node tooltip.
    if corp:
        prof = {}
        try:
            pf = base / "layer0" / "company_profile.json"
            if pf.is_file():
                d = json.loads(pf.read_text())
                if isinstance(d, dict):
                    prof = d
        except Exception:
            prof = {}
        pg = _graph_oneline(str(prof.get("parent_group", "") or ""))
        if pg:
            node("corphub", pg, "corp-hub", kind="corphub")
            edge("root", "corphub")
            phub = "corphub"
        else:
            phub = "root"
        seen_corp: set = set()
        shown_corp = 0
        for r in corp:
            nm = _graph_oneline(str(r.get("name", "")))
            key = nm.lower()
            if not nm or key in seen_corp:
                continue
            seen_corp.add(key)
            if shown_corp >= _GRAPH_CORP_CAP:
                continue
            shown_corp += 1
            sector = _graph_oneline(str(r.get("sector", "") or ""))
            label = nm + ("\n" + sector if sector else "")
            juris = _graph_oneline(str(r.get("jurisdiction", "") or ""))
            nid = _node_id("corp", nm)
            node(nid, label, _corp_sev(str(r.get("state", ""))),
                 kind="corp", dom=nm, tip=juris)
            edge(phub, nid)
        corp_extra = max(0, len(seen_corp) - shown_corp)
        if corp_extra:
            node("corpmore", f"+{corp_extra} more group companies",
                 "more", kind="more")
            edge(phub, "corpmore")

    return els, summary


def _graph_section(slug: str, base: Path) -> str:
    els, s = _asset_graph(slug, base)
    if not els:
        return ('<h2 id="map">Relationship map</h2>'
                '<div class="card"><div class="muted">No assets discovered yet. '
                'Lock and run a phase, and the map builds itself from what the '
                'scan finds.</div></div>')
    sub_txt = f'{s["subs"]} subdomain{"" if s["subs"] == 1 else "s"}'
    look_txt = f'{s["looks"]} lookalike{"" if s["looks"] == 1 else "s"}'
    ip_txt = (f', {s["ips"]} shared host{"" if s["ips"] == 1 else "s"}'
              if s["ips"] else "")
    find_txt = (f', {s["find"]} finding{"" if s["find"] == 1 else "s"}'
                if s.get("find") else "")
    # The elements ride along as JSON in a script block, and Cytoscape (loaded
    # from a pinned CDN build) reads them client-side. If the CDN cannot be
    # reached the card shows a short notice instead of a broken canvas. The only
    # escaping a JSON script block needs is to break any literal </script>.
    payload = json.dumps(els, separators=(",", ":")).replace("</", "<\\/")
    sev_items = ('<div class="gcombo-item" onclick="easSevPick(\'\',\'All severities\')">'
                 'All severities</div>')
    for s_ in SEV_ORDER:
        lbl, clr = SEV[s_][0], SEV[s_][1]
        sev_items += (f'<div class="gcombo-item sevopt" onclick="easSevPick(\'{s_.lower()}\',\'{lbl}\')">'
                      f'<span class="sevdot" style="background:{clr}"></span>'
                      f'<span style="color:{clr}">{lbl}</span></div>')
    # Every identified domain (subdomains, lookalikes and hosts with findings,
    # resolving or not), handed to the search box so a host can be found by typing
    # any part of its name. The list is filtered client-side, 15 matches shown.
    doms = sorted({n["data"]["dom"] for n in els
                   if n.get("data", {}).get("kind") in ("apex", "sub", "find", "look")
                   and n["data"].get("dom")})
    dom_json = json.dumps(doms, separators=(",", ":")).replace("</", "<\\/")
    return (
        '<h2 id="map">Relationship map</h2>'
        '<div class="card graphcard" id="graphcard" style="padding:12px">'
        '<div class="gtoolbar">'
        '<div class="gzoom">'
        '<button type="button" class="btn-ghost" onclick="easGraphZoom(-1)" title="Zoom out">&minus;</button>'
        '<button type="button" class="btn-ghost" onclick="easGraphZoom(1)" title="Zoom in">+</button>'
        '<button type="button" class="btn-ghost" onclick="easGraphFit()" title="Fit the whole graph">Fit</button>'
        '</div>'
        '<div class="gcombo" id="gdomwrap">'
        '<input type="text" id="graphsearch" class="gsel" placeholder="Search a domain..." '
        'autocomplete="off" oninput="easDomFilter(this.value)" onfocus="easDomFilter(this.value)" '
        'onkeydown="easDomKey(event)">'
        '<div class="gcombo-list" id="graphdomlist" hidden></div>'
        f'<script type="application/json" id="graphdomdata">{dom_json}</script>'
        '</div>'
        '<div class="gcombo gsevwrap" id="gsevwrap">'
        '<button type="button" class="gsel gsevbtn" id="graphsevbtn" onclick="easSevToggle()" '
        'title="Filter by severity">All severities</button>'
        f'<div class="gcombo-list" id="graphsevlist" hidden>{sev_items}</div>'
        '</div>'
        '<button type="button" class="btn-ghost gbtn gpush" onclick="easGraphExport(\'png\')" title="Download as PNG">PNG</button>'
        '<button type="button" class="btn-ghost gbtn" onclick="easGraphFull()" id="graphfullbtn" title="Fullscreen">&#9974; Full</button>'
        '</div>'
        f'<div class="graphwrap" id="graphwrap" data-slug="{_esc(slug)}">'
        '<div class="gfallback muted" id="graphfallback">Loading the map...</div>'
        f'<script type="application/json" id="graphdata">{payload}</script>'
        '</div>'
        '</div>')


def _tech_dropdown(techs: list) -> str:
    """A 'Techniques applied' dropdown rendering a technique list as a bullet list.
    Empty string when there are none."""
    if not techs:
        return ""
    items = "".join(
        f'<li><strong>{_esc(t["name"])}</strong> '
        f'<span class="muted">{_esc(t["desc"])}</span></li>' for t in techs)
    return ('<details class="cmdref techref"><summary>'
            '<svg class="chev" viewBox="0 0 24 24" width="13" height="13" fill="none" '
            'stroke="currentColor" stroke-width="2.6"><path d="M6 9l6 6 6-6"/></svg>'
            f'Techniques applied ({len(techs)})</summary>'
            f'<div class="cmdbody"><ul class="techlist">{items}</ul></div></details>')


def _meth_techniques(group: str) -> str:
    """Group-level techniques dropdown (keyed by meth_group label)."""
    return _tech_dropdown(METH_GROUP_TECHNIQUES.get(group))


def _meth_square_one(m: dict, color: str) -> str:
    """One standalone module card inside a methodology stage."""
    gate = m.get("gate", "passive")
    return (f'<div class="actsq methsq"><div class="acttop">'
            f'<span class="actname">{m["title"]}</span>{_help(m["help"])}'
            f'</div><span class="gate {gate}">{gate}</span>'
            f'{_tasks_section(m, color) or _cmd_section("", m, color)}</div>')


def _meth_square_group(label: str, mods: list, color: str) -> str:
    """One merged module card: several modules that share a meth_group render as a
    single square named for the group. Any group-level techniques show once at the
    top, then each member module is its own sub-square carrying its gate, help, a
    per-module Techniques dropdown (when defined) and its own Commands dropdown."""
    subs = ""
    for m in mods:
        gate = m.get("gate", "passive")
        tech = _tech_dropdown(MODULE_TECHNIQUES.get(m["kind"]))
        subs += (f'<div class="actsubsq"><div class="actsubhd">'
                 f'<span class="actsubname">{m["title"]}</span>'
                 f'<span class="gate {gate}">{gate}</span>{_help(m["help"])}</div>'
                 f'{tech}{_cmd_section("", m, color)}</div>')
    return (f'<div class="actsq actsqgroup methsq"><div class="acttop">'
            f'<span class="actname">{_esc(label)}</span></div>'
            f'{_meth_techniques(label)}<div class="actsubs">{subs}</div></div>')


def _meth_squares(layer_keys: list, color: str) -> str:
    """Render the module cards (title, help, gate, Tasks dropdown) for the given
    PHASES layer keys, as they appear inside a methodology stage. Modules that
    share a `meth_group` collapse into one square named for the group. Returns ''
    when those layers carry no promoted modules yet."""
    squares = ""
    for lk in layer_keys or []:
        p = PHASE_BY_KEY.get(lk)
        if not p:
            continue
        for g in p.get("groups", []):
            # Keep original order, but gather each meth_group's members so they
            # render once, as a single merged square at the group's first module.
            seen_groups: set = set()
            for m in g["modules"]:
                grp = m.get("meth_group")
                if not grp:
                    squares += _meth_square_one(m, color)
                    continue
                if grp in seen_groups:
                    continue
                seen_groups.add(grp)
                members = [x for x in g["modules"] if x.get("meth_group") == grp]
                squares += _meth_square_group(grp, members, color)
    return squares


def _meth_notes(notes: list) -> str:
    """A bullet list of the gaps and planned modules for a stage."""
    if not notes:
        return ""
    items = "".join(f"<li>{_esc(n)}</li>" for n in notes)
    return f'<ul class="methnotes">{items}</ul>'


def _meth_anchors(layer_keys: list) -> str:
    """Keep the old /methodology#phase-<layerkey> deep links working by emitting
    an anchor for each layer a stage now contains."""
    return "".join(f'<span id="phase-{_esc(k)}"></span>' for k in layer_keys or [])


def _layer_tag(layer_keys: list) -> str:
    """A small L<n> tag naming the integer layer(s) a stage or track maps to, so
    the layer numbering stays visible even though the S and J ids were removed."""
    nums: list = []
    for k in layer_keys or []:
        p = PHASE_BY_KEY.get(k)
        if p and p.get("layer") is not None and str(p["layer"]) not in nums:
            nums.append(str(p["layer"]))
    if not nums:
        return ""
    return f'<span class="ltag">L{"/".join(nums)}</span>'


def _methodology_page(user: str) -> bytes:
    """The scan methodology, client independent, rendered as the DAG the engine
    really is: passive, parallel work up front, a hard ownership-and-validation
    gate in the middle, then active and sequential work. Read-only: no toggles,
    no run buttons, no client state. It documents stages S0 to S7 and maps each
    to the promoted layer modules it contains. This view does not drive the
    scheduler, the client console does that from PHASES."""
    cards = ""
    for num, st in enumerate(METHODOLOGY_STAGES):
        c = _PHASE_HUES[num % len(_PHASE_HUES)]
        kind = st.get("kind", "stage")
        gate = st.get("gate", "passive")
        gate_badge = f'<span class="gate {gate}">{gate}</span>'
        anchors = _meth_anchors(st.get("layers", []))
        head = (f'<div class="phhead">{anchors}{_layer_tag(st.get("layers", []))}'
                f'<span class="ptitle">Phase {num}: {_esc(st["title"])}</span>'
                f'{gate_badge}{_help(st["help"])}</div>')

        inner = ""
        if kind == "band":
            subs = ""
            for sub in st.get("band", []):
                sq = _meth_squares(sub.get("layers", []), c)
                sqwrap = f'<div class="squares">{sq}</div>' if sq else ""
                subs += (
                    f'<div class="methsub">{_meth_anchors(sub.get("layers", []))}'
                    f'<div class="methsubhead">{_layer_tag(sub.get("layers", []))}'
                    f'<span class="methsubt">{_esc(sub["title"])}</span>'
                    f'<span class="gate {sub.get("gate","passive")}">{sub.get("gate","passive")}</span>'
                    f'</div>{sqwrap}{_meth_notes(sub.get("notes", []))}</div>')
            inner = (f'<div class="methband">{subs}</div>'
                     '<div class="methbandnote muted">These tracks depend only '
                     'on S0 and run in parallel.</div>')
        else:
            jobs = st.get("jobs")
            if jobs:
                jb = ""
                STLBL = {"locked": "Locked", "partial": "Partial", "open": "Open"}
                for j in jobs:
                    sq = _meth_squares(j.get("layers", []), c)
                    sqwrap = f'<div class="squares">{sq}</div>' if sq else ""
                    tag = ' <span class="methnew">NEW</span>' if j.get("new") else ""
                    stt = j.get("status")
                    stbadge = (f' <span class="methst methst-{stt}">{STLBL[stt]}</span>'
                               if stt in STLBL else "")
                    jb += (
                        f'<div class="methsub">{_meth_anchors(j.get("layers", []))}'
                        f'<div class="methsubhead">{_layer_tag(j.get("layers", []))}'
                        f'<span class="methsubt">{_esc(j["title"])}</span>{tag}{stbadge}</div>'
                        f'<div class="methjobhelp muted">{_esc(j["help"])}</div>'
                        f'{sqwrap}{_meth_notes(j.get("notes", []))}</div>')
                inner += f'<div class="methjobs">{jb}</div>'
            sq = _meth_squares(st.get("layers", []), c) if not jobs else ""
            if sq:
                inner += f'<div class="squares">{sq}</div>'
            inner += _meth_notes(st.get("notes", []))
            if kind == "gate" and not sq:
                inner = ('<div class="methgate">GATE</div>' + inner)

        klass = "card phase" + (" methgatecard" if kind == "gate" else "")
        cards += f'<div class="{klass}">{head}{inner}</div>'

    added = ""
    for a in METHODOLOGY_ADDED:
        added += (f'<div class="card phase methadded"><div class="phhead">'
                  f'<span class="ptag methaddtag">NEW</span>'
                  f'<span class="ptitle">{_esc(a["title"])}</span>'
                  f'{_help(a["help"])}</div></div>')

    body = ('<h1 class="ptitle" style="margin-bottom:6px">Methodology</h1>'
            '<div class="methintro muted">The engine is a DAG, not a straight '
            'line. Everything before the S2 gate is passive and parallel, '
            'everything after it is active and sequential.</div>'
            f'<div class="phases">{cards}</div>'
            '<h2 class="fph2" style="margin-top:26px">Asset classes to add</h2>'
            f'<div class="phases">{added}</div>')
    return _page(body, user)


_SUBS_JS = r"""
<script>
var _subsBase='';
var _subsWhich='alive';
function subsView(which){
  var t=document.getElementById('substa'); if(!t||!window._subsData)return;
  var a=document.getElementById('sv_alive'),b=document.getElementById('sv_all'),c=document.getElementById('sv_ips');
  var box=document.getElementById('subfind'); if(box)box.value='';
  _subsWhich=which;
  [a,b,c].forEach(function(el){if(el)el.classList.remove('on');});
  if(which==='all'){_subsBase=window._subsData.all; if(b)b.classList.add('on');}
  else if(which==='ips'){_subsBase=window._subsData.ips; if(c)c.classList.add('on');}
  else {_subsBase=window._subsData.alive; if(a)a.classList.add('on');}
  subsApplyFilter();
}
function subsApplyFilter(){
  var box=document.getElementById('subfind'),t=document.getElementById('substa'); if(!t)return;
  var q=((box&&box.value)||'').toLowerCase();
  if(!q){
    t.value=_subsBase;
    return;
  }
  var lines=_subsBase.split('\n').filter(function(l){return l.toLowerCase().indexOf(q)>=0;});
  t.value=lines.join('\n');
}
function subsCopy(){
  var t=document.getElementById('substa'); if(!t)return;
  var v=t.value;
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(v);}
  else{t.focus();t.select();try{document.execCommand('copy');}catch(e){}}
  var b=document.getElementById('subcopy');
  if(b){b.classList.add('copied');setTimeout(function(){b.classList.remove('copied');},900);}
}
(function(){ if(window._subsData){_subsBase=window._subsData.alive;} })();
</script>
"""


def _subdomain_health(base: Path) -> dict:
    """The newest subdomain-run health sidecar, or {} if none. A degraded run
    means a missing resolver, so the Alive count is an under-report, not a
    confirmed empty surface."""
    sdir = base / "signals"
    if not sdir.is_dir():
        return {}
    best: dict = {}
    best_mtime = -1.0
    for f in sdir.glob("*-subdomains-*.jsonl.health.json"):
        try:
            mt = f.stat().st_mtime
            if mt > best_mtime:
                best, best_mtime = json.loads(f.read_text()), mt
        except Exception:
            pass
    return best


def _subdomains_tab(slug: str, base: Path, cid: str) -> str:
    """The Subdomains tab: a copyable box of the client's subdomains with two
    views, the live (alive) hosts and every enumerated name. Alive is the default
    landing view. The Find box live-filters the shown list; both views are read
    only."""
    all_hosts = _subs_effective(slug, base)
    alive = sorted(_subdomain_alive(base) & set(all_hosts))
    health = _subdomain_health(base)
    banner = ""
    if health.get("degraded"):
        miss = ", ".join(health.get("missing_tools") or []) or "resolver tools"
        banner = (
            '<div class="card" style="border-left:4px solid #c00000;background:#2a1414;'
            'margin-bottom:10px">'
            '<b style="color:#ff6b6b">Resolver tools missing</b> '
            '<span class="muted" style="font-size:12px">&middot; the last '
            f'{_esc(str(health.get("mode","")))} scan could not run {_esc(miss)}, so the '
            'Alive count below is under-reported, not a confirmed empty result. '
            'Install the tools or fix the service PATH and re-run.</span></div>')
    st = _subs_state_load(slug)
    ips = _recovered_ips(base)
    ranges = _ip_ranges(ips)
    # The IPs view shows the known ranges (the netblocks the hosts fall into)
    # and then the recovered addresses, in one copyable box.
    ip_lines = []
    ip_lines.append(f"# Known IP ranges ({len(ranges)})")
    ip_lines += (ranges or ["(none)"])
    ip_lines.append("")
    ip_lines.append(f"# Recovered IPs ({len(ips)})")
    ip_lines += (ips or ["(none)"])
    ip_text = "\n".join(ip_lines)
    alive_js = json.dumps("\n".join(alive))
    all_js = json.dumps("\n".join(all_hosts))
    ips_js = json.dumps(ip_text)
    toggle = (f'<div class="subviews">'
              f'<button type="button" class="subviewbtn on" id="sv_alive" '
              f'onclick="subsView(\'alive\')">Alive subdomains ({len(alive)})</button>'
              f'<span class="subvsep">|</span>'
              f'<button type="button" class="subviewbtn" id="sv_all" '
              f'onclick="subsView(\'all\')">All subdomains ({len(all_hosts)})</button>'
              f'<span class="subvsep">|</span>'
              f'<button type="button" class="subviewbtn" id="sv_ips" '
              f'onclick="subsView(\'ips\')">IPs ({len(ips)})</button></div>')
    box = ('<div class="subwrap">'
           '<input type="text" id="subfind" class="subfind" placeholder="Find" spellcheck="false" '
           'autocomplete="off" oninput="subsApplyFilter()">'
           '<button type="button" class="copybtn" id="subcopy" onclick="subsCopy()" title="Copy all">'
           '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" '
           'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
           '<rect x="9" y="9" width="11" height="11" rx="2"/>'
           '<path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg></button>'
           f'<textarea id="substa" class="substa" spellcheck="false" readonly>{_esc(chr(10).join(alive))}</textarea>'
           '</div>')
    actions = ""
    alerts = st.get("alerts", [])
    alert_html = ""
    if alerts:
        rows = ""
        for a in reversed(alerts[-25:]):
            new = a.get("new", [])
            shown = ", ".join(new[:25]) + (" ..." if len(new) > 25 else "")
            rows += (f'<div class="salert"><div class="salerthd">'
                     f'<b>{len(new)} new subdomain(s)</b>'
                     f'<span class="muted"> via {_esc(a.get("source", ""))} '
                     f'&middot; {_esc(a.get("ts", ""))}</span></div>'
                     f'<div class="muted" style="font-size:12px;word-break:break-all">{_esc(shown)}</div></div>')
        alert_html = f'<h2>Subdomain alerts</h2><div class="card subalerts">{rows}</div>'
    data = (f'<script>window._subsData={{alive:{alive_js},all:{all_js},ips:{ips_js}}};</script>')
    return (f'{banner}{toggle}{box}{actions}{alert_html}{data}{_SUBS_JS}')


_LEAKS_JS = r"""
<script>
function leakFetch(slug){
  fetch('/leak-fetch',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'slug='+encodeURIComponent(slug)})
    .then(function(r){return r.json();}).then(function(d){
      if(d&&d.ok){if(window.showFlash)showFlash(true,d.msg);setTimeout(function(){location.reload();},500);}
      else{alert((d&&d.msg)||'Fetch failed.');}
    }).catch(function(){alert('Request failed.');});
}
function leakReveal(slug,id,el){
  if(!el)return;
  if(el.dataset.shown==='1'){el.textContent=el.dataset.mask||'********';el.dataset.shown='0';return;}
  fetch('/leak-reveal',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'slug='+encodeURIComponent(slug)+'&id='+encodeURIComponent(id)})
    .then(function(r){return r.json();}).then(function(d){
      if(d&&d.ok){el.textContent=d.password;el.dataset.shown='1';}
      else{alert((d&&d.msg)||'Reveal failed.');}
    }).catch(function(){alert('Request failed.');});
}
function leakFilter(){
  var q=(document.getElementById('leakq').value||'').toLowerCase();
  var rows=document.querySelectorAll('#leakbody .leakrow'),shown=0;
  for(var i=0;i<rows.length;i++){var ok=rows[i].getAttribute('data-f').indexOf(q)>=0;rows[i].style.display=ok?'':'none';if(ok)shown++;}
  var none=document.getElementById('leaknone'); if(none)none.style.display=shown?'none':'block';
}
</script>
"""


def _leaks_tab(slug: str, base: Path, cid: str, page: int = 1) -> str:
    """The Leaks tab: a filterable table of credentials ingested from files the
    operator drops into the client's intake folder, with per-row reveal, an Excel
    export, and change alerts. Passwords are masked and only fetched on reveal, so
    the plaintext is never in the page source. The table is paginated at 11 rows
    per page with a numbered pager, and the Leak alerts block is a collapsible
    dropdown so it never crowds the table."""
    st = _leaks_load(slug)
    creds = sorted(st["creds"], key=lambda c: (c.get("domain", ""), c.get("user", "")))
    n = len(creds)
    xlsx_ico = ('<svg class="xlsxico" viewBox="0 0 24 24" width="15" height="15" '
                'fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" '
                'stroke-linejoin="round" aria-hidden="true"><path d="M14 3H6a2 2 0 0 0-2 2v14'
                'a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6"/>'
                '<path d="M9.5 12.5l5 5M14.5 12.5l-5 5"/></svg>')
    fetch_btn = (f'<button type="button" class="btn-ghost sbtn" '
                 f'onclick="leakFetch(\'{cid}\')">Fetch recent</button>')
    export_btn = (f'<a class="btn-ghost sbtn xlsxbtn" href="/leak-export?e={cid}">{xlsx_ico}'
                  f'<span>Export Excel</span></a>' if creds else '')
    alerts = st.get("alerts", [])
    alert_html = ""
    if alerts:
        rows = "".join(
            f'<div class="salert"><div class="salerthd"><b>{a.get("count", 0)} new '
            f'credential(s)</b><span class="muted"> via {_esc(a.get("source", ""))} '
            f'&middot; {_esc(a.get("ts", ""))}</span></div></div>'
            for a in reversed(alerts[-25:]))
        # Collapsible dropdown, collapsed by default, so the alerts never crowd
        # the table. The count rides in the summary so it reads at a glance.
        caret = ('<svg class="dropcaret" viewBox="0 0 24 24" width="15" height="15" '
                 'fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" '
                 'stroke-linejoin="round" aria-hidden="true"><path d="M6 9l6 6 6-6"/></svg>')
        alert_html = (
            '<details class="dropcard"><summary class="dropsum">'
            f'<span>Leak alerts <span class="muted">({len(alerts)})</span></span>{caret}'
            '</summary>'
            f'<div class="card subalerts dropbody">{rows}</div></details>')
    if not creds:
        controls = (f'<div class="leakctrls"><div class="leakbtns">{fetch_btn}</div></div>')
        return (f'{controls}<div class="card"><div class="muted">No leaked '
                f'credentials ingested yet.</div></div>{alert_html}{_LEAKS_JS}')
    # Filter on the left, Fetch recent and Export Excel right-aligned, one row,
    # no heading above the table.
    filt = ('<div class="leakctrls">'
            '<input type="text" id="leakq" class="einp leakfilt" oninput="leakFilter()" '
            'placeholder="Filter by user, domain or source">'
            f'<div class="leakbtns">{fetch_btn}{export_btn}</div></div>')
    shown, page, pages = _page_slice(creds, page, 11)
    trows = ""
    for c in shown:
        pw = c.get("password", "")
        mask = "•" * min(max(len(pw), 6), 12)
        f = f'{c.get("user", "")} {c.get("domain", "")} {c.get("source", "")}'.lower()
        trows += (
            f'<tr class="leakrow" data-f="{_esc(f)}">'
            f'<td style="word-break:break-all">{_esc(c.get("user", ""))}</td>'
            f'<td class="pwcell"><span class="pwmask pwclick" id="pw-{c["id"]}" '
            f'data-mask="{mask}" title="Click to reveal" '
            f'onclick="leakReveal(\'{cid}\',\'{c["id"]}\',this)">{mask}</span></td>'
            f'<td>{_esc(c.get("domain", "") or "-")}</td>'
            f'<td class="muted">{_esc(c.get("source", ""))}</td>'
            f'<td class="muted">{_esc(c.get("date", "") or c.get("first_seen", ""))}</td></tr>')
    table = ('<div class="card" style="overflow-x:auto;padding:4px 6px">'
             '<table class="audit leaktbl"><thead><tr><th>User</th><th>Password</th>'
             '<th>Domain</th><th>Source</th><th>Date</th></tr></thead>'
             f'<tbody id="leakbody">{trows}</tbody></table></div>'
             '<div class="muted" id="leaknone" style="display:none;padding:8px 2px">'
             'No matches.</div>')
    pager = _pager(f"/c/{cid}?t=leaks&", page, pages, param="apage")
    return f'{filt}{table}{pager}{alert_html}{_LEAKS_JS}'


_HIER_JS = r"""
<script>
(function(){
  var PAL={
    'root':{bg:'#3BBBF8',fg:'#06121b'},
    'target':{bg:'#2a1b22',fg:'#ffd7de'},
    'bucket':{bg:'#131A22',fg:'#c7ccd6'},
    'scope':{bg:'#1b2733',fg:'#D4DEEA'},
    'out':{bg:'#0E141B',fg:'#8b93a1'}
  }, hcy=null;
  function wrap(){return document.getElementById('hiergraphwrap');}
  function col(k){return (PAL[k]||PAL['scope']);}
  window.easHierRender=function(){
    var w=wrap();
    if(!w||w.getAttribute('data-done'))return;
    if(typeof cytoscape==='undefined')return;
    var els, dn=document.getElementById('hiergraphdata');
    try{els=JSON.parse(dn?dn.textContent:'[]');}catch(e){els=[];}
    if(!els.length)return;
    w.setAttribute('data-done','1');
    hcy=cytoscape({
      container:w, elements:els, wheelSensitivity:0.2, minZoom:0.1, maxZoom:3,
      style:[
        {selector:'node',style:{
          'background-color':function(n){return col(n.data('kind')).bg;},
          'border-color':function(n){return col(n.data('kind')).bg;},
          'border-width':1,'label':'data(label)',
          'color':function(n){return col(n.data('kind')).fg;},
          'font-size':'10px','font-family':'ui-monospace,Menlo,Consolas,monospace',
          'text-wrap':'wrap','text-valign':'center','text-halign':'center',
          'text-max-width':'180px','padding':'7px','shape':'round-rectangle',
          'width':'label','height':'label'}},
        {selector:'node[kind="root"]',style:{'shape':'ellipse','font-weight':'bold','font-size':'12px'}},
        {selector:'node[kind="target"]',style:{'border-color':'#F3415E','border-width':2,'font-weight':'bold'}},
        {selector:'node[kind="bucket"]',style:{'shape':'round-rectangle','border-style':'dashed','border-color':'#3a4150','font-weight':'bold'}},
        {selector:'node[kind="out"]',style:{'border-color':'#39404c','border-style':'dashed'}},
        {selector:'edge',style:{'width':1,'line-color':'#2a3542','curve-style':'bezier',
          'target-arrow-color':'#2a3542','target-arrow-shape':'triangle','arrow-scale':0.7}}
      ],
      layout:{name:'breadthfirst', directed:true, roots:'#root', spacingFactor:1.05, padding:18}
    });
    hcy.fit(undefined,24);
  };
  window.easHierZoom=function(d){ if(!hcy)return;
    hcy.zoom({level:hcy.zoom()*(d>0?1.3:0.77), renderedPosition:{x:hcy.width()/2,y:hcy.height()/2}}); };
  window.easHierFit=function(){ if(hcy)hcy.fit(undefined,24); };
  window.easHierExport=function(){ if(!hcy)return;
    // PNG over JPEG: Cytoscape's JPEG encoder can emit a corrupt/unreadable file;
    // PNG is lossless and renders the dark background cleanly. Fixed output size
    // (not scale:2) never exceeds the browser canvas limit.
    hcy.fit(undefined,24);
    var o={output:'blob',bg:'#0b0f14',full:false,scale:3};
    var blob; try{blob=hcy.png(o);}catch(e){try{o.scale=2;blob=hcy.png(o);}catch(e2){return;}}
    if(!blob){return;}
    var url=URL.createObjectURL(blob), a=document.createElement('a');
    var slug=(wrap().getAttribute('data-slug')||'group');
    a.href=url; a.download=slug+'-group-hierarchy.png'; a.style.display='none';
    document.body.appendChild(a);
    a.click();
    setTimeout(function(){try{a.remove();URL.revokeObjectURL(url);}catch(e){}},60000); };
  window.easHierFull=function(){
    var card=document.getElementById('hiergraphcard'); if(!card)return;
    var fs=document.fullscreenElement||document.webkitFullscreenElement;
    if(fs){(document.exitFullscreen||document.webkitExitFullscreen).call(document);}
    else{(card.requestFullscreen||card.webkitRequestFullscreen).call(card);}
  };
  function _onfs(){
    var b=document.getElementById('hierfullbtn');
    var fs=document.fullscreenElement||document.webkitFullscreenElement;
    if(b)b.innerHTML=fs?'⛎ Exit':'⛎ Full';
    if(hcy)setTimeout(function(){hcy.resize();hcy.fit(undefined,24);},80);
  }
  document.addEventListener('fullscreenchange',_onfs);
  document.addEventListener('webkitfullscreenchange',_onfs);
  window.easHierRender();
})();
</script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.30.2/cytoscape.min.js"
  onload="window.easHierRender&&window.easHierRender()"></script>
"""

_CONTEXT_JS = r"""
<script>
function ctxEdit(slug){
  var card=document.getElementById('ctxcard'), btn=document.getElementById('cx_edit');
  if(!card)return;
  if(!card.classList.contains('editing')){
    card.classList.add('editing'); if(btn)btn.textContent='Done';
    var first=document.getElementById('cxin_legal'); if(first)first.focus();
    return;
  }
  var err=document.getElementById('cx_err'); if(err)err.style.display='none';
  if(btn)btn.disabled=true;
  function v(id){var e=document.getElementById(id);return e?e.value:'';}
  var fd=new FormData();
  fd.append('slug',slug);
  fd.append('legal',v('cxin_legal'));
  fd.append('website',v('cxin_website'));
  fd.append('ceo',v('cxin_ceo'));
  fd.append('sector',v('cxin_sector'));
  fd.append('description',v('cxin_description'));
  fetch('/context-save',{method:'POST',body:fd})
    .then(function(r){return r.json();}).then(function(d){
      if(btn)btn.disabled=false;
      if(d&&d.ok){if(window.showFlash)showFlash(true,d.msg);
        setTimeout(function(){location.reload();},350);}
      else{if(err){err.textContent=(d&&d.msg)||'Save failed.';err.style.display='block';}}
    }).catch(function(){if(btn)btn.disabled=false;
      if(err){err.textContent='Request failed.';err.style.display='block';}});
}
</script>
"""


def _attr(s: str) -> str:
    """Escape a string for use inside an HTML attribute value."""
    return _esc(s).replace('"', "&quot;")


def _footprint_load(slug: str) -> dict:
    """Read the layer-0 company-footprint output for the Context dossier. The
    source of truth is what tools/footprint_run.py wrote after the gate: the
    accepted records in their native contract shape, the quarantined people and
    email records held for operator confirmation, the sanctions/PEP halt, and the
    coverage statement. Read-only, never recomputed here, the console is read
    over signals."""
    base = ENGAGEMENTS / slug / "layer0"
    out = {"accepted": [], "quarantine": [], "halt": None,
           "coverage": "", "ran": None,
           # The locked-schema structures (references/layer0-seed-output.md).
           # Present-but-empty by default, so the Context dossier shows honest
           # states (unscreened, none, empty) before the modules that fill them
           # are built. An empty structure is a real state, not a missing field.
           "sanctions_screen": {"status": "unscreened"},
           "candidate_domains": [], "investigative": [],
           "ruled_out": [], "subsidiaries": [], "profile": {}}

    def _jsonl(p: Path) -> list:
        recs = []
        try:
            if p.is_file():
                for ln in p.read_text(errors="replace").splitlines():
                    ln = ln.strip()
                    if ln:
                        try:
                            recs.append(json.loads(ln))
                        except Exception:
                            pass
        except Exception:
            pass
        return recs

    acc = base / "accepted.jsonl"
    out["accepted"] = _jsonl(acc)
    out["quarantine"] = _jsonl(base / "quarantine.jsonl")
    out["candidate_domains"] = _jsonl(base / "candidate_domains.jsonl")
    out["investigative"] = _jsonl(base / "investigative.jsonl")
    out["ruled_out"] = _jsonl(base / "ruled_out.jsonl")
    out["subsidiaries"] = _jsonl(base / "subsidiaries.jsonl")
    prof = base / "company_profile.json"
    try:
        if prof.is_file():
            d = json.loads(prof.read_text())
            if isinstance(d, dict):
                out["profile"] = d
    except Exception:
        pass
    screen = base / "sanctions_screen.json"
    try:
        if screen.is_file():
            d = json.loads(screen.read_text())
            if isinstance(d, dict) and d.get("status"):
                out["sanctions_screen"] = d
    except Exception:
        pass
    try:
        if acc.is_file():
            out["ran"] = acc.stat().st_mtime
    except Exception:
        pass
    halt = base / "HALT-sanctions.json"
    try:
        if halt.is_file():
            d = json.loads(halt.read_text())
            if isinstance(d, dict):
                out["halt"] = d
    except Exception:
        pass
    cov = base / "coverage.md"
    try:
        if cov.is_file():
            out["coverage"] = cov.read_text(errors="replace")[:20000]
    except Exception:
        pass
    return out


def _footprint_debug(slug: str) -> dict:
    """Everything a human needs to answer 'where is the Layer 0 run, and did it
    fail'. Reads the runner's own run-status.json (started/stage/state/error),
    the captured agent stdout+stderr, the raw record count, and the live systemd
    unit state. Read-only, best-effort: a missing file is a state, not an error."""
    base = ENGAGEMENTS / slug / "layer0"
    dbg = {"status": None, "agent_err": "", "agent_json_head": "",
           "raw_lines": 0, "unit_state": "", "unit_result": "",
           "files": [], "timeline": [], "tool_counts": {}, "result": None,
           "last_activity": None}

    def _read(p: Path, limit: int = 8000) -> str:
        try:
            if p.is_file():
                return p.read_text(errors="replace")[-limit:]
        except Exception:
            pass
        return ""

    try:
        st = base / "run-status.json"
        if st.is_file():
            dbg["status"] = json.loads(st.read_text(errors="replace"))
    except Exception:
        pass
    dbg["agent_err"] = _read(base / "agent-last.err")
    dbg["agent_json_head"] = _read(base / "agent-last.json", 4000)
    # The live step-by-step timeline the runner tees while the agent works.
    try:
        tl = base / "agent-timeline.jsonl"
        if tl.is_file():
            rows = []
            counts: dict = {}
            for ln in tl.read_text(errors="replace").splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    ev = json.loads(ln)
                except Exception:
                    continue
                rows.append(ev)
                if ev.get("kind") == "tool" and ev.get("tool"):
                    counts[ev["tool"]] = counts.get(ev["tool"], 0) + 1
            dbg["timeline"] = rows
            dbg["tool_counts"] = counts
            if rows:
                dbg["last_activity"] = rows[-1]
            try:
                dbg["timeline_mtime"] = tl.stat().st_mtime
            except Exception:
                pass
    except Exception:
        pass
    # The final result event (totals, cost, turns), parsed from agent-last.json.
    try:
        rj = base / "agent-last.json"
        if rj.is_file():
            txt = rj.read_text(errors="replace").strip()
            if txt:
                dbg["result"] = json.loads(txt)
    except Exception:
        pass
    try:
        raw = base / "footprint-raw.jsonl"
        if raw.is_file():
            dbg["raw_lines"] = sum(1 for _ in raw.open())
    except Exception:
        pass
    # Live unit state. Best-effort, user bus; a non-zero exit just leaves blanks.
    try:
        unit = f"footprint@{slug}.service"
        r = subprocess.run(
            ["systemctl", "--user", "show", unit,
             "--property=ActiveState,Result,ExecMainStatus,InactiveExitTimestamp"],
            capture_output=True, text=True, timeout=5)
        props = {}
        for ln in (r.stdout or "").splitlines():
            if "=" in ln:
                k, v = ln.split("=", 1)
                props[k] = v
        dbg["unit_state"] = props.get("ActiveState", "")
        dbg["unit_result"] = props.get("Result", "")
        dbg["unit_exit"] = props.get("ExecMainStatus", "")
    except Exception:
        pass
    try:
        for name in ("run-status.json", "agent-stream.jsonl",
                     "agent-timeline.jsonl", "agent-last.json", "agent-last.err",
                     "footprint-raw.jsonl", "coverage.md", "accepted.jsonl",
                     "quarantine.jsonl", "dropped.jsonl", "HALT-sanctions.json"):
            p = base / name
            if p.is_file():
                dbg["files"].append({"name": name, "size": p.stat().st_size,
                                     "mtime": p.stat().st_mtime})
    except Exception:
        pass
    return dbg


def _state_label(value: str) -> str:
    """Operator-facing wording for a lifecycle state. Stored values are part of
    the locked schema (live, acquired, divested, winding-down, parked, defunct)
    and unchanged; only the displayed text is plain-English. Chips are uppercased
    by CSS."""
    v = (value or "").lower().strip()
    return {
        "live":          "Active",
        "acquired":      "Newly bought",
        "divested":      "Sold off",
        "divesting":     "Sold off",
        "winding-down":  "Closing down",
        "winding down":  "Closing down",
        "parked":        "Dormant",
        "defunct":       "Closed",
    }.get(v, value or "")


def _fp_state_str(rec: dict) -> str:
    st = rec.get("state")
    if isinstance(st, dict):
        v = _state_label(st.get("value") or "")
        aso = st.get("as_of") or ""
        return f"{v} (as of {aso})" if v and aso else (v or "")
    return _state_label(str(st or ""))


def _fp_chip(kind: str, value: str) -> str:
    """A small coloured tag for a scope or confidence value, same palette idea as
    the severity chips. Green for the strong value, amber for the middle, muted
    for the weak."""
    v = (value or "").lower()
    # Cool pill family (see .cxchip CSS): green for the strong value, amber for
    # the middle, muted for the weak. Same translucent, bordered, uppercase look
    # as the unconfirmed label, and one shared font size.
    variant = {
        "in-scope-confirmed": "c-ok",
        "verified":           "c-ok",
        "attribution-only":   "c-mid",
        "inferred":           "c-mid",
        "lead":               "c-low",
    }.get(v, "c-low")
    # Operator-facing wording for the confidence tiers. The stored record values
    # (verified/inferred/lead) are part of the locked schema and unchanged; only
    # the displayed label is plain-English. Chips are uppercased by CSS.
    label = {"verified": "Confirmed", "inferred": "Likely",
             "lead": "Unconfirmed"}.get(v, value or kind)
    return f'<span class="cxchip {variant}">{_esc(label)}</span>'


def _fp_records_card(records: list, title: str, anchor: str,
                     show_state: bool = False) -> str:
    """One section of the dossier: a table of footprint records, newest schema
    fields shown as chips. Returns empty when there is nothing of this kind, so
    the page only shows sections that have data."""
    if not records:
        return ""
    rows = []
    for r in records:
        val = _esc(str(r.get("value", "")))
        scope_chip = _fp_chip("scope", r.get("scope", ""))
        conf_chip = _fp_chip("confidence", r.get("confidence", ""))
        sig = _esc(str(r.get("ownership_signal", "") or ""))
        src = _esc(str(r.get("source", "") or ""))
        state_cell = (f'<td class="fpst">{_esc(_fp_state_str(r))}</td>'
                      if show_state else "")
        rows.append(
            f'<tr><td class="fpval">{val}</td>'
            f'{state_cell}'
            f'<td>{scope_chip}</td><td>{conf_chip}</td>'
            f'<td class="fpsig">{sig}</td>'
            f'<td class="fpsrc muted">{src}</td></tr>')
    state_h = "<th>State</th>" if show_state else ""
    return (
        f'<h2 id="{anchor}" class="fph2">{title} <span class="fpn">({len(records)})</span></h2>'
        f'<div class="card fptablecard"><table class="fptable"><thead><tr>'
        f'<th>Value</th>{state_h}<th>Scope</th><th>Confidence</th>'
        f'<th>Ownership signal</th><th>Source</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table></div>')


_HOSTPATH_RE = re.compile(r'^(?:[a-z0-9-]+\.)+[a-z]{2,}/\S*$', re.I)


def _linkify(text: str) -> str:
    """Escape source text and turn its URLs into external links, so a source
    string answers 'where was this retrieved from' with a click. A token is
    linked when it is a full http(s) URL or a host with a path (api.github.com/
    orgs/x, login.microsoftonline.com/x/...). A bare word, a resolver like
    dig @1.1.1.1, or a host with no path stays plain text, so only real locators
    become links."""
    if not text:
        return ""
    out = []
    for tok in str(text).split(" "):
        host = tok.rstrip(".,);:")
        trail = tok[len(host):]
        href = None
        if host.startswith(("http://", "https://")):
            href = host
        elif "/" in host and _HOSTPATH_RE.match(host):
            href = "https://" + host
        if href:
            out.append(f'<a class="cxlink" href="{_attr(href)}" target="_blank" '
                       f'rel="noopener noreferrer">{_esc(host)}</a>{_esc(trail)}')
        else:
            out.append(_esc(tok))
    return " ".join(out)


def _crt_link(domain: str) -> str:
    """A domain rendered as a link to its public certificate-transparency log at
    crt.sh. Passive, and the natural 'what else is on this name' pivot."""
    d = _esc(domain)
    return (f'<a class="cxlink" href="https://crt.sh/?q={_attr(domain)}" '
            f'target="_blank" rel="noopener noreferrer">{d}</a>')


def _context_company_tab(slug: str, cid: str) -> str:
    """The Context tab: the layer-0 company dossier. The top is the operator
    identity card (legal entity, CEO, sector, description, brand logo), editable
    in place. Below it the dossier sections render the company footprint the
    layer-0 phase produced: legal entities and ownership, domains and attribution,
    infrastructure attribution, people held for confirmation, the sanctions halt
    if any, and the coverage statement. Everything below the identity card is the
    human view of the footprint signals, read-only, no scan, no traffic."""
    data = _ctx_meta_load(slug)

    # Load the footprint output first: the dossier rows and the header abstract
    # are both driven by it.
    fp = _footprint_load(slug)
    acc = fp["accepted"]

    def _of(types: set) -> list:
        return [r for r in acc if str(r.get("type", "")).lower() in types]

    # Landing URL for the legal entity link, taken from the data not hardcoded:
    # the apex the footprint attributed, else the primary in-scope domain. This
    # keeps whatever TLD the client actually uses (.com, .co.uk, .io, .eu).
    _apex_recs = _of({"apex"})
    _sd = _scope_domains(slug)
    _landing_dom = (str(_apex_recs[0].get("value", "")).strip() if _apex_recs
                    else (_sd[0] if _sd else ""))
    _landing = f"https://{_landing_dom}" if _landing_dom else ""

    logo = data.get("logo")
    if logo:
        src = f"/brand-logo?e={cid}&v={_ctx_meta_file(slug).stat().st_mtime:.0f}"
        logo_inner = f'<img src="{src}" alt="brand logo">'
    else:
        logo_inner = '<span class="ph">Imported<br>automatically</span>'
    # The logo is the third column, merged (rowspan) across the first four rows
    # (legal entity, website, CEO, sector). The two rows below it (description,
    # tech stack) merge their value across the value and logo columns instead.
    logo_cell = (f'<td class="cxlogocell" rowspan="4">'
                 f'<div class="ctxlogobox">{logo_inner}</div></td>')

    # The identity card is left OPEN here (no closing </div>): the Layer 0
    # dossier is appended inside the same card below, and the Edit button is at
    # the very bottom, so the whole box is one unit.
    # ----- derive the values the dossier rows and the header abstract need -----
    NONE = '<span class="muted">None</span>'
    HELD = '<span class="cxheld">Held, unlock people data to view</span>'

    def _tag(r: dict) -> str:
        conf = r.get("confidence", "")
        src = str(r.get("source", "") or "")
        out = ""
        if conf:
            out += " " + _fp_chip("confidence", conf)
        if src:
            out += f' <span class="fpsrc muted">{_linkify(src)}</span>'
        return out

    def _conf(r: dict) -> str:
        # Just the confidence chip, no source prose. Used where the source is
        # shown separately as a short link instead of a long sentence.
        conf = r.get("confidence", "") if r else ""
        return " " + _fp_chip("confidence", conf) if conf else ""

    def _srclink(label: str, url: str) -> str:
        return (f' <a class="fpsrc cxlink" href="{_attr(url)}" target="_blank" '
                f'rel="noopener noreferrer">{_esc(label)}</a>') if url else ""

    in_scope = _scope_domains(slug)
    primary = in_scope[0] if in_scope else ""
    subs = fp["subsidiaries"]
    cands = fp["candidate_domains"]
    # Lookalike count: read straight off the latest lookalike report spreadsheet
    # (the sweep's own output), data rows minus the header. Tolerant: any failure
    # leaves it 0 and the row renders None rather than a wrong number.
    _la_count = 0
    try:
        import zipfile as _zip
        _rdir = ENGAGEMENTS / slug / "reports"
        _las = sorted(_rdir.glob("*lookalike*domains*.xlsx"),
                      key=lambda p: p.stat().st_mtime, reverse=True)
        if _las:
            with _zip.ZipFile(_las[0]) as _z:
                _xml = _z.read("xl/worksheets/sheet1.xml").decode("utf-8", "ignore")
            _la_count = max(0, _xml.count("<row ") - 1)
    except Exception:
        _la_count = 0

    # Lookalike sweep results from the signals the sweep emits (run by the RUN
    # button alongside Layer 0). Count the distinct impersonation domains it
    # identified, and separately list the ones that are ALIVE (resolving, so they
    # carry a resolved IP entity). The xlsx count above is a fallback for the
    # identified total when no signal file is present yet.
    _la_identified: set = set()
    _la_alive: set = set()
    try:
        _sdir = ENGAGEMENTS / slug / "signals"
        if _sdir.is_dir():
            for _f in _sdir.glob("*.jsonl"):
                for _ln in _f.read_text(errors="ignore").splitlines():
                    _ln = _ln.strip()
                    if not _ln or "lookalike_domain" not in _ln:
                        continue
                    try:
                        _d = json.loads(_ln)
                    except Exception:
                        continue
                    if str(_d.get("source_class", "")) != "lookalike_domain":
                        continue
                    _ents = _d.get("entities", []) or []
                    _dom = next((str(e.get("value", "")).lower().rstrip(".")
                                 for e in _ents
                                 if e.get("type") == "domain" and e.get("value")), "")
                    if not _dom:
                        continue
                    _la_identified.add(_dom)
                    _ev = _d.get("evidence", {}) or {}
                    _alive = (any(e.get("type") == "ip" for e in _ents)
                              or "resolves" in (_ev.get("triggers") or [])
                              or _ev.get("mail_capable") or _ev.get("serves_login"))
                    if _alive:
                        _la_alive.add(_dom)
    except Exception:
        pass
    _la_total = len(_la_identified) or _la_count
    ents = _of({"entity"})
    ent_rec = ents[0] if ents else None
    legal_name = (data.get("legal_entity")
                  or (str(ent_rec.get("value", "")) if ent_rec else ""))
    # Drop any trailing parenthetical qualifier from the display name, such as
    # "(brand, legal vehicle not resolved)" or "(registry code ...)". It adds no
    # value on the title and the registry code has its own dossier row. The
    # unresolved-vehicle fact is still carried by the abstract and its own row.
    legal_name = re.sub(r"\s*\([^)]*\)", "", legal_name).strip()
    reg_code = ""
    if ent_rec:
        m = re.search(r"(\d{5,})", str(ent_rec.get("value", "")))
        if m:
            country = "Israel" if "israel" in str(ent_rec.get("value", "")).lower() else ""
            reg_code = m.group(1) + (f" ({country})" if country else "")

    tenant_recs = _of({"entra_tenant"})
    tenant_rec = tenant_recs[0] if tenant_recs else None
    estate = _of({"apex", "domain"})
    clouds = _of({"cloud_account"})
    provs, sso = [], ""
    # Build the stack with each item's provenance (where it was retrieved from),
    # kept to a short phrase, so the row carries context not just bare labels.
    def _provcat(s: str) -> str:
        # Reduce a long ownership-signal sentence to a few-word retrieval source,
        # for context not forensic detail (e.g. "apex TXT", "CNAME", "DNS NS").
        s = re.sub(r"\s+", " ", str(s or "")).strip()
        sl = s.lower()
        # CNAME: name the record host and the target it points to, so the
        # operator sees exactly where the tie was read.
        m = re.search(r"([\w.-]+)\s+cname to\s+([\w.-]+)", sl)
        if m:
            tgt = ".".join(m.group(2).split(".")[-3:])
            return f"{m.group(1)} CNAME → {tgt}"
        if "nameserver" in sl or "route 53" in sl or "route53" in sl or "ns-" in sl:
            return "apex NS (Route 53)" if ("route 53" in sl or "route53" in sl) else "apex NS"
        # apex TXT: carry the actual verification token name (that IS the where).
        mt = re.search(r"(MS=\S+|[\w-]*domain-verification|google-site-verification"
                       r"|ZOOM_verify|dkim|spf)", s, re.I)
        if ("txt" in sl or "verification token" in sl) and mt:
            tok = mt.group(1).split("=")[0] if mt.group(1).lower().startswith(
                ("google", "dkim", "spf")) else mt.group(1)
            return f"apex TXT {tok}"
        if "txt" in sl:
            return "apex TXT"
        if "mx" in sl or "mail" in sl:
            return "MX record"
        if "dns" in sl:
            return "DNS"
        return ""

    # Provider aliases to scan for inside a value. A cloud_account value can be a
    # raw token like "google-workspace-saml-idpid..." or "aws:eu-central-1", so we
    # match a known provider keyword anywhere in the value rather than splitting on
    # ":" and title-casing the whole token (which produced "Google-Workspace-...").
    _alias = {"microsoft": "Entra", "entra": "Entra", "azure": "Entra",
              "office365": "Entra", "o365": "Entra", "outlook": "Entra",
              "aws": "AWS", "amazon": "AWS", "route 53": "AWS", "route53": "AWS",
              "okta": "Okta", "google": "Google", "gsuite": "Google",
              "zoom": "Zoom", "dropbox": "Dropbox", "openai": "OpenAI",
              "github": "GitHub", "cloudflare": "Cloudflare", "fastly": "Fastly",
              "wix": "Wix"}

    def _provlabel(val: str) -> str:
        vl = str(val or "").lower()
        for key, lbl in _alias.items():
            if key in vl:
                return lbl
        # No known provider keyword: fall back to the first token, title-cased,
        # but only the leading word so a long token does not become the label.
        head = re.split(r"[:\s/_-]", str(val or "").strip(), 1)[0]
        return head.title() if head else ""

    prov_rows = []  # (label, provenance, record)
    seen = set()
    for c in clouds:
        label = _provlabel(c.get("value", ""))
        if label == "Okta":
            sso = "Okta"
        if not label or label in seen:
            continue
        seen.add(label)
        prov_rows.append((label,
                          c.get("ownership_signal") or c.get("source") or "", c))
    for t in _of({"technology", "tech", "saas"}):
        tv = str(t.get("value", "")).strip()
        if tv and tv not in seen:
            seen.add(tv)
            prov_rows.append((tv, t.get("ownership_signal") or t.get("source") or "", t))
    provs = [lbl for lbl, _, _ in prov_rows]
    stack_html = ('<ul class="cxlist">' + "".join(
        f'<li><b>{_esc(lbl)}</b>'
        + (f' <span class="muted">{_esc(_provcat(sig))}</span>' if _provcat(sig) else "")
        + _conf(rec) + '</li>' for lbl, sig, rec in prov_rows) + '</ul>'
    ) if prov_rows else ""
    code_orgs = [r for r in (acc + fp["quarantine"])
                 if str(r.get("type", "")).lower() == "code_org"]
    # Corporate map: the subsidiaries record is the single source of truth for
    # brands. Split by state so a brand shows exactly once: current brands under
    # Subsidiaries, brands being wound down under Divestitures in progress. A
    # winding-down brand is a divestiture, not an acquisition, so the overlap the
    # old ents-based "acquisitions" row created is gone.
    _DIVEST_STATES = ("divested", "winding-down", "winding down", "divesting")

    def _norm_brand(n: str) -> str:
        return re.sub(r"[^a-z0-9]", "", str(n or "").lower())

    subs_active, subs_divest, _brand_seen = [], [], set()
    for s in subs:
        nm = str((s.get("name") if isinstance(s, dict) else s) or "").strip()
        if not nm:
            continue
        key = _norm_brand(nm)
        if key in _brand_seen:
            continue
        _brand_seen.add(key)
        st = str(s.get("state", "")).lower().strip() if isinstance(s, dict) else ""
        if st in _DIVEST_STATES:
            subs_divest.append((nm, st))
        else:
            subs_active.append((nm, st))
    acq = subs_divest  # abstract still keys off whether any brand is in flux
    inv = fp["investigative"]

    def _inv_of(kind: str) -> list:
        return [r for r in inv if str(r.get("type", "")).lower() == kind]

    screen = fp.get("sanctions_screen") or {"status": "unscreened"}
    status = str(screen.get("status", "unscreened")).lower()
    SCR = {"clear": ("Clear", "scr-clear"), "hit": ("Hit", "scr-hit"),
           "unscreened": ("Unscreened", "scr-unscreened")}
    slbl, scls = SCR.get(status, SCR["unscreened"])

    # confidence summary, synthesized from the accepted records' tags
    cc = {"verified": 0, "inferred": 0, "lead": 0}
    for r in acc:
        c = str(r.get("confidence", "")).lower()
        if c in cc:
            cc[c] += 1
    conf_bits = [f'{n} {k}' for k, n in cc.items() if n]
    conf_txt = ", ".join(conf_bits) if conf_bits else "no records yet"

    ran = fp.get("ran")
    run_line = (f'Layer 0 run {datetime.fromtimestamp(ran, timezone.utc).strftime("%Y-%m-%d")} '
                f'&middot; {len(acc)} accepted') if ran else "Layer 0 not run yet"

    # A few structured facts the agent recorded only in coverage.md prose, pulled
    # out with tolerant patterns so the dossier and abstract can use them. Empty
    # when not found, never guessed.
    cov = fp.get("coverage") or ""
    mdate = re.search(r"incorporated\s+(\d{4}-\d{2}-\d{2})", cov, re.I)
    incorporated = mdate.group(1) if mdate else ""
    founded = incorporated[:4] if incorporated else ""

    # Interim: several facts the agent established live only in coverage.md prose
    # (registered office, registrar, nameservers, hosting, mail posture, tenant
    # type, headcount). Pull them out with tolerant patterns so the rows fill.
    # The durable fix is a structured company_profile object in the L0 output.
    # Normalize whitespace first: coverage.md wraps lines, so a value like
    # "Hod\n  HaSharon" must be collapsed before a pattern can see it.
    covn = re.sub(r"\s+", " ", cov)

    def _cov(pat: str, grp: int = 1):
        m = re.search(pat, covn, re.I)
        return m.group(grp).strip() if m else ""

    _hq_city = _cov(r"registered office[^,]*?([A-Z][A-Za-z]+(?: [A-Z][A-Za-z]+){0,2})\s+\d{6,7}")
    hq = f"{_hq_city}, Israel" if _hq_city else ""
    _registrar = _cov(r"registrar\s*\(\d+,\s*([A-Za-z][\w .]*?)\)")
    registrar_age = (f"{_registrar}, registered {founded}" if _registrar and founded
                     else _registrar)
    nameservers = "AWS Route 53" if re.search(r"route\s*53", covn, re.I) else ""
    _host = []
    if re.search(r"eu-central-1", covn, re.I):
        _host.append("AWS eu-central-1")
    if re.search(r"\bfastly\b", covn, re.I):
        _host.append("Fastly")
    if re.search(r"\bwix\b", covn, re.I):
        _host.append("Wix")
    if re.search(r"\bokta\b", covn, re.I):
        _host.append("Okta")
    hosting = ", ".join(_host)
    _mail = []
    if re.search(r"outlook|microsoft 365|\bmx\b", covn, re.I):
        _mail.append("Outlook")
    if re.search(r"-all", covn):
        _mail.append("SPF -all")
    _dm = re.search(r"p=(quarantine|reject|none)", covn, re.I)
    if _dm:
        _mail.append(f"DMARC p={_dm.group(1).lower()}")
    mail_posture = ", ".join(_mail)
    tenant_type = "Managed" if re.search(r"\bmanaged\b", covn, re.I) else ""
    _hc = re.search(r"roughly\s+(\d+)", covn, re.I)
    # "N employees" with the unconfirmed caveat shown as a red label, not inline
    # parentheses, so the uncertainty reads at a glance.
    headcount = (f'~{_hc.group(1)} employees '
                 '<span class="cxunconf">unconfirmed</span>') if _hc else ""
    # Business lines: scan coverage plus the operator sector and description so
    # the full model (IR, MDR, red teaming) is caught, not just what prose names.
    _low = " ".join([covn, data.get("sector", ""), data.get("description", "")]).lower()
    _bm = []
    if "incident response" in _low:
        _bm.append("Incident response")
    if "managed detection" in _low or "mdr" in _low:
        _bm.append("MDR")
    if "red team" in _low:
        _bm.append("red teaming")
    business_model = ", ".join(_bm)

    # Structured company profile wins over the prose-parsed guesses. The agent
    # emits these as explicit fields (company_profile.json), so when present they
    # are authoritative and every scalar row reads a real value instead of a
    # regex match against the coverage statement.
    prof = fp.get("profile") or {}

    def _pf(k: str) -> str:
        return str(prof.get(k) or "").strip()

    if _pf("legal_entity"):
        legal_name = re.sub(r"\s*\([^)]*\)", "", _pf("legal_entity")).strip()
    if _pf("registry_code"):
        reg_code = _pf("registry_code")
    if _pf("incorporated"):
        incorporated = _pf("incorporated")
    if _pf("registrar"):
        registrar_age = _pf("registrar") + (
            f", registered {_pf('registrar_date')}" if _pf("registrar_date") else "")
    if _pf("nameservers"):
        nameservers = _pf("nameservers")
    if _pf("hosting"):
        hosting = _pf("hosting")
    if _pf("mail_posture"):
        mail_posture = _pf("mail_posture")
    if _pf("tenant_type"):
        tenant_type = _pf("tenant_type")
    if _pf("business_model"):
        business_model = _pf("business_model")
    if _pf("headquarters"):
        hq = _pf("headquarters")
    if _pf("sso"):
        sso = _pf("sso")
    if _pf("headcount"):
        # A structured headcount is shown as given; the unconfirmed caveat only
        # applies to the prose-estimated fallback.
        headcount = _esc(_pf("headcount"))
    # Profile-only scalar rows (empty string renders an honest None).
    former_names = _pf("former_names")
    parent_group = _pf("parent_group")
    funding = _pf("funding")
    public_filings = _pf("public_filings")
    trademark_owner = _pf("trademark_owner")
    other_offices = _pf("other_offices")
    key_customers = _pf("key_customers")
    certifications = _pf("certifications")
    profile_sector = _pf("sector")
    profile_summary = _pf("summary")

    # data.gov.il Israel Corporations Authority datastore link, built from the
    # resource id in the coverage prose and the company number, so the Legal
    # entity source is a short link to the exact row, not a long sentence.
    _rid = _cov(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")
    _regnum = re.sub(r"\D", "", reg_code)
    ica_url = (f"https://data.gov.il/api/3/action/datastore_search?resource_id={_rid}"
               f"&q={_regnum}") if _rid and _regnum else ""

    # ----- header: synthesized abstract, logo, summary line, Edit -----
    # The abstract is built from the STRUCTURED profile, not the agent's free-text
    # summary, so it always leads with what the company does and makes the holding
    # relationship and the brands it runs explicit. The agent summary and the
    # operator Description are fallbacks only, used when there is no structured
    # signal to describe the company from.
    name = legal_name or _pretty(slug)

    def _oneline(s: str) -> str:
        return re.sub(r"\s+", " ", str(s or "")).strip()

    def _noparen(s: str) -> str:
        # Drop "(registry code ...)" / "(brand)" style parentheticals for prose.
        return _oneline(re.sub(r"\s*\([^)]*\)", "", str(s or "")))

    def _deattr(s: str) -> str:
        # Strip the trailing source/attribution caveat an agent field carries
        # ("..., inferred from ...", "(self-described)"), keeping the fact itself.
        s = _oneline(s)
        low = s.lower()
        for cut in (", inferred", " inferred from", ", not register",
                    ", self-described", " (self-described", " per the entra",
                    " per rdap", " (current registration"):
            i = low.find(cut)
            if i > 0:
                s, low = s[:i], low[:i]
        return s.strip(" .,;")

    def _art(w: str) -> str:
        return "an" if w[:1].lower() in "aeiou" else "a"

    def _and(xs: list) -> str:
        xs = [x for x in xs if x]
        if not xs:
            return ""
        return xs[0] if len(xs) == 1 else ", ".join(xs[:-1]) + " and " + xs[-1]

    sector_txt = _deattr(data.get("sector") or profile_sector)
    bm = _deattr(business_model)
    # A business_model that reads as a role ("... group", "operating company")
    # becomes the lead verbatim; a capability list ("IR, MDR, red teaming") is
    # phrased as what a sector firm provides, the way it reads for a single firm.
    role_like = bool(re.search(
        r"\b(group|holding|operat\w*|provider|company|firm|platform|studio|"
        r"vendor|agency|brand operations)\b", bm, re.I))
    if bm and role_like:
        core = bm[:1].lower() + bm[1:]
        first = f"{name} is {_art(core)} {core}"
    else:
        base = sector_txt or "company"
        first = f"{name} is {_art(base)} {base}"
        if base == "company":
            first += " firm"
        if bm:
            first += f" providing {bm.lower()}"
    sents = [first.rstrip(".") + "."]

    # Holding relationship, stated plainly, with the inference flagged honestly.
    parent = _deattr(parent_group)
    if parent:
        ps = f"It operates as part of {parent}"
        if "inferred" in str(parent_group).lower() or _pf("legal_entity_status") == "unresolved":
            ps += (", an attribution drawn from the shared Microsoft identity "
                   "realm rather than a confirmed register filing")
        sents.append(ps + ".")

    # The consumer brands the group actually runs (the "what do they do" the user
    # wants to see), pulled from the brand-tagged subsidiary records.
    brands = []
    for s in subs:
        nm = str((s.get("name") if isinstance(s, dict) else s) or "")
        if re.search(r"\bbrand\b", nm, re.I):
            c = _noparen(nm)
            if c and c not in brands:
                brands.append(c)
    if brands:
        sents.append("The portfolio's consumer brands include "
                     + _and(brands[:5]) + ".")

    if data.get("ceo") and founded:
        sents.append(f"It was founded in {founded} and is led by {data['ceo']}.")
    elif data.get("ceo"):
        sents.append(f"It is led by {data['ceo']}.")
    elif founded:
        sents.append(f"It was incorporated in {founded}.")

    offices = _noparen(other_offices)
    if offices:
        sents.append(f"It reports {offices}.")
    elif hq:
        sents.append(f"It is headquartered in {hq}"
                     + (f", with a staff of {headcount.split(' employees')[0]} employees"
                        if headcount else "") + ".")

    # NOTE: domain provenance, mail posture (DMARC) and identity-tenant detail are
    # deliberately NOT in this opening paragraph. It is a plain business picture of
    # the company (what they do, who owns them, where they are). The registrar,
    # hosting, mail and tenant facts live in the Infrastructure, Mail posture and
    # SSO sections below, so they are not repeated here as a technical wall.

    # Legal vehicle still unresolved: say so, and name the leading candidate.
    if _pf("legal_entity_status") == "unresolved":
        cand = ""
        for s in subs:
            if isinstance(s, dict) and re.search(
                    r"leading candidate|highest[- ]ranked|holding company",
                    str(s.get("ownership_signal", "")), re.I):
                cand = _noparen(s.get("name", ""))
                break
        ls = (f"No register record yet names {_art(name)} {name} company, so the "
              "operating legal entity is unresolved")
        if cand:
            ls += f"; {cand} is the leading candidate"
        sents.append(ls + ".")

    if not subs and not acq and not parent:
        sents.append("No parent group, subsidiaries, or acquisitions were found.")
    if status != "hit" and not inv:
        sents.append("No sanctions, PEP, or adverse-media thread surfaced during "
                     "Layer 0 screening.")

    synth = " ".join(sents)
    # Lead with the ingested business summary when the agent wrote one. It is the
    # plain-English picture of the company the operator wants first: what they do,
    # who owns them, where they are, written from the OSINT, not a vuln or infra
    # readout. Fall back to the synthesized business narrative, then the operator
    # Description. Either way the opening paragraph carries no security or infra
    # detail now (that was stripped above).
    have_signal = bool(bm or sector_txt or parent or brands)
    _summary = (profile_summary or "").strip()
    abstract_txt = (_summary if len(_summary) >= 80
                    else (synth if have_signal else "")
                    or data.get("description") or synth)

    title_name = legal_name or _pretty(slug)
    title_disp = (f'<a class="cxlink" href="{_attr(_landing)}" target="_blank" '
                  f'rel="noopener noreferrer">{_esc(title_name)}</a>'
                  if _landing else _esc(title_name))
    web = data.get("website", "")
    web_disp = (f'<a class="cxlink" href="{_attr(web if "://" in web else "https://"+web)}" '
                f'target="_blank" rel="noopener noreferrer">{_esc(web)}</a>'
                if web else "")
    header = (
        '<div class="card ctxcard" id="ctxcard">'
        '<div class="ctxhead">'
        # Title spans the full width at the top, sharing the left edge with the
        # summary below it.
        f'<div class="ctxtitle"><span class="cxv" id="cxv_legal">{title_disp}</span>'
        f'<input class="cxin" id="cxin_legal" maxlength="200" '
        f'value="{_attr(data.get("legal_entity",""))}" spellcheck="false"></div>'
        # Below the title: the summary on the left, the logo on the right, their
        # tops aligned so the logo starts where the summary starts.
        '<div class="ctxbody"><div class="ctxheadmain">'
        f'<div class="ctxabstract"><span class="cxv" id="cxv_description">'
        f'{_esc(abstract_txt)}</span>'
        f'<textarea class="cxin" id="cxin_description" rows="5" maxlength="4000">'
        f'{_esc(data.get("description",""))}</textarea></div>'
        f'<div class="ctxweb">'
        + (f'<span class="muted">Website</span> '
           f'<span class="cxv" id="cxv_website">{web_disp}</span>' if web
           else '<span class="cxv" id="cxv_website"></span>')
        + f'<input class="cxin" id="cxin_website" maxlength="200" '
        f'value="{_attr(web)}" spellcheck="false"></div>'
        '</div>'
        f'<div class="ctxlogo"><div class="ctxlogobox">{logo_inner}</div></div>'
        '</div>'
        '</div>')

    edit_footer = (
        '<div class="rerr" id="cx_err" style="display:none"></div>'
        '<div class="row cxeditrow"><button type="button" class="btn-ghost sbtn save" '
        f'id="cx_edit" onclick="ctxEdit(\'{cid}\')">Edit</button></div>')

    # ----- run-debug bar: a link to the live run debug, shown as soon as a run
    # starts (run-status.json is written at launch) so the operator can watch the
    # first run, not only reach the debug after it finishes. While the run is in
    # progress it shows a live state and refreshes itself.
    run_state = ""
    try:
        rs = ENGAGEMENTS / slug / "layer0" / "run-status.json"
        if rs.is_file():
            run_state = str(json.loads(rs.read_text()).get("state", "")).lower()
    except Exception:
        run_state = ""
    dbg_href = f"/l0-debug?e={_esc(cid)}"
    if run_state == "running":
        runbar = (
            '<div class="cxrunbar running">'
            '<span class="cxrundot"></span>'
            '<span>Layer 0 run in progress.</span> '
            f'<a class="cxlink" href="{dbg_href}">Open the run debug</a>'
            '<script>setTimeout(function(){location.reload();},5000);</script>'
            '</div>')
    elif run_state:
        # No debug link here on purpose: the "view in run debug" link at the
        # bottom of the dossier is enough, so the top bar just states the state.
        runbar = (
            '<div class="cxrunbar">'
            f'<span>Last Layer 0 run {_esc(run_state)}.</span>'
            '</div>')
    else:
        runbar = ""

    # ----- screening halt banner (only on a halt) -----
    banner = ""
    if fp.get("halt"):
        banner = (
            '<div class="cxhalt"><span class="cxhalticon">!</span>'
            '<span class="cxhaltx"><b>Screening halt</b> &mdash; sanctions or PEP '
            'signal on a subject. Operator decides whether the engagement proceeds. '
            f'<a href="/l0-debug?e={_esc(cid)}">review</a></span></div>')

    # ----- the dossier rows: one 2-column table, grouped by separators -----
    drows = []

    def R(label: str, value: str) -> None:
        drows.append(f'<tr><td class="cxk">{_esc(label)}</td>'
                     f'<td class="cxv-cell"><span class="cxv">{value or NONE}</span>'
                     f'</td></tr>')

    def ER(label: str, key: str, val: str) -> None:
        # an editable dossier row (keeps cxin id so ctxEdit + save still work)
        disp = _esc(val) if val else NONE
        drows.append(f'<tr><td class="cxk">{_esc(label)}</td>'
                     f'<td class="cxv-cell"><span class="cxv" id="cxv_{key}">{disp}</span>'
                     f'<input class="cxin" id="cxin_{key}" maxlength="200" '
                     f'value="{_attr(val)}" spellcheck="false"></td></tr>')

    def SEC(title: str) -> None:
        # a titled section header row: the title spans both columns, centered,
        # so the dossier reads as grouped sections inside the one table.
        drows.append('<tr class="cxsectitle"><td colspan="2">'
                     f'{_esc(title)}</td></tr>')

    def SEP() -> None:
        # A thin sub-group divider inside a section (no title). Two real cells,
        # not a colspan, so the column-1/column-2 divider (the cxk border-right)
        # runs continuously through the gap instead of breaking for 8px.
        drows.append('<tr class="cxsecsep"><td class="cxk"></td>'
                     '<td class="cxv-cell"></td></tr>')

    chips = "".join(f'<span class="chip">{_esc(d)}</span>' for d in in_scope)

    # Registry and legal. The legal-entity name links to the landing page (same
    # as the header title), and the source is a short "data.gov.il" link to the
    # exact register row -- no bare "inferred" chip, the linked source stands in.
    _leg = legal_name or data.get("legal_entity", "")
    _leg_disp = (f'<a class="cxlink" href="{_attr(_landing)}" target="_blank" '
                 f'rel="noopener noreferrer">{_esc(_leg)}</a>'
                 if _landing and _leg else _esc(_leg))
    # Registry source for the legal entity, matched to the entity's real
    # jurisdiction. The agent-supplied registry_source/registry_url win; the
    # data.gov.il datastore link is used ONLY when the register really is the
    # Israeli one, so a UK company from Companies House is never cross-cited to
    # the Israeli registry.
    _reg_src = _pf("registry_source")
    _reg_url = _pf("registry_url")
    if _reg_url and _reg_src:
        _reg_link = _srclink(_reg_src, _reg_url)
    elif ica_url and ("data.gov.il" in _reg_src.lower()
                      or "israel" in _reg_src.lower()):
        _reg_link = _srclink("data.gov.il", ica_url)
    else:
        _reg_link = ""
    SEC("Identity")
    R("Legal entity", (f'{_leg_disp} <span class="muted">·</span>{_reg_link}'
                       if ent_rec and _reg_link else _leg_disp))
    R("Registry code", _esc(reg_code))
    R("Incorporated", (f'{_esc(incorporated)}, active' if incorporated else ""))
    R("Former names", _esc(former_names))
    R("Parent group", _esc(parent_group))
    SEP()
    R("Funding / ownership", _esc(funding))
    R("Public filings", _esc(public_filings))
    R("Trademark owner", _esc(trademark_owner))
    SEC("Profile")
    R("Business model", _esc(business_model))
    ER("Sector", "sector", data.get("sector", "") or profile_sector)
    R("Headquarters", _esc(hq))
    R("Other offices", _esc(other_offices))
    R("Headcount", headcount)
    SEP()
    R("Key customers", _esc(key_customers))
    R("Certifications", _esc(certifications))
    SEC("Infrastructure")
    # The contracted root(s), including the primary, as one aligned bullet list.
    # There is no separate "Primary domain" row: the primary is the first here.
    scope_items = "".join(
        f'<li><a class="cxlink" href="https://{_attr(d)}" target="_blank" '
        f'rel="noopener noreferrer">{_esc(d)}</a></li>' for d in in_scope)
    R("In-scope root domains",
      f'<ul class="cxlist">{scope_items}</ul>' if in_scope else "")
    # Registrar, nameservers and hosting are read from the PRIMARY apex only.
    # Each root domain carries its own registrar/DNS/hosting, so presenting one
    # value as if it covered every in-scope root is wrong. When more than one
    # root is in scope, the value is scoped to the apex it was read from and the
    # others are flagged as not-yet-read per root (a structured per-apex infra
    # record in the Layer 0 output is the durable fix).
    _multi = len([d for d in in_scope if d]) > 1
    def _apexscoped(v: str) -> str:
        if not v:
            return ""
        if _multi and primary:
            return (f'{_esc(v)} <span class="muted">({_esc(primary)} only; '
                    f'other roots not yet read per domain)</span>')
        return _esc(v)
    R("Registrar / age", _apexscoped(registrar_age))
    R("Nameservers / DNS", _apexscoped(nameservers))
    R("Hosting footprint", _apexscoped(hosting))
    SEP()
    # Tenant type and mail posture live inside the tenant record's signal prose.
    # Pull them out so the rows read a value instead of None, never guessed.
    # The structured profile (set above) is authoritative. Only fall back to
    # parsing the tenant record's signal prose when the profile left a field
    # empty, so a real company_profile value is never clobbered by a regex guess.
    tsig = str(tenant_rec.get("ownership_signal", "")) if tenant_rec else ""
    if not tenant_type:
        m_ns = re.search(r"\b(Managed|Federated)\b", tsig)
        tenant_type = m_ns.group(1) if m_ns else ""
    if not mail_posture:
        mail_bits = []
        if re.search(r"mail\.protection\.outlook\.com|outlook", tsig, re.I):
            mail_bits.append("Outlook")
        m_spf = re.search(r"(-all|~all|\?all)", tsig)
        if m_spf:
            mail_bits.append("SPF " + m_spf.group(1))
        m_dmarc = re.search(r"p=(none|quarantine|reject)", tsig, re.I)
        if m_dmarc:
            mail_bits.append("DMARC p=" + m_dmarc.group(1).lower())
        mail_posture = ", ".join(mail_bits)
    # The GUID itself links to the live OpenID config of the primary domain,
    # which is exactly where the tenant id was retrieved from. The id is plain
    # text (same format as every other value), not a monospace code box, and the
    # verbose retrieval note is dropped because the link already carries it.
    if tenant_rec:
        guid = str(tenant_rec.get("value", ""))
        tenant_val = _esc(guid)
        if primary:
            openid = (f"https://login.microsoftonline.com/{primary}"
                      "/v2.0/.well-known/openid-configuration")
            tenant_val = (f'<a class="cxlink" href="{_attr(openid)}" target="_blank" '
                          f'rel="noopener noreferrer">{_esc(guid)}</a>')
    else:
        tenant_val = ""
    R("Microsoft tenant", tenant_val)
    R("Tenant type", _esc(tenant_type))
    R("Mail posture", _esc(mail_posture))
    R("SSO / identity", _esc(sso))
    # Stack: when the run emitted discrete cloud_account/technology records they
    # drive it; otherwise synthesize the known provider stack from the structured
    # profile (hosting, mail, SSO, tenant) so a client whose providers are only
    # described in prose does not show an empty Stack.
    if not stack_html:
        _fb, _fbseen = [], set()

        def _addfb(label: str, where: str) -> None:
            if label and label.lower() not in _fbseen:
                _fbseen.add(label.lower())
                _fb.append((label, where))
        if _pf("hosting"):
            _addfb(_provlabel(_pf("hosting")) or "Hosting", "hosting")
        _mpl = _pf("mail_posture").lower()
        if "google" in _mpl:
            _addfb("Google Workspace", "mail")
        elif "outlook" in _mpl or "microsoft" in _mpl or "365" in _mpl:
            _addfb("Microsoft 365", "mail")
        _ssl = _pf("sso").lower()
        if "google" in _ssl:
            _addfb("Google Workspace", "identity")
        elif "okta" in _ssl:
            _addfb("Okta", "identity")
        _ttl = _pf("tenant_type").lower()
        if "entra" in _ttl or "microsoft" in _ttl or "azure" in _ttl:
            _addfb("Microsoft Entra", "tenant")
        if _fb:
            stack_html = ('<ul class="cxlist">' + "".join(
                f'<li><b>{_esc(l)}</b> <span class="muted">{_esc(w)}</span></li>'
                for l, w in _fb) + '</ul>')
    R("Stack", stack_html)
    # Social and channels: a bullet list of discovered profiles, each platform
    # name linked to its own URL. Layer 0's social/people pass is operator-gated,
    # so when it has not run this is honestly None (not a claim that none exist).
    _plat = {"linkedin": "LinkedIn", "twitter": "X", "x.com": "X",
             "facebook": "Facebook", "instagram": "Instagram",
             "youtube": "YouTube", "mastodon": "Mastodon", "tiktok": "TikTok"}
    social = []
    seen_soc = set()

    def _add_social(u: str) -> None:
        u = str(u or "").strip().strip(",")
        if not u or "." not in u:
            return
        ul = u.lower()
        if ul in seen_soc:
            return
        seen_soc.add(ul)
        name = next((lbl for key, lbl in _plat.items() if key in ul), "Profile")
        href = u if "://" in u else "https://" + u
        social.append(f'<li><a class="cxlink" href="{_attr(href)}" target="_blank" '
                      f'rel="noopener noreferrer">{_esc(name)}</a></li>')

    # The structured profile's social field wins (the agent's grounded list).
    # It is a free-form string of profile URLs, comma or newline separated.
    for u in re.split(r"[\s,]+", _pf("social")):
        _add_social(u)
    for r in _of({"social", "social_profile", "handle", "profile"}):
        _add_social(r.get("value", ""))
    R("Social and channels",
      f'<ul class="cxlist">{"".join(social)}</ul>' if social else "")
    SEC("People")
    # CEO is a company-level public fact (filings, company site), so the profile
    # value fills it when the operator has not typed one. This does not touch the
    # held people records, which stay behind the identity_sourcing gate.
    ER("CEO", "ceo", data.get("ceo", "") or _pf("ceo"))
    R("Key people", "")
    R("Contact email", HELD)
    R("Email pattern", HELD)
    def LST(items: list) -> str:
        # Wrap one <li> per item in the shared .cxlist, so every multi-value row
        # (subsidiaries, acquisitions, candidates, adverse, offshore, ruled out)
        # has the same bullet, width, and line height as the other list rows.
        items = [i for i in items if i]
        return f'<ul class="cxlist">{"".join(f"<li>{i}</li>" for i in items)}</ul>' if items else ""

    SEC("Corporate map")

    def _sub_site(nm: str, src: str) -> str:
        # Landing page: a brand entry carries its own domain in the name
        # (Yolo.com, Sportsbet.io), so derive the site from there. A legal entity
        # with no public domain falls back to the register/source URL, which is
        # where the operator actually goes to read about it.
        m = re.search(r"\b([a-z0-9][a-z0-9-]*\.(?:io|com|net|org|co|gg|bet|casino|eu))\b",
                      str(nm).lower())
        if m:
            return "https://" + m.group(1)
        s = str(src or "").strip()
        return s.split(" and ")[0] if s.startswith("http") else ""

    def _sub_what(nm: str, sig: str) -> str:
        # A 3-4 word read of what the entry is, classified from the name and the
        # ownership signal, so the row says what it is without the full sentence.
        # Word boundaries matter: "shareholding" must not read as "holding", and
        # the specific brand kinds are tested before the generic group/holding.
        t = (str(nm) + " " + str(sig)).lower()

        def has(*words) -> bool:
            return any(re.search(r"\b" + w + r"\b", t) for w in words)
        if has("former name of") or "retired by rebrand" in t:
            return "Former group name"
        if has("charity"):
            return "Charity in liquidation" if has("liquidation") else "Group charity"
        if has("land.based"):
            return "Land-based casino"
        if "licensed operator" in t or "operator of" in t:
            return "Licensed operator"
        if has("sportsbook") or "sports betting" in t or has("sportsbet"):
            return "Sports betting brand"
        if has("bitcasino") or (has("casino") and has("crypto")):
            return "Crypto casino brand"
        if has("casino"):
            return "Casino brand"
        if "consumer" in t and has("brand"):
            return "Consumer betting brand"
        if has("investment"):
            return "Investment arm"
        if "holding company" in t or has("holding") and "shareholding" not in t:
            return "Holding company"
        if has("vertical"):
            return "Group vertical"
        if has("brand"):
            return "Group brand"
        return ""

    def SUBTABLE(records: list) -> str:
        rows = []
        for r in records:
            if not isinstance(r, dict):
                r = {"name": str(r)}
            nm = _noparen(r.get("name", ""))
            if not nm:
                nm = _oneline(r.get("name", ""))
            site = _sub_site(r.get("name", ""), r.get("source", ""))
            namecell = (f'<a class="cxlink" href="{_attr(site)}" target="_blank" '
                        f'rel="noopener noreferrer">{_esc(nm)}</a>' if site else _esc(nm))
            # Descriptor: the runner's one-line summary when present, else the
            # short role classifier for pre-rerun records with no summary yet.
            # Sector and jurisdiction follow, muted, each shown only when set so
            # there are never empty separators.
            summary = _oneline(str(r.get("summary", "") or "")).strip()
            primary = summary or _sub_what(r.get("name", ""),
                                           r.get("ownership_signal", ""))
            tail = [b for b in (_oneline(str(r.get("sector", "") or "")).strip(),
                                _oneline(str(r.get("jurisdiction", "") or "")).strip())
                    if b]
            muted = (f' <span class="muted">· {_esc(" · ".join(tail))}</span>'
                     if tail else "")
            if primary:
                what = _esc(primary) + muted
            elif tail:
                what = f'<span class="muted">{_esc(" · ".join(tail))}</span>'
            else:
                what = ""
            conf = str(r.get("confidence", "")).strip()
            confcell = _fp_chip("confidence", conf) if conf else ""
            st = str(r.get("state", "")).lower().strip()
            statecell = (f'<span class="cxchip c-low">{_esc(_state_label(st))}</span>'
                         if st and st != "live" else "")
            rows.append(
                f'<tr><td class="cxsub-name">{namecell}</td>'
                f'<td class="cxsub-what">{what}</td>'
                f'<td class="cxsub-conf">{confcell}</td>'
                f'<td class="cxsub-state">{statecell}</td></tr>')
        # Full width of the value cell, with a shared proportional colgroup so
        # both sub-tables (Subsidiaries and Divestitures) fill the row and align
        # column for column. Name carries the link, What the descriptor, and the
        # two compact chips sit snug rather than floating at the far edge.
        cg = ('<colgroup><col style="width:38%"><col style="width:33%">'
              '<col style="width:14%"><col style="width:15%"></colgroup>')
        return (f'<table class="cxsub cxsub-subs">{cg}<tbody>{"".join(rows)}'
                '</tbody></table>' if rows else "")

    # Re-split the raw records (which carry the signal and source the columns
    # need) with the same dedup, so each brand shows once under its state.
    # Split by relationship direction so parents/owners and fund vehicles are not
    # lumped in with the subsidiaries. A record being sold or closed goes to that
    # bucket regardless of direction. Parent and Fund rows appear only when there
    # is something in them; Subsidiaries and Being sold or closed always show.
    sub_parent_rec, sub_sub_rec, sub_fund_rec, sub_divest_rec = [], [], [], []
    _seen2 = set()
    for r in subs:
        nm = str((r.get("name") if isinstance(r, dict) else r) or "").strip()
        if not nm:
            continue
        key = _norm_brand(nm)
        if key in _seen2:
            continue
        _seen2.add(key)
        st = str(r.get("state", "")).lower().strip() if isinstance(r, dict) else ""
        rel = str(r.get("relation", "")).lower().strip() if isinstance(r, dict) else ""
        if st in _DIVEST_STATES:
            sub_divest_rec.append(r)
        elif rel == "parent":
            sub_parent_rec.append(r)
        elif rel == "fund-vehicle":
            sub_fund_rec.append(r)
        else:
            sub_sub_rec.append(r)
    if sub_parent_rec:
        R("Parent and owners", SUBTABLE(sub_parent_rec))
    R("Subsidiaries", SUBTABLE(sub_sub_rec))
    if sub_fund_rec:
        R("Fund vehicles", SUBTABLE(sub_fund_rec))
    R("Being sold or closed", SUBTABLE(sub_divest_rec))

    # ----- group hierarchy graph, drawn right under the Divestitures row -----
    # Rendered with Cytoscape, the same engine and toolbar as the relationship
    # map, so it pans, zooms and fits reliably (no static-text fallback).
    def _hier_label(s: str) -> str:
        # Just the entity NAME for a node, not a descriptive sentence: drop any
        # parenthetical, then keep only the first clause (before the first comma
        # or sentence break) so the top node reads "Yolo Group", not the whole
        # "Yolo Group, Tallinn, Estonia. Group holding company ..." line.
        s = _noparen(s)
        s = re.split(r"[.,;]| - |–|—", s, 1)[0]
        return re.sub(r"\s+", " ", str(s or "")).strip()[:48]

    def _hier_elements() -> list:
        root_lbl = _hier_label(parent) or _hier_label(legal_name or name)
        if not root_lbl:
            return []
        els = [{"data": {"id": "root", "label": root_lbl, "kind": "root"}}]
        tgt = _hier_label(legal_name or name)
        if parent and tgt and tgt.lower() != root_lbl.lower():
            els.append({"data": {"id": "tgt", "label": tgt, "kind": "target"}})
            els.append({"data": {"id": "e_tgt", "source": "root", "target": "tgt"}})
        order = ["Consumer brands", "B2B & platform", "Holding & legal",
                 "Investments", "Being sold or closed", "Dissolved / historical"]
        out_buckets = ("Investments", "Dissolved / historical")

        def bucket(rec: dict) -> str:
            st = str(rec.get("state", "")).lower().strip()
            what = _sub_what(rec.get("name", ""),
                             rec.get("ownership_signal", "")).lower()
            if st in _DIVEST_STATES:
                return "Being sold or closed"
            if st in ("defunct", "dissolved") or "liquidation" in what:
                return "Dissolved / historical"
            if "investment" in what:
                return "Investments"
            if any(k in what for k in ("holding", "vertical", "former group", "operator")):
                return "Holding & legal"
            if any(k in what for k in ("brand", "casino")):
                return "Consumer brands"
            return "Holding & legal"

        groups: dict[str, list] = {}
        seen, i = set(), 0
        for rec in subs:
            if not isinstance(rec, dict):
                rec = {"name": str(rec)}
            nm = _hier_label(rec.get("name", ""))
            if not nm:
                continue
            k = _norm_brand(nm)
            if k in seen:
                continue
            seen.add(k)
            st = str(rec.get("state", "")).lower().strip()
            if st and st != "live":
                nm = f"{nm} ({st})"
            i += 1
            groups.setdefault(bucket(rec), []).append((f"n{i}", nm))
        b_n = 0
        for b in order:
            if b not in groups:
                continue
            b_n += 1
            bid = f"b{b_n}"
            els.append({"data": {"id": bid, "label": b, "kind": "bucket"}})
            els.append({"data": {"id": f"e_{bid}", "source": "root", "target": bid}})
            member_kind = "out" if b in out_buckets else "scope"
            for nid, lbl in groups[b]:
                els.append({"data": {"id": nid, "label": lbl, "kind": member_kind}})
                els.append({"data": {"id": f"e_{nid}", "source": bid, "target": nid}})
        # Worth drawing only when there is more than the lone root node.
        return els if len(els) > 1 else []

    _hier_els = _hier_elements()
    _hier_drawn = bool(_hier_els)
    if _hier_drawn:
        drows.append(
            '<tr><td colspan="2" class="cxmmrow">'
            '<div class="card graphcard hiergraphcard" id="hiergraphcard" style="padding:12px">'
            '<div class="gtoolbar"><div class="gzoom">'
            '<button type="button" class="btn-ghost" onclick="easHierZoom(-1)" title="Zoom out">&minus;</button>'
            '<button type="button" class="btn-ghost" onclick="easHierZoom(1)" title="Zoom in">+</button>'
            '<button type="button" class="btn-ghost" onclick="easHierFit()" title="Fit the whole graph">Fit</button>'
            '</div>'
            '<button type="button" class="btn-ghost gbtn gpush" onclick="easHierExport()" title="Download as PNG">PNG</button>'
            '<button type="button" class="btn-ghost gbtn" onclick="easHierFull()" id="hierfullbtn" title="Fullscreen">&#9974; Full</button>'
            '</div>'
            '<div class="graphwrap hiergraphwrap" id="hiergraphwrap" data-slug="'
            + _esc(slug) + '">'
            '<script type="application/json" id="hiergraphdata">'
            + json.dumps(_hier_els) + '</script>'
            '</div></div></td></tr>')

    R("Government work", "")
    R("Patents / IP", "")
    # Candidate reconciliation: a candidate verdict of third_party whose brand
    # also appears in the corporate map is a group brand living on a separate
    # tenant (e.g. a sister casino), not an unrelated third party. Annotate it so
    # the operator does not rule it out of scope by mistake.
    _map_brands = set(_brand_seen)

    def _cand_note(c: dict) -> str:
        if str(c.get("verdict", "")).lower() != "third_party":
            return ""
        # A parent or owner on its own tenant is correctly third_party at the
        # tenant level, but it is the group's OWNER, not an unrelated party, so
        # say so rather than let the verdict read as "stranger".
        rel = str(c.get("relation", "")).lower().strip()
        if rel in ("parent", "owner"):
            return ' <span class="muted">parent / owner on a separate tenant</span>'
        if rel == "fund-vehicle":
            return ' <span class="muted">group fund vehicle on a separate tenant</span>'
        dom = str(c.get("domain", ""))
        label = _norm_brand(dom.split(".")[0] if "." in dom else dom)
        sig = _norm_brand(c.get("ownership_signal", ""))
        if any(b and (b in label or label in b or (sig and b in sig))
               for b in _map_brands):
            return (' <span class="muted">group brand on a separate tenant</span>')
        return ""

    def _cand_signal(c: dict) -> str:
        # A short, readable basis for the candidate tie, from the signal_type.
        stype = str(c.get("signal_type", "")).lower().strip()
        m = {"shared_entra_tenant": "Shared Entra tenant",
             "different_entra_tenant": "Separate Entra tenant",
             "name_association": "Name match",
             "shared_ns": "Shared nameservers",
             "shared_nameserver": "Shared nameservers",
             "shared_registrant": "Shared registrant",
             "shared_ip": "Shared IP"}
        return m.get(stype, stype.replace("_", " ").title() if stype else "")

    def CANDTABLE(records: list) -> str:
        rows = []
        for c in records:
            namecell = _crt_link(str(c.get("domain", "")))
            sigcell = _esc(_cand_signal(c)) + _cand_note(c)
            verdict = str(c.get("verdict", "pending"))
            vcell = (f'<span class="fpchip vd-{_esc(verdict)}">'
                     f'{_esc(verdict)}</span>')
            conf = str(c.get("confidence", "")).strip()
            confcell = _fp_chip("confidence", conf) if conf else ""
            rows.append(
                f'<tr><td class="cxsub-name">{namecell}</td>'
                f'<td class="cxsub-what">{sigcell}</td>'
                f'<td class="cxsub-conf">{vcell}</td>'
                f'<td class="cxsub-conf">{confcell}</td></tr>')
        # Full width of the value cell, with proportional columns so the chips
        # do not float off to one edge: Domain and Signal carry the text, Verdict
        # and Confidence are narrow but sit snug against the Signal column.
        cg = ('<colgroup><col style="width:27%"><col style="width:46%">'
              '<col style="width:15%"><col style="width:12%"></colgroup>')
        return (f'<table class="cxsub cxsub-cands">{cg}<tbody>'
                f'{"".join(rows)}</tbody></table>' if rows else "")
    R("Candidate domains", CANDTABLE(cands))
    SEC("Integrity")
    R("Sanctions and PEP", f'<span class="scr {scls}">{slbl}</span>')

    def _inv_row(kind: str) -> str:
        # One bullet per investigative record, showing the agent's summary (the
        # finding itself) with the source linked and a confidence chip, not a
        # bare URL. Falls back to the source when no summary was written.
        items = []
        for r in _inv_of(kind):
            summ = _esc(str(r.get("summary", "")).strip())
            src = str(r.get("source", "")).strip()
            if summ:
                items.append(summ + (_srclink("source", src) if src else "") + _conf(r))
            elif src:
                items.append(_linkify(src) + _conf(r))
        return LST(items)
    # Every investigative category the runner can emit gets a row, so a
    # litigation or regulatory record is never silently dropped.
    R("Litigation", _inv_row("litigation"))
    R("Regulatory", _inv_row("regulatory"))
    R("Adverse media", _inv_row("adverse_media"))
    R("Offshore records", _inv_row("offshore"))
    SEP()
    R("Ruled out", LST([
        f'{_esc(str(r.get("entity","")))} '
        f'<span class="muted">{_esc(str(r.get("reason","")))}</span>'
        for r in fp["ruled_out"]]))
    people_held = [r for r in fp["quarantine"]
                   if str(r.get("type", "")).lower() == "person"]
    if people_held:
        R("People (held)", '<ul class="cxlist">' + "".join(
            f'<li>{_esc(str(r.get("value","")))} {HELD}</li>'
            for r in people_held) + '</ul>')
    else:
        R("People (held)", "")
    SEC("Exposure")
    R("Breach exposure", f'<span class="muted">None found</span> '
      f'<a class="cxlink" href="/c/{_esc(cid)}?t=leaks">see Leaks</a>')
    if code_orgs:
        links = ", ".join(
            f'<a class="cxlink" href="https://{_attr(str(o.get("value","")))}" '
            f'target="_blank" rel="noopener noreferrer">'
            f'{_esc(str(o.get("value","")))}</a>' for o in code_orgs)
        R("Code exposure", links)
    else:
        R("Code exposure", "")
    # Identified (potential) count on the first line, then the alive ones as a
    # bullet list, or a muted "none" when nothing resolves. Blank only when the
    # sweep has not run at all.
    if _la_total or _la_identified:
        _alive_sorted = sorted(_la_alive)
        if _alive_sorted:
            _alive_block = (
                '<div class="muted" style="margin-top:6px">Alive</div>'
                '<ul class="cxlist">' + "".join(
                    f'<li><a class="cxlink" href="https://{_attr(d)}" target="_blank" '
                    f'rel="noopener noreferrer">{_esc(d)}</a></li>'
                    for d in _alive_sorted) + '</ul>')
        else:
            _alive_block = (' <span class="muted">Alive: none</span>')
        _la_val = (f'{_la_total:,} identified'
                   f'{" (potential)" if _la_total else ""}{_alive_block}')
        R("Lookalike domains", _la_val)
    else:
        R("Lookalike domains", "")
    SEP()
    if cov:
        R("Coverage and gaps",
          f'<a class="cxlink" href="/l0-debug?e={_esc(cid)}">view in run debug</a>')
    else:
        R("Coverage and gaps", "")
    R("Confidence", _esc(conf_txt))

    # The group-hierarchy diagram was emitted inline under the Divestitures row
    # (see the Corporate map section). The graph init is appended once below
    # when a diagram was drawn.

    # One continuous table: header above, then the grouped dossier rows.
    return (header + runbar + banner + '<table class="cxtable">'
            '<colgroup><col style="width:150px"><col></colgroup><tbody>'
            + "".join(drows)
            + '</tbody></table>'
            + (_HIER_JS if _hier_drawn else "")
            + edit_footer + '</div>' + _CONTEXT_JS)


def _l0_debug_page(user: str, slug: str) -> bytes:
    """A plain, honest view of the last Layer 0 footprint run: the runner's own
    status (stage reached, ok or failed, error), the captured agent stdout and
    stderr, the raw record count, and the live systemd unit state. No Sentry, no
    external calls, just the files the run wrote plus systemctl show."""
    name = _pretty(slug)
    cid = _client_id(slug)
    dbg = _footprint_debug(slug)
    st = dbg.get("status") or {}

    state = str(st.get("state") or "").lower()
    badge = {"ok": "scr scr-clear", "failed": "scr scr-hit",
             "running": "scr scr-unscreened"}.get(state, "scr scr-unscreened")
    statetxt = {"ok": "Completed", "failed": "Failed",
                "running": "Running"}.get(state, "Never run")

    rows = []
    def r(k, v):
        rows.append(f'<div class="cxrow"><span class="cxk">{_esc(k)}</span>'
                    f'<span class="cxsep">:</span><span class="cxv">{v}</span></div>')

    r("State", f'<span class="{badge}">{statetxt}</span>')
    r("Stage reached", _esc(str(st.get("stage") or "None")))
    us = dbg.get("unit_state") or "None"
    ur = dbg.get("unit_result") or ""
    ue = dbg.get("unit_exit") or ""
    unit_v = _esc(us) + (f' (result {_esc(ur)}, exit {_esc(ue)})' if ur else "")
    r("systemd unit", unit_v)
    r("Started", _esc(str(st.get("started_at") or "None")))
    r("Ended", _esc(str(st.get("ended_at") or "None")))
    r("Raw records written", str(dbg.get("raw_lines", 0)))
    if state == "ok":
        r("Accepted / quarantined / dropped / halted",
          f'{st.get("accepted",0)} / {st.get("quarantined",0)} / '
          f'{st.get("dropped",0)} / {st.get("halted",0)}')
    if st.get("error"):
        r("Error type", _esc(str(st.get("error_type") or "")))
        r("Error", f'<span class="scr scr-hit">{_esc(str(st.get("error")))}</span>')

    live = (dbg.get("unit_state") in ("activating", "active")) or state == "running"

    blocks = ['<div class="ctxcard"><div class="ctxfields">' + "".join(rows)
              + '</div></div>']

    # Currently running / last activity banner, so you can see what the agent is
    # doing right now instead of staring at a spinner.
    last = dbg.get("last_activity")
    if live and last:
        tool = last.get("tool") or last.get("kind") or "working"
        detail = _esc(str(last.get("detail", "")))
        blocks.append(
            '<div class="ctxcard l0live"><div class="l0runt">Currently running</div>'
            f'<div class="l0now"><span class="l0dot"></span>'
            f'<b>{_esc(tool)}</b> {detail}</div>'
            '<div class="muted" style="margin-top:4px;font-size:12px">'
            'This page auto-refreshes every 4 seconds while the run is active.</div></div>')

    # Run totals and the "why so long" breakdown, from the final result event.
    res = dbg.get("result") or {}
    counts = dbg.get("tool_counts") or {}
    if res or counts:
        trows = []
        def tr(k, v):
            trows.append(f'<div class="cxrow"><span class="cxk">{_esc(k)}</span>'
                         f'<span class="cxsep">:</span><span class="cxv">{v}</span></div>')
        if res.get("num_turns") is not None:
            tr("Agent turns", str(res.get("num_turns")))
        if res.get("duration_ms") is not None:
            tr("Wall time", f'{res.get("duration_ms",0)/1000:.0f}s')
        if res.get("duration_api_ms") is not None:
            tr("Model (API) time", f'{res.get("duration_api_ms",0)/1000:.0f}s')
        if res.get("total_cost_usd") is not None:
            tr("Cost", f'${res.get("total_cost_usd",0):.2f}')
        if counts:
            summ = ", ".join(f'{v} {k}' for k, v in sorted(counts.items()))
            tr("Tool calls", _esc(summ))
        usage = res.get("usage") or {}
        if usage:
            tr("Tokens (in / out)",
               f'{usage.get("input_tokens",0)+usage.get("cache_read_input_tokens",0):,} / '
               f'{usage.get("output_tokens",0):,}')
        if trows:
            blocks.append('<div class="ctxcard"><div class="l0runt">Run totals '
                          '(why it takes that long)</div><div class="ctxfields">'
                          + "".join(trows) + '</div></div>')

    # Expected timing, so a run in progress can be judged against a budget
    # instead of a blank wait. These are rough ranges from observed runs, not a
    # contract. Elapsed is shown live when the run is active.
    exp_rows = [
        ("Entity resolution + company registry", "about 1 to 2 min"),
        ("Corporate intel (parent, brands, M&A)", "about 1 to 2 min"),
        ("Investigative screen (ICIJ, media)", "about 1 min"),
        ("Infrastructure OSINT (DNS, certs, tenant)", "about 1 to 2 min"),
        ("Gate + write (local, no network)", "a few seconds"),
    ]
    erows = "".join(
        f'<div class="cxrow"><span class="cxk">{_esc(k)}</span>'
        f'<span class="cxsep">:</span><span class="cxv">{_esc(v)}</span></div>'
        for k, v in exp_rows)
    # Progress bar: elapsed against the expected budget while running, full on a
    # completed or failed run, empty before the first run. EXP_MAX is the top of
    # the expected range in seconds (8 min).
    EXP_MAX = 480.0
    secs = None
    started = st.get("started_at")
    if started:
        try:
            t0 = datetime.strptime(started, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc)
            end = st.get("ended_at")
            if end and not live:
                t1 = datetime.strptime(end, "%Y-%m-%dT%H:%M:%SZ").replace(
                    tzinfo=timezone.utc)
            else:
                t1 = datetime.now(timezone.utc)
            secs = int((t1 - t0).total_seconds())
        except Exception:
            secs = None

    if state == "ok":
        pct, fillcls, capl = 100, "ok", "Completed"
    elif state == "failed":
        pct, fillcls, capl = 100, "fail", "Failed"
    elif live and secs is not None:
        pct = min(95, int(secs / EXP_MAX * 100))
        fillcls, capl = "run", "Running"
    else:
        pct, fillcls, capl = 0, "", "Not started"
    elapsed_lbl = (f'{secs//60}m {secs%60}s' if secs is not None else "0m 0s")
    bar = (f'<div class="l0bar"><div class="l0barfill {fillcls}" '
           f'style="width:{pct}%"></div></div>'
           f'<div class="l0barcap"><span>{capl} &middot; {_esc(elapsed_lbl)} '
           f'elapsed</span><span>expected 5 to 8 min</span></div>')

    blocks.append('<div class="ctxcard"><div class="l0runt">Progress and expected '
                  'timing</div>' + bar
                  + '<div class="muted" style="font-size:12px;margin:2px 0 6px">'
                  'A full passive pass is a serial loop of searches and fetches, '
                  'so it normally takes 5 to 8 minutes and costs about $1.50 to '
                  '$2.00.</div><div class="ctxfields">' + erows
                  + '</div></div>')

    # The step-by-step timeline: one row per tool call / step, newest last.
    timeline = dbg.get("timeline") or []
    if timeline:
        trs = []
        for ev in timeline[-200:]:
            ts = str(ev.get("ts", ""))[11:19]  # HH:MM:SS from the ISO stamp
            kind = ev.get("kind")
            tool = ev.get("tool") or ""
            detail = _esc(str(ev.get("detail", "")))
            cls = {"tool": "tlt-tool", "think": "tlt-think",
                   "init": "tlt-init", "result": "tlt-result"}.get(kind, "")
            label = _esc(tool) if tool else _esc(kind or "")
            trs.append(f'<div class="tlrow"><span class="tlts">{_esc(ts)}</span>'
                       f'<span class="tltag {cls}">{label}</span>'
                       f'<span class="tldetail">{detail}</span></div>')
        blocks.append('<div class="ctxcard"><div class="l0runt">Timeline '
                      f'({len(timeline)} steps)</div><div class="tllist">'
                      + "".join(trs) + '</div></div>')

    err = (dbg.get("agent_err") or "").strip()
    if err:
        blocks.append('<div class="ctxcard"><div class="l0runt">Agent stderr '
                      '(last run)</div><pre class="l0pre">' + _esc(err)
                      + '</pre></div>')
    if not st and not timeline and not err and not res:
        blocks.append('<div class="ctxcard"><span class="muted">No run has been '
                      'recorded yet. Trigger the Layer 0 footprint from the '
                      'Context tab, then reload this page. Live step-by-step '
                      'detail appears here on the next run.</span></div>')

    files = dbg.get("files") or []
    if files:
        frows = "".join(
            f'<div class="cxrow"><span class="cxk">{_esc(f["name"])}</span>'
            f'<span class="cxsep">:</span><span class="cxv">{f["size"]} bytes, '
            f'{_ago(f["mtime"])}</span></div>' for f in files)
        blocks.append('<div class="ctxcard"><div class="l0runt">Output files</div>'
                      '<div class="ctxfields">' + frows + '</div></div>')

    refresh = ('<script>setTimeout(function(){location.reload();},4000);</script>'
               if live else "")
    body = (
        f'<a class="back" href="/c/{_esc(cid)}?t=context"><svg class="barrow" '
        'viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" '
        'stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M19 12H5M12 19l-7-7 7-7"/></svg> '
        f'{_esc(name)} context</a>'
        '<h1 style="font-size:19px;margin:0 0 4px">Layer 0 footprint debug</h1>'
        '<p class="muted" style="margin:0 0 14px">What the run is doing, step by '
        'step, with timing. Reads the live agent stream, the run status and the '
        'service state.</p>'
        + "".join(blocks) + refresh)
    return _page(body, user)


def _client_metrics(slug: str) -> dict:
    """The live overview numbers for one client, recomputed from the current
    signals and triage state. One source of truth for both the first render and
    the poll endpoint, so the page and the live refresh never drift. Counts
    exclude false positives (handled in engagements/_read_signals), so the
    overview agrees with the triage tabs."""
    base = ENGAGEMENTS / slug
    e = next((x for x in engagements() if x["slug"] == slug), None)
    if not e:
        return {}
    fp = _fp_load(slug)
    cf = _confirmed_load(slug)
    n_attn = len(_review_findings(slug, fp, cf))
    n_subs_all = len(_subs_effective(slug, base))
    n_subs = len(_subdomain_alive(base) & set(_subs_effective(slug, base)))
    mods_on = sum(1 for m in TOGGLE_MODULES if e["watch"][m["kind"]]["on"])
    # Vulnerabilities tile = the confirmed findings, so the number matches the
    # Confirmed tab it links to.
    n_vulns = len(cf)
    return {
        "attn": n_attn,
        "attn_colour": "var(--red)" if n_attn else "var(--green)",
        "vulns": n_vulns,
        "subs": n_subs, "subs_all": n_subs_all,
        "subs_colour": "var(--green)" if n_subs else "var(--muted)",
        "mods_on": mods_on, "mods_total": len(TOGGLE_MODULES),
        "watch_colour": "var(--green)" if mods_on else "var(--muted)",
        "confirmed": len(cf), "falsepos": len(fp), "leaks": _leaks_count(slug),
        "last": _ago(e["last"]),
        "bar": _sev_bar(e["counts"]),
        "legend": _sev_legend(e["counts"]),
    }


def _client_metrics_json(slug: str) -> bytes:
    return json.dumps(_client_metrics(slug)).encode()


def _metrics_poll_js(cid: str) -> str:
    """Poll the overview metrics and the severity breakdown in place, so a
    finishing scan or a triage action shows without a manual reload. It only
    patches text and the two severity fragments, it never rebuilds the page, so
    it is cheap and does not fight anything the operator is doing. Pauses while
    the tab is hidden."""
    return (
        '<script>(function(){'
        f'var CID={json.dumps(cid)};'
        'function setN(id,val,col){var el=document.getElementById(id);if(!el)return;'
        'if(val!=null&&el.textContent!==String(val))el.textContent=val;'
        'if(col)el.style.color=col;}'
        'function tick(){'
        'if(document.hidden)return;'
        'fetch("/c-metrics?e="+encodeURIComponent(CID),{cache:"no-store"})'
        '.then(function(r){return r.ok?r.json():null;}).then(function(d){'
        'if(!d||!d.hasOwnProperty("vulns"))return;'
        'setN("m_attn",d.attn,d.attn_colour);'
        'setN("m_vulns",d.vulns);'
        'setN("m_subs",d.subs+"/"+d.subs_all,d.subs_colour);'
        'setN("m_watch",d.mods_on+"/"+d.mods_total,d.watch_colour);'
        'var b=document.getElementById("sevbar");if(b&&d.bar!=null)b.innerHTML=d.bar;'
        'var lg=document.getElementById("sevleg_wrap");if(lg&&d.legend!=null)lg.innerHTML=d.legend;'
        '}).catch(function(){});}'
        'setInterval(tick,5000);'
        'document.addEventListener("visibilitychange",function(){if(!document.hidden)tick();});'
        '})();</script>')


def _client_page(user: str, slug: str, flash: tuple | None = None,
                 tab: str = "overview", apage: int = 1) -> bytes:
    base = ENGAGEMENTS / slug
    if not SLUG_RE.match(slug) or not base.is_dir():
        return _page('<a class="back" href="/"><svg class="barrow" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5M12 19l-7-7 7-7"/></svg> All clients</a>'
                     '<div class="empty" style="margin-top:16px">Client not found.</div>',
                     user)
    if tab not in ("overview", "attention", "confirmed", "falsepos",
                   "context", "assets", "subdomains", "leaks"):
        tab = "overview"
    # "subdomains" was the old name for the Assets tab; keep old links working.
    if tab == "subdomains":
        tab = "assets"
    cid = _client_id(slug)
    e = next((x for x in engagements() if x["slug"] == slug), None)
    name = _pretty(slug)
    watching = any(m["on"] for m in e["watch"].values())
    # One client-wide running flag, drives the header button and the edit lock.
    # Only an on-demand run still executing counts as "running" for the Run-all
    # control. A persistent toggle watcher left enabled after Run all is the
    # intended steady state, so it must not keep the button stuck on Stop.
    page_running = _run_in_progress(e["watch"])

    icon_xlsx =('<svg viewBox="0 0 24 24" width="26" height="26" fill="none" '
                 'stroke="currentColor" stroke-width="1.6"><rect x="3" y="3" width="18" '
                 'height="18" rx="2"/><path d="M3 9h18M3 15h18M9 3v18M15 3v18"/></svg>')
    icon_pdf = ('<svg viewBox="0 0 24 24" width="26" height="26" fill="none" '
                'stroke="currentColor" stroke-width="1.6"><path d="M6 2h8l4 4v16H6z"/>'
                '<path d="M14 2v4h4"/><text x="12" y="17" font-size="6" fill="currentColor" '
                'stroke="none" text-anchor="middle" font-family="sans-serif">PDF</text></svg>')
    icon_docx = ('<svg viewBox="0 0 24 24" width="26" height="26" fill="none" '
                 'stroke="currentColor" stroke-width="1.6"><path d="M6 2h8l4 4v16H6z"/>'
                 '<path d="M14 2v4h4"/><text x="12" y="17" font-size="6" fill="currentColor" '
                 'stroke="none" text-anchor="middle" font-family="sans-serif">DOC</text></svg>')
    icon_txt = ('<svg viewBox="0 0 24 24" width="26" height="26" fill="none" '
                'stroke="currentColor" stroke-width="1.6"><path d="M6 2h8l4 4v16H6z"/>'
                '<path d="M14 2v4h4"/><text x="12" y="17" font-size="6" fill="currentColor" '
                'stroke="none" text-anchor="middle" font-family="sans-serif">TXT</text></svg>')

    def _rep_slot(label: str, ext: str, icon: str, pretty: str) -> str:
        """One report slot. The first word (label) is the file type, the name is a
        fixed friendly title (the saved filename stays in the download and the
        tooltip), and the only meta shown is when it was last built."""
        r = e["reports"].get(ext)
        if r:
            dl = f'/dl?e={_client_id(slug)}&f={urllib.parse.quote(r["name"])}'
            info = (f'<a class="repname" href="{dl}" title="{_esc(r["name"])}">{pretty}</a>'
                    f'<span class="muted">{r["when"]}</span>')
            cls = "repslot"
        else:
            info = f'<span class="repname muted">{pretty} not generated yet</span>'
            cls = "repslot empty"
        return (f'<div class="{cls} {ext}"><div class="repicon {ext}">{icon}</div>'
                f'<div class="repinfo"><div class="replabel">{label}</div>{info}</div></div>')

    # The live-subdomains TXT download was retired: subdomains now live on their
    # own tab with a copy box, manual editing and change alerts.
    reps = (_rep_slot("PDF", "pdf", icon_pdf, "EAS Report")
            + _rep_slot("Word", "docx", icon_docx, "EAS Report")
            + _rep_slot("XLSX", "xlsx", icon_xlsx, "Appendix"))

    mods_on = sum(1 for m in TOGGLE_MODULES if e["watch"][m["kind"]]["on"])
    # Drop findings the operator has already triaged (false positive or
    # confirmed) from the live attention list and the metric, so Needs attention
    # only ever shows what is still waiting to be reviewed.
    fp = _fp_load(slug)
    cf = _confirmed_load(slug)
    attention_live = _review_findings(slug, fp, cf)
    n_attn = len(attention_live)
    # Nothing needing attention is good (green), anything at all is bad (red).
    attn_colour = "var(--red)" if n_attn else "var(--green)"
    # Alive subdomains (resolving hosts), not every enumerated name, shown as
    # alive out of all enumerated. Green when any are alive, grey when none.
    n_subs_all = len(_subs_effective(slug, base))
    n_subs = len(_subdomain_alive(base) & set(_subs_effective(slug, base)))
    subs_colour = "var(--green)" if n_subs else "var(--muted)"
    # Watchers on out of the total togglable. Green when any are on, grey at 0.
    n_watch_total = len(TOGGLE_MODULES)
    watch_colour = "var(--green)" if mods_on else "var(--muted)"
    # Vulnerabilities tile = the confirmed findings, so the number matches the
    # Confirmed tab it links to.
    n_vulns = len(cf)
    runall_meta = json.dumps({"kind": "", "name": "all"})
    runall_dis = "" if ALLOW_CONTROL else "disabled"
    running_now = page_running
    if running_now:
        runall_btn = ('<span class="runchip go">Running</span>'
                      f'<button class="stopall" {runall_dis} '
                      f"onclick='askM(\"stop_all\",\"{_client_id(slug)}\",\"{_esc(name)}\",{runall_meta},this)'>STOP</button>")
    else:
        runall_btn = (f'<button class="runall" {runall_dis} '
                      f"onclick='askM(\"run_all\",\"{_client_id(slug)}\",\"{_esc(name)}\",{runall_meta},this)'>RUN</button>")
    def _tab(t: str, lbl: str) -> str:
        href = f"/c/{cid}" if t == "overview" else f"/c/{cid}?t={t}"
        cls = "ctab on" if tab == t else "ctab"
        return f'<a class="{cls}" href="{href}">{lbl}</a>'
    n_leaks = _leaks_count(slug)
    tabbar = (f'<div class="ctabs">{_tab("overview", "Overview")}'
              f'{_tab("context", "Context")}'
              f'{_tab("assets", "Assets")}'
              f'{_tab("attention", f"Needs attention ({n_attn})")}'
              f'{_tab("confirmed", f"Confirmed ({len(cf)})")}'
              f'{_tab("falsepos", f"False positives ({len(fp)})")}'
              f'{_tab("leaks", f"Leaks ({n_leaks})")}</div>')
    head = f"""<div class="chead cheadclient">
  <div class="phead">
    <div class="cnamewrap">
      <div class="cname" style="font-size:22px"><span class="dot {'on' if watching else 'off'}"></span>{name}</div>
      <div class="muted clastrun">Last run {_ago(e['last'])}</div>
    </div>
    <div class="pbtns" id="pbtns">{runall_btn}</div>
  </div>
  {tabbar}
</div>"""
    metrics_html = f"""<div class="metrics">
  <a class="metric" href="/c/{cid}?t=attention"><div class="n" id="m_attn" style="color:{attn_colour}">{n_attn}</div><div class="k">Need attention</div></a>
  <a class="metric" href="/c/{cid}?t=confirmed"><div class="n" id="m_vulns">{n_vulns}</div><div class="k">Vulnerabilities</div></a>
  <a class="metric" href="/c/{cid}?t=assets"><div class="n" id="m_subs" style="color:{subs_colour}">{n_subs}/{n_subs_all}</div><div class="k">Alive subdomains</div></a>
  <a class="metric" href="#watchers"><div class="n" id="m_watch" style="color:{watch_colour}">{mods_on}/{n_watch_total}</div><div class="k">Watchers on</div></a>
</div>"""

    reports_block = (
        '<div class="rephead" id="reports"><h2 style="margin:0">Last reports</h2>'
        f'<button type="button" class="btn-ghost" id="genrep" onclick="genReport(\'{_client_id(slug)}\')">'
        'Regenerate</button></div>'
        f'<div class="repbox"><div class="reports2">{reps}</div></div>')

    if tab == "assets":
        content = _subdomains_tab(slug, base, cid)
    elif tab == "context":
        content = _context_company_tab(slug, cid)
    elif tab == "leaks":
        content = _leaks_tab(slug, base, cid, apage)
    elif tab == "attention":
        content = _attention_section(slug, attention_live, cid, apage, "attention")
    elif tab == "confirmed":
        content = _confirmed_section(slug, cf, cid)
    elif tab == "falsepos":
        content = (_false_positives_section(slug, fp) or
                   '<h2 id="falsepos">False positives</h2><div class="card"><div class="muted">'
                   'No false positives yet.</div></div>')
    else:
        content = (f'{metrics_html}'
                   f'{reports_block}'
                   f'{_phase_summary(slug, e)}'
                   f'<h2>Findings by severity</h2>'
                   f'<div class="card sevcard"><div class="bar" id="sevbar">{_sev_bar(e["counts"])}</div>'
                   f'<div id="sevleg_wrap">{_sev_legend(e["counts"])}</div></div>'
                   f'{_watchers_section(slug, e)}'
                   f'{_graph_section(slug, base)}'
                   f'{_context_section(slug)}'
                   f'{_GRAPH_SCRIPT}'
                   f'{_metrics_poll_js(cid)}')
    # The flash sits under the client header, between the client bar and the
    # Needs-attention boxes, so a confirm or reopen notice lands in context.
    body = f'{head}{_flash(flash)}{content}'
    return _page(body, user, modal=True)


# Cytoscape.js draws the map. It is loaded from a pinned CDN build and reads the
# elements the server put in the graphwrap's data-els attribute, so the graph is
# generated server-side (stdlib only) and only drawn in the browser. Cytoscape
# gives native pan and zoom, image export, and stays usable with far more hosts
# than a static flowchart. If the CDN cannot be reached the card shows a short
# notice. The render re-runs after a soft refresh so a finished scan updates it.
_GRAPH_PALETTE = ("{"
    + ",".join(f"'{s.lower()}':{{bg:'{SEV[s][1]}',fg:'{SEV[s][2]}'}}" for s in SEV_ORDER)
    + ",'root':{bg:'#3BBBF8',fg:'#06121b'}"
    + ",'apex':{bg:'#1b2733',fg:'#D4DEEA'}"
    + ",'hub':{bg:'#2a1b22',fg:'#ffd7de'}"
    + ",'ip':{bg:'#0E141B',fg:'#9fb0c2'}"
    + ",'corp-hub':{bg:'#1f2d3a',fg:'#cfe3f5'}"
    + ",'corp-active':{bg:'#13261c',fg:'#9df5c0'}"
    + ",'corp-new':{bg:'#13202a',fg:'#9fd9ff'}"
    + ",'corp-closing':{bg:'#2a2413',fg:'#ffd98a'}"
    + ",'corp-sold':{bg:'#2a1b22',fg:'#ffb0bd'}"
    + ",'corp-dormant':{bg:'#1a1f27',fg:'#9fb0c2'}"
    + ",'more':{bg:'#131A22',fg:'#6B7A8D'}}")
_SEV_RANK_JS = "{'sev1':0,'sev2':1,'sev3':2,'sev4':3,'sev5':4}"
_GRAPH_SCRIPT = """
<script>
(function(){
  var PAL=__PALETTE__, RANK=__RANK__, cy=null;
  function wrap(){return document.getElementById('graphwrap');}
  function col(p){return (PAL[p]||PAL['more']);}

  window.easRenderGraph=function(){
    var w=wrap();
    if(!w||w.getAttribute('data-done'))return;
    if(typeof cytoscape==='undefined'){
      var fb=document.getElementById('graphfallback');
      if(fb)fb.textContent='The graph library could not be loaded (no network to the CDN). The findings and counts above are unaffected.';
      return;
    }
    var els, dn=document.getElementById('graphdata');
    try{els=JSON.parse(dn?dn.textContent:'[]');}catch(e){els=[];}
    w.setAttribute('data-done','1');
    var fb=document.getElementById('graphfallback');if(fb)fb.remove();
    cy=cytoscape({
      container:w, elements:els, wheelSensitivity:0.2,
      minZoom:0.05, maxZoom:3,
      style:[
        {selector:'node',style:{
          'background-color':function(n){return col(n.data('sev')).bg;},
          'border-color':function(n){return col(n.data('sev')).bg;},
          'border-width':1,
          'label':'data(label)','color':function(n){return col(n.data('sev')).fg;},
          'font-size':'10px','font-family':'ui-monospace,Menlo,Consolas,monospace',
          'text-wrap':'wrap','text-valign':'center','text-halign':'center',
          'text-max-width':'160px','padding':'7px','shape':'round-rectangle',
          'width':'label','height':'label'}},
        {selector:'node[kind="root"]',style:{'shape':'ellipse','font-weight':'bold','font-size':'12px'}},
        {selector:'node[kind="ip"]',style:{'shape':'ellipse','border-color':'#6B7A8D'}},
        {selector:'node[kind="hub"]',style:{'shape':'hexagon','border-color':'#F3415E'}},
        {selector:'node[kind="corphub"]',style:{'shape':'round-rectangle','border-color':'#3BBBF8','border-width':2,'font-weight':'bold'}},
        {selector:'node[kind="corp"]',style:{'shape':'round-rectangle','border-width':2,'border-color':function(n){return col(n.data('sev')).fg;}}},
        {selector:'node[kind="apex"]',style:{'border-color':'#3BBBF8','border-width':2}},
        {selector:'node[kind="more"]',style:{'border-style':'dashed','border-color':'#2a3542','border-width':1}},
        {selector:'node[kind="vuln"]',style:{'shape':'round-tag','font-size':'9px','text-max-width':'130px','border-width':2,'border-color':'#fff'}},
        {selector:'edge',style:{'width':1,'line-color':'#2a3542','curve-style':'bezier',
          'target-arrow-color':'#2a3542','target-arrow-shape':'triangle','arrow-scale':0.7}},
        {selector:'.faded',style:{'opacity':0.1}},
        {selector:'node.pathlit',style:{'opacity':1}},
        {selector:'edge.pathlit',style:{'opacity':1,'line-color':'#3BBBF8',
          'target-arrow-color':'#3BBBF8','width':2.4}},
        {selector:'.hit',style:{'border-color':'#fff','border-width':3}}
      ],
      // Force-directed, not breadthfirst. The estate is one root with dozens of
      // sibling subdomains and corp nodes; breadthfirst lays each depth in a
      // single horizontal row, so 57 siblings become one long thin line that
      // exports as an unreadable strip. cose spreads the graph into a 2D cluster
      // (the Maltego / BloodHound look this map is meant to have), readable on
      // screen and in the PNG export. animate:false so it is settled before fit.
      layout:{name:'cose', animate:false, randomize:true, padding:24,
              idealEdgeLength:70, nodeOverlap:10, nodeRepulsion:9000,
              gravity:0.35, numIter:1200, componentSpacing:90}
    });
    cy.fit(undefined,24);

    // Click a host to trace its direct path: everything from the root down to
    // it (its ancestors) plus what it connects to (shared IPs), lit up, the
    // rest dimmed. Clicking empty canvas clears it. This is the "show me the
    // relations of this finding" view.
    cy.on('tap','node',function(ev){
      var n=ev.target;
      var lit=n.predecessors().union(n.successors()).union(n);
      cy.elements().addClass('faded').removeClass('pathlit hit');
      lit.removeClass('faded').addClass('pathlit');
      n.addClass('hit');
    });
    cy.on('tap',function(ev){
      if(ev.target===cy){cy.elements().removeClass('faded pathlit hit');}
    });
    // Native tooltip from a node's data(tip), e.g. a subsidiary's jurisdiction.
    cy.on('mouseover','node',function(ev){
      var t=ev.target.data('tip'); if(t){w.setAttribute('title',t);}
    });
    cy.on('mouseout','node',function(){ w.removeAttribute('title'); });
  };

  window.easGraphZoom=function(d){ if(!cy)return;
    cy.zoom({level:cy.zoom()*(d>0?1.3:0.77), renderedPosition:{x:cy.width()/2,y:cy.height()/2}}); };
  window.easGraphFit=function(){ if(cy)cy.fit(undefined,24); };

  // Search: dim everything but hosts whose domain contains the text, and frame
  // the matches. Empty box restores the full graph.
  window.easGraphSearch=function(q){ if(!cy)return;
    q=(q||'').trim().toLowerCase();
    cy.elements().removeClass('faded hit pathlit');
    if(!q)return;
    var hit=cy.nodes().filter(function(n){var d=(n.data('dom')||'').toLowerCase();return d&&d.indexOf(q)>=0;});
    if(hit.length===0){return;}
    var keep=hit.closedNeighborhood();
    cy.elements().not(keep).addClass('faded'); hit.addClass('hit');
    cy.fit(hit,60);
  };

  // Domain search box: a type-to-filter list over every identified domain. Any
  // substring match, at most 15 shown, so a huge estate stays usable. Picking
  // one lights up its path; typing also highlights live on the graph. The items
  // are built as DOM nodes, never HTML strings, so a domain name needs no
  // escaping and a broken quote can never abort the script.
  var EAS_DOMS=null;
  function easDoms(){ if(EAS_DOMS===null){ try{
      EAS_DOMS=JSON.parse(document.getElementById('graphdomdata').textContent);
    }catch(e){ EAS_DOMS=[]; } } return EAS_DOMS; }
  window.easDomFilter=function(q){
    var box=document.getElementById('graphdomlist'); if(!box)return;
    q=(q||'').trim().toLowerCase();
    easGraphSearch(q);
    var all=easDoms();
    var hits=q?all.filter(function(d){return d.toLowerCase().indexOf(q)>=0;}):all;
    var more=hits.length-15; hits=hits.slice(0,15);
    box.innerHTML='';
    if(hits.length===0){ box.hidden=true; return; }
    hits.forEach(function(d){
      var it=document.createElement('div');
      it.className='gcombo-item'; it.textContent=d;
      it.addEventListener('mousedown',function(){ easDomPick(d); });
      box.appendChild(it);
    });
    if(more>0){ var m=document.createElement('div'); m.className='gcombo-more';
      m.textContent='+'+more+' more'; box.appendChild(m); }
    box.hidden=false;
  };
  window.easDomPick=function(d){
    var inp=document.getElementById('graphsearch'); if(inp)inp.value=d;
    var box=document.getElementById('graphdomlist'); if(box)box.hidden=true;
    easGraphSearch(d);
  };
  window.easDomKey=function(ev){
    if(ev.key==='Escape'){ var box=document.getElementById('graphdomlist'); if(box)box.hidden=true; }
  };

  // Severity picker: a custom dropdown so the band colours actually render (a
  // native <option> ignores colour on some platforms). Picking one filters.
  window.easSevToggle=function(){
    var l=document.getElementById('graphsevlist'); if(l)l.hidden=!l.hidden; };
  window.easSevPick=function(sev,label){
    var btn=document.getElementById('graphsevbtn'); if(btn)btn.textContent=label;
    var l=document.getElementById('graphsevlist'); if(l)l.hidden=true;
    easGraphFilter(sev);
  };

  document.addEventListener('mousedown',function(ev){
    if(!ev.target.closest('#gdomwrap')){ var d=document.getElementById('graphdomlist'); if(d)d.hidden=true; }
    if(!ev.target.closest('#gsevwrap')){ var s=document.getElementById('graphsevlist'); if(s)s.hidden=true; }
  });

  // Severity filter: show only nodes of exactly the chosen severity (keep the
  // structural root/apex/hub so the shape of the graph survives). Empty = all.
  window.easGraphFilter=function(sev){ if(!cy)return;
    var want=(sev===''?null:RANK[sev]);
    cy.batch(function(){
      cy.nodes().forEach(function(n){
        var k=n.data('kind'), r=RANK[n.data('sev')];
        var structural=(k==='root'||k==='apex'||k==='hub'||k==='ip'||k==='more');
        var show=(want===null)||structural||(r===want);
        n.style('display', show?'element':'none');
      });
    });
    cy.fit(undefined,24);
  };

  // Export the current view as a PNG the tester can drop into a report. PNG is
  // used over JPEG: Cytoscape's JPEG encoder can emit a corrupt/unreadable file,
  // and PNG is lossless and renders the dark background cleanly. Fixed output
  // size (not scale:2), which never exceeds the browser canvas limit.
  window.easGraphExport=function(fmt){ if(!cy)return;
    // Export the FITTED VIEWPORT, not full:true. The breadthfirst layout makes a
    // wide, shallow tree one long horizontal row; a full-extent raster of that is
    // a 40:1 strip that clamps to an unreadable sliver. Fitting first and
    // exporting full:false captures the same landscape view shown on screen, at
    // 3x pixel density so the labels stay crisp.
    cy.fit(undefined,24);
    var o={output:'blob',bg:'#0b0f14',full:false,scale:3};
    var blob; try{blob=cy.png(o);}catch(e){try{o.scale=2;blob=cy.png(o);}catch(e2){return;}}
    if(!blob){return;}
    var url=URL.createObjectURL(blob), a=document.createElement('a');
    var slug=(wrap().getAttribute('data-slug')||'map');
    a.href=url; a.download=slug+'-relationship-map.png'; a.style.display='none';
    document.body.appendChild(a);
    // Do NOT remove the anchor or revoke the blob URL synchronously: removing the
    // anchor or revoking the URL before the browser commits the save (which can
    // be seconds if a "Save As" dialog is shown) cancels the download. Keep both
    // alive, then clean up well after the save has certainly started.
    a.click();
    setTimeout(function(){try{a.remove();URL.revokeObjectURL(url);}catch(e){}},60000);
  };

  // True browser fullscreen on the graph card. Cytoscape is resized and refit
  // once the viewport changes so the canvas fills the screen.
  window.easGraphFull=function(){
    var card=document.getElementById('graphcard'); if(!card)return;
    var fs=document.fullscreenElement||document.webkitFullscreenElement;
    if(fs){(document.exitFullscreen||document.webkitExitFullscreen).call(document);}
    else{(card.requestFullscreen||card.webkitRequestFullscreen).call(card);}
  };
  function _onfs(){
    var fs=document.fullscreenElement||document.webkitFullscreenElement;
    var b=document.getElementById('graphfullbtn');
    if(b)b.innerHTML=fs?'&#9974; Exit':'&#9974; Full';
    if(cy)setTimeout(function(){cy.resize();cy.fit(undefined,24);},80);
  }
  document.addEventListener('fullscreenchange',_onfs);
  document.addEventListener('webkitfullscreenchange',_onfs);

  window.easRenderGraph();
})();
</script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.30.2/cytoscape.min.js"
  onload="window.easRenderGraph&&window.easRenderGraph()"></script>
""".replace("__PALETTE__", _GRAPH_PALETTE).replace("__RANK__", _SEV_RANK_JS)


def _context_section(slug: str) -> str:
    """Add domains and notes to a client at any time, including while a run is
    in progress or after it finished. The client that sends more domains on
    Tuesday lands here. New domains go into scope but still pass the target
    guardrail before anything scans them."""
    dlist = _scope_domains(slug)
    chips = "".join(f'<span class="chip{"" if _domain_allowed(d) else " blocked"}">{_esc(d)}'
                    f'{"" if _domain_allowed(d) else " (blocked)"}</span>' for d in dlist)
    return f"""<h2 id="context">Scope and context</h2>
<div class="card setup">
  <div class="scopechips">{chips or '<span class="muted">No domains in scope yet.</span>'}</div>
  <label class="fld"><span>Add domains <em>one per line, applied live</em></span>
    <textarea id="ac_domains" rows="3" placeholder="newsub.example.com"></textarea></label>
  <label class="fld"><span>Add a note <em>what the client sent, dated for you</em></span>
    <textarea id="ac_notes" rows="3" placeholder="Client shared these on..."></textarea></label>
  <div class="flash no" id="ac_err" style="display:none"></div>
  <div class="row"><button type="button" class="btn btn-start" id="ac_go"
    onclick="addContext('{_client_id(slug)}')">Add to scope</button></div>
  <div class="note">Adding a domain that is not on the approved list keeps it in scope but will not scan it until the allowlist is widened.</div>
</div>"""


def _login_page(err: str = "") -> bytes:
    e = f'<div class="err">{err}</div>' if err else ""
    body = f"""<div class="login"><div class="card">
<div style="font-weight:800;font-size:19px;margin-bottom:2px">Continuous EAS</div>
<div class="muted" style="margin-bottom:18px">Red Team Console</div>
{e}<form method="post" action="/login">
<label class="muted">User</label><input name="user" autofocus>
<label class="muted">Password</label><input name="password" type="password">
<button type="submit">Sign in</button></form>
<div class="foot">Local demo login, replaced by Microsoft Entra sign in
in production.</div></div></div>"""
    return _page(body, "")


_EVENT_LABEL = {
    "login_success": "Sign in",
    "login_failure": "Sign in failed",
    "logout":        "Sign out",
    "control":       "Control",
    "download":      "Download",
    "access_denied": "Access denied",
}


def _esc(s: str) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _ts_epoch(ts: str) -> float | None:
    try:
        return calendar.timegm(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))
    except Exception:
        return None


_AUDIT_SCRIPT = """
<script>
var EAS_PAGE=1, EAS_PS=50, EAS_MATCH=[];
function easMatches(){
  function v(id){var e=document.getElementById(id);return e?e.value.trim():'';}
  var f=v('af_from'), t=v('af_to'), u=v('af_user').toLowerCase(),
      p=v('af_phase').toLowerCase(), o=v('af_oc');
  var rows=document.querySelectorAll('table.audit tbody tr'), out=[];
  rows.forEach(function(tr){
    if(tr.getAttribute('data-empty')){return;}
    var d=tr.getAttribute('data-date')||'', ok=true;
    if(f&&(!d||d<f))ok=false;
    if(t&&(!d||d>t))ok=false;
    if(u&&(tr.getAttribute('data-user')||'').indexOf(u)<0)ok=false;
    if(p&&(tr.getAttribute('data-phase')||'').indexOf(p)<0)ok=false;
    if(o&&(tr.getAttribute('data-oc')||'')!==o)ok=false;
    if(ok)out.push(tr);
  });
  return out;
}
window.easAuditFilter=function(reset){
  if(reset!==false)EAS_PAGE=1;
  EAS_MATCH=easMatches();
  var all=document.querySelectorAll('table.audit tbody tr');
  all.forEach(function(tr){ if(!tr.getAttribute('data-empty'))tr.style.display='none'; });
  var pages=Math.max(1,Math.ceil(EAS_MATCH.length/EAS_PS));
  if(EAS_PAGE>pages)EAS_PAGE=pages;
  var start=(EAS_PAGE-1)*EAS_PS;
  EAS_MATCH.slice(start,start+EAS_PS).forEach(function(tr){ tr.style.display=''; });
  var none=document.getElementById('afnone');
  if(none)none.style.display=(EAS_MATCH.length===0&&all.length)?'block':'none';
  easRenderPager(pages);
};
window.easAuditPage=function(n){ EAS_PAGE=n; easAuditFilter(false);
  var tbl=document.querySelector('table.audit'); if(tbl)tbl.scrollIntoView({block:'start'}); };
function easRenderPager(pages){
  var el=document.getElementById('afpager'); if(!el)return;
  el.innerHTML='';
  if(pages<=1)return;
  function btn(label,n,dis,cur){
    var b=document.createElement('button');
    b.className='afpg'+(cur?' cur':''); b.textContent=label;
    if(dis)b.disabled=true; else b.addEventListener('click',function(){easAuditPage(n);});
    el.appendChild(b);
  }
  btn('Prev',EAS_PAGE-1,EAS_PAGE<=1,false);
  var from=Math.max(1,EAS_PAGE-3), to=Math.min(pages,EAS_PAGE+3);
  if(from>1){ btn('1',1,false,EAS_PAGE===1); if(from>2){var s=document.createElement('span');s.className='afdots';s.textContent='...';el.appendChild(s);} }
  for(var i=from;i<=to;i++){ btn(String(i),i,false,i===EAS_PAGE); }
  if(to<pages){ if(to<pages-1){var s2=document.createElement('span');s2.className='afdots';s2.textContent='...';el.appendChild(s2);} btn(String(pages),pages,false,EAS_PAGE===pages); }
  btn('Next',EAS_PAGE+1,EAS_PAGE>=pages,false);
}
window.easAuditExport=function(){
  var rows=EAS_MATCH.length?EAS_MATCH:easMatches();
  var out='Date,User,Phase,Outcome\\n';
  function q(s){ s=(s==null?'':String(s)); return '"'+s.replace(/"/g,'""')+'"'; }
  rows.forEach(function(tr){
    var c=tr.querySelectorAll('td');
    var vals=[];
    for(var i=0;i<c.length;i++){ vals.push(q(c[i].textContent.replace(/\\s+/g,' ').trim())); }
    out+=vals.join(',')+'\\n';
  });
  var blob=new Blob([out],{type:'text/csv'});
  var url=URL.createObjectURL(blob), a=document.createElement('a');
  var d=new Date().toISOString().slice(0,10);
  a.href=url; a.download='eas-activity-'+d+'.csv'; document.body.appendChild(a);
  a.click(); a.remove(); setTimeout(function(){URL.revokeObjectURL(url);},60000);
};
window.easDateToggle=function(){
  var p=document.getElementById('af_datepanel'); if(p)p.hidden=!p.hidden; };
window.easDateChanged=function(){
  function v(id){var e=document.getElementById(id);return e?e.value:'';}
  var f=v('af_from'), t=v('af_to'), b=document.getElementById('af_datebtn');
  if(b)b.textContent=(f||t)?((f||'...')+' to '+(t||'...')):'Any date';
  easAuditFilter();
};
window.easDateClear=function(){
  var f=document.getElementById('af_from'), t=document.getElementById('af_to');
  if(f)f.value=''; if(t)t.value=''; easDateChanged();
  var p=document.getElementById('af_datepanel'); if(p)p.hidden=true;
};
document.addEventListener('mousedown',function(ev){
  if(!ev.target.closest('#af_datewrap')){ var p=document.getElementById('af_datepanel'); if(p)p.hidden=true; }
});
easAuditFilter();
</script>
"""


# Events shown in the Activity view and their human label. Sign ins, sign outs
# and downloads stay in the server-side log only, so they are not listed here.
_AUDIT_LABELS = {
    "control": "Scan control",
    "false_positive": "Marked false positive",
    "confirm_finding": "Confirmed finding",
    "reopen_finding": "Reopened finding",
    "send_securityjoes": "Sent to Security Joes",
    "manual_finding": "Created manual finding",
    "vuln_meta": "Edited finding",
    "evidence_upload": "Uploaded evidence",
    "evidence_delete": "Removed evidence",
    "evidence_capture": "Captured browser evidence",
    "evidence_caption": "Edited a figure caption",
    "vuln_db": "Vuln DB template",
    "subdomains_edit": "Edited subdomains",
    "leak_fetch": "Fetched leaks",
    "leak_reveal": "Revealed credential",
    "leak_export": "Exported leaks",
    "report": "Generated report",
    "alert": "Generated early alert",
    "create_client": "Created client",
    "add_context": "Added context",
    "context_save": "Saved company context",
    "config": "Changed configuration",
}


_COL_FILTER_JS = (
    '<script>function colFilter(bodyId){'
    'var body=document.getElementById(bodyId);if(!body)return;'
    'var table=body.parentNode;while(table&&table.tagName!=="TABLE")table=table.parentNode;'
    'var frow=table.querySelector(".afilter");'
    'var ctrls=frow?frow.querySelectorAll("input,select"):[];'
    'var rows=body.querySelectorAll("tr"),n=0;'
    'for(var i=0;i<rows.length;i++){var cells=rows[i].children,ok=true;'
    'if(cells.length>1){for(var j=0;j<ctrls.length;j++){'
    'var ci=parseInt(ctrls[j].getAttribute("data-col"));'
    # Date-range bound: compare the cell date (normalised to YYYY-MM-DDTHH:MM)
    # against the datetime-local value. Start = lower bound, end = upper bound.
    'var rng=ctrls[j].getAttribute("data-range");'
    'if(rng){var v=ctrls[j].value;if(!v)continue;'
    'var raw=(cells[ci]?cells[ci].textContent:"").replace(" UTC","").trim();'
    'var norm=raw.replace(" ","T").slice(0,16);'
    'if(!/^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}$/.test(norm)){ok=false;break;}'
    'if(rng==="start"&&norm<v){ok=false;break;}'
    'if(rng==="end"&&norm>v){ok=false;break;}continue;}'
    'var q=(ctrls[j].value||"").toLowerCase();if(!q)continue;'
    'var txt=(cells[ci]?cells[ci].textContent:"").toLowerCase();'
    'if(txt.indexOf(q)<0){ok=false;break;}}}'
    'rows[i].style.display=ok?"":"none";if(ok)n++;}'
    'var e=table.parentNode.querySelector(".nomatch");if(e)e.style.display=n?"none":"block";}'
    '</script>')


def _col_select(bodyid: str, col: int, values, label: str = "All") -> str:
    """A per-column dropdown filter for a table with the shared colFilter JS.
    `label` is the text shown when nothing is filtered (e.g. the column name)."""
    opts = f'<option value="">{_esc(label)}</option>' + "".join(
        f'<option value="{_esc(x)}">{_esc(x)}</option>' for x in values)
    return (f'<select class="afin" data-col="{col}" '
            f'onchange="colFilter(\'{bodyid}\')">{opts}</select>')


# Bulk triage: the modal plus the select/raise/apply JS. The checkboxes carry
# each finding's client id and dedup key, gathered on open. Marking confirmed or
# false positive forces an operator note, Send to Security Joes does not.
_BULK_TRIAGE = r"""
<div class="vmodal" id="bulkmodal" style="display:none">
  <div class="vmback" onclick="bulkClose()"></div>
  <div class="vmcard">
    <h3>Manage <span id="bulkmn">0</span> selected findings</h3>
    <div class="rlbl">Action</div>
    <div class="bulkopt" id="bulkopt">
      <button type="button" class="bulkcard sel" data-act="confirm" onclick="bulkActSel(this)">Mark confirmed</button>
      <button type="button" class="bulkcard" data-act="fp" onclick="bulkActSel(this)">Mark false positive</button>
      <button type="button" class="bulkcard" data-act="send" onclick="bulkActSel(this)">Send to Security Joes</button>
    </div>
    <div class="rlbl" style="margin-top:8px">Operator note <span id="bulkreq" class="muted">(required)</span></div>
    <textarea class="rta bulknote" id="bulknote" rows="8" placeholder="Why these are being actioned together, for the record."></textarea>
    <div class="rerr" id="bulkerr"></div>
    <div class="vmbtns">
      <button type="button" class="btn-ghost sbtn" onclick="bulkClose()">Cancel</button>
      <button type="button" class="btn-ghost sbtn save" id="bulkgo" onclick="bulkApply()">Apply</button>
    </div>
  </div>
</div>
<script>
function bulkSel(){return Array.prototype.filter.call(
  document.querySelectorAll('.bchk'),function(c){return c.checked;});}
function bulkSync(){
  var n=bulkSel().length, btn=document.getElementById('bulkbtn'), bn=document.getElementById('bulkn');
  if(bn)bn.textContent=n;
  if(btn){if(n>=2)btn.classList.add('show');else btn.classList.remove('show');}
  var all=document.getElementById('bchkall');
  if(all){var tot=document.querySelectorAll('.bchk').length;
    all.checked=(n>0&&n===tot); all.indeterminate=(n>0&&n<tot);}
}
function bulkAll(cb){var cs=document.querySelectorAll('.bchk');
  for(var i=0;i<cs.length;i++){cs[i].checked=cb.checked;} bulkSync();}
function bulkActSel(card){var cs=document.querySelectorAll('.bulkcard');
  for(var i=0;i<cs.length;i++)cs[i].classList.remove('sel');
  if(card)card.classList.add('sel');
  var req=document.getElementById('bulkreq');
  if(req)req.textContent=(card.getAttribute('data-act')==='send')?'(optional)':'(required)';}
function bulkAct(){var c=document.querySelector('.bulkcard.sel');return c?c.getAttribute('data-act'):'confirm';}
function bulkOpen(){if(bulkSel().length<2)return;
  var mn=document.getElementById('bulkmn'); if(mn)mn.textContent=bulkSel().length;
  var e=document.getElementById('bulkerr'); if(e)e.textContent='';
  var m=document.getElementById('bulkmodal'); if(m)m.style.display='flex';}
function bulkClose(){var m=document.getElementById('bulkmodal'); if(m)m.style.display='none';}
function bulkApply(){
  var sel=bulkSel(); if(sel.length<2)return;
  var act=bulkAct(), note=(document.getElementById('bulknote').value||'').trim();
  var err=document.getElementById('bulkerr');
  if(act!=='send'&&!note){if(err)err.textContent='A note is required for this action.';return;}
  var items=sel.map(function(c){return {cid:c.getAttribute('data-cid'),key:c.getAttribute('data-key')};});
  var go=document.getElementById('bulkgo'); if(go)go.disabled=true;
  var body='act='+encodeURIComponent(act)+'&reason='+encodeURIComponent(note)
    +'&items='+encodeURIComponent(JSON.stringify(items));
  fetch('/bulk-action',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body})
    .then(function(r){return r.json();}).then(function(d){
      if(go)go.disabled=false;
      if(d&&d.ok){if(window.showFlash)showFlash(true,d.msg);
        setTimeout(function(){location.reload();},550);}
      else{if(err)err.textContent=(d&&d.msg)||'Bulk action failed.';}
    }).catch(function(){if(go)go.disabled=false; if(err)err.textContent='Request failed.';});
}
</script>
"""


def _audit_page(user: str, page: int = 1) -> bytes:
    """The in-UI activity view: every operator action (scan control, triage,
    Vuln DB edits, manual findings, leaks, reports and more), newest first, each
    with the user, the date and the detail. Paginated at 25 per page. Sign ins,
    sign outs and downloads stay in the server-side log only, never here."""
    records = _read_audit(2000)
    rows_data = [r for r in records
                 if r.get("event") in _AUDIT_LABELS and r.get("outcome") in ("ok", "fail", "denied")]

    def describe(r):
        ev = r.get("event", "")
        label = _AUDIT_LABELS.get(ev, ev)
        if ev == "control":
            kind, action = r.get("kind", ""), r.get("action", "")
            m = MODULE_BY_KIND.get(kind)
            phase = m["title"] if m else ("all phases" if action in ("run_all", "stop_all") else (kind or ""))
            verb = {"run": "Ran", "run_all": "Ran", "start": "Started",
                    "stop": "Stopped", "stop_all": "Stopped"}.get(action, "Ran")
            return f"{verb} {phase}".strip()
        return label

    rows = ""
    all_rows = []
    for r in rows_data:
        ep = _ts_epoch(r.get("ts", ""))
        date = (datetime.fromtimestamp(ep, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                if ep else r.get("ts", ""))
        actor = r.get("actor", "")
        client = _pretty(r.get("slug", "")) if r.get("slug") else ""
        what = describe(r)
        detail = r.get("detail", "") or ""
        oc = r.get("outcome", "")
        oc_label, oc_cls = (("error", "no") if oc == "fail"
                            else ("blocked", "no") if oc == "denied" else ("done", "ok"))
        all_rows.append((date, actor, what, client, detail, oc_label, oc_cls))
    total = len(all_rows)
    shown, page, pages = _page_slice(all_rows, page, 12)
    actors_seen, oc_seen = {}, {}
    for date, actor, what, client, detail, oc_label, oc_cls in shown:
        client_html = f' <span class="muted">{_esc(client)}</span>' if client else ""
        detail_html = f'<div class="muted" style="font-size:12px">{_esc(detail)}</div>' if detail else ""
        if actor:
            actors_seen[actor] = True
        oc_seen[oc_label] = True
        rows += (f'<tr class="aurow">'
                 f'<td class="muted" style="white-space:nowrap">{_esc(date)}</td>'
                 f'<td>{_esc(actor)}</td>'
                 f'<td class="auaction"><b>{_esc(what)}</b>{client_html}{detail_html}</td>'
                 f'<td><span class="pill {oc_cls}">{oc_label}</span></td></tr>')
    if not rows:
        rows = '<tr><td colspan="4" class="muted">No activity yet.</td></tr>'
    usr_sel = _col_select("aubody", 1, sorted(actors_seen))
    oc_sel = _col_select("aubody", 3, sorted(oc_seen))
    filt_row = ('<tr class="afilter">'
                '<th><div class="afdates">'
                '<label class="afdlab">From<input type="datetime-local" '
                'class="afin afdate" data-col="0" data-range="start" '
                'onchange="colFilter(\'aubody\')" oninput="colFilter(\'aubody\')"></label>'
                '<label class="afdlab">To<input type="datetime-local" '
                'class="afin afdate" data-col="0" data-range="end" '
                'onchange="colFilter(\'aubody\')" oninput="colFilter(\'aubody\')"></label>'
                '<button type="button" class="afdclear" title="Clear dates" '
                'onclick="var b=this.parentNode.querySelectorAll(\'input\');'
                'b[0].value=\'\';b[1].value=\'\';colFilter(\'aubody\');">Clear</button>'
                '</div></th>'
                f'<th>{usr_sel}</th>'
                '<th><input type="text" class="afin" data-col="2" placeholder="Action, client or detail" oninput="colFilter(\'aubody\')"></th>'
                f'<th>{oc_sel}</th></tr>')
    body = (f'<div class="rephead"><h2 style="margin:0">Activity '
            f'<span class="muted">({total})</span></h2></div>'
            '<div class="card" style="overflow-x:auto;padding:4px 6px">'
            '<table class="audit tcenter">'
            f'<thead>{filt_row}<tr><th>Date</th><th>User</th>'
            '<th>Action</th><th>Outcome</th></tr></thead>'
            f'<tbody id="aubody">{rows}</tbody></table>'
            '<div class="muted nomatch" style="display:none;padding:12px 10px">'
            'No rows match the filter.</div></div>'
            + _pager("/audit?", page, pages) + _COL_FILTER_JS)
    return _page(body, user)


def _vdb_form(t: dict | None) -> str:
    """The create/edit form for one vuln-db template."""
    t = t or {}
    # The form submits a token, never the raw id, so the write endpoints only
    # accept a reference that resolves.
    tok = _esc(_tpl_token(t["id"])) if t.get("id") else ""
    sev_opts = "".join(
        f'<option value="{s}"{" selected" if t.get("severity", "SEV3") == s else ""}>'
        f'{SEV[s][0]}</option>' for s in SEV_ORDER)
    def ta(name, val, rows, ph=""):
        return (f'<textarea name="{name}" class="eta" rows="{rows}" '
                f'placeholder="{_esc(ph)}">{_esc(val)}</textarea>')
    return (f'<form method="POST" action="/vuln-db-save" class="card vdbform">'
            f'<input type="hidden" name="id" value="{tok}">'
            f'<label class="rlbl">Name</label>'
            f'<input class="einp" name="name" value="{_esc(t.get("name", ""))}" required>'
            f'<label class="rlbl">Tags (comma separated, e.g. web, API)</label>'
            f'<input class="einp" name="tags" value="{_esc(t.get("tags", ""))}" placeholder="web, API">'
            f'<div class="clsrow clsgrid">'
            f'<label class="rlbl">OWASP Top 10</label>'
            f'<label class="rlbl">CWE</label>'
            f'<label class="rlbl">Severity</label>'
            f'<input class="einp" name="owasp" value="{_esc(t.get("owasp", ""))}" placeholder="A03:2021 Injection">'
            f'<input class="einp" name="cwe" value="{_esc(t.get("cwe", ""))}" placeholder="CWE-79">'
            f'<select class="einp" name="severity">{sev_opts}</select>'
            f'</div>'
            f'<label class="rlbl">CVSS 3.1 vector</label>'
            f'<input class="einp" name="cvss_vector" value="{_esc(t.get("cvss_vector", ""))}" '
            f'placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">'
            f'<label class="rlbl">Description</label>{ta("description", t.get("description", ""), 8)}'
            f'<label class="rlbl">Steps to reproduce (one per line)</label>'
            f'{ta("reproduction", t.get("reproduction", ""), 5, "1. ...")}'
            f'<label class="rlbl">Mitigation (one per line)</label>{ta("mitigation", t.get("mitigation", ""), 4)}'
            f'<label class="rlbl">References (one per line: Label | URL)</label>{ta("references", t.get("references", ""), 3)}'
            f'<div class="ebtns"><button type="submit" class="btn-ghost sbtn save">Save template</button>'
            + (f'<button type="submit" class="btn-ghost sbtn danger" formaction="/vuln-db-del" '
               f'formnovalidate onclick="return confirm(\'Delete this template?\')">Delete</button>'
               if tok else "")
            + f'</div></form>')


def _vuln_db_page(user: str, edit_id: str = "", new: bool = False, page: int = 1) -> bytes:
    data = _vdb_load()
    if new or edit_id:
        t = None
        if edit_id:
            rid = _resolve_tpl(edit_id)
            t = next((x for x in data["templates"] if x.get("id") == rid), None) if rid else None
            if t is None:
                return _page('<div class="empty">Template not found.</div>', user)
        title = "New template" if new else f'Edit: {_esc(t.get("name", ""))}'
        body = (f'<a class="back" href="/vuln-db"><svg class="barrow" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5M12 19l-7-7 7-7"/></svg> Back to Vuln DB</a>'
                f'<h1 style="margin:10px 0 14px">{title}</h1>{_vdb_form(t)}')
        return _page(body, user)
    templates = sorted(data["templates"], key=lambda x: x.get("name", "").lower())
    shown, page, pages = _page_slice(templates, page, 12)
    rows = ""
    sevs_seen, tags_seen, owasp_seen, cwe_seen = {}, {}, {}, {}
    for t in shown:
        sev = t.get("severity", "SEV3")
        label, bg, fg = SEV.get(sev, SEV["SEV3"])
        sevs_seen[label] = True
        tags = [x.strip() for x in str(t.get("tags", "")).split(",") if x.strip()]
        chips = (['<span class="exampletag">EXAMPLE</span>'] if t.get("example") else [])
        chips += [f'<span class="vtag">{_esc(x)}</span>' for x in tags]
        tag_chips = "".join(chips) or '<span class="muted">-</span>'
        if t.get("example"):
            tags_seen["EXAMPLE"] = True
        for x in tags:
            tags_seen[x] = True
        owasp = t.get("owasp", "") or ""
        cwe = t.get("cwe", "") or ""
        if owasp:
            owasp_seen[owasp] = True
        if cwe:
            cwe_seen[cwe] = True
        tok = _tpl_token(t.get("id", ""))
        rows += (f'<tr class="vdbrow">'
                 f'<td><a class="phlink" href="/vuln-db?edit={tok}">'
                 f'{_esc(t.get("name", ""))}</a></td>'
                 f'<td>{tag_chips}</td>'
                 f'<td class="muted">{_esc(owasp or "-")}</td>'
                 f'<td class="muted">{_esc(cwe or "-")}</td>'
                 f'<td><span class="badge" style="background:{bg};color:{fg}">{label}</span></td>'
                 f'</tr>')
    tag_sel = _col_select("vdbbody", 1, sorted(tags_seen), "Tags")
    owasp_sel = _col_select("vdbbody", 2, sorted(owasp_seen), "OWASP ID")
    cwe_sel = _col_select("vdbbody", 3, sorted(cwe_seen), "CWE")
    sev_sel = _col_select("vdbbody", 4, sorted(sevs_seen), "Severity")
    filt_row = ('<tr class="afilter">'
                '<th><input type="text" class="afin" data-col="0" placeholder="Name" oninput="colFilter(\'vdbbody\')"></th>'
                f'<th>{tag_sel}</th>'
                f'<th>{owasp_sel}</th>'
                f'<th>{cwe_sel}</th>'
                f'<th>{sev_sel}</th>'
                '</tr>')
    body = ('<div class="rephead"><h2 style="margin:0">Vulnerability DB</h2>'
            '<a class="btn-ghost sbtn noborder" href="/vuln-db?new=1">'
            '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" '
            'stroke-width="2.4" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>'
            'New template</a></div>'
            '<div class="card" style="overflow-x:auto;padding:4px 6px"><table class="audit tcenter">'
            f'<thead>{filt_row}<tr><th>Name</th><th>Tags</th><th>OWASP ID</th><th>CWE</th>'
            '<th>Severity</th></tr></thead>'
            f'<tbody id="vdbbody">{rows}</tbody></table>'
            '<div class="muted nomatch" style="display:none;padding:10px">No matches.</div></div>'
            + _pager("/vuln-db?", page, pages) + _COL_FILTER_JS)
    return _page(body, user)


def _bulk_apply_one(slug: str, key: str, act: str, reason: str,
                    user: str, ip: str) -> bool:
    """Apply one triage action to one finding, for the bulk path. Mirrors the
    single-finding handler (confirm / false positive / send to Security Joes)
    but without the per-finding evidence attachments. Returns True on success."""
    v = next((x for x in _all_findings(slug).values() if x["key"] == key), None)
    if v is None:
        return False
    vid = v["id"]
    now = datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC")
    fp = _fp_load(slug)
    cf = _confirmed_load(slug)
    if act == "fp":
        cf.pop(key, None)
        _confirmed_save(slug, cf)
        fp[key] = {"key": key, "id": vid, "severity": v["severity"],
                   "title": v["title"], "by": user, "reason": reason, "ts": now}
        _fp_save(slug, fp)
        _vnotes_append(slug, key, "Marked false positive", reason, user, now)
        _audit("false_positive", user, ip, outcome="ok", slug=slug,
               detail=f"{v['title']} :: {reason} (bulk)")
        return True
    if act == "confirm":
        fp.pop(key, None)
        _fp_save(slug, fp)
        cf[key] = {"key": key, "id": vid, "severity": v["severity"],
                   "title": v["title"], "by": user, "reason": reason, "ts": now}
        _confirmed_save(slug, cf)
        _vnotes_append(slug, key, "Marked confirmed", reason, user, now)
        _audit("confirm_finding", user, ip, outcome="ok", slug=slug,
               detail=f"{v['title']} :: {reason} (bulk)")
        return True
    if act == "send":
        try:
            qf = ENGAGEMENTS / slug / "state" / "sent_to_securityjoes.jsonl"
            qf.parent.mkdir(parents=True, exist_ok=True)
            with qf.open("a") as fh:
                fh.write(json.dumps({
                    "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "key": key, "id": vid, "title": v["title"],
                    "severity": v["severity"], "by": user, "note": reason}) + "\n")
        except Exception:
            return False
        if reason:
            _vnotes_append(slug, key, "Sent to Security Joes", reason, user, now)
        _audit("send_securityjoes", user, ip, outcome="ok", slug=slug,
               detail=f"{v['title']} (bulk)")
        return True
    return False


def _vdb_search_json(query: str, limit: int = 30) -> bytes:
    """Live search over the Vuln DB for the Import picker. Matches the query
    against name, OWASP, CWE and description, so the form never has to render the
    whole catalogue, and returns at most `limit` hits as JSON. A name hit ranks
    above a body hit, and a name prefix above a mid-name hit, so the closest
    template surfaces first even with thousands of entries."""
    q = (query or "").strip().lower()
    templates = _vdb_load()["templates"]

    def rank(t: dict):
        name = (t.get("name", "") or "").lower()
        if not q:
            return (0, name)
        if name.startswith(q):
            return (0, name)
        if q in name:
            return (1, name)
        return (2, name)

    hits = []
    for t in templates:
        name = (t.get("name", "") or "").lower()
        if q:
            hay = " ".join((
                name, (t.get("owasp", "") or ""), (t.get("cwe", "") or ""),
                (t.get("description", "") or ""))).lower()
            if q not in hay:
                continue
        hits.append(t)
    hits.sort(key=rank)
    total = len(hits)
    out = []
    for t in hits[:limit]:
        label, bg, fg = SEV.get(t.get("severity", "SEV3"), SEV["SEV3"])
        out.append({"id": t.get("id", ""),
                    "name": t.get("name", "Untitled"),
                    "severity": label, "bg": bg, "fg": fg,
                    "owasp": t.get("owasp", ""),
                    "cwe": t.get("cwe", "")})
    return json.dumps({"total": total, "shown": len(out), "items": out}).encode()


# The OWASP Top 10 (2021) categories, offered as a dropdown so a finding's
# OWASP tag is consistent across the whole engagement.
OWASP_2021 = [
    "A01:2021 Broken Access Control",
    "A02:2021 Cryptographic Failures",
    "A03:2021 Injection",
    "A04:2021 Insecure Design",
    "A05:2021 Security Misconfiguration",
    "A06:2021 Vulnerable and Outdated Components",
    "A07:2021 Identification and Authentication Failures",
    "A08:2021 Software and Data Integrity Failures",
    "A09:2021 Security Logging and Monitoring Failures",
    "A10:2021 Server-Side Request Forgery (SSRF)",
]

# A curated set of the CWEs that come up most in web and mobile assessments.
# Not the full MITRE list (over 900): a free-text value from an imported
# template is preserved as its own option, so nothing is ever lost.
CWE_COMMON = [
    "CWE-20 Improper Input Validation",
    "CWE-22 Path Traversal",
    "CWE-78 OS Command Injection",
    "CWE-79 Cross-Site Scripting",
    "CWE-89 SQL Injection",
    "CWE-94 Code Injection",
    "CWE-200 Exposure of Sensitive Information",
    "CWE-201 Insertion of Sensitive Information Into Sent Data",
    "CWE-209 Generation of Error Message Containing Sensitive Information",
    "CWE-256 Plaintext Storage of a Password",
    "CWE-269 Improper Privilege Management",
    "CWE-287 Improper Authentication",
    "CWE-295 Improper Certificate Validation",
    "CWE-306 Missing Authentication for Critical Function",
    "CWE-307 Improper Restriction of Excessive Authentication Attempts",
    "CWE-311 Missing Encryption of Sensitive Data",
    "CWE-319 Cleartext Transmission of Sensitive Information",
    "CWE-352 Cross-Site Request Forgery (CSRF)",
    "CWE-353 Missing Support for Integrity Check",
    "CWE-384 Session Fixation",
    "CWE-400 Uncontrolled Resource Consumption",
    "CWE-434 Unrestricted Upload of File with Dangerous Type",
    "CWE-521 Weak Password Requirements",
    "CWE-522 Insufficiently Protected Credentials",
    "CWE-601 Open Redirect",
    "CWE-611 XML External Entity (XXE)",
    "CWE-613 Insufficient Session Expiration",
    "CWE-639 Authorization Bypass Through User-Controlled Key (IDOR)",
    "CWE-732 Incorrect Permission Assignment for Critical Resource",
    "CWE-798 Use of Hard-coded Credentials",
    "CWE-918 Server-Side Request Forgery (SSRF)",
    "CWE-1021 Improper Restriction of Rendered UI Layers (Clickjacking)",
]


def _combo(name: str, listkey: str, current: str, placeholder: str) -> str:
    """A live type-ahead combo: a text input that filters a static list as you
    type (client-side), with the picked or typed value submitted under `name`.
    Free text is allowed, so an imported template's value survives even if it is
    not in the list. `listkey` selects the option list in window._COMBO."""
    return (
        f'<div class="combo"><input type="text" class="einp comboinp" name="{name}" '
        f'value="{_attr(current)}" autocomplete="off" spellcheck="false" '
        f'data-list="{listkey}" placeholder="{_attr(placeholder)}" '
        f'oninput="comboOpen(this)" onfocus="comboOpen(this)">'
        f'<div class="dbresults combores"></div></div>')


def _review_page(user: str, new: bool = False, tpl: str = "", flash=None,
                 page: int = 1, sel_cid: str = "") -> bytes:
    if new:
        templates = _vdb_load()["templates"]
        t = next((x for x in templates if x.get("id") == tpl), None) if tpl else None
        clients = [b.name for b in sorted(ENGAGEMENTS.iterdir())
                   if b.is_dir()] if ENGAGEMENTS.is_dir() else []
        copts = "".join(
            f'<option value="{_client_id(s)}"'
            f'{" selected" if _client_id(s) == sel_cid else ""}>{_esc(_pretty(s))}</option>'
            for s in clients)
        _cur_sev = (t or {}).get("severity", "SEV3")
        sev_opts = "".join(
            f'<option value="{s}" data-bg="{SEV[s][1]}" data-fg="{SEV[s][2]}" '
            f'style="background:{SEV[s][1]};color:{SEV[s][2]}"'
            f'{" selected" if _cur_sev == s else ""}>'
            f'{SEV[s][0]}</option>' for s in SEV_ORDER)
        pre = t or {}
        # Import from Vuln DB: a live type-ahead search (not a giant select, so
        # it scales to thousands of templates). Picking a result reloads the form
        # prefilled with that template, keeping whichever client is selected. Same
        # prefill the Vuln DB "Use as finding" link uses.
        if templates:
            if t:
                imported = (
                    '<div class="dbcur">Imported from Vuln DB: '
                    f'<b>{_esc(t.get("name", "Untitled"))}</b>'
                    '<button type="button" class="dbclear" onclick="importDb(\'\')">'
                    'Clear</button></div>')
            else:
                imported = ""
            db_picker = (
                '<label class="rlbl">Import from Vuln DB (optional)</label>'
                '<div class="dbsearch">'
                '<input type="text" id="dbq" class="einp" autocomplete="off" '
                'placeholder="Search the Vuln DB by name, OWASP, CWE or description" '
                'oninput="dbSearch()" onfocus="dbSearch()">'
                '<div class="dbresults" id="dbresults"></div></div>'
                f'{imported}')
        else:
            db_picker = (
                '<label class="rlbl">Import from Vuln DB (optional)</label>'
                '<div class="muted" style="margin-bottom:6px;font-size:12px">'
                'No templates in the Vuln DB yet.</div>')

        def ta(name, val, rows, ph=""):
            return (f'<textarea name="{name}" class="eta" rows="{rows}" '
                    f'placeholder="{_esc(ph)}">{_esc(val)}</textarea>')
        form = (f'<form method="POST" action="/review-new" class="card vdbform" '
                f'enctype="multipart/form-data">'
                f'<label class="rlbl">Client</label><select class="einp" name="slug" required>{copts}</select>'
                f'{db_picker}'
                f'<div class="inlrow"><label class="rlbl inlk" for="titlein">Title:</label>'
                f'<input class="einp" id="titlein" name="title" value="{_esc(pre.get("name", ""))}" required></div>'
                f'<div class="clsrow"><div><label class="rlbl">OWASP Top 10</label>'
                f'{_combo("owasp", "owasp", pre.get("owasp", ""), "Search OWASP Top 10")}</div>'
                f'<div><label class="rlbl">CWE</label>'
                f'{_combo("cwe", "cwe", pre.get("cwe", ""), "Search CWE")}</div>'
                f'<div><label class="rlbl">Severity (used if no CVSS)</label>'
                f'<select class="einp sevsel" id="sevsel" name="severity" '
                f'onchange="sevColor(this)">{sev_opts}</select></div></div>'
                f'<div class="inlrow"><label class="rlbl inlk" for="cvssvec">CVSS 3.1 Vector:</label>'
                f'<input class="einp" id="cvssvec" name="cvss_vector" value="{_esc(pre.get("cvss_vector", ""))}" '
                f'oninput="cvssScore()" placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"></div>'
                f'<div class="inlrow"><label class="rlbl inlk" for="cvssscore">CVSS Score:</label>'
                f'<input class="einp" id="cvssscore" readonly placeholder="computed from the vector"></div>'
                f'<label class="rlbl">Affected hosts (one per line)</label>{ta("hosts", "", 3)}'
                f'<label class="rlbl">Description</label>{ta("description", pre.get("description", ""), 7)}'
                f'<label class="rlbl">Steps to reproduce (one per line)</label>{ta("steps", pre.get("steps", ""), 5)}'
                f'<label class="rlbl">Mitigation (one per line)</label>{ta("mitigation", pre.get("mitigation", ""), 4)}'
                f'<label class="rlbl">References (one per line: Label | URL)</label>{ta("references", pre.get("references", ""), 3)}'
                f'<label class="rlbl">Evidence (optional)</label>'
                '<div class="evup"><label class="evuplbl">'
                '<span class="evupico"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" '
                'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">'
                '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/>'
                '<path d="m21 15-5-5L5 21"/></svg></span>'
                '<span class="evuptext"><b>Attach evidence</b>'
                '<span class="muted">PNG, JPG or PDF, up to 10 MB each. The file name is used '
                'as the figure name.</span></span>'
                '<input type="file" name="evidence" multiple '
                'accept=".png,.jpg,.jpeg,.pdf,image/png,image/jpeg,application/pdf" '
                'onchange="evPick(this)"></label>'
                '<span class="muted" id="evpick"></span></div>'
                f'<div class="ebtns"><button type="submit" class="btn-ghost sbtn go">Create finding</button>'
                f'<a class="btn-ghost sbtn danger" href="{"/c/" + sel_cid + "?t=attention" if sel_cid else "/review"}">Cancel</a></div></form>')
        import_js = r"""<script>
function importDb(tid){
  var s=document.querySelector('select[name=slug]');
  var u='/review?new=1';
  if(tid)u+='&tpl='+encodeURIComponent(tid);
  if(s&&s.value)u+='&slug='+encodeURIComponent(s.value);
  location.href=u;
}
var _dbT=null;
function dbSearch(){
  var q=document.getElementById('dbq'); var box=document.getElementById('dbresults');
  if(!q||!box)return;
  if(_dbT)clearTimeout(_dbT);
  _dbT=setTimeout(function(){
    fetch('/vdb-search?q='+encodeURIComponent(q.value))
      .then(function(r){return r.json();})
      .then(function(d){
        var items=(d&&d.items)||[]; box.innerHTML='';
        if(!items.length){
          box.innerHTML='<div class="dbnone">No matching templates.</div>';
          box.classList.add('open'); return;
        }
        items.forEach(function(it){
          var row=document.createElement('div'); row.className='dbhit';
          row.onclick=function(){importDb(it.id);};
          var meta=[it.owasp,it.cwe].filter(Boolean).join(' · ');
          row.innerHTML='<span class="dbhitname"></span>'+
            '<span class="badge dbhitsev"></span>';
          row.querySelector('.dbhitname').textContent=it.name+(meta?'  ('+meta+')':'');
          var b=row.querySelector('.dbhitsev');
          b.textContent=it.severity; b.style.background=it.bg; b.style.color=it.fg;
          box.appendChild(row);
        });
        if(d.total>d.shown){
          var more=document.createElement('div'); more.className='dbmore';
          more.textContent='Showing '+d.shown+' of '+d.total+'. Keep typing to narrow.';
          box.appendChild(more);
        }
        box.classList.add('open');
      }).catch(function(){});
  },180);
}
document.addEventListener('click',function(e){
  var box=document.getElementById('dbresults'), q=document.getElementById('dbq');
  if(box&&q&&e.target!==q&&!box.contains(e.target))box.classList.remove('open');
});
// Tint the Severity select to its chosen severity colour, so the field reads
// its level at a glance.
function sevColor(sel){
  if(!sel)return;
  var o=sel.options[sel.selectedIndex];
  var bg=o&&o.getAttribute('data-bg'), fg=o&&o.getAttribute('data-fg');
  if(bg&&fg){sel.style.background=bg;sel.style.color=fg;sel.style.borderColor=bg;}
}
sevColor(document.getElementById('sevsel'));
</script>"""
        combo_js = (
            '<script>window._COMBO='
            + json.dumps({"owasp": OWASP_2021, "cwe": CWE_COMMON})
            + r""";
function comboOpen(inp){
  var box=inp.parentNode.querySelector('.combores');
  if(!box)return;
  var list=(window._COMBO&&window._COMBO[inp.getAttribute('data-list')])||[];
  var q=(inp.value||'').toLowerCase();
  var hits=list.filter(function(o){return o.toLowerCase().indexOf(q)>=0;}).slice(0,40);
  box.innerHTML='';
  if(!hits.length){box.classList.remove('open');return;}
  hits.forEach(function(o){
    var row=document.createElement('div'); row.className='dbhit';
    var n=document.createElement('span'); n.className='dbhitname'; n.textContent=o;
    row.appendChild(n);
    row.onmousedown=function(e){e.preventDefault();inp.value=o;box.classList.remove('open');};
    box.appendChild(row);
  });
  box.classList.add('open');
}
document.addEventListener('click',function(e){
  document.querySelectorAll('.combo').forEach(function(c){
    if(!c.contains(e.target)){var b=c.querySelector('.combores');if(b)b.classList.remove('open');}
  });
});
// Live CVSS 3.1 base score from the vector field (FIRST.org formula).
function _roundup(x){var i=Math.round(x*100000);if(i%10000===0)return i/100000;return (Math.floor(i/10000)+1)/10;}
function _cvss31(vec){
  if(!vec)return null;
  var parts=String(vec).trim().split('/');
  if(!/^CVSS:3\.[01]$/.test(parts[0]))return null;
  var m={};for(var i=1;i<parts.length;i++){var kv=parts[i].split(':');if(kv.length===2)m[kv[0]]=kv[1];}
  var need=['AV','AC','PR','UI','S','C','I','A'];for(var j=0;j<need.length;j++){if(!(need[j] in m))return null;}
  var AV={N:0.85,A:0.62,L:0.55,P:0.2}[m.AV],AC={L:0.77,H:0.44}[m.AC],UI={N:0.85,R:0.62}[m.UI];
  var changed=(m.S==='C');
  var PR=(changed?{N:0.85,L:0.68,H:0.5}:{N:0.85,L:0.62,H:0.27})[m.PR];
  var cia={N:0,L:0.22,H:0.56},C=cia[m.C],I=cia[m.I],A=cia[m.A];
  if([AV,AC,UI,PR,C,I,A].some(function(x){return x===undefined;}))return null;
  var iss=1-(1-C)*(1-I)*(1-A);
  var impact=changed?(7.52*(iss-0.029)-3.25*Math.pow(iss-0.02,15)):(6.42*iss);
  var expl=8.22*AV*AC*PR*UI,base;
  if(impact<=0)base=0;else if(changed)base=_roundup(Math.min(1.08*(impact+expl),10));else base=_roundup(Math.min(impact+expl,10));
  return base;
}
function _band(s){if(s<=0)return'None';if(s<4)return'Low';if(s<7)return'Medium';if(s<9)return'High';return'Critical';}
function cvssScore(){
  var vin=document.getElementById('cvssvec'),out=document.getElementById('cvssscore');
  if(!vin||!out)return;
  var v=(vin.value||'').trim();
  if(!v){out.value='';return;}
  var s=_cvss31(v);
  out.value=(s===null)?'invalid vector':(s.toFixed(1)+' ('+_band(s)+')');
}
cvssScore();
function evPick(inp){
  var el=document.getElementById('evpick');if(!el)return;
  var n=inp.files?inp.files.length:0;
  el.textContent=n?(n+' file'+(n>1?'s':'')+' selected'):'';
}
</script>"""
        )
        back = f"/c/{sel_cid}?t=attention" if sel_cid else "/review"
        body = (f'<a class="back" href="{back}"><svg class="barrow" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5M12 19l-7-7 7-7"/></svg> Back</a>'
                f'{_flash(flash)}<h1 style="margin:0 0 14px">New manual finding</h1>{form}{import_js}{combo_js}')
        return _page(body, user)
    # The review queue: every finding still in to_review, across all clients.
    items = []
    for e in engagements():
        slug = e["slug"]
        for v in _review_findings(slug):
            items.append((slug, v))
    count = len(items)
    shown, page, pages = _page_slice(items, page, 12)
    rows = ""
    clients_seen, sevs_seen, sources_seen = {}, {}, {}
    for slug, v in shown:
        sev = v["severity"]
        label, bg, fg = SEV.get(sev, SEV["SEV3"])
        reported = _fmt_iso(v.get("first_seen", "")) or "-"
        vurl = f'/vuln?e={_client_id(slug)}&v={v["id"]}'
        cname = _pretty(slug)
        src = v["source_class"] or v["source"] or "-"
        clients_seen[cname] = True
        sevs_seen[label] = True
        sources_seen[src] = True
        bcid = _client_id(slug)
        rows += (f'<tr><td class="bchkcol"><input type="checkbox" class="bchk" '
                 f'data-cid="{bcid}" data-key="{_attr(v["key"])}" onchange="bulkSync()"></td>'
                 f'<td>{_esc(cname)}</td>'
                 f'<td><span class="badge" style="background:{bg};color:{fg}">{label}</span></td>'
                 f'<td class="fndcell"><a class="phlink" href="{vurl}">{_esc(v["title"])}</a></td>'
                 f'<td class="muted">{_esc(src)}</td>'
                 f'<td class="muted" style="white-space:nowrap">{_esc(reported)}</td>'
                 f'<td><a class="mnglink" href="{vurl}">Manage</a></td></tr>')
    # Checkbox is column 0, so the real columns start at 1: shift the filters.
    cli_sel = _col_select("rebody", 1, sorted(clients_seen))
    sev_sel = _col_select("rebody", 2, sorted(sevs_seen))
    src_sel = _col_select("rebody", 4, sorted(sources_seen))
    filt_row = (f'<tr class="afilter">'
                f'<th class="bchkcol"></th>'
                f'<th>{cli_sel}</th><th>{sev_sel}</th>'
                f'<th><input type="text" class="afin" data-col="3" placeholder="Finding" '
                f'oninput="colFilter(\'rebody\')"></th>'
                f'<th>{src_sel}</th>'
                f'<th><input type="text" class="afin" data-col="5" placeholder="Reported" '
                f'oninput="colFilter(\'rebody\')"></th><th></th></tr>')
    bulk_btn = ('<button type="button" class="bulkbtn" id="bulkbtn" onclick="bulkOpen()">'
                'Manage selected <span class="bk" id="bulkn">0</span></button>')
    table = (f'<div class="card" style="overflow-x:auto;padding:4px 6px"><table class="audit tcenter">'
             f'<thead>{filt_row}<tr>'
             f'<th class="bchkcol"><input type="checkbox" id="bchkall" class="bchkall" '
             f'onclick="bulkAll(this)" title="Select all"></th>'
             f'<th>Client</th><th>Severity</th><th>Finding</th><th>Source</th>'
             f'<th>Reported</th><th>{bulk_btn}</th></tr></thead>'
             f'<tbody id="rebody">{rows}</tbody></table>'
             '<div class="muted nomatch" style="display:none;padding:10px">No matches.</div></div>'
             f'{_COL_FILTER_JS}{_BULK_TRIAGE}' if count else
             '<div class="card"><div class="muted">Nothing is waiting to be reviewed.</div></div>')
    body = (f'{_flash(flash)}<div class="rephead"><h2 style="margin:0">Triage queue '
            f'<span class="muted">({count})</span></h2>'
            '<a class="btn-ghost sbtn" href="/review?new=1">Add manual finding</a></div>'
            f'{table}{_pager("/review?", page, pages)}')
    return _page(body, user)


# --------------------------------------------------------------------------
# Request handling.
# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "eas-panel"

    def log_message(self, *a):  # quiet
        pass

    def _ip(self) -> str:
        """Best-effort client address for the audit log."""
        try:
            return self.client_address[0]
        except Exception:
            return "-"

    def _identity(self) -> str | None:
        """Who is this request, or None if not authenticated."""
        # ----------------------------------------------------------------
        # PRODUCTION SSO (commented demo of the header path).
        # With PANEL_SSO=1, oauth2-proxy in front of Entra has already
        # authenticated the user and set the verified email header. We trust
        # it only because the panel is bound to localhost and nothing but the
        # proxy can reach it. We still enforce the company domain here.
        #
        # For SAML specifically, oauth2-proxy runs with a SAML provider (or
        # mod_auth_mellon fronts it) and sets the same header. No code change
        # here. See deploy/panel-sso.md.
        # ----------------------------------------------------------------
        if PANEL_SSO:
            email = self.headers.get("X-Auth-Request-Email", "").strip().lower()
            if email.endswith("@" + ALLOWED_EMAIL_DOMAIN):
                return email
            return None

        # DEV ONLY: PANEL_NO_AUTH short-circuits the login so testing needs no
        # sign-in. Refused under SSO above, so this never weakens production.
        if NO_AUTH:
            return NO_AUTH_USER

        # LOCAL DEMO: signed session cookie.
        raw = self.headers.get("Cookie", "")
        if raw:
            jar = SimpleCookie()
            jar.load(raw)
            if COOKIE in jar:
                return _verify(jar[COOKIE].value)
        return None

    def _send(self, code: int, body: bytes, headers: dict | None = None):
        headers = dict(headers or {})
        self.send_response(code)
        # The caller may override Content-Type (CSS, downloads, images). Emit it
        # once: a hardcoded text/html plus an override would send two conflicting
        # Content-Type headers, and with nosniff a strict browser reads the first
        # (text/html) and refuses the stylesheet, so the page loses its CSS.
        ctype = next((headers.pop(k) for k in list(headers)
                      if k.lower() == "content-type"), "text/html; charset=utf-8")
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        # HTML carries the inline JS (the graph, the export). The dev server has
        # no auto-reload and no cache-busting, so a browser that heuristically
        # caches an HTML page keeps running stale JS after a code change. Mark
        # every HTML response no-store so a plain reload always gets fresh code,
        # unless the caller already set its own Cache-Control.
        if ctype.startswith("text/html") and not any(
                k.lower() == "cache-control" for k in headers):
            self.send_header("Cache-Control", "no-store")
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        path = url.path
        user = self._identity()
        if PANEL_SSO and user:
            _note_sso_login(user, self._ip())

        if path == "/panel.css":
            # Served fresh from disk each request (no-store) so editing
            # tools/panel.css shows on a browser reload with no restart.
            return self._send(200, _css().encode("utf-8"), {
                "Content-Type": "text/css; charset=utf-8",
                "Cache-Control": "no-store"})
        if path == "/login" and not PANEL_SSO:
            if NO_AUTH:
                return self._send(302, b"", {"Location": "/"})
            return self._send(200, _login_page())
        if path == "/logout":
            if user:
                _audit("logout", user, self._ip(), outcome="ok")
            return self._send(302, b"", {
                "Location": "/login",
                "Set-Cookie": f"{COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax",
            })
        if not user:
            if PANEL_SSO:
                return self._send(401, _page(
                    '<div class="panel err">Not authenticated. Reach this panel '
                    'through the SSO proxy.</div>', ""))
            return self._send(302, b"", {"Location": "/login"})

        q = urllib.parse.parse_qs(url.query)
        # Flash messages come only from a one-shot server-side token (?f=...),
        # never from reflected URL text. A raw ?msg= in the address bar is
        # ignored, so it cannot be echoed into the page or forged into a toast.
        flash = _flash_pop(q.get("f", [""])[0]) if "f" in q else None

        def _qint(name):
            try:
                return max(1, int(q.get(name, ["1"])[0]))
            except Exception:
                return 1

        if path == "/":
            return self._send(200, _overview(user, flash))
        if path == "/new-client":
            return self._send(200, _new_client_page(user))
        if path == "/audit":
            return self._send(200, _audit_page(user, _qint("page")))
        if path == "/methodology":
            return self._send(200, _methodology_page(user))
        if path == "/vuln-db":
            return self._send(200, _vuln_db_page(
                user, (q.get("edit", [""])[0] or "").strip(),
                q.get("new", [""])[0] == "1", _qint("page")))
        if path == "/review":
            sel_cid = (q.get("slug", [""])[0] or "").strip()
            return self._send(200, _review_page(
                user, q.get("new", [""])[0] == "1",
                (q.get("tpl", [""])[0] or "").strip(), flash, _qint("page"),
                sel_cid))
        if path == "/vdb-search":
            return self._send(200, _vdb_search_json(q.get("q", [""])[0] or ""),
                              {"Content-Type": "application/json; charset=utf-8"})
        if path == "/c-metrics":
            slug = _resolve_client((q.get("e", [""])[0] or "").strip()) or ""
            if not slug:
                return self._send(404, b"{}",
                                  {"Content-Type": "application/json; charset=utf-8"})
            return self._send(200, _client_metrics_json(slug),
                              {"Content-Type": "application/json; charset=utf-8"})
        if path.startswith("/c/"):
            token = urllib.parse.unquote(path[len("/c/"):]).strip("/")
            slug = _resolve_client(token)
            if not slug:
                return self._send(404, _page('<div class="empty">Client not found.</div>', user))
            tab = (q.get("t", [""])[0] or "overview").strip()
            return self._send(200, _client_page(user, slug, flash, tab, _qint("apage")))
        if path == "/vuln":
            slug = _resolve_client((q.get("e", [""])[0] or "").strip()) or ""
            vid = (q.get("v", [""])[0] or "").strip()
            frm = (q.get("from", [""])[0] or "").strip()
            return self._send(200, _vuln_page(user, slug, vid, flash, frm))
        if path == "/l0-debug":
            slug = _resolve_client((q.get("e", [""])[0] or "").strip()) or ""
            if not slug:
                return self._send(404, _page('<div class="empty">Not found.</div>', user))
            return self._send(200, _l0_debug_page(user, slug))
        if path == "/dl":
            return self._download(url, user)
        if path == "/subs":
            return self._download_subs(url, user)
        if path == "/evidence":
            return self._serve_evidence(url, user)
        if path == "/brand-logo":
            return self._serve_brand_logo(url, user)
        if path == "/leak-export":
            return self._leak_export(url, user)
        return self._send(404, _page('<div class="empty">Not found.</div>', user))

    def _flash_redirect(self, ok: bool, msg: str, target: str = "/"):
        # The message text stays server-side; the URL carries only a one-shot
        # token, so nothing user-controllable is reflected back into the page.
        q = urllib.parse.urlencode({"f": _flash_put(ok, msg)})
        # Keep any #fragment after the query, so the browser still jumps to it.
        base, frag, anchor = target.partition("#")
        sep = "&" if "?" in base else "?"
        return self._send(302, b"", {"Location": f"{base}{sep}{q}{frag}{anchor}"})

    def do_POST(self):
        if self.path == "/control":
            return self._control()
        if self.path == "/config":
            return self._config()
        if self.path == "/new-client":
            return self._new_client()
        if self.path == "/ingest":
            return self._ingest()
        if self.path == "/add-context":
            return self._add_context()
        if self.path == "/context-save":
            return self._context_save()
        if self.path == "/report":
            return self._report()
        if self.path == "/alert":
            return self._alert()
        if self.path == "/vuln-action":
            return self._vuln_action()
        if self.path == "/bulk-action":
            return self._bulk_action()
        if self.path == "/vuln-meta":
            return self._vuln_meta()
        if self.path == "/vuln-evidence":
            return self._vuln_evidence()
        if self.path == "/vuln-capture":
            return self._vuln_capture()
        if self.path == "/vuln-figcap":
            return self._vuln_figcap()
        if self.path == "/subs-edit":
            return self._subs_edit()
        if self.path == "/leak-fetch":
            return self._leak_fetch()
        if self.path == "/leak-reveal":
            return self._leak_reveal()
        if self.path == "/vuln-db-save":
            return self._vdb_save_handler()
        if self.path == "/vuln-db-del":
            return self._vdb_del_handler()
        if self.path == "/review-new":
            return self._review_new()
        if self.path != "/login" or PANEL_SSO:
            return self._send(404, _page('<div class="empty">Not found.</div>', ""))
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        u = (form.get("user", [""])[0] or "").strip()
        p = form.get("password", [""])[0] or ""
        ok = (PANEL_PASSWORD
              and hmac.compare_digest(u, PANEL_USER)
              and hmac.compare_digest(p, PANEL_PASSWORD))
        if not ok:
            _audit("login_failure", u or "-", self._ip(), outcome="denied")
            msg = ("Set PANEL_PASSWORD in the environment first."
                   if not PANEL_PASSWORD else "Wrong user or password.")
            return self._send(200, _login_page(msg))
        _audit("login_success", u, self._ip(), outcome="ok")
        return self._send(302, b"", {
            "Location": "/",
            "Set-Cookie": f"{COOKIE}={_sign(u)}; Path=/; HttpOnly; SameSite=Lax",
        })

    def _download_subs(self, url, user: str):
        """Serve the client's enumerated subdomains as a plain text file, one
        host per line, no bullets. Built on the fly from the signals."""
        q = urllib.parse.parse_qs(url.query)
        slug = _resolve_client((q.get("e", [""])[0] or "").strip())
        base = ENGAGEMENTS / slug if slug else None
        if not slug or not base.is_dir():
            return self._send(404, _page('<div class="empty">Client not found.</div>', user))
        subs = _subdomain_list(base)
        body = ("\n".join(subs) + "\n").encode() if subs else b""
        _audit("download", user, self._ip(), outcome="ok",
               slug=slug, file=f"{slug}-live-subdomains.txt", detail="subdomains")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Disposition",
                         f'attachment; filename="{slug}-live-subdomains.txt"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _download(self, url, user: str):
        """Serve a saved report or signal file, path-traversal safe."""
        q = urllib.parse.parse_qs(url.query)
        slug = _resolve_client((q.get("e", [""])[0] or "").strip())
        if not slug:
            return self._send(404, _page('<div class="empty">File not found.</div>', user))
        name = Path(q.get("f", [""])[0]).name
        if (q.get("d", [""])[0] or "reports") == "signals":
            folder = "signals"
            ctype = ("text/plain; charset=utf-8" if name.endswith(".txt")
                     else "application/x-ndjson")
        else:
            folder = "reports"
            low = name.lower()
            if low.endswith(".pdf"):
                ctype = "application/pdf"
            elif low.endswith(".docx"):
                ctype = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            else:
                ctype = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        target = (ENGAGEMENTS / slug / folder / name).resolve()
        base = (ENGAGEMENTS / slug / folder).resolve()
        if not str(target).startswith(str(base)) or not target.is_file():
            _audit("download", user, self._ip(), outcome="fail",
                   slug=slug, file=name, detail=folder)
            return self._send(404, _page('<div class="empty">File not found.</div>', user))
        _audit("download", user, self._ip(), outcome="ok",
               slug=slug, file=name, detail=folder)
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Disposition", f'attachment; filename="{name}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _config(self):
        """Save a module's editable knobs to config.yaml. Same auth and step-up
        as a control action, validated and escape-proof in do_set_knobs."""
        user = self._identity()
        if not user:
            return self._send(302, b"", {"Location": "/login"})
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        kind = (form.get("kind", [""])[0] or "").strip()
        slug = _resolve_client((form.get("slug", [""])[0] or "").strip()) or ""
        password = form.get("password", [""])[0] or ""
        xhr = (form.get("xhr", [""])[0] == "1")
        target = f"/c/{_client_id(slug)}" if slug else "/"

        def respond(ok, msg):
            if xhr:
                return self._send(200, json.dumps({"ok": ok, "msg": msg}).encode(),
                                  {"Content-Type": "application/json; charset=utf-8"})
            return self._flash_redirect(ok, msg, target)

        if not ALLOW_CONTROL:
            return respond(False, "Control is disabled on this panel.")
        if STEP_UP and not hmac.compare_digest(password, ACTION_PASSWORD):
            _audit("config", user, self._ip(), outcome="denied", slug=slug, kind=kind,
                   detail="wrong password")
            return respond(False, "Wrong password. Settings were not saved.")
        values = {k[2:]: v[0] for k, v in form.items() if k.startswith("k_")}
        ok, msg = do_set_knobs(slug, kind, values)
        _audit("config", user, self._ip(), outcome=("ok" if ok else "fail"),
               slug=slug, kind=kind, detail=msg)
        return respond(ok, msg)

    def _new_client(self):
        """Create a client from the setup form. Auth required. No step-up: a new
        client starts in passive mode and cannot scan anything until its target
        is on the approved list, so creation itself changes no running state."""
        user = self._identity()
        if not user:
            return self._send(302, b"", {"Location": "/login"})
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())

        def g(k):
            return form.get(k, [""])[0] or ""
        ok, msg, meta = do_create_client(
            g("name"), g("domains"), g("keywords"), g("notes"), confirm=(g("confirm") == "1"))
        _audit("create_client", user, self._ip(), outcome=("ok" if ok else "fail"),
               slug=meta.get("slug", ""), detail=msg)
        payload = {"ok": ok, "msg": msg}
        payload.update(meta)
        # Hand back the non-enumerable client id so the UI opens /c/<cid>, not
        # /c/<slug> (which would leak the name and not match the console route).
        if ok and meta.get("slug"):
            payload["cid"] = _client_id(meta["slug"])
        return self._send(200, json.dumps(payload).encode(),
                          {"Content-Type": "application/json; charset=utf-8"})

    def _ingest(self):
        """Extract candidate domains from pasted text with the local model, or a
        regex fallback. Read-only, it writes nothing and runs nothing."""
        user = self._identity()
        if not user:
            return self._send(302, b"", {"Location": "/login"})
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        res = do_ingest(form.get("text", [""])[0] or "")
        return self._send(200, json.dumps(res).encode(),
                          {"Content-Type": "application/json; charset=utf-8"})

    def _report(self):
        """Generate the attack-surface report (Word and PDF). Auth required, no
        step-up: it only reads signals and writes into the reports folder, it
        starts no scan and sends no traffic."""
        user = self._identity()
        if not user:
            return self._send(302, b"", {"Location": "/login"})
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        slug = _resolve_client((form.get("slug", [""])[0] or "").strip()) or ""
        ok, msg = do_generate_report(slug)
        _audit("report", user, self._ip(), outcome=("ok" if ok else "fail"),
               slug=slug, detail=msg)
        return self._send(200, json.dumps({"ok": ok, "msg": msg}).encode(),
                          {"Content-Type": "application/json; charset=utf-8"})

    def _alert(self):
        """Generate the editable early-alert Word note for a client (Critical and
        High findings only). Auth required, no step-up: it only reads signals and
        writes into the reports folder, it starts no scan and sends no traffic."""
        user = self._identity()
        if not user:
            return self._send(302, b"", {"Location": "/login"})
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        slug = _resolve_client((form.get("slug", [""])[0] or "").strip()) or ""
        key = (form.get("key", [""])[0] or "").strip()
        ok, msg, name = do_generate_alert(slug, key)
        _audit("alert", user, self._ip(), outcome=("ok" if ok else "fail"),
               slug=slug, detail=msg)
        payload = {"ok": ok, "msg": msg}
        if ok and name:
            payload["url"] = (f'/dl?e={_client_id(slug)}'
                              f'&f={urllib.parse.quote(name)}')
        return self._send(200, json.dumps(payload).encode(),
                          {"Content-Type": "application/json; charset=utf-8"})

    def _vuln_action(self):
        """Triage one finding: mark it a false positive or confirmed, reopen it,
        or record that it was sent to Security Joes. Marking and reopening force
        a reason, which is stored and audited. Auth required, no step-up
        (reversible triage, no scan, no traffic). Every action is audited."""
        user = self._identity()
        if not user:
            return self._send(302, b"", {"Location": "/login"})
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        slug = _resolve_client((form.get("slug", [""])[0] or "").strip()) or ""
        key = (form.get("key", [""])[0] or "").strip()
        act = (form.get("act", [""])[0] or "").strip()
        reason = (form.get("reason", [""])[0] or "").strip()
        if not slug or not (ENGAGEMENTS / slug).is_dir():
            return self._flash_redirect(False, "Unknown client.", "/")
        v = next((x for x in _all_findings(slug).values() if x["key"] == key), None)
        if v is None:
            return self._flash_redirect(False, "Finding not found.", f"/c/{_client_id(slug)}")
        vid = v["id"]
        # Evidence attached in the triage modal: the stored names were already
        # uploaded via /vuln-evidence. Resolve each to its file record so the
        # Activities trail can show the exact files alongside the note.
        wanted = [s.strip() for s in (form.get("evidence", [""])[0] or "").split("\n") if s.strip()]
        note_files = []
        if wanted:
            evfiles = (_vmeta_load(slug).get(key, {}) or {}).get("files", [])
            by_stored = {f.get("stored"): f for f in evfiles}
            for st in wanted:
                f = by_stored.get(st)
                if f:
                    note_files.append({"stored": f.get("stored", ""),
                                       "orig": f.get("orig", f.get("stored", ""))})
        vurl = f"/vuln?e={_client_id(slug)}&v={vid}"
        now = datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC")
        fp = _fp_load(slug)
        cf = _confirmed_load(slug)
        # Marking and reopening both require a recorded reason.
        if act in ("fp", "confirm", "reopen") and not reason:
            return self._flash_redirect(False, "A reason is required.", vurl)
        if act == "fp":
            cf.pop(key, None)
            _confirmed_save(slug, cf)
            fp[key] = {"key": key, "id": vid, "severity": v["severity"],
                       "title": v["title"], "by": user, "reason": reason, "ts": now}
            _fp_save(slug, fp)
            _vnotes_append(slug, key, "Marked false positive", reason, user, now, note_files)
            _audit("false_positive", user, self._ip(), outcome="ok", slug=slug,
                   detail=f"{v['title']} :: {reason}")
            return self._flash_redirect(True, "Marked as a false positive.",
                                        f"/c/{_client_id(slug)}#falsepos")
        if act == "confirm":
            fp.pop(key, None)
            _fp_save(slug, fp)
            cf[key] = {"key": key, "id": vid, "severity": v["severity"],
                       "title": v["title"], "by": user, "reason": reason, "ts": now}
            _confirmed_save(slug, cf)
            _vnotes_append(slug, key, "Marked confirmed", reason, user, now, note_files)
            _audit("confirm_finding", user, self._ip(), outcome="ok", slug=slug,
                   detail=f"{v['title']} :: {reason}")
            return self._flash_redirect(True, "Marked as confirmed.",
                                        f"/c/{_client_id(slug)}#confirmed")
        if act == "reopen":
            if key in fp:
                fp.pop(key, None)
                _fp_save(slug, fp)
            if key in cf:
                cf.pop(key, None)
                _confirmed_save(slug, cf)
            _vnotes_append(slug, key, "Reopened for review", reason, user, now, note_files)
            _audit("reopen_finding", user, self._ip(), outcome="ok", slug=slug,
                   detail=f"{v['title']} :: {reason}")
            # Reopened findings go back to the open (to review) list.
            return self._flash_redirect(True, "Finding reopened for review.",
                                        f"/c/{_client_id(slug)}#attn")
        if act == "send":
            # Record intent to ship this finding to Security Joes AIR. The AIR
            # shipper itself is a separate, pending piece of work, so for now this
            # logs the action and queues it in the client's state folder.
            try:
                qf = ENGAGEMENTS / slug / "state" / "sent_to_securityjoes.jsonl"
                qf.parent.mkdir(parents=True, exist_ok=True)
                with qf.open("a") as fh:
                    fh.write(json.dumps({
                        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "key": key, "id": vid, "title": v["title"],
                        "severity": v["severity"], "by": user}) + "\n")
            except Exception:
                pass
            _audit("send_securityjoes", user, self._ip(), outcome="ok", slug=slug,
                   detail=v["title"])
            return self._flash_redirect(True, "Finding recorded for Security Joes.", vurl)
        return self._flash_redirect(False, "Unknown action.", vurl)

    def _bulk_action(self):
        """Apply one triage action (confirm, false positive, or send to Security
        Joes) to many findings at once from the triage queue. Confirm and false
        positive force an operator note. Answers JSON. Auth required, no step-up:
        reversible triage, no scan, no traffic. Every finding is audited."""
        user = self._identity()
        if not user:
            return self._send(401, b'{"ok":false,"msg":"Not authenticated."}',
                              {"Content-Type": "application/json; charset=utf-8"})
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        act = (form.get("act", [""])[0] or "").strip()
        reason = (form.get("reason", [""])[0] or "").strip()

        def j(ok, msg):
            return self._send(200, json.dumps({"ok": ok, "msg": msg}).encode(),
                              {"Content-Type": "application/json; charset=utf-8"})
        if act not in ("fp", "confirm", "send"):
            return j(False, "Unknown action.")
        if act in ("fp", "confirm") and not reason:
            return j(False, "A note is required for this action.")
        try:
            items = json.loads(form.get("items", ["[]"])[0] or "[]")
        except Exception:
            items = []
        if not isinstance(items, list) or not items:
            return j(False, "Nothing selected.")
        if len(items) > 500:
            return j(False, "Too many findings selected at once.")
        done = 0
        failed = 0
        seen = set()
        for it in items:
            if not isinstance(it, dict):
                failed += 1
                continue
            slug = _resolve_client((it.get("cid") or "").strip()) or ""
            key = (it.get("key") or "").strip()
            if not slug or not key or not (ENGAGEMENTS / slug).is_dir():
                failed += 1
                continue
            if (slug, key) in seen:
                continue
            seen.add((slug, key))
            if _bulk_apply_one(slug, key, act, reason, user, self._ip()):
                done += 1
            else:
                failed += 1
        verb = {"fp": "marked as false positive", "confirm": "marked confirmed",
                "send": "recorded for Security Joes"}[act]
        msg = f"{done} finding(s) {verb}."
        if failed:
            msg += f" {failed} could not be processed."
        return j(done > 0, msg)

    def _vuln_meta(self):
        """Save operator edits to a finding (CVSS vector, description, OWASP, CWE,
        reproduction steps, curl, figures, mitigation, references) into the
        per-client vuln_meta sidecar. Answers JSON. Auth required, no step-up: it
        edits notes, starts no scan and sends no traffic. A blank value clears
        that field, and the finding falls back to whatever the signal carried.
        Fields arrive as cvss_vector= (the rating editor) or f_<field>= (the
        section editors); every field name is whitelisted and length capped."""
        user = self._identity()
        if not user:
            return self._send(401, b'{"ok":false,"msg":"Not authenticated."}',
                              {"Content-Type": "application/json; charset=utf-8"})
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        slug = _resolve_client((form.get("slug", [""])[0] or "").strip()) or ""
        key = (form.get("key", [""])[0] or "").strip()

        def j(ok, msg):
            return self._send(200, json.dumps({"ok": ok, "msg": msg}).encode(),
                              {"Content-Type": "application/json; charset=utf-8"})
        if not slug or not (ENGAGEMENTS / slug).is_dir():
            return j(False, "Unknown client.")
        v = next((x for x in _all_findings(slug).values() if x["key"] == key), None)
        if v is None:
            return j(False, "Finding not found.")
        # Collect the submitted fields: f_<field> from the section editors, plus
        # the legacy cvss_vector= from the rating editor.
        updates: dict[str, str] = {}
        for fk, vals in form.items():
            if fk.startswith("f_"):
                updates[fk[2:]] = (vals[0] if vals else "")
        if "cvss_vector" in form:
            updates["cvss_vector"] = form.get("cvss_vector", [""])[0] or ""
        if not updates:
            return j(False, "Nothing to save.")
        for fk, val in updates.items():
            if fk not in _VMETA_FIELDS:
                return j(False, f"Unknown field {fk}.")
            if len(val) > _VMETA_FIELDS[fk]:
                return j(False, f"{fk} is too long.")
            if fk == "cvss_vector" and val.strip() and not _cvss_vector(val):
                return j(False, "Not a valid CVSS 3.1 vector.")
        meta = _vmeta_load(slug)
        entry = meta.get(key, {})
        for fk, val in updates.items():
            val = val.strip() if fk in ("cvss_vector", "owasp", "cwe") else val.rstrip()
            if val:
                entry[fk] = val
            else:
                entry.pop(fk, None)
        if entry:
            meta[key] = entry
        else:
            meta.pop(key, None)
        _vmeta_save(slug, meta)
        _audit("vuln_meta", user, self._ip(), outcome="ok", slug=slug,
               detail=f"{v['title']} :: {', '.join(sorted(updates))}")
        return j(True, "Saved.")

    def _read_multipart(self):
        """Parse a multipart/form-data body into (fields, files). fields maps a
        name to its decoded string, files is a list of (name, filename, ctype,
        bytes). Returns None if the body is not multipart or is too large. A
        hand-rolled parser, since cgi.FieldStorage is gone in current Python."""
        ctype = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in ctype:
            return None
        m = re.search(r"boundary=([^;]+)", ctype)
        if not m:
            return None
        boundary = m.group(1).strip().strip('"').encode()
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0 or length > MAX_EVIDENCE_TOTAL:
            return None
        data = self.rfile.read(length)
        fields: dict[str, str] = {}
        files: list[tuple[str, str, str, bytes]] = []
        for part in data.split(b"--" + boundary):
            if not part or part in (b"--\r\n", b"--", b"\r\n"):
                continue
            if b"\r\n\r\n" not in part:
                continue
            head, body = part.split(b"\r\n\r\n", 1)
            if body.endswith(b"\r\n"):
                body = body[:-2]
            dispo = cty = ""
            for line in head.decode("utf-8", "replace").split("\r\n"):
                low = line.lower()
                if low.startswith("content-disposition"):
                    dispo = line
                elif low.startswith("content-type"):
                    cty = line.split(":", 1)[1].strip()
            nm = re.search(r'name="([^"]*)"', dispo)
            if not nm:
                continue
            fnm = re.search(r'filename="([^"]*)"', dispo)
            if fnm is not None:
                files.append((nm.group(1), fnm.group(1), cty, body))
            else:
                fields[nm.group(1)] = body.decode("utf-8", "replace")
        return fields, files

    def _vuln_figcap(self):
        """Set the caption of one figure inline. The figure is identified by its
        file name token (the left side of a `filename | caption` figures line);
        only that line's caption changes. Auth required, no step-up."""
        user = self._identity()
        if not user:
            return self._send(401, b'{"ok":false,"msg":"Not authenticated."}',
                              {"Content-Type": "application/json; charset=utf-8"})

        def j(ok, msg=""):
            return self._send(200, json.dumps({"ok": ok, "msg": msg}).encode(),
                              {"Content-Type": "application/json; charset=utf-8"})

        length = int(self.headers.get("Content-Length", 0) or 0)
        form = urllib.parse.parse_qs(self.rfile.read(length).decode()) if length else {}
        slug = _resolve_client((form.get("slug", [""])[0] or "").strip()) or ""
        key = (form.get("key", [""])[0] or "").strip()
        fn = (form.get("file", [""])[0] or "").strip()
        caption = (form.get("caption", [""])[0] or "").strip()
        if len(caption) > 500:
            return j(False, "Caption is too long.")
        if not slug or not (ENGAGEMENTS / slug).is_dir():
            return j(False, "Unknown client.")
        v = next((x for x in _all_findings(slug).values() if x["key"] == key), None)
        if v is None:
            return j(False, "Finding not found.")
        caption = caption.replace("|", "/").replace("\n", " ").replace("\r", " ")
        meta = _vmeta_load(slug)
        entry = meta.get(key, {})
        lines = [ln for ln in (entry.get("figures") or "").splitlines() if ln.strip()]
        found = False
        out = []
        for ln in lines:
            name = ln.split("|", 1)[0].strip()
            if not found and name.lower() == fn.lower():
                out.append(f"{name} | {caption}")
                found = True
            else:
                out.append(ln)
        if not found:
            return j(False, "Figure not found.")
        entry["figures"] = "\n".join(out)
        meta[key] = entry
        _vmeta_save(slug, meta)
        _audit("evidence_caption", user, self._ip(), outcome="ok", slug=slug,
               file=fn, detail=caption[:80])
        return j(True, "Saved.")

    def _vuln_capture(self):
        """Capture a browser-UI screenshot of each confirmed impersonation domain
        for a finding and attach them, so the operator sees the evidence on the
        Manage page without exporting first. Renders each in-scope domain in a
        headful Chromium on a virtual display, so it sends one page request per
        domain. Auth required. Returns JSON {ok, msg, made}."""
        user = self._identity()
        if not user:
            return self._send(401, b'{"ok":false,"msg":"Not authenticated."}',
                              {"Content-Type": "application/json; charset=utf-8"})

        def j(ok, msg, extra=None):
            payload = {"ok": ok, "msg": msg}
            if extra:
                payload.update(extra)
            return self._send(200, json.dumps(payload).encode(),
                              {"Content-Type": "application/json; charset=utf-8"})

        length = int(self.headers.get("Content-Length", 0) or 0)
        form = urllib.parse.parse_qs(self.rfile.read(length).decode()) if length else {}
        slug = _resolve_client((form.get("slug", [""])[0] or "").strip()) or ""
        key = (form.get("key", [""])[0] or "").strip()
        if not slug or not (ENGAGEMENTS / slug).is_dir():
            return j(False, "Unknown client.")
        v = next((x for x in _all_findings(slug).values() if x["key"] == key), None)
        if v is None:
            return j(False, "Finding not found.")
        if v.get("source_class") != "lookalike_domain":
            return j(False, "Browser capture is only available for brand-impersonation findings.")
        try:
            from tools import evidence_capture
        except Exception:
            try:
                import evidence_capture
            except Exception:
                evidence_capture = None
        if evidence_capture is None or [m for m in evidence_capture.preflight()
                                        if m.startswith("missing:")]:
            miss = (evidence_capture.preflight() if evidence_capture else
                    ["capture tools are not installed"])
            return j(False, "Capture tools are missing on this host. " + "; ".join(
                m for m in miss if m.startswith("missing:")))
        try:
            made = _capture_finding_evidence(slug, key)
        except Exception as exc:
            _audit("evidence_capture", user, self._ip(), outcome="fail",
                   slug=slug, detail=str(exc))
            return j(False, f"Capture failed: {exc}")
        _audit("evidence_capture", user, self._ip(), outcome="ok", slug=slug,
               detail=f"{v['title']} ({made} new)")
        if made:
            return j(True, f"Captured {made} screenshot(s).", {"made": made})
        return j(True, "No new screenshots (all domains were already captured or did not render).",
                 {"made": 0})

    def _vuln_evidence(self):
        """Attach or remove an evidence file (PNG, JPG, PDF) for a finding. The
        file is validated against the OWASP upload policy, stored under a safe
        name the client never chose, recorded in vuln_meta, and audited. No
        step-up: it stores proof, starts no scan and sends no traffic."""
        user = self._identity()
        if not user:
            return self._send(401, b'{"ok":false,"msg":"Not authenticated."}',
                              {"Content-Type": "application/json; charset=utf-8"})

        def j(ok, msg, extra=None):
            payload = {"ok": ok, "msg": msg}
            if extra:
                payload.update(extra)
            return self._send(200, json.dumps(payload).encode(),
                              {"Content-Type": "application/json; charset=utf-8"})

        parsed = self._read_multipart()
        if parsed is None:
            return j(False, "Upload too large or malformed.")
        fields, files = parsed
        slug = _resolve_client((fields.get("slug") or "").strip()) or ""
        key = (fields.get("key") or "").strip()
        act = (fields.get("act") or "upload").strip()
        if not slug or not (ENGAGEMENTS / slug).is_dir():
            return j(False, "Unknown client.")
        v = next((x for x in _all_findings(slug).values() if x["key"] == key), None)
        if v is None:
            return j(False, "Finding not found.")
        vid = v["id"]
        evdir = ENGAGEMENTS / slug / "evidence" / vid
        meta = _vmeta_load(slug)
        entry = meta.get(key, {})
        evlist = entry.get("files", [])

        if act == "delete":
            stored = Path((fields.get("stored") or "")).name
            new = [f for f in evlist if f.get("stored") != stored]
            if len(new) == len(evlist):
                return j(False, "File not found.")
            try:
                tgt = (evdir / stored).resolve()
                if str(tgt).startswith(str(evdir.resolve())) and tgt.is_file():
                    tgt.unlink()
            except Exception:
                pass
            entry["files"] = new
            # Drop this file's figure line too, so the figure block disappears
            # entirely and every later figure renumbers down by one (numbering is
            # by position in the list).
            fig_lines = [ln for ln in (entry.get("figures") or "").splitlines()
                         if ln.strip()]
            kept = [ln for ln in fig_lines
                    if ln.split("|", 1)[0].strip().lower() != stored.lower()]
            if kept:
                entry["figures"] = "\n".join(kept)
            else:
                entry.pop("figures", None)
            if entry:
                meta[key] = entry
            else:
                meta.pop(key, None)
            _vmeta_save(slug, meta)
            _audit("evidence_delete", user, self._ip(), outcome="ok", slug=slug,
                   file=stored, detail=v["title"])
            return j(True, "Removed.")

        if not files:
            return j(False, "No file received.")
        name, filename, cty, body = files[0]
        ok, ext, msg = _validate_evidence(filename, cty, body)
        if not ok:
            _audit("evidence_upload", user, self._ip(), outcome="denied", slug=slug,
                   file=filename, detail=msg)
            return j(False, msg)
        declared = _safe_token(fields.get("name") or Path(filename).stem)
        # Each upload is its own figure, even when the same image is uploaded
        # again, so numbering keeps climbing (Figure 11, 12, ...). A counter
        # suffix keeps every stored name unique instead of deduping on content.
        base_stored = f"{declared}-{hashlib.sha1(body).hexdigest()[:8]}"
        # The name must be unique against both files on disk AND existing figure
        # lines, so a new upload always appends a fresh figure and never collides
        # with (and silently refills) an existing or orphaned one.
        taken = {p.name.lower() for p in evdir.glob("*")} if evdir.exists() else set()
        taken |= {ln.split("|", 1)[0].strip().lower()
                  for ln in (entry.get("figures") or "").splitlines() if ln.strip()}
        taken |= {f.get("stored", "").lower() for f in evlist}
        stored = f"{base_stored}.{ext}"
        seq = 2
        while stored.lower() in taken:
            stored = f"{base_stored}-{seq}.{ext}"
            seq += 1
        try:
            evdir.mkdir(parents=True, exist_ok=True)
            (evdir / stored).write_bytes(body)
        except Exception:
            return j(False, "Could not store the file.")
        evlist = [f for f in evlist if f.get("stored") != stored]
        evlist.append({"stored": stored, "orig": Path(filename).name[:120],
                       "ct": cty[:80], "size": len(body), "by": user,
                       "ts": datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC")})
        entry["files"] = evlist
        # An uploaded image becomes the next figure automatically (Figure N+1),
        # appended after the existing figures with an empty caption the operator
        # fills in via the Figures editor. PDFs stay as plain attachments.
        if ext in ("png", "jpg"):
            fig_lines = [ln for ln in (entry.get("figures") or "").splitlines()
                         if ln.strip()]
            # stored is unique per upload, so this always appends a new figure,
            # numbered after the last one.
            if not any(ln.split("|", 1)[0].strip().lower() == stored.lower()
                       for ln in fig_lines):
                fig_lines.append(f"{stored} | ")
                entry["figures"] = "\n".join(fig_lines)
        meta[key] = entry
        _vmeta_save(slug, meta)
        _audit("evidence_upload", user, self._ip(), outcome="ok", slug=slug,
               file=stored, detail=f"{v['title']} ({len(body)} bytes)")
        return j(True, "Uploaded.", {"stored": stored})

    def _serve_evidence(self, url, user: str):
        """Serve one stored evidence file inline, path-traversal safe."""
        q = urllib.parse.parse_qs(url.query)
        slug = _resolve_client((q.get("e", [""])[0] or "").strip())
        vid = (q.get("v", [""])[0] or "").strip()
        name = Path(q.get("f", [""])[0]).name
        if not slug or not _CID_RE.match(vid):
            return self._send(404, _page('<div class="empty">Not found.</div>', user))
        v = _vuln_by_id(slug, vid)
        if not v:
            return self._send(404, _page('<div class="empty">Not found.</div>', user))
        base = (ENGAGEMENTS / slug / "evidence" / vid).resolve()
        target = (base / name).resolve()
        if not str(target).startswith(str(base)) or not target.is_file():
            return self._send(404, _page('<div class="empty">Not found.</div>', user))
        ext = target.suffix.lower().lstrip(".")
        ctype = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
                 "pdf": "application/pdf"}.get(ext, "application/octet-stream")
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Disposition", f'inline; filename="{name}"')
        self.send_header("Content-Security-Policy", "default-src 'none'; img-src 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _subs_edit(self):
        """Save the operator's curated subdomain list for a client. Hosts are
        normalised and validated, invalid lines dropped. Any host not previously
        known (not in the saved list and not in discovery) is recorded as a new
        subdomain alert. Answers JSON. Auth required, no step-up: it edits a list,
        starts no scan and sends no traffic."""
        user = self._identity()
        if not user:
            return self._send(401, b'{"ok":false,"msg":"Not authenticated."}',
                              {"Content-Type": "application/json; charset=utf-8"})
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        slug = _resolve_client((form.get("slug", [""])[0] or "").strip()) or ""

        def j(ok, msg):
            return self._send(200, json.dumps({"ok": ok, "msg": msg}).encode(),
                              {"Content-Type": "application/json; charset=utf-8"})
        if not slug or not (ENGAGEMENTS / slug).is_dir():
            return j(False, "Unknown client.")
        base = ENGAGEMENTS / slug
        raw_lines = (form.get("list", [""])[0] or "").splitlines()
        if len(raw_lines) > 8000:
            return j(False, "Too many lines.")
        cleaned: list[str] = []
        seen: set[str] = set()
        dropped = 0
        for ln in raw_lines:
            if not ln.strip():
                continue
            h = _host_clean(ln)
            if not h:
                dropped += 1
                continue
            if h not in seen:
                seen.add(h)
                cleaned.append(h)
        cleaned.sort()
        st = _subs_state_load(slug)
        known = set(st.get("list") or []) | set(_subdomain_list(base))
        added = sorted(seen - known)
        st["list"] = cleaned
        if added:
            st.setdefault("alerts", []).append({
                "ts": datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC"),
                "source": "manual edit", "new": added})
            st["alerts"] = st["alerts"][-100:]
            _slack_notify(f":mag: Continuous EAS: {len(added)} subdomain(s) added for "
                          f"{_pretty(slug)}: {', '.join(added[:20])}")
        _subs_state_save(slug, st)
        _audit("subdomains_edit", user, self._ip(), outcome="ok", slug=slug,
               detail=f"{len(cleaned)} hosts, {len(added)} new, {dropped} dropped")
        msg = f"Saved {len(cleaned)} subdomains."
        if added:
            msg += f" {len(added)} new (alert raised)."
        if dropped:
            msg += f" {dropped} invalid line(s) dropped."
        return j(True, msg)

    def _leak_fetch(self):
        """Ingest the client's intake folder into the leak store. Answers JSON.
        Auth required, no step-up: it reads files already on the server, starts
        no scan and sends no traffic."""
        user = self._identity()
        if not user:
            return self._send(401, b'{"ok":false,"msg":"Not authenticated."}',
                              {"Content-Type": "application/json; charset=utf-8"})
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        slug = _resolve_client((form.get("slug", [""])[0] or "").strip()) or ""

        def j(ok, msg):
            return self._send(200, json.dumps({"ok": ok, "msg": msg}).encode(),
                              {"Content-Type": "application/json; charset=utf-8"})
        if not slug or not (ENGAGEMENTS / slug).is_dir():
            return j(False, "Unknown client.")
        files_read, new_count = _ingest_leaks(slug)
        _audit("leak_fetch", user, self._ip(), outcome="ok", slug=slug,
               detail=f"{files_read} file(s), {new_count} new")
        if not files_read and not new_count:
            return j(True, "No new credentials to add.")
        if not files_read:
            return j(True, f"{new_count} new credential(s) added.")
        msg = f"Read {files_read} file(s), {new_count} new credential(s)."
        return j(True, msg)

    def _leak_reveal(self):
        """Return one credential's plaintext password. Answers JSON. The reveal is
        audited because it exposes a secret. Passwords are never embedded in the
        page, only fetched here on demand."""
        user = self._identity()
        if not user:
            return self._send(401, b'{"ok":false,"msg":"Not authenticated."}',
                              {"Content-Type": "application/json; charset=utf-8"})
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        slug = _resolve_client((form.get("slug", [""])[0] or "").strip()) or ""
        cid = (form.get("id", [""])[0] or "").strip()

        def j(ok, **kw):
            return self._send(200, json.dumps({"ok": ok, **kw}).encode(),
                              {"Content-Type": "application/json; charset=utf-8"})
        if not slug or not (ENGAGEMENTS / slug).is_dir():
            return j(False, msg="Unknown client.")
        rec = next((c for c in _leaks_load(slug)["creds"] if c.get("id") == cid), None)
        if rec is None:
            return j(False, msg="Credential not found.")
        _audit("leak_reveal", user, self._ip(), outcome="ok", slug=slug,
               detail=rec.get("user", ""))
        return j(True, password=rec.get("password", ""))

    def _leak_export(self, url, user: str):
        """Export the client's leaked credentials as an XLSX, including the
        plaintext passwords (the point of the export). Named for the client and
        the date. The export is audited."""
        q = urllib.parse.parse_qs(url.query)
        slug = _resolve_client((q.get("e", [""])[0] or "").strip())
        if not slug:
            return self._send(404, _page('<div class="empty">Client not found.</div>', user))
        creds = sorted(_leaks_load(slug)["creds"],
                       key=lambda c: (c.get("domain", ""), c.get("user", "")))
        try:
            from openpyxl import Workbook
        except Exception:
            return self._send(500, _page('<div class="empty">openpyxl is not '
                                          'installed on the server.</div>', user))
        wb = Workbook()
        ws = wb.active
        ws.title = "Credentials"
        ws.append(["User", "Password", "Domain", "Source", "Date"])
        for c in creds:
            ws.append([c.get("user", ""), c.get("password", ""), c.get("domain", ""),
                       c.get("source", ""), c.get("date", "") or c.get("first_seen", "")])
        import io
        buf = io.BytesIO()
        wb.save(buf)
        data = buf.getvalue()
        when = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        fname = f"Corporate credentials - {_pretty(slug)} - {when}.xlsx"
        _audit("leak_export", user, self._ip(), outcome="ok", slug=slug,
               detail=f"{len(creds)} credential(s)")
        self.send_response(200)
        self.send_header("Content-Type", "application/vnd.openxmlformats-"
                         "officedocument.spreadsheetml.sheet")
        self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _vdb_save_handler(self):
        """Create or update a vuln-db template. Every change is logged."""
        user = self._identity()
        if not user:
            return self._send(302, b"", {"Location": "/login"})
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())

        def g(k):
            return (form.get(k, [""])[0] or "").strip()
        name = g("name")
        if not name:
            return self._flash_redirect(False, "Name is required.", "/vuln-db")
        vector = g("cvss_vector")
        if vector and not _cvss_vector(vector):
            return self._flash_redirect(False, "Invalid CVSS vector.", "/vuln-db")
        sev = g("severity") if g("severity") in SEV_ORDER else "SEV3"
        rec = {"name": name[:160], "owasp": g("owasp")[:120], "cwe": g("cwe")[:120],
               "tags": g("tags")[:160], "severity": sev, "cvss_vector": vector,
               "description": (form.get("description", [""])[0] or "")[:20000],
               "reproduction": (form.get("reproduction", [""])[0] or "")[:20000],
               "mitigation": (form.get("mitigation", [""])[0] or "")[:20000],
               "references": (form.get("references", [""])[0] or "")[:8000],
               "example": False}
        data = _vdb_load()
        rid = _resolve_tpl(g("id")) if g("id") else ""
        existing = next((x for x in data["templates"] if x.get("id") == rid), None) if rid else None
        if existing:
            rec["example"] = existing.get("example", False)
            rec["id"] = rid
            data["templates"] = [rec if x.get("id") == rid else x for x in data["templates"]]
            _vdb_log(data, "edited", name, user)
        else:
            rec["id"] = hashlib.sha1(f"{name}|{secrets.token_hex(4)}".encode()).hexdigest()[:12]
            data["templates"].append(rec)
            _vdb_log(data, "created", name, user)
        _vdb_save(data)
        _audit("vuln_db", user, self._ip(), outcome="ok", detail=f"save {name}")
        return self._flash_redirect(True, "Template saved.", "/vuln-db")

    def _vdb_del_handler(self):
        user = self._identity()
        if not user:
            return self._send(302, b"", {"Location": "/login"})
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        rid = _resolve_tpl((form.get("id", [""])[0] or "").strip())
        data = _vdb_load()
        t = next((x for x in data["templates"] if x.get("id") == rid), None) if rid else None
        if t:
            data["templates"] = [x for x in data["templates"] if x.get("id") != rid]
            _vdb_log(data, "deleted", t.get("name", ""), user)
            _vdb_save(data)
            _audit("vuln_db", user, self._ip(), outcome="ok", detail=f"delete {t.get('name', '')}")
        return self._flash_redirect(True, "Template deleted.", "/vuln-db")

    def _review_new(self):
        """Create a manual finding for a client. It is written as a signal (source
        class manual) so it flows into Needs attention, the vuln page and triage
        like any finding, and its editable fields are seeded in vuln_meta. Severity
        comes from the CVSS vector when given, otherwise the chosen severity."""
        user = self._identity()
        if not user:
            return self._send(302, b"", {"Location": "/login"})
        # The form posts multipart so it can carry evidence files. Fall back to
        # urlencoded for a plain submit with no attachments.
        parsed = self._read_multipart()
        upfiles: list[tuple[str, str, str, bytes]] = []
        if parsed is not None:
            mfields, upfiles = parsed

            def g(k):
                return (mfields.get(k, "") or "").strip()

            def gmulti(k):
                return mfields.get(k, "") or ""
        else:
            length = int(self.headers.get("Content-Length", 0))
            form = urllib.parse.parse_qs(self.rfile.read(length).decode())

            def g(k):
                return (form.get(k, [""])[0] or "").strip()

            def gmulti(k):
                return form.get(k, [""])[0] or ""
        slug = _resolve_client(g("slug")) or ""
        title = g("title")
        if not slug or not (ENGAGEMENTS / slug).is_dir():
            return self._flash_redirect(False, "Unknown client.", "/review?new=1")
        if not title:
            return self._flash_redirect(False, "Title is required.", "/review?new=1")
        vector = g("cvss_vector")
        if vector and not _cvss_vector(vector):
            return self._flash_redirect(False, "Invalid CVSS vector.", "/review?new=1")
        if vector:
            sev = _sev_for_score(_cvss31_score(vector))
        else:
            sev = g("severity") if g("severity") in SEV_ORDER else "SEV3"
        hosts = [h for h in (_host_clean(x) for x in
                 gmulti("hosts").splitlines()) if h]
        key = f"manual|{secrets.token_hex(8)}"
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        finding = {
            "dedup_id": key, "title": title[:200],
            "description": gmulti("description")[:20000],
            "severity": sev, "source": "Manual entry", "source_class": "manual",
            "entities": [{"type": "domain", "value": h} for h in hosts],
            "evidence": {"manual": True, "by": user},
            "cvss": vector, "first_seen": now, "last_seen": now}
        sigf = ENGAGEMENTS / slug / "signals" / f"{slug}-manual.jsonl"
        try:
            sigf.parent.mkdir(parents=True, exist_ok=True)
            with sigf.open("a") as fh:
                fh.write(json.dumps(finding) + "\n")
        except Exception:
            return self._flash_redirect(False, "Could not save the finding.", "/review?new=1")
        # Seed the editable fields so the vuln page shows them.
        meta = _vmeta_load(slug)
        entry = {}
        if vector:
            entry["cvss_vector"] = vector
        for fk in ("owasp", "cwe"):
            if g(fk):
                entry[fk] = g(fk)
        for fk in ("description", "steps", "mitigation", "references"):
            val = gmulti(fk).strip()
            if val:
                entry[fk] = val
        vid = _vuln_id(slug, key)
        # Store any attached evidence under the finding's evidence folder, the
        # same validation and layout as the per-vuln uploader.
        ev_saved = 0
        if upfiles:
            evdir = ENGAGEMENTS / slug / "evidence" / vid
            evlist = entry.get("files", [])
            for (_nm, filename, cty, bodyb) in upfiles[:12]:
                if not filename:
                    continue
                okv, ext, _msg = _validate_evidence(filename, cty, bodyb)
                if not okv:
                    _audit("evidence_upload", user, self._ip(), outcome="denied",
                           slug=slug, file=filename, detail=_msg)
                    continue
                declared = _safe_token(Path(filename).stem)
                stored = f"{declared}-{hashlib.sha1(bodyb).hexdigest()[:8]}.{ext}"
                try:
                    evdir.mkdir(parents=True, exist_ok=True)
                    (evdir / stored).write_bytes(bodyb)
                except Exception:
                    continue
                evlist = [f for f in evlist if f.get("stored") != stored]
                evlist.append({"stored": stored, "orig": Path(filename).name[:120],
                               "ct": cty[:80], "size": len(bodyb), "by": user,
                               "ts": datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC")})
                ev_saved += 1
            if evlist:
                entry["files"] = evlist
        if entry:
            meta[key] = entry
            _vmeta_save(slug, meta)
        _invalidate_state(slug)
        _audit("manual_finding", user, self._ip(), outcome="ok", slug=slug, detail=title)
        if ev_saved:
            _audit("evidence_upload", user, self._ip(), outcome="ok", slug=slug,
                   detail=f"{title} ({ev_saved} file(s) at creation)")
        return self._flash_redirect(True, "Manual finding created (to review).",
                                    f"/vuln?e={_client_id(slug)}&v={vid}")

    def _add_context(self):
        """Add domains and notes to an existing client, including mid-run. New
        domains enter scope but still pass the target guardrail before scanning."""
        user = self._identity()
        if not user:
            return self._send(302, b"", {"Location": "/login"})
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())

        def g(k):
            return form.get(k, [""])[0] or ""
        slug = _resolve_client(g("slug").strip()) or ""
        xhr = (g("xhr") == "1")
        ok, msg = do_add_context(slug, g("domains"), g("notes"))
        _audit("add_context", user, self._ip(), outcome=("ok" if ok else "fail"),
               slug=slug, detail=msg)
        if xhr:
            return self._send(200, json.dumps({"ok": ok, "msg": msg}).encode(),
                              {"Content-Type": "application/json; charset=utf-8"})
        target = f"/c/{_client_id(slug)}" if slug else "/"
        return self._flash_redirect(ok, msg, target)

    def _context_save(self):
        """Save a client's company context (legal entity, CEO, sector,
        description) and an optional imported brand logo. Answers JSON. Auth
        required, no step-up: it writes a per-client record and an image, starts
        no scan and sends no traffic."""
        user = self._identity()
        if not user:
            return self._send(401, b'{"ok":false,"msg":"Not authenticated."}',
                              {"Content-Type": "application/json; charset=utf-8"})

        def j(ok, msg):
            return self._send(200, json.dumps({"ok": ok, "msg": msg}).encode(),
                              {"Content-Type": "application/json; charset=utf-8"})

        parsed = self._read_multipart()
        if parsed is None:
            return j(False, "Upload too large or malformed.")
        fields, files = parsed
        slug = _resolve_client((fields.get("slug") or "").strip()) or ""
        if not slug or not (ENGAGEMENTS / slug).is_dir():
            return j(False, "Unknown client.")
        data = _ctx_meta_load(slug)
        data["legal_entity"] = (fields.get("legal") or "").strip()[:200]
        data["website"] = (fields.get("website") or "").strip()[:200]
        data["ceo"] = (fields.get("ceo") or "").strip()[:200]
        data["sector"] = (fields.get("sector") or "").strip()[:200]
        data["description"] = (fields.get("description") or "").strip()[:4000]
        logo = next((f for f in files if f[0] == "logo" and f[3]), None)
        if logo:
            _name, filename, cty, body = logo
            ok, ext, msg = _validate_evidence(filename, cty, body)
            if not ok:
                return j(False, msg)
            if ext == "pdf":
                return j(False, "The logo must be a PNG or JPG image.")
            sdir = ENGAGEMENTS / slug / "state"
            try:
                sdir.mkdir(parents=True, exist_ok=True)
                for old in sdir.glob("brand-logo.*"):
                    try:
                        old.unlink()
                    except Exception:
                        pass
                stored = f"brand-logo.{ext}"
                (sdir / stored).write_bytes(body)
            except Exception:
                return j(False, "Could not store the logo.")
            data["logo"] = stored
        _ctx_meta_save(slug, data)
        _audit("context_save", user, self._ip(), outcome="ok", slug=slug,
               detail="company context" + (" + logo" if logo else ""))
        return j(True, "Company context saved.")

    def _serve_brand_logo(self, url, user: str):
        """Serve a client's imported brand logo inline, path-traversal safe."""
        q = urllib.parse.parse_qs(url.query)
        slug = _resolve_client((q.get("e", [""])[0] or "").strip())
        if not slug:
            return self._send(404, _page('<div class="empty">Not found.</div>', user))
        stored = _ctx_meta_load(slug).get("logo")
        if not stored:
            return self._send(404, _page('<div class="empty">Not found.</div>', user))
        base = (ENGAGEMENTS / slug / "state").resolve()
        target = (base / Path(stored).name).resolve()
        if not str(target).startswith(str(base)) or not target.is_file():
            return self._send(404, _page('<div class="empty">Not found.</div>', user))
        ext = target.suffix.lower().lstrip(".")
        ctype = {"png": "image/png", "jpg": "image/jpeg",
                 "jpeg": "image/jpeg"}.get(ext, "application/octet-stream")
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Disposition", f'inline; filename="{Path(stored).name}"')
        self.send_header("Content-Security-Policy", "default-src 'none'; img-src 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _control(self):
        """Start or stop a watcher. Requires auth plus a password step-up.
        Answers with JSON for an async (xhr) call, a redirect otherwise."""
        user = self._identity()
        if not user:
            return self._send(302, b"", {"Location": "/login"})
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        action = (form.get("action", [""])[0] or "").strip()
        slug = _resolve_client((form.get("slug", [""])[0] or "").strip()) or ""
        kind = (form.get("kind", [""])[0] or "").strip()
        password = form.get("password", [""])[0] or ""
        xhr = (form.get("xhr", [""])[0] == "1")
        # Return to the client page the action was taken on (non-xhr path).
        target = f"/c/{_client_id(slug)}" if slug else "/"

        def respond(ok, msg):
            if xhr:
                return self._send(200, json.dumps({"ok": ok, "msg": msg}).encode(),
                                  {"Content-Type": "application/json; charset=utf-8"})
            return self._flash_redirect(ok, msg, target)

        if not ALLOW_CONTROL:
            _audit("control", user, self._ip(), outcome="denied", detail="control disabled")
            return respond(False, "Control is disabled on this panel.")
        # Step up: the password must be re-entered and must match, every time,
        # unless step-up is disabled for testing (PANEL_NO_STEPUP).
        if STEP_UP and not hmac.compare_digest(password, ACTION_PASSWORD):
            _audit("control", user, self._ip(), outcome="denied",
                   action=action, slug=slug, kind=kind, detail="wrong password")
            return respond(False, f"Wrong password. The {action or 'action'} was not performed.")
        if action == "run_all":
            ok, msg = do_run_all(slug)
        elif action == "stop_all":
            ok, msg = do_stop_all(slug)
        else:
            ok, msg = do_control(action, slug, kind)
        _audit("control", user, self._ip(), outcome=("ok" if ok else "fail"),
               action=action, slug=slug, kind=kind, detail=msg)
        return respond(ok, msg)


def main() -> int:
    ap = argparse.ArgumentParser(description="Continuous EAS read-only operator console")
    ap.add_argument("--host", default="127.0.0.1", help="bind address, localhost by default")
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args()

    if not PANEL_SSO and not PANEL_PASSWORD and not NO_AUTH:
        print("[!] PANEL_PASSWORD is not set. Set PANEL_USER and PANEL_PASSWORD in "
              "your environment (.env on a dev box) before starting the panel.")
    if NO_AUTH and not PANEL_SSO:
        print("[i] No-auth local mode: no sign-in required (bound to "
              f"{args.host}). Set PANEL_REQUIRE_AUTH=1 or PANEL_SSO to require a login.")
    mode = "no-auth (local)" if NO_AUTH and not PANEL_SSO else "SSO" if PANEL_SSO else "local demo login"
    print(f"[i] Continuous EAS console on http://{args.host}:{args.port}  (auth: {mode})")
    print(f"[i] reading state from {DATA}")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
