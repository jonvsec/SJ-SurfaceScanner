#!/usr/bin/env python3
"""tools/page_template.py. The single source of truth for client-page structure.

WHY THIS FILE EXISTS
--------------------
Every client (every engagement) must present the SAME tabs, the
SAME sections, in the SAME order, with the SAME wording, so improving a page once
improves it for every client without editing each one. Per-client state holds
only the DATA (names, numbers, findings); this file holds the STRUCTURE. The tab
renderers in panel.py read the section list from here and fill each slot from the
client's own data, showing the section's empty-state prompt when the client has
nothing for it yet. "Template always wins": the structure, order and prompts come
from here, never from per-client files.

Modeled on the reference context page, which is the reference for a complete dossier.

HOW TO CHANGE A PAGE
--------------------
Edit the section list for the tab here (add, remove, reorder, rename, or reword a
prompt). The change applies to every client on the next page load. Do not special
-case a client in a renderer: if something is client-specific it is DATA and
belongs in that client's state, not in the structure.

Each section is a dict:
    id      stable key the renderer uses to find/fill the section (never shown)
    title   the heading shown on the page
    prompt  the empty-state line shown when the client has no data for it
    note    optional one-line helper under the title (operator guidance)

A renderer walks TABS[<tab>] in order; for each section it asks its own data
layer for that section's content, and falls back to `prompt` when empty.
"""
from __future__ import annotations


# Context tab: the layer-0 company dossier. The identity card at the top is the
# operator-editable summary; the sections below are the footprint the layer-0
# phase produced. Order follows the reference dossier.
CONTEXT_SECTIONS = [
    {"id": "identity",
     "title": "Company identity",
     "prompt": "No identity set yet. Edit to add the legal entity, website, "
               "CEO, sector and a short description.",
     "note": "Operator-maintained summary. Overrides the footprint where set."},
    {"id": "legal_ownership",
     "title": "Legal entity and ownership",
     "prompt": "No legal entity or ownership resolved yet. Run the layer-0 "
               "footprint, or add the registered entity, registry code and "
               "parent group by hand."},
    {"id": "brands_subsidiaries",
     "title": "Brands and subsidiaries",
     "prompt": "No brands or subsidiaries attributed yet."},
    {"id": "domains_attribution",
     "title": "Domains and attribution",
     "prompt": "No domains attributed yet beyond the in-scope apex."},
    {"id": "infrastructure",
     "title": "Infrastructure and hosting",
     "prompt": "No hosting, nameserver, mail or tenant posture resolved yet."},
    {"id": "people",
     "title": "People",
     "prompt": "No people recorded. People data stays held until unlocked.",
     "note": "Sourcing people data is gated, it is the operator's call."},
    {"id": "lookalikes",
     "title": "Lookalike and impersonation domains",
     "prompt": "No lookalike or impersonation domains identified yet.",
     "note": "Live count comes from the latest lookalike sweep."},
    {"id": "exposure",
     "title": "Sanctions and exposure",
     "prompt": "No sanctions, litigation or adverse-media exposure recorded."},
    {"id": "coverage",
     "title": "Coverage",
     "prompt": "No coverage statement yet. It is written by the layer-0 phase."},
]

# Vulnerabilities tab: the per-finding detail page. Order follows the lookalike
# finding, which is the reference for a complete write-up.
VULN_SECTIONS = [
    {"id": "summary",
     "title": "Summary",
     "prompt": "No summary yet.",
     "note": "Severity, CVSS and affected locations."},
    {"id": "classification",
     "title": "Classification",
     "prompt": "No OWASP or CWE classification set yet."},
    {"id": "description",
     "title": "Description",
     "prompt": "No description yet. The Vuln DB template fills this for known "
               "finding types."},
    {"id": "evidence",
     "title": "Evidence",
     "prompt": "No reproduction steps or figures yet.",
     "note": "Reproduction steps and figures. Screenshots attach as figures."},
    {"id": "mitigation",
     "title": "Mitigation",
     "prompt": "No mitigation steps yet."},
    {"id": "references",
     "title": "References",
     "prompt": "No references yet. Add at least one."},
]

# Subdomains tab.
SUBDOMAIN_SECTIONS = [
    {"id": "subdomains",
     "title": "Subdomains",
     "prompt": "No subdomains discovered yet. Run recon to populate this.",
     "note": "The live hosts discovered for the client."},
]

# Leaks tab.
LEAK_SECTIONS = [
    {"id": "credentials",
     "title": "Credential exposure",
     "prompt": "No leaked credentials ingested yet. Attach an intake file to "
               "populate this.",
     "note": "Credentials ingested from breach and stealer-log intake files."},
]

TABS = {
    "context": CONTEXT_SECTIONS,
    "vuln": VULN_SECTIONS,
    "subdomains": SUBDOMAIN_SECTIONS,
    "leaks": LEAK_SECTIONS,
}


def sections(tab: str) -> list:
    """The ordered section list for a tab, or [] for an unknown tab."""
    return TABS.get(tab, [])


def empty_state(section: dict) -> str:
    """The standard empty-state block for a section, used by every renderer so a
    client with no data for a section shows the same prompt instead of a gap."""
    note = (f'<div class="secnote">{section["note"]}</div>'
            if section.get("note") else "")
    return (f'<div class="secempty">{section.get("prompt", "Nothing here yet.")}'
            f'</div>{note}')
