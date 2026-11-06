#!/usr/bin/env python3
"""
tools/footprint_run.py. Layer 0 company-footprint phase, agent-backed.

WHAT THIS DOES
--------------
Turns one in-scope domain plus a company name into a resolved entity chain, a
parent and acquisitions map, a passive infrastructure attribution set, and
investigative leads, written as layer-0 signal records every later phase
consumes. See deploy/LAYER0_FOOTPRINT_BRIEF.md.

The investigative logic is NOT reimplemented here. It lives in the maintained
Claude Code skill `eas-company-footprint`, which this runner invokes headless
on the server. The engine wraps that agent with the hard guardrails a prompt
cannot be trusted to keep. The agent proposes, the engine disposes.

Three pieces, in order:

  1. the invoker        build the prompt, run the agent, collect what it wrote
  2. the pre-run wrap   inject scope and mode as data the agent must obey
  3. the post-run gate  enforce the four hard invariants before any signal is
                        accepted (scope promotion, mode, sanctions halt, people
                        and email quarantine)

Only validated records become signals. The record contract is
references/layer0-seed-output.md.

    # real run (needs ANTHROPIC_API_KEY and the skill installed on the host)
    python tools/footprint_run.py --scope scopes/acme.yaml --once

    # offline: validate an agent output that already exists, no agent call.
    # Used to test the gate without a key or the skill present.
    python tools/footprint_run.py --scope scopes/acme.yaml --skip-agent

No em dashes, no en dashes, no semicolons in anything emitted to signals.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import _slug, engagement_paths   # noqa: E402
from scope_parser import load_scope, Scope         # noqa: E402

# Record contract, mirrored into the repo at references/layer0-seed-output.md.
RECORD_FIELDS = ("type", "value", "canonical_id", "scope", "state",
                 "ownership_signal", "confidence", "source", "as_of")

ASSET_TYPES = {"apex", "domain", "ip", "netblock", "asn", "cloud_account",
               "entra_tenant", "code_org", "mobile_app", "entity", "person"}

SCOPE_TAGS = {"in-scope-confirmed", "attribution-only"}
STATE_VALUES = {"live", "acquired", "divested", "winding-down", "parked", "defunct"}
CONFIDENCE_VALUES = {"verified", "inferred", "lead"}

# The subsidiary and brand-to-domain resolver's input type. The agent proposes a
# candidate domain for every subsidiary, acquisition, parent, or sister brand it
# names. This is NOT an asset type: a candidate is never accepted as scope. The
# engine resolves each one and sets a verdict (see resolve_candidates), then
# writes candidate_domains.jsonl. A candidate with an owned verdict feeds back as
# an attribution-only root, never in-scope-confirmed (the authorization interlock).
CANDIDATE_TYPE = "candidate_domain"
VERDICTS = {"pending", "owned", "lookalike", "third_party"}

# The structured company profile. The agent emits exactly one of these, a single
# line carrying a nested `profile` object with the scalar dossier facts (legal
# entity, registry code, registrar, nameservers, hosting, sector, headquarters,
# and so on). It is NOT an asset and holds no scope. Capturing these as explicit
# fields is what lets the Context dossier show them reliably instead of guessing
# them out of the coverage prose. Any field the agent could not establish is left
# empty, which the console renders as an honest None.
PROFILE_TYPE = "company_profile"
PROFILE_FIELDS = (
    "legal_entity", "legal_entity_status", "registry_code", "registry_source",
    "registry_url", "incorporated", "former_names", "parent_group", "ceo",
    "funding", "public_filings",
    "trademark_owner", "sector", "business_model", "headquarters",
    "other_offices", "headcount", "key_customers", "certifications",
    "registrar", "registrar_date", "nameservers", "hosting", "mail_posture",
    "tenant_type", "sso", "social", "summary",
)

# The integrity dimension. The agent emits one sanctions_screen record (the
# outcome of screening the entity and every named principal against OFAC, the EU
# and UK consolidated lists and PEP sources) and zero or more investigative
# records (adverse media, litigation, regulatory action, offshore). These land in
# their own schema files, not the asset stream. A sanctions_screen with status
# hit is the escalation, read from the status FIELD, never grepped from text, so
# the word "sanctions" in the record type can never trip a false halt.
SCREEN_TYPE = "sanctions_screen"
SCREEN_FIELDS = ("status", "list", "matched_entity", "screened_at", "subjects")
INVEST_TYPE = "investigative"
INVEST_CATEGORIES = ("litigation", "regulatory", "offshore", "adverse_media")

# Same-name entities the agent considered and ruled out (a different company that
# merely shares the brand word). Emitted as their own records so the exclusion is
# a structured, auditable line in ruled_out.jsonl, not only prose in the coverage
# statement. value is the ruled-out name, reason why it is not the target.
RULED_OUT_TYPE = "ruled_out"
RULED_OUT_FIELDS = ("value", "reason", "source", "confidence")

# A related entity's relationship to the target, from the TARGET's point of view:
# parent (sits above it, including its owner), subsidiary (sits below it, a brand
# or operating company it holds), sister (a sibling under the same parent), or
# fund-vehicle (a fund or ICAV/UCITS product, not a group company). The agent may
# set it explicitly; _relation() falls back to the ownership-signal wording.
RELATION_VALUES = ("parent", "subsidiary", "sister", "fund-vehicle")

# Microsoft's public OpenID endpoint resolves a domain to its Entra tenant GUID.
# It queries Microsoft, never the candidate's own infrastructure, so it is
# passive-safe and is the same signal azure_tenant uses. It is the single probe
# the resolver is allowed to make, and it is the strongest ownership tie available.
_OPENID = "https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration"
_GUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_DOMAIN_RE = re.compile(r"\b([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9\-]+)*\.[a-z]{2,})\b",
                        re.IGNORECASE)
_RESOLVER_UA = {"User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                               "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")}
# Bound the resolver's runtime: at most this many distinct candidate domains get
# a live tenant lookup in one cycle. The rest are emitted with a pending verdict.
_RESOLVER_MAX = 30

# Invariant 2. A source or signal that implies the agent (or a tool it drove)
# actively touched client or third-party infrastructure. In a passive scope any
# record carrying one of these is rejected. Matched case-insensitively against
# the record's source and ownership_signal text.
ACTIVE_PROBE_MARKERS = (
    "port scan", "portscan", "nmap", "masscan", "active probe", "active scan",
    "login attempt", "credential test", "brute", "fuzz", "dns bruteforce",
    "zone transfer", "axfr", "sent a request to", "connected to the host",
)

# Invariant 3. A sanctions, OFAC, embargo, or clear PEP signal halts the thread
# and escalates. Matched case-insensitively against type, source, ownership and
# a dedicated `thread`/`category` field when the agent set one.
SANCTIONS_MARKERS = (
    "sanction", "ofac", "sdn list", "embargo", "pep", "politically exposed",
    "eu consolidated list", "ofsi", "specially designated",
)

# Invariant 4. Person-level and email-sourcing records are never auto-accepted.
# They are quarantined as a recommendation behind the existing operator gate.
PEOPLE_EMAIL_TYPES = {"person"}
# Named email-sourcing tools and services. A bare "@" is NOT here: it matched
# resolver syntax like `dig @1.1.1.1` in a source field and wrongly quarantined
# ordinary domain records. A real email address is detected by _EMAIL_RE below,
# which requires a dotted alphabetic TLD, so `@1.1.1.1` and `@resolver` do not
# match.
EMAIL_SOURCE_MARKERS = ("hunter.io", "linkedin", "email harvest", "email-harvest",
                        "rocketreach")
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[a-z]{2,}", re.IGNORECASE)


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _clean(text: str) -> str:
    """Strip the punctuation the house style forbids from emitted signal text."""
    if not isinstance(text, str):
        return ""
    out = text.replace("—", ", ").replace("–", "-").replace(";", ",")
    return " ".join(out.split())


def _slack_notify(text: str, blocks: list | None = None) -> bool:
    """Best-effort post of a message to the configured Slack webhook, so a
    finished (or failed) Layer 0 run reaches the operator's channel. Reads the
    same SURFACESCANNER_SLACK_WEBHOOK the panel uses. When blocks are given they
    render the rich layout and text is kept as the notification fallback. No
    webhook set, or any error, is a silent no-op. Never raises."""
    hook = os.environ.get("SURFACESCANNER_SLACK_WEBHOOK", "").strip()
    if not hook.startswith("https://hooks.slack.com/"):
        return False
    try:
        payload: dict = {"text": text}
        if blocks:
            payload["blocks"] = blocks
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            hook, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=6) as r:  # noqa: S310 (fixed host)
            return 200 <= r.status < 300
    except Exception:
        return False


def _panel_base() -> str:
    """The panel's externally reachable base URL, for deep links in notices.
    SURFACESCANNER_PANEL_URL overrides the local-dev default. Trailing slash
    trimmed so a path can be appended directly."""
    return os.environ.get(
        "SURFACESCANNER_PANEL_URL", "http://127.0.0.1:8787").strip().rstrip("/")


def _client_id(slug: str) -> str:
    """Recompute the panel's non-guessable client id for a slug, so a notice can
    deep-link to the client without putting the name in the URL. Mirrors the
    panel's _client_id: HMAC of the slug keyed by the shared per-install secret
    at DATA/.vuln-id-secret. Empty string if the secret is not readable, and the
    caller then falls back to a plain link."""
    try:
        data_dir = Path(os.environ.get(
            "SURFACESCANNER_DATA", Path.home() / "surfacescanner-data"))
        secret = (data_dir / ".vuln-id-secret").read_bytes()
        if not secret:
            return ""
        return hmac.new(secret, f"client|{slug}".encode(),
                        hashlib.sha256).hexdigest()[:24]
    except Exception:
        return ""


def _context_url(slug: str) -> str:
    """Deep link to a client's Context dossier tab."""
    cid = _client_id(slug)
    if cid:
        return f"{_panel_base()}/c/{cid}?t=context"
    return _panel_base() + "/"


def _overrun_warn_secs() -> float:
    """Wall-clock seconds past which a still-running Layer 0 is flagged as taking
    longer than expected. The panel's expected budget tops out at 8 min (480s);
    the default warns at 1.5x that (12 min) to skip false alarms on a merely slow
    run. SURFACESCANNER_L0_WARN_SECS overrides it; 0 or less disables the warning."""
    try:
        return float(os.environ.get("SURFACESCANNER_L0_WARN_SECS", "720"))
    except Exception:
        return 720.0


def _start_overrun_watchdog(name: str, slug: str) -> threading.Timer | None:
    """Arm a one-shot timer that posts a single alert-emoji Slack warning if the
    run is still going past the expected budget. Returns the timer so the caller
    cancels it the moment the run ends (so a run that finishes in time warns
    nobody). A daemon timer never blocks process exit. None when disabled or no
    webhook is configured."""
    secs = _overrun_warn_secs()
    hook = os.environ.get("SURFACESCANNER_SLACK_WEBHOOK", "").strip()
    if secs <= 0 or not hook.startswith("https://hooks.slack.com/"):
        return None
    mins = int(round(secs / 60.0))

    def _fire() -> None:
        _slack_notify(
            f":warning: Layer 0 for {name} is taking longer than expected "
            f"(past {mins} min and still running). Check the run debug: "
            f"{_panel_base()}/l0-debug?e={_client_id(slug)}",
            blocks=[
                {"type": "header",
                 "text": {"type": "plain_text",
                          "text": "Layer 0 taking longer than expected",
                          "emoji": True}},
                {"type": "section",
                 "text": {"type": "mrkdwn",
                          "text": f":warning: *Client:* {name}\n"
                                  f"Still running after *{mins} min*, past the "
                                  f"expected budget. It may be stalled."}},
                {"type": "section",
                 "text": {"type": "mrkdwn",
                          "text": f"<{_panel_base()}/l0-debug?e={_client_id(slug)}"
                                  f"|Open the run debug>"}},
                {"type": "divider"},
            ])

    t = threading.Timer(secs, _fire)
    t.daemon = True
    t.start()
    return t


def _finish_blocks(name: str, slug: str, summary: dict, halt: str) -> list:
    """Block Kit layout for a finished Layer 0 run: a client line, the run
    totals, a SurfaceScanner mark, and a link to the Context dossier."""
    halt_line = f"\n:warning: *{halt.strip()}*" if halt.strip() else ""
    stats = (f"Accepted *{summary['accepted']}*  |  candidates "
             f"*{summary['candidates']}* ({summary['candidates_owned']} owned)"
             f"  |  subsidiaries *{summary['subsidiaries']}*  |  quarantined "
             f"*{summary['quarantined']}*  |  dropped *{summary['dropped']}*")
    blocks = [
        {"type": "header",
         "text": {"type": "plain_text", "text": "Layer 0 complete",
                  "emoji": True}},
        {"type": "section",
         "text": {"type": "mrkdwn",
                  "text": f":white_check_mark: *Client:* {name}\n{stats}{halt_line}"}},
        {"type": "section",
         "text": {"type": "mrkdwn",
                  "text": f"<{_context_url(slug)}|Open the Context dossier>"}},
        {"type": "divider"},
    ]
    return blocks


# ---------------------------------------------------------------------------
# Piece 2: pre-run wrapper. Scope and mode as data the agent cannot argue with.
# ---------------------------------------------------------------------------

def build_prompt(scope: Scope, outdir: Path, raw_file: Path) -> str:
    """Build the headless prompt. The scope, the mode, and the output contract
    are stated as data, and the authorization interlock is spelled out so the
    agent starts everything it spreads to as attribution-only. The engine still
    enforces all of this in validate(), the prompt is a convenience not a trust
    boundary."""
    domain = scope.primary_domain or ""
    aliases = ", ".join(scope.target.aliases) if scope.target.aliases else "none recorded"
    oos = ", ".join(scope.out_of_scope) if scope.out_of_scope else "none recorded"
    extra = ", ".join(scope.domains[1:]) if len(scope.domains) > 1 else "none"

    return f"""Use the eas-company-footprint skill to run the layer-0 company
footprint for this engagement. Passive OSINT only.

ENGAGEMENT DATA (authoritative, do not override from your own knowledge):
- Contracted in-scope domain: {domain}
- Company name: {scope.target.name}
- Known aliases: {aliases}
- Other domains named in scope: {extra}
- Out of scope: {oos}
- Scope mode: {scope.mode}. Layer 0 is passive OSINT only regardless of mode.
- Data classification: {scope.data_classification}

AUTHORIZATION INTERLOCK (hard):
- The contracted domain and anything the signed authorization names are
  in-scope-confirmed. Everything you reach by spreading scope (parent, group,
  sister, brand, acquired domains, people, infrastructure) starts as
  attribution-only. Never mark a spread-to asset in-scope-confirmed.
- Never auto-promote an attribution-only asset to active testing.

SAME-NAME GATE (hard):
- An entity, record, person, or story belongs to the target ONLY when a concrete
  ownership signal ties it to the target. A shared brand word is never proof.
- For every same-name entity you rule out (a different company that merely shares
  the brand word), emit a record of type ruled_out: value the ruled-out entity
  name, reason a short why-it-is-not-the-target, source, confidence. Emit one per
  ruled-out entity. Also name them in the coverage statement. Do not leave an
  exclusion only in prose: the record is what the dossier shows.

CORPORATE MAP AND CANDIDATE DOMAINS (the subsidiary resolver's input):
- For every subsidiary, acquisition, former name, parent, or sister brand you
  find, emit an entity record with its state ({", ".join(sorted(STATE_VALUES))})
  and an as_of date. Name the group relationship in the ownership_signal.
- On each related entity set "relation", its direction from the TARGET's point of
  view, one of: {", ".join(RELATION_VALUES)}. parent = sits ABOVE the target
  (its owner or holding company), subsidiary = sits BELOW it (a brand or company
  it holds), sister = a sibling under the same parent, fund-vehicle = a fund or
  ICAV/UCITS product rather than a group company. Get the direction right: an
  owner is a parent, not a subsidiary.
- On each of those related entity records also set three context fields so the
  corporate map reads, not just a name: "summary" (one line on what it is and its
  main service, for example "crypto sportsbook brand" or "B2B game-content
  aggregation platform"), "sector" (its industry), and "jurisdiction" (where it
  is based or licensed, for example "Estonia" or "Curacao"). Leave any you could
  not establish as an empty string, never a guess.
- For each of those related brands or companies, ALSO emit a candidate domain if
  you can identify the website it appears to use. One record per candidate:
  type candidate_domain, value the apex domain (example.com, not a URL or a
  subdomain), ownership_signal naming which brand or company it belongs to and
  why you think so, confidence, source. Do NOT resolve its tenant or probe it,
  the engine does that and sets the owned / lookalike / third-party verdict. Just
  propose the domain. A candidate is a lead for the engine to verify, never scope.

COMPANY PROFILE (one structured record, required):
- Emit exactly one line of type company_profile carrying a nested "profile"
  object with these scalar facts about the TARGET company, as far as you
  established them: {", ".join(PROFILE_FIELDS)}.
  legal_entity is the resolved legal vehicle, or the brand if unresolved;
  legal_entity_status is "resolved" or "unresolved". registry_code is the company
  number and jurisdiction. registry_source is the NAME of the register the legal
  entity was resolved from (for example "Companies House", "data.gov.il",
  "Estonian e-Business Register"), and registry_url a direct link to that exact
  register row, both matching the entity's real jurisdiction, never a register
  from another country. ceo is the chief executive or managing director from
  public filings or the company site (a company-level fact, not held people
  data). incorporated is the formation or domain-registration date. sector and business_model describe what the company actually does (do not
  guess a generic label). registrar/registrar_date/nameservers/hosting/mail_posture
  describe the PRIMARY in-scope apex only. tenant_type and sso come from the Entra
  and identity signals.
- Fill these four, they are the ones most often left wrongly empty:
  * mail_posture: describe the mail path for ANY provider, not just Microsoft.
    Name the provider from the MX (Google Workspace, Outlook, Proofpoint, other),
    then the SPF all-qualifier and the DMARC policy, for example "Google
    Workspace, SPF -all, no DMARC" or "Outlook, SPF -all, DMARC p=quarantine".
  * headquarters: name the principal office or registered jurisdiction even when
    there are several locations, and put the rest in other_offices. Do not leave
    HQ empty just because the company lists more than one office.
  * social: the company's OWN official accounts (LinkedIn, X, YouTube) are
    company-level, not personal data, so fill them. The people gate is about
    individuals, not the corporate channel.
  * summary: two to four sentences that LEAD with what the company actually does,
    named plainly. Derive the real sector from the parent and the brands, not the
    company's own marketing label. If the company describes itself in neutral or
    euphemistic terms (for example "online entertainment" for a gambling
    operator), state the real business first and note the self-description as a
    hedge. A reader must know what they do from the first sentence.
- sector and business_model state the real activity concretely, not a generic
  label. Leave any field you could not establish as an empty string, never a
  guess. This is not an asset and has no scope or ownership_signal.

INTEGRITY AND SCREENING (required, do not skip):
- Screen the target entity AND every named principal (founders, directors,
  beneficial owners) against sanctions and PEP sources: OFAC SDN, the EU and UK
  consolidated lists, and PEP databases (OpenSanctions consolidates these).
- Emit exactly one line of type sanctions_screen with these fields:
  {", ".join(SCREEN_FIELDS)}. status is clear, hit, or unscreened. A screen that
  ran and found nothing is status clear, NOT unscreened and NOT silence. Only a
  screen you could not run at all is unscreened. subjects lists who you screened.
  If status is hit, name the matched_entity and the list, and stop spreading
  scope around that subject, the engine halts and escalates.
- Search adverse media, litigation, regulatory action, and offshore records
  (ICIJ Offshore Leaks and Pandora Papers, and offshore vehicles such as Curacao
  or BVI entities in the corporate map). Emit one line of type investigative per
  finding, with fields: category (one of {", ".join(INVEST_CATEGORIES)}), source
  (the locator), node_id (the ICIJ node id if any), confidence (verified,
  inferred or lead), and summary (one line). If you searched and found nothing
  adverse, record that empty result in the coverage statement, it is a negative,
  not an omission.
- Also emit the public code organisation (GitHub or GitLab org) as a code_org
  asset record when the company has one, with the org URL as the value.

OUTPUT CONTRACT:
- Write one JSON object per line (JSONL) to: {raw_file}
- Each asset line has exactly these fields: {", ".join(RECORD_FIELDS)}.
  type is one of {", ".join(sorted(ASSET_TYPES))}.
  scope is in-scope-confirmed or attribution-only.
  state (for entity and brand records) is one of {", ".join(sorted(STATE_VALUES))} with an as_of date.
  ownership_signal is the concrete signal that ties the asset to the target and is required.
  confidence is verified, inferred, or lead.
- A candidate_domain line has: type candidate_domain, value, ownership_signal,
  confidence, source. It is not an asset, so it is exempt from the asset fields.
- After the records, write a coverage statement of what was searched and came
  back empty to: {outdir / "coverage.md"}
- If you surface a sanctions, OFAC, embargo, or clear PEP hit on the target or a
  principal, still write it as a record with ownership_signal naming the match,
  and stop spreading scope around that subject. The engine halts and escalates it.
- Do not emit em dashes, en dashes, or semicolons in any field.

You may use WebSearch, WebFetch, Read, Write, and Bash. Write only under
{outdir}. Do not touch any other path."""


# ---------------------------------------------------------------------------
# Piece 1: the invoker.
# ---------------------------------------------------------------------------

def _claude_logged_in(claude_bin: str) -> bool:
    """True when the Claude Code CLI is resolvable and has a stored login, so
    the agent can run on the operator's subscription with no API key."""
    if not shutil.which(claude_bin) and not os.path.isfile(claude_bin):
        return False
    cred = os.path.expanduser("~/.claude/.credentials.json")
    return os.path.isfile(cred)


def agent_env() -> dict:
    """Environment for the headless agent. Two credential paths are accepted,
    in this order:

      1. ANTHROPIC_API_KEY in the process environment (loaded from the
         engagement .env by the unit), which bills the Anthropic API.
      2. no key, but a logged-in Claude Code CLI, which runs the agent on the
         operator's subscription. When no key is set we must NOT inject one, so
         the CLI uses its stored session.

    The key is never hardcoded and never comes from the skill."""
    env = dict(os.environ)
    if env.get("ANTHROPIC_API_KEY"):
        return env
    claude_bin = os.environ.get("CLAUDE_BIN", "claude")
    if _claude_logged_in(claude_bin):
        # Subscription path: leave the environment as-is (no key) so the CLI
        # falls back to its stored OAuth session.
        return env
    raise RuntimeError(
        "No credentials for the agent. Set ANTHROPIC_API_KEY in the engagement "
        ".env to bill the API, or log in the Claude Code CLI (claude) to run on "
        "your subscription, or run with --skip-agent for an offline validation "
        "of an existing agent output.")


def _summarize_event(line: str) -> dict | None:
    """Turn one stream-json NDJSON event into a compact, timestamped timeline
    entry for the debug view: which tool the agent called and the one detail
    that matters (the query, the URL, the command, the file). Returns None for
    events not worth a timeline row. Never raises."""
    s = line.strip()
    if not s or not s.startswith("{"):
        return None
    try:
        ev = json.loads(s)
    except Exception:
        return None
    et = ev.get("type")
    if et == "system" and ev.get("subtype") == "init":
        return {"kind": "init", "tool": "", "detail": "agent session started"}
    if et == "result":
        return {"kind": "result", "tool": "",
                "detail": f'done, {ev.get("num_turns", "?")} turns, '
                          f'${ev.get("total_cost_usd", 0):.2f}'}
    if et == "assistant":
        out = []
        for blk in (ev.get("message", {}) or {}).get("content", []) or []:
            bt = blk.get("type")
            if bt == "tool_use":
                name = blk.get("name", "tool")
                inp = blk.get("input", {}) or {}
                detail = (inp.get("query") or inp.get("url")
                          or inp.get("command") or inp.get("file_path")
                          or inp.get("pattern") or "")
                out.append({"kind": "tool", "tool": name,
                            "detail": str(detail)[:300]})
            elif bt == "text":
                txt = (blk.get("text") or "").strip()
                if txt:
                    out.append({"kind": "think", "tool": "",
                                "detail": txt[:300]})
        # One assistant turn may hold several blocks; the pump writes each.
        return out or None
    return None


def invoke_agent(prompt: str, outdir: Path) -> None:
    """Run the maintained skill headless, STREAMING. The engine validates
    whatever it writes afterwards, so a crash or a partial write degrades to
    'validate what is there', never to 'trust the agent'.

    Output is streamed as stream-json NDJSON so a debug view can follow the run
    live. Three files, overwritten each run, never appended:
      agent-stream.jsonl    the raw event stream, exactly as the CLI emits it
      agent-timeline.jsonl  one timestamped row per tool call / step, for the UI
      agent-last.json       the final result event (totals, cost, turns)
      agent-last.err        stderr
    """
    import threading
    claude_bin = os.environ.get("CLAUDE_BIN", "claude")
    cmd = [
        claude_bin, "-p", prompt,
        "--allowedTools", "WebSearch WebFetch Read Write Bash",
        "--output-format", "stream-json", "--verbose",
        "--add-dir", str(outdir),
    ]
    timeout = int(os.environ.get("FOOTPRINT_AGENT_TIMEOUT", "3300"))
    stream_file = outdir / "agent-stream.jsonl"
    tl_file = outdir / "agent-timeline.jsonl"
    out_json = outdir / "agent-last.json"
    err_log = outdir / "agent-last.err"
    last_result = {"line": ""}

    proc = subprocess.Popen(cmd, env=agent_env(), text=True, bufsize=1,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def pump_stdout():
        with stream_file.open("w") as sf, tl_file.open("w") as tf:
            for line in proc.stdout:
                sf.write(line)
                sf.flush()
                if '"type":"result"' in line:
                    last_result["line"] = line.strip()
                evs = _summarize_event(line)
                if not evs:
                    continue
                if isinstance(evs, dict):
                    evs = [evs]
                for ev in evs:
                    ev["ts"] = _utcnow()
                    tf.write(json.dumps(ev) + "\n")
                    tf.flush()

    def pump_stderr():
        with err_log.open("w") as ef:
            for line in proc.stderr:
                ef.write(line)
                ef.flush()

    t1 = threading.Thread(target=pump_stdout, daemon=True)
    t2 = threading.Thread(target=pump_stderr, daemon=True)
    t1.start()
    t2.start()
    try:
        rc = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        t1.join(timeout=5)
        t2.join(timeout=5)
        out_json.write_text(last_result["line"])
        with err_log.open("a") as ef:
            ef.write(f"\nTIMEOUT after {timeout}s\n")
        raise
    t1.join(timeout=5)
    t2.join(timeout=5)
    out_json.write_text(last_result["line"])
    if rc != 0:
        raise subprocess.CalledProcessError(rc, cmd)


def read_agent_records(raw_file: Path) -> list[dict]:
    """Read the JSONL the agent wrote. A malformed line is skipped, not fatal,
    the whole point of the gate is that the agent's output is untrusted."""
    records: list[dict] = []
    if not raw_file.is_file():
        return records
    for ln in raw_file.read_text(errors="replace").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        try:
            obj = json.loads(ln)
        except Exception:
            continue
        if isinstance(obj, dict):
            records.append(obj)
    return records


# ---------------------------------------------------------------------------
# Piece 3: the post-run validator. The four hard invariants.
# ---------------------------------------------------------------------------

def _record_text(rec: dict) -> str:
    bits = [str(rec.get(k, "")) for k in
            ("type", "source", "ownership_signal", "thread", "category", "value")]
    return " ".join(bits).lower()


def _authorized_values(scope: Scope) -> set[str]:
    """What may legitimately carry in-scope-confirmed: the contracted domains and
    anything a signed authorization file names. The authorization file lives in
    the engagement's own state dir, outside the repo and outside the agent's
    reach."""
    vals = {d.strip().lower() for d in scope.domains if d.strip()}
    base = engagement_paths(scope.target.name)["state"]
    authz = base / "authorization.json"
    try:
        if authz.is_file():
            data = json.loads(authz.read_text())
            for v in (data.get("in_scope") or data.get("authorized") or []):
                if isinstance(v, str) and v.strip():
                    vals.add(v.strip().lower())
    except Exception:
        pass
    return vals


# A sanctions/PEP marker only halts when it is a real hit, not a negated mention
# like "no sanctions or PEP hit". Match each marker as a whole word (so "pep"
# does not fire inside other words) and skip it when a negation sits just before.
_NEG_CTX = ("no ", "not ", "zero ", "without ", "clear", "negative", "none ")


def _sanctions_hit(text: str) -> bool:
    for m in SANCTIONS_MARKERS:
        for mt in re.finditer(r"\b" + re.escape(m) + r"\b", text):
            ctx = text[max(0, mt.start() - 28):mt.start()]
            if any(n in ctx for n in _NEG_CTX):
                continue
            return True
    return False


def validate(records: list[dict], scope: Scope) -> dict:
    """Walk every record the agent wrote and enforce the invariants. Returns a
    result bag: accepted records (cleaned), quarantined people/email records, the
    sanctions halt list, and the records dropped with a reason. Nothing is
    silently discarded, every drop is logged."""
    authorized = _authorized_values(scope)
    passive = scope.mode == "passive"

    accepted: list[dict] = []
    quarantined: list[dict] = []
    halted: list[dict] = []
    dropped: list[dict] = []
    candidates: list[dict] = []
    profile: dict = {}
    sanctions_screen: dict = {"status": "unscreened"}
    investigative: list[dict] = []
    ruled_out: list[dict] = []

    for rec in records:
        rtype = str(rec.get("type", "")).strip().lower()
        value = str(rec.get("value", "")).strip()
        text = _record_text(rec)

        # The structured company profile. Not an asset and holds no scope: keep
        # only the recognised scalar fields, cleaned, and take the last one the
        # agent wrote. A sanctions phrase inside it must not slip past the halt.
        if rtype == PROFILE_TYPE:
            prof = rec.get("profile")
            if isinstance(prof, dict):
                if _sanctions_hit(_clean(" ".join(str(v) for v in prof.values()))):
                    rec["halt_reason"] = "sanctions/OFAC/embargo/PEP signal in profile"
                    halted.append(rec)
                    continue
                profile = {k: _clean(str(prof[k])) for k in PROFILE_FIELDS
                           if prof.get(k)}
            continue

        # The sanctions and PEP screen. The verdict is read from the status FIELD,
        # never grepped from text, so the word "sanctions" in the type cannot trip
        # a false halt. status hit is the real escalation and halts. clear and
        # unscreened are recorded for the Context dossier.
        if rtype == SCREEN_TYPE:
            st = str(rec.get("status", "unscreened")).strip().lower()
            if st not in ("clear", "hit", "unscreened"):
                st = "unscreened"
            sanctions_screen = {k: _clean(str(rec.get(k, "")))
                                for k in SCREEN_FIELDS if rec.get(k)}
            sanctions_screen["status"] = st
            if st == "hit":
                rec["halt_reason"] = "sanctions/OFAC/embargo/PEP hit from screen"
                halted.append(rec)
            continue

        # Investigative records (adverse media, litigation, regulatory, offshore).
        # Stored under their category so the Context dossier can group them.
        if rtype == INVEST_TYPE:
            cat = str(rec.get("category", "")).strip().lower()
            if cat not in INVEST_CATEGORIES:
                cat = "adverse_media"
            investigative.append({
                "type":       cat,
                "source":     _clean(str(rec.get("source", ""))),
                "node_id":    rec.get("node_id"),
                "confidence": rec.get("confidence"),
                "summary":    _clean(str(rec.get("summary", ""))),
            })
            continue

        # Candidate domains are the resolver's input, not scope assets. Set them
        # aside here, resolve_candidates verifies each one and sets the verdict.
        if rtype == CANDIDATE_TYPE and value:
            candidates.append(rec)
            continue

        # Same-name entities the agent ruled out (a different company that merely
        # shares the brand word). Persisted as structured exclusions so the
        # Context dossier's "Ruled out" row is not silently empty.
        if rtype == RULED_OUT_TYPE and value:
            ruled_out.append({k: _clean(str(rec.get(k, "")))
                              for k in RULED_OUT_FIELDS if rec.get(k)}
                             | {"value": value})
            continue

        # Basic shape. A record with no type or value is not a scope asset.
        if rtype not in ASSET_TYPES or not value:
            dropped.append({"record": rec, "reason": "missing or unknown type/value"})
            continue

        # Invariant 1. Scope promotion. Force attribution-only unless the value
        # is authorized. Never trust the agent's own in-scope-confirmed tag.
        claimed = str(rec.get("scope", "")).strip().lower()
        if value.lower() in authorized:
            rec["scope"] = "in-scope-confirmed"
        else:
            rec["scope"] = "attribution-only"
            if claimed == "in-scope-confirmed":
                rec["scope_note"] = ("agent claimed in-scope-confirmed, forced to "
                                     "attribution-only (not in authorization)")

        # Invariant 3. Sanctions and PEP halt. Collect and escalate, do not just
        # store and flow on. Checked before mode so it is never dropped by it.
        # Whole-word, negation-aware: a record stating "no sanctions or PEP hit"
        # is not a hit.
        if _sanctions_hit(text):
            rec["halt_reason"] = "sanctions/OFAC/embargo/PEP signal on the subject"
            halted.append(rec)
            continue

        # Invariant 2. Mode. In a passive scope reject anything whose source
        # implies an active probe of infrastructure.
        if passive and any(m in text for m in ACTIVE_PROBE_MARKERS):
            dropped.append({"record": rec,
                            "reason": "active-probe source rejected in passive scope"})
            continue

        # Invariant 4. People and email gate. Quarantine as a recommendation,
        # never an auto-accepted signal. The email test looks only at the
        # record's VALUE (the record IS an email address), not at any email that
        # merely appears in its ownership signal, so a domain or tenant whose
        # signal cites a DMARC or generic contact address is not held.
        is_person = rtype in PEOPLE_EMAIL_TYPES
        is_email_sourced = (any(m in text for m in EMAIL_SOURCE_MARKERS)
                            or bool(_EMAIL_RE.search(value)))
        if is_person or is_email_sourced:
            rec["quarantine_reason"] = ("person or email-sourced record, held for "
                                        "operator confirmation (identity_sourcing gate)")
            quarantined.append(rec)
            continue

        accepted.append(rec)

    return {"accepted": accepted, "quarantined": quarantined,
            "halted": halted, "dropped": dropped, "candidates": candidates,
            "profile": profile, "sanctions_screen": sanctions_screen,
            "investigative": investigative, "ruled_out": ruled_out}


# ---------------------------------------------------------------------------
# The subsidiary and brand-to-domain resolver. Deterministic engine step, runs
# after the gate. The agent proposes candidate domains and names the corporate
# map, the engine verifies each candidate against the target's Entra tenant and
# sets the verdict. Owned candidates feed back as attribution-only roots so later
# layers discover them, but nothing is ever auto-promoted to in-scope-confirmed.
# ---------------------------------------------------------------------------

def _norm_domain(value: str) -> str:
    """Reduce a value to a bare registrable-looking apex, lowercased. Strips a
    scheme, a path, a port, and a leading www. Returns '' if nothing domain-like
    is present, so a free-text value cannot become a candidate."""
    v = (value or "").strip().lower()
    v = re.sub(r"^[a-z]+://", "", v)          # scheme
    v = v.split("/", 1)[0].split("?", 1)[0]   # path, query
    v = v.split(":", 1)[0]                     # port
    v = v.strip().strip(".")
    if v.startswith("www."):
        v = v[4:]
    m = _DOMAIN_RE.fullmatch(v) or _DOMAIN_RE.search(v)
    return m.group(1).lower() if m else ""


def _extract_domain(text: str) -> str:
    """Pull the first domain-looking token out of free text (a subsidiary
    record's ownership_signal), ignoring the resolver and common infra domains
    that are never the subsidiary's own site."""
    for m in _DOMAIN_RE.finditer(text or ""):
        d = m.group(1).lower()
        if any(d.endswith(s) for s in (
                "microsoftonline.com", "outlook.com", "windows.net",
                "amazonaws.com", "cloudflare.com", "github.com", "google.com")):
            continue
        return d
    return ""


def _resolve_tenant_guid(domain: str) -> str | None:
    """Live OpenID lookup, Microsoft only, never the candidate's own host. HTTP
    400 or anything non-200 means the domain has no Entra tenant. Never raises."""
    try:
        req = urllib.request.Request(_OPENID.format(domain=domain),
                                     headers=_RESOLVER_UA)
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 (fixed https host)
            if resp.status != 200:
                return None
            data = json.loads(resp.read().decode("utf-8", "replace"))
        m = _GUID_RE.search(str(data.get("issuer", "")))
        return m.group(0).lower() if m else None
    except Exception:
        return None


def _target_tenant_id(accepted: list[dict]) -> str | None:
    for r in accepted:
        if str(r.get("type", "")).lower() == "entra_tenant":
            m = _GUID_RE.search(str(r.get("value", "")))
            if m:
                return m.group(0).lower()
    return None


def _is_target_entity(rec: dict, scope: Scope) -> bool:
    """True when an entity record is the target itself, not a related company."""
    v = str(rec.get("value", "")).lower()
    names = {scope.target.name.lower(),
             *[a.lower() for a in scope.target.aliases]}
    return any(n and n in v for n in names if len(n) > 2)


def _relation(explicit: str, signal: str, summary: str, scope: Scope) -> str:
    """Classify a related entity's relationship to the target, from the target's
    point of view: parent / subsidiary / sister / fund-vehicle. The agent's
    explicit relation wins; otherwise infer it from the ownership-signal wording
    so parents and fund vehicles are not silently lumped in as subsidiaries. The
    signal is written from the target's perspective, so "parent of <target>" or
    "owns <target>" means the entity is the PARENT, while "subsidiary of
    <target>" or "owned by <target>" means it sits below."""
    e = (explicit or "").lower().strip().replace(" ", "-")
    if e in RELATION_VALUES:
        return e
    if e in ("owner", "holding", "ultimate-parent"):
        return "parent"
    t = f"{signal} {summary}".lower()
    tgt = scope.target.name.lower()
    if any(k in t for k in ("icav", "ucits", "qiaif", "sub-fund", "sub fund",
                            "fund vehicle", "umbrella fund", "ils fund",
                            "feeder fund", "sicav")):
        return "fund-vehicle"
    # Entity is above the target (its parent/owner).
    if (any(k in t for k in ("parent of", "owner of", "owns the target",
                             "ultimate parent", "majority shareholder of",
                             "controls ", "holding company above",
                             "acquired the target", "holds the target"))
            or f"owns {tgt}" in t or f"parent of {tgt}" in t
            or f"holds {tgt}" in t or f"owner of {tgt}" in t):
        return "parent"
    if any(k in t for k in ("sister", "affiliate", "sibling",
                            "under the same parent", "fellow subsidiary")):
        return "sister"
    # Default: a company or brand below the target (the common case).
    return "subsidiary"


def resolve_candidates(result: dict, scope: Scope,
                       passive: bool) -> tuple[list[dict], list[dict]]:
    """Resolve every proposed candidate domain against the target's Entra tenant
    and set a verdict. Also build the corporate map (subsidiaries and related
    entities) from the accepted entity records. Returns (candidate_domains,
    subsidiaries). The one network call is the Microsoft OpenID endpoint, which
    is passive-safe, so this runs in every mode."""
    accepted = result["accepted"]
    target_tid = _target_tenant_id(accepted)
    known = {d.strip().lower() for d in scope.all_domains if d.strip()}

    # The pool: the agent's explicit candidate_domain records, plus a domain
    # mined from any related entity record that embedded one in its signal.
    pool: list[tuple[str, dict]] = []
    for c in result.get("candidates", []):
        dom = _norm_domain(str(c.get("value", "")))
        if dom:
            pool.append((dom, c))
    subsidiaries: list[dict] = []
    for e in accepted:
        if str(e.get("type", "")).lower() != "entity" or _is_target_entity(e, scope):
            continue
        sub = {
            "name":       str(e.get("value", "")),
            "state":      (e.get("state", {}) or {}).get("value")
                          if isinstance(e.get("state"), dict) else e.get("state"),
            "canonical_id": e.get("canonical_id"),
            # Context so the corporate map reads, not a bare name list: a one-line
            # what-it-is, the sector, and where it sits. Supplied by the agent per
            # related entity, empty string when it did not establish one.
            "summary":    _clean(str(e.get("summary", ""))),
            "sector":     _clean(str(e.get("sector", ""))),
            "jurisdiction": _clean(str(e.get("jurisdiction", ""))),
            # Relationship direction (parent/subsidiary/sister/fund-vehicle) so the
            # corporate map does not lump owners and fund products in with brands.
            "relation":   _relation(str(e.get("relation", "")),
                                    str(e.get("ownership_signal", "")),
                                    str(e.get("summary", "")), scope),
            "ownership_signal": _clean(str(e.get("ownership_signal", ""))),
            "confidence": e.get("confidence"),
            "source":     _clean(str(e.get("source", ""))),
            "as_of":      e.get("as_of") or _today(),
        }
        subsidiaries.append(sub)
        dom = _extract_domain(f"{e.get('ownership_signal','')} {e.get('value','')}")
        if dom:
            # Tag the mined entity so its candidate domain carries the relationship
            # too (a parent's domain reads as owner, not a bare third party).
            e = dict(e)
            e["relation"] = sub["relation"]
            pool.append((dom, e))

    out: list[dict] = []
    owned_roots: list[dict] = []
    seen: set[str] = set()
    looked_up = 0
    for dom, rec in pool:
        if dom in seen or dom in known:
            continue
        seen.add(dom)

        cand_tid = None
        if looked_up < _RESOLVER_MAX:
            cand_tid = _resolve_tenant_guid(dom)
            looked_up += 1

        if target_tid and cand_tid and cand_tid == target_tid:
            verdict, sig_type, conf = "owned", "shared_entra_tenant", "verified"
            signal = (f"resolves to the same Microsoft Entra tenant {target_tid} "
                      f"as the target, common administrative ownership")
        elif target_tid and cand_tid and cand_tid != target_tid:
            verdict, sig_type, conf = "third_party", "different_entra_tenant", "inferred"
            signal = (f"resolves to a different Entra tenant {cand_tid}, not the "
                      f"target tenant {target_tid}")
        else:
            verdict, sig_type, conf = "pending", "name_association", "lead"
            signal = (_clean(str(rec.get("ownership_signal", "")))
                      or f"name or brand association to {scope.target.name}, no "
                         f"infrastructure tie confirmed, needs operator review")

        out.append({
            "domain":          dom,
            "ownership_signal": _clean(signal),
            "signal_type":     sig_type,
            "confidence":      conf,
            "verdict":         verdict,
            # The entity's relationship, so a parent/owner domain on a separate
            # tenant is not read as a bare third party. Empty for a plain
            # candidate that was not mined from a related entity.
            "relation":        str(rec.get("relation", "") or ""),
            "source":          _clean(str(rec.get("source", ""))),
            "as_of":           _today(),
        })

        # Owned candidates feed back as attribution-only roots so Layer 2 can
        # discover them. They are NEVER in-scope-confirmed: the operator still
        # has to promote them against the signed authorization before any active
        # testing, exactly like every other spread-to asset.
        if verdict == "owned":
            owned_roots.append({
                "type":  "apex",
                "value": dom,
                "canonical_id": rec.get("canonical_id") or f"candidate:{dom}",
                "scope": "attribution-only",
                "ownership_signal": _clean(signal),
                "confidence": "verified",
                "source": _clean(str(rec.get("source", ""))
                                 or "subsidiary resolver, shared Entra tenant"),
                "as_of": _today(),
                "resolver_note": "owned candidate promoted to attribution-only "
                                 "root by the subsidiary resolver",
            })

    # Append the owned roots to accepted so they reach the signal stream and the
    # corporate map, de-duplicated against domains already present.
    present = {str(r.get("value", "")).lower() for r in accepted}
    for root in owned_roots:
        if root["value"].lower() not in present:
            accepted.append(root)
            present.add(root["value"].lower())

    return out, subsidiaries


# ---------------------------------------------------------------------------
# Signal + dossier emit
# ---------------------------------------------------------------------------

def _dedup_id(rec: dict) -> str:
    key = f"footprint|{rec.get('type')}|{rec.get('value')}".lower()
    return hashlib.sha1(key.encode()).hexdigest()


def _severity(rec: dict) -> str:
    if rec.get("halt_reason"):
        return "SEV1"
    t = str(rec.get("type", "")).lower()
    if t in ("entra_tenant", "domain", "apex", "netblock", "asn", "ip"):
        return "SEV4"
    return "SEV5"


def _entities(rec: dict) -> list[dict]:
    t = str(rec.get("type", "")).lower()
    emap = {"domain": "domain", "apex": "domain", "ip": "ip",
            "entra_tenant": "asset", "asn": "asset", "netblock": "asset",
            "entity": "asset", "person": "asset", "code_org": "asset",
            "cloud_account": "asset", "mobile_app": "asset"}
    return [{"type": emap.get(t, "asset"), "value": str(rec.get("value", ""))}]


def _to_signal(rec: dict, report_ref: str, first_seen: str) -> dict:
    state = rec.get("state")
    state_str = state.get("value") if isinstance(state, dict) else state
    desc = []
    if rec.get("confidence"):
        desc.append(f"confidence {rec['confidence']}")
    if rec.get("ownership_signal"):
        desc.append(f"ownership signal {rec['ownership_signal']}")
    if state_str:
        desc.append(f"state {state_str}")
    if rec.get("halt_reason"):
        desc.append(rec["halt_reason"])
    title = f"{rec.get('type')} {rec.get('value')}"
    return {
        "dedup_id":     _dedup_id(rec),
        "title":        _clean(title),
        "description":  _clean(". ".join(desc)),
        "severity":     _severity(rec),
        "source":       "Continuous EAS / layer0 footprint",
        "source_class": "company_footprint",
        "entities":     _entities(rec),
        "evidence": {
            "scope":            rec.get("scope"),
            "state":            state_str,
            "as_of":            rec.get("as_of"),
            "canonical_id":     rec.get("canonical_id"),
            "ownership_signal": _clean(str(rec.get("ownership_signal", ""))),
            "confidence":       rec.get("confidence"),
            "record_source":    _clean(str(rec.get("source", ""))),
        },
        "first_seen": first_seen,
        "report_ref": report_ref,
    }


def write_outputs(outdir: Path, signals_out: Path, result: dict,
                  scope: Scope, candidate_domains: list[dict] | None = None,
                  subsidiaries: list[dict] | None = None) -> dict:
    """Persist the gate's decision. Accepted records become signals (with a
    first-seen sidecar, like the other watchers). Quarantined and halted records
    are written to their own files for the operator, never into the signal
    stream. The halt list, if any, is the escalation."""
    now = _utcnow()
    report_ref = f"{scope.target.name}:{now}"

    cache_path = signals_out.with_suffix(signals_out.suffix + ".seen.json")
    try:
        cache = json.loads(cache_path.read_text())
    except Exception:
        cache = {}

    signals_out.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for rec in result["accepted"]:
        sig = _to_signal(rec, report_ref, cache.get(rec.get("value", ""), {})
                         .get("first_seen", now))
        lines.append(sig)
        cache[rec.get("value", "")] = {"first_seen":
                                       cache.get(rec.get("value", ""), {}).get("first_seen", now),
                                       "last_seen": now}
    with signals_out.open("w") as fh:
        for ln in lines:
            fh.write(json.dumps(ln) + "\n")
    cache_path.write_text(json.dumps(cache, indent=2))

    outdir.mkdir(parents=True, exist_ok=True)
    # Accepted records in their native contract shape (type, canonical_id, scope,
    # state, ownership_signal, confidence, source, as_of), so the console can
    # render the dossier faithfully. The signals file carries the same data in
    # the engine's dedup schema for later layers, this one is the human view.
    (outdir / "accepted.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in result["accepted"]))
    (outdir / "quarantine.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in result["quarantined"]))
    (outdir / "dropped.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in result["dropped"]))

    # The subsidiary resolver's outputs, in the locked seed-output shape the
    # Context dossier reads. Written every run, empty when there is nothing, so
    # the rows show an honest None rather than a missing field.
    candidate_domains = candidate_domains or []
    subsidiaries = subsidiaries or []
    (outdir / "candidate_domains.jsonl").write_text(
        "".join(json.dumps(c) + "\n" for c in candidate_domains))
    (outdir / "subsidiaries.jsonl").write_text(
        "".join(json.dumps(s) + "\n" for s in subsidiaries))
    # The structured company profile, written every run (empty object when the
    # agent emitted none) so the Context dossier reads scalar facts from a known
    # shape instead of parsing them out of the coverage prose.
    (outdir / "company_profile.json").write_text(
        json.dumps(result.get("profile") or {}, indent=2))
    # The integrity schema files, written every run in the locked shape. An empty
    # or unscreened result is a real state the Context dossier shows honestly:
    # unscreened is not clear, and clear must come from a screen that actually ran.
    (outdir / "sanctions_screen.json").write_text(
        json.dumps(result.get("sanctions_screen") or {"status": "unscreened"},
                   indent=2))
    (outdir / "investigative.jsonl").write_text(
        "".join(json.dumps(i) + "\n" for i in (result.get("investigative") or [])))
    (outdir / "ruled_out.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in (result.get("ruled_out") or [])))

    halt_file = outdir / "HALT-sanctions.json"
    if result["halted"]:
        halt_file.write_text(json.dumps({
            "ts": now,
            "target": scope.target.name,
            "note": _clean("Layer 0 halted this thread. A sanctions, OFAC, embargo "
                           "or PEP signal was surfaced. Operator decides whether and "
                           "how the engagement proceeds."),
            "records": result["halted"],
        }, indent=2))
    elif halt_file.exists():
        halt_file.unlink()

    return {
        "signals_out":  str(signals_out),
        "accepted":     len(result["accepted"]),
        "quarantined":  len(result["quarantined"]),
        "dropped":      len(result["dropped"]),
        "halted":       len(result["halted"]),
        "candidates":   len(candidate_domains),
        "subsidiaries": len(subsidiaries),
        "candidates_owned": sum(1 for c in candidate_domains
                                if c.get("verdict") == "owned"),
    }


# ---------------------------------------------------------------------------
# Cycle
# ---------------------------------------------------------------------------

def _write_status(outdir: Path, status: dict) -> None:
    """Record the run's progress to outdir/run-status.json so a debug view can
    always answer 'where is it, and did it fail'. Best-effort, never fatal."""
    try:
        outdir.mkdir(parents=True, exist_ok=True)
        (outdir / "run-status.json").write_text(json.dumps(status, indent=2))
    except Exception:
        pass


def run_cycle(scope_path: Path, skip_agent: bool) -> dict:
    scope = load_scope(scope_path)
    slug = _slug(scope.target.name)
    paths = engagement_paths(scope.target.name)
    outdir = paths["base"] / "layer0"
    raw_file = outdir / "footprint-raw.jsonl"
    signals_out = paths["signals"] / f"{slug}-footprint.jsonl"
    outdir.mkdir(parents=True, exist_ok=True)

    status = {
        "started_at": _utcnow(),
        "target": scope.target.name,
        "slug": slug,
        "mode": scope.mode,
        "agent_invoked": not skip_agent,
        "stage": "starting",
        "state": "running",
    }
    _write_status(outdir, status)

    # Warn once on Slack if this run outlives its expected budget; cancelled the
    # moment it ends, so a run that finishes in time never warns.
    watchdog = _start_overrun_watchdog(scope.target.name, slug)

    try:
        if not skip_agent:
            status["stage"] = "agent"
            _write_status(outdir, status)
            prompt = build_prompt(scope, outdir, raw_file)
            invoke_agent(prompt, outdir)

        status["stage"] = "validate"
        _write_status(outdir, status)
        records = read_agent_records(raw_file)
        result = validate(records, scope)

        status["stage"] = "resolve"
        _write_status(outdir, status)
        candidate_domains, subsidiaries = resolve_candidates(
            result, scope, passive=(scope.mode == "passive"))

        summary = write_outputs(outdir, signals_out, result, scope,
                                candidate_domains, subsidiaries)
        summary.update({
            "target": scope.target.name,
            "slug": slug,
            "mode": scope.mode,
            "agent_invoked": not skip_agent,
            "raw_records": len(records),
            "raw_file": str(raw_file),
        })
        status.update({
            "stage": "done",
            "state": "ok",
            "ended_at": _utcnow(),
            "raw_records": len(records),
            "accepted": summary["accepted"],
            "quarantined": summary["quarantined"],
            "dropped": summary["dropped"],
            "halted": summary["halted"],
            "candidates": summary["candidates"],
            "subsidiaries": summary["subsidiaries"],
            "candidates_owned": summary["candidates_owned"],
        })
        _write_status(outdir, status)
        halt = (f"HALT: {summary['halted']} sanctions/PEP signal(s)."
                if summary["halted"] else "")
        fallback = (
            f":satellite: Layer 0 complete for {scope.target.name}. "
            f"Accepted {summary['accepted']}, candidates {summary['candidates']} "
            f"({summary['candidates_owned']} owned), subsidiaries "
            f"{summary['subsidiaries']}, quarantined {summary['quarantined']}, "
            f"dropped {summary['dropped']}."
            + (f" {halt}" if halt else "")
            + f" Context dossier ready: {_context_url(slug)}")
        _slack_notify(
            fallback,
            blocks=_finish_blocks(scope.target.name, slug, summary, halt))
        return summary
    except Exception as exc:  # noqa: BLE001 (notify on any failure, then re-raise)
        status.update({
            "stage": status.get("stage", "?"),
            "state": "failed",
            "ended_at": _utcnow(),
            "error_type": type(exc).__name__,
            "error": _clean(str(exc))[:1500],
        })
        _write_status(outdir, status)
        stage = status.get("stage", "?")
        _slack_notify(
            f":rotating_light: Layer 0 FAILED for {scope.target.name} at stage "
            f"{stage}: {type(exc).__name__}. Check the run debug: "
            f"{_panel_base()}/l0-debug?e={_client_id(slug)}",
            blocks=[
                {"type": "header",
                 "text": {"type": "plain_text", "text": "Layer 0 failed",
                          "emoji": True}},
                {"type": "section",
                 "text": {"type": "mrkdwn",
                          "text": f":rotating_light: *Client:* {scope.target.name}\n"
                                  f"Stopped at stage *{stage}*  ·  "
                                  f"`{type(exc).__name__}`"}},
                {"type": "section",
                 "text": {"type": "mrkdwn",
                          "text": f"<{_panel_base()}/l0-debug?e={_client_id(slug)}"
                                  f"|Open the run debug>"}},
                {"type": "divider"},
            ])
        raise
    finally:
        if watchdog is not None:
            watchdog.cancel()


def main() -> int:
    ap = argparse.ArgumentParser(description="Layer 0 company footprint, agent-backed.")
    ap.add_argument("--scope", required=True, type=Path, help="scope yaml file")
    ap.add_argument("--once", action="store_true",
                    help="run a single cycle and exit (for systemd oneshot)")
    ap.add_argument("--skip-agent", action="store_true",
                    help="do not invoke the agent, only validate an existing "
                         "agent output (offline test of the gate)")
    args = ap.parse_args()

    if not args.scope.is_file():
        print(f"[!] scope file not found: {args.scope}", file=sys.stderr)
        return 2

    summary = run_cycle(args.scope, skip_agent=args.skip_agent)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
