#!/usr/bin/env python3
"""
tools/dmarc_watch.py. Run the email authentication posture pipeline on a
cadence, standalone. The DMARC/SPF/DKIM/MX sibling of tools/lookalike_watch.py.

WHY A SEPARATE ENTRY POINT
--------------------------
Email authentication posture is a second ingest-ready signal for JOES AIR,
shaped exactly like the lookalike feed. It runs the email_dns_security producer
against a scope file, with no database required, and writes a sanitised signal
file. A missing or weak DMARC policy is the most common phishing initial access
vector, and every client EAS reviewed so far carried one (weak or missing DMARC, often with missing SPF and MX records, sometimes tied to an active phishing campaign). This watcher turns that same
check into a live, repeatable feed.

    python tools/dmarc_watch.py --scope scopes/acme.yaml --once
    python tools/dmarc_watch.py --scope scopes/acme.yaml --mode semi \
        --once --signals-out outputs/signals/acme-dmarc.jsonl

The signal file is metadata only. Each line carries the domain, its named severity
value, the posture evidence (policy, SPF qualifier, DKIM, MX), what changed this
cycle, and when we first saw it. No raw mail, no credentials. It does not POST
anywhere: the operator drives the actual ingest when ready.

CADENCE
-------
--once runs a single cycle and exits, which is what a weekly cron or systemd
timer wants:

    # crontab, every Monday 06:10
    10 6 * * 1 cd /path/to/SurfaceScanner && \
        .venv/bin/python tools/dmarc_watch.py --scope scopes/acme.yaml --once

The delta (what regressed since last run, first_seen) is kept in a small JSON
cache beside the signal file, so the weekly run reports changes without a
pipeline database.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import load_config                 # noqa: E402
from layer2_5 import email_dns_security             # noqa: E402
from scope_parser import load_scope                 # noqa: E402


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_cache(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def _save_cache(path: Path, cache: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cache, indent=2))


def _dedup_id(domain: str) -> str:
    """Stable id for idempotent ingest: the portal dedupes on this across deltas."""
    return hashlib.sha1(f"email_auth_posture|{domain}".encode()).hexdigest()


def _plain(s: str) -> str:
    """House style for emitted text: no em dashes, no en dashes, no semicolons.
    The producer (email_dns_security) writes issue strings with em dashes, so any
    text folded in from it is normalised here before it leaves in a signal."""
    return (s.replace(" — ", ", ").replace("—", ", ")
             .replace(" – ", ", ").replace("–", "-")
             .replace("; ", ". ").replace(";", ".")).strip()


# --------------------------------------------------------------------------- #
# posture model
# --------------------------------------------------------------------------- #
# The producer emits four findings per domain (dmarc_record, spf_record,
# mx_records, dkim_record), all keyed on the domain in `value`. We fold them
# into one posture row per domain, then watch the posture for regressions.

# Producer severity word -> JOES AIR named level. The platform uses named levels
# (Critical, High, Medium, Low, Informational), not SEVn tokens. Critical is
# reserved for a confirmed live attack (for example a working phishing clone), so
# an email authentication gap caps at High: it enables spoofing but still needs a
# recipient to act. This matches how the reviewed client reports rated it.
_SEV_FROM_SEVERITY = {
    "critical": "High",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "info":     "Informational",
}

# More severe first, for escalation comparisons.
_SEV_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]


def _spf_qualifier(record: str | None) -> str | None:
    """The 'all' mechanism qualifier, the part that decides enforcement."""
    if not record:
        return None
    m = re.search(r"([-~?+])all\b", record)
    return (m.group(1) + "all") if m else None


# The posture flags we watch on each domain. A false -> true transition on any
# of these is a REGRESSION trigger, even on a domain we have already seen. This
# is what turns a static scan into live monitoring: a domain that drops its
# DMARC record, weakens p=reject to p=none, or loses SPF re-fires at the new,
# higher severity.
_SPOOFABLE_FLAGS = (
    "no_dmarc",            # no _dmarc TXT at all
    "dmarc_monitor_only",  # p=none
    "dmarc_partial",       # p=quarantine or pct<100
    "no_spf",              # no v=spf1 TXT
    "spf_weak",            # ?all / ~all / +all
    "no_dkim",             # no DKIM selector found
    "no_aggregate_report", # no rua tag, blind to abuse
)

_TRIGGER_LABEL = {
    "new":                 "newly observed spoofable domain",
    "no_dmarc":            "DMARC record removed or never present",
    "dmarc_monitor_only":  "DMARC weakened to p=none",
    "dmarc_partial":       "DMARC only partially enforced",
    "no_spf":              "SPF record removed or never present",
    "spf_weak":            "SPF enforcement weakened",
    "no_dkim":             "no DKIM signing found",
    "no_aggregate_report": "DMARC aggregate reporting turned off",
    "policy_downgrade":    "DMARC policy downgraded",
    "escalated":           "severity escalated",
}

_POLICY_RANK = {"reject": 2, "quarantine": 1, "none": 0, None: -1}


def _posture_severity(*, dmarc_found: bool, policy, pct, has_rua: bool,
                      spf_found: bool, spf_q, dkim_found: bool) -> str:
    """Lowest defensible named severity for the actual email-auth posture.
    Mirrors tools/surface_report._dmarc_severity, in named levels.

    The label must match the CVSS band. Email spoofing computes to 4.3 (Medium)
    under CVSS 3.1 because the recipient must act (UI:R) and only integrity is
    affected at a low level (I:L), so this class cannot reach High. Medium is the
    ceiling, and an enforcing policy with only a cosmetic gap is Informational.

      Medium         spoofable: no DMARC, p=none, p=quarantine, or pct<100
      Informational  enforcing policy (p=reject): any remaining gap is cosmetic
    """
    policy = (policy or "").lower()
    if policy == "reject" and (pct is None or pct == 100):
        return "Informational"
    return "Medium"


def _fold_posture(domain: str, records: dict) -> dict:
    """Collapse the four producer findings for one domain into a posture row."""
    dmarc = records.get("dmarc_record", {})
    spf   = records.get("spf_record", {})
    mx    = records.get("mx_records", {})
    dkim  = records.get("dkim_record", {})

    policy = dmarc.get("policy") if dmarc.get("found") else None
    pct    = dmarc.get("pct", 100)
    has_rua = bool(re.search(r"rua=", dmarc.get("record") or "")) if dmarc.get("found") else False
    spf_q  = _spf_qualifier(spf.get("record"))

    flags = {
        "no_dmarc":            not dmarc.get("found"),
        "dmarc_monitor_only":  policy == "none",
        "dmarc_partial":       policy == "quarantine" or (dmarc.get("found") and pct < 100),
        "no_spf":              not spf.get("found"),
        "spf_weak":            spf_q in ("?all", "~all", "+all"),
        "no_dkim":             not dkim.get("found"),
        "no_aggregate_report": bool(dmarc.get("found")) and not has_rua,
    }

    # Worst producer severity across the records, kept for reference only.
    sev_words = [r.get("severity", "info") for r in records.values()]
    worst = max(sev_words, key=lambda s: email_dns_security._SEVERITY_RANK.get(s, 0))

    # The platform severity is posture-aware, not the worst single producer. DMARC
    # is one control of three, so a missing DMARC record on a domain that still
    # hard-fails SPF and signs with DKIM is not the same risk as no protection at
    # all. This mirrors surface_report._dmarc_severity so the panel and the early
    # alert agree on the band.
    sev_platform = _posture_severity(
        dmarc_found=bool(dmarc.get("found")), policy=policy, pct=pct,
        has_rua=has_rua, spf_found=bool(spf.get("found")),
        spf_q=spf_q, dkim_found=bool(dkim.get("found")))

    return {
        "domain":        domain,
        "dmarc_found":   bool(dmarc.get("found")),
        "dmarc_policy":  policy,
        "dmarc_pct":     pct,
        "dmarc_rua":     has_rua,
        "spf_found":     bool(spf.get("found")),
        "spf_qualifier": spf_q,
        "dkim_found":    bool(dkim.get("found")),
        "mx":            mx.get("mx") or [],
        "severity_word": worst,
        "sev_platform":  sev_platform,
        "flags":         flags,
        "issues":        (dmarc.get("issues") or []) + (spf.get("issues") or [])
                         + ([dmarc["issue"]] if dmarc.get("issue") else [])
                         + ([spf["issue"]] if spf.get("issue") else []),
    }


def _sev_rank(sev: str) -> int:
    """Higher number = more severe. Unknown labels rank lowest."""
    try:
        return len(_SEV_ORDER) - _SEV_ORDER.index(sev)
    except ValueError:
        return 0


def _triggers(prev: dict | None, posture: dict) -> list[str]:
    """What regressed since last cycle. Empty list means no trigger, no signal."""
    flags = posture["flags"]
    if prev is None:
        # first sight: only a signal if the domain is actually spoofable
        return ["new"] if any(flags.values()) else []

    prev_flags = (prev.get("flags") or {})
    out = [f for f in _SPOOFABLE_FLAGS if flags.get(f) and not prev_flags.get(f)]

    # explicit policy downgrade (reject -> quarantine -> none), a regression even
    # if the coarse flags did not flip
    prev_pol = prev.get("dmarc_policy")
    if _POLICY_RANK.get(posture["dmarc_policy"], -1) < _POLICY_RANK.get(prev_pol, -1):
        out.append("policy_downgrade")

    if _sev_rank(posture["sev_platform"]) > _sev_rank(prev.get("sev") or "Informational"):
        out.append("escalated")
    return list(dict.fromkeys(out))


def _description(p: dict, triggers: list[str]) -> str:
    reason = ", ".join(_TRIGGER_LABEL.get(t, t) for t in triggers)
    bits = []
    if not p["dmarc_found"]:
        bits.append("no DMARC record published")
    else:
        bits.append(f"DMARC p={p['dmarc_policy']}"
                    + ("" if p["dmarc_pct"] == 100 else f" pct={p['dmarc_pct']}")
                    + ("" if p["dmarc_rua"] else ", no aggregate reporting"))
    if not p["spf_found"]:
        bits.append("no SPF record")
    elif p["spf_qualifier"]:
        bits.append(f"SPF {p['spf_qualifier']}")
    if not p["dkim_found"]:
        bits.append("no DKIM signing found")
    if not p["mx"]:
        bits.append("no MX record")
    posture = ". ".join(bits) if bits else "email authentication posture reviewed"
    return _plain((f"Trigger: {reason}. " if reason else "") + posture)


def _entities(domain: str, p: dict) -> list[dict]:
    ents = [{"type": "domain", "value": domain}]
    for mx in p.get("mx") or []:
        parts = str(mx).split()
        host = (parts[-1].rstrip(".") if parts else "")
        if host:
            ents.append({"type": "mx_host", "value": host})
    return ents


def _sanitise(p: dict, first_seen: str, report_ref: str, triggers: list[str]) -> dict:
    """
    One posture row -> one sanitised JOES AIR signal, shaped to the same ingest
    contract as the lookalike feed: dedup id, title, description, severity,
    source, entity list, evidence. `triggers` records what regressed this cycle.
    """
    domain = p["domain"]
    title = ("No DMARC policy" if p["flags"]["no_dmarc"]
             else f"Weak DMARC policy (p={p['dmarc_policy']})" if p["flags"]["dmarc_monitor_only"]
             else "Weak email authentication posture")
    return {
        "dedup_id":     _dedup_id(domain),           # idempotent alias, repeat-safe
        "title":        f"{title} on {domain}",
        "description":  _description(p, triggers),
        "severity":     p["sev_platform"],
        "source":       "Continuous EAS / email_dns_security",
        "source_class": "email_auth_posture",
        "entities":     _entities(domain, p),
        "evidence": {
            "triggers":       triggers,
            "dmarc_found":    p["dmarc_found"],
            "dmarc_policy":   p["dmarc_policy"],
            "dmarc_pct":      p["dmarc_pct"],
            "dmarc_rua":      p["dmarc_rua"],
            "spf_found":      p["spf_found"],
            "spf_qualifier":  p["spf_qualifier"],
            "dkim_found":     p["dkim_found"],
            "mx":             [m for m in (p["mx"] or []) if str(m).strip()],
            "issues":         [_plain(str(i)) for i in p["issues"]],
        },
        "first_seen":  first_seen,
        "report_ref":  report_ref,
    }


async def _cycle(scope_path: Path, mode: str | None, signals_out: Path | None = None) -> dict:
    config = load_config()
    scope = load_scope(scope_path)
    if mode:
        scope.mode = mode

    config.use_engagement(scope.target.name)
    if signals_out is None:
        signals_out = config.paths["signals"] / f"{scope_path.stem}-dmarc.jsonl"

    try:
        res = await email_dns_security.run(scope, config, db=None)
    except Exception as exc:
        print(f"[!] email_dns_security raised: {exc}", file=sys.stderr)
        res = {"findings": []}

    # fold producer findings into one posture row per domain
    by_domain: dict[str, dict] = {}
    for f in res.get("findings", []):
        dom = f.get("value")
        if not dom:
            continue
        by_domain.setdefault(dom, {})[f.get("type")] = f.get("data", {})
    postures = {d: _fold_posture(d, recs) for d, recs in by_domain.items()}

    cache_path = signals_out.with_suffix(signals_out.suffix + ".seen.json")
    cache = _load_cache(cache_path)
    now = _utcnow()
    report_ref = f"{scope.target.name}:{now}"

    lines: list[dict] = []
    tracked = 0
    for domain, p in postures.items():
        tracked += 1
        prev = cache.get(domain)
        fired = _triggers(prev, p)
        spoofable = any(p["flags"].values())
        first_seen = (prev or {}).get("first_seen", now)

        # A fully locked-down domain (DMARC reject, SPF -all, DKIM present) is
        # inventory, not a finding, so it is cached but emits no signal. Emit
        # only when the domain is spoofable AND something regressed this cycle.
        if fired and spoofable:
            lines.append(_sanitise(p, first_seen, report_ref, fired))

        cache[domain] = {
            "first_seen":   first_seen,
            "last_seen":    now,
            "sev":          p["sev_platform"],
            "dmarc_policy": p["dmarc_policy"],
            "flags":        p["flags"],
        }

    signals_out.parent.mkdir(parents=True, exist_ok=True)
    with signals_out.open("w") as fh:
        for ln in lines:
            fh.write(json.dumps(ln) + "\n")
    _save_cache(cache_path, cache)

    by_sev: dict[str, int] = {}
    for ln in lines:
        by_sev[ln["severity"]] = by_sev.get(ln["severity"], 0) + 1

    return {
        "target": scope.target.name,
        "mode": scope.mode,
        "tracked": tracked,
        "triggered": len(lines),
        "by_sev": by_sev,
        "signals_out": str(signals_out),
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Run the email authentication posture pipeline on a cadence.")
    ap.add_argument("--scope", required=True, type=Path, help="scope yaml file")
    ap.add_argument("--mode", choices=["passive", "semi", "active"], default=None,
                    help="override the scope mode (DNS checks run in every mode)")
    ap.add_argument("--signals-out", type=Path, default=None,
                    help="JSONL signal file (default: DATA/engagements/<client>/signals/<scope>-dmarc.jsonl)")
    ap.add_argument("--once", action="store_true",
                    help="run a single cycle and exit (for cron/systemd timers)")
    args = ap.parse_args()

    if not args.scope.is_file():
        print(f"[!] scope file not found: {args.scope}", file=sys.stderr)
        return 2

    summary = asyncio.run(_cycle(args.scope, args.mode, args.signals_out))
    print(json.dumps(summary, indent=2))
    if not args.once:
        print("[i] single-shot run complete. Schedule with cron or systemd for a "
              "cadence, see the module docstring.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
