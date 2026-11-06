#!/usr/bin/env python3
"""
tools/lookalike_watch.py. Run the lookalike pipeline on a cadence, standalone.

WHY A SEPARATE ENTRY POINT
--------------------------
The agreed first point of contact with JOES AIR is lookalike data: produce it
locally, then test how the platform ingests it. This runs the two lookalike
producers (dnstwist permutations + CT/NRD discovery) end to end against a scope
file, with no database required, and writes a sanitised, ingest-ready signal
file. It is the artifact for the ingest test.

    python tools/lookalike_watch.py --scope scopes/test.yaml --once
    python tools/lookalike_watch.py --scope scopes/acme.yaml --mode semi \
        --once --signals-out outputs/signals/acme.jsonl

The signal file is metadata only. Each line carries the lookalike domain, its
SEV1 to SEV5 value, the evidence flags, and when we first saw it. No raw page
bytes, no screenshots, no AI, nothing confidential. It does not POST anywhere:
the operator drives the actual ingest when ready.

CADENCE
-------
--once runs a single cycle and exits, which is what a weekly cron or systemd
timer wants:

    # crontab, every Monday 06:00
    0 6 * * 1 cd /path/to/SurfaceScanner && \
        .venv/bin/python tools/lookalike_watch.py --scope scopes/acme.yaml --once

The delta (new_since_last_run / first_seen) is kept in a small JSON cache beside
the signal file, so the weekly run reports what changed without needing the
pipeline database.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import load_config                 # noqa: E402
from layer1 import brand_protection, newly_registered_domains  # noqa: E402
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


def _dedup_id(asset: str) -> str:
    """Stable id for idempotent ingest: the portal dedupes on this across deltas."""
    return hashlib.sha1(f"lookalike_domain|{asset}".encode()).hexdigest()


def _description(d: dict) -> str:
    """Human-readable description from the finding, no raw page content."""
    parts = list(d.get("reasons") or [])
    if d.get("registrar"):
        parts.append(f"registrar {d['registrar']}")
    if d.get("created"):
        parts.append(f"registered {d['created']}")
    if d.get("serves_login"):
        parts.append("serves a login page")
    if d.get("visual_match"):
        parts.append("page visually matches the brand")
    if d.get("favicon_match"):
        parts.append("favicon matches the brand")
    return ". ".join(parts) if parts else "registered lookalike domain"


def _entities(asset: str, d: dict) -> list[dict]:
    """The entity list the portal maps on: the domain plus any resolved IPs."""
    ents = [{"type": "domain", "value": asset}]
    for ip in d.get("dns_a") or []:
        ents.append({"type": "ip", "value": ip})
    return ents


# The state flags we watch on each candidate. A false -> true transition on any
# of these is a trigger, even on a domain we have already seen. This is what turns
# a static pool into live monitoring: the same name gaining mail, a login page, or
# a visual clone re-fires at the new, higher severity.
_STATE_FLAGS = ("resolves", "mail", "serves_login", "visual_match", "favicon_match")

_TRIGGER_LABEL = {
    "new":           "newly registered",
    "resolves":      "started resolving",
    "mail":          "gained mail capability",
    "serves_login":  "now serves a login page",
    "visual_match":  "now visually matches the brand",
    "favicon_match": "now reuses the brand favicon",
    "new_host":      "resolved to a new host",
    "escalated":     "severity escalated",
}


def _state_of(d: dict) -> dict:
    """The watched state of one finding, as plain booleans."""
    return {
        "resolves":      bool(d.get("dns_a")),
        "mail":          bool(d.get("mail_capable")),
        "serves_login":  bool(d.get("serves_login")),
        "visual_match":  bool(d.get("visual_match")),
        "favicon_match": bool(d.get("favicon_match")),
    }


def _sev_rank(sev: str) -> int:
    try:
        return 6 - int(str(sev).replace("SEV", ""))   # SEV1 highest -> 5
    except Exception:
        return 0


def _triggers(prev: dict | None, cur_state: dict, prev_sev: str, cur_sev: str) -> list[str]:
    """What changed since last cycle. Empty list means no trigger, so no signal."""
    if prev is None:
        return ["new"]
    out = [f for f in _STATE_FLAGS
           if cur_state.get(f) and not (prev.get("state") or {}).get(f)]
    if _sev_rank(cur_sev) > _sev_rank(prev_sev):
        out.append("escalated")
    return out


def _sanitise(f: dict, first_seen: str, report_ref: str, triggers: list[str]) -> dict:
    """
    One finding -> one sanitised JOES AIR signal, shaped to the documented ingest
    contract: dedup id, title, description, severity, source name, entity list,
    and evidence. Only finding metadata crosses, no raw page content, no
    credentials, nothing client side. `triggers` records what changed this cycle.
    """
    d = f.get("data", {})
    asset = f.get("value")
    reason = ", ".join(_TRIGGER_LABEL.get(t, t) for t in triggers)
    return {
        "dedup_id":     _dedup_id(asset),          # idempotent alias, repeat-safe
        "title":        d.get("issue") or f"Lookalike domain {asset}",
        "description":  (f"Trigger: {reason}. " if reason else "") + _description(d),
        "severity":     d.get("sev_platform", "SEV5"),
        "source":       "Continuous EAS / brand_protection",
        "source_class": "lookalike_domain",
        "entities":     _entities(asset, d),
        "evidence": {
            "triggers":      triggers,
            "fuzzer":        d.get("fuzzer"),
            "origin_domain": d.get("origin_domain"),
            "mail_capable":  d.get("mail_capable", False),
            "serves_login":  d.get("serves_login", False),
            "favicon_match": d.get("favicon_match", False),
            "visual_match":  d.get("visual_match", False),
            "registrar":     d.get("registrar"),
            "created":       d.get("created"),
            "age_days":      d.get("age_days"),
            "cluster_id":    d.get("cluster_id"),
            "discovered_by": d.get("source"),
        },
        "first_seen":  first_seen,
        "report_ref":  report_ref,
    }


async def _cycle(scope_path: Path, mode: str | None, signals_out: Path | None = None) -> dict:
    config = load_config()
    scope = load_scope(scope_path)
    if mode:
        scope.mode = mode

    # Isolate this client's signals under DATA/engagements/<slug>/signals, so the
    # code tree never holds engagement output and clients never share state.
    config.use_engagement(scope.target.name)
    if signals_out is None:
        signals_out = config.paths["signals"] / f"{scope_path.stem}.jsonl"

    results = []
    for mod in (brand_protection, newly_registered_domains):
        try:
            results.append(await mod.run(scope, config, db=None))
        except Exception as exc:   # modules are not supposed to raise, belt and braces
            print(f"[!] {mod.__name__} raised: {exc}", file=sys.stderr)

    findings: list[dict] = []
    for r in results:
        findings += r.get("findings", [])

    # Per-candidate state cache (no DB in standalone mode). Each entry holds the
    # first_seen, last_seen, last emitted severity, and the watched state, so a
    # later state change on a known domain still fires.
    cache_path = signals_out.with_suffix(signals_out.suffix + ".seen.json")
    cache = _load_cache(cache_path)
    now = _utcnow()
    report_ref = f"{scope.target.name}:{now}"

    lines: list[dict] = []          # only triggered signals go out this cycle
    tracked = 0
    for f in findings:
        asset = f.get("value")
        if not asset:
            continue
        tracked += 1
        d = f.get("data", {})
        cur_state = _state_of(d)
        cur_sev = d.get("sev_platform", "SEV5")

        prev = cache.get(asset)
        if isinstance(prev, str):   # migrate legacy {asset: timestamp} entries
            prev = {"first_seen": prev, "state": {}, "sev": None, "ips": []}
        prev_sev = (prev or {}).get("sev") or "SEV5"

        # A finding is ONE confirmed, actively running lookalike domain. The
        # permutation pool and any registered-but-dormant name (no resolving
        # host, no mail, no live page) are monitoring inventory only, never a
        # finding, so they are tracked in the cache but emit no signal.
        is_active = any(cur_state.get(k) for k in
                        ("resolves", "mail", "serves_login",
                         "visual_match", "favicon_match"))

        fired = _triggers(prev, cur_state, prev_sev, cur_sev)
        # A known active domain that resolved to a NEW host (a new IP it did not
        # have before) is a visible update to that same finding, not a new one.
        cur_ips = set(str(ip) for ip in (d.get("dns_a") or []))
        prev_ips = set((prev or {}).get("ips") or [])
        if prev is not None and is_active and (cur_ips - prev_ips):
            fired = list(dict.fromkeys(fired + ["new_host"]))

        first_seen = (prev or {}).get("first_seen", now)
        # Dedup is per DOMAIN (the dedup_id is keyed on the asset), so the same
        # domain seen again updates its finding in place while a different active
        # domain always opens its own. Emit only when the domain is active and
        # something changed, so an inventory name never becomes an alert.
        if fired and is_active:
            lines.append(_sanitise(f, first_seen, report_ref, fired))

        cache[asset] = {
            "first_seen": first_seen,
            "last_seen":  now,
            "sev":        cur_sev,
            "state":      cur_state,
            "ips":        sorted(cur_ips),
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
    ap = argparse.ArgumentParser(description="Run the lookalike pipeline on a cadence.")
    ap.add_argument("--scope", required=True, type=Path, help="scope yaml file")
    ap.add_argument("--mode", choices=["passive", "semi", "active"], default=None,
                    help="override the scope mode; semi+ enables page/favicon enrichment")
    ap.add_argument("--signals-out", type=Path, default=None,
                    help="JSONL signal file (default: DATA/engagements/<client>/signals/<scope>.jsonl)")
    ap.add_argument("--once", action="store_true",
                    help="run a single cycle and exit (for cron/systemd timers)")
    args = ap.parse_args()

    if not args.scope.is_file():
        print(f"[!] scope file not found: {args.scope}", file=sys.stderr)
        return 2

    # signals_out defaults to the engagement's own signals dir, resolved in _cycle
    # once the scope (and therefore the client) is known.
    summary = asyncio.run(_cycle(args.scope, args.mode, args.signals_out))
    print(json.dumps(summary, indent=2))
    if not args.once:
        print("[i] single-shot run complete. Schedule with cron or systemd for a "
              "cadence, see the module docstring.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
