#!/usr/bin/env python3
"""
tools/subdomain_watch.py. Run subdomain enumeration on a cadence, standalone.

WHAT THIS DOES
--------------
Enumerates a client's subdomains and emits the same sanitised, ingest-ready
signal file the lookalike watcher produces, so subdomains flow to JOES AIR
through the one pipe when ingest is wired up.

It runs the subdomain modules in order and chains them the way the full
pipeline does, passive discovery first, then active resolution and bruteforce,
then takeover detection. There is no database in standalone mode, so a tiny
in-memory store carries findings from one module to the next (the modules only
read prior findings, they never write).

    # passive only, no contact with the client
    python tools/subdomain_watch.py --scope scopes/acme.yaml --mode passive --once

    # full active enumeration (DNS bruteforce and resolution against the client)
    python tools/subdomain_watch.py --scope scopes/acme.yaml --mode active --once

PASSIVE vs ACTIVE
-----------------
Passive runs only the contactless sources (certificate transparency, passive
aggregators) plus resolution of what they find. Active adds amass active,
permutation and wordlist bruteforce, zone transfer, and takeover detection,
which send DNS traffic to the client. Per the network boundary, active should
egress from the disposable host, not an analyst workstation.

The signal file is metadata only. Each line is a host, its severity, and the
evidence (resolves, records, discovery source, takeover exposure). No raw
responses, nothing confidential. It does not POST anywhere.

Beside it the watcher writes a plain host list, <scope>-subdomains.txt, with
just the domains and subdomains found, one per line, lowercased and sorted.
That file is the operator download, the JSONL is for ingest.
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
from core import network as _net                    # noqa: E402
from layer2.subdomain import (                      # noqa: E402
    cert_transparency, subdomain_passive, subdomain_wayback, subdomain_deep,
    subdomain_permutations, subdomain_prefix_sweep, subdomain_bruteforce,
    dns_resolve, subdomain_takeover,
)
from layer2.network import zone_transfer            # noqa: E402
from scope_parser import load_scope                 # noqa: E402

# Run order. Each module is gated by its own MODULE_META["mode"] against the
# chosen run mode, so passive runs only the contactless subset. Order matters:
# discovery feeds resolution feeds takeover, all through the in-memory store.
ORDER = [
    cert_transparency,       # passive, CT logs (8-source fallback chain)
    subdomain_passive,       # passive, subfinder aggregators (-all -recursive)
    subdomain_wayback,       # passive, archived-URL hostname mining
    subdomain_deep,          # semi+, amass
    subdomain_permutations,  # semi+, alterx then dnsx
    subdomain_prefix_sweep,  # semi+, curated hit-rate-ordered prefix probe
    subdomain_bruteforce,    # semi+, wordlist resolve (size-to-time-budget)
    zone_transfer,           # semi+, AXFR attempt
    dns_resolve,             # resolves every candidate found above
    subdomain_takeover,      # semi+, dangling CNAME detection
]

_ALLOWED = {
    "passive": {"passive"},
    "semi":    {"passive", "semi"},
    "active":  {"passive", "semi", "active"},
}


class _MemDB:
    """In-memory stand-in for the pipeline DB. Modules only read, we feed them."""
    def __init__(self) -> None:
        self._findings: list[dict] = []

    async def get_last_run_id(self, target: str) -> str:
        return "standalone"

    async def get_findings(self, run_id: str, finding_type: str | None = None) -> list[dict]:
        if finding_type is None:
            return list(self._findings)
        return [f for f in self._findings if f.get("type") == finding_type]

    def add(self, findings: list[dict]) -> None:
        for f in findings or []:
            if f.get("value"):
                self._findings.append(
                    {"type": f.get("type"), "value": f.get("value"), "data": f.get("data", {})})


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


def _dedup_id(host: str) -> str:
    return hashlib.sha1(f"subdomain|{host}".encode()).hexdigest()


def _slack_notify(text: str) -> bool:
    """Best-effort Slack post, mirrors the console helper. No webhook, no-op."""
    import os
    hook = os.environ.get("SURFACESCANNER_SLACK_WEBHOOK", "").strip()
    if not hook or not hook.startswith("https://hooks.slack.com/"):
        return False
    try:
        import urllib.request
        req = urllib.request.Request(
            hook, data=json.dumps({"text": text}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=6) as r:
            return 200 <= r.status < 300
    except Exception:
        return False


def _update_panel_subdomains(eng_dir: Path, discovered: list[str],
                             new_hosts: list[str], had_baseline: bool,
                             mode: str) -> list[str]:
    """Reconcile a scan result into the panel's curated subdomain state so the
    Subdomains tab shows a change alert. Newly discovered hosts are merged into
    the curated list, and when there was a prior baseline any host new to that
    list raises an alert. Returns the hosts that raised the alert.

    This writes the same state/subdomains.json the console reads and edits, so a
    scheduled scan and a manual edit share one working set. It never imports the
    console, to keep the watcher standalone."""
    f = eng_dir / "state" / "subdomains.json"
    try:
        data = json.loads(f.read_text()) if f.is_file() else {}
        if not isinstance(data, dict):
            data = {}
    except Exception:
        data = {}
    data.setdefault("list", [])
    data.setdefault("alerts", [])
    known = set(data.get("list") or [])
    truly_new = sorted(set(new_hosts) - known)
    data["list"] = sorted(known | set(discovered))
    raised: list[str] = []
    if had_baseline and truly_new:
        raised = truly_new
        data["alerts"].append({
            "ts": datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC"),
            "source": f"{mode} scan", "new": truly_new})
        data["alerts"] = data["alerts"][-100:]
    try:
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(json.dumps(data, indent=2))
    except Exception:
        pass
    return raised


_TRIGGER_LABEL = {
    "new":        "newly discovered",
    "resolves":   "started resolving",
    "takeover":   "takeover exposure appeared",
    "escalated":  "severity escalated",
}


def _severity(h: dict) -> str:
    """Host severity. Takeover dominates, then a resolving host, then inventory."""
    if h.get("takeover"):
        return "SEV1"
    if h.get("resolves"):
        return "SEV4"
    return "SEV5"


def _sev_rank(sev: str) -> int:
    try:
        return 6 - int(str(sev).replace("SEV", ""))
    except Exception:
        return 0


def _aggregate(findings: list[dict]) -> dict:
    """Collapse raw findings into one record per host."""
    hosts: dict[str, dict] = {}

    def host(v):
        v = (v or "").strip().lower().rstrip(".")
        if v and v not in hosts:
            hosts[v] = {"sources": set(), "records": [], "resolves": False, "takeover": None}
        return v

    for f in findings:
        t, v, d = f.get("type"), f.get("value"), f.get("data", {})
        if t == "subdomain":
            hv = host(v)
            if hv:
                hosts[hv]["sources"].add(d.get("source") or "subdomain")
        elif t == "resolved_host":
            hv = host(v)
            if hv:
                hosts[hv]["resolves"] = True
                recs = d.get("records") or d.get("a") or []
                if isinstance(recs, list):
                    hosts[hv]["records"] = recs
                hosts[hv]["sources"].add("dns_resolve")
        elif t and "takeover" in t:
            hv = host(v)
            if hv:
                hosts[hv]["takeover"] = {"service": d.get("service") or d.get("signature"),
                                         "confidence": d.get("confidence")}
    return hosts


def _ip_entities(records) -> list[dict]:
    ents = []
    for r in records or []:
        val = r.get("value") if isinstance(r, dict) else r
        if isinstance(val, str) and val and not val.startswith("!"):
            ents.append({"type": "ip", "value": val})
    return ents


def _sanitise(host: str, h: dict, sev: str, first_seen: str,
              report_ref: str, triggers: list[str]) -> dict:
    reason = ", ".join(_TRIGGER_LABEL.get(t, t) for t in triggers)
    tk = h.get("takeover")
    title = (f"Subdomain takeover exposure on {host}" if tk
             else f"Subdomain {host}")
    desc_bits = []
    if tk and tk.get("service"):
        desc_bits.append(f"dangling pointer to {tk['service']}")
    desc_bits.append("resolves" if h.get("resolves") else "does not resolve")
    if h.get("sources"):
        desc_bits.append("found by " + ", ".join(sorted(h["sources"])))
    return {
        "dedup_id":     _dedup_id(host),
        "title":        title,
        "description":  (f"Trigger: {reason}. " if reason else "") + ". ".join(desc_bits),
        "severity":     sev,
        "source":       "Continuous EAS / subdomain",
        "source_class": "subdomain",
        "entities":     [{"type": "domain", "value": host}] + _ip_entities(h.get("records")),
        "evidence": {
            "triggers":     triggers,
            "resolves":     h.get("resolves", False),
            "records":      [r.get("value") if isinstance(r, dict) else r
                             for r in (h.get("records") or [])][:20],
            "sources":      sorted(h.get("sources") or []),
            "takeover":     h.get("takeover"),
        },
        "first_seen": first_seen,
        "report_ref": report_ref,
    }


# Tools each mode needs to produce a trustworthy result. A missing REQUIRED tool
# means a "0 alive" is really "could not run", so the whole cycle is marked
# degraded. OPTIONAL tools widen coverage but their absence is not a false
# negative on its own.
_REQUIRED_TOOLS = {
    "passive": ["subfinder"],
    "semi":    ["subfinder", "dnsx"],
    "active":  ["subfinder", "dnsx"],
}
_OPTIONAL_TOOLS = ["puredns", "massdns", "alterx", "amass", "httpx"]


async def _preflight(mode: str) -> tuple[list[str], list[str]]:
    """Return (missing_required, missing_optional) resolved the same way the
    executor resolves tools, so this never disagrees with what a module can run."""
    missing_req, missing_opt = [], []
    for t in _REQUIRED_TOOLS.get(mode, ["subfinder"]):
        if not await _net.check_tool(t):
            missing_req.append(t)
    for t in _OPTIONAL_TOOLS:
        if not await _net.check_tool(t):
            missing_opt.append(t)
    return missing_req, missing_opt


async def _cycle(scope_path: Path, mode: str | None, signals_out: Path | None = None) -> dict:
    config = load_config()
    scope = load_scope(scope_path)
    if mode:
        scope.mode = mode
    allowed = _ALLOWED.get(scope.mode, {"passive"})

    # Loud-fail wiring: clear the missing-tool registry, then preflight the tools
    # this mode needs. A missing resolver is the difference between "nothing is
    # live" and "could not check", so it must never be silent.
    _net.reset_missing_tools()
    missing_required, missing_optional = await _preflight(scope.mode)
    if missing_required:
        print(f"[!] DEGRADED: required tools missing: {', '.join(missing_required)}. "
              f"Results will under-report live hosts.", file=sys.stderr)

    config.use_engagement(scope.target.name)
    if signals_out is None:
        # Passive and active keep separate exports, so one does not overwrite
        # the other and each phase square links its own file.
        signals_out = config.paths["signals"] / f"{scope_path.stem}-subdomains-{scope.mode}.jsonl"

    db = _MemDB()
    ran, skipped = [], []
    for mod in ORDER:
        meta = getattr(mod, "MODULE_META", {})
        if not (set(meta.get("mode", [])) & allowed):
            skipped.append(meta.get("name", mod.__name__))
            continue
        try:
            result = await mod.run(scope, config, db)
            db.add(result.get("findings", []))
            ran.append(meta.get("name", mod.__name__))
        except Exception as exc:   # modules should not raise, belt and braces
            print(f"[!] {mod.__name__} raised: {exc}", file=sys.stderr)
            skipped.append(meta.get("name", mod.__name__) + " (error)")

    hosts = _aggregate(await db.get_findings("standalone"))

    cache_path = signals_out.with_suffix(signals_out.suffix + ".seen.json")
    cache = _load_cache(cache_path)
    had_baseline = bool(cache)
    new_hosts: list[str] = []
    now = _utcnow()
    report_ref = f"{scope.target.name}:{now}"

    lines: list[dict] = []
    for host, h in sorted(hosts.items()):
        sev = _severity(h)
        prev = cache.get(host) or {}
        prev_state = prev.get("state") or {}
        triggers = []
        if not prev:
            triggers.append("new")
            new_hosts.append(host)
        else:
            if h.get("resolves") and not prev_state.get("resolves"):
                triggers.append("resolves")
            if h.get("takeover") and not prev_state.get("takeover"):
                triggers.append("takeover")
            if _sev_rank(sev) > _sev_rank(prev.get("sev") or "SEV5"):
                triggers.append("escalated")
        first_seen = prev.get("first_seen", now)
        if triggers:
            lines.append(_sanitise(host, h, sev, first_seen, report_ref, triggers))
        cache[host] = {
            "first_seen": first_seen, "last_seen": now, "sev": sev,
            "state": {"resolves": bool(h.get("resolves")), "takeover": bool(h.get("takeover"))},
        }

    signals_out.parent.mkdir(parents=True, exist_ok=True)
    with signals_out.open("w") as fh:
        for ln in lines:
            fh.write(json.dumps(ln) + "\n")
    _save_cache(cache_path, cache)

    # Also write a host list beside the signal file. This is the operator
    # download: one host per line, lowercased, deduplicated and sorted, with the
    # source that found it as a second tab-separated column. Pure hostnames are
    # still one cut away (cut -f1). The hosts keys are already cleaned in
    # _aggregate (lowercased, trailing dot stripped).
    txt_out = signals_out.with_suffix(".txt")
    lines_txt = []
    for host in sorted(h for h in hosts if h):
        src = ", ".join(sorted(hosts[host].get("sources") or [])) or "unknown"
        lines_txt.append(f"{host}\t{src}")
    txt_out.write_text("\n".join(lines_txt) + ("\n" if lines_txt else ""))

    # Reconcile into the panel's curated subdomain state and raise a change
    # alert for anything new (skipped on the very first baseline run).
    alerted = _update_panel_subdomains(
        signals_out.parent.parent, sorted(hosts), new_hosts, had_baseline, scope.mode)
    if alerted:
        _slack_notify(f":mag: Continuous EAS: {len(alerted)} new subdomain(s) for "
                      f"{scope.target.name} ({scope.mode} scan): "
                      f"{', '.join(alerted[:20])}")

    by_sev: dict[str, int] = {}
    for ln in lines:
        by_sev[ln["severity"]] = by_sev.get(ln["severity"], 0) + 1

    # Health sidecar. A tool missing at preflight OR hit at runtime makes the
    # cycle degraded, so a "0 alive" is never shown as a clean, trustworthy
    # empty result. The panel reads this file and shows a banner instead.
    runtime_missing = sorted(_net.MISSING_TOOLS)
    all_missing = sorted(set(missing_required) | set(runtime_missing))
    degraded = bool(missing_required or runtime_missing)
    health = {
        "ts": now,
        "mode": scope.mode,
        "degraded": degraded,
        "missing_required": missing_required,
        "missing_optional": missing_optional,
        "missing_at_runtime": runtime_missing,
        "missing_tools": all_missing,
        "hosts_found": len(hosts),
    }
    health_path = signals_out.with_suffix(signals_out.suffix + ".health.json")
    health_path.write_text(json.dumps(health, indent=2))
    if degraded:
        print(f"[!] cycle DEGRADED, missing tools: {', '.join(all_missing)}",
              file=sys.stderr)

    return {
        "target": scope.target.name,
        "mode": scope.mode,
        "modules_ran": ran,
        "modules_skipped": skipped,
        "hosts_found": len(hosts),
        "triggered": len(lines),
        "new_subdomains_alerted": len(alerted),
        "by_sev": by_sev,
        "degraded": degraded,
        "missing_tools": all_missing,
        "signals_out": str(signals_out),
        "hosts_out": str(txt_out),
        "health_out": str(health_path),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Run subdomain enumeration on a cadence.")
    ap.add_argument("--scope", required=True, type=Path, help="scope yaml file")
    ap.add_argument("--mode", choices=["passive", "semi", "active"], default=None,
                    help="passive is contactless, active adds bruteforce and resolution")
    ap.add_argument("--signals-out", type=Path, default=None,
                    help="JSONL signal file (default: DATA/engagements/<client>/signals/<scope>-subdomains.jsonl)")
    ap.add_argument("--once", action="store_true",
                    help="run a single cycle and exit (for cron or systemd timers)")
    args = ap.parse_args()

    if not args.scope.is_file():
        print(f"[!] scope file not found: {args.scope}", file=sys.stderr)
        return 2

    summary = asyncio.run(_cycle(args.scope, args.mode, args.signals_out))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
