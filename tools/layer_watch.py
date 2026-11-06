#!/usr/bin/env python3
"""
tools/layer_watch.py. Generic per-layer watcher for the Continuous EAS engine.

WHAT THIS IS
------------
One standalone runner that drives a whole SurfaceScanner layer and bridges what
its modules find into the EAS signal format the operator console reads. It is
the same productised pattern as lookalike_watch.py and subdomain_watch.py, but
layer-driven: point it at a layer and it runs every module promoted into that
layer's package, in process, with no database and no orchestrator.

    python tools/layer_watch.py --scope scopes/acme.yaml --layer 2.5 --once

Each layer module exposes `async def run(scope, config, db) -> {"findings": [...]}`.
This runner calls them with db=None (standalone, no Postgres), collects the
findings, and converts each into one signal: a stable dedup id, a title and
sanitised description, a SEV1 to SEV5 severity mapped from the module's own
severity word, the source class (the finding type), and the entity list. The
current full set is written to the layer's signal file every cycle, so the
console counts and the relationship map always reflect the latest state.

WHY STANDALONE
--------------
The shipped product stays decoupled from the private Postgres pipeline. It
imports only the layer's own modules and the small core helpers they need
(config, ratelimiter, scope_guard, network). A module that needs an API key or
a tool it cannot find skips itself and simply contributes no findings, so a
layer with nothing configured runs clean and empty rather than failing.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib
import json
import os
import pkgutil
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Per-module wall-clock budget. A module that hangs on an external call must not
# block the rest of the layer, so each run is bounded and a timeout is a skip,
# not a stall. Override with SURFACESCANNER_MODULE_TIMEOUT (seconds).
MODULE_TIMEOUT = float(os.environ.get("SURFACESCANNER_MODULE_TIMEOUT", "120"))

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import load_config                 # noqa: E402
from scope_parser import load_scope                 # noqa: E402

# Layer selector -> (python package, signal-file suffix, human name). The suffix
# keeps each layer's signals in their own file under the engagement, so they
# never clobber the lookalike or subdomain watchers' files.
LAYERS = {
    "0":   ("layer0",   "layer0",   "Corporate Intelligence"),
    "2.5": ("layer2_5", "layer2_5", "Surface Recon"),
    "3":   ("layer3",   "layer3",   "Digital Footprint and Breach"),
    "4":   ("layer4",   "layer4",   "Kill Chain and Sector Intelligence"),
}

# Module severity words -> the platform SEV scale. Anything unknown is INFO, the
# safe floor, so a miscategorised finding never inflates its own severity.
_SEV_WORD = {
    "critical": "SEV1", "crit": "SEV1",
    "high": "SEV2",
    "medium": "SEV3", "med": "SEV3", "moderate": "SEV3",
    "low": "SEV4",
    "info": "SEV5", "informational": "SEV5", "none": "SEV5",
}
_SEV_OK = {"SEV1", "SEV2", "SEV3", "SEV4", "SEV5"}

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.I)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62}\.)+[a-z]{2,}$", re.I)


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


def _to_sev(finding: dict) -> str:
    """Map a module finding to a SEV1..SEV5 value. Accepts an already-platform
    SEVx, or a severity word at the top level or inside data."""
    data = finding.get("data") or {}
    for raw in (finding.get("severity"), data.get("severity"),
                data.get("sev_platform"), finding.get("sev_platform")):
        if not raw:
            continue
        s = str(raw).strip()
        up = s.upper()
        if up in _SEV_OK:
            return up
        if s.lower() in _SEV_WORD:
            return _SEV_WORD[s.lower()]
    return "SEV5"


def _entity_type(value: str) -> str:
    v = (value or "").strip()
    if _IP_RE.match(v):
        return "ip"
    if _CVE_RE.match(v):
        return "cve"
    if _EMAIL_RE.match(v):
        return "email"
    if _DOMAIN_RE.match(v):
        return "domain"
    return "asset"


def _entities(value: str, data: dict) -> list[dict]:
    """The entity list for a finding: the value itself, plus any related IPs,
    domains or emails the module attached in data. Deduplicated, scalar only, so
    no raw payloads leak into the signal."""
    ents: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(t: str, val):
        if not isinstance(val, str):
            return
        val = val.strip()
        if not val or (t, val) in seen:
            return
        seen.add((t, val))
        ents.append({"type": t, "value": val})

    add(_entity_type(value), value)
    for key, t in (("ips", "ip"), ("dns_a", "ip"), ("addresses", "ip"),
                   ("domains", "domain"), ("hosts", "domain"),
                   ("emails", "email")):
        v = data.get(key)
        if isinstance(v, (list, tuple)):
            for item in v:
                add(t, item)
        elif isinstance(v, str):
            add(t, v)
    return ents or [{"type": "asset", "value": str(value)}]


def _title(finding: dict, source_class: str, value: str) -> str:
    t = finding.get("title") or (finding.get("data") or {}).get("title")
    if t:
        return str(t)[:200]
    pretty = source_class.replace("_", " ").strip().capitalize()
    return f"{pretty}: {value}"[:200]


def _description(finding: dict) -> str:
    data = finding.get("data") or {}
    for key in ("description", "summary", "detail", "note"):
        for src in (finding, data):
            v = src.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()[:600]
    reasons = data.get("reasons")
    if isinstance(reasons, (list, tuple)) and reasons:
        return ". ".join(str(r) for r in reasons)[:600]
    return ""


def _dedup_id(source_class: str, value: str) -> str:
    return hashlib.sha1(f"{source_class}|{value}".encode()).hexdigest()


def _signal(finding: dict, layer_name: str, first_seen: str, last_seen: str) -> dict | None:
    value = finding.get("value")
    if value in (None, ""):
        return None
    value = str(value)
    source_class = str(finding.get("type") or "finding")
    sev = _to_sev(finding)
    return {
        "dedup_id":     _dedup_id(source_class, value),
        "title":        _title(finding, source_class, value),
        "description":  _description(finding),
        "severity":     sev,
        "source":       f"Continuous EAS / {layer_name}",
        "source_class": source_class,
        "entities":     _entities(value, finding.get("data") or {}),
        "first_seen":   first_seen,
        "last_seen":    last_seen,
    }


def _discover(package: str) -> list:
    """Every module in a layer package that exposes a run() coroutine. Adding a
    module to a layer is dropping its file into the package, nothing else."""
    mods = []
    try:
        pkg = importlib.import_module(package)
    except Exception as exc:
        print(f"[!] could not import {package}: {exc}", file=sys.stderr)
        return mods
    for info in pkgutil.iter_modules(pkg.__path__):
        if info.name.startswith("_"):
            continue
        try:
            m = importlib.import_module(f"{package}.{info.name}")
        except Exception as exc:
            print(f"[!] skip {package}.{info.name}: {exc}", file=sys.stderr)
            continue
        if callable(getattr(m, "run", None)):
            mods.append(m)
    return mods


async def _cycle(scope_path: Path, layer: str, mode: str | None,
                 signals_out: Path | None = None) -> dict:
    if layer not in LAYERS:
        raise SystemExit(f"Unknown layer {layer}. Known: {', '.join(LAYERS)}")
    package, suffix, layer_name = LAYERS[layer]

    config = load_config()
    scope = load_scope(scope_path)
    if mode:
        scope.mode = mode
    config.use_engagement(scope.target.name)
    if signals_out is None:
        signals_out = config.paths["signals"] / f"{scope_path.stem}-{suffix}.jsonl"

    modules = _discover(package)
    findings: list[dict] = []
    ran, skipped = [], []
    for mod in modules:
        short = mod.__name__.rsplit(".", 1)[-1]
        try:
            res = await asyncio.wait_for(mod.run(scope, config, db=None),
                                         timeout=MODULE_TIMEOUT)
            got = (res or {}).get("findings", []) if isinstance(res, dict) else []
            findings += [f for f in got if isinstance(f, dict)]
            ran.append(short)
        except asyncio.TimeoutError:
            # A module that hangs past its budget is skipped, the layer goes on.
            skipped.append(short)
            print(f"[!] {mod.__name__} timed out after {MODULE_TIMEOUT:.0f}s, skipped",
                  file=sys.stderr)
        except Exception as exc:
            # A module that needs a key, a tool or the database it was not given
            # raises here. It skips, it never breaks the layer.
            skipped.append(short)
            print(f"[!] {mod.__name__} skipped: {exc}", file=sys.stderr)

    cache_path = signals_out.with_suffix(signals_out.suffix + ".seen.json")
    cache = _load_cache(cache_path)
    now = _utcnow()

    lines: list[dict] = []
    new_cache: dict = {}
    by_sev: dict[str, int] = {}
    for f in findings:
        sig = _signal(f, layer_name, now, now)
        if not sig:
            continue
        did = sig["dedup_id"]
        first_seen = (cache.get(did) or {}).get("first_seen", now)
        sig["first_seen"] = first_seen
        new_cache[did] = {"first_seen": first_seen, "last_seen": now}
        lines.append(sig)
        by_sev[sig["severity"]] = by_sev.get(sig["severity"], 0) + 1

    # Write the full current set for this layer, so the console always reflects
    # the latest state rather than an append-only history.
    signals_out.parent.mkdir(parents=True, exist_ok=True)
    with signals_out.open("w") as fh:
        for ln in lines:
            fh.write(json.dumps(ln) + "\n")
    _save_cache(cache_path, new_cache)

    return {
        "layer": layer, "layer_name": layer_name,
        "modules_ran": ran, "modules_skipped": skipped,
        "signals": len(lines), "by_severity": by_sev,
        "signals_out": str(signals_out),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Run one SurfaceScanner layer and emit EAS signals")
    ap.add_argument("--scope", type=Path, required=True, help="Path to the client scope.yaml")
    ap.add_argument("--layer", required=True, choices=list(LAYERS),
                    help="Which layer to run (0, 2.5, 3 or 4)")
    ap.add_argument("--mode", default=None, help="Override scope mode: passive|semi|active")
    ap.add_argument("--signals-out", type=Path, default=None,
                    help="JSONL signal file (default: the engagement's own signals dir)")
    ap.add_argument("--once", action="store_true",
                    help="Run a single cycle and exit (the only mode today)")
    args = ap.parse_args()
    summary = asyncio.run(_cycle(args.scope, args.layer, args.mode, args.signals_out))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
