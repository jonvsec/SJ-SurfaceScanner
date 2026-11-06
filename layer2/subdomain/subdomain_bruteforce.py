"""
layer2/subdomain/subdomain_bruteforce.py, DNS wordlist bruteforce.

Generates subdomain candidates by prefixing known wordlists against target
domains, then resolves with dnsx. Catches subdomains that appear in no
certificate log and match no permutation pattern, pure internal naming.

Wordlist priority (first found wins):
  1. config.paths["wordlists"] / "subdomains.txt"   (custom user list)
  2. /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
  3. /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
  4. built-in 500-word minimal list (always available, no file deps)

CLI tool required: dnsx (from ProjectDiscovery).
Mode: semi only, bruteforce generates DNS noise visible in target logs.
"""
from __future__ import annotations

import tempfile
import time
from pathlib import Path
from typing import Any

import structlog

from core.config import Config
from core.network import run_command
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "subdomain_bruteforce",
    "title":    "Subdomain Bruteforce",
    "description": "Wordlist-driven DNS discovery",
    "layer":    2,
    "mode":     ["semi", "active"],
    "requires": [],
    "optional": True,
}

# Nested-zone bruteforcing: a zone must already hold this many known hosts
# before it is worth spending a full wordlist on, and we cap the total so a
# large estate cannot explode the candidate count.
_MIN_CHILDREN      = 2
_MAX_NESTED_ZONES  = 40

# Queries/sec ceiling for puredns, deliberately conservative so recursive
# bruteforcing across many zones stays polite to client resolvers.
_PUREDNS_RATE = 1000

# Minimal built-in wordlist when no external list is available
_BUILTIN_WORDS = """www api mail smtp pop imap ftp ssh vpn dev staging test
beta admin portal dashboard app mobile cdn static assets media img images
files upload download backup db database mysql postgres redis cache queue
jira confluence gitlab jenkins ci cd build deploy prod production uat qa
internal intranet corp office help support ticket auth login sso oauth
webmail exchange owa mx relay smtp1 smtp2 email newsletter
blog forum community shop store ecommerce payment checkout cart
monitor metrics grafana kibana elastic search logs logging
api1 api2 api-v1 api-v2 api-dev api-test api-prod
dev1 dev2 staging1 staging2 test1 test2 demo sandbox
vpn1 vpn2 remote access citrix rdp jump bastion
s3 storage files-cdn assets-cdn media-cdn
old legacy retired archive deprecated
us eu ap asia pacific east west north south""".split()


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0        = time.monotonic()
    findings: list[dict] = []
    metadata: dict       = {}

    wordlist = _find_wordlist(config)
    words    = _load_wordlist(wordlist)
    metadata["wordlist"]    = str(wordlist) if wordlist else "builtin"
    metadata["word_count"]  = len(words)
    metadata["tier"]        = _tier_name(len(words))
    metadata["time_budget_s"] = _time_budget(len(words))

    # Bruteforcing only the scope roots cannot reach a host two labels deep:
    # finding vpn-1.adm.example.com by prefixing example.com would require
    # "vpn-1.adm" to be a single wordlist entry. Derive intermediate zones
    # from what earlier modules already discovered and brute those too.
    roots  = list(scope.all_domains)
    nested = await _discover_parent_zones(scope, db)
    bases  = roots + nested

    metadata["root_zones"]   = roots
    metadata["nested_zones"] = nested
    metadata["bases"]        = len(bases)

    log.info(
        "bruteforce.starting",
        words=len(words),
        roots=len(roots),
        nested_zones=len(nested),
        candidates=len(words) * len(bases),
    )

    for base in bases:
        candidates = [f"{w}.{base}" for w in words]
        resolved   = await _resolve_batch(candidates, config, base)
        metadata.setdefault("per_domain", {})[base] = len(resolved)

        for host in resolved:
            findings.append({
                "type":  "subdomain",
                "value": host,
                "data": {
                    "source":        "dns_bruteforce",
                    "parent_domain": base,
                    "nested":        base not in roots,
                },
            })

    log.info(
        "bruteforce.complete",
        findings=len(findings),
        bases=len(bases),
        wordlist=metadata["wordlist"],
        words=len(words),
    )

    return {
        "module":   "layer2/subdomain/subdomain_bruteforce",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }


def _find_wordlist(config: Config) -> Path | None:
    """
    Locate the largest available DNS wordlist.

    Ordered best-first. The SecLists paths cover both a system install and a
    checkout symlinked into the project's wordlists/ directory, the previous
    list only checked /usr/share/* and silently fell through to the 126-word
    builtin on any machine where SecLists lives in $HOME.
    """
    wl_dir = config.paths.get("wordlists", Path("/nonexistent"))

    candidates = [
        # Operator-supplied list always wins
        wl_dir / "subdomains.txt",
        # SecLists checked out or symlinked under the project
        wl_dir / "SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt",
        wl_dir / "SecLists/Discovery/DNS/n0kovo_subdomains.txt",
        wl_dir / "SecLists/Discovery/DNS/subdomains-top1million-110000.txt",
        wl_dir / "SecLists/Discovery/DNS/dns-Jhaddix.txt",
        # SecLists in the user's home
        Path.home() / "SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt",
        Path.home() / "SecLists/Discovery/DNS/dns-Jhaddix.txt",
        # System-wide installs (both common layouts)
        Path("/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt"),
        Path("/usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt"),
        Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"),
    ]
    for p in candidates:
        try:
            if isinstance(p, Path) and p.is_file():
                return p
        except OSError:
            continue

    log.warning(
        "bruteforce.no_wordlist_found",
        detail="falling back to builtin word list, DNS coverage will be minimal",
    )
    return None


def _load_wordlist(path: Path | None) -> list[str]:
    if path and path.exists():
        try:
            words = [l.strip() for l in path.read_text().splitlines() if l.strip() and not l.startswith("#")]
            return words[:50_000]  # cap to prevent extremely long runs
        except Exception:
            pass
    return _BUILTIN_WORDS


async def _discover_parent_zones(scope: Scope, db: Any) -> list[str]:
    """
    Derive intermediate zones to brute against, from hosts already discovered.

    For every known host, strip the leftmost label; whatever remains is a
    candidate base. Only zones that already hold at least _MIN_CHILDREN known
    hosts are kept, so one-off hostnames do not multiply the candidate space.
    """
    if db is None:
        return []

    roots = set(scope.all_domains)
    hosts: set[str] = set()

    try:
        run_id = await db.get_last_run_id(scope.target.name) or ""
        if not run_id:
            return []
        for ftype in ("subdomain", "certificate", "resolved_host"):
            for row in await db.get_findings(run_id, ftype):
                v = (row.get("value") or "").strip().lower().rstrip(".")
                if v and any(v.endswith("." + r) for r in roots):
                    hosts.add(v)
    except Exception as exc:
        log.debug("bruteforce.zone_query_failed", error=str(exc))
        return []

    counts: dict[str, int] = {}
    for h in hosts:
        parent = h.split(".", 1)[1] if "." in h else ""
        # Must still sit under a scoped root, and not be a root itself
        if not parent or parent in roots:
            continue
        if not any(parent == r or parent.endswith("." + r) for r in roots):
            continue
        # Skip zones whose own leftmost label is machine-generated. Ephemeral
        # per-deployment hosts (uuid.dev-apps-gcloud-888...) accumulate
        # children but are worthless as bruteforce bases, the names below
        # them are equally random and no wordlist will ever hit them.
        if _is_generated_label(parent.split(".", 1)[0]):
            continue
        counts[parent] = counts.get(parent, 0) + 1

    # Rank by child count, the zones already holding the most known hosts are
    # the ones most likely to hold more. Alphabetical order would just take
    # whatever sorts first.
    ranked = sorted(
        ((z, n) for z, n in counts.items() if n >= _MIN_CHILDREN),
        key=lambda kv: (-kv[1], kv[0]),
    )

    # Never brute a wildcard zone. Every candidate would "resolve", turning
    # one zone into 50k phantom hosts, and such zones rank *highest* here,
    # because a wildcard is exactly what makes a zone look busy. This has to
    # be checked per zone: dns_resolve only probes the scope roots, so a
    # wildcard three labels deep is invisible to it.
    zones: list[str] = []
    for z, _n in ranked:
        if len(zones) >= _MAX_NESTED_ZONES:
            break
        if await _is_wildcard_zone(z):
            log.warning("bruteforce.wildcard_zone_skipped", zone=z)
            continue
        zones.append(z)

    if zones:
        log.info(
            "bruteforce.nested_zones",
            count=len(zones),
            top=[f"{z}({n})" for z, n in ranked[:10]],
        )
    return zones


async def _is_wildcard_zone(zone: str) -> bool:
    """
    True if `zone` answers for labels that cannot exist.

    Two random probes must agree, so a zone that merely catches one stray
    lookup is not misclassified. Resolution failures mean "not a wildcard" -
    a transient DNS error must never silently drop a real zone.
    """
    import asyncio as _asyncio

    async def _resolve(name: str) -> set[str]:
        try:
            proc = await _asyncio.create_subprocess_exec(
                "dig", "+short", "+time=3", "+tries=2", "A", name,
                stdout=_asyncio.subprocess.PIPE,
                stderr=_asyncio.subprocess.DEVNULL,
            )
            out, _ = await _asyncio.wait_for(proc.communicate(), timeout=15)
            return {
                l.strip() for l in out.decode().splitlines()
                if l.strip() and not l.strip().endswith(".")
            }
        except Exception:
            return set()

    a = await _resolve(f"zz-bf-wildcard-probe-a1.{zone}")
    b = await _resolve(f"zz-bf-wildcard-probe-b2.{zone}")
    return bool(a) and a == b


def _is_generated_label(label: str) -> bool:
    """
    True for labels that look machine-generated rather than human-chosen.

    Catches hex blobs (32-char UUIDs without dashes, short hex IDs) and
    all-digit labels, tenant/deployment identifiers that make useless
    bruteforce bases.
    """
    if not label:
        return True
    if label.isdigit():
        return True
    stripped = label.replace("-", "")
    if len(stripped) >= 8 and all(c in "0123456789abcdef" for c in stripped.lower()):
        return True
    return False


async def _resolve_batch(
    candidates: list[str],
    config:     Config,
    base:       str = "",
) -> list[str]:
    """
    Resolve candidates, preferring puredns over dnsx.

    puredns wraps massdns and does native wildcard detection and filtering,
    which matters here: a wildcard zone otherwise returns every candidate as
    a "discovery" and floods the inventory with hosts that do not exist.
    Falls back to dnsx when puredns is unavailable.
    """
    if not candidates:
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(candidates))
        list_file = Path(f.name)

    resolvers = _find_resolvers(config)

    # Scale the wall-clock budget to the candidate count instead of a flat
    # 30-minute cap. A <10k list finishes in a minute or two, a 100k list wants
    # ten-plus, a 1M list is a multi-hour job. At the conservative puredns rate
    # a run needs roughly count/100 seconds, floored at 5 minutes and ceiled at
    # one hour so one pathological zone cannot hang the whole layer.
    budget = _time_budget(len(candidates))

    try:
        cmd = [
            "puredns", "resolve", str(list_file),
            "--quiet",
            "--wildcard-tests", "3",
            "--rate-limit", str(_PUREDNS_RATE),
        ]
        if resolvers:
            cmd += ["--resolvers", str(resolvers)]

        result = await run_command(
            cmd, recon_mode="semi", config=config, timeout=budget,
        )
        engine = "puredns"

        # Fall back on ANY unproductive puredns outcome, not just "not
        # installed". puredns depends on massdns plus a working resolver
        # list, and fails in several ways that still exit cleanly with no
        # output. dnsx is the proven path, so never let a silent puredns
        # failure turn into an empty bruteforce.
        if not (result.stdout or "").strip():
            log.info(
                "bruteforce.puredns_unproductive",
                base=base,
                stderr=(result.stderr or "")[:160],
                detail="falling back to dnsx",
            )
            result = await run_command(
                ["dnsx", "-l", str(list_file), "-silent", "-resp", "-retry", "2"],
                recon_mode="semi", config=config, timeout=budget,
            )
            engine = "dnsx"
    finally:
        list_file.unlink(missing_ok=True)

    if not result.ok and not (result.stdout or "").strip():
        log.warning(
            "bruteforce.resolve_failed",
            base=base, engine=engine, stderr=(result.stderr or "")[:200],
        )
        return []

    resolved = set()
    for line in result.stdout.splitlines():
        parts = line.strip().split()
        if parts:
            resolved.add(parts[0].rstrip("."))

    log.debug("bruteforce.resolved", base=base, engine=engine, hits=len(resolved))
    return sorted(resolved)


def _time_budget(candidate_count: int) -> int:
    """Wall-clock seconds for a resolve pass, scaled to the candidate count.

    Tiers (at the ~1000 q/s puredns rate): under 10k finishes inside the 300s
    floor, 100k lands near 1000s, 1M hits the 3600s ceiling. The floor stops a
    tiny list timing out on resolver warm-up, the ceiling stops a runaway zone
    hanging the layer."""
    return min(3600, max(300, candidate_count // 100))


def _tier_name(candidate_count: int) -> str:
    if candidate_count < 10_000:
        return "fast(<10k)"
    if candidate_count < 100_000:
        return "standard(10k-100k)"
    if candidate_count < 1_000_000:
        return "thorough(100k-1M)"
    return "exhaustive(>1M)"


def _find_resolvers(config: Config) -> Path | None:
    """Locate a resolver list for puredns; None lets it use its default."""
    wl_dir = config.paths.get("wordlists", Path("/nonexistent"))
    for p in (wl_dir / "resolvers.txt", Path.home() / "resolvers.txt"):
        try:
            if p.is_file():
                return p
        except OSError:
            continue
    return None
