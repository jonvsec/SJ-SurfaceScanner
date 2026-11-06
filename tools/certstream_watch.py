#!/usr/bin/env python3
"""
tools/certstream_watch.py — real-time lookalike detection from the CT firehose.

The newly-registered-domain producer polls crt.sh on a cadence. This watches the
certificate transparency stream live: every certificate issued anywhere, as it
is logged, via a CertStream server. The day a phishing operator gets a
certificate for a lookalike (usually minutes before the page goes live) it
appears here, ahead of any polling window.

Each certificate's domains are matched against the client brand labels with the
same fuzzy matcher the pollers use, and scored phishing_catcher-style: a brand
resemblance is the base hit, and suspicious keywords (login, secure, verify)
raise the score. Hits are de-duplicated and appended to the same sanitised
signal file the cadence runner writes, so one lookalike looks the same whether a
poll or the stream found it.

    python tools/certstream_watch.py --scope scopes/acme.yaml
    python tools/certstream_watch.py --scope scopes/acme.yaml \
        --server wss://my-selfhosted-certstream:4443/ --signals-out outputs/signals/acme.stream.jsonl

Runs until interrupted (Ctrl-C), reconnecting if the stream drops. Pure
scripting, no AI, nothing client side leaves the machine. Suitable as a systemd
service:

    [Service]
    ExecStart=/path/.venv/bin/python tools/certstream_watch.py --scope scopes/acme.yaml
    Restart=always
"""
from __future__ import annotations

import argparse
import asyncio
import json
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import load_config                 # noqa: E402
from layer1 import _lookalike_common as lc           # noqa: E402
from layer1.newly_registered_domains import _brand_labels  # noqa: E402
from scope_parser import load_scope                 # noqa: E402

try:
    import aiohttp
except ImportError:
    aiohttp = None


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _score_domain(domain: str, matched_brand: str, keywords: list[str]) -> int:
    """
    phishing_catcher-style score. The brand resemblance is the reason we emit at
    all; keywords and a deep hostname only raise the confidence.
    """
    score = 60  # fuzzy brand match is the base
    low = domain.lower()
    score += 15 * sum(1 for k in keywords if k in low)
    if low.count(".") >= 3:         # deep subdomain, e.g. login.acme.secure.example
        score += 10
    if any(low.endswith(t) for t in (".zip", ".mov", ".top", ".xyz", ".live", ".click")):
        score += 10
    if "-" in low.split(".")[0]:
        score += 5
    return min(score, 100)


def _signal(domain: str, brand: str, score: int, keywords: list[str]) -> dict:
    sev = "SEV2" if score >= 85 else "SEV3" if score >= 70 else "SEV4"
    return {
        "asset":  domain,
        "type":   "lookalike_domain",
        "sev":    sev,
        "source": "certstream",
        "fuzzer": "ct-stream",
        "origin_domain": brand,
        "issue":  f"Lookalike domain {domain} seen in certificate transparency",
        "evidence": {
            "resembles_brand": brand,
            "stream_score":    score,
            "mail_capable":    False,
            "serves_login":    False,
            "favicon_match":   False,
            "visual_match":    False,
        },
        "first_seen": _utcnow(),
        "report_ref": "certstream",
    }


async def _watch(server: str, labels: set[str], keywords: list[str],
                 max_distance: int, signals_out: Path, stop: asyncio.Event) -> None:
    signals_out.parent.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    backoff = 1

    while not stop.is_set():
        try:
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(server, heartbeat=30) as ws:
                    print(f"[i] connected to {server}", file=sys.stderr)
                    backoff = 1
                    async for msg in ws:
                        if stop.is_set():
                            break
                        if msg.type != aiohttp.WSMsgType.TEXT:
                            continue
                        try:
                            data = json.loads(msg.data)
                        except Exception:
                            continue
                        if data.get("message_type") != "certificate_update":
                            continue
                        domains = (
                            data.get("data", {}).get("leaf_cert", {}).get("all_domains", [])
                        )
                        for dom in domains:
                            dom = str(dom).lstrip("*.").lower()
                            if not dom or dom in seen:
                                continue
                            brand = lc.fuzzy_brand_match(dom, labels, max_distance)
                            if not brand:
                                continue
                            seen.add(dom)
                            score = _score_domain(dom, brand, keywords)
                            sig = _signal(dom, brand, score, keywords)
                            with signals_out.open("a") as fh:
                                fh.write(json.dumps(sig) + "\n")
                            print(f"[+] {sig['sev']} {dom} (~{brand}, score {score})",
                                  file=sys.stderr)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            if stop.is_set():
                break
            print(f"[!] stream error: {exc}; reconnecting in {backoff}s", file=sys.stderr)
            try:
                await asyncio.wait_for(stop.wait(), timeout=backoff)
            except asyncio.TimeoutError:
                pass
            backoff = min(backoff * 2, 60)


def main() -> int:
    if aiohttp is None:
        print("[!] aiohttp is required for the CertStream watcher (pip install aiohttp).",
              file=sys.stderr)
        return 3

    ap = argparse.ArgumentParser(description="Live CT-stream lookalike watcher.")
    ap.add_argument("--scope", required=True, type=Path)
    ap.add_argument("--server", default=None, help="CertStream server (default: config)")
    ap.add_argument("--signals-out", type=Path, default=None)
    args = ap.parse_args()

    if not args.scope.is_file():
        print(f"[!] scope file not found: {args.scope}", file=sys.stderr)
        return 2

    config = load_config()
    scope = load_scope(args.scope)
    bp = config.brand_protection
    labels = _brand_labels(scope)
    if not labels:
        print("[!] no brand labels derived from scope; nothing to watch.", file=sys.stderr)
        return 2

    server = args.server or bp.certstream_url
    signals_out = args.signals_out or (
        Path(bp.signals_dir) / f"{args.scope.stem}.stream.jsonl"
    )

    print(f"[i] watching {sorted(labels)} on {server} -> {signals_out}", file=sys.stderr)

    async def _run() -> None:
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, stop.set)
            except NotImplementedError:
                pass
        await _watch(server, labels, bp.certstream_keywords,
                     bp.fuzzy_max_distance, signals_out, stop)

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass
    print("[i] stopped.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
