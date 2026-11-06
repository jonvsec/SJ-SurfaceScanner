"""
core/browser_session.py — operator-assisted browser session broker.

WHY THIS EXISTS
---------------
A handful of high-value external tests sit behind an interactive sign-in that no
scanner can perform: the credential is in a human's possession, the sign-in is
MFA-gated, and the resulting token is short-lived and unscriptable. Microsoft
Teams external-user search is the canonical case. Its /api/mt/ endpoints need a
Skype bearer token, and that token only exists after a human authenticates to
SOME Microsoft 365 tenant.

The workaround is a credential broker, not a credential store. The operator
signs in by hand in a headed Chromium that we control over the Chrome DevTools
Protocol. We then borrow the Authorization header off a request the browser
itself makes, hand it to a scanner module, and let the module run unattended.

Borrowing the live header is deliberate, and is more durable than reading tokens
out of localStorage: vendors reshuffle client-side storage layouts constantly,
but the wire format of a client's own request cannot drift from what its own API
accepts.

The same CDP channel gives us screenshots, so a module can produce report-grade
visual evidence of whatever the operator is looking at, named and timestamped
consistently with the rest of the pipeline.

SCOPE AND SAFETY
----------------
  * We authenticate as OUR OWN tester identity, never as the target. Queries then
    run cross-tenant, exactly as any internet party could, which is precisely what
    the test is meant to measure.
  * The browser profile is a throwaway under state/ and is never committed.
  * Captured tokens live in a 0600 file under state/ with the session, are
    short-lived by nature, and MUST NOT be written into a report. Only the
    boolean outcome of a test belongs in a deliverable.
  * Nothing here touches target infrastructure. Teams lookups are served by
    Microsoft, so this generates no traffic to the target and leaves nothing in
    a target user's client.

CLI
---
    python -m core.browser_session launch  [--url URL]
    python -m core.browser_session capture [--match SUBSTRING] [--timeout S]
    python -m core.browser_session shot    [--out PATH] [--full]
    python -m core.browser_session status
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger(__name__)

CDP_PORT   = int(os.environ.get("SS_CDP_PORT", "9222"))
CDP        = f"http://127.0.0.1:{CDP_PORT}"
STATE_DIR  = Path(__file__).resolve().parent.parent / "state"
PROFILE    = STATE_DIR / "chrome-profile"
TOKEN_FILE = STATE_DIR / "captured_auth.json"
SHOT_DIR   = STATE_DIR / "screenshots"

_BROWSERS = ("chromium", "google-chrome-stable", "google-chrome", "brave")


# ---------------------------------------------------------------------------
# availability
# ---------------------------------------------------------------------------

def browser_binary() -> str | None:
    import shutil
    for b in _BROWSERS:
        if shutil.which(b):
            return b
    return None


def cdp_alive() -> bool:
    try:
        urllib.request.urlopen(f"{CDP}/json/version", timeout=2).read()
        return True
    except Exception:
        return False


def load_auth(max_age_s: int = 3600) -> dict | None:
    """Return a captured auth record, or None if absent or stale.

    Tokens of this kind are short-lived. Returning a stale one would produce a
    401 that looks exactly like a restrictive target policy, which is the single
    most dangerous false negative in this class of test, so we refuse instead.
    """
    if not TOKEN_FILE.exists():
        return None
    try:
        rec = json.loads(TOKEN_FILE.read_text())
    except Exception:
        return None
    age = time.time() - rec.get("captured_epoch", 0)
    if age > max_age_s:
        log.warning("browser_session.auth_stale", age_s=int(age))
        return None
    rec["age_s"] = int(age)
    return rec


# ---------------------------------------------------------------------------
# launch
# ---------------------------------------------------------------------------

def launch(url: str = "about:blank", wait_s: int = 60) -> bool:
    binary = browser_binary()
    if not binary:
        log.error("browser_session.no_browser", tried=_BROWSERS)
        return False
    if cdp_alive():
        log.info("browser_session.already_running", port=CDP_PORT)
        return True

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    PROFILE.mkdir(parents=True, exist_ok=True)
    cmd = [
        binary,
        f"--remote-debugging-port={CDP_PORT}",
        "--remote-allow-origins=*",
        f"--user-data-dir={PROFILE}",
        "--no-first-run",
        "--no-default-browser-check",
        url,
    ]
    subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True)
    for _ in range(wait_s):
        if cdp_alive():
            log.info("browser_session.up", port=CDP_PORT, binary=binary)
            return True
        time.sleep(1)
    log.error("browser_session.cdp_timeout", port=CDP_PORT)
    return False


# ---------------------------------------------------------------------------
# CDP plumbing
# ---------------------------------------------------------------------------

# Modern SPAs, Teams among them, issue their authenticated API calls from
# workers rather than the page. Attaching only to page targets sees nothing and
# looks exactly like "the client never made the request", so the capture default
# covers every target type that can own a fetch.
_NET_TARGETS = ("page", "iframe", "worker", "shared_worker", "service_worker")


def _targets(kinds: tuple[str, ...] = _NET_TARGETS) -> list[dict]:
    raw = urllib.request.urlopen(f"{CDP}/json/list", timeout=5).read()
    return [t for t in json.loads(raw)
            if t.get("type") in kinds and t.get("webSocketDebuggerUrl")]


async def _send(ws, mid: int, method: str, params: dict | None = None) -> dict:
    await ws.send(json.dumps({"id": mid, "method": method,
                              "params": params or {}}))
    while True:
        msg = json.loads(await ws.recv())
        if msg.get("id") == mid:
            return msg


# ---------------------------------------------------------------------------
# capture
# ---------------------------------------------------------------------------

_KEEP_HEADERS = {
    "authorization", "user-agent", "accept", "accept-language",
    "content-type", "x-ms-client-version", "x-clientinfo", "x-ms-client-request-id",
}


async def _watch_one(target: dict, match: str, out: list, deadline: float) -> None:
    import websockets
    try:
        async with websockets.connect(target["webSocketDebuggerUrl"],
                                      max_size=40 * 1024 * 1024,
                                      open_timeout=10) as ws:
            await ws.send(json.dumps({"id": 1, "method": "Network.enable"}))
            while time.time() < deadline and not out:
                try:
                    msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=2))
                except asyncio.TimeoutError:
                    continue
                if msg.get("method") != "Network.requestWillBeSent":
                    continue
                req = msg["params"]["request"]
                if match not in req.get("url", ""):
                    continue
                hdrs = {k: v for k, v in req.get("headers", {}).items()
                        if k.lower() in _KEEP_HEADERS}
                if not any(k.lower() == "authorization" for k in hdrs):
                    continue
                out.append({
                    "match":          match,
                    "sample_url":     req["url"],
                    "headers":        hdrs,
                    "captured_epoch": time.time(),
                    "captured_at":    time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                    time.gmtime()),
                })
                return
    except Exception as exc:
        log.debug("browser_session.watch_failed",
                  url=target.get("url", "?")[:80], error=str(exc))


async def capture_auth(match: str, timeout: int = 300) -> dict | None:
    """Borrow an Authorization header off any live request whose URL contains `match`."""
    if not cdp_alive():
        log.error("browser_session.cdp_down", port=CDP_PORT)
        return None
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    out: list[dict] = []
    deadline = time.time() + timeout
    while time.time() < deadline and not out:
        try:
            tg = _targets()
        except Exception as exc:
            log.error("browser_session.target_list_failed", error=str(exc))
            return None
        slice_end = min(deadline, time.time() + 15)
        await asyncio.gather(
            *[_watch_one(t, match, out, slice_end) for t in tg],
            return_exceptions=True,
        )
    if not out:
        log.warning("browser_session.no_match", match=match)
        return None
    rec = out[0]
    TOKEN_FILE.write_text(json.dumps(rec, indent=2))
    os.chmod(TOKEN_FILE, 0o600)
    log.info("browser_session.captured", match=match,
             url=rec["sample_url"][:80],
             bearer_len=len(rec["headers"].get("Authorization", "")))
    return rec


# ---------------------------------------------------------------------------
# screenshots
# ---------------------------------------------------------------------------

async def screenshot(out_path: Path | None = None, full_page: bool = True,
                     target_url_contains: str | None = None) -> Path | None:
    """Capture report-grade PNG evidence of whatever the operator has on screen.

    full_page captures beyond the viewport, which matters for evidence of long
    results pages. We do NOT redact: the operator reviews every screenshot
    before it reaches a deliverable, and silently altering evidence would be
    worse than capturing too much.
    """
    import websockets
    if not cdp_alive():
        log.error("browser_session.cdp_down", port=CDP_PORT)
        return None
    try:
        tg = _targets(("page",))
    except Exception as exc:
        log.error("browser_session.target_list_failed", error=str(exc))
        return None
    if target_url_contains:
        tg = [t for t in tg if target_url_contains in t.get("url", "")] or tg
    if not tg:
        log.error("browser_session.no_page_target")
        return None

    SHOT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = out_path or SHOT_DIR / f"shot_{time.strftime('%Y%m%d-%H%M%S')}.png"

    async with websockets.connect(tg[0]["webSocketDebuggerUrl"],
                                  max_size=80 * 1024 * 1024,
                                  open_timeout=10) as ws:
        await _send(ws, 1, "Page.enable")
        params: dict[str, Any] = {"format": "png"}
        if full_page:
            params["captureBeyondViewport"] = True
        resp = await _send(ws, 2, "Page.captureScreenshot", params)
        data = resp.get("result", {}).get("data")
        if not data:
            log.error("browser_session.screenshot_failed",
                      error=str(resp.get("error")))
            return None
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(base64.b64decode(data))

    log.info("browser_session.screenshot", path=str(out_path),
             bytes=out_path.stat().st_size, page=tg[0].get("url", "")[:80])
    return out_path


# ---------------------------------------------------------------------------
# Page driving — the primitives a scraping module needs
# ---------------------------------------------------------------------------

async def navigate(url: str, settle_s: float = 8.0) -> bool:
    """Point the active page at a URL and give it time to render.

    settle_s is deliberately generous. Several of the sites these modules read
    are single-page apps that answer the navigation instantly and then fill the
    result in afterwards, so reading too early returns the PREVIOUS query's
    result while looking perfectly successful.
    """
    import websockets
    if not cdp_alive():
        log.error("browser_session.cdp_down", port=CDP_PORT)
        return False
    tg = _targets(("page",))
    if not tg:
        log.error("browser_session.no_page_target")
        return False
    async with websockets.connect(tg[0]["webSocketDebuggerUrl"],
                                  max_size=32 * 1024 * 1024,
                                  open_timeout=10) as ws:
        await _send(ws, 1, "Page.enable")
        await _send(ws, 2, "Page.navigate", {"url": url})
    await asyncio.sleep(settle_s)
    log.info("browser_session.navigate", url=url[:100])
    return True


async def evaluate(expression: str, await_promise: bool = True) -> Any:
    """Run JavaScript in the active page and return the value.

    This is how a module reads a rendered result that has no API behind it.
    The expression runs with the operator's own logged-in session, so a module
    using it is acting as the operator and must be in an operator-assisted
    phase, never in an unattended one.
    """
    import websockets
    if not cdp_alive():
        return None
    tg = _targets(("page",))
    if not tg:
        return None
    async with websockets.connect(tg[0]["webSocketDebuggerUrl"],
                                  max_size=32 * 1024 * 1024,
                                  open_timeout=10) as ws:
        resp = await _send(ws, 1, "Runtime.evaluate", {
            "expression":     expression,
            "returnByValue":  True,
            "awaitPromise":   await_promise,
        })
    r = resp.get("result", {}).get("result", {})
    if r.get("subtype") == "error":
        log.warning("browser_session.eval_error", desc=str(r.get("description"))[:200])
        return None
    return r.get("value")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli() -> None:
    p = argparse.ArgumentParser(
        description="Operator-assisted browser session broker (CDP).")
    sub = p.add_subparsers(dest="cmd", required=True)

    l = sub.add_parser("launch", help="start a headed browser with CDP")
    l.add_argument("--url", default="about:blank")

    c = sub.add_parser("capture", help="borrow an Authorization header")
    c.add_argument("--match", default="/api/mt/",
                   help="substring the request URL must contain")
    c.add_argument("--timeout", type=int, default=300)

    s = sub.add_parser("shot", help="screenshot the active page")
    s.add_argument("--out", default=None)
    s.add_argument("--full", action="store_true", default=True)
    s.add_argument("--viewport", dest="full", action="store_false",
                   help="viewport only instead of full page")
    s.add_argument("--page", default=None, help="only a page whose URL contains this")

    sub.add_parser("status", help="report browser/CDP/token state")

    a = p.parse_args()

    if a.cmd == "launch":
        ok = launch(a.url)
        print("[+] CDP up on", CDP if ok else "(failed)")
        print("    profile:", PROFILE)

    elif a.cmd == "capture":
        print(f"[*] waiting for a request matching {a.match!r} "
              f"({a.timeout}s)")
        print("    trigger it in the browser now.")
        rec = asyncio.run(capture_auth(a.match, a.timeout))
        if not rec:
            raise SystemExit("[!] nothing captured")
        print(f"[+] {rec['sample_url'][:90]}")
        print(f"[+] bearer {len(rec['headers'].get('Authorization',''))} chars "
              f"-> {TOKEN_FILE}")

    elif a.cmd == "shot":
        path = asyncio.run(screenshot(Path(a.out) if a.out else None,
                                      full_page=a.full,
                                      target_url_contains=a.page))
        if not path:
            raise SystemExit("[!] screenshot failed")
        print("[+]", path)

    elif a.cmd == "status":
        b = browser_binary()
        rec = load_auth()
        print(f"browser binary : {b or 'NONE FOUND'}")
        print(f"CDP {CDP:<14}: {'up' if cdp_alive() else 'down'}")
        print(f"profile        : {PROFILE}")
        if rec:
            print(f"captured auth  : {rec['match']} "
                  f"({rec['age_s']}s old, usable)")
        elif TOKEN_FILE.exists():
            print("captured auth  : present but STALE, re-capture before testing")
        else:
            print("captured auth  : none")


if __name__ == "__main__":
    _cli()
