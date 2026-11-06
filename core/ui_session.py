"""
core/ui_session.py — read the browser UI, decide, and act as the UI.

WHY THIS EXISTS
---------------
core/browser_session.py brokers a token: it launches a headed browser, borrows
an Authorization header off a request the browser makes, and takes screenshots.
What it cannot do is tell you WHAT IS ON THE SCREEN. So every assisted run
degraded to the same shape: a human watches the window, decides whether the
session is live, triggers a request by hand, and only then starts the scanner.
If the session had quietly expired the module got a 401 and reported it as a
restrictive target policy, which is the worst false negative in this class of
test.

This module closes that gap. It reads a set of signals out of the live page,
classifies them into one state, and then either acts on that state itself or
tells the operator precisely what it is waiting for and blocks until it changes.
The result is a run that is unattended when the session is live, and pauses for
exactly as long as a password or an MFA approval takes when it is not.

THE STATE MACHINE
-----------------
    UNREACHABLE      no CDP, or no page target                -> fatal
    BLANK            about:blank or a dead tab                -> navigate
    SIGNED_OUT       a sign-in landing page                   -> navigate to app
    NEEDS_EMAIL      account picker or email field            -> OPERATOR
    NEEDS_PASSWORD   password field                           -> OPERATOR
    NEEDS_MFA        approve-request, OTC, number match       -> OPERATOR
    NEEDS_CONSENT    app permission consent screen            -> OPERATOR, never auto
    KMSI             "stay signed in?"                        -> auto-advance
    INTERSTITIAL     redirecting, loading, spinner            -> wait
    BLOCKED          AADSTS error, CA block, account locked   -> fatal, report code
    READY            the app itself is loaded and usable      -> proceed

WHAT IT WILL NOT DO
-------------------
  * It never types a password, a code, or an email address. Those are the
    operator's to enter, and a tool that fills them is a tool that stores them.
  * It never accepts a consent prompt. Consent grants an application standing
    permission against a real account, which is a decision with a lifetime far
    longer than this run.
  * It never claims a state it cannot see. An unrecognised page is reported as
    UNKNOWN with the signals attached, not optimistically treated as READY.

ACTING AS THE UI
----------------
Two paths, and the module uses both so they check each other.

  API path    the client's own bearer token is borrowed and the backend is
              queried directly. Fast, exact, and the response is machine
              readable. This is the primary path.

  UI path     the search box is typed into with real key events and the
              rendered result list is read back out of the DOM. Slower and
              markup-fragile, but it survives header drift, which has twice
              silently turned a true finding into a clean negative, and it
              produces a screenshot a client can look at.

A disagreement between the two paths is reported, never averaged. The API
saying a mailbox resolves while the UI shows nothing means the markup selectors
have moved. The reverse means the header set has drifted. Both are
actionable and neither is a result.

Nothing here touches target infrastructure. Teams lookups are served by
Microsoft and leave nothing in a target user's client.

CLI
---
    python -m core.ui_session state
    python -m core.ui_session wait   [--url URL] [--timeout S]
    python -m core.ui_session search "Jane Doe" [--screenshot PATH]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import time
import urllib.parse
from pathlib import Path
from typing import Any

import structlog

from core import browser_session as bs

log = structlog.get_logger(__name__)

# The app we drive. teams.cloud.microsoft is the current client host, and the
# older teams.microsoft.com redirects to it, so either is accepted as READY.
TEAMS_URL   = "https://teams.cloud.microsoft/"
TEAMS_HOSTS = ("teams.cloud.microsoft", "teams.microsoft.com")
LOGIN_HOSTS = ("login.microsoftonline.com", "login.microsoft.com",
               "login.live.com", "adfs")

# States that only a human can clear. Listed once so the waiter, the CLI and
# the modules cannot disagree about which they are.
OPERATOR_STATES = {"NEEDS_EMAIL", "NEEDS_PASSWORD", "NEEDS_MFA", "NEEDS_CONSENT"}
FATAL_STATES    = {"UNREACHABLE", "BLOCKED"}

# What the operator is told for each state. Specific, because "please sign in"
# in a terminal while a number-match prompt waits on a phone is not help.
OPERATOR_HINT = {
    "NEEDS_EMAIL":    "enter the tester account's email address in the browser window",
    "NEEDS_PASSWORD": "enter the tester account's password in the browser window",
    "NEEDS_MFA":      "approve the sign-in on your second factor "
                      "(check the browser for a number to match)",
    "NEEDS_CONSENT":  "an app consent prompt is showing. Read it and decide yourself. "
                      "This tool will not accept it for you",
}

# ---------------------------------------------------------------------------
# Signal collection
# ---------------------------------------------------------------------------

# Read once, classify in Python. Collecting raw signals rather than asking the
# page "are you logged in?" keeps the decision reviewable: every classification
# can be replayed from the signal dict in a log, which is how selector drift
# gets diagnosed after the fact instead of during the next engagement.
_SIGNAL_JS = r"""
(() => {
  const sel = (s) => { try { return document.querySelector(s); } catch (e) { return null; } };
  const vis = (el) => {
    if (!el) return false;
    const r = el.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) return false;
    const st = getComputedStyle(el);
    return st.visibility !== 'hidden' && st.display !== 'none';
  };
  const has = (s) => vis(sel(s));
  const txt = (document.body ? document.body.innerText : '') || '';
  return {
    href:   location.href,
    host:   location.host,
    title:  document.title || '',
    ready:  document.readyState,
    // Microsoft sign-in surface. ids have been stable for years; the
    // data-testid forms are the newer markup and are checked alongside.
    email:    has('#i0116') || has('input[name="loginfmt"]'),
    password: has('#i0118') || has('input[name="passwd"]'),
    otc:      has('#idTxtBx_SAOTCC_OTC') || has('input[name="otc"]'),
    approve:  has('#idDiv_SAOTCAS_Description') || has('#idRemoteNGC_DisplaySign'),
    kmsi:     has('#KmsiCheckboxField') || has('#idSIButton9') && /stay signed in/i.test(txt),
    consent:  has('#consentHeader') || /permissions requested|accept.*on behalf/i.test(txt),
    picker:   has('#tilesHolder') || has('#otherTileText'),
    err:      (sel('#passwordError') || sel('#usernameError') || sel('.alert-error')
                ? (sel('#passwordError') || sel('#usernameError') || sel('.alert-error')).innerText
                : ''),
    // Teams client surface. Several selectors because the search box has moved
    // between builds; the first that exists wins and is reported by name.
    search_sel: ['input[data-tid="search-input"]',
                 '#ms-searchux-input',
                 'input[placeholder*="Search"]',
                 'div[role="combobox"] input',
                 'input[type="search"]'].find(s => has(s)) || null,
    app_shell:  has('#app') || has('[data-tid="app-layout-area--main"]')
                  || has('[data-tid="left-rail"]'),
    aadsts:     (txt.match(/AADSTS\d+/) || [''])[0],
    // A short text sample, for the log only. Long enough to recognise an
    // unexpected page, short enough not to drag secrets into a log file.
    sample: txt.replace(/\s+/g, ' ').slice(0, 240),
  };
})()
"""


async def signals() -> dict | None:
    """Read the raw state signals out of the live page."""
    return await bs.evaluate(_SIGNAL_JS, await_promise=False)


def classify(sig: dict | None) -> tuple[str, dict]:
    """Map a signal dict to exactly one state. Pure, so it is testable."""
    if not sig:
        return "UNREACHABLE", {}
    host = (sig.get("host") or "").lower()
    href = (sig.get("href") or "").lower()

    # Hard blocks first. An AADSTS code on screen is a verdict, and continuing
    # to wait on one burns the operator's time for nothing.
    code = sig.get("aadsts") or ""
    if code and code not in ("AADSTS50058",):   # 50058 = not signed in yet, normal
        return "BLOCKED", {"aadsts": code, "error": sig.get("err", "")}
    if sig.get("err"):
        return "BLOCKED", {"error": sig["err"]}

    if href.startswith("about:") or not host:
        return "BLANK", {}

    # Consent before the other login states: it can appear after a successful
    # authentication, and auto-advancing past it is the one irreversible thing
    # on this screen.
    if sig.get("consent"):
        return "NEEDS_CONSENT", {}
    if sig.get("otc") or sig.get("approve"):
        return "NEEDS_MFA", {}
    if sig.get("password"):
        return "NEEDS_PASSWORD", {}
    if sig.get("email") or sig.get("picker"):
        return "NEEDS_EMAIL", {}
    if sig.get("kmsi"):
        return "KMSI", {}

    if any(h in host for h in TEAMS_HOSTS):
        if sig.get("search_sel"):
            return "READY", {"search_sel": sig["search_sel"]}
        if sig.get("app_shell") or sig.get("ready") != "complete":
            return "INTERSTITIAL", {"why": "app shell up, search box not rendered yet"}
        return "INTERSTITIAL", {"why": "teams host, nothing recognised yet"}

    if any(h in host for h in LOGIN_HOSTS):
        return "SIGNED_OUT", {}

    return "UNKNOWN", {"sample": sig.get("sample", "")[:240]}


async def state() -> tuple[str, dict, dict]:
    """Current state, its detail, and the signals it was derived from."""
    sig = await signals()
    st, detail = classify(sig)
    return st, detail, (sig or {})


# ---------------------------------------------------------------------------
# Auto-advance
# ---------------------------------------------------------------------------

async def _click(selector: str) -> bool:
    ok = await bs.evaluate(
        f"(() => {{ const e = document.querySelector({selector!r});"
        f" if (!e) return false; e.click(); return true; }})()",
        await_promise=False)
    return bool(ok)


async def _advance(st: str, sig: dict) -> bool:
    """Handle the states this module is allowed to clear by itself."""
    if st == "BLANK" or st == "SIGNED_OUT":
        await bs.navigate(TEAMS_URL, settle_s=6.0)
        return True
    if st == "KMSI":
        # "Stay signed in?" Answering yes is what makes the profile durable,
        # and it grants nothing that the completed sign-in has not already
        # granted. This is the only prompt we answer.
        for s in ("#idSIButton9", "#idBtn_Back"):
            if await _click(s):
                log.info("ui_session.kmsi_answered", button=s)
                await asyncio.sleep(4)
                return True
    return False


# ---------------------------------------------------------------------------
# The waiter
# ---------------------------------------------------------------------------

async def ensure_ready(timeout: int = 900, poll: float = 3.0,
                       url: str = TEAMS_URL,
                       announce: Any = None) -> dict:
    """Block until the app is usable, advancing what we can and asking for the rest.

    timeout is generous by default. A password plus a push approval on a phone
    that is in another room is minutes, not seconds, and timing that out leaves
    the operator with a failed run and no idea why.
    """
    say = announce or (lambda m: print(m, flush=True))
    if not bs.cdp_alive():
        if not bs.launch(url):
            return {"ready": False, "state": "UNREACHABLE",
                    "error": "no browser with CDP; run: python -m core.ui_session launch"}
        await asyncio.sleep(4)

    deadline = time.time() + timeout
    last = None
    waiting_since = None

    while time.time() < deadline:
        st, detail, sig = await state()

        if st != last:
            log.info("ui_session.state", state=st, host=sig.get("host", ""), **detail)
            last = st
            waiting_since = time.time() if st in OPERATOR_STATES else None
            if st in OPERATOR_STATES:
                say(f"\n[!] waiting for you: {OPERATOR_HINT[st]}")
                say(f"    window: {sig.get('href', '')[:110]}")
                say(f"    this run resumes by itself once the page moves on.")

        if st == "READY":
            return {"ready": True, "state": st, "search_sel": detail.get("search_sel"),
                    "href": sig.get("href", "")}

        if st == "BLOCKED":
            return {"ready": False, "state": st, **detail,
                    "error": "sign-in is blocked, not pending. "
                             + (detail.get("aadsts") or detail.get("error") or "")}

        if st == "UNREACHABLE":
            return {"ready": False, "state": st, "error": "page is not readable over CDP"}

        if st == "UNKNOWN":
            # Not fatal: an unrecognised interstitial is common. But it is
            # logged with its text sample every time, because a silent loop here
            # is how selector drift hides.
            log.warning("ui_session.unknown_page", sample=detail.get("sample", ""))

        if await _advance(st, sig):
            continue

        if st in OPERATOR_STATES and waiting_since:
            waited = int(time.time() - waiting_since)
            if waited and waited % 60 == 0:
                say(f"    still waiting ({waited // 60} min): {OPERATOR_HINT[st]}")

        await asyncio.sleep(poll)

    return {"ready": False, "state": last or "UNKNOWN",
            "error": f"not ready within {timeout}s"}


# ---------------------------------------------------------------------------
# The people picker — the only surface that fires externalsearchv3
# ---------------------------------------------------------------------------

# MEASURED 2026-10-12, and it cost a whole assisted run. The GLOBAL search bar
# (#ms-searchux-input) is served by SubstrateSearch. It never touches
# /api/mt/.../externalsearchv3, so typing into it produces no token to borrow
# and no external resolution to read. The endpoint fires from ONE place: the
# "To:" people picker of a new chat, and only when the typed string is shaped
# like an address, because that is what makes the client attempt a cross-tenant
# lookup rather than a directory search.
#
# So the nudge and the UI evidence both have to go through the picker. Driving
# the global bar was the defect that made a self-driving run return "skipped".
# MEASURED 2026-10-12 against a live client: the app pane decides which markup
# exists. A client sitting on Calendar has NO new-chat button and NO people
# picker anywhere in the DOM, and its search input is data-tid AUTOSUGGEST_INPUT
# rather than #ms-searchux-input. So clicking our way to the picker means
# guessing at markup that differs per pane and per build.
#
# The deep link avoids all of it. It is Microsoft's own documented route, it
# puts the client on the chat composer with the address already in the "To:"
# field, and resolving an address the tenant has never seen is exactly the
# cross-tenant lookup we want to trigger. No selectors involved.
CHAT_DEEPLINK = "https://teams.cloud.microsoft/l/chat/0/0?users={addr}"

NEW_CHAT_SELS = (
    '[data-tid="new-conversation-button"]',
    'button[data-tid="newChatButton"]',
    '[data-tid="new-chat-button"]',
    'button[aria-label*="New chat" i]',
    'button[title*="New chat" i]',
)
PICKER_SELS = (
    '[data-tid="people-picker-input"]',
    'input[data-tid="mentions-input"]',
    'div[data-tid="people-picker"] input',
    'input[aria-label*="To:" i]',
    'input[placeholder*="Enter name" i]',
    'input[placeholder*="name, email" i]',
)

# An invented address on a domain that is reserved by RFC 2606. It is
# email-shaped, so the client attempts an external lookup and we get our
# token, and it cannot resolve for anyone, so the nudge asserts nothing about
# any real tenant and sends no real target's data anywhere.
NUDGE_ADDRESS = "zzq9xnotreal99@example.com"


async def _first_present(selectors: tuple[str, ...]) -> str | None:
    js = ("(() => { const c = %s;"
          " const vis = e => { if(!e) return false; const r = e.getBoundingClientRect();"
          " if (r.width===0 && r.height===0) return false; const s = getComputedStyle(e);"
          " return s.visibility!=='hidden' && s.display!=='none'; };"
          " for (const s of c) { try { if (vis(document.querySelector(s))) return s; }"
          " catch(e){} } return null; })()" % json.dumps(list(selectors)))
    return await bs.evaluate(js, await_promise=False)


async def open_picker(timeout: float = 20.0) -> dict:
    """Get a usable "To:" people picker on screen, opening a new chat if needed."""
    sel = await _first_present(PICKER_SELS)
    if sel:
        return {"ok": True, "selector": sel, "opened": False}

    btn = await _first_present(NEW_CHAT_SELS)
    if not btn:
        return {"ok": False, "error": "no new-chat button found; the client markup "
                                      "has moved. Update NEW_CHAT_SELS"}
    if not await _click(btn):
        return {"ok": False, "error": f"click on {btn} did nothing"}

    deadline = time.time() + timeout
    while time.time() < deadline:
        await asyncio.sleep(1.0)
        sel = await _first_present(PICKER_SELS)
        if sel:
            log.info("ui_session.picker_open", via=btn, selector=sel)
            return {"ok": True, "selector": sel, "opened": True}
    return {"ok": False, "error": "new chat opened but no picker input appeared; "
                                  "update PICKER_SELS"}


async def picker_search(address: str, settle_s: float = 6.0,
                        read_results: bool = True) -> dict:
    """Type an address into the "To:" picker. This is what fires externalsearchv3."""
    st, detail, _ = await state()
    if st != "READY":
        return {"ok": False, "state": st, "error": "app not ready"}

    pk = await open_picker()
    if not pk.get("ok"):
        return {"ok": False, "state": st, **pk}
    sel = pk["selector"]

    res = await bs.evaluate(f"({_SET_VALUE_JS})({sel!r}, {address!r})",
                            await_promise=False)
    if res != "ok":
        return {"ok": False, "state": st,
                "error": f"could not type into {sel}: {res}"}

    await asyncio.sleep(settle_s)
    if not read_results:
        return {"ok": True, "state": st, "query": address, "selector": sel}

    read = await bs.evaluate(_READ_RESULTS_JS, await_promise=False) or {}
    out = {
        "ok": True, "state": st, "query": address, "selector": sel,
        "surface": "people_picker",
        "results": read.get("results", []),
        "empty_state": bool(read.get("empty_state")),
    }
    out["conclusive"] = bool(out["results"]) or out["empty_state"]
    log.info("ui_session.picker_search", address=address,
             n=len(out["results"]), conclusive=out["conclusive"])
    return out



async def nudge_deeplink(address: str, settle_s: float = 9.0) -> dict:
    """Open the chat composer on an address via the documented deep link.

    This is the primary way to make the client perform an external resolution,
    because it does not depend on any selector. The address lands in the "To:"
    field and the client resolves it cross-tenant, which is the request whose
    header we borrow.
    """
    url = CHAT_DEEPLINK.format(addr=urllib.parse.quote(address))
    ok = await bs.navigate(url, settle_s=settle_s)
    if not ok:
        return {"ok": False, "error": "navigate failed", "url": url}
    st, _, sig = await state()
    log.info("ui_session.nudge_deeplink", address=address, state=st,
             host=sig.get("host", ""))
    return {"ok": st in ("READY", "INTERSTITIAL"), "state": st, "url": url,
            "surface": "deeplink"}


async def resolve_external(address: str, settle_s: float = 9.0) -> dict:
    """Make the client resolve one external address, and read what it shows.

    Deep link first, DOM picker second. Both paths are reported by name, so a
    result can be traced to the surface that produced it rather than to "the
    UI", which is what makes selector drift diagnosable.
    """
    d = await nudge_deeplink(address, settle_s=settle_s)
    if d.get("ok"):
        read = await bs.evaluate(_READ_RESULTS_JS, await_promise=False) or {}
        out = {"ok": True, "query": address, "surface": "deeplink",
               "results": read.get("results", []),
               "empty_state": bool(read.get("empty_state"))}
        out["conclusive"] = bool(out["results"]) or out["empty_state"]
        if out["conclusive"]:
            return out
        log.info("ui_session.deeplink_inconclusive", address=address,
                 note="falling back to the DOM people picker")

    pk = await picker_search(address, settle_s=settle_s)
    pk.setdefault("surface", "people_picker")
    return pk


# ---------------------------------------------------------------------------
# Token lifecycle
# ---------------------------------------------------------------------------

async def refresh_token(match: str = "/api/mt/", timeout: int = 120,
                        nudge: str | None = None) -> dict | None:
    """Make the client issue an authenticated request, then borrow its header.

    The nudge matters. capture_auth only sees a request that actually happens,
    so waiting passively for one is waiting for the operator to type something.
    Typing a harmless query ourselves produces the request on demand, which is
    what turns an assisted step into an unattended one.
    """
    ready = await ensure_ready()
    if not ready.get("ready"):
        return None
    cap = asyncio.create_task(bs.capture_auth(match, timeout))
    await asyncio.sleep(1.5)
    # Through the people picker. The global search bar is SubstrateSearch and
    # never issues the request we are trying to borrow a header from.
    addr = nudge or NUDGE_ADDRESS
    nudged = await nudge_deeplink(addr, settle_s=9.0)
    if not nudged.get("ok"):
        # Deep link did not land. Try the picker before giving up, since a
        # client already sitting on Chat has one.
        log.warning("ui_session.deeplink_nudge_failed", **{
            k: v for k, v in nudged.items() if k in ("error", "state")})
        nudged = await picker_search(addr, settle_s=6.0, read_results=False)
    if not nudged.get("ok"):
        log.error("ui_session.nudge_failed", **{k: v for k, v in nudged.items()
                                               if k in ("error", "state")})
    rec = await cap
    if rec:
        log.info("ui_session.token_refreshed",
                 bearer_len=len(rec["headers"].get("Authorization", "")))
    return rec


# ---------------------------------------------------------------------------
# Acting as the UI
# ---------------------------------------------------------------------------

# React controlled inputs ignore a plain `el.value = x`, because the framework
# re-renders from its own state and overwrites it. Going through the native
# property setter and then dispatching the events React listens for is what
# makes the component see the change. Learned by watching a search box silently
# keep its previous query while the DOM claimed the new one.
_SET_VALUE_JS = r"""
(sel, text) => {
  const el = document.querySelector(sel);
  if (!el) return 'no-element';
  el.focus();
  const proto = el instanceof HTMLTextAreaElement
    ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  const setter = Object.getOwnPropertyDescriptor(proto, 'value').set;
  setter.call(el, '');
  el.dispatchEvent(new Event('input', {bubbles: true}));
  setter.call(el, text);
  el.dispatchEvent(new Event('input', {bubbles: true}));
  el.dispatchEvent(new Event('change', {bubbles: true}));
  return 'ok';
}
"""

# Read the rendered people results. Keyed on data-tid attributes rather than
# class names, since class names are build-generated and change every release.
_READ_RESULTS_JS = r"""
(() => {
  const out = [];
  const seen = new Set();
  const sels = ['[data-tid="search-result-item"]',
                '[data-tid^="people-picker-"]',
                '[role="option"]',
                '[role="listbox"] [role="option"]',
                '[data-tid="suggestion-item"]'];
  for (const s of sels) {
    let nodes;
    try { nodes = document.querySelectorAll(s); } catch (e) { continue; }
    for (const n of nodes) {
      const t = (n.innerText || '').replace(/\s+/g, ' ').trim();
      if (!t || seen.has(t)) continue;
      seen.add(t);
      out.push({text: t.slice(0, 200), via: s});
    }
    if (out.length) break;
  }
  const body = (document.body ? document.body.innerText : '') || '';
  return {
    results: out,
    // Teams renders a distinct empty state. Telling "no match" apart from
    // "the query never ran" is the whole point of reading this.
    empty_state: /no results|we couldn't find|nothing here/i.test(body),
  };
})()
"""


async def ui_search(query: str, settle_s: float = 6.0,
                    read_results: bool = True) -> dict:
    """Type a query into the app's own search box and read what it renders."""
    st, detail, sig = await state()
    if st != "READY":
        return {"ok": False, "state": st, "error": "app not ready to search"}
    sel = detail.get("search_sel")
    if not sel:
        return {"ok": False, "state": st, "error": "no search box selector matched"}

    res = await bs.evaluate(
        f"({_SET_VALUE_JS})({sel!r}, {query!r})", await_promise=False)
    if res != "ok":
        return {"ok": False, "state": st, "error": f"could not type into {sel}: {res}"}

    await asyncio.sleep(settle_s)
    if not read_results:
        return {"ok": True, "state": st, "query": query, "selector": sel}

    read = await bs.evaluate(_READ_RESULTS_JS, await_promise=False) or {}
    out = {
        "ok":          True,
        "state":       st,
        "query":       query,
        "selector":    sel,
        "results":     read.get("results", []),
        "empty_state": bool(read.get("empty_state")),
    }
    # An empty list with no empty-state banner is not a negative result, it is
    # an unread page. Saying so stops a silent false negative.
    out["conclusive"] = bool(out["results"]) or out["empty_state"]
    log.info("ui_session.ui_search", query=query,
             n=len(out["results"]), conclusive=out["conclusive"])
    return out


# ---------------------------------------------------------------------------
# Evidence framing
# ---------------------------------------------------------------------------

# A viewport screenshot of a signed-in Teams window contains the operator's own
# chat list, the names of everyone they have spoken to recently, and whatever
# conversation is open behind the search panel. None of that belongs in a client
# deliverable, and redacting it afterwards is work that will eventually be
# skipped. So evidence is clipped to the result panel at capture time.
#
# The box is the union of the rendered result rows plus the search input, which
# is what makes the image self-explanatory: the reader sees the query and the
# answer, and nothing else.
_RESULT_BOX_JS = r"""
(() => {
  // Evidence rule: a capture may contain ONLY the address we typed and the
  // client's answer about it. The chat list, the app rail, the left nav and any
  // conversation behind the composer are the operator's own data and must never
  // reach a client deliverable. So we anchor on the "To:" field, clamp the left
  // edge to it, and add only nodes that sit to its right.
  const vis = (el) => {
    if (!el) return null;
    const r = el.getBoundingClientRect();
    if (r.width <= 0 || r.height <= 0) return null;
    if (r.bottom < 0 || r.top > window.innerHeight) return null;
    return r;
  };
  // 1. the address field: the deep link focuses it, so prefer the active element
  const inputSels = ['[data-tid="chat-new-people-picker"] input',
                     'input[data-tid="people-picker-input"]',
                     '[data-tid="new-chat-people-picker"] input',
                     '[role="combobox"]',
                     'input[data-tid="search-input"]',
                     '#ms-searchux-input'];
  let anchor = null;
  const ae = document.activeElement;
  if (ae && /^(INPUT|TEXTAREA)$/.test(ae.tagName) && vis(ae)) anchor = ae;
  if (!anchor) {
    for (const s of inputSels) {
      let el; try { el = document.querySelector(s); } catch (e) { continue; }
      if (vis(el)) { anchor = el; break; }
    }
  }
  if (!anchor) return null;
  const a = anchor.getBoundingClientRect();
  const boxes = [a];
  const left = a.left;              // hard left wall: nothing further left ships

  // 2. the answer: result rows, or the "we couldn't find any matches" line
  const itemSels = ['[data-tid="people-picker-list"] [role="option"]',
                    '[role="listbox"] [role="option"]',
                    '[data-tid="search-result-item"]',
                    '[data-tid^="people-picker-"]',
                    '[data-tid="suggestion-item"]',
                    '[role="option"]'];
  let found = false;
  for (const s of itemSels) {
    let nodes; try { nodes = document.querySelectorAll(s); } catch (e) { continue; }
    if (!nodes.length) continue;
    nodes.forEach((n) => { const r = vis(n); if (r && r.left >= left - 4) boxes.push(r); });
    if (boxes.length > 1) { found = true; break; }
  }
  if (!found) {
    const re = /couldn.?t find any matches|no results found|we didn.?t find/i;
    const walk = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT);
    let n;
    while ((n = walk.nextNode())) {
      if (n.children.length) continue;                 // leaf nodes only
      if (!re.test(n.textContent || '')) continue;
      const r = vis(n);
      if (r && r.left >= left - 4 && Math.abs(r.top - a.bottom) < 260) {
        boxes.push(r); found = true; break;
      }
    }
  }
  if (!found) return null;   // no answer on screen means nothing to evidence

  const x1 = Math.max(left, Math.min(...boxes.map(b => b.left)));
  const y1 = Math.min(...boxes.map(b => b.top));
  const x2 = Math.max(...boxes.map(b => b.right));
  const y2 = Math.max(...boxes.map(b => b.bottom));
  return {x: x1, y: y1, width: x2 - x1, height: y2 - y1,
          left_wall: left, answered: found,
          dpr: window.devicePixelRatio || 1,
          vw: window.innerWidth, vh: window.innerHeight};
})()
"""


async def shot_results(out_path: Path, pad: int = 14) -> dict:
    """Screenshot ONLY the search input and its result rows.

    Returns the box used, so a run can prove in its own log that the capture was
    clipped rather than full-frame. If the box cannot be computed we do NOT fall
    back to a viewport capture: a wide screenshot of someone's mailbox is worse
    than a missing figure, and a missing figure is visible.
    """
    import websockets
    if not bs.cdp_alive():
        return {"ok": False, "error": "cdp down"}
    box = await bs.evaluate(_RESULT_BOX_JS, await_promise=False)
    if not box:
        log.warning("ui_session.no_result_box",
                    note="refusing a full-frame capture of a signed-in client")
        return {"ok": False, "error": "no address field with a visible answer; "
                                      "capture skipped rather than capturing the "
                                      "whole window"}

    # pad may never breach the left wall, that is where the chat list lives
    x = max(float(box.get("left_wall", box["x"])), box["x"] - pad)
    y = max(0.0, box["y"] - pad)
    w = min(box["vw"] - x, box["width"] + pad * 2)
    h = min(box["vh"] - y, box["height"] + pad * 2)

    tg = bs._targets(("page",))
    if not tg:
        return {"ok": False, "error": "no page target"}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    async with websockets.connect(tg[0]["webSocketDebuggerUrl"],
                                  max_size=80 * 1024 * 1024,
                                  open_timeout=10) as ws:
        await bs._send(ws, 1, "Page.enable")
        resp = await bs._send(ws, 2, "Page.captureScreenshot", {
            "format": "png",
            "clip": {"x": x, "y": y, "width": w, "height": h, "scale": 1},
        })
    data = resp.get("result", {}).get("data")
    if not data:
        return {"ok": False, "error": str(resp.get("error"))[:200]}
    import base64
    out_path.write_bytes(base64.b64decode(data))
    log.info("ui_session.shot_results", path=str(out_path),
             box=[round(x), round(y), round(w), round(h)],
             bytes=out_path.stat().st_size)
    return {"ok": True, "path": str(out_path),
            "clip": {"x": round(x), "y": round(y),
                     "width": round(w), "height": round(h)}}


async def ui_search_many(queries: list[str], delay: float = 2.5,
                         shot_dir: Path | None = None) -> list[dict]:
    """Run the UI path over a list of queries, with evidence if asked."""
    out = []
    for i, q in enumerate(queries, 1):
        r = await ui_search(q)
        if shot_dir and r.get("ok"):
            shot_dir.mkdir(parents=True, exist_ok=True)
            safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in q)[:60]
            shot = await shot_results(shot_dir / f"ui_search_{i:03d}_{safe}.png")
            r["screenshot"] = shot.get("path", "")
            r["screenshot_error"] = shot.get("error")
        out.append(r)
        await asyncio.sleep(delay)
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli() -> None:
    p = argparse.ArgumentParser(description="Read the browser UI and act as it.")
    sub = p.add_subparsers(dest="cmd", required=True)

    lp = sub.add_parser("launch", help="start a headed browser on the Teams client")
    lp.add_argument("--url", default=TEAMS_URL)

    sub.add_parser("state", help="print the current UI state and its signals")

    w = sub.add_parser("wait", help="block until the app is usable")
    w.add_argument("--url", default=TEAMS_URL)
    w.add_argument("--timeout", type=int, default=900)

    s = sub.add_parser("search", help="type a query into the app and read results")
    s.add_argument("query")
    s.add_argument("--screenshot", default=None)

    t = sub.add_parser("token", help="make the client issue a request and borrow its header")
    t.add_argument("--match", default="/api/mt/")
    t.add_argument("--timeout", type=int, default=120)

    a = p.parse_args()

    if a.cmd == "launch":
        print("[+] CDP up" if bs.launch(a.url) else "[-] failed to start a browser")
        print("    profile:", bs.PROFILE)
        return

    if a.cmd == "state":
        st, detail, sig = asyncio.run(state())
        print(f"state: {st}")
        for k, v in detail.items():
            print(f"  {k}: {v}")
        print("signals:")
        print(json.dumps(sig, indent=2)[:2000])
        return

    if a.cmd == "wait":
        r = asyncio.run(ensure_ready(timeout=a.timeout, url=a.url))
        print(("[+] ready" if r.get("ready") else "[-] not ready") + f": {r}")
        return

    if a.cmd == "search":
        async def go():
            r = await ensure_ready()
            if not r.get("ready"):
                return r
            res = await ui_search(a.query)
            if a.screenshot:
                res["screenshot"] = await shot_results(Path(a.screenshot))
            return res
        out = asyncio.run(go())
        print(json.dumps(out, indent=2))
        return

    if a.cmd == "token":
        rec = asyncio.run(refresh_token(a.match, a.timeout))
        if not rec:
            print("[-] no token captured")
            return
        print(f"[+] captured from {rec['sample_url'][:90]}")
        print(f"    bearer length {len(rec['headers'].get('Authorization',''))}, "
              f"stored 0600 at {bs.TOKEN_FILE}")


if __name__ == "__main__":
    _cli()
