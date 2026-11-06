"""
core/ms_identity.py — durable Microsoft 365 tester identity for the pipeline.

THE PROBLEM
-----------
Several external tests need a Microsoft token that only an interactive, MFA-gated
sign-in can produce. Doing that by hand once per engagement is not automation, it
is a chore with a human in the critical path of every run.

THE SHAPE OF THE FIX
--------------------
Authenticate ONCE with the OAuth device authorization grant, keep the refresh
token, and mint everything else silently from then on. Entra refresh tokens for a
public client are valid 90 days and slide forward on every use, so in steady
state a tester signs in a few times a year and every scan in between is fully
unattended.

The chain, all of it scripted after that first sign-in:

    device code  ->  refresh token           (interactive, once per ~90 days)
    refresh token -> AAD access token        (aud: api.spaces.skype.com)
    access token  -> Skype token             (POST /api/authsvc/v1.0/authz)
    Skype token   -> /api/mt/ Teams queries  (what the modules actually use)

Device code is chosen over a browser profile deliberately. It needs no browser on
the scanning host, survives headless servers and CI, and the operator can
complete it from a phone. The CDP browser broker in core/browser_session.py
remains as the fallback for the case where Conditional Access blocks the device
code grant, which is an increasingly common and entirely correct hardening.

WE ARE THE TESTER, NOT THE TARGET
---------------------------------
This authenticates OUR tenant identity. Target tenants are then queried
cross-tenant, exactly as any internet party could. Never put a target credential
in here; that would measure something else entirely and is almost never in scope.

CREDENTIAL HANDLING — READ THIS
-------------------------------
A stored refresh token is a real, long-lived credential for a real corporate
identity. Treat the token store as you would an SSH private key.

  * state/ms_identity.json is written 0600 and state/ is gitignored.
  * Set SS_TOKEN_KEY to encrypt the store at rest (Fernet). Without it the file
    is plaintext on disk and the module says so loudly rather than pretending
    otherwise.
  * Nothing from here is ever written to a report. Only test outcomes are.
  * `logout` deletes the store locally. It does NOT revoke server-side; to kill
    a leaked token do that in Entra (revoke sign-in sessions for the user).

CLI
---
    python -m core.ms_identity login [--tenant T] [--scope S]
    python -m core.ms_identity status
    python -m core.ms_identity token [--skype]
    python -m core.ms_identity logout
"""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

import httpx
import structlog

log = structlog.get_logger(__name__)

STATE_DIR = Path(__file__).resolve().parent.parent / "state"
STORE     = STATE_DIR / "ms_identity.json"

# First-party Microsoft Teams public client. A public client needs no secret,
# which is why a device code grant works at all.
TEAMS_CLIENT = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
SKYPE_SCOPE  = "https://api.spaces.skype.com/.default offline_access openid profile"
GRAPH_SCOPE  = "https://graph.microsoft.com/.default offline_access openid profile"

_AUTHZ   = "https://teams.microsoft.com/api/authsvc/v1.0/authz"
_DEVCODE = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode"
_TOKEN   = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
_TIMEOUT = 30

# Mint a new access token a minute before the old one lapses. A token that
# expires mid-run produces an HTTP 401 that looks exactly like a target
# restricting access, which is the worst false negative in this class of test.
_SKEW = 60


# ---------------------------------------------------------------------------
# store
# ---------------------------------------------------------------------------

def _fernet():
    key = os.environ.get("SS_TOKEN_KEY")
    if not key:
        return None
    try:
        from cryptography.fernet import Fernet
        return Fernet(key.encode() if isinstance(key, str) else key)
    except Exception as exc:
        log.warning("ms_identity.bad_token_key", error=str(exc))
        return None


def _read_store() -> dict:
    if not STORE.exists():
        return {}
    raw = STORE.read_bytes()
    f = _fernet()
    if f:
        try:
            raw = f.decrypt(raw)
        except Exception:
            log.error("ms_identity.decrypt_failed",
                      hint="SS_TOKEN_KEY does not match the stored data")
            return {}
    try:
        return json.loads(raw)
    except Exception:
        # Written encrypted, now read without a key.
        log.error("ms_identity.store_unreadable",
                  hint="store looks encrypted; set SS_TOKEN_KEY")
        return {}


def _write_store(data: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(data, indent=2).encode()
    f = _fernet()
    if f:
        raw = f.encrypt(raw)
    else:
        log.warning("ms_identity.plaintext_store",
                    path=str(STORE),
                    hint="set SS_TOKEN_KEY to encrypt the refresh token at rest")
    STORE.write_bytes(raw)
    os.chmod(STORE, 0o600)


# ---------------------------------------------------------------------------
# interactive sign-in, once
# ---------------------------------------------------------------------------

def login(tenant: str = "organizations", scope: str = SKYPE_SCOPE,
          client_id: str = TEAMS_CLIENT, quiet: bool = False) -> bool:
    """Device authorization grant. Blocks until the operator completes it."""
    with httpx.Client(timeout=_TIMEOUT) as c:
        r = c.post(_DEVCODE.format(tenant=tenant),
                   data={"client_id": client_id, "scope": scope})
        if r.status_code != 200:
            log.error("ms_identity.devicecode_failed",
                      status=r.status_code, body=r.text[:300])
            return False
        d = r.json()

        if not quiet:
            print()
            print("  " + "=" * 64)
            print(f"  Open   {d['verification_uri']}")
            print(f"  Code   {d['user_code']}")
            print("  " + "=" * 64)
            print("  Sign in with the TESTER account (ours, never the target).")
            print(f"  Expires in {d['expires_in'] // 60} minutes.")
            print()

        interval = int(d.get("interval", 5))
        deadline = time.time() + int(d.get("expires_in", 900))
        while time.time() < deadline:
            time.sleep(interval)
            t = c.post(_TOKEN.format(tenant=tenant), data={
                "client_id":   client_id,
                "grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": d["device_code"],
            })
            body = t.json()
            if t.status_code == 200:
                _save_tokens(body, tenant, scope, client_id)
                log.info("ms_identity.login_ok", tenant=tenant,
                         upn=_upn(body.get("access_token", "")))
                if not quiet:
                    print(f"  [+] signed in as {_upn(body.get('access_token','')) or 'unknown'}")
                return True
            err = body.get("error")
            if err == "authorization_pending":
                continue
            if err == "slow_down":
                interval += 5
                continue
            # expired_token, access_denied, or a Conditional Access block.
            log.error("ms_identity.login_failed", error=err,
                      description=(body.get("error_description") or "")[:200])
            if not quiet:
                print(f"  [!] {err}: {(body.get('error_description') or '')[:200]}")
                if err == "invalid_grant":
                    print("  [i] if this is a Conditional Access block on the device")
                    print("      code grant, that is correct hardening. Fall back to")
                    print("      python -m core.browser_session")
            return False
    log.error("ms_identity.login_timeout")
    return False


def _save_tokens(body: dict, tenant: str, scope: str, client_id: str) -> None:
    store = _read_store()
    store.update({
        "tenant":        tenant,
        "client_id":     client_id,
        "scope":         scope,
        "refresh_token": body.get("refresh_token"),
        "access_token":  body.get("access_token"),
        "expires_at":    time.time() + int(body.get("expires_in", 3600)),
        "upn":           _upn(body.get("access_token", "")),
        "obtained_at":   time.time(),
    })
    _write_store(store)


def _upn(jwt: str) -> str | None:
    """Best-effort UPN from an access token, for operator feedback only.

    We never make a security decision on an unverified JWT body. This is a label
    so a human can confirm which identity is signed in.
    """
    import base64
    try:
        p = jwt.split(".")[1]
        p += "=" * (-len(p) % 4)
        claims = json.loads(base64.urlsafe_b64decode(p))
        return claims.get("upn") or claims.get("preferred_username")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# silent, every run after that
# ---------------------------------------------------------------------------

def access_token(force: bool = False) -> str | None:
    """A valid AAD access token, refreshed silently when needed."""
    store = _read_store()
    if not store.get("refresh_token"):
        return None
    if (not force and store.get("access_token")
            and time.time() < store.get("expires_at", 0) - _SKEW):
        return store["access_token"]

    with httpx.Client(timeout=_TIMEOUT) as c:
        r = c.post(_TOKEN.format(tenant=store.get("tenant", "organizations")), data={
            "client_id":     store.get("client_id", TEAMS_CLIENT),
            "grant_type":    "refresh_token",
            "refresh_token": store["refresh_token"],
            "scope":         store.get("scope", SKYPE_SCOPE),
        })
    body = r.json()
    if r.status_code != 200:
        # The 90-day window has closed, or an admin revoked sessions. Either way
        # the fix is a human, so say so instead of returning something unusable.
        log.error("ms_identity.refresh_failed",
                  error=body.get("error"),
                  description=(body.get("error_description") or "")[:200],
                  hint="re-run: python -m core.ms_identity login")
        return None
    _save_tokens(body, store.get("tenant", "organizations"),
                 store.get("scope", SKYPE_SCOPE),
                 store.get("client_id", TEAMS_CLIENT))
    log.info("ms_identity.refreshed")
    return body.get("access_token")


def skype_token(force: bool = False) -> str | None:
    """Mint the Skype token the Teams /api/mt/ endpoints actually want.

    Cached alongside the access token because minting it is a second round trip
    and these run inside rate-limited scan loops.
    """
    store = _read_store()
    if (not force and store.get("skype_token")
            and time.time() < store.get("skype_expires_at", 0) - _SKEW):
        return store["skype_token"]

    at = access_token()
    if not at:
        return None
    with httpx.Client(timeout=_TIMEOUT) as c:
        r = c.post(_AUTHZ, headers={"Authorization": f"Bearer {at}"})
    if r.status_code != 200:
        log.error("ms_identity.skypetoken_failed",
                  status=r.status_code, body=r.text[:200])
        return None
    try:
        tok = r.json()["tokens"]
        st  = tok["skypeToken"]
        exp = int(tok.get("expiresIn", 3600))
    except Exception as exc:
        log.error("ms_identity.skypetoken_parse_failed", error=str(exc))
        return None

    store = _read_store()
    store["skype_token"]      = st
    store["skype_expires_at"] = time.time() + exp
    _write_store(store)
    log.info("ms_identity.skypetoken_ok", expires_in=exp)
    return st


def teams_headers() -> dict | None:
    """Ready-to-use headers for the Teams /api/mt/ API, or None if not signed in."""
    st = skype_token()
    if not st:
        return None
    return {
        "Authorization": f"Bearer {st}",
        "Accept":        "application/json",
        "User-Agent":    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/131.0 Safari/537.36"),
    }


def status() -> dict:
    s = _read_store()
    if not s.get("refresh_token"):
        return {"signed_in": False}
    age_days = (time.time() - s.get("obtained_at", 0)) / 86400
    return {
        "signed_in":       True,
        "upn":             s.get("upn"),
        "tenant":          s.get("tenant"),
        "scope":           s.get("scope"),
        "access_valid_s":  int(max(0, s.get("expires_at", 0) - time.time())),
        "skype_valid_s":   int(max(0, s.get("skype_expires_at", 0) - time.time())),
        "refresh_age_days": round(age_days, 1),
        # Entra public-client refresh tokens are 90 days and slide on use.
        "refresh_days_left_est": round(max(0, 90 - age_days), 1),
        "encrypted_at_rest": bool(os.environ.get("SS_TOKEN_KEY")),
    }


def logout() -> None:
    if STORE.exists():
        STORE.unlink()
    log.info("ms_identity.logged_out",
             note="local store removed; revoke server-side in Entra if leaked")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli() -> None:
    p = argparse.ArgumentParser(
        description="Durable Microsoft 365 tester identity (device code grant).")
    sub = p.add_subparsers(dest="cmd", required=True)

    li = sub.add_parser("login")
    li.add_argument("--tenant", default="organizations")
    li.add_argument("--scope", default=SKYPE_SCOPE)
    li.add_argument("--graph", action="store_const", const=GRAPH_SCOPE,
                    dest="scope", help="request Graph scope instead of Teams")

    sub.add_parser("status")
    sub.add_parser("logout")

    t = sub.add_parser("token")
    t.add_argument("--skype", action="store_true",
                   help="mint the Skype token instead of the AAD access token")
    t.add_argument("--show", action="store_true",
                   help="print the token itself; default prints only its length")

    a = p.parse_args()

    if a.cmd == "login":
        raise SystemExit(0 if login(a.tenant, a.scope) else 1)

    if a.cmd == "status":
        s = status()
        if not s["signed_in"]:
            print("not signed in — run: python -m core.ms_identity login")
            raise SystemExit(1)
        print(f"signed in as   : {s['upn']}")
        print(f"tenant         : {s['tenant']}")
        print(f"access token   : {s['access_valid_s']}s left")
        print(f"skype token    : {s['skype_valid_s']}s left")
        print(f"refresh token  : {s['refresh_age_days']}d old, "
              f"~{s['refresh_days_left_est']}d left before re-login")
        print(f"encrypted      : {s['encrypted_at_rest']}"
              f"{'' if s['encrypted_at_rest'] else '   <-- set SS_TOKEN_KEY'}")

    elif a.cmd == "token":
        tok = skype_token() if a.skype else access_token()
        if not tok:
            raise SystemExit("[!] no token — sign in first")
        print(tok if a.show else
              f"[+] {'skype' if a.skype else 'access'} token OK, {len(tok)} chars")

    elif a.cmd == "logout":
        logout()
        print("[+] local token store removed")
        print("    to kill a leaked token, revoke sign-in sessions in Entra")


if __name__ == "__main__":
    _cli()
