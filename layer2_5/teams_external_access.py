"""
layer2_5/teams_external_access.py — Microsoft Teams external access and user enumeration.

WHAT THIS MEASURES
------------------
Whether the target tenant's Teams external-access policy lets an arbitrary
external organisation resolve its users. When it is open, any party on the
internet with a Microsoft 365 account can confirm that a mailbox exists and
retrieve display name, availability and presence for it.

That matters for three reasons, in ascending order of severity:

  1. It is a reliable user-enumeration oracle that is not rate-limited the way
     the login endpoints are, and leaves nothing in the target's sign-in logs.
  2. Presence tells an attacker when a target is away, which is the timing
     signal used to choose when to attempt a takeover or a help-desk social
     engineering call.
  3. It is the delivery channel for device-code phishing. An inbound Teams chat
     from an unknown external party is far less scrutinised than an email, and
     is not processed by the mail gateway at all.

MEASURED CONSTRAINT — WHY THIS MODULE NEEDS AN OPERATOR
-------------------------------------------------------
The endpoint is

    GET https://teams.cloud.microsoft/api/mt/part/{region}/beta/users/{upn}/externalsearchv3

and it is a hard authentication wall. Verified 2026-10-08: an unauthenticated
request returns HTTP 401 with an empty body, and a deliberately invalid local
part returns a byte-identical 401 with identical headers. There is no pre-auth
existence oracle, no fail-open and no timing differential. Microsoft platform
behaviour, not target configuration, so it is attributable to neither.

The bearer token therefore has to come from a real interactive sign-in to SOME
Microsoft 365 tenant. We use OUR OWN tester tenant via core.browser_session, and
query the target cross-tenant exactly as any internet party could. We never
authenticate as, or to, the target.

If no fresh captured token is available the module returns status "skipped" with
the operator action required. It does NOT return an empty result set, because an
empty result set here is indistinguishable from "the target blocks external
access" and would silently manufacture a false clean bill of health.

CONTROL DISCIPLINE — NON-NEGOTIABLE
-----------------------------------
A null result from this endpoint has at least four causes: the target restricts
external access, the token is wrong, the region path is wrong, or the token has
expired. Only one of those is a statement about the target. So:

  * POSITIVE control, a UPN in a tenant known to permit external access. If it
    returns nothing, the run is INVALID and every target result is discarded.
  * NEGATIVE control, an invented local part on the target domain. If it returns
    data, the endpoint is matching loosely and every hit is discarded.

Both controls must pass before any finding is emitted. This exists because an
earlier phase of a live engagement produced 53 fabricated service accounts from
a throttle fail-open that was not control-tested.

CONFIG
------
    teams_external_access:
      positive_control: tester@our-second-tenant.example   # REQUIRED for a verdict
      negative_control_local: zzq9xnotreal99               # invented local part
      regions: [emea, apac, noam]
      delay: 2.0
      assisted: true            # drive the browser and wait for MFA if needed
      capture_timeout: 180      # seconds to wait for the client to issue a request
      max_reauth: 2             # token renewals allowed mid-run
      ui_crosscheck: true       # also read the rendered result list and compare
      ui_sample: 1              # hits to cross-check in the UI (one hit plus one
                                # miss is the whole evidence set a report needs)
      ui_shot_dir: ""           # where to write UI evidence screenshots

Data classification: SEMI-PUBLIC. Target traffic: NONE (served by Microsoft).
"""
from __future__ import annotations

import asyncio
import json
import random
import time
import uuid
import urllib.parse
from pathlib import Path
from typing import Any

import httpx
import structlog

from core.browser_session import load_auth
from core.ms_identity import teams_headers
from core import ui_session
from core.config import Config
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "teams_external_access",
    "title":    "Teams External Access & User Enumeration",
    "description": ("Cross-tenant Teams user resolution via an operator-authenticated "
                    "session; measures the target's external-access policy"),
    "layer":    2.5,
    "mode":     ["active"],
    "requires": [],
    "optional": True,
}

# MEASURED 2026-10-08. The old teams.microsoft.com/api/mt/{region}/... form is
# dead: it answers 401 for a Skype token and 400 from the federated backend for
# an AAD token, identically for real and invented users, so it yields no oracle.
# The live client uses teams.cloud.microsoft with a /part/ segment, a region of
# the emea-02 form, and the includeTFLUsers parameter. The x-ms-client-* headers
# below are required; without them the backend returns BadRequest.
_URL = ("https://teams.cloud.microsoft/api/mt/part/{region}/beta/users/"
        "{upn}/externalsearchv3?includeTFLUsers=true")
_REGIONS = ["emea-02", "emea-03", "apac-02", "noam-02", "emea"]

# A resolved user answers 200 with a profile; an unknown one answers 403. That
# differential IS the enumeration oracle, so 403 is a normal negative result
# here, not a transport error.
#
# MEASURED 2026-10-10, THE HARD WAY. An INCOMPLETE header set does not fail
# loudly. It returns 400 BadRequest ("Failed to execute UserDiscovery backend
# request ... Workload Unknown") for EVERY address, real and invented alike.
# That is indistinguishable from "nothing resolves", so a run missing one header
# reads as a clean negative and silently retracts a true finding. The specific
# header missing that day was x-ms-client-version. Do not trim this dict.
#
# x-ms-client-version pins a Teams web build. If every address starts answering
# 400 again, re-capture the live client's request and refresh this value before
# concluding anything about the target.
_CLIENT_HEADERS = {
    "x-ms-client-type":    "cdlworker",
    "x-ms-client-caller":  "powerbarSearchFederatedUser",
    "x-ms-client-version": "1415/26090315820",
    "x-ms-migration":      "True",
    "x-ms-test-user":      "False",
    "x-ms-request-id":     "",
    "x-ms-object-id":      "",
    "Referer":             "https://teams.cloud.microsoft/",
    "accept":              "application/json",
    "content-type":        "application/json;charset=UTF-8",
}
_TIMEOUT = 25
_AUTH_MATCH = "/api/mt/"


def _skip(reason: str, t0: float, extra: dict | None = None) -> dict:
    return {
        "module":   "layer2_5/teams_external_access",
        "status":   "skipped",
        "findings": [],
        "metadata": {"reason": reason, **(extra or {})},
        "duration": time.monotonic() - t0,
        "error":    None,
    }


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0  = time.monotonic()
    # Accept either the typed Config section or a plain dict, so the module is
    # usable standalone in a test harness as well as inside the pipeline.
    raw = getattr(config, "teams_external_access", None)
    if raw is None:
        cfg: dict = {}
    elif isinstance(raw, dict):
        cfg = raw
    else:
        cfg = raw.model_dump() if hasattr(raw, "model_dump") else dict(vars(raw))
    cfg = {k: v for k, v in cfg.items() if v not in ("", None, [])}

    # Preferred: the durable tester identity. One device-code sign-in lasts ~90
    # days and every run in between is unattended. Fall back to a brokered
    # browser session only when that is unavailable, which in practice means
    # Conditional Access blocks the device code grant.
    headers = teams_headers()
    auth_source = "ms_identity"
    token_age: int | None = None

    if not headers:
        auth = load_auth(max_age_s=int(cfg.get("max_token_age_s", 3600)))

        # No usable token on disk. Rather than stopping here and handing the
        # operator a checklist, drive the browser: if the profile still holds a
        # live session this is unattended, and if it does not, ui_session blocks
        # on the exact prompt that is showing and resumes by itself. Set
        # assisted: false for a strictly unattended run.
        if not auth and cfg.get("assisted", True):
            log.info("teams.assisted_acquire")
            auth = await ui_session.refresh_token(
                _AUTH_MATCH, timeout=int(cfg.get("capture_timeout", 180)))

        if not auth:
            return _skip(
                "no Microsoft tester identity available",
                t0,
                {"operator_action": [
                    "preferred, once per ~90 days:",
                    "  python -m core.ms_identity login",
                    "fallback if Conditional Access blocks the device code grant:",
                    "  python -m core.browser_session launch --url https://teams.microsoft.com/",
                    "  sign in, then search any name so the client issues an /api/mt/ request",
                    f"  python -m core.browser_session capture --match {_AUTH_MATCH}",
                ]},
            )
        headers = dict(auth["headers"])
        auth_source = "browser_session"
        token_age = auth.get("age_s")

    upns = await _target_upns(scope, db, cfg)
    if not upns:
        return _skip("no target UPNs available; run an email/identity module first", t0)

    pos_ctl = cfg.get("positive_control")
    neg_local = cfg.get("negative_control_local", "zzq9xnotreal99")
    primary = (scope.all_domains[0] if scope.all_domains else "example.com")
    neg_ctl = f"{neg_local}@{primary}"

    delay = float(cfg.get("delay", 2.0))

    metadata: dict = {
        "auth_source":      auth_source,
        "token_age_s":      token_age,
        "upns_tested":      0,
        "resolved":         0,
        "region":           None,
        "controls":         {},
        "verdict":          "inconclusive",
        "target_traffic":   "none (queries are served by Microsoft)",
    }

    headers = {**_CLIENT_HEADERS, "x-ms-session-id": str(uuid.uuid4()), **headers}

    async with httpx.AsyncClient(headers=headers, timeout=_TIMEOUT) as client:
        region = cfg.get("region") or await _pick_region(client, upns[0],
                                                         cfg.get("regions") or _REGIONS)
        if not region:
            return _skip("no usable Teams API region; token is probably expired", t0)
        metadata["region"] = region

        # --- controls first. We do not spend queries on targets we cannot trust. ---
        neg = await _lookup(client, region, neg_ctl)
        metadata["controls"]["negative"] = {
            "upn": neg_ctl, "status": neg["status"],
            "data_returned": neg["hit"],
        }
        # A correct request for an address that does not resolve answers 403.
        # A 400 on the CONTROL means the request itself is malformed, almost
        # always header drift, and every target would answer 400 too. Treating
        # that as "nothing resolves" is how a true finding gets retracted.
        if neg["status"] == 400:
            metadata["verdict"] = "invalid_run"
            return {
                "module": "layer2_5/teams_external_access", "status": "error",
                "findings": [], "metadata": metadata,
                "duration": time.monotonic() - t0,
                "error": ("negative control returned 400, so the request shape is "
                          "rejected before any lookup happens. Re-capture the live "
                          "Teams client request and refresh x-ms-client-version in "
                          "_CLIENT_HEADERS. No conclusion about the target is "
                          "possible from this run."),
            }

        if neg["hit"]:
            metadata["verdict"] = "invalid_run"
            return {
                "module": "layer2_5/teams_external_access", "status": "error",
                "findings": [], "metadata": metadata,
                "duration": time.monotonic() - t0,
                "error": ("negative control resolved: an invented address returned "
                          "data, so the endpoint matches loosely and no hit can be "
                          "trusted"),
            }

        if pos_ctl:
            await asyncio.sleep(random.uniform(delay, delay * 2))
            pos = await _lookup(client, region, pos_ctl)
            metadata["controls"]["positive"] = {
                "upn": pos_ctl, "status": pos["status"],
                "data_returned": pos["hit"],
            }
            if not pos["hit"]:
                metadata["verdict"] = "invalid_run"
                return {
                    "module": "layer2_5/teams_external_access", "status": "error",
                    "findings": [], "metadata": metadata,
                    "duration": time.monotonic() - t0,
                    "error": ("positive control did not resolve: the token or region "
                              "is wrong, so an empty target result proves nothing "
                              "about the target"),
                }
        else:
            metadata["controls"]["positive"] = {
                "upn": None, "status": None, "data_returned": None,
                "note": ("no positive control configured; an empty result is "
                         "INCONCLUSIVE and must not be reported as restricted"),
            }

        # --- targets ---
        # These tokens are short-lived and a long UPN list outlives them. A 401
        # part way through is a token expiry, NOT a target that stopped
        # resolving, so it is repaired once and the address is retried. Without
        # this the back half of a long list silently reads as negative.
        results = []
        reauths = 0
        max_reauth = int(cfg.get("max_reauth", 2))
        for upn in upns:
            await asyncio.sleep(random.uniform(delay, delay * 2))
            r = await _lookup(client, region, upn)

            if r["status"] == 401 and reauths < max_reauth and cfg.get("assisted", True):
                reauths += 1
                log.warning("teams.token_expired_midrun", upn=upn, attempt=reauths)
                fresh = await ui_session.refresh_token(
                    _AUTH_MATCH, timeout=int(cfg.get("capture_timeout", 180)))
                if fresh:
                    client.headers.update(fresh["headers"])
                    metadata["reauths"] = reauths
                    r = await _lookup(client, region, upn)

            if r["status"] == 401:
                # Still unauthenticated. Every remaining result would be a false
                # negative, so stop and say so rather than finish the list.
                metadata["verdict"] = "invalid_run"
                metadata["aborted_after"] = metadata["upns_tested"]
                return {
                    "module": "layer2_5/teams_external_access", "status": "error",
                    "findings": [], "metadata": metadata,
                    "duration": time.monotonic() - t0,
                    "error": ("token expired mid-run and could not be renewed, so "
                              "the remaining addresses were not tested and no "
                              "conclusion about the target is possible"),
                }

            metadata["upns_tested"] += 1
            results.append(r)
            if r["hit"]:
                metadata["resolved"] += 1
            log.info("teams.lookup", upn=upn, status=r["status"], hit=r["hit"])

    findings: list[dict] = []
    hits = [r for r in results if r["hit"]]

    # --- UI cross-check -----------------------------------------------------
    # The API path and the UI path fail in opposite directions. A drifted header
    # set makes the API answer 400 or empty for everything, which reads as a
    # restrictive target. Drifted DOM selectors make the UI read as empty, which
    # reads the same way. Running both and comparing is what catches either,
    # and a disagreement is reported rather than resolved: this module does not
    # get to pick which of its own two methods was lying.
    if cfg.get("ui_crosscheck") and results:
        # One hit and one miss is the entire UI evidence set. Every further
        # capture is another chance to put the operator's own client on screen
        # for no extra proof, so the sample stays at the minimum by default and
        # the miss prefers the negative control, which is invented by us and so
        # names no real person.
        misses = [r for r in results if not r["hit"]]
        misses.sort(key=lambda r: not r.get("negative_control"))
        sample = ([r for r in results if r["hit"]][:int(cfg.get("ui_sample", 1))]
                  + misses[:1])
        checks, disagree = [], 0
        shot_dir = Path(cfg["ui_shot_dir"]) if cfg.get("ui_shot_dir") else None
        for r in sample:
            # Through the people picker: the global search bar does not
            # perform external resolution at all, so reading it would
            # report every address as absent.
            ui = await ui_session.resolve_external(r["upn"])
            ui_found = bool(ui.get("results"))
            agrees = (ui_found == r["hit"]) if ui.get("conclusive") else None
            if agrees is False:
                disagree += 1
            shot = None
            if shot_dir and ui.get("ok"):
                safe = r["upn"].replace("@", "_at_").replace(".", "_")
                # Clipped to the result panel. A viewport capture of a signed-in
                # client puts the operator's own chat list and open conversation
                # into client evidence.
                shot = await ui_session.shot_results(shot_dir / f"ui_{safe}.png")
            checks.append({
                "upn":         r["upn"],
                "api_hit":     r["hit"],
                "ui_hit":      ui_found,
                "ui_results":  len(ui.get("results", [])),
                "conclusive":  ui.get("conclusive"),
                "agrees":      agrees,
                "ui_surface":  ui.get("surface"),
                "ui_error":    ui.get("error"),
                "screenshot":  (shot or {}).get("path"),
                "shot_clip":   (shot or {}).get("clip"),
                "shot_error":  (shot or {}).get("error"),
            })
        metadata["ui_crosscheck"] = {
            "checked": len(checks), "disagreements": disagree, "detail": checks,
        }
        if disagree:
            metadata["verdict"] = "needs_review"
            log.warning("teams.ui_api_disagree", n=disagree,
                        note="selector drift or header drift; do not report either "
                             "path as authoritative until resolved")

    if hits:
        metadata["verdict"] = "external_access_open"
        for r in hits:
            findings.append({
                "type":  "teams_user",
                "value": r["upn"],
                "data": {
                    "upn":           r["upn"],
                    **r.get("profile", {}),
                    "region":        region,
                    "method":        "teams externalsearchv3, cross-tenant",
                    "controls_passed": True,
                },
            })
        findings.append({
            "type":  "teams_external_access_open",
            "value": primary,
            "data": {
                "domain":          primary,
                "users_resolved":  len(hits),
                "users_tested":    len(results),
                "region":          region,
                "impact": ("any external Microsoft 365 account can confirm user "
                           "existence and read display name and presence, and can "
                           "initiate chat with staff, which is the delivery channel "
                           "for device-code phishing"),
                "remediation": ("restrict Teams external access to an allow-list of "
                                "federated domains in the Teams admin centre, and "
                                "block the device code flow with Conditional Access"),
                "controls_passed": True,
            },
        })
    elif metadata["controls"].get("positive", {}).get("data_returned"):
        metadata["verdict"] = "external_access_restricted"
        findings.append({
            "type":  "teams_external_access_restricted",
            "value": primary,
            "data": {
                "domain":       primary,
                "users_tested": len(results),
                "region":       region,
                "note": ("no target user resolved cross-tenant while the positive "
                         "control did; Teams external access is restricted. This is "
                         "a positive control result, not an absence of evidence"),
                "controls_passed": True,
            },
        })
    else:
        metadata["verdict"] = "inconclusive"

    return {
        "module":   "layer2_5/teams_external_access",
        "status":   "success" if findings else "partial",
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None if findings else
                    "no verdict: configure positive_control to make a null result meaningful",
    }


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

async def _lookup(client: httpx.AsyncClient, region: str, upn: str) -> dict:
    url = _URL.format(region=region, upn=urllib.parse.quote(upn))
    try:
        resp = await client.get(url)
        body = resp.text
        status = resp.status_code
    except Exception as exc:
        return {"upn": upn, "status": 0, "hit": False, "error": str(exc)}

    hit, profile = False, {}
    if status == 200 and body.strip() not in ("", "[]", "{}", "null"):
        try:
            data = json.loads(body)
            rec = data[0] if isinstance(data, list) and data else data
            if isinstance(rec, dict) and rec.get("displayName"):
                hit = True
                profile = {
                    "display_name":    rec.get("displayName"),
                    "tenant_name":     rec.get("tenantName"),
                    "tenant_id":       rec.get("tenantId"),
                    "object_id":       rec.get("objectId"),
                    "account_enabled": rec.get("accountEnabled"),
                    "coexistence":     (rec.get("featureSettings") or {}).get("coExistenceMode"),
                    "mri":             rec.get("mri"),
                }
        except Exception:
            pass
    return {"upn": upn, "status": status, "hit": hit,
            "display_name": profile.get("display_name"),
            "profile": profile, "body_len": len(body)}


async def _pick_region(client: httpx.AsyncClient, probe_upn: str,
                       regions: list[str]) -> str | None:
    """Find a region path the token is valid for. 404 means the path is wrong."""
    for r in regions:
        res = await _lookup(client, r, probe_upn)
        log.debug("teams.region_probe", region=r, status=res["status"])
        if res["status"] in (200, 403):
            return r             # 403 = valid region, user simply not resolvable
        if res["status"] == 401:
            return None          # token problem, no region will help
    return None


async def _target_upns(scope: Scope, db: Any, cfg: dict) -> list[str]:
    """Target UPNs, preferring addresses already proven valid earlier in the run.

    Only addresses on in-scope domains are returned. A harvested address on a
    third-party domain is not ours to test, even though the endpoint would
    happily answer for it.
    """
    if cfg.get("upns"):
        return list(cfg["upns"])

    in_scope = {d.lower() for d in scope.all_domains}
    out: list[str] = []
    if db is None:
        return out
    try:
        run_id = await db.get_last_run_id(scope.target.name) or ""
        if not run_id:
            return out
        for ftype in ("valid_user", "o365_user", "email"):
            for row in await db.get_findings(run_id, ftype):
                v = (row.get("value") or "").strip().lower()
                if "@" not in v:
                    continue
                if v.split("@", 1)[1] not in in_scope:
                    continue
                if v not in out:
                    out.append(v)
    except Exception as exc:
        log.debug("teams.db_lookup_failed", error=str(exc))
    return out[:int(cfg.get("max_upns", 25))]
