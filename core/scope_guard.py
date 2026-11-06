"""
core/scope_guard.py — authorised-target enforcement.

Every module that sends traffic to, or enumerates, a named host must pass that
host through `assert_in_scope()` first. Scope is engagement data: the domains a
client has authorised in writing. Anything else is a third party.

Why this exists: modules discover domains at runtime (tenant enumeration, SaaS
detection, certificate parsing, page scraping) and feed them back into the
pipeline. A single over-broad regex in a discovery module is enough to point an
enumeration tool at somebody who never signed anything. That is an authorisation
problem, not a data-quality problem, so it is enforced centrally and the failure
mode is to refuse.

On one engagement an `amass enum -passive -d <out-of-scope-domain>` process was
observed while the pipeline was running, though the stored scope contained no
such domain. Root cause was not established, which is precisely why the control
belongs here rather than in whichever module turned out to be at fault.
"""
from __future__ import annotations

import structlog

log = structlog.get_logger(__name__)


class OutOfScopeError(Exception):
    """Raised when a module attempts to act on a host the client did not authorise."""


def _norm(host: str) -> str:
    h = (host or "").strip().lower().rstrip(".")
    if "://" in h:
        h = h.split("://", 1)[1]
    return h.split("/")[0].split(":")[0]


def in_scope(host: str, scope) -> bool:
    """True when `host` is an authorised apex or a subdomain of one."""
    h = _norm(host)
    if not h:
        return False

    for bad in (getattr(scope, "out_of_scope", None) or []):
        b = _norm(str(bad))
        if b and (h == b or h.endswith("." + b)):
            return False

    for good in (getattr(scope, "all_domains", None) or []):
        g = _norm(str(good))
        if g and (h == g or h.endswith("." + g)):
            return True
    return False


def assert_in_scope(host: str, scope, *, module: str, action: str = "query") -> None:
    """Refuse to act on an unauthorised host. Never downgrade this to a warning."""
    if in_scope(host, scope):
        return
    log.error(
        "scope_guard.blocked",
        module=module, action=action, host=_norm(host),
        authorised=sorted(_norm(str(d)) for d in (getattr(scope, "all_domains", None) or [])),
    )
    raise OutOfScopeError(
        f"{module} tried to {action} '{_norm(host)}', which is not in the authorised "
        f"scope. Refusing: this host belongs to a third party who has not consented "
        f"to testing."
    )


def filter_in_scope(hosts, scope, *, module: str) -> list[str]:
    """Drop unauthorised hosts from a list, logging each one. Returns survivors."""
    kept, dropped = [], []
    for h in hosts or []:
        (kept if in_scope(h, scope) else dropped).append(h)
    if dropped:
        log.warning("scope_guard.filtered", module=module,
                    dropped_count=len(dropped), dropped=sorted(_norm(d) for d in dropped)[:20])
    return kept
