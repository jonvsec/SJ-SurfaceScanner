"""
layer0/azure_tenant.py — Microsoft Entra (Azure AD) tenant discovery.

Resolves the Microsoft tenant behind a domain and uses tenant identity as an
**ownership-correlation signal**: two domains that resolve to the same tenant
GUID are administered by the same organisation. That is a far stronger
attribution basis than a name match, which is unreliable for targets whose
trading name is widely shared.

Sources, and what each can actually do — measured, not assumed:

  1. OpenID configuration (login.microsoftonline.com/<domain>/v2.0/...)
     domain -> tenant GUID. Live and authoritative. HTTP 400 means the domain
     has no Microsoft tenant. This is the workhorse.

  2. PingCastle Tenant Resolution (tenantresolution.pingcastle.com)
     Accepts either a domain or a tenant GUID and is the only source that
     answers in the GUID -> domain direction, which is useful when a tenant ID
     is recovered from somewhere else (a login page, a JWT issuer, a support
     ticket) and must be attributed to an organisation.

  3. Autodiscover GetFederationInformation (autodiscover-s.outlook.com)
     Retained only as a corroborating check that the domain is Exchange
     Online-hosted.

  4. getuserrealm.srf (login.microsoftonline.com)
     Tenant-level namespace type (Managed vs Federated), federation brand name
     and, when federated, the external AuthURL. This is the signal that decides
     which M365 attack applies, so it is captured once per tenant. Unauthenticated
     and user-independent, a throwaway login string is used and no user is enumerated.

IMPORTANT — measured limitation. Neither (2) nor (3) enumerates a tenant's full
domain list. Verified against microsoft.com, whose tenant
(72f988bf-86f1-41af-91ab-2d7cd011db47) contains hundreds of domains: PingCastle
returns exactly one domain for the tenant GUID, and Autodiscover echoes back
only the domain queried. Do not treat a single-domain result as evidence that a
tenant has one domain — it is the API's ceiling, not a finding about the target.

Autodiscover additionally rejects a browser User-Agent with HTTP 401 and must
identify as "AutodiscoverClient".

No API key required. All three sources are public and unauthenticated.
Data classification: SEMI-PUBLIC (public identity metadata about the target).
"""
from __future__ import annotations

import re
import time
from typing import Any

import httpx
import structlog

from core.config import Config
from core.ratelimiter import RateLimiter
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "azure_tenant",
    "title":    "Microsoft Entra Tenant",
    "description": "Resolves the Azure AD tenant GUID and correlates domains by shared tenancy",
    "layer":    0,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": True,
}

_OPENID   = "https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration"
_AUTODISC = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
_PINGCASTLE = "https://tenantresolution.pingcastle.com"
# getuserrealm answers the one question tenant-GUID resolution does not: HOW the
# tenant authenticates. NameSpaceType "Managed" means cloud-only (ROPC/password
# spray is the path), "Federated" means an on-prem IdP/ADFS (the AuthURL below,
# a different attack). It is tenant-level, unauthenticated, and returns the same
# fields for any login string, so a throwaway local-part is used — no user is
# enumerated here. This is the pre-auth identity signal that steers the whole
# M365 attack decision, so it belongs in outside-in attack-surface mapping.
_GETUSERREALM = "https://login.microsoftonline.com/getuserrealm.srf?login=probe@{domain}&xml=1"
_TIMEOUT  = 30

_UA = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"),
}

_GUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I
)

_FEDERATION_SOAP = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages"
 xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types"
 xmlns:a="http://www.w3.org/2005/08/addressing"
 xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Header>
<a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
<a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>
<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
</soap:Header>
<soap:Body>
<GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
<Request><Domain>{domain}</Domain></Request>
</GetFederationInformationRequestMessage>
</soap:Body></soap:Envelope>"""


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0       = time.monotonic()
    limiter  = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict = {
        "domains_checked":  0,
        "tenants_found":    0,
        "sibling_domains":  0,
        "new_root_domains": 0,
        "sources":          [],
    }

    known = {d.lower() for d in scope.all_domains}
    tenants: dict[str, dict] = {}   # tenant_id -> record

    async with httpx.AsyncClient(headers=_UA, timeout=_TIMEOUT,
                                 follow_redirects=True) as client:
        # --- 1. tenant ID per in-scope domain (authoritative) ---
        for domain in scope.all_domains:
            metadata["domains_checked"] += 1
            tid = await _tenant_id_for_domain(client, domain, limiter)
            if not tid:
                continue
            rec = tenants.setdefault(tid, {"tenant_id": tid, "seed_domains": [],
                                           "domains": set(), "sources": set(),
                                           "federation": {}})
            rec["seed_domains"].append(domain)
            rec["domains"].add(domain.lower())
            rec["sources"].add("openid_configuration")

            # Namespace/federation type is a tenant-level property. Capture it
            # from the first seed domain that answers and keep it on the record.
            if not rec["federation"]:
                fed = await _federation_info(client, domain, limiter)
                if fed:
                    rec["federation"] = fed
                    rec["sources"].add("getuserrealm")

        # --- 2 & 3. expand each tenant to its full domain set ---
        for tid, rec in tenants.items():
            for seed in rec["seed_domains"]:
                for d in await _autodiscover_domains(client, seed, limiter):
                    rec["domains"].add(d)
                    rec["sources"].add("autodiscover_federation")

            pc = await _pingcastle_lookup(client, tid, limiter)
            if pc:
                rec["domains"].update(pc)
                rec["sources"].add("pingcastle")

    for tid, rec in tenants.items():
        domains = sorted(rec["domains"])
        new = [d for d in domains if d not in known]
        metadata["tenants_found"]    += 1
        metadata["sibling_domains"]  += len(domains)
        metadata["new_root_domains"] += len(new)
        metadata["sources"] = sorted(set(metadata["sources"]) | rec["sources"])

        findings.append({
            "type":  "azure_tenant",
            "value": tid,
            "data": {
                "tenant_id":         tid,
                "seed_domains":      rec["seed_domains"],
                "tenant_domains":    domains,
                "domain_count":      len(domains),
                "new_domains":       new,
                "sources":           sorted(rec["sources"]),
                "corroborated":      len(rec["sources"]) > 1,
                "shared_tenancy":    len(rec["seed_domains"]) > 1,
                "namespace_type":    rec["federation"].get("namespace_type"),
                "federation_brand":  rec["federation"].get("federation_brand"),
                "federation_auth_url": rec["federation"].get("auth_url"),
                "cloud_instance":    rec["federation"].get("cloud_instance"),
                "auth_note":         _auth_note(rec["federation"].get("namespace_type")),
                "ownership_note":    ("multiple in-scope domains share this tenant "
                                      "— common administrative ownership is proven"
                                      if len(rec["seed_domains"]) > 1 else
                                      "single in-scope domain; tenant domain list "
                                      "cannot be enumerated via public APIs"),
            },
        })
        # Each previously-unknown domain is emitted separately so Layer 2 can
        # pick it up as a scanning target.
        for d in new:
            findings.append({
                "type":  "tenant_domain",
                "value": d,
                "data": {
                    "domain":    d,
                    "tenant_id": tid,
                    "reason":    "registered to the same Microsoft Entra tenant "
                                 "as an in-scope domain",
                    "sources":   sorted(rec["sources"]),
                },
            })
        log.info("azure_tenant.resolved", tenant=tid,
                 domains=len(domains), new=len(new))

    status = "success" if tenants else "partial"
    error  = None if tenants else "no Microsoft Entra tenant found for any scope domain"

    return {
        "module":   "layer0/azure_tenant",
        "status":   status,
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    error,
    }


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

async def _tenant_id_for_domain(
    client: httpx.AsyncClient, domain: str, limiter: RateLimiter
) -> str | None:
    """Live OpenID configuration lookup. HTTP 400 means 'no tenant', not an error."""
    await limiter.acquire("default")
    try:
        r = await client.get(_OPENID.format(domain=domain))
        if r.status_code != 200:
            return None
        issuer = (r.json() or {}).get("issuer", "")
        m = _GUID_RE.search(issuer)
        return m.group(0).lower() if m else None
    except Exception as exc:
        log.debug("azure_tenant.openid_failed", domain=domain, error=str(exc))
        return None


def _auth_note(ns: str | None) -> str:
    if ns == "Managed":
        return ("cloud-only authentication, credential validation / password "
                "spray via ROPC or the SSO endpoints applies")
    if ns == "Federated":
        return ("federated to an external identity provider (see auth_url), "
                "authentication happens off Microsoft so spray hits the IdP")
    return "namespace type not resolved"


async def _federation_info(
    client: httpx.AsyncClient, domain: str, limiter: RateLimiter
) -> dict:
    """
    getuserrealm tenant-level realm metadata. Returns namespace type (Managed /
    Federated), the tenant's federation brand name, the federated AuthURL when
    present, and the cloud instance. A throwaway local-part is used because the
    tenant-level fields do not depend on the user existing — no enumeration.
    """
    await limiter.acquire("default")
    try:
        r = await client.get(_GETUSERREALM.format(domain=domain))
        if r.status_code != 200:
            return {}
        body = r.text

        def _tag(name: str) -> str | None:
            m = re.search(rf"<{name}>([^<]+)</{name}>", body, re.I)
            return m.group(1).strip() if m else None

        ns = _tag("NameSpaceType")
        if not ns:
            return {}
        return {
            "namespace_type":   ns,
            "federation_brand": _tag("FederationBrandName"),
            "auth_url":         _tag("AuthURL"),
            "cloud_instance":   _tag("CloudInstanceName"),
        }
    except Exception as exc:
        log.debug("azure_tenant.getuserrealm_failed", domain=domain, error=str(exc))
        return {}


async def _autodiscover_domains(
    client: httpx.AsyncClient, domain: str, limiter: RateLimiter
) -> list[str]:
    """Domains the tenant itself advertises via Autodiscover."""
    await limiter.acquire("default")
    # Autodiscover rejects a browser User-Agent with HTTP 401 — it must be
    # identified as an Autodiscover client. Verified: browser UA -> 401,
    # "AutodiscoverClient" -> 200.
    headers = {
        "User-Agent": "AutodiscoverClient",
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": ('"http://schemas.microsoft.com/exchange/2010/Autodiscover/'
                       'Autodiscover/GetFederationInformation"'),
    }
    try:
        r = await client.post(_AUTODISC,
                              content=_FEDERATION_SOAP.format(domain=domain).encode(),
                              headers=headers)
        if r.status_code != 200:
            return []
        return sorted({d.lower() for d in
                       re.findall(r"<Domain>([^<]+)</Domain>", r.text)})
    except Exception as exc:
        log.debug("azure_tenant.autodiscover_failed", domain=domain, error=str(exc))
        return []


async def _pingcastle_lookup(
    client: httpx.AsyncClient, tenant_id: str, limiter: RateLimiter
) -> list[str]:
    """
    Reverse lookup by TenantID against PingCastle's CT-derived tenant database.

    This is the only source of the three that can go ID -> domains. It is an
    ASP.NET Razor Pages form: the antiforgery token must be read from the
    landing page and posted back together with its cookie, otherwise the POST
    is rejected. A GET against /Search returns HTTP 405.
    """
    await limiter.acquire("default")
    try:
        landing = await client.get(f"{_PINGCASTLE}/")
        m = re.search(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"',
                      landing.text)
        if not m:
            log.debug("azure_tenant.pingcastle_no_token")
            return []

        await limiter.acquire("default")
        r = await client.post(
            f"{_PINGCASTLE}/Search",
            data={"Search": tenant_id, "__RequestVerificationToken": m.group(1)},
            headers={**_UA,
                     "Content-Type": "application/x-www-form-urlencoded",
                     "Referer": f"{_PINGCASTLE}/",
                     "Origin": _PINGCASTLE},
        )
        if r.status_code != 200:
            return []
        return _parse_pingcastle(r.text, tenant_id)
    except Exception as exc:
        log.debug("azure_tenant.pingcastle_failed", tenant=tenant_id, error=str(exc))
        return []


def _parse_pingcastle(body: str, tenant_id: str) -> list[str]:
    """
    Extract domains from a PingCastle result page.

    Results render as 'Domain: example.com' lines and, for multi-domain tenants,
    as table cells. Both shapes are handled. The tenant GUID is required to be
    present, so a 'not found' page cannot be mistaken for an empty result set.
    """
    if tenant_id.lower() not in body.lower():
        return []
    text = re.sub(r"<[^>]+>", "\n", body)
    domains: set[str] = set()
    for m in re.finditer(r"Domain\s*:\s*([A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,})",
                         text):
        domains.add(m.group(1).lower())
    for m in re.finditer(r"<td[^>]*>\s*([A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,})\s*</td>",
                         body, re.I):
        domains.add(m.group(1).lower())
    return sorted(domains)
