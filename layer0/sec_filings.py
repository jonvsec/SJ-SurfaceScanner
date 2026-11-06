"""
layer0/sec_filings.py — SEC EDGAR corporate intelligence.

Queries the SEC EDGAR submissions API and filing archives to:
  1. Resolve company name → CIK number (no form filter — foreign issuers never
     file a 10-K, so a 10-K-filtered lookup found none of them)
  2. Fetch the most recent annual report: 10-K, 20-F or 40-F
  3. Extract the subsidiary exhibit — Exhibit 21 (10-K) or Exhibit 8.1 (20-F)

EDGAR is NOT limited to US-incorporated companies: it covers every SEC
registrant, including foreign private issuers listed on US exchanges, who file
20-F. Verified live: Grupo Televisa (MX) 104 subsidiaries, Infosys (IN) 162.

Subsidiary company names from Exhibit 21 are emitted as "subsidiary" findings
and recorded in scope.discovered_subsidiaries (deduplicated). This is the
primary source for forgotten subsidiary infrastructure — often the easiest
entry point — but resolving a subsidiary *name* to its *domain(s)* for
inclusion in Layer 2+ scanning is not yet implemented (see DOSSIER.md
Section 15 — Backlog: "Subsidiary domain discovery").

API: free, no key required. Rate limit: 10 req/sec (use default limiter).
"""
from __future__ import annotations

import html
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
    "name":     "sec_filings",
    "title":    "SEC Filings (US)",
    "description": "Subsidiary extraction from SEC annual reports (10-K Ex-21 / 20-F Ex-8.1)",
    "layer":    0,
    "mode":     ["passive", "semi", "active"],
    "requires": [],
    "optional": False,
}

_EDGAR_BASE   = "https://data.sec.gov"     # /submissions/, /api/ only
# EDGAR *Archives* are NOT served from data.sec.gov — that host 404s for every
# /Archives/ path. Filing documents live on www.sec.gov. Getting this wrong made
# subsidiary extraction fail at the first request on every run.
_ARCHIVES_BASE = "https://www.sec.gov"
_EFTS_BASE    = "https://efts.sec.gov"

# Annual-report forms that carry a subsidiary exhibit, most-preferred first.
#   10-K  (US domestic filers)      -> Exhibit 21
#   20-F  (foreign private issuers) -> Exhibit 8.1
#   40-F  (Canadian MJDS filers)    -> varies
# Only 10-K was accepted before, which silently excluded every foreign issuer —
# Grupo Televisa (MX), Sanofi (FR), Infosys (IN) and Banco Santander, Telefonica
# and BBVA (ES) all file 20-F and were invisible to this module.
_ANNUAL_FORMS = ("10-K", "10-K/A", "20-F", "20-F/A", "40-F", "40-F/A")

# Exhibit filenames are the reliable signal. The index.json "type" field is an
# ICON filename ("text.gif"), not a form type, so matching on it never fires.
# No trailing boundary: real filenames append a sequence/date, e.g.
# "a10-kexhibit21109272025.htm" — requiring a non-digit after "21" never matched.
# Over-matching is cheap because each candidate is parsed and only accepted if it
# actually yields subsidiaries.
# Filers encode the decimal point differently: "ex21", "ex-21", "exhibit21",
# "infy-ex8_1", and Televisa's "tv-20251231xex8d1" where 'd' stands in for '.'.
_EXHIBIT_FILE_RE = re.compile(
    r"(?:ex|exhibit)[\-_. ]?(?:21|8[\-_.d ]?0?1)",
    re.IGNORECASE,
)

# Corporate legal suffixes, used to tell a company name from prose in
# plain-text filings that have no column structure.
_LEGAL_SUFFIX_RE = re.compile(
    r"\b(inc|incorporated|corp|corporation|co|company|ltd|limited|llc|llp|lp|"
    r"plc|gmbh|ag|nv|bv|b\.v|n\.v|s\.a|sa|sas|sarl|s\.r\.l|srl|spa|s\.p\.a|"
    r"pty|ab|as|a/s|oy|kk|k\.k|pte|sdn|bhd|c\.v|de c\.v|unlimited)\b\.?",
    re.IGNORECASE,
)
_HEADERS      = {
    "User-Agent": "SurfaceScanner security-research@example.com",
    "Accept-Encoding": "gzip, deflate",
}
_TIMEOUT      = 30


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0      = time.monotonic()
    limiter = RateLimiter(config.rate_limits)
    findings: list[dict] = []
    metadata: dict       = {}

    try:
        return await _run_inner(scope, config, findings, metadata, limiter, t0)
    except Exception as exc:
        log.error("edgar.unexpected_error", error=str(exc))
        return _result("error", findings, metadata, t0, error=str(exc))


async def _run_inner(scope, config, findings, metadata, limiter, t0) -> dict:
    async with httpx.AsyncClient(headers=_HEADERS, timeout=_TIMEOUT) as client:
        # Step 1 — find CIK
        cik = await _find_cik(client, scope.target.name, limiter)
        if not cik:
            return _result("partial", findings, metadata, t0,
                           error=f"CIK not found for '{scope.target.name}'")

        metadata["cik"] = cik
        log.info("edgar.cik_found", company=scope.target.name, cik=cik)

        # Step 2 — fetch company submissions (filings list)
        submissions = await _fetch_submissions(client, cik, limiter)
        if not submissions:
            return _result("partial", findings, metadata, t0,
                           error="Could not fetch EDGAR submissions")

        company_info = {
            "name":        submissions.get("name"),
            "cik":         cik,
            "sic":         submissions.get("sic"),
            "sic_desc":    submissions.get("sicDescription"),
            "state":       submissions.get("stateOfIncorporation"),
            "category":    submissions.get("category"),
            "fiscal_year": submissions.get("fiscalYearEnd"),
        }
        findings.append({
            "type":  "corporate_profile",
            "value": company_info["name"] or scope.target.name,
            "data":  company_info,
        })

        # Step 3 — most recent annual report (10-K, 20-F or 40-F)
        latest = _find_latest_annual_report(submissions)
        if not latest:
            log.info("edgar.no_annual_report", cik=cik)
            return _result("partial", findings, metadata, t0,
                           error="No 10-K / 20-F / 40-F filing found")

        accession, form_type = latest
        metadata["latest_annual_accession"] = accession
        metadata["annual_form_type"]        = form_type
        company_info["filer_type"] = (
            "foreign_private_issuer" if form_type.startswith(("20-F", "40-F"))
            else "us_domestic"
        )

        # Step 4 — locate and parse the subsidiary exhibit (Ex-21 / Ex-8.1)
        subsidiaries = await _extract_subsidiaries(client, cik, accession, limiter)
        metadata["subsidiary_count"] = len(subsidiaries)

        for sub in subsidiaries:
            findings.append({
                "type":  "subsidiary",
                "value": sub["name"],
                "data":  sub,
            })
            # Add to live scope so downstream layers include subsidiary infra
            if sub["name"] not in scope.discovered_subsidiaries:
                scope.discovered_subsidiaries.append(sub["name"])

        log.info("edgar.complete", cik=cik, subsidiaries=len(subsidiaries))

        if not subsidiaries:
            # The filing was located but carries no separate subsidiary exhibit.
            # Common for 20-F filers (Sanofi, Banco Santander) who list
            # subsidiaries inside the main document body instead. Reported
            # explicitly so this is distinguishable from "company has none".
            return _result(
                "partial", findings, metadata, t0,
                error=(f"{form_type} located (accession {accession}) but it "
                       "contains no separate subsidiary exhibit — the list may "
                       "be inside the main filing body"),
            )

    return _result("success", findings, metadata, t0)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _find_cik(
    client:  httpx.AsyncClient,
    company: str,
    limiter: RateLimiter,
) -> str | None:
    """
    Resolve a company name to its CIK (zero-padded to 10 digits).

    Deliberately does NOT restrict to 10-K. Foreign private issuers file 20-F and
    never a 10-K, so a form-filtered lookup returned None for every one of them
    (verified: Sanofi, Infosys and Grupo Televisa all failed here before this).
    """
    # 1. Official name->CIK index. Authoritative, no form filter, one request.
    await limiter.acquire("default")
    try:
        r = await client.get(f"{_ARCHIVES_BASE}/files/company_tickers.json",
                             headers=_HEADERS)
        r.raise_for_status()
        wanted = _normalise_company(company)
        entries = list(r.json().values())
        for entry in entries:                      # exact match first
            if _normalise_company(entry.get("title", "")) == wanted:
                return str(entry.get("cik_str", "")).zfill(10)
        for entry in entries:                      # then prefix match
            title = _normalise_company(entry.get("title", ""))
            if title.startswith(wanted) or wanted.startswith(title):
                if abs(len(title) - len(wanted)) <= 12:
                    return str(entry.get("cik_str", "")).zfill(10)
    except Exception as exc:
        log.warning("edgar.ticker_index_failed", error=str(exc))

    # 2. Full-text search across all forms.
    await limiter.acquire("default")
    try:
        r = await client.get(
            f"{_EFTS_BASE}/LATEST/search-index",
            params={"q": f'"{company}"'},
            headers=_HEADERS,
        )
        r.raise_for_status()
        hits = r.json().get("hits", {}).get("hits", [])
        if hits:
            entity_id = hits[0].get("_source", {}).get("entity_id", "")
            if entity_id:
                return str(entity_id).zfill(10)
    except Exception as exc:
        log.warning("edgar.cik_search_failed", error=str(exc))

    # 3. Company browse endpoint, no form filter.
    await limiter.acquire("default")
    try:
        r = await client.get(
            f"{_ARCHIVES_BASE}/cgi-bin/browse-edgar",
            params={
                "company": company, "CIK": "", "type": "",
                "dateb": "", "owner": "include", "count": "5",
                "search_text": "", "action": "getcompany", "output": "atom",
            },
            headers=_HEADERS,
        )
        r.raise_for_status()
        match = re.search(r"CIK=(\d+)", r.text)
        if match:
            return match.group(1).zfill(10)
    except Exception as exc:
        log.warning("edgar.cik_fallback_failed", error=str(exc))

    return None


def _normalise_company(name: str) -> str:
    """Lowercase, strip punctuation and common legal suffixes for matching."""
    n = re.sub(r"[^\w\s]", " ", name.lower())
    n = re.sub(
        r"\b(inc|incorporated|corp|corporation|company|co|ltd|limited|plc|"
        r"sa|s a|nv|n v|ag|gmbh|llc|lp|holdings?|group|the)\b", " ", n)
    return re.sub(r"\s+", " ", n).strip()


async def _fetch_submissions(
    client:  httpx.AsyncClient,
    cik:     str,
    limiter: RateLimiter,
) -> dict | None:
    await limiter.acquire("default")
    try:
        r = await client.get(
            f"{_EDGAR_BASE}/submissions/CIK{cik}.json",
            headers=_HEADERS,
        )
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        log.warning("edgar.submissions_failed", cik=cik, error=str(exc))
        return None


def _find_latest_annual_report(submissions: dict) -> tuple[str, str] | None:
    """
    Return (accession_no_dashes, form_type) for the most recent annual report.

    Accepts 10-K, 20-F and 40-F so foreign private issuers are covered, not just
    US domestic filers. `filings.recent` is already newest-first, so the first
    match in document order is the latest.
    """
    filings = submissions.get("filings", {}).get("recent", {})
    forms   = filings.get("form", [])
    acc_nos = filings.get("accessionNumber", [])
    for form, acc in zip(forms, acc_nos):
        if form in _ANNUAL_FORMS:
            return acc.replace("-", ""), form
    return None


async def _extract_subsidiaries(
    client:    httpx.AsyncClient,
    cik:       str,
    accession: str,
    limiter:   RateLimiter,
) -> list[dict]:
    """
    Find Exhibit 21 in a 10-K filing and parse subsidiary names + jurisdictions.
    """
    base_url  = f"{_ARCHIVES_BASE}/Archives/edgar/data/{int(cik)}/{accession}"
    index_url = f"{base_url}/index.json"

    await limiter.acquire("default")
    try:
        r = await client.get(index_url, headers=_HEADERS)
        r.raise_for_status()
        index = r.json()
    except Exception as exc:
        log.warning("edgar.index_failed", accession=accession, error=str(exc))
        return []

    # Match on FILENAME. The index's "type" field holds an icon name
    # ("text.gif"), and real exhibit filenames look like
    # "a10-kexhibit21109272025.htm" — which contains "exhibit21" but NOT "ex21",
    # so the previous substring checks could never match anything.
    candidates = [
        doc.get("name", "")
        for doc in index.get("directory", {}).get("item", [])
        if doc.get("name") and _EXHIBIT_FILE_RE.search(doc["name"])
        and doc["name"].lower().endswith((".htm", ".html", ".txt"))
    ]

    for name in candidates:
        await limiter.acquire("default")
        try:
            r = await client.get(f"{base_url}/{name}", headers=_HEADERS)
            r.raise_for_status()
        except Exception as exc:
            log.debug("edgar.exhibit_fetch_failed", name=name, error=str(exc))
            continue
        subs = _parse_exhibit21(r.text)
        if subs:
            log.info("edgar.exhibit_parsed", document=name, subsidiaries=len(subs))
            return subs

    log.debug("edgar.no_subsidiary_exhibit", accession=accession,
              candidates=candidates)
    return []


def _parse_exhibit21(text: str) -> list[dict]:
    """
    Parse a subsidiary exhibit (10-K Exhibit 21 / 20-F Exhibit 8.1) into
    [{"name": ..., "jurisdiction": ...}].

    Modern filings are HTML tables, so rows are extracted from the markup. The
    previous implementation collapsed ALL whitespace (`\\s+` -> " ") and then
    called .splitlines() on the result — which by construction yields a single
    line, immediately discarded by the `len(line) > 200` guard. Verified against
    Apple's real 11,807-byte EX-21.1: it returned 0 subsidiaries, always.
    """
    subsidiaries: list[dict] = []
    seen: set[str] = set()

    def _clean(cell: str) -> str:
        cell = re.sub(r"<[^>]+>", " ", cell)
        cell = html.unescape(cell)
        cell = cell.replace("\xa0", " ")
        return re.sub(r"\s+", " ", cell).strip(" .,;:")

    def _add(name: str, juris: str) -> None:
        if not name or len(name) < 3 or len(name) > 200:
            return
        if re.fullmatch(r"[\d\W]+", name):
            return
        # Table headers and section labels sit in the same <td> positions as
        # real rows, so they must be filtered by content.
        if re.match(r"^(exhibit|subsidiar|jurisdiction|state|country|name of|"
                    r"list of|entit|company name|percent|ownership|holding|"
                    r"related part|place of|where incorporated|principal|"
                    r"organi[sz]ed|proportion|\d+[.\d]*\s)",
                    name, re.IGNORECASE):
            return
        if re.fullmatch(r"(name|company|subsidiary|no\.?|#|total)", name, re.IGNORECASE):
            return
        if not re.search(r"[A-Za-z]{3}", name):
            return
        key = name.lower()
        if key in seen:
            return
        seen.add(key)
        subsidiaries.append({"name": name, "jurisdiction": juris})

    # --- Primary path: HTML table rows ---
    rows = re.findall(r"<tr[^>]*>(.*?)</tr>", text, re.S | re.I)
    for row in rows:
        cells = [_clean(c) for c in
                 re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", row, re.S | re.I)]
        cells = [c for c in cells if c]
        if not cells:
            continue
        if len(cells) == 1:
            _add(cells[0], "")
        else:
            _add(cells[0], cells[-1] if cells[-1] != cells[0] else "")

    if subsidiaries:
        return subsidiaries

    # --- Fallback: plain-text filings, where layout is column-aligned ---
    #
    # Prose must not be ingested here: a single-column line is only accepted if
    # it carries a corporate legal suffix, otherwise any sentence in the
    # document would become a "subsidiary".
    plain = re.sub(r"<[^>]+>", "\n", text)
    plain = html.unescape(plain).replace("\xa0", " ")
    for line in plain.splitlines():
        if not line.strip():
            continue
        parts = [p.strip() for p in re.split(r"\s{2,}|\t", line.strip()) if p.strip()]
        if not parts:
            continue
        if len(parts) == 1:
            if _LEGAL_SUFFIX_RE.search(parts[0]):
                _add(_clean(parts[0]), "")
        else:
            _add(_clean(parts[0]), _clean(parts[-1]))

    return subsidiaries


def _result(
    status:   str,
    findings: list[dict],
    metadata: dict,
    t0:       float,
    error:    str | None = None,
) -> dict:
    return {
        "module":   "layer0/sec_filings",
        "status":   status,
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    error,
    }
