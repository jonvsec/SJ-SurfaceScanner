"""
core/prefilter.py — signal extraction and text condensing before every LLM call.

RULE: call prefilter before every LLM invocation. Raw tool output can be
megabytes of HTML, JSON, or binary noise that wastes tokens and causes
hallucinations. This module extracts structured signals and condenses text
to a manageable size before it touches any LLM.

Usage:
    from core.prefilter import prepare_for_llm, extract_signals

    signals   = extract_signals(raw_text)
    condensed = prepare_for_llm(raw_text, max_chars=6000)

YARA support is optional. If yara-python is installed it will be used
for rule-based matching; otherwise the regex layer runs alone.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import structlog

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Compiled regex patterns — all pre-compiled at import time
# ---------------------------------------------------------------------------

_PATTERNS: dict[str, re.Pattern] = {
    "ipv4":       re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "ipv6":       re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"),
    "domain":     re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
        r"+[a-zA-Z]{2,}\b"
    ),
    "email":      re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
    "url":        re.compile(r"https?://[^\s\"'<>]+"),
    "cve":        re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "aws_arn":    re.compile(r"\barn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d*:[^\s\"']+"),
    "s3_bucket":  re.compile(r"\bs3://[a-zA-Z0-9.\-_/]+"),
    "azure_blob": re.compile(r"\bhttps://[a-zA-Z0-9]+\.blob\.core\.windows\.net[^\s\"']*"),
    "port_ref":   re.compile(r"\b(?:port\s+|:)(\d{1,5})\b", re.IGNORECASE),
    "api_key":    re.compile(
        r"\b(?:api[_\-]?key|access[_\-]?key|secret[_\-]?key|token|bearer)"
        r"\s*[=:]\s*[\"']?([A-Za-z0-9+/\-_]{20,})[\"']?",
        re.IGNORECASE,
    ),
    "hash_md5":   re.compile(r"\b[0-9a-fA-F]{32}\b"),
    "hash_sha1":  re.compile(r"\b[0-9a-fA-F]{40}\b"),
    "hash_sha256":re.compile(r"\b[0-9a-fA-F]{64}\b"),
    "jwt":        re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
}

# Lines containing these are likely to be high-value signals
_SIGNAL_KEYWORDS = re.compile(
    r"\b(?:password|passwd|secret|token|api.?key|credential|private.?key|"
    r"access.?key|auth|bearer|admin|root|sudo|ssh|ftp|smtp|database|db|"
    r"cve|vuln|exploit|breach|leak|exposed|open|misconfigured|s3|bucket|"
    r"endpoint|api|v1|v2|graphql|swagger|openapi|debug|staging|dev|test|"
    r"internal|corp|intranet|vpn|rdp|jenkins|gitlab|jira|confluence)\b",
    re.IGNORECASE,
)


@dataclass
class Signals:
    """Structured signals extracted from raw text."""
    ipv4:        list[str] = field(default_factory=list)
    ipv6:        list[str] = field(default_factory=list)
    domains:     list[str] = field(default_factory=list)
    emails:      list[str] = field(default_factory=list)
    urls:        list[str] = field(default_factory=list)
    cves:        list[str] = field(default_factory=list)
    aws_arns:    list[str] = field(default_factory=list)
    s3_buckets:  list[str] = field(default_factory=list)
    azure_blobs: list[str] = field(default_factory=list)
    ports:       list[str] = field(default_factory=list)
    api_keys:    list[str] = field(default_factory=list)
    jwts:        list[str] = field(default_factory=list)
    yara_hits:   list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, list[str]]:
        return {k: v for k, v in self.__dict__.items() if v}

    def summary_text(self) -> str:
        parts = []
        if self.cves:
            parts.append(f"CVEs: {', '.join(self.cves)}")
        if self.ipv4:
            parts.append(f"IPs: {', '.join(sorted(set(self.ipv4))[:20])}")
        if self.domains:
            parts.append(f"Domains: {', '.join(sorted(set(self.domains))[:20])}")
        if self.emails:
            parts.append(f"Emails: {', '.join(sorted(set(self.emails))[:10])}")
        if self.api_keys:
            parts.append(f"Possible API keys: {len(self.api_keys)} found")
        if self.jwts:
            parts.append(f"JWTs: {len(self.jwts)} found")
        if self.s3_buckets:
            parts.append(f"S3 buckets: {', '.join(self.s3_buckets[:10])}")
        if self.azure_blobs:
            parts.append(f"Azure blob URLs: {', '.join(self.azure_blobs[:10])}")
        if self.ports:
            parts.append(f"Ports: {', '.join(sorted(set(self.ports))[:20])}")
        if self.yara_hits:
            parts.append(f"YARA hits: {', '.join(self.yara_hits)}")
        return "\n".join(parts) if parts else "(no structured signals extracted)"


# ---------------------------------------------------------------------------
# YARA (optional)
# ---------------------------------------------------------------------------

try:
    import yara as _yara  # type: ignore[import]
    _YARA_AVAILABLE = True
except ImportError:
    _yara = None
    _YARA_AVAILABLE = False

_yara_rules: Any = None


def load_yara_rules(rules_path: str) -> bool:
    """Load YARA rules from a file. Returns True on success."""
    global _yara_rules
    if not _YARA_AVAILABLE:
        log.debug("prefilter.yara_unavailable")
        return False
    try:
        _yara_rules = _yara.compile(filepath=rules_path)
        log.info("prefilter.yara_loaded", path=rules_path)
        return True
    except Exception as exc:
        log.warning("prefilter.yara_load_failed", error=str(exc))
        return False


def _run_yara(text: str) -> list[str]:
    if not _YARA_AVAILABLE or _yara_rules is None:
        return []
    try:
        matches = _yara_rules.match(data=text.encode(errors="replace"))
        return [m.rule for m in matches]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_signals(text: str) -> Signals:
    """
    Extract all structured signals from raw text using regex patterns.
    Optionally augmented with YARA rule matches if rules are loaded.
    """
    s = Signals()
    s.ipv4        = list(set(_PATTERNS["ipv4"].findall(text)))
    s.ipv6        = list(set(_PATTERNS["ipv6"].findall(text)))
    s.domains     = list(set(_PATTERNS["domain"].findall(text)))
    s.emails      = list(set(_PATTERNS["email"].findall(text)))
    s.urls        = list(set(_PATTERNS["url"].findall(text)))
    s.cves        = list(set(m.upper() for m in _PATTERNS["cve"].findall(text)))
    s.aws_arns    = list(set(_PATTERNS["aws_arn"].findall(text)))
    s.s3_buckets  = list(set(_PATTERNS["s3_bucket"].findall(text)))
    s.azure_blobs = list(set(_PATTERNS["azure_blob"].findall(text)))
    s.ports       = list(set(_PATTERNS["port_ref"].findall(text)))
    s.api_keys    = list(set(_PATTERNS["api_key"].findall(text)))
    s.jwts        = list(set(_PATTERNS["jwt"].findall(text)))
    s.yara_hits   = _run_yara(text)
    return s


def condense(text: str, max_chars: int = 6000) -> str:
    """
    Condense raw text to max_chars by scoring lines and keeping the highest
    signal lines. Signal-dense lines (matching regex patterns or keywords)
    are kept preferentially over noise.

    Always keeps the first 10 and last 5 lines for context.
    """
    if max_chars <= 0:
        return ""

    if len(text) <= max_chars:
        return text

    lines = text.splitlines()
    if not lines:
        return text[:max_chars]

    # Score each line by number of pattern matches + keyword hits
    def score(line: str) -> int:
        hits = sum(len(p.findall(line)) for p in _PATTERNS.values())
        hits += 3 * len(_SIGNAL_KEYWORDS.findall(line))
        return hits

    scored = [(score(line), i, line) for i, line in enumerate(lines)]

    # Always include first 10 and last 5
    must_include = set(range(min(10, len(lines)))) | set(
        range(max(0, len(lines) - 5), len(lines))
    )

    # Fill remaining budget with highest-scoring lines
    remaining = [(s, i, l) for s, i, l in scored if i not in must_include]
    remaining.sort(reverse=True)  # highest score first

    kept_indices = set(must_include)
    char_budget  = max_chars - sum(len(lines[i]) + 1 for i in kept_indices)

    for _, idx, line in remaining:
        if char_budget <= 0:
            break
        if idx not in kept_indices:
            kept_indices.add(idx)
            char_budget -= len(line) + 1

    # Reconstruct in original order
    result_lines = [lines[i] for i in sorted(kept_indices)]
    result = "\n".join(result_lines)
    return result[:max_chars]


def prepare_for_llm(text: str, max_chars: int = 6000) -> str:
    """
    Full pipeline: extract signals summary + condense raw text.
    Returns a string ready to embed in an LLM prompt.

    Always call this (not bare text) before sending to any LLM.
    """
    signals  = extract_signals(text)
    summary  = signals.summary_text()
    condensed = condense(text, max_chars=max_chars - len(summary) - 100)

    return (
        f"=== EXTRACTED SIGNALS ===\n{summary}\n\n"
        f"=== RAW CONTENT (condensed) ===\n{condensed}"
    )
