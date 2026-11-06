"""
scope_parser.py — scope.yaml loader.

scope.yaml contains engagement data ONLY (what to scan). It never contains
system configuration — that lives in config.yaml. Mixing them causes state
bugs in multi-client EASM where one client's scope bleeds into another's.

Usage:
    scope = load_scope(Path("scope.yaml"))
    print(scope.target.name, scope.mode)
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

import os
from dotenv import load_dotenv

load_dotenv()


# ---------------------------------------------------------------------------
# Scope sub-models
# ---------------------------------------------------------------------------

class TargetInfo(BaseModel):
    name:    str
    aliases: list[str] = Field(default_factory=list)
    sector:  str | None = None


class Scope(BaseModel):
    target:              TargetInfo
    domains:             list[str]      = Field(default_factory=list)
    emails:              list[str]      = Field(default_factory=list)
    ip_ranges:           list[str]      = Field(default_factory=list)
    asn:                 list[str]      = Field(default_factory=list)
    attachments:         list[str]      = Field(default_factory=list)
    out_of_scope:        list[str]      = Field(default_factory=list)
    mode:                str            = "passive"
    data_classification: str            = "SEMI-PUBLIC"
    grok_enabled:        bool           = False

    # Populated dynamically during Layer 0 as subsidiary *company names* are
    # discovered (e.g. from EDGAR Exhibit 21). Not read from scope.yaml — this
    # is runtime state only. NOT included in all_domains: these are company
    # names, not domains, and resolving them to domains is not yet implemented
    # (see DOSSIER.md Section 15 — Backlog).
    discovered_subsidiaries: list[str] = Field(default_factory=list, exclude=True)

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        allowed = {"passive", "semi", "active"}
        if v not in allowed:
            raise ValueError(f"mode must be one of {allowed}, got '{v}'")
        return v

    @field_validator("data_classification")
    @classmethod
    def validate_classification(cls, v: str) -> str:
        allowed = {"PUBLIC", "SEMI-PUBLIC", "CONFIDENTIAL"}
        if v not in allowed:
            raise ValueError(f"data_classification must be one of {allowed}, got '{v}'")
        return v

    @property
    def primary_domain(self) -> str | None:
        """The first domain in the list, used as a canonical identifier."""
        return self.domains[0] if self.domains else None

    @property
    def all_domains(self) -> list[str]:
        """
        Domains in scope for technical recon (Layer 2+).

        Deliberately excludes `discovered_subsidiaries` — those are subsidiary
        *company names* from EDGAR, not domains. Mixing them in here would make
        every Layer 2+ module (crt.sh, subfinder, nuclei, headers, ssl, ...)
        issue DNS/HTTP queries for strings like "Acme Subsidiary Inc".
        """
        return list(self.domains)

    def to_dict(self) -> dict:
        """Serialisable dict for storing in PostgreSQL (scope column in runs)."""
        return {
            "target":              self.target.model_dump(),
            "domains":             self.domains,
            "emails":              self.emails,
            "ip_ranges":           self.ip_ranges,
            "asn":                 self.asn,
            "attachments":         self.attachments,
            "out_of_scope":        self.out_of_scope,
            "mode":                self.mode,
            "data_classification": self.data_classification,
            "grok_enabled":        self.grok_enabled,
        }


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def _interpolate_env(value: Any) -> Any:
    """Replace ${VAR} patterns with values from the environment."""
    if isinstance(value, str):
        return re.sub(
            r"\$\{([^}]+)\}",
            lambda m: os.environ.get(m.group(1), ""),
            value,
        )
    if isinstance(value, dict):
        return {k: _interpolate_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate_env(item) for item in value]
    return value


def load_scope(path: Path) -> Scope:
    """
    Load and validate scope.yaml.

    Raises:
        FileNotFoundError: if the file does not exist.
        ValueError: if required fields are missing or invalid.
    """
    if not path.exists():
        raise FileNotFoundError(f"scope.yaml not found: {path}")

    with open(path) as f:
        raw = yaml.safe_load(f) or {}

    data = _interpolate_env(raw)

    # Reject any system config keys that should live in config.yaml
    _SYSTEM_KEYS = {
        "database", "neo4j", "ollama", "openrouter", "rate_limits",
        "timeouts", "output", "logging", "network", "chromadb", "searxng",
    }
    forbidden = _SYSTEM_KEYS & set(data.keys())
    if forbidden:
        raise ValueError(
            f"scope.yaml contains system config keys: {forbidden}. "
            "These belong in config.yaml — keep engagement data and system "
            "config strictly separated."
        )

    return Scope.model_validate(data)
