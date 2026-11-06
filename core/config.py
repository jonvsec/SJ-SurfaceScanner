"""
core/config.py — environment-aware path resolution and system configuration.

Entry point: load_config() returns a validated Config object.

Code lives under SURFACESCANNER_ROOT (the repo / install dir). Engagement data
— scopes, outputs, reports, logs, state, signals — lives under
SURFACESCANNER_DATA, a separate root OUTSIDE the code tree, namespaced per
engagement. Change those two env vars to deploy anywhere (local dev, Docker,
server) without touching any config file, and the repository never holds client
data.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field

# Load .env first — sets SURFACESCANNER_ROOT, secrets, API keys
load_dotenv()

# ---------------------------------------------------------------------------
# Root path resolution — one variable controls everything
# ---------------------------------------------------------------------------

ROOT = Path(os.environ.get("SURFACESCANNER_ROOT", Path.home() / "surfacescanner"))
# Engagement data is deliberately kept OUT of the code tree, so the repository
# never holds client scopes, outputs or reports. Defaults to a sibling data
# root; set SURFACESCANNER_DATA=$SURFACESCANNER_ROOT to restore the old in-tree
# layout.
DATA = Path(os.environ.get("SURFACESCANNER_DATA", Path.home() / "surfacescanner-data"))
TMP  = Path(os.environ.get("SURFACESCANNER_TMP",  "/tmp/surfacescanner"))

# Point Python's tempfile module and every child process at our scratch dir.
# Modules call tempfile.NamedTemporaryFile() without dir=, which otherwise lands
# in /tmp. On hosts where /tmp is a tmpfs that is system RAM: a bruteforce
# writing 50k candidates per domain took this machine down on 2026-09-17.
TMP.mkdir(parents=True, exist_ok=True)
os.environ["TMPDIR"] = str(TMP)
os.environ["TMP"]    = str(TMP)
os.environ["TEMP"]   = str(TMP)

# Code assets stay with the code (ROOT). Everything written during an engagement
# goes under DATA, never inside the repo. These are the default (non-namespaced)
# locations; call Config.use_engagement() to switch to a per-client directory.
PATHS: dict[str, Path] = {
    "root":      ROOT,                 # code / install dir (the repo)
    "data":      DATA,                 # engagement data root (outside the repo)
    "wordlists": ROOT / "wordlists",   # repo asset, ships with the code
    "scopes":    DATA / "scopes",
    "outputs":   DATA / "outputs",
    "reports":   DATA / "reports",
    "logs":      DATA / "logs",
    "state":     DATA / "state",
    "signals":   DATA / "signals",
    "tmp":       TMP,
}


def _slug(name: str) -> str:
    """Filesystem-safe engagement slug from a scope or target name."""
    s = re.sub(r"[^a-z0-9]+", "-", str(name).strip().lower()).strip("-")
    return s or "engagement"


def engagement_paths(name: str) -> dict[str, Path]:
    """
    Per-engagement data directories: every client's outputs, reports, logs,
    signals and state live in their OWN directory under DATA. This keeps
    multiple clients from sharing state (CLAUDE.md principle 16) and keeps the
    code tree free of any engagement data. Scope files are shared input and stay
    in DATA/scopes rather than per-run output.
    """
    base = DATA / "engagements" / _slug(name)
    return {
        "root":      ROOT,
        "data":      DATA,
        "wordlists": ROOT / "wordlists",
        "base":      base,
        "scopes":    DATA / "scopes",
        "outputs":   base / "outputs",
        "reports":   base / "reports",
        "logs":      base / "logs",
        "state":     base / "state",
        "signals":   base / "signals",
        "tmp":       TMP,
    }


# ---------------------------------------------------------------------------
# Config section models — each maps directly to a config.yaml top-level key
# ---------------------------------------------------------------------------

class DatabaseConfig(BaseModel):
    host:     str = "localhost"
    port:     int = 5432
    name:     str = "surfacescanner"
    user:     str = "ssuser"
    password: str = ""

    @property
    def dsn(self) -> str:
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"

    @property
    def async_dsn(self) -> str:
        return f"postgresql+asyncpg://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"


class Neo4jConfig(BaseModel):
    uri:      str = "bolt://localhost:7687"
    user:     str = "neo4j"
    password: str = ""


class ChromaDBConfig(BaseModel):
    host: str = "localhost"
    port: int = 8000

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"


class SearXNGConfig(BaseModel):
    url: str = "http://localhost:8888"
    # Comma-separated engine list passed straight to SearXNG. None = its default
    # set, which is frequently entirely CAPTCHA-blocked.
    engines: str | None = None


class OllamaConfig(BaseModel):
    host:            str  = "http://localhost:11434"
    model:           str  = "qwen3:32b"       # primary: fully in VRAM, fast, thinking mode
    heavy_model:     str  = "qwen2.5:72b"     # kill chain narrative: biggest available
    fallback_model:  str  = "qwen3:8b"        # simple tasks: very fast
    embedding_model: str  = "nomic-embed-text"
    context_limit:   int  = 32000
    thinking_mode:   bool = False


class OpenRouterConfig(BaseModel):
    model: str = "openai/gpt-4o-mini"


class BreachExposureConfig(BaseModel):
    """layer2_5/breach_exposure — per-address breach history.

    allow_browser_scrape stays False by default on purpose. Bulk automation of
    the public HIBP page is against the spirit of their terms, so turning it on
    is a per-engagement decision an operator makes knowingly. With HIBP_API_KEY
    set the module uses the API and this flag is irrelevant.
    """
    enabled:              bool = True
    allow_browser_scrape: bool = False
    positive_control:      str = ""
    addresses:       list[str] = Field(default_factory=list)
    max_addresses:         int = 50
    scrape_delay:        float = 13.0


class IdentitySourcingConfig(BaseModel):
    """layer2_5/identity_sourcing — candidate addresses from staff names.

    confirmed defaults to False and must never be defaulted on. hunter.io spends
    the operator's paid credits, and scraping LinkedIn People pages breaches
    LinkedIn's terms and risks the operator's own account. Both are a human's
    call, per engagement.
    """
    confirmed:            bool = False
    sources:         list[str] = Field(
        default_factory=lambda: ["hunter", "linkedin_manual"])
    names_file:            str = ""
    known_file:            str = ""
    patterns:        list[str] = Field(default_factory=list)
    max_candidates:        int = 200


class TeamsExternalAccessConfig(BaseModel):
    """layer2_5/teams_external_access — cross-tenant Teams user resolution.

    positive_control is what makes a null result meaningful. Without a UPN in a
    tenant known to permit external access, an empty response is
    indistinguishable from an expired token, and the module reports
    "inconclusive" rather than claiming the target is restricted.
    """
    positive_control:       str = ""
    negative_control_local: str = "zzq9xnotreal99"
    regions:          list[str] = Field(
        default_factory=lambda: ["emea", "apac", "noam", "emea-02", "emea-03"])
    region:           str | None = None
    upns:             list[str] = Field(default_factory=list)
    delay:                float = 2.0
    max_upns:               int = 25
    max_token_age_s:        int = 3600


class BrandProtectionConfig(BaseModel):
    """layer1/brand_protection + layer1/newly_registered_domains.

    One section drives the whole lookalike pipeline. Weights and the SEV1 to
    SEV5 mapping live here on purpose: the severity mapping is a team decision,
    and keeping it in config lets the team retune it without touching code.

    The page/favicon enrichers touch the lookalike host (not the client) and run
    only in semi/active mode, so enrich_* defaults are safe but still honoured by
    the recon-mode gate in the module.
    """
    # dnstwist invocation
    dnstwist_threads:   int   = 20
    dnstwist_timeout:   int   = 1800
    use_phash:          bool  = False  # dnstwist screenshot perceptual hash (needs a browser)
    use_lsh:            str   = "ssdeep"  # "", "ssdeep" or "tlsh". HTML fuzzy hash

    # scoring
    recent_days:        int   = 180
    stale_days:         int   = 730   # older + dormant + no mail -> downgraded to info
    weights: dict[str, int] = Field(
        default_factory=lambda: {"mx": 3, "a": 1, "recent": 2, "ns_differ": 1})
    generic_labels: list[str] = Field(default_factory=lambda: [
        "get", "chat", "app", "web", "mail", "cloud", "api", "shop", "store",
        "pay", "go", "my", "one", "now", "live", "team", "work", "hub", "box",
        "net", "data", "link", "send", "talk", "text", "call", "meet", "buy",
    ])
    min_distinctive_len: int = 6

    # enrichment
    # A lookalike host is suspect by definition, so for this vertical the active
    # checks (favicon, login page, visual) are on by default regardless of the
    # scope mode. Set always_enrich to false for a contactless run when a client
    # requires zero contact with the suspect host.
    always_enrich:      bool  = True
    enrich_favicon:     bool  = True
    enrich_http:        bool  = True
    enrich_screenshot:  bool  = False   # gowitness, optional external binary
    max_enrich:         int   = 200     # cap live hosts probed per run

    # discovery feeds (newly_registered_domains)
    crtsh_enabled:      bool  = True
    nrd_feed_url:       str   = ""      # WHOISDS newly-registered-domains daily zip
    fuzzy_max_distance: int   = 2
    extra_generators: list[str] = Field(default_factory=list)  # urlcrazy, ail-typo-squatting

    # real-time CertStream daemon
    certstream_url:     str   = "wss://certstream.calidog.io/"
    certstream_keywords: list[str] = Field(default_factory=lambda: [
        "login", "secure", "account", "verify", "support", "portal", "sso",
    ])

    # output
    signals_dir:        str   = "outputs/signals"

    # SEV1 to SEV5 mapping (the team decision, one place)
    sev_map: dict = Field(default_factory=lambda: {
        "base": {
            "critical": "SEV2", "high": "SEV2", "medium": "SEV3",
            "low": "SEV4", "info": "SEV5",
        },
        "sev1_when_all": ["serves_login", "visual_match", "mail_capable"],
        "sev2_when_any_with_mail": ["serves_login", "visual_match", "favicon_match"],
    })


class RateLimits(BaseModel):
    shodan:         float = 1.0
    hudsonrock:     float = 0.5     # free OSINT endpoints, be gentle
    leakcheck:      float = 1.0
    leakradar:      float = 1.0
    securitytrails: float = 2.0
    hunter:         float = 3.0
    intelx:         float = 1.0
    github:         float = 5.0
    passivetotal:   float = 0.25
    default:        float = 5.0

    def get(self, service: str) -> float:
        """Return rate limit for service, falling back to default."""
        return getattr(self, service, self.default)


class Timeouts(BaseModel):
    default: int = 30
    amass:   int = 3600
    nuclei:  int = 7200
    katana:  int = 1800

    def get(self, tool: str) -> int:
        """Return timeout for tool, falling back to default."""
        return getattr(self, tool, self.default)


class OutputConfig(BaseModel):
    formats:  list[str] = Field(default_factory=lambda: ["markdown", "json", "pdf"])
    template: str = "default"


class LoggingConfig(BaseModel):
    level:      str  = "INFO"
    structured: bool = True


class NetworkConfig(BaseModel):
    active_recon_via_vps: bool       = True
    vps_ssh_host:         str | None = None
    vps_ssh_key:          str | None = None


# ---------------------------------------------------------------------------
# Root Config model
# ---------------------------------------------------------------------------

class Config(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    database:    DatabaseConfig   = Field(default_factory=DatabaseConfig)
    neo4j:       Neo4jConfig      = Field(default_factory=Neo4jConfig)
    chromadb:    ChromaDBConfig   = Field(default_factory=ChromaDBConfig)
    searxng:     SearXNGConfig    = Field(default_factory=SearXNGConfig)
    ollama:      OllamaConfig     = Field(default_factory=OllamaConfig)
    openrouter:  OpenRouterConfig = Field(default_factory=OpenRouterConfig)
    rate_limits: RateLimits       = Field(default_factory=RateLimits)
    timeouts:    Timeouts         = Field(default_factory=Timeouts)
    output:      OutputConfig     = Field(default_factory=OutputConfig)
    logging:     LoggingConfig    = Field(default_factory=LoggingConfig)
    network:     NetworkConfig    = Field(default_factory=NetworkConfig)
    teams_external_access: TeamsExternalAccessConfig = Field(
        default_factory=TeamsExternalAccessConfig)
    breach_exposure: BreachExposureConfig = Field(
        default_factory=BreachExposureConfig)
    identity_sourcing: IdentitySourcingConfig = Field(
        default_factory=IdentitySourcingConfig)
    brand_protection: BrandProtectionConfig = Field(
        default_factory=BrandProtectionConfig)

    # Always derived from the env roots — never read from config.yaml
    paths: dict[str, Path] = Field(default_factory=lambda: dict(PATHS))

    def use_engagement(self, name: str) -> "Config":
        """
        Point all writable paths at this engagement's own directory under DATA,
        so each client's data is isolated. Call once, right after the scope is
        loaded. Returns self for chaining.
        """
        self.paths = engagement_paths(name)
        return self


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


def load_config(config_path: Path | None = None) -> Config:
    """
    Load and validate system configuration.

    Reads config.yaml from ROOT by default. Interpolates ${ENV_VAR} references.
    Falls back to all Pydantic defaults when no config file is present — useful
    for tests and first-run before config.yaml is created.

    Paths are always overwritten from PATHS (derived from SURFACESCANNER_ROOT),
    never taken from the YAML file.
    """
    if config_path is None:
        config_path = ROOT / "config.yaml"

    if not config_path.exists():
        return Config()

    with open(config_path) as f:
        raw = yaml.safe_load(f) or {}

    data = _interpolate_env(raw)

    # Discard any 'paths' key that may accidentally appear in config.yaml
    data.pop("paths", None)

    config = Config.model_validate(data)
    config.paths = dict(PATHS)  # always authoritative from env, own copy
    return config
