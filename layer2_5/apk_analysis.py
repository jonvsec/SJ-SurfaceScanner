"""
layer2_5/apk_analysis.py — static analysis of the brand's Android apps.

Consumes the inventory from layer1/mobile_apps (Google Play packages marked as
owned) and, for each app the operator has authorised, pulls the APK from a public
mirror, unpacks and decompiles it, and mines the binary for the things a mobile
build routinely leaks: cloud credentials and API tokens, internal/owned API
hostnames that never surface in web recon, Firebase project configuration,
pinned certificates (whose SANs reveal more internal hosts), and exported
components (intent-injection surface).

Boundaries, enforced here:
  - **No active scanning of client infrastructure.** Every network call goes to
    an APK mirror, never to the target. Subprocesses run locally (recon_mode
    "semi"), never via the active-recon VPS path.
  - **Authorisation gate.** config.apk_analysis.confirmed must be set per
    engagement. Without it the module reports which apps it WOULD analyse and
    downloads nothing — pulling and unpacking third-party binaries is a human's
    call, like identity_sourcing.
  - **Runtime instrumentation is never auto-run.** Frida SSL-pinning and
    root-detection bypasses and objection commands need a test device and are
    active by nature. The module writes ready-to-run scripts into the engagement
    tools/ directory and records them as operator-assisted steps. It does not
    launch frida or objection.

Secrets are redacted before they enter a finding (first/last 4 characters only),
per the evidence-hygiene rule — the report names the leak and where it lives, not
a working credential.

Tools (local): jadx (decompile, falls back to strings on classes*.dex), 7z/unzip
(unpack, handles XAPK), openssl (certificate parsing), curl (acquire). frida and
objection are referenced by the emitted scripts, not invoked.
"""
from __future__ import annotations

import ipaddress
import json
import re
import time
from pathlib import Path
from typing import Any

import structlog

from core.config import Config
from core.network import run_command
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "apk_analysis",
    "title":    "APK Static Analysis",
    "description": "Decompile brand Android apps and mine secrets, internal hosts, Firebase and certs",
    "layer":    2.5,
    "mode":     ["semi", "active"],
    "requires": [],
    "optional": True,
}

# --- Secret catalogue. (name, compiled regex, redact?) ----------------------
# High-signal patterns only: a bare "password" grep is noise, these are specific.
_SECRET_PATTERNS: list[tuple[str, re.Pattern, bool]] = [
    ("aws_access_key",   re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                      True),
    ("aws_secret",       re.compile(r"(?i)aws_secret_access_key[\"'\s:=]+([A-Za-z0-9/+=]{40})"), True),
    ("google_api_key",   re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),                True),
    ("google_oauth",     re.compile(r"\bya29\.[0-9A-Za-z_\-]+"),                   True),
    ("github_token",     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),           True),
    ("gitlab_token",     re.compile(r"\bglpat-[A-Za-z0-9_\-]{20}\b"),              True),
    ("slack_token",      re.compile(r"\bxox[pbaro]-[A-Za-z0-9\-]{10,}"),          True),
    ("openai_key",       re.compile(r"\bsk-[A-Za-z0-9]{48}\b"),                    True),
    ("anthropic_key",    re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{90,}"),             True),
    ("stripe_live",      re.compile(r"\b[sr]k_live_[A-Za-z0-9]{24,}\b"),           True),
    ("twilio_sid",       re.compile(r"\bAC[a-f0-9]{32}\b"),                        True),
    ("sendgrid_key",     re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), True),
    ("private_key_block",re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), False),
    ("jwt",              re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), True),
]

# Private / loopback URL (internal endpoint shipped in a client binary).
_PRIVATE_URL_RE = re.compile(
    r"https?://(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)[0-9][0-9.]*(?::\d+)?[^\s\"'<>]*"
)
_ANY_URL_RE = re.compile(r"https?://[A-Za-z0-9.\-]+(?::\d+)?[^\s\"'<>]*")

_TEXT_SUFFIXES = {
    ".java", ".kt", ".smali", ".xml", ".json", ".js", ".txt", ".properties",
    ".yml", ".yaml", ".gradle", ".cfg", ".conf", ".pem", ".html", ".graphql",
}
_MAX_FILE_BYTES = 4_000_000      # skip anything larger when scanning text
_MAX_FINDINGS_PER_TYPE = 200     # keep one noisy app from flooding the run


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0 = time.monotonic()
    findings: list[dict] = []
    cfg = config.apk_analysis
    metadata: dict = {
        "authorised": bool(cfg.confirmed),
        "apps_considered": 0,
        "apps_analysed": 0,
        "apps_failed": 0,
    }

    # 1. Decide which apps to analyse: operator override, else owned Play apps.
    targets = await _select_targets(scope, config, db)
    metadata["apps_considered"] = len(targets)
    metadata["candidate_apps"] = [t["ref"] for t in targets]

    if not targets:
        return _result(findings, {**metadata, "note": "no owned Android apps found to analyse"},
                       t0, "partial")

    # 2. Gate: without written authorisation, report the plan and stop.
    if not cfg.confirmed:
        log.warning("apk_analysis.not_authorised", candidates=len(targets))
        findings.append({
            "type": "apk_analysis_pending",
            "value": f"{len(targets)} app(s) await authorisation",
            "data": {
                "apps": [t["ref"] for t in targets],
                "issue": "APK static analysis is gated — set apk_analysis.confirmed "
                         "in config.yaml per engagement to acquire and decompile these apps.",
                "note": "No binary was downloaded. No client infrastructure was contacted.",
                "source": "layer1/mobile_apps",
            },
        })
        return _result(findings, {**metadata, "note": "awaiting authorisation (confirmed=False)"},
                       t0, "partial")

    owned_hosts = _owned_host_labels(scope)
    work_root = Path(config.paths.get("base", config.paths["tmp"])) / "mobile" / "apk"
    work_root.mkdir(parents=True, exist_ok=True)

    # 3. Analyse each authorised app (capped).
    for tgt in targets[: cfg.max_apks]:
        try:
            app_findings = await _analyse_one(tgt, scope, config, owned_hosts, work_root)
            if app_findings is None:
                metadata["apps_failed"] += 1
                continue
            metadata["apps_analysed"] += 1
            findings.extend(app_findings)
        except Exception as exc:   # never raise — one bad APK cannot kill the run
            log.warning("apk_analysis.app_failed", app=tgt["ref"], error=str(exc))
            metadata["apps_failed"] += 1

    # 4. Emit operator-assisted runtime scripts (Frida / objection), never run.
    if cfg.emit_frida and metadata["apps_analysed"]:
        frida_finding = _emit_runtime_scripts(targets[: cfg.max_apks], config)
        if frida_finding:
            findings.append(frida_finding)

    by_type: dict[str, int] = {}
    for f in findings:
        by_type[f["type"]] = by_type.get(f["type"], 0) + 1
    metadata["by_type"] = by_type

    log.info("apk_analysis.complete",
             analysed=metadata["apps_analysed"], failed=metadata["apps_failed"],
             findings=len(findings))
    status = "success" if metadata["apps_analysed"] else "partial"
    return _result(findings, metadata, t0, status)


# ---------------------------------------------------------------------------
# Target selection
# ---------------------------------------------------------------------------

async def _select_targets(scope: Scope, config: Config, db: Any) -> list[dict]:
    """
    Apps to analyse. Operator-supplied packages/paths win; otherwise the
    owned Android apps discovered by layer1/mobile_apps at/above the configured
    ownership likelihood.
    """
    cfg = config.apk_analysis
    out: list[dict] = []
    seen: set[str] = set()

    for item in cfg.packages:
        item = (item or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        if item.lower().endswith(".apk") or "/" in item:
            out.append({"ref": item, "package": None, "local_path": item, "title": None})
        else:
            out.append({"ref": item, "package": item, "local_path": None, "title": None})

    if out:
        return out

    # Pull owned Play apps from the most recent run's mobile_app findings.
    rank = {"high": 3, "medium": 2, "low": 1}
    floor = rank.get(cfg.min_owned_likelihood, 3)
    for row in await _recent_mobile_apps(scope, db):
        data = _row_data(row)
        if data.get("store") != "google_play":
            continue
        if rank.get(data.get("owned_likelihood", "low"), 1) < floor:
            continue
        pkg = data.get("package_id")
        if not pkg or pkg in seen:
            continue
        seen.add(pkg)
        out.append({"ref": pkg, "package": pkg, "local_path": None,
                    "title": data.get("title")})
    return out


async def _recent_mobile_apps(scope: Scope, db: Any) -> list[dict]:
    if db is None:
        return []
    try:
        run_id = await db.get_last_run_id(scope.target.name) or ""
        if not run_id:
            return []
        return await db.get_findings(run_id, "mobile_app")
    except Exception as exc:
        log.debug("apk_analysis.history_failed", error=str(exc))
        return []


def _row_data(row: dict) -> dict:
    d = row.get("data")
    if isinstance(d, str):
        try:
            return json.loads(d)
        except json.JSONDecodeError:
            return {}
    return d or {}


# ---------------------------------------------------------------------------
# Per-app analysis
# ---------------------------------------------------------------------------

async def _analyse_one(
    tgt: dict, scope: Scope, config: Config, owned_hosts: set[str], work_root: Path
) -> list[dict] | None:
    cfg = config.apk_analysis
    ref = tgt["ref"]
    app_dir = work_root / _slug(ref)
    app_dir.mkdir(parents=True, exist_ok=True)

    apk_path = await _obtain_apk(tgt, config, app_dir)
    if not apk_path:
        return None

    # XAPK (a zip of split APKs) -> the base apk inside it.
    apk_path = await _resolve_base_apk(apk_path, config, app_dir)

    extract_dir = app_dir / "unpacked"
    await run_command(["7z", "x", "-y", f"-o{extract_dir}", str(apk_path)],
                      recon_mode="semi", config=config, timeout=120)

    decompiled: Path | None = None
    if cfg.decompile:
        decompiled = app_dir / "jadx"
        r = await run_command(
            ["jadx", "--no-debug-info", "-d", str(decompiled), str(apk_path)],
            recon_mode="semi", config=config, timeout=cfg.jadx_timeout,
        )
        if not r.ok and not decompiled.exists():
            log.debug("apk_analysis.jadx_failed", app=ref, err=(r.stderr or "")[:200])
            decompiled = None

    findings: list[dict] = []
    scan_dirs = [d for d in (decompiled, extract_dir) if d and d.exists()]

    # Text-file scan (decompiled sources + resources).
    secrets, urls = _scan_text_tree(scan_dirs, owned_hosts)

    # String constants in the dex (catches what jadx formats away).
    dex_strings = await _dex_strings(extract_dir, config)
    s2, u2 = _scan_blob(dex_strings, owned_hosts)
    secrets += s2
    urls += u2

    findings += _dedupe_findings(ref, "apk_secret", secrets)
    findings += _dedupe_findings(ref, "apk_internal_url", urls)
    findings += _firebase_findings(ref, scan_dirs)
    findings += _cert_findings(ref, extract_dir, config_cert=config)
    findings += await _exported_components(ref, scan_dirs, config)

    if not findings:
        findings.append({
            "type": "apk_analysed_clean",
            "value": ref,
            "data": {"issue": f"{ref} decompiled, no secrets/internal hosts/exported sinks found",
                     "title": tgt.get("title"), "source": "jadx/static"},
        })
    return findings


async def _obtain_apk(tgt: dict, config: Config, app_dir: Path) -> Path | None:
    cfg = config.apk_analysis
    if tgt.get("local_path"):
        p = Path(tgt["local_path"]).expanduser()
        if p.is_file():
            return p
        log.warning("apk_analysis.local_missing", path=str(p))
        return None
    if not (cfg.acquire and tgt.get("package")):
        return None
    dest = app_dir / f"{tgt['package']}.apk"
    url = cfg.mirror_url.format(pkg=tgt["package"])
    r = await run_command(
        ["curl", "-sk", "-L", "--max-time", str(cfg.acquire_timeout), url, "-o", str(dest)],
        recon_mode="semi", config=config, timeout=cfg.acquire_timeout + 30,
    )
    if not dest.exists() or dest.stat().st_size < 10_000:
        log.warning("apk_analysis.acquire_failed", pkg=tgt["package"],
                    size=dest.stat().st_size if dest.exists() else 0)
        return None
    return dest


async def _resolve_base_apk(apk_path: Path, config: Config, app_dir: Path) -> Path:
    """If the download is an XAPK (zip of apks), extract and return the base apk."""
    r = await run_command(["7z", "l", str(apk_path)], recon_mode="semi",
                          config=config, timeout=60)
    listing = (r.stdout or "")
    inner = [ln.split()[-1] for ln in listing.splitlines()
             if ln.strip().lower().endswith(".apk")]
    if not inner:
        return apk_path          # already a plain APK
    xdir = app_dir / "xapk"
    await run_command(["7z", "x", "-y", f"-o{xdir}", str(apk_path)],
                      recon_mode="semi", config=config, timeout=120)
    apks = sorted(xdir.rglob("*.apk"), key=lambda p: p.stat().st_size, reverse=True)
    # Prefer base.apk, else the largest split.
    for p in apks:
        if p.name.lower() in ("base.apk",) or "config." not in p.name.lower():
            return p
    return apks[0] if apks else apk_path


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def _scan_text_tree(dirs: list[Path], owned_hosts: set[str]) -> tuple[list[dict], list[dict]]:
    secrets: list[dict] = []
    urls: list[dict] = []
    for base in dirs:
        for p in base.rglob("*"):
            if not p.is_file() or p.suffix.lower() not in _TEXT_SUFFIXES:
                continue
            try:
                if p.stat().st_size > _MAX_FILE_BYTES:
                    continue
                text = p.read_text(errors="replace")
            except OSError:
                continue
            rel = _rel(p, base)
            s, u = _scan_blob(text, owned_hosts, where=rel)
            secrets += s
            urls += u
    return secrets, urls


def _scan_blob(text: str, owned_hosts: set[str], where: str = "classes.dex") -> tuple[list[dict], list[dict]]:
    secrets: list[dict] = []
    for name, rx, redact in _SECRET_PATTERNS:
        for mobj in rx.finditer(text):
            raw = mobj.group(0)
            secrets.append({
                "kind": name,
                "match": _redact(raw) if redact else raw,
                "where": where,
            })
    urls: list[dict] = []
    for mobj in _PRIVATE_URL_RE.finditer(text):
        urls.append({"url": mobj.group(0), "why": "private/loopback address", "where": where})
    if owned_hosts:
        for mobj in _ANY_URL_RE.finditer(text):
            host = _host_of(mobj.group(0))
            if host and any(host == h or host.endswith("." + h) for h in owned_hosts):
                urls.append({"url": mobj.group(0), "why": "owned-brand host", "where": where})
    return secrets, urls


async def _dex_strings(extract_dir: Path, config: Config) -> str:
    dexes = sorted(extract_dir.glob("classes*.dex"))
    out: list[str] = []
    for dex in dexes:
        r = await run_command(["strings", "-n", "6", str(dex)],
                              recon_mode="semi", config=config, timeout=120)
        if r.ok:
            out.append(r.stdout or "")
    return "\n".join(out)


def _firebase_findings(ref: str, dirs: list[Path]) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for base in dirs:
        for p in list(base.rglob("google-services.json")) + list(base.rglob("google_services.json")):
            try:
                doc = json.loads(p.read_text(errors="replace"))
            except (OSError, json.JSONDecodeError):
                continue
            proj = (((doc.get("project_info") or {}).get("project_id")) or "")
            bucket = (((doc.get("project_info") or {}).get("storage_bucket")) or "")
            key = proj + "|" + bucket
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "type": "apk_firebase_config",
                "value": proj or ref,
                "data": {
                    "app": ref,
                    "project_id": proj,
                    "storage_bucket": bucket,
                    "database_url": (doc.get("project_info") or {}).get("firebase_url"),
                    "issue": f"Firebase config shipped in {ref} (project {proj})",
                    "next": [
                        f"RTDB public read: https://{proj}.firebaseio.com/.json" if proj else "",
                        f"Storage list: https://firebasestorage.googleapis.com/v0/b/{bucket}/o" if bucket else "",
                    ],
                    "source": "google-services.json",
                },
            })
    return out


def _cert_findings(ref: str, extract_dir: Path, config_cert: Config) -> list[dict]:
    # Enumeration is cheap; parsing each cert with openssl is done lazily by the
    # operator from the recorded path. We record the pinned-cert presence + path.
    out: list[dict] = []
    exts = {".cer", ".der", ".pem", ".crt", ".pfx", ".p12", ".bks"}
    for p in extract_dir.rglob("*"):
        if p.is_file() and p.suffix.lower() in exts and "assets" in str(p).lower():
            out.append({
                "type": "apk_pinned_cert",
                "value": p.name,
                "data": {
                    "app": ref,
                    "path": _rel(p, extract_dir),
                    "issue": f"Certificate bundled in {ref} assets ({p.name}) — likely pinning; "
                             f"inspect SANs for undisclosed internal hosts",
                    "inspect": f"openssl x509 -in <path> -noout -text | grep -E 'Subject:|DNS:'",
                    "source": "assets/",
                },
            })
    # network_security_config pinning
    for p in extract_dir.rglob("network_security_config.xml"):
        try:
            txt = p.read_text(errors="replace")
        except OSError:
            continue
        if "pin-set" in txt or "<pin " in txt:
            out.append({
                "type": "apk_pinned_cert",
                "value": "network_security_config",
                "data": {"app": ref, "path": _rel(p, extract_dir),
                         "issue": f"{ref} pins via network_security_config.xml",
                         "source": "res/xml"},
            })
    return out[:_MAX_FINDINGS_PER_TYPE]


async def _exported_components(ref: str, dirs: list[Path], config: Config) -> list[dict]:
    manifest = None
    for base in dirs:
        for cand in [base / "resources" / "AndroidManifest.xml",
                     base / "AndroidManifest.xml"]:
            if cand.is_file():
                manifest = cand
                break
        if manifest:
            break
    if not manifest:
        return []
    try:
        txt = manifest.read_text(errors="replace")
    except OSError:
        return []
    out: list[dict] = []
    comp_re = re.compile(
        r"<(activity|service|receiver|provider)\b[^>]*android:exported=\"true\"[^>]*>",
        re.IGNORECASE,
    )
    name_re = re.compile(r'android:name="([^"]+)"')
    for mobj in comp_re.finditer(txt):
        tag = mobj.group(1)
        nm = name_re.search(mobj.group(0))
        out.append({
            "type": "apk_exported_component",
            "value": (nm.group(1) if nm else tag),
            "data": {
                "app": ref, "component_type": tag,
                "name": nm.group(1) if nm else None,
                "issue": f"Exported {tag} in {ref} — reachable by other apps "
                         f"(check intent extras reaching WebView/URI/redirect sinks)",
                "source": "AndroidManifest.xml",
            },
        })
    return out[:_MAX_FINDINGS_PER_TYPE]


# ---------------------------------------------------------------------------
# Operator-assisted runtime scripts (never auto-run)
# ---------------------------------------------------------------------------

def _emit_runtime_scripts(targets: list[dict], config: Config) -> dict | None:
    tools_dir = Path(config.paths.get("base", config.paths["tmp"])) / "tools" / "frida"
    try:
        tools_dir.mkdir(parents=True, exist_ok=True)
        (tools_dir / "ssl_pinning_bypass.js").write_text(_FRIDA_PINNING)
        (tools_dir / "root_bypass.js").write_text(_FRIDA_ROOT)
        (tools_dir / "http_hook.js").write_text(_FRIDA_HTTP_HOOK)
        pkgs = [t["package"] for t in targets if t.get("package")]
        (tools_dir / "RUN.md").write_text(_runbook(pkgs))
    except OSError as exc:
        log.debug("apk_analysis.frida_emit_failed", error=str(exc))
        return None
    return {
        "type": "apk_runtime_playbook",
        "value": "frida/objection scripts staged",
        "data": {
            "dir": str(tools_dir),
            "scripts": ["ssl_pinning_bypass.js", "root_bypass.js", "http_hook.js", "RUN.md"],
            "issue": "Runtime instrumentation staged for operator use on a test device. "
                     "Not executed by the pipeline (requires a device and is active by nature).",
            "run": "frida -U -l ssl_pinning_bypass.js -f <package> --no-pause",
            "source": "apk_analysis",
        },
    }


def _runbook(pkgs: list[str]) -> str:
    lst = "\n".join(f"  frida -U -l ssl_pinning_bypass.js -f {p} --no-pause" for p in pkgs) or \
          "  frida -U -l ssl_pinning_bypass.js -f <package> --no-pause"
    return (
        "# Runtime instrumentation (operator-assisted)\n\n"
        "Run on a rooted test device or emulator with frida-server, never a production phone.\n"
        "These are ACTIVE on the app runtime and are intentionally not run by the scanner.\n\n"
        "## SSL pinning bypass + traffic capture\n"
        f"{lst}\n\n"
        "  # then route the device through Burp/mitmproxy and exercise the app\n\n"
        "## Root-detection bypass (if the app refuses to start)\n"
        "  frida -U -l root_bypass.js -f <package> --no-pause\n\n"
        "## Token/HTTP tracing\n"
        "  frida -U -l http_hook.js -f <package> --no-pause\n\n"
        "## objection (quick exploration)\n"
        "  objection --gadget <package> explore\n"
        "  # android sslpinning disable\n"
        "  # android root disable\n"
    )


_FRIDA_PINNING = """// SSL pinning bypass (OkHttp + Conscrypt + TrustManager). Test device only.
Java.perform(function () {
  try {
    var CP = Java.use('okhttp3.CertificatePinner');
    CP.check.overload('java.lang.String', 'java.util.List').implementation = function (h) {
      console.log('[+] OkHttp pinning bypassed: ' + h); return;
    };
  } catch (e) {}
  try {
    var TM = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TM.verifyChain.implementation = function (chain) {
      console.log('[+] TrustManagerImpl.verifyChain bypassed'); return chain;
    };
  } catch (e) {}
});
"""

_FRIDA_ROOT = """// Root-detection bypass. Test device only.
Java.perform(function () {
  try {
    var F = Java.use('java.io.File');
    F.exists.implementation = function () {
      var p = this.getAbsolutePath();
      if (p.indexOf('su') !== -1 || p.indexOf('magisk') !== -1 || p.indexOf('busybox') !== -1) {
        console.log('[+] hid root path: ' + p); return false;
      }
      return this.exists();
    };
  } catch (e) {}
});
"""

_FRIDA_HTTP_HOOK = """// Log outbound OkHttp requests (URL + headers). Test device only.
Java.perform(function () {
  try {
    var Client = Java.use('okhttp3.OkHttpClient');
    Client.newCall.implementation = function (req) {
      try { console.log('[REQ] ' + req.url().toString() + '\\n' + req.headers().toString()); }
      catch (e) {}
      return this.newCall(req);
    };
  } catch (e) {}
});
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dedupe_findings(ref: str, ftype: str, items: list[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for it in items:
        key = json.dumps(it, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        if ftype == "apk_secret":
            value = f"{it['kind']}"
            data = {"app": ref, "kind": it["kind"], "match_redacted": it["match"],
                    "where": it["where"],
                    "issue": f"{it['kind']} hardcoded in {ref} ({it['where']})",
                    "source": "jadx/strings"}
        else:  # apk_internal_url
            value = it["url"]
            data = {"app": ref, "url": it["url"], "why": it["why"], "where": it["where"],
                    "issue": f"Internal/owned host in {ref}: {it['url']} ({it['why']})",
                    "source": "jadx/strings"}
        out.append({"type": ftype, "value": value, "data": data})
        if len(out) >= _MAX_FINDINGS_PER_TYPE:
            break
    return out


def _owned_host_labels(scope: Scope) -> set[str]:
    hosts: set[str] = set()
    for d in scope.all_domains:
        d = (d or "").strip().lower()
        if d:
            hosts.add(d)
    for a in scope.target.aliases or []:
        a = (a or "").strip().lower()
        if "." in a and " " not in a:
            hosts.add(a)
    return hosts


def _host_of(url: str) -> str | None:
    m = re.match(r"https?://([A-Za-z0-9.\-]+)", url)
    return m.group(1).lower() if m else None


def _redact(s: str) -> str:
    s = s.strip()
    if len(s) <= 10:
        return s[:2] + "***"
    return f"{s[:4]}...{s[-4:]} (len {len(s)})"


def _rel(p: Path, base: Path) -> str:
    try:
        return str(p.relative_to(base))
    except ValueError:
        return p.name


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:120] or "app"


def _result(findings: list, metadata: dict, t0: float, status: str) -> dict:
    return {
        "module":   "layer2_5/apk_analysis",
        "status":   status,
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None,
    }
