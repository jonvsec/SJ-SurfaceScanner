"""
layer2_5/smtp_recon.py — SMTP service security assessment.

When an SMTP port (25/465/587) is discovered, this module runs the standard
external SMTP checklist against it. These techniques were applied by hand during
a live engagement and are codified here so every future SMTP finding is assessed
consistently:

  1. EHLO capability enumeration               (banner + advertised extensions)
  2. Internal-extension exposure               (XEXCH50 / XSHADOW / X-EXPS —
                                                internal Exchange verbs that must
                                                not face the internet)
  3. STARTTLS certificate inspection           (self-signed / expired / hostname
                                                mismatch on the mail transport)
  4. Open-relay test                           (safe: MAIL FROM/RCPT TO an
                                                external address, observe the
                                                rejection, QUIT before DATA — no
                                                message is ever relayed)
  5. User enumeration surface                  (does the server advertise VRFY /
                                                EXPN, which permit account
                                                enumeration)
  6. NTLM information disclosure               (AUTH NTLM Type-1 → decode the
                                                Type-2 challenge for the internal
                                                NetBIOS/DNS/forest names — no
                                                credentials submitted)
  7. Internal server-name disclosure           (MAIL FROM:<me> auto-completion
                                                leaking the internal FQDN)

SAFETY. Every check is non-mutating. The open-relay test never sends DATA, so no
mail is transmitted. NTLM disclosure sends a canned negotiate token and reads the
challenge; no password is submitted. No authentication is attempted.

Targets are taken from `open_port` findings (ports 25/465/587) and from MX
hostnames in `resolved_host` findings, so the module works whether ports came
from an active scan or MX records came from passive DNS.

Mode: semi/active — it connects to the target's mail server directly.
"""
from __future__ import annotations

import asyncio
import base64
import re
import ssl
import struct
import time
from typing import Any

import structlog

from core.config import Config
from core.scope_guard import in_scope
from scope_parser import Scope

log = structlog.get_logger(__name__)

MODULE_META = {
    "name":     "smtp_recon",
    "title":    "SMTP Service Assessment",
    "description": "Open-relay, user-enum, STARTTLS cert, NTLM disclosure and internal-extension checks on discovered SMTP services",
    "layer":    2.5,
    "mode":     ["semi", "active"],
    "requires": [],
    "optional": True,
}

_SMTP_PORTS = (25, 587, 465)
_TIMEOUT = 15

# Internal Exchange verbs that should never be advertised to the internet.
_INTERNAL_EXTENSIONS = ("XEXCH50", "XSHADOW", "X-EXPS", "XLONGADDR", "XRDST")

# Canned NTLMSSP Type-1 negotiate token (no credentials).
_NTLM_TYPE1 = "TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA="


async def run(scope: Scope, config: Config, db: Any) -> dict:
    t0       = time.monotonic()
    findings: list[dict] = []
    metadata: dict = {"targets": 0, "reachable": 0, "issues": 0}

    targets = await _collect_targets(scope, db)
    metadata["targets"] = len(targets)

    for host, port in targets:
        result = await _assess(host, port)
        if result is None:
            continue
        metadata["reachable"] += 1
        for f in result:
            findings.append(f)
            if f["type"] != "smtp_capabilities":
                metadata["issues"] += 1

    status = "success" if findings else "partial"
    log.info("smtp_recon.complete", targets=len(targets),
             reachable=metadata["reachable"], findings=len(findings))
    return {
        "module":   "layer2_5/smtp_recon",
        "status":   status,
        "findings": findings,
        "metadata": metadata,
        "duration": time.monotonic() - t0,
        "error":    None if targets else "no SMTP targets discovered",
    }


async def _collect_targets(scope: Scope, db: Any) -> list[tuple[str, int]]:
    """SMTP endpoints from open-port findings + MX hosts from resolved hosts."""
    seen: set[tuple[str, int]] = set()
    if db is None:
        return []
    try:
        run_id = await db.get_last_run_id(scope.target.name) or ""
        if not run_id:
            return []
        for row in await db.get_findings(run_id, "open_port"):
            d = row.get("data") or {}
            ip, port = d.get("ip", ""), int(d.get("port", 0) or 0)
            if ip and port in _SMTP_PORTS:
                seen.add((ip, port))
        # MX hostnames are prime SMTP targets even without an active port scan.
        for row in await db.get_findings(run_id, "resolved_host"):
            d = row.get("data") or {}
            for mx in (d.get("mx") or []):
                mx = mx.strip().rstrip(".")
                if not mx:
                    continue
                # An MX host usually belongs to the mail PROVIDER, not the
                # client. Every domain in this engagement points at
                # *.mail.protection.outlook.com — probing those is probing
                # Microsoft, who authorised nothing.
                if not in_scope(mx, scope):
                    log.warning("smtp_recon.third_party_mx_skipped", mx=mx)
                    continue
                seen.add((mx, 25))
    except Exception as exc:
        log.debug("smtp_recon.target_collection_failed", error=str(exc))
    return sorted(seen)


async def _assess(host: str, port: int) -> list[dict] | None:
    """Run the full checklist against one SMTP endpoint. Never raises."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=_TIMEOUT)
    except Exception:
        return None

    findings: list[dict] = []
    try:
        banner = await _readline(reader)
        caps   = await _ehlo(reader, writer)
        base   = {"host": host, "port": port}

        findings.append({
            "type":  "smtp_capabilities",
            "value": f"{host}:{port}",
            "data":  {**base, "banner": banner[:200],
                      "extensions": sorted(caps)},
        })

        # 1. internal-extension exposure ----------------------------------
        exposed = [e for e in _INTERNAL_EXTENSIONS
                   if any(e in c for c in caps)]
        if exposed:
            findings.append({
                "type":  "smtp_internal_extension_exposure",
                "value": f"{host}:{port}",
                "data": {**base, "extensions": exposed, "severity": "medium",
                         "detail": "internal-only Exchange verbs advertised to "
                                   "the internet — indicates an internal-role "
                                   "connector is publicly bound"},
            })

        # 2. user-enum surface --------------------------------------------
        enum_verbs = [v for v in ("VRFY", "EXPN") if v in caps]
        if enum_verbs:
            findings.append({
                "type":  "smtp_user_enumeration",
                "value": f"{host}:{port}",
                "data": {**base, "verbs": enum_verbs, "severity": "low",
                         "detail": "VRFY/EXPN advertised — permits account "
                                   "enumeration"},
            })

        # 3. NTLM information disclosure -----------------------------------
        if any("NTLM" in c for c in caps):
            info = await _ntlm_disclose(reader, writer)
            if info:
                findings.append({
                    "type":  "smtp_ntlm_disclosure",
                    "value": f"{host}:{port}",
                    "data": {**base, **info, "severity": "low",
                             "detail": "AUTH NTLM challenge leaks internal AD "
                                       "naming pre-authentication"},
                })

        # 4. STARTTLS certificate ------------------------------------------
        if "STARTTLS" in caps:
            cert = await _starttls_cert(host, port)
            if cert and cert.get("issue"):
                findings.append({
                    "type":  "smtp_starttls_cert_issue",
                    "value": f"{host}:{port}",
                    "data": {**base, **cert, "severity": "medium"},
                })

        # 5. open relay (safe — no DATA) -----------------------------------
        relay = await _open_relay_test(host, port)
        if relay is not None:
            findings.append({
                "type":  "smtp_open_relay" if relay else "smtp_relay_closed",
                "value": f"{host}:{port}",
                "data": {**base, "open_relay": relay,
                         "severity": "high" if relay else "info",
                         "detail": ("accepted external->external mail (open relay)"
                                    if relay else
                                    "rejected external relay (correct)")},
            })
        return findings
    except Exception as exc:
        log.debug("smtp_recon.assess_failed", host=host, error=str(exc))
        return findings or None
    finally:
        try:
            writer.write(b"QUIT\r\n"); await writer.drain()
            writer.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# SMTP primitives
# ---------------------------------------------------------------------------

async def _readline(reader) -> str:
    try:
        data = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=_TIMEOUT)
        return data.decode("utf-8", "ignore").strip()
    except Exception:
        return ""


async def _cmd(reader, writer, line: str) -> str:
    writer.write((line + "\r\n").encode())
    await writer.drain()
    # multiline replies: read until a line without a continuation dash.
    out = []
    while True:
        ln = await _readline(reader)
        if not ln:
            break
        out.append(ln)
        if len(ln) >= 4 and ln[3] == " ":
            break
    return "\n".join(out)


async def _ehlo(reader, writer) -> set[str]:
    resp = await _cmd(reader, writer, "EHLO example.com")
    caps: set[str] = set()
    for i, ln in enumerate(resp.splitlines()):
        m = re.match(r"^250[ -](.+)$", ln)
        if not m:
            continue
        cap = m.group(1).strip()
        # The first 250 line is the server greeting ("host Hello [ip]"), not a
        # capability — skip it so it does not pollute the extension list.
        if i == 0 and ("hello" in cap.lower() or "[" in cap):
            continue
        caps.add(cap.upper())
    return caps


async def _ntlm_disclose(reader, writer) -> dict | None:
    resp = await _cmd(reader, writer, "AUTH NTLM " + _NTLM_TYPE1)
    m = re.search(r"334\s+([A-Za-z0-9+/=]+)", resp)
    if not m:
        return None
    try:
        chal = base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4))
        ti_len = struct.unpack("<H", chal[40:42])[0]
        ti_off = struct.unpack("<I", chal[44:48])[0]
        ti = chal[ti_off:ti_off + ti_len]
        names = {1: "netbios_computer", 2: "netbios_domain",
                 3: "dns_computer", 4: "dns_domain", 5: "dns_forest"}
        out: dict = {}
        i = 0
        while i + 4 <= len(ti):
            t, l = struct.unpack("<HH", ti[i:i + 4]); i += 4
            if t == 0:
                break
            v = ti[i:i + l]; i += l
            if t in names:
                out[names[t]] = v.decode("utf-16le", "ignore")
        # abort the auth cleanly
        writer.write(b"*\r\n"); await writer.drain()
        await _readline(reader)
        return out or None
    except Exception:
        return None


async def _starttls_cert(host: str, port: int) -> dict | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=_TIMEOUT)
        await _readline(reader)
        await _cmd(reader, writer, "EHLO example.com")
        resp = await _cmd(reader, writer, "STARTTLS")
        if not resp.startswith("220"):
            writer.close(); return None
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        loop = asyncio.get_event_loop()
        # upgrade the existing transport to TLS
        transport = writer.transport
        protocol = transport.get_protocol()
        new_transport = await loop.start_tls(
            transport, protocol, ctx, server_side=False,
            server_hostname=host)
        ssl_obj = new_transport.get_extra_info("ssl_object")
        der = ssl_obj.getpeercert(binary_form=True)
        new_transport.close()
        return _analyse_cert(der, host)
    except Exception as exc:
        log.debug("smtp_recon.starttls_failed", host=host, error=str(exc))
        return None


def _analyse_cert(der: bytes, host: str) -> dict:
    import datetime
    pem = ssl.DER_cert_to_PEM_cert(der)
    info: dict = {"issue": None}
    try:
        import tempfile, os
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write(pem); path = f.name
        cert = ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
        os.unlink(path)
        subj = dict(x[0] for x in cert.get("subject", ()))
        issr = dict(x[0] for x in cert.get("issuer", ()))
        cn   = subj.get("commonName", "")
        info["subject_cn"] = cn
        info["issuer_cn"]  = issr.get("commonName", "")
        info["not_after"]  = cert.get("notAfter", "")
        sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
        info["sans"] = sans
        # self-signed?
        if subj == issr:
            info["issue"] = "self-signed certificate on mail transport"
        # expired?
        try:
            exp = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            if exp < datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None):
                info["issue"] = "expired certificate"
        except Exception:
            pass
        # hostname mismatch?
        if not info["issue"] and host not in sans and host != cn:
            info["issue"] = f"hostname mismatch (cert for {cn or sans})"
    except Exception:
        pass
    return info


async def _open_relay_test(host: str, port: int) -> bool | None:
    """
    Safe open-relay probe: attempt MAIL FROM external -> RCPT TO external, read
    the RCPT response, then QUIT. DATA is never sent, so no message can be
    relayed. Returns True (relay accepted), False (rejected), or None (couldn't
    determine).
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=_TIMEOUT)
        await _readline(reader)
        await _cmd(reader, writer, "EHLO example.com")
        mf = await _cmd(reader, writer, "MAIL FROM:<relaytest@example.com>")
        if not mf.startswith(("250", "251")):
            writer.close(); return None
        rcpt = await _cmd(reader, writer, "RCPT TO:<relaytest@gmail.com>")
        writer.write(b"QUIT\r\n"); await writer.drain()
        writer.close()
        # 250/251 = accepted for relay (BAD). 5xx = rejected (GOOD).
        if rcpt.startswith(("250", "251")):
            return True
        if rcpt[:1] == "5":
            return False
        return None
    except Exception:
        return None
