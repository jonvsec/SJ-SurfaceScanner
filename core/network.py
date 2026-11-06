"""
core/network.py — local vs VPS boundary enforcement.

Modules call run_command() to execute shell tools. Routing:
  passive/semi → always local
  active + active_recon_via_vps=True → disposable VPS via SSH

NetworkBoundaryError is raised (not swallowed) when active mode is requested
but no VPS is configured. This makes the enforcement a hard code check,
not a policy comment that can be silently ignored.
"""
from __future__ import annotations

import asyncio
import os
import shlex
import shutil
import time
from dataclasses import dataclass

import structlog

from core.config import Config

log = structlog.get_logger(__name__)


# ProjectDiscovery / Go-installed tools that must resolve to the Go bin, never to
# a same-named shadow earlier on PATH. `httpx` is the dangerous one: the Python
# httpx library ships a `.venv/bin/httpx` console script that shadows the
# ProjectDiscovery prober under a thin service PATH, so a blind shutil.which()
# would silently run the WRONG binary (different flags, garbage output). For
# every name here the Go bin is searched first, so the tool is unambiguous no
# matter who launched the process or what their PATH looks like.
_GO_TOOLS = frozenset({
    "httpx", "dnsx", "subfinder", "naabu", "alterx", "amass", "puredns",
    "massdns", "nuclei", "katana", "gowitness", "chaos", "gau", "waybackurls",
    "assetfinder", "subjack", "subzy", "dalfox", "qsreplace", "urlfinder",
    "hakrawler", "gotator", "httprobe",
})

# Tools a run asked for but could not resolve this cycle. A watcher resets this
# at the start of a cycle and inspects it at the end, so a missing tool becomes
# a loud, visible "degraded" state instead of a module silently returning [].
MISSING_TOOLS: set[str] = set()


def reset_missing_tools() -> None:
    MISSING_TOOLS.clear()


def _go_bin_dirs() -> list[str]:
    dirs: list[str] = []
    gobin = os.environ.get("GOBIN")
    gopath = os.environ.get("GOPATH")
    for v in (gobin,
              (os.path.join(gopath, "bin") if gopath else None),
              os.path.expanduser("~/go/bin")):
        if v and v not in dirs:
            dirs.append(v)
    return dirs


def resolve_tool(name: str) -> str | None:
    """
    Absolute path to a CLI tool, or None if it cannot be found anywhere.

    Go tools (see _GO_TOOLS) resolve to the Go bin FIRST, so a same-named shadow
    such as the Python httpx CLI in the venv never wins. Everything else falls
    back to the normal PATH search. This makes tool resolution independent of the
    caller's PATH, which is the whole point: a thin systemd --user PATH can no
    longer hide an installed tool.
    """
    if os.path.isabs(name):
        return name if os.access(name, os.X_OK) else None
    if name in _GO_TOOLS:
        for d in _go_bin_dirs():
            cand = os.path.join(d, name)
            if os.access(cand, os.X_OK):
                return cand
    found = shutil.which(name)
    if found:
        return found
    return None


class NetworkBoundaryError(Exception):
    """Active recon attempted without a configured VPS."""


@dataclass
class CommandResult:
    returncode: int
    stdout:     str
    stderr:     str
    duration:   float
    ran_on:     str   # "local" | "vps"

    @property
    def ok(self) -> bool:
        return self.returncode == 0


async def run_command(
    cmd: list[str],
    *,
    recon_mode: str,
    config: Config,
    timeout: int | None = None,
    env: dict[str, str] | None = None,
) -> CommandResult:
    """
    Execute a shell command, routing to VPS when active recon is required.

    Args:
        cmd:        Command and arguments as a list, e.g. ["nmap", "-sV", target].
        recon_mode: The module's recon mode — "passive", "semi", or "active".
        config:     Loaded system config (used for network settings and timeouts).
        timeout:    Override timeout in seconds. Defaults to config.timeouts.default.
        env:        Additional environment variables for the subprocess.

    Returns:
        CommandResult with returncode, stdout, stderr, duration, ran_on.

    Raises:
        NetworkBoundaryError: if recon_mode is "active", active_recon_via_vps is
            enabled, but vps_ssh_host is not configured.
    """
    timeout = timeout or config.timeouts.default
    net     = config.network

    if recon_mode == "active" and net.active_recon_via_vps:
        if not net.vps_ssh_host:
            raise NetworkBoundaryError(
                "Active recon requires a VPS but network.vps_ssh_host is not set. "
                "Configure vps_ssh_host in config.yaml or set mode to 'semi'."
            )
        return await _run_via_ssh(cmd, config, timeout)

    return await _run_local(cmd, timeout, env)


async def _run_local(
    cmd: list[str],
    timeout: int,
    env: dict[str, str] | None = None,
) -> CommandResult:
    log.debug("network.run_local", cmd=cmd[0], args=cmd[1:])
    t0 = time.monotonic()

    # Resolve the tool to an absolute path so we never depend on the caller's
    # PATH, and record it loudly if it cannot be found anywhere.
    resolved = resolve_tool(cmd[0])
    if resolved is None:
        MISSING_TOOLS.add(cmd[0])
        log.warning("network.tool_missing", tool=cmd[0])
        return CommandResult(
            returncode=127,
            stdout="",
            stderr=f"command not found: {cmd[0]}",
            duration=time.monotonic() - t0,
            ran_on="local",
        )
    cmd = [resolved, *cmd[1:]]

    # Give the child a PATH that includes the Go bin, so a tool that shells out
    # to a sibling by bare name (for example puredns calling massdns) finds it
    # even when the service PATH is thin.
    run_env = dict(os.environ)
    if env:
        run_env.update(env)
    existing = run_env.get("PATH", "")
    run_env["PATH"] = os.pathsep.join(
        _go_bin_dirs() + ([existing] if existing else [])
    )

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=run_env,
        )
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        log.warning("network.timeout", cmd=cmd[0], timeout=timeout)
        return CommandResult(
            returncode=-1,
            stdout="",
            stderr=f"command timed out after {timeout}s",
            duration=time.monotonic() - t0,
            ran_on="local",
        )
    except FileNotFoundError:
        return CommandResult(
            returncode=127,
            stdout="",
            stderr=f"command not found: {cmd[0]}",
            duration=time.monotonic() - t0,
            ran_on="local",
        )

    return CommandResult(
        returncode=proc.returncode,
        stdout=stdout_b.decode(errors="replace"),
        stderr=stderr_b.decode(errors="replace"),
        duration=time.monotonic() - t0,
        ran_on="local",
    )


async def _run_via_ssh(
    cmd: list[str],
    config: Config,
    timeout: int,
) -> CommandResult:
    net         = config.network
    remote_cmd  = shlex.join(cmd)
    ssh_cmd     = ["ssh"]

    if net.vps_ssh_key:
        ssh_cmd += ["-i", net.vps_ssh_key]

    ssh_cmd += [
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        net.vps_ssh_host,
        remote_cmd,
    ]

    log.info("network.run_vps", host=net.vps_ssh_host, cmd=cmd[0])
    result = await _run_local(ssh_cmd, timeout)
    result.ran_on = "vps"
    return result


async def check_tool(tool: str) -> bool:
    """
    Return True if a CLI tool can be resolved (Go bin or PATH).

    Uses the same resolver the executor uses, so a tool the service can actually
    run is never reported missing and vice versa. For `httpx` it also verifies
    identity, because a resolvable `httpx` might be the Python library's CLI
    rather than the ProjectDiscovery prober.
    """
    path = resolve_tool(tool)
    if path is None:
        return False
    if tool == "httpx":
        res = await _run_local([path, "-version"], timeout=5)
        blob = (res.stdout + res.stderr).lower()
        # the Python httpx CLI does not know -version and does not mention PD
        if "projectdiscovery" not in blob and res.returncode != 0:
            log.warning("network.httpx_wrong_binary", path=path)
            return False
    return True
