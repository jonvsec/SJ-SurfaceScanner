"""
tests/test_tool_resolve.py. Regression tests for core.network tool resolution.

These lock in the fix for the "0 alive for a live domain" bug: the resolver must
find Go tools regardless of the caller's PATH, and must resolve `httpx` to the
ProjectDiscovery prober rather than the Python httpx CLI that the venv installs
under the same name. A thin systemd --user PATH must not be able to hide or
swap a tool.
"""
from __future__ import annotations

import os

from core import network as net


def _make_go_tool(tmp_path, name):
    d = tmp_path / "go" / "bin"
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_text("#!/bin/sh\necho ok\n")
    p.chmod(0o755)
    return d, p


def test_go_tool_found_without_path(tmp_path, monkeypatch):
    """A Go tool resolves from GOBIN even when PATH is empty."""
    gobin, exe = _make_go_tool(tmp_path, "dnsx")
    monkeypatch.setenv("GOBIN", str(gobin))
    monkeypatch.setenv("PATH", "/nonexistent")
    assert net.resolve_tool("dnsx") == str(exe)


def test_httpx_prefers_go_over_shadow(tmp_path, monkeypatch):
    """httpx must resolve to the Go bin even when a same-named shadow (the
    Python httpx CLI) is earlier on PATH. This is the collision that would
    silently run the wrong binary under the service."""
    gobin, go_httpx = _make_go_tool(tmp_path, "httpx")
    shadow_dir = tmp_path / "venv" / "bin"
    shadow_dir.mkdir(parents=True, exist_ok=True)
    shadow = shadow_dir / "httpx"
    shadow.write_text("#!/bin/sh\necho python-httpx\n")
    shadow.chmod(0o755)
    monkeypatch.setenv("GOBIN", str(gobin))
    monkeypatch.setenv("PATH", str(shadow_dir))   # shadow is the only thing on PATH
    assert net.resolve_tool("httpx") == str(go_httpx)


def test_missing_tool_returns_none(monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")
    monkeypatch.setenv("GOBIN", "/nonexistent/go/bin")
    monkeypatch.delenv("GOPATH", raising=False)
    # a name that is not a Go tool and not on PATH
    assert net.resolve_tool("totally-not-a-real-tool-xyz") is None


def test_missing_registry_records_on_run(tmp_path, monkeypatch):
    """A missing tool run through _run_local populates the loud registry."""
    import asyncio

    monkeypatch.setenv("PATH", "/nonexistent")
    monkeypatch.setenv("GOBIN", "/nonexistent/go/bin")
    monkeypatch.delenv("GOPATH", raising=False)
    net.reset_missing_tools()
    res = asyncio.run(net._run_local(["totally-not-a-real-tool-xyz"], timeout=5))
    assert res.returncode == 127
    assert "totally-not-a-real-tool-xyz" in net.MISSING_TOOLS
