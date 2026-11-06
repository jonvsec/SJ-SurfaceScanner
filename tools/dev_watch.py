#!/usr/bin/env python3
"""Dev live-reload for the Continuous EAS console.

Runs tools/panel.py and restarts it automatically whenever a watched Python
file changes, so the edit-save-see loop needs no manual restart.

CSS is NOT watched on purpose: tools/panel.css is served fresh on every request
(see _css() in panel.py), so a stylesheet edit shows on a plain browser reload
with no restart at all. This watcher is only for Python changes.

Usage:
    # stop any panel already bound to 8787 first, then:
    PANEL_ACTION_PASSWORD=<dev-pw> .venv/bin/python tools/dev_watch.py

It honors any PANEL_* variables already in the environment and defaults the two
dev flags (no auth, no step-up). Ctrl-C stops the panel and the watcher.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PYTHON = ROOT / ".venv" / "bin" / "python"
WATCH = [HERE / "panel.py", HERE / "footprint_run.py"]

env = dict(os.environ)
env.setdefault("PANEL_NO_AUTH", "1")
env.setdefault("PANEL_NO_STEPUP", "1")
# PANEL_ACTION_PASSWORD is left to the operator: without it, control actions
# (Run/Stop) stay disabled, which is the safe default.


def launch() -> subprocess.Popen:
    return subprocess.Popen([str(PYTHON), str(HERE / "panel.py")],
                            cwd=str(ROOT), env=env)


def snapshot() -> dict:
    return {p: p.stat().st_mtime for p in WATCH if p.exists()}


def stop(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def main() -> int:
    if not PYTHON.exists():
        print(f"[dev_watch] venv python not found at {PYTHON}", file=sys.stderr)
        return 2
    proc = launch()
    last = snapshot()
    names = ", ".join(p.name for p in WATCH)
    print(f"[dev_watch] panel started pid={proc.pid}. Watching {names}. "
          f"Edit tools/panel.css freely (no restart). Ctrl-C to stop.")
    try:
        while True:
            time.sleep(1)
            if proc.poll() is not None:
                print("[dev_watch] panel exited, relaunching")
                proc = launch()
                last = snapshot()
                continue
            now = snapshot()
            if now != last:
                changed = [p.name for p in now if last.get(p) != now[p]]
                print(f"[dev_watch] change in {changed or ['(file set)']}, "
                      f"restarting panel")
                stop(proc)
                proc = launch()
                last = now
    except KeyboardInterrupt:
        print("\n[dev_watch] stopping panel")
        stop(proc)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
