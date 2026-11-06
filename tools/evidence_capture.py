#!/usr/bin/env python3
"""tools/evidence_capture.py. Browser-UI screenshot of a domain, headless-server safe.

WHY THIS EXISTS
---------------
For a brand-impersonation finding the useful picture is the spoofed domain shown
in a real browser, address bar included, so the reader sees the fake name sitting
where the genuine one should be. A page-only headless screenshot cannot show that
chrome: the browser UI does not exist in headless mode. So we run a real, headful
Chromium on a virtual X display (Xvfb) with no monitor and no desktop, then grab
the whole display, browser frame and all. This is exactly how a non-graphical
server captures a UI shot.

SCOPE AND SAFETY
----------------
This fetches and renders the target page once, the same interaction the lookalike
visual-match step already performs in semi and active mode. It sends no
credentials, runs an ephemeral extension-free profile that is thrown away after
each shot, and never persists cookies. It is best effort: if the tools are
missing or the page never paints, it returns False and the caller falls back to
the hand-capture marker. It does not decide policy, the caller gates when to run.

    python tools/evidence_capture.py --url https://example.com --out shot.png
    python tools/evidence_capture.py --check          # list missing packages

INSTALL ON AN EMPTY DEBIAN
--------------------------
A bare Debian (or Ubuntu) box has none of this. One apt line covers it:

    sudo apt-get update && sudo apt-get install -y \
        chromium xvfb maim xdotool fonts-liberation ca-certificates

  - chromium          the browser (binary is `chromium`; its many shared-library
                      dependencies are pulled in automatically by the package).
  - xvfb              the virtual X server (provides Xvfb), so a headless box has
                      a display to render into.
  - maim              the screen grabber; `scrot` works too and is used if maim
                      is absent (`apt-get install -y scrot`).
  - xdotool           optional, only to park the mouse pointer out of the shot.
  - fonts-liberation  so Chromium has fonts to render text; without any fonts the
                      page renders blank boxes. `fonts-dejavu-core` works too.
  - ca-certificates   so HTTPS to the target domains validates.

On Ubuntu the chromium package is a snap; prefer `chromium-browser` or the
`chromium` deb from a PPA. Run `--check` to confirm the box is ready.
"""
from __future__ import annotations

import argparse
import os
import random
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

# Chromium flags that keep the window clean: no first-run bubbles, no restore
# prompt, no translate bar, no automation infobar, a fixed window the grab
# matches exactly. --no-sandbox and --disable-dev-shm-usage keep it alive in a
# minimal container or CI box.
_CHROME_FLAGS = [
    # X11 Ozone backend: without it Chromium never maps a top-level window on a
    # bare Xvfb (no window manager), so the grab comes back an empty root.
    "--ozone-platform=x11",
    # --test-type suppresses the yellow "unsupported flag / automation" infobars
    # so they do not land in the evidence image.
    "--test-type",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-infobars",
    "--disable-session-crashed-bubble",
    "--disable-translate",
    "--disable-features=Translate,InfiniteSessionRestore,AutomationControlled",
    "--no-sandbox",
    "--disable-gpu",
    "--disable-dev-shm-usage",
    "--disable-background-networking",
    "--disable-sync",
    "--hide-crash-restore-bubble",
    "--force-device-scale-factor=1",
]


def _chromium() -> str | None:
    for name in ("chromium", "chromium-browser", "google-chrome",
                 "google-chrome-stable", "chrome"):
        p = shutil.which(name)
        if p:
            return p
    return None


def _grabber() -> tuple[str, list] | None:
    """A whole-display grabber: maim or scrot. Returns (path, argv_template)."""
    m = shutil.which("maim")
    if m:
        return (m, [m, "--format=png"])          # maim <flags> OUT
    s = shutil.which("scrot")
    if s:
        return (s, [s, "-o", "-z"])               # scrot -o -z OUT
    return None


def _free_display() -> int:
    for _ in range(60):
        n = random.randint(90, 999)
        if not os.path.exists(f"/tmp/.X11-unix/X{n}"):
            return n
    return 99


def _wait_for_x(disp: int, timeout: float) -> bool:
    sock = f"/tmp/.X11-unix/X{disp}"
    end = time.time() + timeout
    while time.time() < end:
        if os.path.exists(sock):
            return True
        time.sleep(0.15)
    return False


def capture_url(url: str, out_path: str | Path, *, width: int = 1366,
                height: int = 900, wait_s: float = 7.0,
                timeout_s: float = 60.0) -> bool:
    """Render `url` in a headful Chromium on a virtual display and write a PNG of
    the whole browser window (address bar included) to `out_path`. Returns True
    only when a non-trivial image was produced. Never raises."""
    chromium = _chromium()
    xvfb = shutil.which("Xvfb")
    grab = _grabber()
    if not (chromium and xvfb and grab):
        return False
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    disp = _free_display()
    profile = tempfile.mkdtemp(prefix="ss-evshot-")
    env = dict(os.environ, DISPLAY=f":{disp}")
    xproc = cproc = None
    try:
        xproc = subprocess.Popen(
            [xvfb, f":{disp}", "-screen", "0", f"{width}x{height}x24",
             "-nolisten", "tcp", "-ac"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not _wait_for_x(disp, 10.0):
            return False
        cproc = subprocess.Popen(
            [chromium, *_CHROME_FLAGS,
             f"--user-data-dir={profile}",
             "--window-position=0,0",
             f"--window-size={width},{height}",
             url],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Give the page time to resolve, connect and paint. No CDP here, so the
        # wait is fixed and capped by the overall timeout.
        deadline = time.time() + timeout_s
        time.sleep(min(wait_s, max(0.0, deadline - time.time())))
        # Park the pointer in the bottom-right corner so the arrow does not sit
        # over the page in the evidence shot. Best effort, ignored if absent.
        xdt = shutil.which("xdotool")
        if xdt:
            try:
                subprocess.run([xdt, "mousemove", str(width - 1), str(height - 1)],
                               env=env, timeout=5,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        gbin, gargv = grab
        try:
            subprocess.run([*gargv, str(out_path)], env=env,
                           timeout=max(5.0, deadline - time.time()),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            return False
        return out_path.is_file() and out_path.stat().st_size > 2000
    except Exception:
        return False
    finally:
        for proc in (cproc, xproc):
            if proc is None:
                continue
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        try:
            shutil.rmtree(profile, ignore_errors=True)
        except Exception:
            pass


# What a bare box must have, mapped to the Debian/Ubuntu package that ships it,
# so a preflight can tell the operator exactly what to apt-get.
_REQUIRED = [
    (("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"),
     "chromium", "the browser"),
    (("Xvfb",), "xvfb", "the virtual X server"),
    (("maim", "scrot"), "maim (or scrot)", "the screen grabber"),
]
_OPTIONAL = [
    (("xdotool",), "xdotool", "parks the mouse pointer out of the shot"),
]


def preflight() -> list[str]:
    """Return a list of human-readable lines for every required tool that is
    missing, empty when the box is ready. Optional tools are noted, not failed."""
    out: list[str] = []
    for names, pkg, what in _REQUIRED:
        if not any(shutil.which(n) for n in names):
            out.append(f"missing: {names[0]} ({what}) -> apt-get install -y {pkg}")
    for names, pkg, what in _OPTIONAL:
        if not any(shutil.which(n) for n in names):
            out.append(f"optional: {names[0]} ({what}) -> apt-get install -y {pkg}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Capture a browser-UI screenshot of a URL.")
    ap.add_argument("--check", action="store_true",
                    help="report missing packages for capture and exit")
    ap.add_argument("--url")
    ap.add_argument("--out")
    ap.add_argument("--width", type=int, default=1366)
    ap.add_argument("--height", type=int, default=900)
    ap.add_argument("--wait", type=float, default=7.0)
    args = ap.parse_args()
    if args.check:
        missing = preflight()
        if not missing:
            print("ready: all capture tools present.")
            return 0
        print("\n".join(missing))
        return 1
    if not (args.url and args.out):
        ap.error("--url and --out are required unless --check is given")
    miss = [m for m in preflight() if m.startswith("missing:")]
    if miss:
        print("\n".join(miss))
        return 1
    ok = capture_url(args.url, args.out, width=args.width, height=args.height,
                     wait_s=args.wait)
    print("ok" if ok else "failed")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
